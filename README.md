# GSB Bugfix Task

## 题面

证书签发平台上线 CT 强制策略后，监控连续三天报同一类告警：一张 365 天有效期的证书只带了两个 SCT 就被放行，事后查到这两个 SCT 来自同一个日志运营方；另一张证书把同一个 SCT 在 TLS 扩展里重复塞了五份，策略层按条数累加，误判成满足多样性要求；还有攻击者把 A 证书的 SCT 原样搬到 B 证书上，签名校验只看日志公钥、没绑定证书指纹，居然通过了。日志退役后旧 SCT 仍在计数，时间戳在未来的 SCT 也被当成有效，列表长度没有上限，单个请求能塞进上千条把校验拖垮。任务在 `gsb/batch46-safety-b-05`，文件 `sct_policy_guard.py`，任务类型 Bugfix，修 `SctGuard`，日志注册、SCT 签发、策略校验、列表编解码四条路径共用同一份内存状态。

公开接口（与骨架一致）：`__init__(self, *, now=0, max_scts=16, max_list_bytes=4096)`；`add_log(self, log_id, *, operator, key, not_after=None, status="usable", quota=0) -> dict`；`set_log_status(self, log_id, status) -> dict`；`submit(self, log_id, cert_fingerprint, *, now=None) -> dict`；`required_count(self, cert) -> int`；`verify(self, cert, scts, *, now=None) -> dict`；`require(self, cert, scts, *, now=None) -> dict`；`pack(self, scts) -> str`；`unpack(self, blob) -> list`；`sweep(self, *, now=None) -> int`；`stats(self) -> dict`；`audit_log(self) -> list`；`snapshot(self) -> dict`；类方法 `restore(cls, state)`。

证书是含 fingerprint、not_before、not_after 的字典；SCT 是含 log_id、timestamp、signature 的字典，签名输入是 `log_id|cert_fingerprint|timestamp` 的 UTF-8 字节，HMAC-SHA256 取小写十六进制。需要修的点：

1. `add_log` 重复注册报 SCT_LOG_EXISTS，status 只接受 usable、readonly、retired、disabled，其余报 SCT_BAD_STATUS；`submit` 对未知日志报 SCT_UNKNOWN_LOG，对 retired 或 disabled 的日志报 SCT_LOG_UNAVAILABLE。
2. `submit` 返回 log_id、operator、timestamp、signature，并把该日志的已签发数加一；quota 大于零时超出报 SCT_QUOTA，quota 为零表示不限。
3. `required_count` 按证书有效期的天数上取整：不超过 90 天返回 1，超过 90 天且不超过 180 天返回 2，超过 180 天返回 3；90、180 这两个边界落到较小的档位。
4. `verify` 返回 valid、code、required、accepted、rejected、operators 六个字段；accepted 保持输入顺序，rejected 每项至少带 code，operators 是去重排序后的运营方名字。
5. 逐条判定顺序：未知日志报 SCT_UNKNOWN_LOG；retired 报 SCT_LOG_RETIRED；disabled 报 SCT_LOG_DISABLED；签名不符报 SCT_BAD_SIGNATURE；timestamp 大于 now 报 SCT_FUTURE_TIMESTAMP；timestamp 落在 not_before 之前或 not_after 之后报 SCT_OUTSIDE_VALIDITY。这些条目都不计数。
6. 重复控制：同一 log_id 与同一 timestamp 只计一次并保留首次出现；同一个日志的多个时间戳仍然只算一个运营方；不同日志但同一 operator 也只算一个运营方。
7. 多样性只按不同 operator 的数量判定，达到 required_count 才 valid；有 accepted 但不够数时 code 为 SCT_INSUFFICIENT；一条 accepted 都没有时取 rejected 里第一项的 code；输入为空列表时返回 SCT_EMPTY_LIST。
8. `require` 在 valid 时原样返回，否则抛 SctError，code 与 verify 一致，detail 带上完整判定结果。
9. `pack` 输出无填充 URL-safe base64 的紧凑 JSON 数组，元素是 log_id、timestamp、signature 三元组，按首次出现顺序去重；条数超过 max_scts 报 SCT_TOO_MANY，结果长度超过 max_list_bytes 报 SCT_SIZE_LIMIT；`unpack` 先判长度再解码，非法 base64、JSON 或元素形状统一报 SCT_MALFORMED_LIST。
10. 资源硬约束：单次 verify 的 scts 条数超过 max_scts 直接返回 SCT_TOO_MANY，不再逐条验签；单条 SCT 校验不得触发额外的日志注册表写入。
11. 并发硬约束：同一个日志被八个线程同时 submit、quota 为 3 时只能有三个成功，其余五个全部 SCT_QUOTA，已签发计数只能加到三，计数检查与自增必须在同一临界区内。
12. 快照恢复：snapshot 必须可 JSON 序列化，restore 之后日志状态、not_after、quota、已签发计数和 stats 全部延续；`sweep` 把 not_after 小于等于 now 的日志置为 retired 并返回条数。

stats 至少包含 logs、usable、issued、verified、passed、failed 六个计数；audit_log 记录每次 verify 的指纹前缀、结果与错误码。

验收：在项目根执行 `python3 -m pytest -q tests`，15 条必须全部通过；不得修改测试、跳过或按固定输入写死；并发与重启恢复场景请自行验证；只做本地实现，除 pytest 外不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
