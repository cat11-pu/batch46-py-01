# GSB Bugfix Task

## 题面

移动端灰度发版后，客服陆续收到“刚登录就掉线”的反馈：网关用的本地令牌库在上次重构里把 footer 当成了纯展示字段，改一个租户名也能通过校验；更严重的是轮换密钥时旧密钥被立刻删除，正在刷新的客户端全部 401，回滚后又被安全同学发现旧令牌还能重放。审计日志里同一条 jti 在十分钟内被兑换了四次，而令牌大小没有上限，有人用超长 claims 把校验线程拖到超时。任务在 `gsb/batch46-safety-b-04`，文件 `paseto_v4_guard.py`，任务类型 Bugfix，修 `PasetoGuard`，签发、校验、轮换、吊销四条路径共用同一份内存状态。

公开接口（与骨架一致）：`__init__(self, *, key, key_id="k1", now=0, max_token_bytes=1024)`；`issue(self, claims, *, footer=None, implicit=None, ttl=600, now=None) -> str`；`verify(self, token, *, implicit=None, audience=None, max_age=None, single_use=False, require_footer=None, now=None) -> dict`；`peek(self, token) -> dict`；`revoke(self, jti, *, expires_at=None, now=None) -> dict`；`rotate_key(self, *, key_id, key=None, grace=300, now=None) -> dict`；`retire_key(self, key_id, *, now=None) -> dict`；`keyring(self) -> list`；`sweep_revocations(self, *, now=None) -> int`；`stats(self) -> dict`；`audit_log(self) -> list`；`snapshot(self) -> dict`；类方法 `restore(cls, state)`。

令牌固定四段：`v4.local.<正文>.<footer>`，两段都是无填充的 URL-safe base64。正文用标准库 HMAC-SHA256 之类的对称构造做认证加密，footer 的原始字节也要纳入认证范围；footer 是 JSON 对象且必须含 kid。需要修的点：

1. `issue` 复制传入 claims，不修改调用方字典；iat 取 now，exp 取 claims 里已有的值，否则取 now 加 ttl；没有 jti 时生成一个非空字符串。
2. 签发结果和待校验令牌长度超过 max_token_bytes 都报 PASETO_SIZE_LIMIT，校验时先判长度再解析。
3. 段数不是四段、前两段不是 v4 与 local、base64 解不开、footer 不是 JSON 对象、正文缺 exp/iat/jti，统一报 PASETO_FORMAT。
4. footer 里的 kid 未知、已退役或宽限期已过，报 PASETO_UNKNOWN_KEY；正文或 footer 任意字节被改、密钥不对、解密或正文解析失败，统一报 PASETO_INTEGRITY，不能把底层异常直接抛给调用方。
5. 隐式断言不写进令牌明文，而是把它的摘要放进认证过的正文；校验时先验完整性再比对摘要，传入值与签发时不一致（包括该传没传）报 PASETO_IMPLICIT。
6. 时间校验顺序：now 大于等于 exp 报 PASETO_EXPIRED；claims 带 nbf 且 now 小于 nbf 报 PASETO_NOT_YET_VALID；传入 max_age 且 now 减 iat 大于 max_age 报 PASETO_TOKEN_TOO_OLD。
7. 传入 audience 时，claims 的 aud 可以是字符串或列表，交集为空报 PASETO_AUDIENCE；未传 audience 不校验。
8. `revoke` 写入 jti 与 expires_at（缺省 now 加 3600），在 now 小于 expires_at 期间校验报 PASETO_REVOKED；`sweep_revocations` 删除 expires_at 小于等于 now 的记录并返回条数。
9. single_use 校验成功后把 jti 记入已消费集合，之后无论是否再传 single_use 都报 PASETO_REPLAY；不传 single_use 的校验只读该集合、不写入。
10. `rotate_key` 让旧密钥进入宽限期，expires_at 为 now 加 grace，新密钥立即成为 current，返回 key_id、previous、expires_at；宽限期内旧令牌仍可验，边界等于 expires_at 时拒绝；`keyring` 按插入顺序返回 key_id、status（current 或 grace）、expires_at，不得返回密钥材料。
11. 并发硬约束：同一个 jti 被八个线程同时以 single_use 校验，只能有一个成功，其余七个全部 PASETO_REPLAY，verified 计数只能加一，重放集合的读写必须原子。
12. 快照恢复：snapshot 必须可 JSON 序列化，restore 之后当前密钥、宽限期、已吊销 jti、已消费 jti 与计数器全部延续；恢复后旧令牌在宽限期内仍可验，已吊销与已重放的令牌不能复活。

stats 至少包含 issued、verified、denied、replays 四个计数；audit_log 记录校验结果与错误码，但不得写入密钥材料。require_footer 传入时按子集比对，缺键或值不等报 PASETO_FOOTER_MISMATCH。

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
