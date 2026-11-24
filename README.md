# GSB Bugfix Task

## 题面

运维在核心网边界抓到一段可疑流量：攻击者往现网偶联里塞入没有 AUTH 的 DATA 块，接收端照单全收；另有一段带合法 AUTH 的报文被原样重放，半小时内触发了四次重复计费。凌晨换密钥时更乱，旧密钥刚下线，边缘节点还在用旧签名，探活包被整批拒绝，业务闪断了十几秒。抓包文件里还混着填充字节非零的块，旧解析器把最后两字节当成了新块头，越界读了半个包。请修 `gsb/batch46-safety-c-10` 下的 `sctp_chunk_guard.py`，核心类型 `SctpGuard`，任务类型 Bugfix；所有校验失败统一抛 `SctpError(code, detail=None)`，调用方按 `code` 处理。

需要保留这些公开方法：`__init__(self, *, max_chunks: int = 16, max_bundle_bytes: int = 1200, replay_window: int = 256, key_grace: float = 300.0) -> None`、`add_key(self, key_id: int, key: bytes, *, active: bool = False, now: float = 0.0) -> dict`、`rotate_key(self, key_id: int, *, now: float = 0.0) -> dict`、`remove_key(self, key_id: int, *, now: float = 0.0) -> bool`、`active_key_id(self) -> int | None`、`keys(self) -> list[dict]`、`parse_bundle(self, raw: bytes) -> list[dict]`、`verify(self, chunks: list[dict], *, assoc: str, now: float = 0.0) -> dict`、`replay_count(self, assoc: str) -> int`、`clear_replay(self, assoc: str) -> int`、`stats(self) -> dict`、`snapshot(self) -> dict`、`restore(self, state: dict) -> None`。

具体故障与边界：一、`parse_bundle` 按块头 type、flags、length 解析，length 含四字节块头但不含补齐字节，至少为 4，按 4 字节对齐补零且填充必须全零，整包超过 `max_bundle_bytes` 报 `SCTP_BUNDLE_TOO_LARGE`，块数超过 `max_chunks` 报 `SCTP_CHUNK_LIMIT`，length 小于 4 报 `SCTP_BAD_LENGTH`，剩余字节不足或块被截断报 `SCTP_TRUNCATED`，填充非零报 `SCTP_BAD_PADDING`。二、解析结果每项含 type、flags、length、payload 和 raw，raw 包含补齐字节；成功一次 parsed_bundles 加一。三、AUTH 块 type 为 15，payload 固定 24 字节：key_id 两个字节、hmac_id 两个字节、20 字节 HMAC-SHA1；hmac_id 只接受 1，长度或编号不符报 `SCTP_AUTH_FORMAT`。签名内容是从第二个块开始所有块 raw 的拼接，包含补齐字节。四、AUTH 块必须恰好一个且排在第一位，缺失报 `SCTP_NO_AUTH`，多个报 `SCTP_AUTH_DUP`，不在首位报 `SCTP_AUTH_NOT_FIRST`。五、密钥编号在 0 到 65535，密钥长度 16 到 64 字节，非法分别报 `SCTP_BAD_KEY_ID`、`SCTP_BAD_KEY`；同一编号重复添加报 `SCTP_KEY_CONFLICT`，第一条密钥自动激活，带 active=True 添加会退役当前密钥，`rotate_key` 切换活动密钥并记录退役时间，`keys` 不返回密钥原文，`active_key_id` 在活动密钥被删后返回 None。

六、`verify` 查密钥时，编号不存在报 `SCTP_UNKNOWN_KEY`，当前没有活动密钥报 `SCTP_NO_ACTIVE_KEY`，从未激活的密钥报 `SCTP_KEY_INACTIVE`，已退役且 now 减退役时间严格大于 `key_grace` 报 `SCTP_KEY_EXPIRED`；签名不符报 `SCTP_BAD_SIGNATURE`。七、验证成功时 status 为 accepted、code 为 None，结果固定含 status、code、assoc、key_id、chunk_count、auth_index、reported、replay_entries；未知块类型的处置看 flags 的高两位：0x80 报 `SCTP_UNKNOWN_ERROR`，0xC0 报 `SCTP_UNKNOWN_ABORT`，0x40 放行并计入 reported，0x00 直接跳过；已知类型集合包含 0 到 11、14、15。八、重放缓存按 assoc 保存 AUTH 摘要的十六进制串，同一摘要再次出现报 `SCTP_REPLAY`，缓存最多保留 `replay_window` 条，超出淘汰最旧记录；`replay_count` 返回当前条数，`clear_replay` 清空并返回条数。九、`stats` 给出 parsed_bundles、verified、rejected、replayed、keys、replay_entries 和 codes。十、快照固定含 version、keys（含 key_hex、active、added_at、retired_at）、active_key_id、replay、counters；恢复要深拷贝密钥和缓存，恢复后已消费的摘要仍按重放处理，版本不符报 `SCTP_STATE_VERSION`。

硬约束：解析、验签、密钥表、重放缓存和统计由同一把可重入锁保护，八个线程并发验证不同 assoc 时 verified 和 replay_entries 必须精确；快照恢复后活动密钥、退役时间、重放摘要和计数要一致；块数、整包字节数、重放缓存和密钥数量都有上限，重放缓存不得无界增长，未通过验签或未知块处置的报文不能写入重放缓存。验收标准是 `python3 -m pytest -q tests` 的 15 条全部通过；不得改测试、跳过或按固定输入写死，并发与重启恢复自行验证，只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
