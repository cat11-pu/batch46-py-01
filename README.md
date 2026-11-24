# GSB Bugfix Task

## 题面

一批边缘节点升级固件后，远程证明通过率从九成八掉到六成，运维抽查发现其中一半是误杀：PCR 列表里的 10 和 2 被按字符串排序，摘要永远对不上；基线轮换之后老 AK 仍按旧版本通过校验；验证服务重启后同一个 nonce 又被发了一遍；坏签名请求把 nonce 消耗掉，真节点重试反而被拒。更糟的是攻击者拿一台已经落地的旧 quote 反复重放，计数器没有单调约束，十分钟内把三台机器刷成 trusted。请修 `gsb/batch46-safety-b-07` 下的 `tpm_quote_guard.py`，暴露类型 `TpmQuoteGuard`，任务类型 Bugfix，只改这一个文件，不得改测试。

题目已提供签名工具 `quote_signature(secret: str, node_id: str, nonce: str, pcr_digest: str, counter: int) -> str`，实现为 sha256("节点|nonce|pcr_digest|计数器|secret")，直接用它验签即可。保持这些公开接口：

- `define_profile(name: str, *, required_pcrs: tuple[int, ...], golden: dict[int, str], min_counter: int = 0) -> dict`
- `rotate_profile(name: str, *, required_pcrs: tuple[int, ...] | None = None, golden: dict[int, str] | None = None, min_counter: int | None = None) -> dict`
- `enroll_ak(ak_name: str, *, secret: str, profile: str, pcrs: dict[int, str], pubkey_id: str | None = None, now: str = ...) -> dict`
- `revoke_ak(ak_name: str, *, reason: str = "manual") -> dict`
- `issue_nonce(node_id: str, *, ttl_seconds: int | None = None, now: str = ...) -> dict`
- `verify_quote(node_id: str, *, ak_name: str, quote: dict, now: str = ...) -> dict`
- `trust_state(node_id: str) -> dict`、`sweep(now: str = ...) -> dict`、`snapshot() -> dict`、`restore(snap: dict) -> None`、`audit(limit: int = 20) -> list`、`stats() -> dict`

构造参数 `nonce_ttl_seconds`、`nonce_cap`、`failure_budget`、`failure_window_seconds`、`audit_capacity` 默认 300、4、3、60、128。

故障与边界：profile 的 required_pcrs 必须是非空且不重复的整数列表，golden 的键集合必须与之一致，PCR 摘要必须是 64 位十六进制，min_counter 不得为负，否则 `TQ_PROFILE_INVALID` 或 `TQ_PCR_INVALID`；重名报 `TQ_PROFILE_DUPLICATE`，轮换不存在的基线报 `TQ_PROFILE_UNKNOWN`，轮换成功版本号加一。注册 AK 时 secret 必须是 64 位十六进制否则 `TQ_AK_SECRET_INVALID`，基线不存在报 `TQ_PROFILE_UNKNOWN`，缺少基线要求的 PCR 报 `TQ_PCR_REQUIRED_MISSING`，PCR 摘要非法报 `TQ_PCR_INVALID`，重名报 `TQ_AK_DUPLICATE`，注册要记下当时的基线版本。nonce 按 `sha256("<node>|<seq>")` 取前 32 位生成，seq 从 1 起单调递增；ttl 非正报 `TQ_TTL_INVALID`，单节点未使用 nonce 最多 4 个，超出报 `TQ_NONCE_CAP`，返回值含 node、nonce、seq、expires_at。nonce 过期后再次提交报 `TQ_NONCE_EXPIRED` 并从待用集合移除，已经成功用过或已判失败消耗掉的 nonce 再出现报 `TQ_NONCE_CONSUMED`，从未签发过的报 `TQ_NONCE_UNKNOWN`，sweep 清理过期 nonce 并返回 `{"nonces": n}`。quote 缺字段或 counter 不是整数报 `TQ_QUOTE_INVALID`，缺少基线要求的 PCR 报 `TQ_PCR_MISSING`，摘要格式错报 `TQ_PCR_INVALID`。签名不匹配报 `TQ_SIGNATURE_INVALID`，且这次失败不能消耗 nonce，节点必须能用同一个 nonce 重试成功。PCR 摘要按所有条目 `序号:摘要` 用竖线连接、序号按数值升序后取 sha256，算出来与 quote 声明的不一致报 `TQ_PCR_DIGEST_MISMATCH` 并消耗 nonce；与 golden 值不一致报 `TQ_PCR_MISMATCH` 并置为不可信。计数器必须严格大于该 AK 上次通过的值，否则 `TQ_COUNTER_REPLAY`；低于基线 min_counter 报 `TQ_COUNTER_STALE`；两者都消耗 nonce。60 秒窗口内失败达到 3 次后，该节点后续请求一律先报 `TQ_RATE_LIMITED`。AK 被吊销后报 `TQ_AK_REVOKED` 并立即取消信任，重复吊销幂等；AK 记录的基线版本落后于当前版本时报 `TQ_ENROLLMENT_STALE`。校验通过返回 status="trusted" 与 counter、profile、pcr_digest，并让 generation 加一。

硬约束：snapshot/restore 必须可 JSON 序列化，保留每个 AK 的计数器、每个节点的 nonce 序号与已消费 nonce 集合，版本号不认识报 `TQ_SNAPSHOT_INVALID`，generation 比当前小的旧快照报 `TQ_SNAPSHOT_STALE`，恢复后不允许 nonce 重发或计数器回退；12 个线程用同一个计数器值并发提交各自 nonce 时，只能有 1 个通过，其余全部 `TQ_COUNTER_REPLAY`；所有判定在一把可重入锁内完成，失败路径不得留下半个已消费状态。

验收：`python3 -m pytest -q tests` 的 15 条必须全过，不得改测试、跳过或按固定输入写死；并发与重启恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
