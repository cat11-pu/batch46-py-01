# GSB Bugfix Task

## 题面

生产机群的 IMA 完整性评估上周连着出事：一台机器上的 `/usr/sbin/sshd` 被换成后门版本，评估结果照样是 pass，因为基线里根本没有这个路径；运维用脚本改基线，单人一次调用就生效，事后没人说得清是谁批的；热修复期间加的临时豁免没有过期时间，半年后还能把篡改后的新摘要放过去。旧评估器还会把测量列表里重复的路径算两次，批量上报一多整段就超时。请修 `gsb/batch46-safety-b-08` 下的 `ima_appraisal_guard.py`，暴露类型 `ImaGuard`，任务类型 Bugfix，只改这一个文件，不得改测试。

保持这些公开接口：

- `add_baseline(host: str, path: str, *, digest: str, algo: str = "sha256", note: str | None = None, now: str = ...) -> dict`
- `remove_baseline(host: str, path: str, *, algo: str = "sha256", now: str = ...) -> dict`
- `propose_baseline(host: str, *, changes: list[dict], proposer: str, now: str = ...) -> dict`
- `approve_proposal(proposal_id: str, *, approver: str, now: str = ...) -> dict`
- `apply_proposal(proposal_id: str, *, now: str = ...) -> dict`
- `appraise(host: str, measurements: list[dict], *, require_complete: bool = True, now: str = ...) -> dict`
- `grant_exception(host: str, path: str, *, digest: str, ttl_seconds: int = 600, reason: str = "", now: str = ...) -> dict`
- `host_state(host: str) -> dict`、`expire(now: str = ...) -> dict`、`release_quarantine(host: str) -> dict`、`snapshot() -> dict`、`restore(snap: dict) -> None`、`audit(limit: int = 20) -> list`、`stats() -> dict`

构造参数 `max_batch`、`quorum`、`proposal_ttl_seconds`、`quarantine_after`、`audit_capacity` 的默认值分别是 4096、2、3600、3、256。`host_state` 返回 baseline 条数、status、consecutive_failures、quarantined、last_appraised；`appraise` 除 status、violations、checked、excepted 外还要返回 consecutive_failures 与 quarantined。

故障与边界：摘要长度按算法区分，sha1 40 位、sha256 64 位、sha384 96 位、sha512 128 位，算法不在白名单报 `IMA_ALGO_INVALID`，长度或字符不对报 `IMA_DIGEST_INVALID`，路径必须以斜杠开头否则 `IMA_PATH_INVALID`。同一 host 下 path 加算法相同且摘要一致时 `add_baseline` 返回 status="unchanged"，摘要不同报 `IMA_BASELINE_CONFLICT`，删除不存在的条目报 `IMA_BASELINE_UNKNOWN`。评估批次上限 4096 条，超过报 `IMA_BATCH_TOO_LARGE` 且不能改动任何 host 状态；单条缺字段或类型不对报 `IMA_MEASUREMENT_INVALID`；同一批里 path 加算法重复报 `IMA_DUPLICATE_PATH`，整批拒绝、失败计数不变。违规分三类：基线没有的 `unknown_file`（expected 为 None）、摘要不一致的 `digest_mismatch`、以及 require_complete 为真时基线有但本次没上报的 `missing_file`（actual 为 None），违规按 path 再按 kind 排序，返回 status 为 pass 或 fail、checked 为测量条数、excepted 为被豁免路径的升序列表。失败一次 consecutive_failures 加一，成功清零；连续 3 次失败进入隔离，之后 appraise 直接报 `IMA_HOST_QUARANTINED`，`release_quarantine` 解除并清零。豁免按 path 加摘要精确匹配，ttl 非正报 `IMA_TTL_INVALID`，只能压掉相同摘要的 unknown_file 或 digest_mismatch，压不掉 missing_file 和其他摘要；过期后不再生效，`expire` 清理并返回 `{"exceptions": n}`。

基线变更必须走提案：changes 非空，每项 op 只能是 add 或 remove，path、算法、摘要按上面的规则校验，同一批里 path 加算法重复报 `IMA_CHANGE_INVALID`；提案 ID 为 `"<host>:<序号>"`，序号从 1 起，有效期 3600 秒。审批人不能是提案人，报 `IMA_SELF_APPROVAL`；重复审批报 `IMA_APPROVER_DUPLICATE`；已通过的提案报 `IMA_PROPOSAL_APPLIED`；过期报 `IMA_PROPOSAL_EXPIRED`；不存在报 `IMA_PROPOSAL_UNKNOWN`；审批数达到 2 时状态为 ready，否则 pending。apply 时不足 2 票报 `IMA_QUORUM_PENDING`，同一提案只能成功一次；先整体校验所有 remove 的条目都存在，任一不存在报 `IMA_BASELINE_UNKNOWN` 并且一条都不落库，全部通过后才一次性提交。

硬约束：snapshot/restore 必须可 JSON 序列化，保留各 host 基线、提案及其审批人、豁免、连续失败次数和隔离状态，版本号不认识报 `IMA_SNAPSHOT_INVALID`；12 个线程同时 apply 同一个已够票的提案，只能有 1 个返回 applied，其余全部 `IMA_PROPOSAL_APPLIED`，基线里不能出现重复或半份变更；appraise 的校验与计数、提案的审批与落库都必须在同一把可重入锁内完成。audit 新的在前，超出容量丢最旧的。

验收：`python3 -m pytest -q tests` 的 15 条必须全过，不得改测试、跳过或按固定输入写死；并发与快照恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 困难
