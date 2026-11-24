# GSB Bugfix Task

## 题面

堡垒机的 ssh-agent 转发最近在审计里连出四起事故：同一个密钥指纹同时出现在两个不同账号的会话里，离职账号的密钥吊销后还能签出 git 提交，压测时单个密钥的签名次数被并发请求打到配置上限的三倍，还有人把转发目标设成 127.0.0.1 自建隧道绕开出网策略。值班同学临时关掉转发才压住告警，可业务方的 git 发布和 scp 传包都走这条链路，不能一关了之。请修 `gsb/batch46-safety-b-06` 下的 `ssh_agent_forward_guard.py`，暴露类型 `AgentForwardGuard`，任务类型 Bugfix，只改这一个文件，不得改测试。

保持这些公开接口的签名与默认值：

- `register_key(key_id: str, *, fingerprint: str, owner_account: str, principals: tuple = (), max_signs: int = 32, ttl_seconds: int = 3600, now: str = ...) -> dict`
- `revoke_key(key_id: str, *, reason: str = "manual") -> dict`
- `open_session(session_id: str, *, account: str, host: str, target_user: str, keys: tuple, ttl_seconds: int = 600, purposes: tuple = ("git", "scp"), targets: tuple = (), now: str = ...) -> dict`
- `close_session(session_id: str, *, reason: str = "closed") -> dict`
- `request_forward(session_id: str, *, remote_host: str, nonce: str, remote_port: int = 22, now: str = ...) -> dict`
- `approve_forward(session_id: str, request_id: str, *, approved_by: str, now: str = ...) -> dict`
- `sign(session_id: str, key_id: str, *, digest: str, purpose: str = "git", request_id: str | None = None, now: str = ...) -> dict`
- `usage(session_id: str) -> dict`、`sweep(now: str = ...) -> dict`、`snapshot() -> dict`、`restore(snap: dict) -> None`、`audit(limit: int = 20) -> list`、`stats() -> dict`

构造参数只有 `audit_capacity`，默认 256。`usage` 返回 status、signs、forwards、keys、expires_at，`stats` 返回 keys、sessions、signs、audit 四个计数。

故障与边界：重复 key_id 报 `AF_KEY_DUPLICATE`，重复 fingerprint 报 `AF_KEY_FINGERPRINT_DUP`，指纹不是 64 位小写十六进制报 `AF_FINGERPRINT_INVALID`；ttl 非正报 `AF_TTL_INVALID`，max_signs 小于 1 报 `AF_SIGN_BUDGET_INVALID`。会话只能绑定属主自己的、未吊销、未过期且未被其它活动会话占用的密钥，依次报 `AF_KEY_OWNER_MISMATCH`、`AF_KEY_REVOKED`、`AF_KEY_EXPIRED`、`AF_KEY_BUSY`；keys 为空报 `AF_SESSION_NO_KEYS`，session_id 复用报 `AF_SESSION_DUPLICATE`，会话关闭后密钥可被新会话接管。转发目标必须在会话 targets 内（空表示不限），否则 `AF_FORWARD_HOST_DENIED`；localhost、127.0.0.1、::1、0.0.0.0 一律 `AF_FORWARD_LOOPBACK`；端口越界 `AF_PORT_INVALID`；nonce 必须 8 到 64 位十六进制，否则 `AF_NONCE_INVALID`，且全局一次性，重复报 `AF_NONCE_REPLAY`，request_id 固定为 `会话:nonce`。审批必须由非会话账号完成，自审报 `AF_SELF_APPROVAL`，未知请求报 `AF_FORWARD_UNKNOWN`，重复审批幂等并保留首个审批人。没有任何审批通过的转发时签名报 `AF_FORWARD_REQUIRED`；purpose 不在会话许可内报 `AF_PURPOSE_DENIED`；digest 必须是 64 位十六进制，否则 `AF_DIGEST_INVALID`；密钥不在会话内报 `AF_KEY_NOT_ALLOWED`，已吊销的密钥优先报 `AF_KEY_REVOKED`。单个密钥的累计签名次数跨会话计算，超过 max_signs 报 `AF_SIGN_BUDGET`。request_id 幂等：同 request_id 同 digest 返回 `status="replayed"`，不消耗预算、sign_index 不变；digest 不同报 `AF_REQUEST_CONFLICT`。会话到期后签名报 `AF_SESSION_EXPIRED` 并立即释放密钥绑定，close 后签名报 `AF_SESSION_CLOSED`；sweep 返回 `{"sessions": n, "keys": m}` 并回收过期资源。snapshot/restore 必须可 JSON 序列化，保留已用签名预算、会话状态、nonce 集合和审计序号，未知 version 报 `AF_SNAPSHOT_INVALID`，恢复后审计 seq 只能继续递增。audit 新的在前，超出容量丢最旧的，条目含 seq、action、session、key 等字段；审计只记录成功的状态变更与重放，被拒绝的请求不入表。

硬约束：18 个线程同时对同一密钥签名、预算为 5 时，必须恰好 5 次成功、13 次 `AF_SIGN_BUDGET`，usage 的 signs 只记 5；所有状态改动在一把可重入锁内完成，任何校验失败都不得留下半成品状态，不允许出现密钥被占用却没有会话、或预算被扣掉而签名失败的情况。审计同事还要求每次拒绝都能追溯到具体会话和密钥，事后按序号复盘，重启或恢复快照都不能让已经用掉的预算重新出现。

验收：`python3 -m pytest -q tests` 的 15 条必须全过，不得改测试、跳过或按固定输入写死；并发与快照恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
