# GSB Bugfix Task

## 题面

支付网关共用的加密机最近出了几起对不上的签名事故：服务重连后加密机分配的句柄被回收再用，旧句柄指向了新密钥，柜面把一笔转账签成了上一笔的摘要；同一个应用的会话 A 创建的密钥句柄，被会话 B 直接拿去做签名；应用切走之后既没有 logout，也没有销毁对象，句柄越积越多，两周后加密机报对象表满；运维重启客户端后句柄编号从头开始，审计日志里出现两条记录指向同一个句柄。另外压测时 24 个线程同时用一个限次密钥，实际用出 30 多次。请修 `gsb/batch46-safety-b-09` 下的 `hsm_session_guard.py`，暴露类型 `HsmSessionGuard`，任务类型 Bugfix，只改这一个文件，不得改测试。

保持这些公开接口：

- `login(app_id: str, *, pin_digest: str, slot: str = "slot-0", now: str = ...) -> dict`
- `unlock_app(app_id: str) -> dict`、`logout(session_id: str, *, reason: str = "closed", now: str = ...) -> dict`
- `open_object(session_id: str, *, label: str, value_digest: str, kind: str = "session", max_uses: int | None = None, now: str = ...) -> dict`
- `find_objects(session_id: str, *, label: str | None = None, kind: str | None = None, now: str = ...) -> list`
- `use_object(session_id: str, handle: int, *, now: str = ...) -> dict`
- `destroy_object(session_id: str, handle: int, *, now: str = ...) -> dict`
- `rotate_handles(session_id: str, *, now: str = ...) -> dict`
- `heartbeat(session_id: str, *, now: str = ...) -> dict`
- `session_state(session_id: str) -> dict`、`sweep(now: str = ...) -> dict`、`snapshot() -> dict`、`restore(snap: dict) -> None`、`audit(limit: int = 20) -> list`、`stats() -> dict`

构造参数 `max_sessions_per_app`、`max_objects`、`idle_timeout`、`max_failed_logins`、`handle_floor`、`audit_capacity` 默认 4、64、900、3、1000、256。PIN 必须是 64 位十六进制，否则 `HSM_PIN_INVALID`；应用首次登录建立会话并记住 PIN，同一应用同一 slot 已有活动会话时 PIN 一致返回 status="reused"，不一致记一次失败并报 `HSM_AUTH_FAILED`，失败累计到 3 次后该应用被锁，之后任何登录都报 `HSM_PIN_LOCKED`，成功登录把失败计数清零，`unlock_app` 解锁。会话 ID 为 `"<app>-<序号>"`，序号按应用从 1 起只增不减；每个应用的活动会话上限 4，超出报 `HSM_SESSION_LIMIT`；logout 幂等，再次调用返回 closed。

对象：`kind` 只允许 session 或 token，否则 `HSM_OBJECT_KIND_INVALID`；label 不能为空，否则 `HSM_LABEL_INVALID`；value_digest 必须是 64 位十六进制，否则 `HSM_DIGEST_INVALID`；max_uses 只能是 None 或大于等于 1 的整数，否则 `HSM_USE_LIMIT_INVALID`；全局存活对象上限 64，超出报 `HSM_OBJECT_LIMIT`。句柄从 1000 起全局单调递增，销毁、轮换、重连后都不得复用。`find_objects` 返回本会话的 session 对象加同应用所有 token 对象，按句柄升序，元素含 handle、label、kind、uses。`use_object` 时已销毁或不存在报 `HSM_HANDLE_UNKNOWN`，被轮换掉的旧句柄报 `HSM_HANDLE_STALE`，session 对象被别的会话使用、token 对象被别的应用使用都报 `HSM_HANDLE_FOREIGN`，用量达到 max_uses 报 `HSM_USE_LIMIT`，成功时 uses 加一并返回。`destroy_object` 只能销毁本会话创建的对象，销毁后该对象的所有历史句柄一律 `HSM_HANDLE_UNKNOWN`。logout 销毁本会话的 session 对象，token 对象保留，同应用其它会话仍可 find 和 use。`rotate_handles` 重映射本会话可见的全部对象，返回 `{"rotated": n, "handles": [{"from": 旧, "to": 新}]}` 且按旧句柄升序，旧句柄立即变 `HSM_HANDLE_STALE`，新句柄可正常使用，整个重映射要么全成要么全不改。

空闲与恢复：会话距最后一次操作达到 idle_timeout 即过期，任何操作先报 `HSM_SESSION_EXPIRED`，session_state 显示 closed；heartbeat 续期；sweep 关闭空闲会话、销毁其 session 对象，返回 `{"sessions": n, "objects": m}`。已关闭会话上的对象操作先报 `HSM_SESSION_CLOSED`，未知会话报 `HSM_SESSION_UNKNOWN`。snapshot/restore 必须可 JSON 序列化，保留会话、对象、已用句柄代数与下一个句柄号，版本号不认识报 `HSM_SNAPSHOT_INVALID`，代数比当前小的旧快照报 `HSM_SNAPSHOT_STALE`，被拒绝的恢复不得改动任何状态。

硬约束：24 个线程同时 use 同一个 max_uses=10 的句柄，必须恰好 10 次成功、14 次 `HSM_USE_LIMIT`，uses 最终为 10；同一应用重连轮换期间对同一对象的并发使用只能看到旧句柄或新句柄之一，不能出现句柄丢失；登录计数、句柄分配、对象表和审计写入都在同一把可重入锁内完成。audit 新的在前，超出容量丢最旧的。

验收：`python3 -m pytest -q tests` 的 15 条必须全过，不得改测试、跳过或按固定输入写死；并发与重启恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
