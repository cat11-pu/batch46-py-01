# GSB Bugfix Task

## 题面

宿主机安全代理上线 ptrace scope 以后，值班同学收到的误报和漏报叠在一起：同 uid 的兄弟进程在 scope=1 下还能 attach；父进程刚退出，子进程的跟踪关系没有释放，新进程复用同一个 pid 后直接继承旧的 busy 状态；reparent 把进程挂到自己的子节点下，祖先遍历绕不出去；scope=2 下普通进程仍然 attach 成功；scope=3 下带特权的巡检进程也被一刀切挡住；detach 一个并不持有目标的跟踪者却返回成功；tracer 退出后它挂的所有目标仍显示 attached；审计只保留最后几条，统计却对不上；快照恢复后进程树和 busy 关系丢了；八个巡检进程同时 attach 同一个目标，最后全部成功。修复范围在模块 gsb/batch46-safety-e-08 的 ptrace_scope_guard.py，类型 PtraceGuard，任务类型 Bugfix，只用 Python 标准库，失败统一抛 PtraceError，异常对象带 code 与 detail。

接口按骨架保持：register_process(self, pid: int, *, uid: int = 0, ppid: int = 1, comm: str = "proc", privileged: bool = False) -> dict、process_info(self, pid: int) -> dict、unregister_process(self, pid: int) -> dict、reparent(self, pid: int, new_ppid: int) -> bool、children(self, pid: int) -> list[int]、ancestors(self, pid: int) -> list[int]、set_scope(self, level: int) -> int、scope(self) -> int、check_attach(self, pid: int, tracer_pid: int) -> dict、attach(self, pid: int, tracer_pid: int) -> dict、detach(self, pid: int, tracer_pid: int) -> bool、detach_all(self, tracer_pid: int) -> int、attachments(self) -> dict、stats(self) -> dict、audit(self, limit: int | None = None) -> list[dict]、snapshot(self) -> str、restore(cls, data: str) -> "PtraceGuard"。

scope 只接受 0 到 3，非法值抛 PT_BAD_SCOPE，set_scope 返回旧级别。注册要求 pid 为正、uid 非负、comm 非空，父进程只能是 1 或已存在，重复注册抛 PT_EXISTS，父进程不存在抛 PT_UNKNOWN_PPID，其他未知 pid 统一抛 PT_UNKNOWN；process_info 返回 pid、uid、ppid、comm、privileged、attached_by 与 children，unregister_process 对未知 pid 抛 PT_UNKNOWN。判定顺序固定：自己 attach 自己抛 PT_SELF；scope=3 一律 PT_SCOPE_DENY；uid 不同且 tracer 不带特权抛 PT_DAC_DENY；scope=2 且 tracer 不带特权抛 PT_SCOPE_DENY；scope=1 且 tracer 不带特权且不是目标祖先抛 PT_NOT_ANCESTOR；目标已被其他 tracer 持有抛 PT_BUSY。同一 tracer 重复 attach 同一目标不算错误，返回 already 为 True，重复计数单独记入 already。

check_attach 是只读预判，返回 allowed、code、already、target、tracer，绝不改变持有关系；attach 在拒绝时抛对应 code，成功时返回 allowed、already、target、tracer，目标同一时刻只能有一个 tracer。detach 只在调用者确实是持有者时返回 True，否则 False；detach_all 撤销该 tracer 的全部持有并返回数量。unregister_process 让直接子进程改挂到 1，删除该进程作为目标和作为 tracer 的全部持有，返回 reparented 与 detached 两个计数；同一 pid 重新注册必须是全新状态，不能继承旧 attachment。reparent 遇到新父节点是自身或自己的后代时抛 PT_CYCLE，父节点不变时返回 False，children 按 pid 升序，ancestors 从直接父进程一路列到 1。

attachments 返回目标 pid 到 tracer pid 的映射。stats 至少给出 registered、attaches、already、denied、detaches、exits、reparents；审计缓冲最多 audit_capacity 条，审计行含 event 与 code，按发生顺序记录 attach、attach_already、attach_denied、detach、detach_all、exit、reparent。snapshot 保存 scope、进程树、持有关系、统计和审计，restore 恢复后 ancestors、attachments、busy 判定、特权标记都必须一致，坏数据抛 PT_SNAPSHOT_INVALID。

八个 tracer 并发 attach 同一个目标时只能有一个成功，其余必须拿到 PT_BUSY；六百层深的进程链上连续做三百次祖先预判要在两秒内完成，且 check_attach 不能留下任何 attachment。重放旧 pid 的注册必须得到全新状态，旧跟踪关系不得复活；scope 调整立即影响后续判断。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过或用固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 困难
