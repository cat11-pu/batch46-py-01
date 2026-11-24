# GSB Bugfix Task

## 题面

昨夜值班组切换了新的 TACACS+ 网关，设备授权和计费都落到 gsb/batch46-safety-a-06 的 tacacs_authz_guard.py，类型是 TacacsGuard，任务类型 Bugfix。上线后故障单堆了一摞：低权限账号执行 reload 被拒，升到十五级后仍然被拒，看起来上一次判断被缓存住了；两个命令组的规则拼在一起时，同一个账号在两台设备上得到相反结果，顺序完全取决于注册时怎么填 groups；一条 deny 规则排在 show * 前面，却被后面的通配规则放行了；没注册的临时账号直接拿到拒绝回执，而不是明确的未知用户错误；计费面重复提交同一个 session id，两次都开成功，报表里一台设备挂了两条会话；会话关闭以后再补发流量计数，接口不报错，还把已关闭的会话改了；计数器回退也能写进去，账单算成负数；新会话把表撑满后没有回收，正常登录全部失败；补丁回滚重启后会话快照丢了，已关闭的会话又变回打开；审计日志没有上限，一天涨到两百万行把磁盘写满；多线程授权时审计条数和实际请求数对不上。模块路径 gsb/batch46-safety-a-06，文件名 tacacs_authz_guard.py，类名 TacacsGuard，请按下面的契约补齐实现。

关键接口保持现有骨架：define_command_set(name: str, *, rules: Sequence[Mapping[str, Any]], default: str = "deny") -> dict；register_user(username: str, *, privilege: int = 1, groups: Sequence[str] = ()) -> dict；set_privilege(username: str, privilege: int) -> dict；authorize(username: str, command: str, *, device: str | None = None) -> dict；account_start(username: str, session_id: str, *, device: str, started_at: int | None = None) -> dict；account_update(session_id: str, *, bytes_in: int | None = None, bytes_out: int | None = None) -> dict；account_stop(session_id: str, *, stopped_at: int | None = None, reason: str = "normal") -> dict；sessions(username: str | None = None) -> list[dict]；snapshot() -> dict；restore(state: Mapping[str, Any]) -> None；purge_closed() -> int；audit(limit: int | None = None) -> list[dict]。

具体故障与边界如下。命令规则按列表顺序匹配，命中即停，deny 排在前面就不能被后面的 show * 翻案，未命中时取命令集的 default，放行返回 TAC_PERMIT，规则拒绝返回 TAC_DENY_RULE，默认拒绝返回 TAC_DENY_DEFAULT，规则序号是规则列表里的全局下标。规则的 min_privilege 高于用户当前等级时跳过该条继续看后面的规则，而不是直接拒绝；set_privilege 返回的用户记录里 privilege 必须是新值，下一次 authorize 立即生效。未注册用户调用 authorize 抛 TacacsError，code 为 TAC_DENY_UNKNOWN_USER，不能伪装成普通 deny。多个组的规则按 groups 顺序拼接，后一个组不能因为更严格就提前生效。同一 session id 重复 account_start 抛 TAC_DUP_SESSION，第一次建立的设备信息不能被覆盖。account_stop 用 stopped_at 减 started_at 得到 elapsed，未知或已清理的会话抛 TAC_NO_SESSION。account_update 的 bytes_in 和 bytes_out 只增不减，回退抛 TAC_COUNTER_REGRESS 并保留旧值，已关闭会话再更新抛 TAC_SESSION_CLOSED。活跃会话数达到 max_sessions 时新会话抛 TAC_SESSION_LIMIT，关闭会话释放名额，已关闭会话不占名额。sessions 按 session_id 升序返回，可按用户名过滤，行里至少要有 session_id、user、device、status、started_at、bytes_in、bytes_out。重新 define_command_set 后旧授权结论立即失效。审计只保留最近 max_audit 条，按发生时间从旧到新返回，audit(limit) 取最近 limit 条，每条至少带 command 和 code。

硬约束：authorize 与 account_start 必须并发安全，六路各两百次授权后结果全部为 permit、审计恰好一千二百条；同一个 session id 被八个线程同时抢占时只能有一个成功，其余七个拿到 TAC_DUP_SESSION。snapshot 必须返回深拷贝，restore 用它完整替换用户、命令集、会话、审计和计数器，恢复后已关闭的会话仍是关闭状态，恢复快照不能被后续修改污染；恢复后再授权要按快照里的规则判断。资源上限是硬要求，审计保留 max_audit 条、会话上限 max_sessions 条，超出按上面的错误码处理，不能靠无限增长兜底。

验收：python3 -m pytest -q tests 的 15 条测试必须全部通过；不得修改测试、跳过或用固定输入写死返回值；并发与快照恢复需要自己写脚本验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
