# GSB Bugfix Task

## 题面

安全加固平台上周把一批 Web 服务的 AppArmor 配置从 complain 切到 enforce，结果两台机器在发布窗口直接失联：加载新 profile 时老进程还挂在旧代次上，回滚又找不到可用的历史版本，值班同学只能手工重启。事后复盘发现 profile 的加载、切换和回滚没有共享同一份代次账本，进程与 profile 的关联只是临时变量，重启即丢，审计日志也只留下最后一条。问题落在 gsb/batch46-safety-e-01 的 apparmor_profile_guard.py，AppArmorGuard 负责 profile 注册、代次历史、可执行文件挂载、进程 confinement 与 hat 栈，任务类型 Bugfix。现在要按下面的接口把它补成一套可回滚、可审计的状态机：

register_profile(self, name: str, *, mode: str = "enforce", attachments: Sequence[str] = (), body: str = "", flags: dict | None = None) -> dict
load_profile(self, name: str, body: str, *, generation: int | None = None) -> dict
replace_profile(self, name: str, body: str, *, expect_generation: int | None = None, mode: str | None = None) -> dict
switch_mode(self, name: str, mode: str) -> dict
rollback(self, name: str, generation: int) -> dict
attach(self, name: str, executable: str) -> dict
detach(self, name: str, executable: str) -> dict
confine(self, pid: int, profile_name: str) -> dict
release(self, pid: int) -> dict
enter_hat(self, pid: int, hat: str) -> dict
exit_hat(self, pid: int) -> dict
state(self, name: str) -> dict
snapshot(self) -> dict
restore(self, snapshot: dict) -> dict
audit(self, limit: int | None = None) -> list[dict]

需要修正的行为：

1. 同名 profile 重复注册报 APPARMOR_DUP_PROFILE；mode 不是 enforce/complain 报 APPARMOR_MODE_INVALID，且失败注册不得留下任何 profile 或 executable 索引。
2. 注册时若 attachments 已被别的 profile 占用，报 APPARMOR_ATTACH_CONFLICT，整次注册回滚；之后单独注册另一个 executable 必须成功，证明没有半写入。
3. 同一 profile 重复 load 完全相同的 body 返回 unchanged 且 generation 不变；body 变化才生成严格递增的新代次并写入历史。state() 要返回 mode、generation、body、按字典序排列的 attachments、confined 计数和 revisions 条数。
4. replace_profile 带 expect_generation 且与当前代次不符时抛 APPARMOR_STALE_GENERATION，body、mode、generation 原样保留。
5. 有 pid 挂在某 profile 下时，切到 complain 必须报 APPARMOR_BUSY；release 之后可以切，并推进代次；重复切到当前 mode 返回 unchanged。
6. rollback 按历史代次恢复 body 与 mode，恢复动作本身要产生比当前更大的新代次，不能复用旧号；目标代次不存在报 APPARMOR_UNKNOWN_GENERATION；回滚到当前代次返回 unchanged；历史按代次升序保存，重复文本不得制造空代次。
7. attach 重复挂载同一 executable 返回 unchanged；detach 未挂载项报 APPARMOR_ATTACH_UNKNOWN；一个 executable 任何时刻只能属于一个 profile。
8. profile 总数超过 max_profiles 或挂载总数超过 max_attachments 时报 APPARMOR_LIMIT，拒绝后注册表、索引、代次都不变。
9. 同一 pid 重复 confine 报 APPARMOR_PID_CONFINED；release 未知 pid 报 APPARMOR_PID_UNKNOWN；confined 计数按 profile 实时统计；confinement 以 pid 为键，同一 pid 同时只能挂在一个 profile 下。
10. hat 栈深超过 max_hat_depth 报 APPARMOR_HAT_DEPTH，空栈 exit 报 APPARMOR_HAT_EMPTY，未 confine 的 pid 操作 hat 报 APPARMOR_PID_UNCONFINED，连续进入同名 hat 返回 unchanged。
11. audit 每条带自增 seq，只保留最近 max_audit 条；limit 取尾部若干条；动作名要能区分 register、load、replace、mode、attach、detach、confine、release，方便复盘时还原时间线。
12. snapshot 必须深拷贝 profile、历史、pid 与审计，恢复后所有表一致；非法快照报 APPARMOR_SNAPSHOT_INVALID，且当前状态不被破坏。

硬约束：replace_profile 的乐观并发必须原子，多个线程拿着同一个 expect_generation 同时替换，只能有一个成功，其余全部是 stale，最终 generation 只加一次；所有表在同一把可重入锁内更新，查询也不能读到半更新的代次；快照恢复要能跨“重启”把 confinement、挂载和代次一起还原；所有上限都是硬上限，超过就拒绝而不是截断。

验收标准：在项目根执行 python3 -m pytest -q tests，15 条测试全部通过；不得改测试、跳过或用固定输入写死结果；并发与恢复场景自行加线程和快照往返验证；只做本地实现，不接真实内核。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 困难
