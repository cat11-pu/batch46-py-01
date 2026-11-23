# GSB Bugfix Task

## 题面

凌晨割接后核心交换机出了一串怪事：过期会话还能下发配置，同一个会话标识被两台设备复用，甲租户的规则放行了乙租户的命令，重复上报的计费把字节数算了两遍。相关逻辑在模块 gsb/batch46-safety-a-06 的 tacacs_authz_guard.go，类型 TacacsGuard，任务类型 Bugfix，需要把会话、授权、计费三条链路一起修好。值班同学查了两晚，确认不是设备侧的问题，而是我们自己的 AAA 服务把状态放错了地方。这批设备分布在三个机房，白天有存量会话，夜里还有批量作业，所以修复不能靠重启清状态，也不能让某个租户的规则忽然失效。

接口按现有骨架实现：NewTacacsGuard(cfg Config) *TacacsGuard、NewTacacsGuardFromSnapshot(cfg Config, data []byte) (*TacacsGuard, error)、Authenticate(sessionID, user, deviceID, tenantID string, now time.Time) error、SessionActive(sessionID string, now time.Time) (bool, error)、ExpireSessions(now time.Time) int、AddRule(r Rule) error、RuleCount() int、Authorize(req AuthorizeRequest, now time.Time) (Decision, error)、Accounting(rec AcctRecord, now time.Time) error、AcctUsage(taskID string) (int64, error)、Prune(now time.Time) int、Snapshot() ([]byte, error)。

具体要改的点：1）会话在 now 到达 expires 的瞬间失效，之前仍可授权；2）未过期的重复会话标识返回 ErrArgInvalid，过期后允许同名重建；3）单设备活跃会话数达到 MaxSessions 后返回 ErrLimit，已过期的不计入；4）授权先查会话，未知、过期、用户或租户不符一律 ErrUnauthenticated，规则不跨租户共享；5）规则按 Order 升序、同序按 Name 排序取第一条命中，deny 返回 ErrNotAuthorized、Decision.Rule 为规则名、AVs 为空，无命中时 Rule 为 default-deny；6）Rule.Args 为 nil 表示任意参数，否则长度一致且逐项相等，单项 "*" 通配，permit 按声明顺序返回 AV；7）参数个数超过 MaxArgs 返回 ErrLimit，正好等于上限放行；8）计费 Flags 仅接受 start/watchdog/stop，其余 ErrArgInvalid；未 start 的 watchdog/stop、重复 start、重复 stop 均 ErrAccounting，被拒记录不得改动累计字节；9）watchdog 与 stop 的 Bytes 累加，AcctUsage 返回累计值，未知任务 ErrAccounting，计费前会话必须存活且属于同一用户，否则 ErrUnauthenticated；10）ExpireSessions 只清会话并返回删除数，Prune 同时清过期会话与超过 AcctRetention 的已关闭任务并返回两者之和；11）Snapshot 覆盖会话、规则、计费，重启恢复后会话仍活跃、规则仍生效、累计字节不变；12）授权与计费并发执行时结果与串行一致。

硬约束：状态判定与写入必须在一把锁内完成，重复会话和重复 start 的判定要原子；被拒绝的请求不能留下任何副作用；会话数与计费保留期必须有界，不能无限增长。自动化巡检会拿同一份会话连续调用，幂等性必须经得住重复请求，计费数据也要能对上账。割接窗口只有十分钟，修复要能在不打断存量会话的前提下生效，任何状态迁移都得可回放、可核对；计费口径以设备侧上报为准，服务端只做累加与保留，不允许在查询时二次折算。

验收：go test ./... 的 15 条测试全部通过，不得修改测试、跳过或按固定输入写死；并发与重启场景自行验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
