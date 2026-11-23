# GSB Bugfix Task

## 题面

机房双栈改造上线第二天，值班同事发现核心交换机下面混进来一台贴着家用固件的小路由器，它每隔几秒发一次路由通告，把一批服务器的默认网关改成了 `fe80::99`，还把某个前缀的 preferred lifetime 设得比 valid 还长；从服务器侧抓包看得清清楚楚，接入环节一条通告校验都没做。现在补这块防护，范围是模块 `gsb/batch46-safety-c-02`、文件 `ipv6_ra_guard.go`、类型 `RaGuard`，任务类型 Bugfix，骨架里的方法签名保持不变。

对外接口：`TrustPort(ifName string) error` 与 `UntrustPort(ifName string) error` 维护可信接口；`TrustRouter(linkLocal, tenantID string) error` 登记可信路由器；`Revoke(linkLocal string) error` 吊销；`Process(ra RouterAdvert, now time.Time) error` 校验一条通告并更新表项；`DefaultRouters(now time.Time) []Router` 取当前默认路由；`IsDefaultRouter(addr string, now time.Time) bool` 单点判断；`LearnedPrefixes(now time.Time) []string` 取有效前缀；`Sweep(now time.Time) int` 清理过期数据；`Stats() Stats`；`Snapshot() ([]byte, error)` 与 `NewRaGuardFromSnapshot(cfg Config, data []byte) (*RaGuard, error)` 负责快照恢复。

需要逐条落地的行为：

1. 通告只能从 `TrustPort` 登记过的接口进来，否则返回 `ErrPort`；源地址必须是 `TrustRouter` 登记过的链路本地地址，否则返回 `ErrRouter`，被 `Revoke` 之后立刻按未登记处理，不能还留着默认路由身份。
2. 通告里的 `TenantID` 必须等于该路由器登记时的租户，不一致或为空返回 `ErrTenant`。
3. 收到通告时的 `HopLimit` 必须正好是 255，其他值返回 `ErrHopLimit`。
4. `RouterLifetime` 为负或超过 `MaxRouterLifetime` 返回 `ErrLifetime`；等于 0 表示撤销自己的默认路由，这条通告本身仍要通过其余校验。
5. 每个前缀选项的长度必须恰好等于 `PrefixLength`（当前 64），否则返回 `ErrPrefixLen`，不要接受 /48 或 /72 再自行裁剪。
6. ULA 前缀（fc00::/7）默认返回 `ErrULA`，只有配置打开 `AllowULA` 之后才允许学习并出现在 `LearnedPrefixes` 里。
7. `ManagedFlag` 打开而 `AllowManaged` 为 false 时返回 `ErrManaged`。
8. 前缀选项的 `PreferredLifetime` 为负或大于 `ValidLifetime` 返回 `ErrPrefixLifetime`；`ValidLifetime` 为 0 表示撤销该前缀，路由器本身保持默认。
9. 同一源地址在 `MinAdvertInterval` 内重复通告返回 `ErrRate`，超过间隔后恢复接受；限速只按源地址记，一个路由器不要牵连别的源。
10. 合法通告要落成默认路由：地址、接口、租户、寿命、学习时间都要能读回；`DefaultRouters` 按地址排序，`LearnedPrefixes` 按字符串排序，结果是确定的。
11. 默认路由表达到 `MaxRouters` 后，新源的通告返回 `ErrCapacity`；这条被拒的通告不能占名额、不能刷新限速状态，`Sweep` 腾出名额之后同一来源要能重新通过。
12. `Sweep(now)` 清理到期路由和前缀并返回清掉的路由数；`IsDefaultRouter`、`DefaultRouters` 对到期路由必须直接返回否/空，`Stats` 的计数与表内实际条目一致；空接口名、无法解析的前缀等非法输入返回 `ErrInvalid` 而不是 panic。

硬约束：同一份通告被并发提交两次时只能被接受一次，另一次拿 `ErrRate`，默认路由表不能出现重复条目；被拒绝的通告必须完全无副作用，不能部分更新前缀表；快照要把可信接口、可信路由器、默认路由表和前缀表一起带上，进程重启恢复后这些表项、寿命和排序行为与重启前一致。

验收：`go test ./...` 的 15 条测试必须全过；不得修改测试、跳过或用固定输入写死；并发和重启场景自行写验证程序确认；只在本地实现，不需要真的接交换机。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
