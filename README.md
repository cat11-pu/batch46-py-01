# GSB Bugfix Task

## 题面

上周城域接入网割接后，运维在夜间告警里发现两件事：部分政企客户的 CPE 连续拿到别家租户的前缀，还有一台没有登记过的委派路由器在链路里下发地址，接入侧的前缀委派防护一条都没拦住。现在要把这块防护补齐，范围是模块 `gsb/batch46-safety-c-01`、源文件 `dhcpv6_guard.go`、类型 `Dhcpv6Guard`，任务类型 Bugfix，骨架里已有的方法签名保持不变。

对外接口：`AddServer(duid, tenantID string) error` 登记可信委派路由器；`RevokeServer(duid string) error` 吊销；`AddPool(cidr string) error` 登记可下发地址池；`Screen(adv Advertise, now time.Time) (Offer, error)` 校验 Advertise 并生成待提交的 Offer；`Commit(offerID string, now time.Time) (Lease, error)` 把 Offer 落成租约；`LeaseFor(clientDUID string, iaid uint32) (Lease, bool)` 查租约；`Release(clientDUID string, iaid uint32, now time.Time) error` 释放；`Expire(now time.Time) int` 清理到期数据；`Stats() Stats` 看占用；`Snapshot() ([]byte, error)` 与 `NewDhcpv6GuardFromSnapshot(cfg Config, data []byte) (*Dhcpv6Guard, error)` 负责快照恢复。

需要逐条落地的行为：

1. 未登记的 server 发来的 Advertise 必须返回 `ErrServer`；已登记但被 `RevokeServer` 吊销的 server 同样按不可信处理，不能因为租约还在就继续放行。
2. 前缀长度必须落在 `MinPrefixLen` 与 `MaxPrefixLen` 之间（含端点，配置是 48 到 64），越界返回 `ErrPrefixLen`，不允许截断后照发；长度合法但不在任何 `AddPool` 池内的前缀返回 `ErrPool`，比池更大的前缀（池是 /48、报到 /40）也属于池外。
3. 广告里的 `TenantID` 必须等于服务器登记时的租户，不一致或为空返回 `ErrTenant`。
4. `ValidLifetime` 为 0、`PreferredLifetime` 为负或大于 `ValidLifetime` 都返回 `ErrLifetime`，不要静默纠正成合法值。
5. 同一 server 对同一 `(clientDUID, IAID)` 在 `AdvertiseInterval` 内重复下发要返回 `ErrRate`，超过间隔后重新放行；限速表按 server 和客户端分别记，不要一个客户端把同一 server 的其他客户端连带限死。
6. `Commit` 出来的租约带 T1 = 租期一半、T2 = 租期 80%，租期取广告 `ValidLifetime` 与 `LeaseTTL` 的较小值；`ExpiresAt`、T1、T2 要能原样从 `LeaseFor` 读回。
7. 同一 `(clientDUID, IAID)` 重复提交同一个 Offer 必须幂等：返回原租约、不延长到期时间、租约计数不增加；同一 IA_PD 换另一个前缀提交则返回 `ErrBound`。
8. 与任何活动租约前缀重叠的新租约返回 `ErrConflict`，被包含的更具体前缀（例如 /57 落在活动 /56 里）也算重叠；`Release` 或 `Expire` 之后同一前缀才允许重新分配。
9. 每租户活动租约数达到 `MaxLeasesPerTenant` 时，新客户提交返回 `ErrQuota`；这条失败的提交不能消耗 Offer、不能留下占位，`Release` 出一个名额后同一个 Offer 仍要能提交成功。
10. 未知的 offerID、或已过 `OfferTTL` 的 Offer 返回 `ErrNoOffer`；所有失败路径都不允许留下半个租约、改坏已有租约或把已提交的 Offer 算两次。
11. `Expire(now)` 只清理到期的租约和 Offer 并返回清掉的租约数，提前调用返回 0；被清掉的租约 `LeaseFor` 必须查不到，`Release` 一个不存在的租约返回 `ErrNoLease`。
12. 空 `clientDUID`、无法解析的前缀等非法输入返回 `ErrInvalid`，不要 panic。

硬约束：并发提交必须原子，两个客户端同时提交互相重叠的前缀时恰好一个成功、另一个拿 `ErrConflict`，租约表与限速表在并发下不能重复分配；快照要带上可信服务器（含吊销状态）、地址池、活动租约及其 T1/T2 与到期时间，进程重启恢复后继续拒绝重叠和重复提交，`Stats` 计数与重启前一致；重复提交与失败回滚必须幂等，任何一次失败都不能改变已有租约或占用名额。

验收：`go test ./...` 的 15 条测试必须全过；不得修改测试、跳过或用固定输入写死；并发与重启场景自行写验证程序确认；只在本地实现，不需要对接真实 DHCPv6 设备。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
