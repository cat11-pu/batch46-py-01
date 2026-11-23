# GSB Bugfix Task

## 题面

晚上八点，某园区的虚拟化平台开始丢包：同一台宿主机上的两台虚机互相指责对方网关换了 MAC，监控里能看到一批 IPv6 邻居条目在几分钟内被同一个 MAC 刷走，邻居缓存从三百条涨到两万多条，连交换机的 MAC 表都跟着抖动。这套邻居缓存防护目前是空壳，需要补齐：模块路径 `gsb/batch46-safety-c-03`，文件 `ndp_cache_guard.go`，类型 `NdpGuard`，任务类型 Bugfix，骨架中已有的方法签名不要改动。

对外接口：`Bind(ip, mac, iface, tenantID string) error` 安装静态绑定；`Process(adv Advertisement, now time.Time) error` 处理一条邻居通告；`Lookup(ip string, now time.Time) (Neighbor, bool)` 读取当前视图；`Probe(ip string, now time.Time) error` 把陈旧条目推进探测态；`Confirm(ip, mac string, now time.Time) error` 完成探测；`Purge(iface string) int` 按接口清空；`Len() int`；`Stats() Stats`；`Snapshot() ([]byte, error)` 与 `NewNdpGuardFromSnapshot(cfg Config, data []byte) (*NdpGuard, error)` 负责快照恢复。

需要逐条落地的行为：

1. 首次通告建立 `reachable` 条目，IP、MAC、接口、租户、状态和更新时间都能通过 `Lookup` 读回；同一 IP 同一 MAC 再通告是刷新不是新增，`Len` 不变、`UpdatedAt` 前进。
2. 动态条目换 MAC：`AllowOverride` 关闭时返回 `ErrSpoof` 且原 MAC 原样保留；打开时更新 MAC，但状态必须落到 `stale`，要再走一次探测确认才重新可信。
3. 通过 `Bind` 安装的静态绑定任何情况下都不能被通告改 MAC，即使 `AllowOverride` 打开也要返回 `ErrSpoof`，`Static` 标记、接口和租户都不能被改写。
4. 同一地址出现在另一个接口返回 `ErrInterface`，被另一个租户认领返回 `ErrTenant`；校验顺序是租户、接口、MAC，不要先改状态再报错。
5. 一个 MAC 名下地址数达到 `MaxIPsPerMAC` 后，新地址返回 `ErrQuota`；`Purge` 掉对应接口后配额要真正释放，同一 MAC 能重新加入。
6. 缓存达到 `MaxEntries` 时只能淘汰 `stale` 条目，按 `UpdatedAt` 最老的先淘汰，并用 IP 字典序打破平局；`reachable`、`probe` 和静态条目都不能淘汰；没有可淘汰条目时返回 `ErrFull`，`Len` 不得超过上限。
7. `ReachableTime` 内没有流量，`Lookup` 把状态衰减为 `stale`；超过 `ReachableTime + StaleTime` 仍未刷新则返回未找到，不要让过期条目无限占位。
8. `Probe` 只接受当前视图为 `stale` 的条目，其余状态返回 `ErrState`；`Confirm` 必须处于 `probe` 态，MAC 一致才回到 `reachable`；MAC 不一致返回 `ErrSpoof` 并把条目退回 `stale`；对非 `probe` 条目调用 `Confirm` 返回 `ErrState`。
9. 静态条目永远按 `reachable` 返回；`Purge(iface)` 删除该接口上的全部条目（含静态）并返回删除条数；`Len` 与 `Stats` 的 `Entries`/`Static`/`Probes` 必须和表内实际一致。
10. 无法解析的 IP、非法 MAC、空接口名、空租户都返回 `ErrInvalid`，任何失败路径都不能留下半条记录或改坏已有条目的时间戳。
11. 快照要带上每条条目的状态、`UpdatedAt`、静态标记、接口和租户；重启恢复后静态绑定继续拒绝换 MAC，动态条目按原有时间衰减，`Len` 与 `Stats` 和重启前一致。

硬约束：两个 MAC 并发抢同一地址时恰好一个成功、另一个拿 `ErrSpoof`，表里只能有一条且不能出现数据竞争；缓存容量和单 MAC 配额在并发下都不能被突破；被拒绝的通告必须完全无副作用；重启恢复后状态机与快照前一致。

验收：`go test ./...` 的 15 条测试必须全过；不得修改测试、跳过或用固定输入写死；并发与重启场景自行写验证程序确认；只在本地实现，不需要接真实交换机。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 地狱
