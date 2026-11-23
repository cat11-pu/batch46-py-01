# GSB Bugfix Task

## 题面

tenant-b 的采集节点在新扩容的 VNI 5000 上抓到了 tenant-a 的数据库心跳，运维核对后发现两个租户的 VNI 被同一条学习记录覆盖：后注册的租户直接接管了前一个租户的 VNI，内层源 MAC 还能跨 VNI 迁移，表项过了理论寿命也不消失，单租户的表项数量没有任何上限。消息面平稳了两周，这次是凭一条广播才被发现，两个可用区的隔离策略实际上都处在失效状态。

请修复 gsb/batch46-safety-c-07 中 vxlan_tenant_guard.go 的 VxlanGuard，任务类型 Bugfix，只改本地实现。

需要遵守的公开接口（签名不得改动）：

- NewVxlanGuard(cfg Config) *VxlanGuard
- NewVxlanGuardFromSnapshot(cfg Config, data []byte) (*VxlanGuard, error)
- (*VxlanGuard) BindVNI(vni int, tenantID string) error / UnbindVNI(vni int) (int, error) / TenantForVNI(vni int) (string, error)
- (*VxlanGuard) Learn(frame Frame, now time.Time) error
- (*VxlanGuard) Lookup(vni int, mac string, now time.Time) (Entry, error)
- (*VxlanGuard) Expire(now time.Time) int / TenantMACCount(tenantID string) int
- (*VxlanGuard) Snapshot() ([]byte, error) / Stats() Stats

具体现象与边界：

1. 可用 VNI 是 1 到 16777214；0、16777215、负数和超过 24 位的值都返回 ErrVNIRange，范围检查必须在建立绑定之前完成，失败不能留下半条归属记录。
2. 同一个 VNI 被另一个租户绑定时返回 ErrVNIBound，原租户的归属保持不变；同一租户重复绑定要幂等成功。
3. 未绑定 VNI 上执行 TenantForVNI、Learn、Lookup 一律返回 ErrTenantUnknown，不能隐式创建租户。
4. Learn 成功后 Entry 必须带回 MAC、VNI、TenantID、SrcIP，LearnedAt 等于传入的 now，这些字段是审计和对账的依据，不能只存 MAC 与 VNI。
5. 同一个 MAC 出现在另一个租户的 VNI 上返回 ErrMACConflict，原表项保持原样；同一租户内换 VNI 同样返回 ErrMACConflict，禁止 MAC 漂移。
6. 单租户存活的 MAC 数量达到 MaxMACsPerTenant 后，新 MAC 返回 ErrMACLimit 且不落表，已有表项不受影响；配额按租户累计，只有释放、过期或解绑后才回落。
7. 同一个 MAC 在它当前 VNI 上重复 Learn 只刷新 SrcIP 与 LearnedAt，不新增条目，Stats 的 Learned 只计一次。
8. 表项寿命按 LearnTTL 计算：恰好到 TTL 的 Lookup 视为过期返回 ErrNotFound，早 1 纳秒仍可查到，边界不能靠四舍五入蒙混过去。
9. Expire 删除所有到期表项并返回删除数量，同时累加 Stats 的 Evicted；TenantMACCount 只统计当前存留条目，过期但尚未扫描的条目不能继续计入上限。
10. UnbindVNI 解除绑定并清掉该 VNI 上的全部表项，返回清掉的条数；之后 TenantForVNI 与 Lookup 都要返回 ErrTenantUnknown。
11. 同一个 MAC 被两个租户并发 Learn，必须恰好一个成功，另一个拿到 ErrMACConflict，两个租户的计数合计为 1。
12. Snapshot 要包含 VNI 归属和全部已学习表项，经 NewVxlanGuardFromSnapshot 恢复后 TenantForVNI 与 Lookup 结果一致，租户计数也保持一致。

硬约束：冲突检查、配额检查和写入必须是一个原子动作，不能出现“检查通过后又被另一个租户插队”；租户表项总数受 MaxMACsPerTenant 限制，不能靠重放请求无限增长；TTL 扫描不能误删仍在寿命内的表项，快照恢复后归属与表项要与恢复前一致。

验收：go test ./... 的 15 条测试全部通过；不得修改测试、跳过或用固定输入写死结果；并发与恢复场景自行验证；只做本地实现，不涉及上游提交。

交付：修改后的源码与测试通过记录，附一段简要说明，写清学习、刷新、过期三条路径的区别。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
