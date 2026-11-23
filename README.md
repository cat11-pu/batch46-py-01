# GSB Bugfix Task

## 题面

HR 系统每小时往内部用户目录推一次增量，最近一个月出了四起数据事故：已经离职删除的账号在下一轮同步里被同一个 externalId 重新建了出来，权限跟着回来了；同一条变更事件被上游重试三次，用户版本号一路涨到 7，下游缓存全部失效；两个不同的人用了同一个邮箱，目录里出现两个账号，登录时随机命中其中一个；批量接口返回 500 时一半用户已经写进去、另一半没写，第二天对账差了三百多人。另外分页游标用的是偏移量，同步过程中有人新增就会漏页；网关重启后删除标记清零，被删的人又被加了回来。这次要把增量同步做成可重放、可恢复的，模块路径 gsb/batch46-safety-a-04，实现文件 scim_provisioning_guard.go，类型 ScimGuard，任务类型 Bugfix。

需要保留的公开能力：

- NewScimGuard(p ScimPolicy) *ScimGuard
- NewScimGuardFromSnapshot(p ScimPolicy, data []byte) (*ScimGuard, error)
- (g *ScimGuard) Apply(user User, expectedVersion int) (ApplyResult, error)
- (g *ScimGuard) Patch(tenantID, userID string, ops []PatchOperation, expectedVersion int) (ApplyResult, error)
- (g *ScimGuard) Delete(tenantID, externalID string, expectedVersion int, now time.Time) error
- (g *ScimGuard) Get(tenantID, userID string) (User, error)
- (g *ScimGuard) ByExternalID(tenantID, externalID string) (User, error)
- (g *ScimGuard) Batch(tenantID string, users []User) ([]ApplyResult, error)
- (g *ScimGuard) Page(tenantID, cursor string, limit int) ([]User, string, error)
- (g *ScimGuard) Tombstoned(tenantID, externalID string, now time.Time) (bool, error)
- (g *ScimGuard) Snapshot(now time.Time) ([]byte, error)
- (g *ScimGuard) Stats() ScimStats

故障与边界：

1. Apply 以租户加 externalId 为键，首次创建时 UserID 取 tenantID 加斜杠加 externalId，Version 从 1 开始，Created 为 true；
2. 内容完全一致的重放（用户名、启用状态、邮箱集合、组集合全相同）直接返回当前版本，Created 为 false，版本不涨，即使 expectedVersion 落后也不报冲突；
3. 内容有变化且 expectedVersion 等于当前版本时版本加一、Updated 加一；expectedVersion 落后返回 ErrVersionConflict 且不落盘；expectedVersion 为 -1 跳过版本检查；
4. 同一租户内两个用户的邮箱集合不允许有交集，冲突返回 ErrDuplicateEmail，且不能留下半个用户；跨租户同邮箱允许；
5. 邮箱和组在写入前要去重并按字典序排序，Get 返回的顺序必须是稳定排序后的结果；
6. Delete 按 externalId 删除并记录删除时刻，版本不符返回 ErrVersionConflict；删除后 Get 返回 ErrNotFound，Tombstoned 为 true，Users 减一、Tombstones 加一；
7. 墓碑有效期内用同一 externalId 重新 Apply 返回 ErrDeleted；墓碑过期后由 PruneTombstones 清掉并返回条数，清掉之后 Tombstoned 为 false；
8. Patch 支持 groups 的 add/remove 和 userName 的 replace，未知 op 或 path 返回 ErrInvalidPatch 且版本不动；一次 Patch 最多涨一个版本；
9. Batch 整批使用入参 tenantID，先整批校验再落盘，任何一条失败整批不写并返回对应错误；成功时结果顺序与入参一致；
10. 批量条数超过 MaxBatch 返回 ErrBatchTooLarge；用户总数超过 MaxUsers 返回 ErrCapacity；
11. Page 按 UserID 升序返回，cursor 取上一页最后一条的 UserID，最后一页 cursor 为空；五个用户、每页两条时分三页取完；
12. Snapshot 要包含存活用户和墓碑，重启恢复后 ByExternalID、Tombstoned 与统计数字都对得上；Stats 的 Users、Tombstones、Created、Updated、Deleted 要与实际状态一致。

硬约束：同一 externalId 被并发 Apply 时只能出现一次 Created，其余请求看到同一个版本 1，不能建出两个用户；重启恢复后的墓碑继续拒绝重建，不能因为内存清零把已删账号放回来；批量写入必须整批原子，失败不留半条记录；所有时间判断使用入参 now，不读系统时钟，否则回放和补数对不上。

验收：go test ./... 的 15 条用例全部通过；不得修改测试、跳过用例或按固定输入写死；并发和重启恢复要自行验证；只做本地实现，不涉及上游仓库。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
