# GSB Bugfix Task

## 题面

网关的令牌自省接口最近连着出了几起值班事故。先是离职员工的 access token 被管理员在 IdP 侧禁用后，业务接口还能继续调用，最长拖了五分钟才断；接着一次大促前的预热把缓存过期时间对齐到同一秒，过期瞬间几百个请求同时穿透到 IdP，把自省接口打到限流，网关大面积 502；还有租户 A 的 token 在租户 B 的请求里命中了同一条缓存，下游直接按错误主体授权。现在要把这层缓存重做，模块路径 gsb/batch46-safety-a-02，实现文件 oidc_introspection_cache.go，类型 IntrospectionCache，任务类型 Bugfix。

需要保留的公开能力：

- NewIntrospectionCache(p CachePolicy, upstream UpstreamFunc) *IntrospectionCache
- NewIntrospectionCacheFromSnapshot(p CachePolicy, upstream UpstreamFunc, data []byte) (*IntrospectionCache, error)
- (c *IntrospectionCache) Lookup(token, tenantID string, now time.Time) (TokenInfo, error)
- (c *IntrospectionCache) Revoke(token, tenantID string, now time.Time) error
- (c *IntrospectionCache) Revoked(token, tenantID string, now time.Time) (bool, error)
- (c *IntrospectionCache) Invalidate(token, tenantID string) error
- (c *IntrospectionCache) Flush() int
- (c *IntrospectionCache) Resize(max int) error
- (c *IntrospectionCache) Prune(now time.Time) int
- (c *IntrospectionCache) Snapshot(now time.Time) ([]byte, error)
- (c *IntrospectionCache) Stats() CacheStats

故障与边界：

1. 同一 token 在同一租户下 TTL 内重复查询只允许调用一次上游，主体、客户端、scope、过期时间要和首次结果一致；
2. 超过 TTL 的条目必须重新自省，不能继续把旧结果返回给业务；
3. active 为 false 的结果按 NegativeTTL 缓存，不能套用正向 TTL，否则禁用状态要多拖几分钟；
4. 上游报错返回 ErrUpstream，失败结果不进缓存，下一次查询必须重新打上游；
5. 本地撤销的 token 查询直接返回 ErrRevoked，且不得调用上游；撤销时同时删掉该 token 的正向缓存条目；
6. 撤销有效期长于缓存 TTL 时，缓存过期后仍要返回 ErrRevoked；撤销到期后恢复自省，重新向上游取结果；
7. 令牌自身的 ExpiresAt 早于缓存 TTL 时，缓存存活期取两者中更早的，不能返回已过期令牌的 active 结果；
8. 并发查询同一个 key 只能发生一次上游调用，其余请求等这次调用的结果，不许各自穿透；
9. 缓存 key 必须带租户维度，同一个 token 串在不同租户下互不影响；
10. 条目数达到 MaxEntries 时按最近最少使用淘汰，Evictions 计数要对得上；Resize 缩小上限要淘汰多余条目，传 0 返回 ErrBadCapacity；
11. Snapshot 要带上未过期条目和撤销标记，进程重启恢复后命中缓存不再打上游，撤销依旧生效；
12. Prune 返回清理条数，只统计缓存条目，撤销标记不计入返回值；Flush 返回清空条数，Entries 要实时反映当前条目数，别让监控面板读到滞后一拍的数字；CacheStats 里的 Hits、Misses、UpstreamCalls、Evictions、Entries 都要如实累计，值班靠它判断穿透和命中比例。

硬约束：单飞合并要覆盖同一 key 的整段上游调用，不允许先用后写导致并发下重复探测；重启恢复后的条目剩余寿命按快照时刻计算，不能整体续期；缓存条目数必须有硬上限，早高峰批量令牌不能把网关内存顶爆；撤销标记不占正向条目名额，但自身也要有过期清理；查询是只读语义，读路径不能把别的协程正在更新的条目写坏。所有时间判断一律用入参 now，不要读系统时钟，否则测试和回放对不上。

验收：go test ./... 的 15 条用例全部通过；不得修改测试、跳过用例或按固定输入写死；并发和重启恢复要自行验证；只做本地实现，不涉及上游仓库。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
