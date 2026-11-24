# GSB Bugfix Task

## 题面

网关把 access token 的自省结果缓存在本地，上周一次批量下线把问题全掀了出来。管理员撤销某个用户后，缓存里仍是 active，业务继续放行十几分钟；上游自省服务抖动时缓存又恰好集体过期，几百个请求同时打过去把自省接口打挂；短命 token 的 exp 只剩五秒，缓存却按默认十分钟记录，过期 token 被反复命中；匿名 token 每次返回 inactive，网关照旧每个请求问一次上游；scope 不足的 token 命中了完整缓存，越权调用照样通过；缓存没有容量上限，压测时内存一路涨到 OOM；淘汰只看写入顺序，热点 token 被冷 token 挤掉；撤销名单和缓存分开维护，进程重启后撤销记录全丢；快照恢复把已经过期的条目原样装回来；监控面板上 upstream_calls 与 cache_hits 之和跟实际请求量对不上。

范围是 gsb/batch46-safety-a-02 下的 oidc_introspection_cache.py，类 IntrospectionCache，任务类型 Bugfix，负责自省结果缓存、撤销名单、容量控制与快照。上游由构造参数注入：`IntrospectionCache(introspect_fn, *, max_entries: int = 128, max_ttl: float = 60.0, negative_ttl: float = 5.0, clock=None)`，introspect_fn 接收 token 字符串并返回 {"active": bool, "scope": str, "exp": float} 形态的字典。公开接口（Python 类型注解）：`check(token: str, *, scopes=None, now=None) -> dict`；`prefetch(tokens, *, now=None) -> dict`；`revoke(token: str, *, expires_at=None, now=None) -> bool`；`is_revoked(token: str, now=None) -> bool`；`invalidate(token: str) -> bool`；`purge(now=None) -> int`；`snapshot() -> dict`；`restore(state: dict) -> None`；`stats() -> dict`；`reset_stats() -> None`；`usage() -> dict`。上游返回结构非法抛 IntrospectionError(code, detail)。

故障与边界：一、命中缓存的 check 必须返回 cached=True 且不再调用上游，ttl 是剩余秒数；二、正向缓存时间取 max_ttl 与 exp 减 now 的较小值，等于过期时刻即刷新；三、inactive 结果按 negative_ttl 缓存，且 negative_ttl 大于 max_ttl 时按 max_ttl 截断；四、已撤销 token 直接返回 {"active": False, "code": "OIDC_REVOKED", "cached": True}，不得调用上游，重复撤销返回 False；五、撤销可带 expires_at，到期后 is_revoked 返回 False 并允许重新自省，purge 负责清掉过期撤销；六、scopes 参数要求 token 的 scope 全覆盖，缺一个就返回 {"active": False, "code": "OIDC_SCOPE_MISSING", "missing": [...]}，该拒绝响应不写入缓存，上游给出的有效结果仍按自身 TTL 保留；七、缓存按 max_entries 做 LRU 淘汰，读取命中也要刷新最近使用顺序，淘汰计入 evictions；八、upstream 返回非字典或 active 不是布尔值抛 OIDC_UPSTREAM_INVALID；九、prefetch 对重复 token 去重，返回 requested、cached、fetched 三个计数；十、invalidate 只删缓存不动撤销名单，返回是否删到；十一、snapshot/restore 覆盖缓存条目、撤销名单和统计，恢复后命中缓存不再打上游，结构非法抛 OIDC_SNAPSHOT_INVALID 且原状态不变；十二、purge 同时清理过期缓存与过期撤销，返回删除总数，usage 反映当前条目数和撤销数。

硬约束：同一 token 并发冷启动只能触发一次上游调用，其余线程等待后直接拿缓存结果；check、revoke、purge 与快照操作都要加锁，统计计数不能丢；缓存条目数不得超过 max_entries，禁止无界增长；快照要能跨进程恢复，统计中的 upstream_calls、cache_hits、cache_misses、evictions、revocations 必须精确对账，reset_stats 全部归零。

验收：`python3 -m pytest -q tests` 的 15 条测试全部通过；不得修改测试、跳过或按固定输入写死；并发与重启恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
