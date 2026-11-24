# GSB Bugfix Task

## 题面

早上九点，网关开始出现零星的签名校验失败：身份提供方凌晨轮换了公钥，新 kid 在缓存里查不到，网关每个请求都去拉一次 JWKS，把对端限流打满；缓存过期后对端刚好抖动，明明手里还有十分钟内的旧公钥，网关却直接拒绝全部令牌。更糟的是两个租户的 kid 撞名，A 租户的令牌被 B 租户的公钥验过，日志里出现跨租户的 subject。运维还发现密钥退役接口只改了展示状态，旧公钥仍然能验签，重叠期配置形同虚设。任务在 `gsb/batch46-safety-b-03`，文件 `jwks_rotation_guard.py`，任务类型 Bugfix，修 `JwksGuard`，发布、轮换、缓存刷新、验签四条路径共用同一份内存状态。

公开接口（与骨架一致）：`__init__(self, *, ttl=300, refresh_cooldown=30, max_stale=900, max_keys=8, now=0)`；`add_issuer(self, issuer) -> dict`；`publish_key(self, issuer, kid, *, material, alg="RS256", not_before=None, expires_at=None, now=None) -> dict`；`retire_key(self, issuer, kid, *, now=None) -> dict`；`rotate(self, issuer, *, kid, material, overlap=60, alg="RS256", now=None) -> dict`；`set_endpoint_healthy(self, issuer, healthy) -> dict`；`keys(self, issuer, *, now=None) -> dict`；`verify(self, token, *, issuer, now=None) -> dict`；`refresh(self, issuer, *, now=None, force=False) -> dict`；`cache_info(self) -> dict`；`stats(self) -> dict`；`audit_log(self) -> list`；`snapshot(self) -> dict`；类方法 `restore(cls, state)`。

令牌是字典，含 iss、kid、alg、payload、signature。签名输入是 `iss|kid|alg|payload紧凑JSON` 的 UTF-8 字节，payload 按 key 升序、分隔符为逗号与冒号且不加空格，HMAC-SHA256 取小写十六进制。需要修的点：

1. `add_issuer` 重复注册报 JWKS_ISSUER_EXISTS，未注册的 issuer 验签报 JWKS_UNKNOWN_ISSUER；`publish_key` 在同一 issuer 内 kid 重复报 JWKS_DUP_KID，已退役或已过期的同名 kid 允许重新发布。
2. 每 issuer 活跃密钥数不得超过 max_keys，超出报 JWKS_KEY_LIMIT；`retire_key` 立即从缓存移除该 kid，未知 kid 报 JWKS_UNKNOWN_KID。
3. `keys` 与 `verify` 一样按 TTL 加载缓存，按发布顺序返回未退役且未过期的密钥，元素至少含 kid、alg，不返回 material。
4. 缓存为空时首次验签触发一次拉取；缓存年龄大于等于 ttl 时先尝试刷新，刷新成功用新缓存。
5. 拉取失败时若缓存年龄不超过 max_stale，继续用旧缓存验签并在结果里把 stale 置为真；超过 max_stale 报 JWKS_CACHE_STALE。失败次数计入 stats 的 failures。
6. 未知 kid 在 refresh_cooldown 秒内最多触发一次额外拉取，冷却期内直接报 JWKS_UNKNOWN_KID；冷却结束后允许再拉一次，拉取失败也按未知 kid 处理。
7. 验签顺序：令牌缺字段报 JWKS_MALFORMED_TOKEN，令牌 iss 与入参 issuer 不等报 JWKS_ISSUER_MISMATCH，算法与密钥不一致报 JWKS_ALG_MISMATCH，key 未到 not_before 报 JWKS_KEY_NOT_YET_VALID，到达 expires_at 报 JWKS_KEY_EXPIRED，签名不符报 JWKS_BAD_SIGNATURE。
8. 验签成功返回 payload 副本、kid、issuer 和 stale 标志，不得把内部缓存对象直接暴露给调用方。
9. `rotate` 发布新密钥并立即刷新缓存，旧密钥的 expires_at 置为 now 加 overlap，返回 kid、previous、previous_expires_at；重叠期内旧密钥仍可验签，边界等于 expires_at 时拒绝。
10. 跨 issuer 隔离：不同 issuer 出现相同 kid 时只能各用各的 material，混用必须验签失败，不能退化成全局 kid 表。
11. 并发硬约束：八个线程同时用未知 kid 验签，全流程只能发生一次拉取，八个调用都报 JWKS_UNKNOWN_KID，刷新计数只能加一，缓存加载与计数递增必须在同一临界区内。
12. 快照恢复：snapshot 必须可 JSON 序列化，restore 之后 issuer、密钥、缓存内容与 cache_at、冷却时间、刷新与失败计数全部延续；恢复后的实例在 TTL 内验签不得再次拉取。

验收：在项目根执行 `python3 -m pytest -q tests`，15 条必须全部通过；不得修改测试、跳过或按固定输入写死；并发与重启恢复场景请自行验证；只做本地实现，除 pytest 外不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
