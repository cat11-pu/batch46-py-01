# GSB Bugfix Task

## 题面

数据平台把工作负载身份从静态密钥切到服务账号 JWT 交换后，跨项目调用开始随机 401：同一个断言换出的令牌有时全量权限、有时只剩只读，原因是 scope 没有排序去重，缓存键每次都不一样；安全评审又发现更严重的问题，伪造 alg 为 none 的断言可以换到有效令牌；已经过期十分钟的断言仍能通过，因为校验拿 exp 和 iat 比大小而不是和当前时间比；签发时间比当前时间快五分钟的断言也直接放行；audience 完全不校验，拿 A 服务的断言能换 B 服务的令牌；请求的 scope 只要和断言里任意一项有交集就整包下发，越权拿到写权限；jti 重放检测只存在进程内，滚动发布后同一个断言可以再用一次；服务账号以 subject 冒充任意用户时没人拦；访问令牌表只增不减，一周堆了几十万条；令牌撤销后 introspect 仍返回 active；八路并发交换同一断言时会同时成功两次，账单出现双份调用；快照恢复后重放缓存和令牌状态全丢。模块路径 gsb/batch46-safety-a-09，文件名 gcp_sa_jwt_guard.py，类名 SaJwtGuard，任务类型 Bugfix。

接口以骨架为准：register_service_account(email: str, *, secret: str, scopes: Sequence[str]) -> dict；allow_delegation(email: str, subject: str) -> dict；create_assertion(email: str, *, audience: str, scope: Sequence[str] | None = None, now: int, lifetime: int = 3600, subject: str | None = None, jwt_id: str | None = None) -> dict；decode_assertion(token: str) -> dict；exchange(assertion: str, *, audience: str, requested_scope: Sequence[str], now: int) -> dict；introspect(access_token: str, *, now: int) -> dict；revoke_token(access_token: str) -> dict；purge_replays(cutoff: int) -> int；purge_expired_tokens(*, now: int) -> int；snapshot() -> dict；restore(state: Mapping[str, Any]) -> None；stats() -> dict。

具体规则与边界。断言是紧凑 JWT，头部只允许 HS256，段用无填充 base64url；载荷包含 iss、sub、aud、iat、exp、jti、scope，scope 是空格连接的已排序去重列表。create_assertion 返回 assertion、jti、exp、iat、scope，lifetime 必须大于零且不超过 max_lifetime，超出抛 SaJwtError，code 为 JWT_LIFETIME_TOO_LONG；scope 为 None 时取该服务账号登记的全部 scope；subject 默认等于 iss。exchange 的检查顺序是解析与算法、签发者、签名、audience、生命期、时间窗、委派、scope、重放、令牌容量：非三段或载荷解析失败返回 JWT_MALFORMED，算法不是 HS256 返回 JWT_ALG_NONE，签发者未登记返回 JWT_UNKNOWN_ISSUER，签名不符返回 JWT_BAD_SIGNATURE，audience 不一致返回 JWT_BAD_AUDIENCE，exp 减 iat 超过上限返回 JWT_LIFETIME_TOO_LONG，iat 晚于 now 加 skew 返回 JWT_NOT_YET_VALID，now 大于等于 exp 返回 JWT_EXPIRED，subject 不等于 iss 且不在该账号的委派白名单里返回 JWT_DELEGATION_DENIED，请求的任一 scope 不在断言 scope 或账号登记 scope 内返回 JWT_SCOPE_NOT_GRANTED，jti 用过返回 JWT_REPLAY，活跃令牌已满且无过期记录返回 JWT_TOKEN_LIMIT。成功后签发 opaque 访问令牌，前缀 ya29.，token_type 为 Bearer，expires_in 取 3600 与断言剩余生命期的较小值，scope 按排序去重返回，sub 为实际主体。introspect 对未知、过期或已撤销令牌返回 active 为 False，否则带 sub、scope、exp、iat；revoke_token 返回 revoked 布尔。purge_replays 删除 used_at 小于等于 cutoff 的 jti 并返回条数，purge_expired_tokens 删除 exp 小于等于 now 的访问令牌并返回条数。

硬约束：jti 的重放判定与登记必须原子，八路并发交换同一断言只能有一个成功、七个 JWT_REPLAY，stats 里 exchanged 记一次、rejected 记七次；访问令牌表受 max_tokens 限制，满了先允许显式清理过期记录，仍满才报 JWT_TOKEN_LIMIT，不能无限增长；snapshot 深拷贝服务账号密钥、委派白名单、重放缓存、访问令牌和统计，restore 完整替换，恢复后已用断言仍判 JWT_REPLAY、快照之后对原对象的撤销不影响恢复结果。stats 至少含 asserted、exchanged、rejected 三个计数。

验收：python3 -m pytest -q tests 的 15 条测试必须全部通过；不得修改测试、跳过或按固定输入写死；并发与快照恢复需要自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
