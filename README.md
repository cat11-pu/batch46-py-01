# GSB Bugfix Task

## 题面

证书轮换的窗口里，API 网关出现大面积 401：旧公钥刚被标记为 retired 就从缓存里消失，按旧 kid 签发、还有二十分钟才过期的访问令牌全部失效；同一 kid 在缓存未命中时被两百个并发请求各自回源，身份提供方限流后整批校验失败，回源风暴还把提供方的配额打穿，后续十分钟所有服务都拿不到新密钥；有服务把 alg 为 none 的 key 塞进缓存，随后任意 token 都能通过；还有别的租户的 token 用了不属于本服务的 issuer，却照样验签成功。这次事故发生在证书轮换的十分钟窗口内，网关团队临时把缓存 TTL 调到一天才止血，但这让刚下线的密钥仍有被信任的风险。请在模块 gsb/batch46-safety-b-03 的 jwks_rotation_guard.go 中修复类型 JwksGuard，任务类型 Bugfix，覆盖密钥发布、退休、轮换、回源和快照恢复。

需要保持的接口：NewJwksGuard(cfg Config, src KeySource) *JwksGuard；NewJwksGuardFromSnapshot(cfg Config, src KeySource, data []byte) (*JwksGuard, error)；PublishKey(k Key, now time.Time) error；RetireKey(kid string, now time.Time) error；KeyFor(kid string, now time.Time) (Key, error)；Verify(h Header, c Claims, now time.Time) (Key, error)；Refresh(kid string, now time.Time) (Key, error)；WarmCache(keys []Key, now time.Time) error；Rotate(oldKID string, k Key, now time.Time) error；Snapshot() ([]byte, error)。

故障与边界：1) kid 为空、alg 不在 ES256/RS256/PS256/EdDSA 内或 ExpiresAt 不晚于 NotBefore，PublishKey 返回 ErrKeyInvalid，alg=none 绝对不能进入缓存；2) ExpiresAt 超过 now+KeyTTL 要截断，十一分钟后 KeyFor 返回 ErrKeyExpired，截断后的过期时间要能被 KeyFor 直接看到；3) 缓存条目超过 MaxKeys 返回 ErrTooManyKeys；4) 未知 kid 返回 ErrKeyNotFound，不能和过期密钥混用同一个错误，未注册 key 也不能触发一次隐式回源；5) Verify 要求 header.Alg 与 key.Alg 完全一致，否则 ErrAlgMismatch，token 过期 ErrTokenExpired，issuer 不符 ErrIssuerMismatch，audience 不符 ErrAudienceMismatch，声明校验失败时不能返回任何 key；6) RetireKey 之后 KeyGrace 内 KeyFor 仍可用，超过宽限期返回 ErrKeyExpired，宽限期内只允许验签，不允许再用于签发新令牌，过期时间的比较要包含边界；7) WarmCache 必须全有或全无，其中一个 key 非法时缓存保持原样并返回 ErrKeyInvalid；8) Rotate 先校验新 key，校验失败时旧 key 不得被退休；9) Refresh 对同一 kid 的并发调用只能触发一次 KeySource，所有调用共享结果，等待中的调用不能各自拿到不同的 key，源错误要能被 errors.Is 识别为 ErrSourceFailed，回源结果写回缓存前要重新检查容量；10) MaxKeys=10 时五十个并发 PublishKey 只能成功 10 个，缓存大小不能超过上限，失败的那些必须返回明确错误，不能静默丢弃；11) Snapshot 保存 key 集合与 Generation 计数，恢复后 KeyFor 可用且 Generation 不变，恢复过程不依赖 KeySource，Generation 用来判断缓存是否发生过变化；12) 轮换之后旧 key 在 KeyGrace 内仍能验旧 token，新 key 立即能验新 token。

并发回源、重启恢复、密钥容量和令牌时限这几类约束都要落到实现里，不能只覆盖串行 happy path；回源失败不能污染已有缓存。验收：go test ./... 的 15 条用例必须全部通过；不得修改测试、跳过用例或按固定输入写死；并发、重启和轮换场景要自行验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
