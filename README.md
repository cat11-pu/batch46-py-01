# GSB Bugfix Task

## 题面

服务账号 JWT 交换上线后，安全评审复现了五个问题：换 token 时不校验受众，同一个 jti 在有效期内能换多次，scope 可以随便加，委托链能无限套，配额只在日志里看着像有；进程重启后重放记录和吊销状态还全丢了。代码在模块 gsb/batch46-safety-a-09 的 gcp_sa_jwt_guard.go，类型 SaJwtGuard，任务类型 Bugfix。这条链路每天要换几万个 token，既有集群内工作负载，也有跨项目的数据导入任务，任何一个环节放宽都会直接变成越权访问；审计里已经能看到同一断言被重复兑换的痕迹，重放窗口必须真正落地。委托链在多级运维场景里很常见，但链路上每一跳都必须显式声明，不能靠拼接字符串绕过。

接口：NewSaJwtGuard(cfg Config) *SaJwtGuard、NewSaJwtGuardFromSnapshot(cfg Config, data []byte) (*SaJwtGuard, error)、RegisterServiceAccount(email, project string) error、AllowSubjectDelegation(email, subject string) error、ScopeSet(scopes []string) ([]string, error)、Exchange(a Assertion, now time.Time) (AccessToken, error)、JTIUsed(jti string) (bool, error)、QuotaRemaining(email string, now time.Time) (int, error)、RevokeToken(value string) error、ValidateToken(value, requiredScope string, now time.Time) (AccessToken, error)、PruneJTIs(now time.Time) int、Snapshot() ([]byte, error)。

问题与边界：1）断言的 issuer、jti、audience、iat、exp 任一为空或零值 ErrMalformed；签名无效 ErrSignature；audience 与配置不一致 ErrAudience。2）exp 必须晚于 iat，且 exp 减 iat 不超过 MaxAssertionTTL，否则 ErrMalformed。3）now 晚于 exp 加 MaxSkew 返回 ErrExpired，now 加 MaxSkew 早于 iat 返回 ErrNotYet，正好等于边界允许。4）签发者必须在注册表里，否则 ErrUnknownIssuer。5）ScopeSet 去空白、去重、升序；空集合、空白项、非绝对 URL 都 ErrScope，请求的每个 scope 都必须出现在 AllowedScopes，否则一样是 ErrScope。6）带 subject 的断言必须先由 AllowSubjectDelegation 登记，否则 ErrSubject，为未注册账号登记委托返回 ErrUnknownIssuer；subject 与 delegates 同时出现 ErrChain。7）delegates 超过 MaxDelegates、含空项、含签发者本身或重复成员都 ErrChain。8）同一 jti 在 JTITTL 内第二次交换返回 ErrReplay，并发同一 jti 只能有一个成功；成功后 JTIUsed 为 true，空 jti ErrMalformed。9）每个签发者按 QuotaWindow 滑动窗口计数，超过 QuotaPerWindow 返回 ErrQuota，被拒的交换不占配额，QuotaRemaining 反映窗口内剩余。10）发出的 token 值必须是 64 位小写十六进制；Subject 取断言 subject，没有则取 issuer；Scopes 为规范序；ExpiresAt 为 now 加 TokenTTL；有 subject 或 delegates 时 Impersonated 为 true。11）ValidateToken 对未知值 ErrMalformed、已吊销 ErrTokenRevoked（重复吊销不算错、吊销未知值 ErrMalformed）、过期 ErrExpired、缺 requiredScope ErrScope。12）Snapshot 要保存 jti、已发 token、吊销位和配额，恢复后重放仍拦住、吊销仍生效，PruneJTIs 按 TTL 清理并返回数量；并发交换、校验、吊销必须安全。

硬约束：jti 判定与配额计数必须原子，被拒请求不产生副作用；jti、token 与配额窗口都有 TTL 或窗口上限，不能无界增长。值班同学需要随时问出某个账号在当前窗口还能换多少次，因此配额必须解释得清；失败请求更不能把配额吃掉，否则一次攻击就能把正常任务全部拖死。broker 前面还有一层网关，断言会先被缓存再转发，因此判断必须完全依赖断言内容本身，不能假设调用顺序；重启在滚动发布时每天都会发生，恢复后既不能放过已经用过的断言，也不能把正常令牌全部作废。

验收：go test ./... 的 15 条测试全部通过，不得修改测试、跳过或按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
