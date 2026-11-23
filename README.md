# GSB Bugfix Task

## 题面

三家云厂商的 STS 都接到了同一套工作负载联邦服务上，最近两周的审计报告里出现了三类可疑兑换：有工作负载拿一份还有效的令牌在十秒内换了三份凭据，令牌的 jti 完全没有被记住；有一套跑在测试集群里的 Pod 拿着生产信任域的标识，换到了生产只读角色；还有离职团队遗留的工作负载在被下线一周后仍然能继续兑换，因为吊销只能按角色做，做不到按主体做。更麻烦的是凭据侧没有数量上限，某次压测一次性签出了四千多份两小时有效的凭据，把云厂商的配额打满，事后连哪些凭据还在用都查不清。联邦服务需要重写兑换与校验这一段：模块路径 gsb/batch46-safety-b-10，文件名 workload_identity_guard.go，类型名 WorkloadIdentityGuard，任务类型 Bugfix。

公开接口按骨架来：NewWorkloadIdentityGuard(Config) *WorkloadIdentityGuard；BindRole(RoleBinding) error；UnbindRole(tenantID, subjectPrefix string) error；BindingFor(tenantID, subject string) (RoleBinding, error)；RevokeSubject(tenantID, subject string) error；ReinstateSubject(tenantID, subject string) error；Exchange(Token, tenantID string, ttl time.Duration, now time.Time) (Credential, error)；Validate(credValue string, now time.Time) (Credential, error)；RevokeCredential(credValue string) error；Outstanding(now time.Time) int；Snapshot() ([]byte, error)；NewWorkloadIdentityGuardFromSnapshot(Config, []byte) (*WorkloadIdentityGuard, error)。

必须覆盖的行为：

1. 令牌的 Domain 和 Subject 都必须落在配置的信任域内，否则 ErrTrustDomain；Subject、JTI、时间窗缺失或签名不通过属于 ErrTokenInvalid；
2. audience 必须与配置完全一致，差一个字符也返回 ErrAudience；
3. 已过期的令牌返回 ErrTokenExpired；令牌签发时的有效期长度超过 MaxTokenTTL 的，即使还没过期也按 ErrTokenInvalid 拒绝；
4. 同一 jti 在 ReplayTTL 内只能兑换一次，第二次返回 ErrReplay，失败的那次不能占用 jti；
5. 角色绑定按租户和 Subject 前缀注册，取最长前缀命中；没有命中返回 ErrNoRole，别的租户注册的前缀不算；绑定字段不全或 MaxTTL 非正数返回 ErrBindingInvalid；
6. 被 RevokeSubject 的负载返回 ErrRevoked，ReinstateSubject 之后恢复；吊销按租户隔离，重复吊销和重复恢复都不报错；
7. 请求的 ttl 必须大于 0 且不超过 MaxCredTTL，否则 ErrTTLTooLong；命中绑定的 MaxTTL 更小时，签发时长取两者较小值而不是报错；
8. 未过期凭据数量达到 MaxOutstanding 时返回 ErrCredCap，已过期凭据不占额度，被拒绝的兑换不得留下凭据；
9. Validate 对未知凭据报 ErrCredUnknown，对已吊销的报 ErrRevoked，对过期凭据报 ErrCredExpired；
10. RevokeCredential 必须立刻生效，哪怕凭据还在有效期内；对未知凭据吊销报 ErrCredUnknown；
11. BindingFor 返回实际命中的绑定，UnbindRole 删除后立刻变成 ErrNoRole，删除不存在的前缀报 ErrBindingInvalid；
12. 签发出的凭据要带 RoleARN、Subject、TenantID 和到期时刻，到期时刻等于兑换时刻加上生效时长，同一时刻签出的多份凭据值互不相同。

硬约束：同一 jti 的并发兑换只能成功一次，检查与占用必须原子完成；Snapshot 要带上绑定、主体吊销、已用 jti、已签发凭据和计数器，重启后重放与吊销继续生效，Outstanding 也接着算；过期凭据在超过 MaxCredTTL 的保留期后要清理，不能让内存随时间线性增长。

验收：go test ./... 的 15 条用例全过，不得改测试或跳过；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
