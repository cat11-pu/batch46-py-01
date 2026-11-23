# GSB Bugfix Task

## 题面

上周安全评审复现了一个登录重放问题：值班同学把同一份已经用过的 SAML 断言原样再提交一次，门户照样放行，还把用户重新登进了后台，等于绕过了二次认证。追下来发现断言校验只看签名和有效期，断言 ID 没有落库，时间窗内可以反复提交；受众、目的地只比了前缀，多改一段路径也能过；请求号和应答的对应关系没人校验；签名失败和重放还共用同一个错误码，值班时根本分不清是伪造还是重放。这批问题要在 gsb/batch46-safety-a-01 里修掉，实现文件 saml_assertion_replay_guard.go，类型 SamlReplayGuard，任务类型 Bugfix，相关结构体和方法的骨架已经在该文件里给出。

需要保留的公开能力：

- NewSamlReplayGuard(p Policy) *SamlReplayGuard
- NewSamlReplayGuardFromSnapshot(p Policy, data []byte) (*SamlReplayGuard, error)
- (g *SamlReplayGuard) RegisterServiceProvider(tenantID, entityID, acsURL string, audiences []string) error
- (g *SamlReplayGuard) TrackRequest(tenantID, requestID string, now time.Time) error
- (g *SamlReplayGuard) Validate(a Assertion, requestID string, now time.Time) (Identity, error)
- (g *SamlReplayGuard) AssertionSeen(tenantID, id string, now time.Time) (bool, error)
- (g *SamlReplayGuard) RevokeSubject(tenantID, subject string, until time.Time) error
- (g *SamlReplayGuard) SubjectRevoked(tenantID, subject string, now time.Time) (bool, error)
- (g *SamlReplayGuard) Snapshot(now time.Time) ([]byte, error)
- (g *SamlReplayGuard) Prune(now time.Time) int
- (g *SamlReplayGuard) Stats() Stats

故障与边界：

1. 断言 ID 在 ReplayTTL 内二次提交返回 ErrReplay，并累计 ReplayHits；AssertionSeen 在窗口内返回 true，过期或被 Prune 清掉后返回 false；
2. Audience 不在该租户注册的受众里返回 ErrAudienceMismatch；
3. InResponseTo 不是已登记请求号返回 ErrUnknownRequest，断言 ID 与请求号分别登记、互不替代；
4. NotOnOrAfter 早于当前超过 MaxClockSkew 返回 ErrAssertionExpired，NotBefore 晚于当前超过 MaxClockSkew 返回 ErrAssertionInvalid，偏差在 MaxClockSkew 内（例如 NotOnOrAfter 比现在早 10 秒）必须放行，不能因为 IdP 和门户时钟差几秒就把整批登录打回重试；
5. 签名未通过返回 ErrSignature，且不能同时被判定为重放；
6. 签发方不是该租户登记的 entity id 返回 ErrIssuerUnknown；
7. Destination 必须与注册的 ACS 地址逐字相等，多一段路径、大小写或结尾斜杠不同都要拒绝并返回 ErrDestination；
8. 断言携带的租户与请求登记租户不一致返回 ErrTenantMismatch，这条要单独判定，不能被受众校验顺带放过；
9. 被撤销的主体在撤销截止前一律返回 ErrSubjectRevoked，截止之后恢复放行，撤销记录本身不能占重放表的名额；
10. 重放表达到 MaxReplayEntries 后新断言返回 ErrCapacity，不许静默淘汰仍在有效期内的记录，Stats 的 ReplayEntries 要等于当前表内条数；
11. 校验通过返回的 Identity 要带租户、主体、签发方、断言 ID 与属性副本，属性要深拷贝，调用方改动返回值不能影响后续判定。

硬约束：同一断言 ID 被并发提交时只能有一个成功，其余必须是 ErrReplay，不能出现两边都换到会话的窗口；快照要包含未过期的断言 ID，进程重启恢复后继续拒绝同一断言，Prune 清掉过期记录并返回清理条数，返回值只算断言 ID 与撤销记录，请求登记表不计入；重放表有内存上限，不能因为一次早高峰批量登录把内存顶爆；只有校验通过的断言才占用重放表，被拒绝的输入不能留下半条记录，否则攻击者可以拿畸形断言把正常用户的 ID 空间挤掉。

验收：go test ./... 的 15 条用例全部通过；不得修改测试、跳过用例或按固定输入写死；并发和重启恢复要自行验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
