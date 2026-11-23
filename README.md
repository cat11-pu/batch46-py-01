# GSB Bugfix Task

## 题面

集团把 AD 拆成三个域之后，网关的目录搜索开始跟着 referral 乱跳。一次是新子域上线，referral 指向一个未登记的第三方目录，网关把绑定账号和密码原样带了过去，等于把服务账号送人；一次是两个域互相引用，请求在两条 referral 之间来回跳，线程池被打满，登录接口整体超时；还有一次对方返回两百多兆的结果集，网关直接 OOM。上个月做容量评估时才发现，网关对这些 referral 既没有白名单，也没有记账，谁返回的地址都敢跟。审计给的要求很直接：只跟白名单域，凭据不许跨域透传，跳数要有上限，结果集大小要卡死，referral 记录要有过期时间，网关重启后记录不能全丢。改造范围是 gsb/batch46-safety-a-05，实现文件 ldap_referral_guard.go，类型 LdapReferralGuard，任务类型 Bugfix。

需要保留的公开能力：

- NewLdapReferralGuard(p ReferralPolicy) *LdapReferralGuard
- NewLdapReferralGuardFromSnapshot(p ReferralPolicy, data []byte) (*LdapReferralGuard, error)
- (g *LdapReferralGuard) AllowDomain(domain string) error
- (g *LdapReferralGuard) RegisterHomeBind(tenantID, host, bindDN, password string) error
- (g *LdapReferralGuard) RegisterCredential(tenantID, host, bindDN, password string) error
- (g *LdapReferralGuard) BindPlan(tenantID string, ref Referral) (BindRequest, error)
- (g *LdapReferralGuard) ResolveChain(tenantID string, refs []Referral, now time.Time) ([]ReferralHop, error)
- (g *LdapReferralGuard) CheckResponseSize(n int) error
- (g *LdapReferralGuard) Seen(url string, now time.Time) (bool, error)
- (g *LdapReferralGuard) Prune(now time.Time) int
- (g *LdapReferralGuard) Stats() ReferralStats

故障与边界：

1. AllowDomain 登记允许跟随的域名，匹配必须按 DNS 标签边界：host 等于域名或以点加域名结尾，evilcorp.example.com 不能因为后缀像 corp.example.com 就放行；
2. 空链或链里出现空 URL 返回 ErrInvalidReferral，不能把空串当成本域处理；
3. referral 的 scheme 只接受 ldaps，ldap 明文返回 ErrScheme；
4. host 不在白名单返回 ErrDomainNotAllowed，并把这次链校验计入 Rejected；
5. 同一条链里 URL 重复出现返回 ErrReferralLoop，不能当成重试继续跳；
6. 链长度超过 MaxHops 返回 ErrHopLimit，并且要在逐个解析前就拒绝整条链；
7. 新 URL 数量加上未过期的已记忆数量超过 MaxReferrals 返回 ErrReferralCapacity；第 5 到 7 条的任何拒绝都不能留下半条记忆记录；
8. BindPlan 对登记过的 home host 返回 home bind；跨域 host 只有通过 RegisterCredential 登记过才返回对应凭据，否则必须返回 ErrNoCredential，绝不能回退到 home 密码；
9. BindRequest 的 Host 要剥掉端口，只留主机名，URL 里的 userinfo 和多余路径不能混进主机名；
10. ResolveChain 返回的 hop 顺序与入参一致，URL、BaseDN、Scope 原样保留，CrossDomain 按是否 home host 标记；Followed 累加 hop 数，CrossDomain 累加跨域 hop 数；
11. CheckResponseSize 在 n 等于 MaxResponseSize 时放行，超过返回 ErrResponseTooLarge；
12. Seen 在 CacheTTL 内返回 true、过期返回 false，Prune 返回清理条数；Snapshot 只携带已记忆的 referral，白名单和绑定凭据在启动时重新登记，恢复后 Seen 结论不变。

硬约束：同一条链被并发解析时，每个 URL 只能记一次，Followed 和 SeenEntries 的计数必须精确；重启恢复后的记录继续按原时间点算剩余寿命，不能整体续期；记忆条目和响应大小都要有硬上限，不能因为对方域返回大结果集把网关内存顶爆；所有时间判断使用入参 now，不读系统时钟，否则回放对不上。

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
