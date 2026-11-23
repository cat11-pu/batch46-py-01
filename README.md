# GSB Bugfix Task

## 题面

凌晨两点，CI 流水线批量报错说拿不到云上临时凭证，安全团队同时收到越权告警：一个来自 repo:acme/payments-evil 的 PR 任务被授予了支付仓库的发布权限，排查发现 subject 匹配把星号当成可以跨冒号的通配，仓库名多一段后缀也能命中；同一个 id_token 在十分钟内被重放四次，每次都换到新凭证；还有作业拿一小时有效期的 token 通过了只允许十分钟的信任策略；更离谱的是，已经删除的信任策略仍在继续发授权。告警在凌晨持续了二十分钟，值班同学先手工放行了整条流水线，事后要求两件事：越权的 subject 必须被模式挡住，重放的 token 必须留下可查询的记录。请在模块 gsb/batch46-safety-b-02 的 ci_oidc_trust_guard.go 中修复类型 CiOidcGuard，任务类型 Bugfix，把策略注册、subject 与 ref 匹配、时间校验和重放窗口做成完整链路。

需要保持的接口：NewCiOidcGuard(cfg Config) *CiOidcGuard；NewCiOidcGuardFromSnapshot(cfg Config, data []byte) (*CiOidcGuard, error)；AddPolicy(p TrustPolicy) error；RemovePolicy(name string) error；Evaluate(c Claims, now time.Time) (Grant, error)；ReplaySeen(issuer, jti string) (bool, error)；Snapshot() ([]byte, error)。

故障与边界：1) 策略重名返回 ErrPolicyExists，subject 模式含双星号或为空返回 ErrInvalidPolicy，策略数超过 MaxPolicies 返回 ErrTooManyPolicies；2) token 的 Issuer 没有任何策略时返回 ErrIssuerMismatch，不能退化成随便挑一个策略，策略查找要按 issuer 精确匹配，不能模糊前缀；3) Audience 不在策略 Audiences 列表内返回 ErrAudienceMismatch，audience 数组为空视为拒绝；4) subject 按冒号分段匹配，模式与值的段数必须一致，星号只在一段内匹配且不能吃掉冒号，repo:acme/payments:ref:refs/heads/* 不能匹配 payments-evil，否则返回 ErrSubjectMismatch，模式里的字面量必须逐字匹配，大小写和斜杠都敏感；5) Ref 不在 RefPatterns 内返回 ErrRefNotAllowed，RefPatterns 为空表示不限制；6) 已过期返回 ErrTokenExpired，签发时间超前超过 ClockSkew 返回 ErrTokenNotYetValid，有效期超过策略 MaxTTL 与 Config.MaxTokenLifetime 的较小值返回 ErrTokenLifetime；7) IssuedAt 在 ClockSkew 内（例如超前 20 秒）必须放行，Grant 要带策略名、subject 和到期时间，字段要和输入一致，不能返回空值让调用方再查一次；8) 同一 issuer+jti 在 ReplayTTL 内二次提交返回 ErrReplay，不同 issuer 的相同 jti 互不影响；9) 多个请求并发提交同一 token 时只能产生一个 Grant，其余必须是 ErrReplay，不能两边都拿到权限；10) 删除策略后该 issuer 立即变为不可信，Policy 查询返回 ErrPolicyNotFound，删除不存在的策略也不能静默成功；11) Snapshot 同时保存策略和重放记录，重启后重放的 token 仍被拒绝，新 jti 可以正常通过。

并发互斥、重启恢复和策略数量上限要一起满足，不能只在单线程路径下成立；授权结果要么完整写入重放表，要么完全不写，不能留下半条记录。验收：go test ./... 的 15 条用例必须全部通过；不得修改测试、跳过用例或按固定输入写死；并发和重启场景要自行验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
