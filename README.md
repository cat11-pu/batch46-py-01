# GSB Bugfix Task

## 题面

证书透明度的季度审计里，合规同事发现一批本该被拒的证书拿到了放行：某证书只带两张来自同一家日志运营商的 SCT，却满足了两张不同日志的要求；另一张证书的 SCT 时间戳比证书 notBefore 早十分钟，仍然被计入数量；某日志因为私钥泄露被标记为 disqualified，它的历史 SCT 却仍被算作有效；更严重的是，两次 SCT 来自同一日志的 embedded 和 ocsp 通道，系统把它们当成了两个不同日志。这类问题在季度审计里被列为高风险，审计报告里还提到，被拒证书的判定理由无法复现，排障只能靠猜，审计要求在下个季度前补齐策略，并把每一张被拒证书的原因写进报告。请在模块 gsb/batch46-safety-b-05 的 sct_policy_guard.go 中修复类型 SctGuard，任务类型 Bugfix，把日志注册、状态变更、SCT 计数和证书时间窗校验做成完整策略。

需要保持的接口：NewSctGuard(cfg Config) *SctGuard；NewSctGuardFromSnapshot(cfg Config, data []byte) (*SctGuard, error)；AddLog(l Log) error；SetLogState(id string, state LogState) error；RemoveLog(id string) error；Evaluate(cert Cert, scts []SCT, now time.Time) (Verdict, error)；LogCount() int；Snapshot() ([]byte, error)。

故障与边界：1) 日志重复注册返回 ErrLogExists，id 或 operator 为空返回 ErrLogInvalid，日志数超过 MaxLogs 返回 ErrTooManyLogs；2) 出现未注册日志的 SCT 时整次评估返回 ErrUnknownLog，未知日志不能被静默忽略；3) 状态为 LogDisqualified 的日志，其 SCT 直接跳过且不计入任何数量，状态切换要立即对后续评估生效；4) 同一日志的多张 SCT 只计一次，不同 Source 也一样，去重严格按 LogID，重复的 SCT 不能靠时间戳或来源绕过；5) 任一有效日志的 SCT 签名无效返回 ErrBadSCTSignature；6) SCT 时间戳早于 cert.NotBefore 减 ClockSkew、晚于 now 加 ClockSkew、或比 now 早超过 MaxSCTAge，都返回 ErrSCTTimestamp，边界按闭合区间处理；7) 证书 notAfter 已过返回 ErrCertExpired，notBefore 尚未到返回 ErrCertNotYetValid，证书时间窗和 SCT 时间窗要分别判定；8) 去重后不足 MinDistinctLogs 返回 ErrTooFewSCTs，Verdict 的 Count 与 Logs 保留已经计入的部分，被拒绝的 SCT 不能占用数量名额；9) 日志数够但 Operator 去重后不足 MinOperators 返回 ErrOperatorDiversity，Verdict.Count 为日志数，运营商必须按 Log.Operator 去重；10) 满足条件时 Verdict.Accepted 为 true，Logs 与 Operators 都按字典序返回，排序结果要稳定，方便逐条比对，Accepted 只在数量和运营商都满足时才为 true；11) MaxLogs=10 时五十个并发 AddLog 只能成功 10 个，LogCount 必须为 10，注册失败不能影响已经存在的日志；12) Snapshot 保存日志及其 State，重启后被 disqualified 的日志仍然不计数，恢复过程不需要重新注册日志。

并发注册、重启恢复、日志容量和时间窗这几类约束都要落到实现里，不能只在单条 SCT 上正确；评估失败时 Verdict 也要能给排障同学提供已计入的日志。验收：go test ./... 的 15 条用例必须全部通过；不得修改测试、跳过用例或按固定输入写死；并发和重启场景要自行验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
