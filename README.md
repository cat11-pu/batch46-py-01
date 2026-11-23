# GSB Bugfix Task

## 题面

大促压测时，推荐链路的 P99 从 180ms 涨到 4 秒，查下来不是某个服务变慢，而是 deadline 在传播过程中一路被放大：入口给网关 500ms，网关按自己的默认值 2 秒给下游，下游又按默认值再放一次，最末端的缓存服务实际拿到 8 秒预算，前面早就超时了还在继续算。另一个问题是重试：一次 1 秒的调用失败后，重试逻辑把剩下的预算原样再花一遍，三次重试把上游 3 秒的窗口全部吃掉；入口重试和网关重试还各算一套，同一份预算被两层同时花掉。任务在 gsb/batch46-safety-d-09 中完成，实现文件 grpc_deadline_guard.go，类型 DeadlineGuard，任务类型 Bugfix。

需要保留的公开能力：

- NewDeadlineGuard(cfg Config) *DeadlineGuard
- NewDeadlineGuardFromSnapshot(cfg Config, data []byte) (*DeadlineGuard, error)
- (g *DeadlineGuard) StartCall(callID, parentID string, requested time.Duration, now time.Time) (Deadline, error)
- (g *DeadlineGuard) Deadline(callID string) (time.Time, error)
- (g *DeadlineGuard) Remaining(callID string, now time.Time) (time.Duration, error)
- (g *DeadlineGuard) Finish(callID string) (int, error)
- (g *DeadlineGuard) IsActive(callID string) bool
- (g *DeadlineGuard) ActiveCount() int
- (g *DeadlineGuard) RetrySlice(callID string, attempt, maxAttempts int, now time.Time) (time.Duration, error)
- (g *DeadlineGuard) Expire(now time.Time) int
- (g *DeadlineGuard) Stats() Stats
- (g *DeadlineGuard) Snapshot() ([]byte, error)

故障与边界：1) 根调用 requested 大于 0 时按 requested 下发，但不得超过 MaxDeadline，requested 小于等于 0 时用 DefaultTimeout；2) 子调用预算取 min(请求值, 父剩余减 HopReserve)，父剩余必须按绝对截止时间减 now 计算，不能按父调用启动时的预算计算；3) 父剩余已经小于等于 0（包括 now 正好等于父截止时刻）返回 ErrDeadlineExceeded，不建子调用；4) 计算出的预算小于 MinBudget 返回 ErrBudgetBelowMinimum，父剩余减掉 HopReserve 后不足 MinBudget 时同样返回该错误；5) parentID 不存在返回 ErrUnknownCall，callID 重复返回 ErrDuplicateCall，被拒绝的调用不能出现在 ActiveCount、IsActive 和 Stats.Started 里；6) 根调用 Hop 为 1，每深一层加一，超过 MaxHops 返回 ErrMaxHops 且不留下任何状态；7) Remaining 在截止前返回精确差值，过期后返回 0 并带 ErrDeadlineExceeded，任何情况下都不能返回负数；8) Finish 关闭整棵子树并返回被一并关闭的后代数量（不含自己），重复 Finish 或对已经级联关闭的调用再 Finish 返回 ErrUnknownCall，Stats.Finished 按实际关闭的调用数累计；9) RetrySlice 把当前剩余预算平均切成 maxAttempts 份并向下取整，每次重试最多拿其中一份，attempt 从 1 开始，越界返回 ErrInvalidAttempt，份额低于 MinBudget 返回 ErrBudgetBelowMinimum；10) Expire 清掉所有已经过截止时间的调用并返回条数，不能顺手清掉还有预算的调用；11) Stats 的 Active、Started、Expired、Finished 必须和账目一致，失败的 StartCall、非法 attempt、未知调用都不能虚增；12) Snapshot 恢复后绝对截止时间、父子关系、Hop 与剩余预算都不变，重启后不能重新起算。

硬约束：同一个父调用下并发创建子调用时，各自的预算必须按父剩余独立计算，不能因为并发少扣或多扣 HopReserve，也不能出现 ActiveCount 与实际节点数不一致；快照只保存绝对时刻，恢复后 Remaining 继续按原截止时间递减；MaxHops、MaxDeadline、MinBudget 是硬上限，任何路径都不能绕过。

验收：go test ./... 的 15 条用例全部通过；不得修改测试、跳过用例或按固定输入写死；并发与重启恢复需要自行验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 地狱
