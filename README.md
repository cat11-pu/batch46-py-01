# GSB Bugfix Task

## 题面

边缘路由器按计划上线标签栈校验后，值班组连续收到隧道被劫持的告警：同一个接入电路在几十秒内重复送出完全相同的标签栈，PE 全部放行；有客户把标签值写到 1048576，转发面直接崩溃；深度 5 的标签栈越过上限 4 照常转发；底部标签缺少 S 位、非底部标签却置了 S 位都没有被拦住；保留标签 7 进入核心网；TTL 为 0 或低于策略下限的标签未被丢弃；只属于其他租户的标签值通过校验；下一跳 PE1 的期望序列是 100/200/300，实际收到 200/100/300 仍被接受；执行出栈后新栈顶 TTL 没有递减，调用方传入的切片还被就地改写；压栈把深度顶到 5 也不报错。重启一次后，已经记录过的重复标签栈全部遗忘。现在补上这层校验，范围是模块 gsb/batch46-safety-d-01 的 mpls_label_guard.go、类型 MplsGuard，任务类型 Bugfix。

保留现有导出错误值和结构体字段，关键入口：NewMplsGuard(policy Policy) *MplsGuard；NewMplsGuardFromSnapshot(policy Policy, data []byte) (*MplsGuard, error)；AddNexthop(name string, stack []uint32) error；NexthopStack(name string) ([]uint32, error)；ValidateStack(stack []Label) error；ValidateNexthop(name string, stack []Label) error；Pop(stack []Label, n int) ([]Label, error)；Push(stack []Label, add []Label) ([]Label, error)；Observe(sourceID string, stack []Label, now time.Time) error；Snapshot() ([]byte, error)；Counters() Stats；ResetCounters()。

校验规则：空栈返回 ErrLabelInvalid；标签值超过 20 位、TC 超过 3 位返回 ErrLabelInvalid；深度超过 MaxDepth 返回 ErrStackDepth 并累加 DepthRejected；S 位只允许出现在最后一个标签；保留区间 0–15 中只有 0、2、3 能作为底部标签，其他值或位置返回 ErrReserved；TTL 为 0 或低于 MinTTL 返回 ErrTTL；AllowedLabels 非空时不在名单里的普通标签返回 ErrLabelNotAllowed。ValidateNexthop 要求标签值序列逐项相等，名称不存在返回 ErrNotFound，同名 nexthop 重复登记必须幂等，换成不同序列则返回 ErrLabelInvalid。

Pop 只允许移除少于整个栈的标签，越界返回 ErrStackDepth；返回的新栈顶 TTL 减一，减到 0 返回 ErrTTL；不得修改入参。Push 拒绝带 S 位、保留值或 TTL 非法的标签，结果深度超过 MaxDepth 返回 ErrStackDepth。Observe 先做完整校验，再按接入电路与标签值序列在 ReplayWindow 内去重，重复返回 ErrReplay；存活记录数达到 MaxFlows 且无可回收的过期记录时返回 ErrFlowLimit，过期记录必须优先清理。同一标签栈并发提交必须恰好一个成功。Snapshot 必须保存 nexthop、去重记录和计数器，恢复后重启前见过的标签栈仍然判重，计数器延续；损坏的快照返回 ErrSnapshot；Counters 要准确累加 Accepted、Rejected、DepthRejected、ReplayRejected、FlowRejected。

此外，AddNexthop 对空名称、空序列和保留标签必须拒绝，同名重复登记只有在序列完全一致时才视为幂等；RemoveNexthop 删除不存在的名称不报错；IsReserved 只对 0 到 15 返回真；Policy 的 MaxDepth 与 MinTTL 为 0 时按无限制处理，不能把合法单标签报文误杀；Observe 的每一次拒绝都要计入 Rejected，ResetCounters 之后重新从零累计；同一份 Snapshot 要能被同一 Policy 反复恢复，恢复后 nexthop 校验与重启前一致。

验收：go test ./... 的 15 条测试全部通过；不得修改或跳过测试、不得按固定输入硬编码；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
