# GSB Bugfix Task

## 题面

周一凌晨的准入网关把三台生产机器挡在了门外，排查下来不是网络问题，而是完整性评估组件自己乱了套：同一份度量日志被截断了一半仍然通过，理由是上层只看了最后一条记录；某台机器把 /usr/bin/sshd 换成了带后门的版本，哈希对不上，日志里却只有一条没有级别的告警；还有一台因为上一次误报被隔离，值班同事重启服务后隔离自己消失了，机器又偷偷进了集群；更离谱的是测试租户传上来的列表，把生产租户的规则全带上了，评估结果互相污染。我们需要把度量列表的评估、累计违规和隔离状态放到一个组件里重做：模块路径 gsb/batch46-safety-b-08，文件名 ima_appraisal_guard.go，类型名 ImaGuard，任务类型 Bugfix。

接口以骨架为准：NewImaGuard(Config) *ImaGuard；AddRule(Rule) error；RemoveRule(tenantID, path string) error；Appraise(tenantID, nodeID string, entries []Entry, aggregate string, now time.Time) (Assessment, error)；Verdict(tenantID, nodeID string) (Assessment, error)；Violations(tenantID, nodeID string) []string；ViolationCount(tenantID, nodeID string) int；IsQuarantined(tenantID, nodeID string) bool；Reset(tenantID, nodeID string) error；Snapshot() ([]byte, error)；NewImaGuardFromSnapshot(Config, []byte) (*ImaGuard, error)。

必须逐条覆盖的行为：

1. 度量列表为空、条数超过 MaxEntries，或任一条缺 Seq、Path、Hash、Template，一律 ErrEntryInvalid；
2. Seq 必须严格递增，出现相等或倒退返回 ErrSeqOrder；
3. 调用方传入的 aggregate 必须是按列表顺序把 "<seq>:<path>:<hash>\n" 串起来再做 SHA-256 的小写十六进制，不一致返回 ErrListTampered，且不留下任何评估结果；
4. 基准规则按租户和路径注册，重复注册覆盖旧规则，允许哈希列表为空时 ErrRuleInvalid；删除不存在的规则同样报 ErrRuleInvalid，删除后该路径立刻按无策略处理；
5. 路径命中规则但哈希不在白名单里记 "hash:<path>"，没有对应规则记 "no-policy:<path>"，RequireSigned 打开时非 ima-sig 或没有签名者的记录记 "unsigned:<path>"，同一列表里重复出现同一路径记 "duplicate:<path>"，这些按列表顺序进入 Assessment.Violations；
6. 标记为 Critical 的规则必须出现在列表里，否则整个评估失败并返回 ErrMissingCritical；
7. 累计违规数超过 ViolationBudget 后节点进入隔离，Assessment.Quarantined 与 IsQuarantined 都为真，之后的评估直接 ErrQuarantined；
8. 每个节点最多保留 MaxStoredViolations 条违规文本，但 ViolationCount 要持续累计，不能被截断；
9. Reset 清空某个节点的违规计数、已存违规和隔离状态，其他节点不受影响；
10. 规则和节点状态都按租户隔离，相同 nodeID 在不同租户下互不影响；
11. 评估成功时 Verdict 能取回最近一次的 Assessment，包括 NodeID、实际评估条数 Evaluated、这一轮的 Violations 和隔离标记，从未评估过则 ErrNoVerdict；
12. 违规文本的存储顺序与列表顺序一致，被截断时保留前面的条目，计数与截断互不影响。

硬约束：同一节点的并发评估必须逐条记账，不能丢违规也不能越过存储上限；Snapshot 要带上规则、违规计数、已存违规和隔离状态，重启后隔离继续生效，除非显式 Reset；被拒绝的列表（结构错误、聚合不符、顺序错、缺关键文件）不得改变任何计数。

验收：go test ./... 的 15 条用例全过；不得改测试、跳过或写死结果；并发评估和重启恢复请自行验证；只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
