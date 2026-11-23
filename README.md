# GSB Bugfix Task

## 题面

核心网计费侧反馈，某天下午两个租户的会话在同一个 TEID 上互相串话，晚到的报文被记到了刚建立的新会话名下；同时监控显示单租户的 TEID 表可以无限增长，释放后的 TEID 立刻被下一个租户复用，同一序列号重放也不会被拒绝。运维回滚后复现，确认问题出在 GTP-U 的 TEID 归属表和序列号水位线上，两个故障叠加才放大了串话范围。

请修复 gsb/batch46-safety-c-09 中 gtp_teid_guard.go 的 GtpGuard，任务类型 Bugfix，只改本地实现。

需要遵守的公开接口（签名不得改动）：

- NewGtpGuard(cfg Config) *GtpGuard
- NewGtpGuardFromSnapshot(cfg Config, data []byte) (*GtpGuard, error)
- (*GtpGuard) Allocate(teid uint32, tenantID string, peer PeerAddr, now time.Time) (Binding, error)
- (*GtpGuard) Release(teid uint32, now time.Time) error / Binding(teid uint32) (Binding, error)
- (*GtpGuard) Parse(raw []byte) (Packet, error)
- (*GtpGuard) Admit(pkt Packet, peer PeerAddr, now time.Time) error
- (*GtpGuard) LastSequence(teid uint32) (uint32, error) / TenantTEIDCount(tenantID string) int
- (*GtpGuard) Snapshot() ([]byte, error) / Stats() Stats

具体现象与边界：

1. 解析 T-PDU 要给出 MessageType 0xFF、TEID、Payload；S 标志置位时 HasSequence 为真并解出 16 位序列号，未置位时序列号不参与判断。
2. 版本字段不是 1 时在解析其他字段前返回 ErrVersion；PT 位为 0（GTP'）返回 ErrProtocolType。
3. 长度字段与实际报文不符，短于或多于声明字节都返回 ErrMalformed，不能截断后继续。
4. TEID 0 是保留值，Allocate 返回 ErrTEIDRange；0xFFFFFFFF 可以作为普通 TEID 正常分配。
5. 同一 TEID 分配给两个租户返回 ErrTEIDInUse；同租户同 peer 重复分配幂等并返回相同 Binding；同租户换 peer 同样返回 ErrTEIDInUse。
6. 单租户存活分配达到 MaxTEIDsPerTenant 后，新 TEID 返回 ErrQuota 且不落表，其他租户不受影响。
7. 已分配 TEID 收到来源 peer 完全匹配的报文要放行，LastSequence 更新为本次序列号，Stats 的 Accepted 加一。
8. 来源地址或端口与分配时不一致返回 ErrPeerMismatch，并累加 Dropped；未分配的 TEID 返回 ErrTEIDUnknown。
9. 带序列号的报文必须严格递增：等于或小于该 TEID 上次放行的序列号都返回 ErrReplay，只有更大值才更新水位线。
10. Release 未知 TEID 返回 ErrTEIDUnknown；释放后 Quarantine 内重新分配返回 ErrQuarantine，恰好到期的时刻允许分配，释放后租户计数立即下降；隔离期从释放时刻起算。
11. 两个租户并发分配同一个空闲 TEID，必须恰好一个成功，另一个拿到 ErrTEIDInUse，两个租户的计数合计为 1。
12. Snapshot 必须保存分配关系、每个 TEID 的序列水位线和释放隔离期，恢复后 Binding 仍能查到原租户与 peer，旧序列号仍返回 ErrReplay、新序列号可以放行。

硬约束：TEID 冲突、租户配额、释放隔离期的判断与写入必须在同一把锁内完成；同一 TEID 的放行判定要串行，避免两个报文同时通过水位线检查；序列水位线随快照持久化，重启不能把已接收的序列号忘掉；释放隔离期内 TEID 不得复用，防止迟到报文命中新会话。

验收：go test ./... 的 15 条测试全部通过；不得修改测试、跳过或用固定输入写死结果；并发与恢复场景自行验证；只做本地实现，不涉及上游提交。

交付：修改后的源码与测试通过记录，附一段简要说明，写清分配、释放、放行三条路径的状态变化。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 地狱
