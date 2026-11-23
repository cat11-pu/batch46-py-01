# GSB Bugfix Task

## 题面

信令网关在一次链路抖动后连续吐出畸形报文：INIT 和 DATA 被打进同一个包，奇数长度的块后面跟着脏填充，AUTH 块里的校验码被原样重放仍然通过，DATA 的 TSN 回退也被照收。更严重的是两个对端协商到了同一个 verification tag，网关把 B 对端的报文记到了 A 对端的关联上，计费和告警同时出错，值班同学花了两个小时才把两条关联拆开，事后统计重放窗口内还多计了十七万条话单。

请修复 gsb/batch46-safety-c-10 中 sctp_chunk_guard.go 的 SctpGuard，任务类型 Bugfix，只改本地实现。

需要遵守的公开接口（签名不得改动）：

- NewSctpGuard(cfg Config) *SctpGuard
- NewSctpGuardFromSnapshot(cfg Config, data []byte) (*SctpGuard, error)
- (*SctpGuard) RegisterAssociation(id string, vtag uint32, peer Peer, tenantID string) error
- (*SctpGuard) RemoveAssociation(id string) error / Association(id string) (Association, error)
- (*SctpGuard) Parse(raw []byte) (Packet, error)
- (*SctpGuard) Admit(assocID string, raw []byte, now time.Time) (Packet, error)
- (*SctpGuard) Authenticate(assocID string, chunkValue, mac []byte, now time.Time) error
- (*SctpGuard) LastTSN(assocID string) (uint32, error)
- (*SctpGuard) Snapshot() ([]byte, error) / Stats() Stats

具体现象与边界：

1. 解析要给出源端口、目的端口、verification tag 和块列表；DATA 块的 Type、Flags、Value 保持原样，TSN 取 Value 的前 4 字节，块值长度不足 4 字节时不能读越界。
2. 块长度小于 4 返回 ErrMalformed；块长度超出剩余报文返回 ErrMalformed，不能按剩余长度截断。
3. 块值后面用于对齐的填充字节必须全为 0，出现非零字节返回 ErrPadding。
4. 单包块数超过 MaxChunksPerPacket 返回 ErrTooManyChunks；整包字节数超过 MaxPacketBytes 返回 ErrPacketTooLarge。
5. INIT 或 INIT_ACK 与任何其他块同包返回 ErrBundling，单独成包才允许通过。
6. 一个 verification tag 只能登记给一个关联，冲突返回 ErrVTagConflict，原关联保持不变；同 id 同 tag 重复登记要幂等，不能把关联计数加两次。
7. 同一 tag 被两个关联并发登记，只能有一个成功，另一个拿到 ErrVTagConflict。
8. Admit 未知关联返回 ErrAssocUnknown；Association 查询未知 id 同样返回 ErrAssocUnknown；报文 tag 与关联登记值不一致返回 ErrVTagMismatch。
9. Authenticate 用 Config.AuthKey 对 chunkValue 计算 HMAC-SHA256 并与 mac 比较，不一致返回 ErrMACInvalid；关联未登记同样返回 ErrAssocUnknown。
10. 正确的校验码只能使用一次：首次成功后同一码在 AuthTTL 内再次提交返回 ErrReplay，Stats 的 Authenticated 与 Replayed 分别累加；不同码不受影响。
11. DATA 的 TSN 必须严格大于该关联上次放行的值，相等或更小返回 ErrTSNRegression，LastTSN 只在水位线推进后变化。
12. Snapshot 要包含关联登记、TSN 水位线和已用校验码，恢复后旧的 TSN 与旧码仍被拒绝，新码可以正常使用，关联查询与恢复前的 peer、tenant 一致。

硬约束：校验码比较与已用记录必须在同一把锁内完成，避免并发双花；块数、包长和每关联状态都有上限，不能随重放无限增长；快照恢复后的关联、水位线与已用码必须与恢复前一致，不能因为重启留下重放窗口。

验收：go test ./... 的 15 条测试全部通过；不得修改测试、跳过或用固定输入写死结果；并发与恢复场景自行验证；只做本地实现，不涉及上游提交。

交付：修改后的源码与测试通过记录，附一段简要说明，写清解析拒绝、认证拒绝与顺序拒绝三类的区别。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
