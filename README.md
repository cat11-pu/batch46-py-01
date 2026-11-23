# GSB Bugfix Task

## 题面

周二上午，安全团队用旁路流量给自建 DoT 网关做指纹测试，发现 45 字节的 A 查询在链路上原样出现，长度分布和明文 DNS 几乎一样，观察者不用解密就能按报文长度猜出用户访问的域名类别。同一份抓包还暴露出连接管理的问题：网关只开了两条长连接，每条的并发查询被堆到几百，其中一条抖动断开时上面所有在途查询一起失败；空闲连接又一直挂着不释放。接入层的连接复用和填充策略是两拨人先后加的，账目对不上时很难判断是填充算法算错了还是池子漏了租约，值班只能靠重启网关把连接清空。任务在 gsb/batch46-safety-d-07 中完成，实现文件 dot_padding_guard.go，类型 DotPaddingGuard，任务类型 Bugfix，要求填充计算和连接池账目在同一份状态里对齐。

需要保留的公开能力：

- NewDotPaddingGuard(cfg Config) *DotPaddingGuard
- NewDotPaddingGuardFromSnapshot(cfg Config, data []byte) (*DotPaddingGuard, error)
- (g *DotPaddingGuard) PadLength(wireSize int) (int, error)
- (g *DotPaddingGuard) PaddingBytes(wireSize int) (int, error)
- (g *DotPaddingGuard) Acquire(now time.Time) (string, error)
- (g *DotPaddingGuard) Release(connID string, now time.Time) error
- (g *DotPaddingGuard) MarkSent(connID string) error
- (g *DotPaddingGuard) Outstanding(connID string) (int, error)
- (g *DotPaddingGuard) ConnCount() int
- (g *DotPaddingGuard) CloseConn(connID string) error
- (g *DotPaddingGuard) CloseIdle(now time.Time) int
- (g *DotPaddingGuard) Stats() Stats
- (g *DotPaddingGuard) Snapshot() ([]byte, error)

故障与边界：1) PadLength 取 max(wireSize, MinSize) 后向上取整到 BlockSize 的倍数，128 字节在 block 128 时必须保持 128，不能多加一整块；2) wireSize 为负或 BlockSize 小于等于 0 返回 ErrInvalidConfig，不能除零；3) 取整结果超过 MaxSize 返回 ErrTooLarge，500 字节在 block 128、MaxSize 512 下得到 512，而 MinSize 与 MaxSize 都是 500 时取整到 512 必须报错；4) PaddingBytes 必须恰好等于 PadLength 减去 wireSize，整数倍时返回 0；5) Acquire 优先选 Outstanding 最少的连接，负载相同时选最早创建的，只有全部连接都达到 MaxOutstanding 且 ConnCount 未到 MaxConns 才新建连接；6) 全部连接满载时返回 ErrPoolFull，返回的连接 ID 必须是空字符串，失败的申请不能占用任何计数；7) Release 对未知连接、或已经释放到 0 的连接返回 ErrUnknownConn，计数不能变成负数，重复释放不能让 Released 虚增；8) MarkSent 累计该连接发出的查询数，超过 MaxQueriesPerConn 返回 ErrQueryBudget，预算用完的连接在最后一个租约释放后立即下线，下一次 Acquire 必须换到新连接；9) CloseIdle 只关闭 Outstanding 为 0 且空闲时间达到 IdleTimeout 的连接并返回关闭条数，仍在服务查询的连接一律保留，紧接着再清理一次应返回 0；10) CloseConn 关闭任意已知连接并清理账目，未知 ID 返回 ErrUnknownConn；11) Stats 的 Conns、Outstanding、Acquired、Released 要和当前账面对得上，失败的申请与重复释放不能虚增；12) Snapshot 恢复后连接 ID、Outstanding、Sent、LastUsed 保持不变，能继续用原 ID 释放租约，空字节或损坏内容返回 ErrCorruptSnapshot。

硬约束：并发抢槽时任何连接的 Outstanding 都不能超过 MaxOutstanding，40 个并发租约全部释放后 Outstanding 必须归零，ConnCount 不能越过 MaxConns；连接预算与空闲清理必须原子地作用在同一份池状态上，不能出现已经下线却还能释放的残留条目；快照要从绝对时间恢复，重启后空闲时长继续累计。

验收：go test ./... 的 15 条用例全部通过；不得修改测试、跳过用例或按固定输入写死；并发与重启恢复需要自行验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
