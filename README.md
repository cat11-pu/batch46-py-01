# GSB Bugfix Task

## 题面

接入层凌晨报警：四层转发节点把真实客户端 IP 记成了上一跳负载均衡器的地址，审计里同一秒出现两个来源的“同一连接”，限流规则随后被整段绕过。抓包回放把这批事故归到 PROXY protocol 头：不可信网段自带的头被直接采信，v2 的 TLV 任意透传，多级代理串联的链路也没有任何上限，重启后已放行的连接又全部丢失。值班同学先回滚了转发配置，但根因还在，任何一条新建连接都可能被伪造头带偏。

请修复 gsb/batch46-safety-c-06 中 proxy_protocol_guard.go 的 ProxyProtocolGuard，任务类型 Bugfix，只改本地实现。

需要遵守的公开接口（签名不得改动）：

- NewProxyProtocolGuard(policy TrustPolicy) (*ProxyProtocolGuard, error)
- NewProxyProtocolGuardFromSnapshot(policy TrustPolicy, data []byte) (*ProxyProtocolGuard, error)
- (*ProxyProtocolGuard) Parse(raw []byte) (Header, error)
- (*ProxyProtocolGuard) ParseChain(raw []byte) ([]Header, error)
- (*ProxyProtocolGuard) TrustPeer(cidr string) error / UntrustPeer(cidr string) error / IsTrusted(addr string) bool
- (*ProxyProtocolGuard) Admit(connID string, peer Peer, raw []byte, now time.Time) (Client, error)
- (*ProxyProtocolGuard) Client(connID string) (Client, error) / CloseConn(connID string) error / ActiveConns() int
- (*ProxyProtocolGuard) Snapshot() ([]byte, error) / Stats() Stats

具体现象与边界：

1. v1 的 TCP4 行要完整解出源目的地址与端口，Header 的 Version、Command、Family 以及四个地址端口字段都要填对，没有选项时 TLVs 为空 map；端口超过 65535、字段缺失、端口非数字一律 ErrMalformed，不能把残缺行当合法头。
2. 不是 PROXY 头的字节（例如普通 HTTP 请求行）返回 ErrNotProxy；v2 的 12 字节签名被改动同样按 ErrNotProxy 处理。
3. v2 必须校验版本、声明长度与地址块；声明长度大于实际字节返回 ErrMalformed；只支持 TCP4/TCP6，AF_UNIX 等返回 ErrUnknownFamily。
4. v2 选项只允许策略里的类型（如 authority），未知类型返回 ErrTLVInvalid，不能静默透传给上层。
5. 头长度超过 MaxHeaderBytes 时必须先返回 ErrHeaderTooLarge，不允许先做字段解析；上限按整条头（含 CRLF）计算，不能只量地址部分。
6. peer 不在受信 CIDR 内返回 ErrUntrustedPeer，且不能占用连接表；TrustPeer/UntrustPeer 要立即影响后续判断，撤销后同地址再连必须被拒，策略初始 CIDR 为空表示默认谁都不信。
7. 多级代理按“外层在前”拼接，客户端地址取最内层头的源地址；头数超过 MaxChainHops 返回 ErrLimit。
8. 同一 connID 重复提交完全相同的链路要幂等：返回同一 Client，Stats 的 Idempotent 加一、Admitted 不重复加、Rejected 不增加；同 connID 出现不同链路返回 ErrBrokenChain。
9. 两条不同链路并发抢占同一 connID，必须只有一个成功，另一个拿到 ErrBrokenChain，ActiveConns 保持 1。
10. Client/CloseConn 对未知连接返回 ErrConnUnknown；CloseConn 之后 ActiveConns 立即下降。
11. Snapshot 必须带走受信 CIDR 与已放行连接，经 NewProxyProtocolGuardFromSnapshot 恢复后 Client 仍能查到原地址、ActiveConns 不变，快照里不保存原始报文。
12. 信任表与连接表的所有读写要互斥，不能出现“刚撤销的 CIDR 仍被放行”或计数错乱；连接关闭后决策立即从内存移除，重新建连要重新走一遍信任检查。

硬约束：连接表的判定必须是原子事务，解析失败不得留下半条连接；快照恢复前后已放行的连接和信任集合要一致；单连接只保存一条链路决策，内存不随重放请求增长。

验收：go test ./... 的 15 条测试全部通过；不得修改测试、跳过或用固定输入写死结果；并发与恢复场景自行验证；只做本地实现，不涉及上游提交。

交付：修改后的源码与测试通过记录，附一段简要说明，讲清各错误码的触发顺序。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 地狱
