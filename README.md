# GSB Bugfix Task

## 题面

上周三的发布窗口里，堡垒机上的 agent 转发连着出了三次状况。先是有人把转发套接字留在跳板机上过夜，第二天凌晨那把部署密钥还在陌生主机上签名，值班同学翻遍审计也只看到一串没有归属的签名记录；接着一位同学反馈自己的会话早就断了，转发出去的套接字却还能被隔壁会话拿去签提交；最后安全审计重放了一份三天前的签名请求，居然又拿到了成功响应，因为转发层对签名次数根本没有计数，也没有任何地方记录哪把钥匙被吊销过、吊销发生在哪个租户。这几件事让我们决定把散在多个调用点的判断收敛成一个组件重写：模块路径 gsb/batch46-safety-b-06，文件名 ssh_agent_forward_guard.go，类型名 AgentForwardGuard，任务类型 Bugfix。

骨架里已经给出这些公开方法，参数与返回值以它为准：NewAgentForwardGuard(Config) *AgentForwardGuard；RegisterKey(Key, uint32) error；RevokeKey(tenantID, fingerprint string) error；OpenSession(Session, time.Time) error；CloseSession(tenantID, sessionID string) error；ListKeys(tenantID, sessionID string) ([]string, error)；Sign(SignRequest, time.Time) (SignResult, error)；SessionSigns(tenantID, sessionID string) (int, error)；KeySigns(tenantID, fingerprint string) (int, error)；ActiveSessions(time.Time) int；Snapshot() ([]byte, error)；NewAgentForwardGuardFromSnapshot(Config, []byte) (*AgentForwardGuard, error)。

现在的故障和必须覆盖的边界：

1. 会话 ID 从未打开过时签名要返回 ErrSessionUnknown，不能和过期混在一起；
2. 到达 ExpiresAt 的那一刻起签名返回 ErrSessionExpired，失败请求不消耗任何配额；
3. 同 ID 的会话还在有效期内再次打开要返回 ErrSessionDuplicate；
4. 存活会话数达到 MaxSessions 时返回 ErrSessionCap，已过期会话必须先被清掉、不占名额，ActiveSessions 也不能把它们算进去；
5. 签名成功要回显请求负载的拷贝，调用方之后改动自己的切片不能影响结果，并按会话给出从 1 开始递增的 Serial；
6. 单个会话签名次数达到 MaxSignsPerSession 后，换一把钥匙也要拒绝，错误为 ErrSignBudget；
7. 单把钥匙的签名上限 MaxSignsPerKey 跨该租户的所有会话累计，换会话不重置；
8. 请求的 flags 为 0 或包含注册掩码之外的位时返回 ErrFlagNotAllowed，只有掩码内的非零组合能通过；
9. 已吊销的钥匙返回 ErrKeyRevoked，且重新注册同一指纹只能更新掩码和备注，不得恢复可用，也不能出现在列表里；
10. ListKeys 只列本租户未吊销的指纹，按字典序升序返回；用别的租户的钥匙签名必须报 ErrKeyUnknown 而不是吊销错误；
11. 关闭会话之后签名和查计数都返回 ErrSessionUnknown，重复关闭同样如此；
12. 重启后快照要带回会话、两类计数和吊销状态，签名 Serial 接着往下走，原有上限继续生效，不能因为重启多出名额。

硬约束：Sign 的检查与计数必须在同一把锁内完成，十个并发请求打向只剩三个名额的会话时只能成功三个；快照恢复后不得出现配额清零或吊销丢失；任何一次被拒绝的请求都不改变计数与 Serial，也不推进列表顺序。

验收：go test ./... 的 15 条用例必须全部通过，不得修改或跳过测试，不得按固定输入写死结果；并发与重启场景自己跑过再交付；只做本地实现，不碰上游仓库。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
