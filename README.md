# GSB Bugfix Task

## 题面

邮件网关的 STARTTLS 策略上线后，安全运营复盘了三起真实事故：上游 MTA 的 EHLO 应答里 STARTTLS 被中间设备删掉，网关仍然按明文继续投递，用户的 AUTH 凭据直接出现在链路上；一台主机返回的能力行里混入 CRLF，被原样拼进下一条应答；能力缓存一小时不失效，主机早已关闭 STARTTLS 却仍按旧缓存放行；客户端重复下发 STARTTLS 时网关每次都重新协商；TLS 1.0 握手被接受；AUTH 在握手前就执行；主机只声明 AUTH PLAIN，客户端却用 LOGIN 通过；同一会话可以认证两次；收件人列表大小写不同被当成多个地址重复投递，并且没有数量上限；网关重启后能力缓存和会话的 TLS 状态全部丢失，客户端又回到明文重试。现在补齐这层防护，范围是模块 gsb/batch46-safety-d-02 的 smtp_starttls_guard.go、类型 StarttlsGuard，任务类型 Bugfix。

保留现有导出错误值与状态常量，关键入口：NewStarttlsGuard(policy Policy) *StarttlsGuard；NewStarttlsGuardFromSnapshot(policy Policy, data []byte) (*StarttlsGuard, error)；Advertise(host string, caps []string, now time.Time) error；Capabilities(host string, now time.Time) (Capabilities, error)；Negotiate(host string, now time.Time) ([]string, error)；BeginSession(id, host string, now time.Time) (Session, error)；RequireStartTLS(sessionID string, now time.Time) error；MarkTLS(sessionID, version string, now time.Time) error；Authenticate(sessionID, mechanism, user string) error；CheckRecipients(sessionID string, rcpts []string) ([]string, error)；Snapshot() ([]byte, error)；Counters() Stats。

能力处理要求：主机名或任一能力行包含 CR 或 LF 时返回 ErrInjection；能力行去重后按首次出现顺序缓存；主机从未登记返回 ErrCapabilityMissing，超过 CapabilityTTL 返回 ErrCapabilityStale；Negotiate 把 STARTTLS 放在第一位，丢弃 XTRN 等不支持的行并去重；策略要求 TLS 而主机未声明 STARTTLS 时返回 ErrDowngrade 并累加 DowngradesRejected。

会话要求：BeginSession 建立 new 状态，重复会话号、重复 STARTTLS、握手前重复操作都返回 ErrSessionState；RequireStartTLS 对同一会话只能成功一次并进入 greeted，会话记录 StartTLSIssued 与 TLSVersion；主机未声明 STARTTLS 返回 ErrDowngrade；MarkTLS 只在 greeted 状态可用，版本低于 MinTLSVersion 返回 ErrTLSVersion，成功后进入 tls 并累加 TLSCompleted；Authenticate 在握手前调用返回 ErrPlaintextAuth 并累加 PlaintextAuthRejected，机制不在主机 AUTH 行中返回 ErrAuthMechanism，成功后进入 authenticated，再次认证返回 ErrSessionState；DropSession 之后所有操作返回 ErrSessionNotFound；CheckRecipients 仅在 tls 或 authenticated 状态可用，按大小写不敏感去重并保留首次拼写与顺序，去重后超过 MaxRecipients 返回 ErrRecipientLimit 且不写入会话。

并发与恢复：同一会话两个并发 RequireStartTLS 必须恰好一个成功、另一个得到 ErrSessionState。Snapshot 必须保存能力缓存、会话（含 TLS 版本与状态）和计数器；恢复后缓存仍按原始 ReceivedAt 计算新鲜度，处于 tls 的会话可以直接继续认证；损坏快照返回 ErrSnapshot。

补充要求：Session 返回会话副本，调用方修改收件人切片不得影响内部状态；能力行保存前要裁剪首尾空白并按原顺序去重；AUTH 机制匹配不区分大小写，主机没有 AUTH 行时任何机制都返回 ErrAuthMechanism；TLS 版本按主次版本号数值比较，无法解析的版本一律视为不达标；MaxSessions 为 0 表示不限制，超过上限返回 ErrSessionLimit；DropSession 之后用同一会话号重新 BeginSession 必须成功。

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
