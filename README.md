# GSB Bugfix Task

## 题面

邮件系统切到 IDLE 推送后，移动端用户大面积反馈漏信：会话停留在旧 UIDVALIDITY 上，邮箱重建后仍按旧序号推送 EXISTS；同一封新邮件在分页拉取时被重复下发；一次返回几百条通知把客户端打挂；两个账号使用同名 INBOX，A 账号的变更出现在 B 的连接上；会话已经结束 IDLE，服务端仍往里塞通知；MODSEQ 回退的更新覆盖了较新的邮箱快照；邮件数从 5 降到 4 被当作正常更新；连接闲置超时后仍能继续 Poll；重启后待推送队列和游标全部丢失，客户端只能全量重同步；异常客户端把会话数占满，正常用户再也建不了连接。现在重建这条推送链路，范围是模块 gsb/batch46-safety-d-03 的 imap_idle_guard.go、类型 ImapIdleGuard，任务类型 Bugfix。

保留现有导出错误值与状态、通知类型常量，关键入口：NewImapIdleGuard(policy Policy) *ImapIdleGuard；NewImapIdleGuardFromSnapshot(policy Policy, data []byte) (*ImapIdleGuard, error)；SetMailbox(account string, m Mailbox) error；Mailbox(account, name string) (Mailbox, error)；RegisterSession(account, sessionID, mailbox string, now time.Time) (IdleSession, error)；BeginIdle(sessionID string, now time.Time) error；EndIdle(sessionID string) error；Publish(u Update, now time.Time) error；Poll(sessionID string, now time.Time) ([]Notification, error)；CloseSession(sessionID string) error；SessionsFor(account string) []string；Snapshot() ([]byte, error)；Counters() Stats。

邮箱与更新要求：邮箱名、UIDVALIDITY、消息数、MODSEQ 任一非法返回 ErrMailboxInvalid；未登记邮箱返回 ErrMailboxNotFound；Publish 的账号与邮箱必须已登记；MODSEQ 必须严格递增，相等或更旧返回 ErrStaleUpdate 且邮箱快照不变；UIDVALIDITY 不变的邮件数回退返回 ErrStaleUpdate，UIDVALIDITY 变化时允许计数变小并把会话游标重置到新计数。

会话要求：重复会话号、会话数超过 MaxSessions、在 active 状态 Poll、重复 BeginIdle、EndIdle 后 Poll 都返回 ErrSessionState 或 ErrSessionLimit；注册会话时游标取当前邮箱的消息数与 MODSEQ；Poll 只能在 idle 状态使用，按发布顺序返回至多 BatchSize 条，通知带 Kind、Value、ModSeq 三个字段，返回后游标前进，再次 Poll 不重复投递；UIDVALIDITY 变化只下发一条 UIDVALIDITY 通知并以新计数重置游标，不补发旧代 EXISTS；通知按账号和邮箱双重隔离，同名邮箱在不同账号之间不得串消息。

资源与恢复：每个会话的待推送队列受 MaxPending 限制，超出时丢弃最旧的通知并累加 Dropped；idle 时间超过 IdleTimeout 的会话在 Poll 时返回 ErrIdleTimeout、状态转为 closed、累加 Expired，之后再次 Poll 返回 ErrSessionState；CloseSession 释放会话名额，关闭后操作返回 ErrSessionNotFound。并发向不同邮箱发布不得丢通知或串号。Snapshot 必须保存邮箱、会话游标、待推送队列和计数器，恢复后未送达的通知继续按原顺序下发，计数器延续；损坏快照返回 ErrSnapshot。

补充要求：Mailbox 与 SessionsFor 返回副本，调用方修改返回值不得影响内部状态；SetMailbox 对同一账号的同名邮箱是覆盖登记，用于进程启动时装载状态；SessionsFor 的结果按会话号升序；Seq 返回最近一次已投递的消息总数，未投递的通知不影响它；MaxSessions 为 0 表示不限制；Counters 的 Published、Delivered、Dropped、Expired、Rejected 分别对应成功发布、已投递、队列丢弃、超时关闭和被拒绝的更新。

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
