# GSB Bugfix Task

## 题面

客服转来一条投诉：某办公网里有人用共享账号在代理上同时开了二十多个会话，其中几个连到了内网主机和云主机的元数据地址，日志里只能看到成功的 CONNECT，是谁认证的、传了多少字节一概查不出来。现在要做代理入口的认证与转发防护：模块路径 `gsb/batch46-safety-c-05`，文件 `socks5_auth_guard.go`，类型 `Socks5Guard`，任务类型 Bugfix，骨架方法签名保持不变。

对外接口：`AddUser(username, proof, tenantID string) error` 登记用户；`SetResolver(fn func(host string) ([]string, error)) error` 注入域名解析；`Open(now time.Time) (Session, error)` 开会话；`Greet(sessionID string, gr Greeting, now time.Time) error` 协商认证方式；`Authenticate(sessionID, username, proof string, now time.Time) error` 认证；`Connect(sessionID, host string, port int, now time.Time) (Target, error)` 解析并校验目标；`Transfer(sessionID string, up, down int64, now time.Time) error` 记账；`Close(sessionID string, now time.Time) error`；`Sweep(now time.Time) int`；`Stats() Stats`；`Snapshot() ([]byte, error)` 与 `NewSocks5GuardFromSnapshot(cfg Config, data []byte) (*Socks5Guard, error)` 负责快照恢复。

需要逐条落地的行为：

1. `Open` 受 `MaxSessions` 限制，超出返回 `ErrCapacity`；`Close` 要立刻释放名额，重复 `Close` 返回 nil 不能重复计数；未知会话 ID 返回 `ErrSession`。
2. `Greet` 的协议版本必须为 5，否则 `ErrVersion`；方法列表里必须有 0x02 用户名/密码，只有 0x00 无认证或没有任何可用方法时返回 `ErrMethod`，即使客户端同时提供了 0x00 也不许选它；重复 `Greet` 返回 `ErrState`。
3. 握手步骤不能跳过：`Authenticate` 只能在 `greeted` 态调用，`Connect` 只能在 `authenticated` 态调用，其余状态一律 `ErrState`。
4. 密码错误和用户不存在必须返回同一个 `ErrAuth`、同一段错误文本，不能通过报错区分账号是否存在；每次失败都要计入 `Stats` 的 `AuthFails`。
5. 连续失败达到 `MaxAuthFailures` 后锁定 `LockoutDuration`，锁定期内即使密码正确也返回 `ErrLocked`，锁定到期后自动可以重新认证。
6. `MaxSessionsPerUser` 限制单用户并发会话数，达到后返回 `ErrQuota`，其他用户不受影响；被拒绝的认证不能把会话变成已认证。
7. `Connect` 的端口必须在 `AllowedPorts` 白名单内，否则返回 `ErrPort`；端口小于等于 0 或大于 65535 返回 `ErrInvalid`。
8. 目标地址先按字面 IP 解析，域名走注入的 resolver，解析失败或没有地址返回 `ErrHost`；解析结果落在回环、私网、链路本地（包括 169.254.169.254 这类元数据地址）、未指定或组播地址时返回 `ErrAddress`。
9. 域名必须在每次 `Connect` 时重新解析并重新校验：同一域名先解析到公网地址、之后解析到内网地址，第二次必须被拒绝，不能拿上一次的结果复用。
10. `Transfer` 只能在 `connected` 态调用，`up`/`down` 为负返回 `ErrInvalid`；会话累计字节超过 `MaxBytesPerSession` 时返回 `ErrBudget` 并关闭该会话，之后再 `Transfer` 返回 `ErrState`；正常累加要同时反映到会话与 `Stats`。
11. `Sweep(now)` 关闭空闲超过 `IdleTimeout` 的会话并返回关闭数量；被清理的会话再 `Transfer` 返回 `ErrState`，`Stats` 的 `Active` 同步下降。
12. 快照要带上用户（含失败次数与锁定截止时间）、打开会话总数、上传下载字节数和认证失败总数；重启恢复后锁定继续有效、`Stats` 与重启前一致；空用户名、空 proof、空租户返回 `ErrInvalid`。

硬约束：同一会话的并发 `CONNECT` 只能有一个成功，后到的拿 `ErrState`；会话上限与单用户配额在并发下都不能被突破；任何失败的 `Connect`、`Transfer` 都不能占用名额、不能计入字节或把状态推进；重启后锁定与计数器必须和快照前一致。

验收：`go test ./...` 的 15 条测试必须全过；不得修改测试、跳过或用固定输入写死；并发和重启场景自行写验证程序确认；只在本地实现，不需要真的起代理服务。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
