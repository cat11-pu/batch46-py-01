# GSB Bugfix Task

## 题面

支付开放平台的授权码流程接入 PAR 之后，前端把 request_uri 放在地址栏里传来传去，连着出了两次事故：一次是同一个 request_uri 被浏览器刷新重复提交，第二次居然也换到了授权码；一次是 A 客户端的 request_uri 被 B 客户端拿去兑换，服务端只判断了 URI 是否存在，没校验归属。值班同学起初以为是前端重复提交，给按钮加了防抖，结果手工构造请求照样能复用，说明问题在服务端。审计还发现 PKCE 只存了 challenge 不校验方法，plain 和超短 challenge 都能过；scope 没有和客户端白名单比对，测试账号给自己加 admin 也能成；待处理请求没有上限，压测时内存涨到 3G；网关重启后已经用过的 URI 又能兑换一次。这批问题要在 gsb/batch46-safety-a-03 里修掉，实现文件 oauth_par_request_guard.go，类型 ParGuard，任务类型 Bugfix。

需要保留的公开能力：

- NewParGuard(p ParPolicy) *ParGuard
- NewParGuardFromSnapshot(p ParPolicy, data []byte) (*ParGuard, error)
- (g *ParGuard) RegisterClient(c Client) error
- (g *ParGuard) Push(req PARRequest, now time.Time) (string, error)
- (g *ParGuard) Consume(requestURI, clientID string, now time.Time) (PushedRequest, error)
- (g *ParGuard) Pending(requestURI string, now time.Time) (bool, error)
- (g *ParGuard) RevokeClient(clientID string) error
- (g *ParGuard) Prune(now time.Time) int
- (g *ParGuard) Snapshot(now time.Time) ([]byte, error)
- (g *ParGuard) Stats() ParStats

故障与边界：

1. request_uri 必须是固定前缀 urn:ietf:params:oauth:request_uri: 加 32 位小写十六进制，每次 Push 都不同，Pushed 计数同步累加；
2. Consume 返回的记录要还原 client、租户、redirect_uri、response_type、state、PKCE 字段和 nonce，ExpiresAt 等于 Push 时刻加 RequestURITTL；
3. scope 按空格切分后去空、去重并保留首次出现的顺序，例如 profile  openid profile 还原成 profile、openid；
4. 同一 request_uri 只能兑换一次，第二次返回 ErrRequestConsumed；
5. 超过 RequestURITTL 后 Pending 返回 false，Consume 返回 ErrRequestExpired；
6. redirect_uri 必须与该客户端注册值逐字相等，多一段路径返回 ErrRedirectMismatch；
7. 请求的 scope 必须是客户端白名单的子集，多出 admin 这类值返回 ErrScopeNotAllowed，合法但顺序不同仍要放行；
8. CodeChallengeMethod 只接受 S256，plain 或空值返回 ErrPKCE，challenge 短于 MinChallengeLen 也返回 ErrPKCE；
9. 未注册的 ClientID 返回 ErrClientUnknown，且不能把这次 Push 计入 Pushed；
10. response_type 必须命中 AllowedResponseTypes，否则返回 ErrResponseType；
11. 机密客户端要核对 ClientSecret 的 SHA-256 与注册的 SecretHash，不一致返回 ErrClientAuth，只对公开客户端跳过；
12. 用别人的 ClientID 兑换返回 ErrRequestOwner，且不影响原客户端继续兑换；待处理请求达到 MaxPending 后返回 ErrCapacity，被拒绝的请求不能占用名额，Stats 的 Pending 反映未消费的待处理请求数。

硬约束：同一个 request_uri 被并发兑换时只能有一个成功，其余必须稳定返回 ErrRequestConsumed，不能出现两枚授权码；快照要覆盖注册客户端、未过期请求和已消费标记，重启恢复后已消费的 URI 不能复活；待处理数量必须有硬上限，购物节前的批量压测不能把内存顶爆；注册客户端时 ID 重复要报错，redirect_uri 和 scope 为空的脏数据不能带进后续流程；过期请求不能只靠后台定时任务清理，查询路径上就要按 now 判定失效；所有时间判断使用入参 now，不在实现里读系统时钟。

验收：go test ./... 的 15 条用例全部通过；不得修改测试、跳过用例或按固定输入写死；并发和重启恢复要自行验证；只做本地实现，不涉及上游仓库。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
