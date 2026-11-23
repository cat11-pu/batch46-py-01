# GSB Bugfix Task

## 题面

凌晨两点，值班收到一串时间跳变告警：一批主机在一个小时内被拨快了两秒，业务日志的时间戳出现倒序。排查下来，某个上游时间源回过来的报文没有通过认证也被采信，几个源之间偏差到了八百毫秒仍在继续使用，最终修正是一次性硬跳，日志里还看到同一条响应被重复采了两次。现在把这套时间源校验补起来：模块路径 `gsb/batch46-safety-c-04`，文件 `ntp_auth_guard.go`，类型 `NtpAuthGuard`，任务类型 Bugfix，骨架方法签名保持不变。

对外接口：`AddKey(server string, keyID uint32) error` 登记密钥号；`RevokeKey(server string, keyID uint32) error` 吊销；`Query(server string, now time.Time) (Query, error)` 发起一次请求并拿到 T1 与 nonce；`Submit(resp Response, now time.Time) (Sample, error)` 校验响应并采样；`SelectedServer(now time.Time) (string, error)` 选源；`Offset(server string) (time.Duration, bool)` 读最近一次偏差；`Apply(now time.Time) (Correction, error)` 按速率上限施加修正；`Sweep(now time.Time) int`；`Stats() Stats`；`Snapshot() ([]byte, error)` 与 `NewNtpAuthGuardFromSnapshot(cfg Config, data []byte) (*NtpAuthGuard, error)` 负责快照恢复。

需要逐条落地的行为：

1. 未登记的服务器、未知密钥号、以及被 `RevokeKey` 吊销之后再发来的响应一律返回 `ErrKey`，吊销后 `Query` 也不许再发出。
2. `AuthOK` 为 false 的响应返回 `ErrAuth`，不能把未认证的报文当成可用样本。
3. `Version` 不是 4、`Leap` 等于 3、`Stratum` 为 0 或大于 15 的响应返回 `ErrPacket`；`Stratum` 为 0 的 kiss-o'-death 只丢弃报文，不改动服务器已有样本。
4. `Query` 返回的 T1 和 nonce 是这次事务的凭据：`Submit` 的 `Originate` 必须等于该 T1、`Nonce` 必须一致，没有未决查询或对不上都返回 `ErrStale`。
5. 一个 nonce 只能采信一次，重复提交返回 `ErrReplay`；进程重启后 nonce 序号不能从零重来，否则已用 nonce 会被再次签发。
6. 偏差与往返延迟必须按 `((T2-T1)+(T3-T4))/2` 和 `(T4-T1)-(T3-T2)` 精确计算，纳秒级结果不能截断或取整到毫秒。
7. 单次偏差绝对值超过 `MaxOffset` 返回 `ErrOffset`，这条响应不消耗 nonce、不计入轮次、不改动待修正量。
8. 每个服务器要记住轮次、最近偏差、延迟、层级和采样时间；`SelectedServer` 只从轮次达到 `MinRounds`、且采样时间距 `now` 不超过 `ServerMaxAge` 的服务器里选，一个都没有返回 `ErrNoSource`。
9. 多个可选中服务器的最近偏差相差超过 `MaxSkew` 时返回 `ErrDivergence`，不要退而求其次挑一个；层级相同时延迟小的优先，再按服务器名排序，结果必须确定。
10. `Apply` 的可应用额度从采样时刻起按 `MaxSlewPPM` 累积：待修正 1ms、速率 100ppm、距采样 1 秒时只应用 100us 并留下 900us，再过 9 秒把剩余 900us 全部应用，任何一次都不能超调。
11. `Sweep(now)` 清掉采样超龄的服务器并返回个数，清掉之后不能被选中、`Stats` 的 `Servers`/`Rounds` 随之归零，但密钥登记保留，重新 `Query` 仍可用。
12. 空服务器名、非法响应字段返回错误而不是 panic；任何失败路径都不能改变轮次、待修正量或已用 nonce 集合。

硬约束：同一条响应被并发提交两次时恰好一次成功、另一次拿 `ErrReplay`，轮次只能加一；`Apply` 的额度计算必须原子，不能出现两次调用各自按满额应用导致超调；快照要带上密钥（含吊销状态）、轮次、最近样本、待修正量、采样与施加时间、nonce 序号和已用 nonce 集合，重启恢复后选源、施加速率与 `Stats` 和重启前一致。

验收：`go test ./...` 的 15 条测试必须全过；不得修改测试、跳过或用固定输入写死；并发和重启场景自行写验证程序确认；只在本地实现，不需要连真实时间服务器。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 地狱
