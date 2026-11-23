# GSB Bugfix Task

## 题面

上周车联网平台做断网演练，运维发现三件事凑在一起：设备 A 在隧道里掉线，平台的掉线通知本该由遗嘱消息发出，结果晚了 4 分钟才到监控大屏；设备 B 用同一个 client id 重连，把旧连接顶掉，旧连接上 37 条未确认指令跟着消失；还有一批设备在会话过期后重连，离线队列里积压的报文被无上限地倒出来，直接把下行带宽打满；清理脚本只能按 client id 逐台核对，谁也说不清哪条遗嘱该发、哪条已经发过。任务在 gsb/batch46-safety-d-10 中完成，实现文件 mqtt_session_guard.go，类型 MqttSessionGuard，任务类型 Bugfix。

需要保留的公开能力：

- NewMqttSessionGuard(cfg Config) *MqttSessionGuard
- NewMqttSessionGuardFromSnapshot(cfg Config, data []byte) (*MqttSessionGuard, error)
- (g *MqttSessionGuard) Connect(clientID string, cleanStart bool, will Will, now time.Time) (Takeover, error)
- (g *MqttSessionGuard) Disconnect(clientID string, clean bool, now time.Time) error
- (g *MqttSessionGuard) Lose(clientID string, now time.Time) error
- (g *MqttSessionGuard) Queue(clientID string, msg Message, now time.Time) error
- (g *MqttSessionGuard) Pending(clientID string) ([]Message, error)
- (g *MqttSessionGuard) Next(clientID string, now time.Time) (Message, error)
- (g *MqttSessionGuard) Ack(clientID string, packetID uint16) error
- (g *MqttSessionGuard) Inflight(clientID string) (int, error)
- (g *MqttSessionGuard) Subscribe(clientID, topic string) error
- (g *MqttSessionGuard) Subscriptions(clientID string) ([]string, error)
- (g *MqttSessionGuard) DueWills(now time.Time) []Will
- (g *MqttSessionGuard) PurgeExpired(now time.Time) int
- (g *MqttSessionGuard) SessionCount() int
- (g *MqttSessionGuard) Info(clientID string) (SessionInfo, error)
- (g *MqttSessionGuard) Stats() Stats
- (g *MqttSessionGuard) Snapshot() ([]byte, error)

故障与边界：1) 首次 Connect 返回 Replaced 为 false，已有在线连接被同一个 client id 顶掉时返回 true，顶替会清空旧连接的在途窗口、cleanStart 为 false 时保留未投递的离线队列，并把旧连接的遗嘱按立即到期入队、忽略遗嘱自带的 Delay；2) 正常 Disconnect 不论 clean 与否都不发遗嘱，clean 为 true 删除会话、队列和订阅，clean 为 false 保留队列与订阅并把 ExpiresAt 设为 now 加 SessionExpiry；3) cleanStart 为 true 的重连必须清空旧队列、在途窗口和订阅，但 Replaced 只在顶掉在线连接时为 true；4) Lose 表示非正常断开，连接标记为断开，遗嘱按自身 Delay 入队，Delay 为 0 时用配置的 WillDelay，DueWills 只返回到期时间小于等于 now 的遗嘱并从待发表移除；5) Queue 超过 MaxQueued 返回 ErrQueueFull 且保留已有消息不淘汰，会话已过期返回 ErrSessionAbsent 并顺手清掉过期会话；6) PacketID 在队列和在途窗口内都必须唯一，重复返回 ErrDuplicatePacketID，Ack 之后同一 ID 可以再次使用；7) Next 在队列为空时返回 ErrQueueEmpty，在途达到 MaxInflight 返回 ErrInflightLimit，成功时从队首取出并计入在途；8) Ack 未知 packet id 返回 ErrUnknownPacketID，重复 Ack 不能把在途数减成负数；9) Pending 按 FIFO 返回队列副本，Next 之后 Pending 不再包含已取出的消息；10) Subscribe 幂等，同一主题不重复记录，Subscriptions 按字典序返回，未知会话返回 ErrSessionAbsent；11) PurgeExpired 只清理已断开且 now 已达到 ExpiresAt 的会话并返回条数，在线会话一律保留；12) Stats 的 Sessions、Queued、Inflight、WillsPending、Takeovers 必须和实际状态一致，失败的 Connect、Queue、Ack 不能虚增。

硬约束：同一 client id 被大量并发 Connect 时只能有一个返回 Replaced 为 false，其余全部是顶替且各自把上一条连接的遗嘱排入待发表，最终会话数只能是 1；队列、在途窗口、遗嘱待发表各自有上限或明确的清理时机，任何路径都不能绕过 MaxQueued 与 MaxInflight；Snapshot 要保留会话的连接状态、绝对过期时刻、队列顺序、在途 packet id、订阅和待发遗嘱，重启恢复后 Pending、Subscriptions、DueWills 与重启前一致。

验收：go test ./... 的 15 条用例全部通过；不得修改测试、跳过用例或按固定输入写死；并发与重启恢复需要自行验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 地狱
