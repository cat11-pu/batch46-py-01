# GSB Bugfix Task

## 题面

WebSocket 网关打开 permessage-deflate 后，安全团队复现了一组压缩相关的事故：握手时对端声明的 server_max_window_bits=7 被接受，解压窗口与协商结果不一致；客户端不带任何扩展也能被标记为已压缩；同一条连接重复协商；控制帧带上 RSV1 被当成压缩数据处理；分片消息的后续帧再次置 RSV1 也能过；一条消息的解压结果没有上限，几百 KB 的压缩包把进程内存打满；已经协商 no_context_takeover，第二条压缩消息仍沿用旧上下文；上下文数量没有上限，异常连接耗尽内存；连接关闭后上下文不释放；网关重启时正在分片的消息丢失，最后一片续不上；并发分片时字节数少算，消息统计与真实流量对不上。现在重写这层防护，范围是模块 gsb/batch46-safety-d-05 的 websocket_compression_guard.go、类型 WsCompressionGuard，任务类型 Bugfix。

保留现有导出错误值、操作码常量和结构体字段，关键入口：NewWsCompressionGuard(params Params) *WsCompressionGuard；NewWsCompressionGuardFromSnapshot(params Params, data []byte) (*WsCompressionGuard, error)；Negotiate(connID string, offers []string) (string, error)；Open(connID string) error；AcceptFrame(connID string, f Frame) error；ResetContext(connID string) error；Close(connID string) error；State(connID string) (ConnState, error)；Compressible(connID string, size int) bool；Snapshot() ([]byte, error)；Counters() Stats。

握手要求：只接受 permessage-deflate，解析 server_no_context_takeover、client_no_context_takeover、server_max_window_bits、client_max_window_bits；窗口位数必须在 9 到 15 之间且为数字，否则返回 ErrParam；对端没有提供扩展时返回空串且连接保持未压缩；返回串的顺序固定为 permessage-deflate、server_no_context_takeover、client_no_context_takeover、server_max_window_bits=N，与策略无关的参数不输出；打开压缩上下文的连接数达到 MaxContexts 时返回 ErrContextLimit，释放后可以重新协商；重复 Open 返回 ErrConnExists，未打开或已关闭的连接一律返回 ErrNoConnection。

帧处理要求：数据帧操作码只允许 text、binary、continuation，控制帧只允许 close、ping、pong，其余返回 ErrOpcode；控制帧必须 FIN、负载不超过 125 字节且不得置 RSV1，否则返回 ErrControl，控制帧可以穿插在分片之间但不影响消息状态；continuation 必须已有打开的消息，消息未结束时再发 text 或 binary 返回 ErrOpcode；RSV1 只允许出现在一条消息的第一个数据帧上，且必须已协商压缩，否则返回 ErrRSV1；同一条消息各分片的解压长度累加超过 MaxMessageSize 时返回 ErrMessageTooLarge、累加 BombsRejected 并丢弃该消息；FIN 帧结束消息时累加 MessagesCompleted，所有数据帧的解压字节累加到 BytesAccepted。

上下文要求：协商了 server_no_context_takeover 时，每条压缩消息完成后上下文标记为 dirty，下一条压缩消息未先 ResetContext 就返回 ErrContextStale；未协商该参数时上下文持续复用，显式 ResetContext 也应允许；消息未结束时 ResetContext 返回 ErrConnState。Compressible 在未协商、长度低于 CompressionThreshold 或超过 MaxMessageSize 时返回 false。

并发与恢复：同一条连接上 50 个并发 continuation 的字节与帧数必须全部计入且不丢失。Snapshot 必须保存连接、未完成消息的分片统计、上下文代次与 dirty 标记以及计数器，恢复后最后一片 continuation 能正常结束原消息；损坏快照返回 ErrSnapshot。State 返回的 ConnState 必须包含 Compressed、MessageOpen、MessageCompressed、MessageBytes、Frames、ContextGeneration、ContextDirty；Counters 的 Opened、Closed、FramesAccepted、FramesRejected、MessagesCompleted、BytesAccepted、ContextsReset、BombsRejected 必须逐项对应实际操作。

验收：go test ./... 的 15 条测试全部通过；不得修改或跳过测试、不得按固定输入硬编码；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 地狱
