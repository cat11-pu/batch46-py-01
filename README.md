# GSB Bugfix Task

## 题面

HTTP/3 网关接入 QPACK 动态表后，压测与灰度阶段暴露出成组问题：peer 把 Connection、Keep-Alive 这类逐跳头塞进动态表，服务端照单全收；authorization、cookie 被压缩进共享表，凭据条目在多个请求间复用；一次请求把表容量撑到协商上限之外，后续解码全部错位；插入条目大小超过容量时表被清空而不是拒绝；队头索引已驱逐仍能查回旧条目；伪头出现在普通头之后、重复 :path、未知 :xxx 都能通过解码；40 个并发插入拿到重复的绝对索引；阻塞流数量不受 MaxBlockedStreams 约束，恶意请求用很少的字节挂住连接；插入计数确认可以回退，也可以确认到尚未插入的位置；取消流后阻塞名额没有释放；重启后动态表、插入计数和阻塞流状态全部丢失。现在重做这层校验，范围是模块 gsb/batch46-safety-d-04 的 http3_qpack_guard.go、类型 QpackGuard，任务类型 Bugfix。

保留现有导出错误值，关键入口：NewQpackGuard(settings Settings) *QpackGuard；NewQpackGuardFromSnapshot(settings Settings, data []byte) (*QpackGuard, error)；Insert(name, value string, sensitive bool) (uint64, error)；Lookup(absIndex uint64) (Entry, error)；InsertCount() uint64；DynamicTableSize() uint64；EncodeSection(streamID uint64, fields []HeaderField) (uint64, error)；DecodeSection(streamID uint64, requiredInsertCount uint64) error；AcknowledgeSection(streamID, insertCount uint64) error；CancelStream(streamID uint64) error；SetCapacity(capacity uint64) error；Stream(streamID uint64) (StreamState, error)；Snapshot() ([]byte, error)；Counters() Stats。

动态表要求：字段名必须非空、全小写、不以冒号开头，且不能是 connection、keep-alive、transfer-encoding 等逐跳头，否则返回 ErrFieldInvalid；sensitive 为真返回 ErrSensitiveField；条目大小按名称加值加 32 字节计算，超过当前容量返回 ErrEntryTooLarge 且表保持不变；容量不足时从最旧条目开始驱逐，插入返回连续递增的绝对索引；查询未来索引返回 ErrNoEntry，已驱逐索引返回 ErrEvicted；SetCapacity 高于协商上限返回 ErrCapacityExceeded，降低容量时必须驱逐到装得下。

字段段要求：伪头只允许 :method、:path、:scheme、:authority、:status，必须全部位于普通头之前且不得重复，名称必须小写，否则返回 ErrFieldInvalid；普通头同样校验小写与逐跳规则；authorization、cookie、proxy-authorization 永远不能进入动态表，只作为字面量并累加 SensitiveFields；其余普通字段若表中没有同名同值则插入，已存在则复用，EncodeSection 返回编码时的插入计数；重复编码同一组字段不得产生新条目。

阻塞与确认：DecodeSection 在 requiredInsertCount 大于当前插入计数时返回 ErrBlocked，并把流标记为 blocked；当前阻塞流数达到 MaxBlockedStreams 时再阻塞新流返回 ErrBlockedLimit，且被拒绝的流不得留痕；所需插入补齐后再次 DecodeSection 必须成功并移除阻塞标记；确认计数不得小于该流上次确认值（ErrAckRegression），也不得超过当前插入计数（ErrAckFuture），相同值重复确认必须幂等；CancelStream 释放阻塞名额并删除流状态，未知流返回 ErrStreamNotFound。Stream 返回的 StreamState 要包含 StreamID、RequiredInsertCount、Acknowledged、Blocked、Sections；Counters 的 Inserted、Evicted、FieldsRejected、SensitiveFields、BlockedRejected、SectionsEncoded、SectionsDecoded、BlockedStreams、Cancelled、Acks 必须逐项对应实际操作，BlockedStreams 是当前阻塞流数而不是累计值。

并发与恢复：并发插入必须得到互不重复的连续绝对索引，表大小与插入计数一致。Snapshot 必须保存动态表、插入计数、容量、确认进度、阻塞流和计数器，恢复后旧条目仍可查询、阻塞流仍占名额并在补齐插入后解除；损坏快照返回 ErrSnapshot。

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
