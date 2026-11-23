# GSB Bugfix Task

## 题面

上个月视频站灰度时，边缘节点在 Range 请求上连着出了两起客诉：同一段 1MB 的切片，用户拖动进度条后拿到的是上一版封面的前几十个字节，播放器直接报解码失败；另一次是客户端带着旧 ETag 发 If-Range，节点仍然回了 206，把新旧两版内容拼在了同一个响应里。排查发现 Range 解析只做了字符串切分，重叠区间、越界结尾、后缀长度都没校验，不同 ETag 的段共用一个槽位，字节预算也没有上限；更隐蔽的一批 206 响应末端字节数被截短，播放器按错误的长度续传，问题要等到第二次拖动才暴露。任务在 gsb/batch46-safety-d-08 中完成，实现文件 http_range_cache_guard.go，类型 RangeCacheGuard，任务类型 Bugfix。

需要保留的公开能力：

- NewRangeCacheGuard(cfg Config) *RangeCacheGuard
- NewRangeCacheGuardFromSnapshot(cfg Config, data []byte) (*RangeCacheGuard, error)
- (g *RangeCacheGuard) Register(etag string, size int64) error
- (g *RangeCacheGuard) ParseRange(header string, size int64) ([]Segment, error)
- (g *RangeCacheGuard) Coverage(segs []Segment) (int64, error)
- (g *RangeCacheGuard) Store(etag string, seg Segment, data []byte) error
- (g *RangeCacheGuard) Fetch(etag string, seg Segment) ([]byte, error)
- (g *RangeCacheGuard) CachedBytes(etag string) int64
- (g *RangeCacheGuard) TotalBytes() int64
- (g *RangeCacheGuard) ValidateIfRange(etag, ifRange string) bool
- (g *RangeCacheGuard) Invalidate(etag string) int
- (g *RangeCacheGuard) Len() int
- (g *RangeCacheGuard) Stats() Stats
- (g *RangeCacheGuard) Snapshot() ([]byte, error)

故障与边界：1) ParseRange 只接受 bytes= 单位，支持 start-end、start-、-suffix 三种写法，逗号后面的空格要容忍；2) 结尾超过资源大小时截到 size-1，后缀长度超过资源大小时返回整个表示，起始位置大于等于 size 返回 ErrUnsatisfiable，-0 这种零长度后缀也返回 ErrUnsatisfiable；3) 结束位置小于起始位置、数字段解析失败、单位不是 bytes 都返回 ErrInvalidRange；4) 区间数量超过 MaxRanges 返回 ErrTooManyRanges，任意两段有交叠返回 ErrOverlappingRanges，而 0-99 与 100-199 这种相邻段必须放行；5) Register 只接受强 ETag，空串、W/ 开头、size 小于等于 0 返回 ErrInvalidRange，同一 ETag 同一 size 幂等返回 nil，同一 ETag 换 size 返回 ErrValidatorConflict；6) Store 的 data 长度必须等于 End 减 Start 加一，否则返回 ErrSizeMismatch 且一个字节也不写；7) Store 的区间必须落在注册的 size 内，越界返回 ErrInvalidRange，未注册的 ETag 返回 ErrUnknownResource；8) Fetch 只在某个已缓存段完整包住请求区间时返回精确切片，任何一段都覆盖不了就返回 ErrPartialMiss，不许拿相邻段拼接；9) 总字节超过 MaxBytes 时按最早写入的资源整块淘汰，被淘汰资源 CachedBytes 归零、Fetch 返回 ErrPartialMiss，单个段本身就超过 MaxBytes 时返回 ErrBudgetExceeded 且不能破坏已有缓存；10) ValidateIfRange 只做强比较，与注册 ETag 逐字相等才返回 true，W/ 前缀、其他 ETag、未注册 ETag 一律 false，空 If-Range 视为不限制；11) Invalidate 删除该 ETag 的全部段并返回条数，注册信息保留，之后 Store 不需要重新 Register，未知 ETag 返回 0；12) Stats 的 Resources、Segments、Bytes、Hits、Misses、Evicted 必须和实际缓存一致，被拒绝的写入不能虚增计数。

硬约束：多个 ETag 并发写入时字节账目必须和实际段一致，不能出现同一段被算两次或者超预算写入成功；淘汰要么整体完成要么完全不发生，失败的写入不能顺手把别人的缓存清掉；Snapshot 要带上注册的 size 和每段内容，重启恢复后 Fetch、CachedBytes、TotalBytes 与重启前一致，损坏的字节流返回 ErrCorruptSnapshot。

验收：go test ./... 的 15 条用例全部通过；不得修改测试、跳过用例或按固定输入写死；并发与重启恢复需要自行验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
