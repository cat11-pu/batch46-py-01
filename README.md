# GSB Bugfix Task

## 题面

上周大文件下载平台连续收到投诉：客户端断点续传拼出来的安装包校验失败，抓包发现缓存把没有覆盖到的区间当成命中直接回了 206，把另一段数据塞了进去；同一对象的两段缓存分属不同版本，If-Range 带了弱 ETag 也被当成有效校验，用户拿到新旧混合的内容；多段 Range 请求的 multipart 边界和每段 Content-Range 对不上，播放器直接黑屏。更麻烦的是缓存组件把不同 ETag 的分段混在同一张表里，连回源都救不回来。修复范围在 gsb/batch46-safety-d-08 的 http_range_cache_guard.py，RangeCacheGuard 负责区间解析、分段缓存和条件请求判定，任务类型 Bugfix，接口签名不许改。

需要落地的接口（签名与骨架一致）：parse_range(self, header: str, total: int) -> list[tuple[int, int]]；coalesce(self, ranges) -> list[tuple[int, int]]；store(self, url: str, *, body: bytes, etag: str, last_modified: str = "", ttl: float | None = None) -> dict；store_partial(self, url: str, *, body: bytes, etag: str, start: int, total: int, ttl: float | None = None) -> dict；handle(self, request: dict) -> dict；invalidate(self, url: str) -> int；entries(self) -> list[str]；expire(self, now=None) -> int；snapshot(self) -> dict；restore(self, state: dict) -> None；stats(self) -> dict。

返回字段固定：store 返回 url、total、etag、evicted；store_partial 返回 url、total、complete、covered；handle 返回 status、headers、body，未命中时 status 为 miss 并带 code；stats 至少包含 entries、stored、partial_stored、hits、misses、partial_206、not_modified、unsatisfiable、multipart、evicted、expired、bytes_served。

具体故障与边界：一、Range 头只认 bytes= 前缀，a-b、a-、-n 三种写法都要支持，结束位置超过总长要截断到 total-1，起止颠倒按 RANGE_INVALID 拒绝；二、起始位置不小于总长、后缀长度为 0 按 RANGE_UNSATISFIABLE 拒绝；三、单次请求超过 max_ranges 个区间按 RANGE_TOO_MANY 拒绝；四、重叠和首尾相邻的区间要先合并再取数据，合并结果按起点升序；五、完整对象返回 200，headers 里要有 Content-Length、ETag、Accept-Ranges；六、单区间命中返回 206，Content-Range 必须是 bytes 起-止/总长，正文只包含该区间；七、区间无法满足返回 416，Content-Range 为 bytes */总长，正文为空；八、If-None-Match 与当前 ETag 相同返回 304，正文为空并带 ETag；九、If-Range 与 ETag 不一致，或用了 W/ 开头的弱校验，一律返回完整 200；十、分段缓存只覆盖部分字节时，落在覆盖范围内的区间可以回 206，未覆盖区间和完整对象请求都按 miss 返回，分别带 RANGE_INCOMPLETE 或 RANGE_MISS，绝不允许用空洞拼数据；十一、同一 ETag 的分段要合并，拼满整个对象后 complete 置真，完整请求返回原始字节；十二、过期条目按 RANGE_EXPIRED 处理，entries 只返回排好序的 URL，容量超过 max_entries 时淘汰最久未访问的对象并累加 evicted，快照要能 json.dumps，版本不符抛 RANGE_SNAPSHOT_VERSION 且原状态不动。

硬约束：十个线程同时向同一个 URL 写入互不重叠的分段时，最终必须拼出与原文逐字节一致的完整对象，partial_stored 正好记十次，不能出现丢段或长度错位；快照恢复要么整体生效要么整体回退；对象大小、区间数量、缓存条目数都有上限，任何路径都不能绕过，淘汰对象时要连同分段一起清掉，不能留下半份索引。验收：python3 -m pytest -q tests 的 15 条测试全过，不得改测试、跳过或按固定输入写死，并发和重启场景自己造数据验证，只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
