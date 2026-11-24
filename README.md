# GSB Bugfix Task

## 题面

HTTP/3 网关灰度到 10% 流量后，前端大量请求返回 QPACK_DECOMPRESSION_FAILED。抓包看到解码器还没收到编码器插入的字段，就先把引用这些字段的头部块交给上层；动态表容量从 4096 调到 2048 后，老条目没有及时淘汰，used 一路涨到超过容量；同一个键值被反复插入，表项数量翻了几倍；流被阻塞后计数没有上限，一次攻击打开了上千条阻塞流；重启后编码器的插入计数归零，所有相对索引全部错位。编码器与解码器对动态表的淘汰时机理解也不一致，相对索引换算出来指向了错误字段。修复范围：模块路径 gsb/batch46-safety-d-04，文件 http3_qpack_guard.py，类 QpackGuard，任务类型 Bugfix，异常类 QpackError 携带 code。

接口：QpackGuard(*, capacity: int = 4096, max_capacity: int = 8192, max_blocked: int = 8)、set_capacity(capacity: int) -> dict、insert(name: str, value: str) -> dict、lookup_absolute(index: int) -> dict、lookup_relative(index: int) -> dict、encode(headers: Sequence[Sequence[str]]) -> dict、decode(block: Mapping[str, object]) -> dict、open_stream(stream_id: str, *, required_insert_count: int) -> dict、acknowledge(stream_id: str, section_ack: int) -> dict、unblock(stream_id: str) -> dict、blocked_streams() -> list[str]、table_state() -> dict、snapshot() -> dict、restore(payload: Mapping[str, object]) -> dict、metrics() -> dict。

故障与边界：一、表项大小等于名称字节数加值字节数加 32，绝对索引从 0 单调递增，insert 返回 index、size、used、evicted、insert_count。二、完全相同的名称和值再次 insert 返回 status duplicate，复用原索引，不增加 insert_count，duplicates 加一；去重只针对当前仍在表内的键值，条目被淘汰后可以重新插入。三、单条表项大于当前容量按 QPACK_ENTRY_TOO_LARGE 拒绝且表不变；容量不足时从最旧条目开始淘汰，evicted 返回条数。四、set_capacity 只接受 0 到 max_capacity，越界按 QPACK_CAPACITY 且容量不变；缩小容量要立即淘汰到 used 不超过新容量。五、lookup_absolute 对负数、bool、超出 insert_count 的索引按 QPACK_INDEX；已被淘汰的条目按 QPACK_EVICTED；lookup_relative 的 0 表示最新一条，换算后越界同样按 QPACK_INDEX。六、encode 对表里已有的字段复用索引，缺失的字段先插入；返回 required_insert_count 与每条的 name、value、index、relative、literal，literal 表示该字段是本次新插入的。七、decode 在 required_insert_count 大于当前 insert_count 时按 QPACK_BLOCKED 拒绝，不能返回部分头部；结构缺字段按 QPACK_BLOCK_INVALID；引用已淘汰条目按 QPACK_EVICTED；解码失败不能污染已有表项和流状态。八、open_stream 的 required_insert_count 超过当前插入数时进入 blocked，阻塞流总数达到 max_blocked 后新流按 QPACK_BLOCKED_LIMIT 拒绝且不登记。九、unblock 只对已阻塞且所需插入数已满足的流生效，否则 QPACK_NOT_READY；blocked_streams 按名称排序返回。十、acknowledge 对未知流按 QPACK_STREAM_UNKNOWN，section_ack 超过 insert_count 或小于上次确认值按 QPACK_ACK_INVALID；重复 stream_id 按 QPACK_STREAM_EXISTS。十一、snapshot 保存容量、插入计数、表项、流状态与计数器，restore 原子且校验表项大小与 used，超过容量或不一致按 QPACK_SNAPSHOT_INVALID，失败时现有表不变。十二、metrics 给出 inserts、duplicates、evictions、encoded、decoded、blocked_count；table_state 按插入顺序返回条目。

硬约束：插入、淘汰、索引查询与流状态在同一把锁内完成，多线程并发插入 160 条必须得到 160 个不同绝对索引且 used 不超容量；恢复后新插入必须接着快照的 insert_count 继续编号，旧块仍能按原索引解码。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得改测试、不得跳过、不得按固定输入写死。并发与重启场景自行验证；只做本地实现，不涉及其他目录。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
