# GSB Bugfix Task

## 题面

新版本上线后每次进图都重新编译管线：同一个描述符只因顶点属性声明顺序不同就生成两份缓存，不同渲染通道的管线被塞进同一个兼容组，绑定描述符集时校验报错；缓存文件里还混入了上一次设备世代的条目，设备重启后旧哈希被当成新管线。请修复 gsb/batch46-game-e-03 的 pipeline_cache_guard.py 中 PipelineCache（Bugfix），负责稳定哈希、兼容分组、LRU 与世代失效。需要保持这些公开方法：define_pipeline(self, pipeline_id: str, *, vs: str, fs: str, blend: str = "opaque", depth_test: bool = True, depth_write: bool = True, cull: str = "back", topology: str = "tri", vertex_layout: Sequence[tuple[str, str]] = (), render_pass: str = "main", layout: str = "default", tags: Sequence[str] = ()) -> dict、register(self, pipeline_id: str) -> dict、get(self, pipeline_id: str) -> dict、store_blob(self, pipeline_id: str, blob: bytes) -> dict、blob(self, pipeline_id: str) -> bytes、trim(self) -> dict、compat_group(self, pipeline_id: str) -> int、validate_bindings(self, pipeline_id: str, set_layout: str) -> dict、invalidate_generation(self, new_generation: int) -> dict、snapshot(self) -> dict、restore(self, state: dict) -> dict。

故障与边界：1) 哈希对顶点属性顺序和 tags 顺序不敏感，对 vs、fs、blend、depth_test、depth_write、render_pass、layout 变化敏感，输出十六位小写十六进制，不得使用内存地址或字典遍历顺序。2) 空 pipeline_id 报 PLC_ID_INVALID，空 vs/fs/blend 或非字符串标签报 PLC_DESCRIPTOR_INVALID，描述符字段必须为字符串，重复属性名或缺字段的顶点声明报 PLC_LAYOUT_INVALID，同 id 改描述符报 PLC_ID_CONFLICT。3) 同一哈希只保留一条记录，不同 id 同描述符 register 返回 duplicate，条目数仍为一，哈希冲突时以先注册的描述符为准，后来者不得覆盖。4) get 命中刷新 LRU，返回 hit、bytes、group、generation；已定义未注册不算错误，返回 hit 为 False；完全未知 id 报 PLC_UNKNOWN，定义与注册是两个阶段，未注册不影响哈希与兼容组。5) trim 同时满足 entry_budget 与 byte_budget，按 last_used 淘汰并返回 evicted、entries、bytes，被淘汰的管线再次 register 必须重新计为 stored，重复 trim 必须幂等。6) store_blob 替换同一管线二进制并按新大小记账；非 bytes 或空串报 PLC_BLOB_INVALID，单条超过 byte_budget 报 PLC_BLOB_TOO_LARGE；未存二进制读 blob 报 PLC_NO_BLOB，替换后 total_bytes 立即反映差值，旧数据不得残留。7) 兼容组以 layout 与 render_pass 为键，先出现的组编号为一，同键复用编号，不同 layout 或不同 render_pass 必须得到不同组号，组号只增不复用。8) validate_bindings 的 set_layout 与描述符 layout 不符报 PLC_LAYOUT_MISMATCH，校验通过返回 compatible 为 True 与实际 layout。9) invalidate_generation 必须严格递增，回退或相等报 PLC_GENERATION_REGRESS；删除所有旧世代条目并按注册顺序返回 removed，世代号在快照恢复后继续单调，不允许回到一号。10) 快照 version 为 3，恢复要重算每条哈希，篡改哈希报 PLC_HASH_MISMATCH，版本或结构损坏报 PLC_SNAPSHOT_INVALID，恢复前不得自动 trim，恢复后 get 与 register 的命中行为必须与快照前一致，stats 的计数保持原值。11) define_pipeline 返回 id、hash、group，group 在 define 时分配，重复定义同一 id 不得换组；register 返回 status、id、hash、group、generation；keys 按注册顺序，stats 返回 entries、bytes、hits、misses、evictions、generation。12) store_blob 成功返回 id、bytes、total_bytes，快照里的二进制以十六进制保存，恢复后再次快照应与原快照等价。

硬约束：并发 register 同一 id 只能有一个 stored，其余 duplicate，条目数为一；并发 get 计数不丢；快照跨重启保住兼容组与 LRU；条目数和字节数是硬预算。验收：python3 -m pytest -q tests 十五条全过，不得改测试、跳过或写死输入；并发和恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- difficulty: 困难
