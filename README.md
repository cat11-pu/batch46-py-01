# GSB Bugfix Task

## 题面

热更新后玩家第一次进副本卡顿三秒：同一个着色器被四个线程同时编译，缓存键把 define 顺序当成不同变体，旧驱动留下的二进制混进新驱动缓存导致花屏；磁盘上缓存从两百兆涨到六吉，淘汰时又把正在使用的条目删掉，下一帧全部重编。请修复 gsb/batch46-game-e-02 的 shader_cache_guard.py 中 ShaderCache（Bugfix），负责内容键、变体折叠、LRU 淘汰、编译去重与驱动失效。需要保持这些公开方法：compose_key(self, source_hash: str, driver: str, defines: Sequence[str] = ()) -> str、put(self, source_hash: str, driver: str, defines: Sequence[str], byte_size: int, *, pinned: bool = False) -> dict、get(self, key: str) -> dict、begin_compile(self, source_hash: str, driver: str, defines: Sequence[str] = ()) -> dict、finish_compile(self, key: str, byte_size: int) -> dict、fail_compile(self, key: str) -> dict、trim(self) -> dict、invalidate_driver(self, driver: str) -> dict、variants(self, source_hash: str) -> list[str]、stats(self) -> dict、snapshot(self) -> dict、restore(self, state: dict) -> dict。

故障清单：1) 缓存键格式固定为 source_hash|driver|A=1,B=2，define 去重并按名字排序，重复同名不同值报 SHC_DEFINE_CONFLICT，缺等号或空名空值报 SHC_DEFINE_FORMAT，空哈希或空驱动报 SHC_KEY_INVALID，defines 为空时键以竖线结尾。2) put 新条目返回 stored 与 key、entries、bytes；同键同大小返回 duplicate，同键不同大小报 SHC_SIZE_CONFLICT；byte_size 必须为正整数，否则报 SHC_SIZE_INVALID，重复 put 不得刷新 last_used，除非显式 get。3) put 不主动淘汰，超预算只能由 trim 回收，这是硬规则，预算判断以字节与条目两个维度同时成立为准，trim 不改变 pinned 状态。4) trim 按 last_used 从旧到新淘汰未固定条目，同一时刻再按插入先后决定，直到 bytes 与 entries 都回预算内；全部固定且仍超预算报 SHC_BUDGET_STUCK；返回 evicted 顺序、bytes、entries。5) get 命中刷新 LRU 并返回 hit、byte_size、defines，未命中只累加 misses 并返回 hit 为 False，命中与未命中都不得抛异常，未知键按未命中处理。6) 同一 source_hash 与 driver 的变体数达到 variant_limit 时，put 淘汰最旧未固定变体，全部固定报 SHC_VARIANT_LIMIT，变体折叠只按 source_hash 与 driver 判定，不同驱动互不影响。7) begin_compile 已有条目返回 hit，已有编译中返回 joined，否则返回 compile；finish_compile 未在编译报 SHC_NOT_COMPILING，成功后返回 stored，二进制大小参与预算但不在完成时自动淘汰；fail_compile 清除在飞状态并允许稍后重试。8) invalidate_driver 删除所有非当前驱动的条目，固定的也删，返回 removed 与 bytes，失效不写回磁盘，也不修改命中率。9) stats 返回 hits、misses、evictions、compiles、bytes、entries、hit_rate，命中率为 hits 除以 hits 加 misses 保留四位，空查询为 0.0，淘汰与失效不计入查询次数；keys 按插入顺序返回，variants 只按 source_hash 过滤并保持插入顺序。10) 快照 version 为 2，entries 必须携带 key、source_hash、driver、defines、byte_size、pinned、last_used、seq，恢复要保住字节数、LRU 次序与统计，键与元数据重算不一致报 SHC_SNAPSHOT_INVALID，恢复后 compiling 集合必须清空，重启前未完成的编译允许重新发起。11) keys、variants、evicted 的返回顺序必须确定，不得依赖字典的偶然遍历顺序，返回列表不得出现重复键。

硬约束：并发 begin_compile 同一键只能产生一个 compiler，其余 joined；并发 get 的命中计数不得丢；trim 是唯一淘汰入口；快照跨进程重启后 LRU 行为一致。验收：python3 -m pytest -q tests 十五条全过，禁止改测试、跳过或按固定输入写死；并发和恢复自行验证；本地实现即可。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- difficulty: 困难
