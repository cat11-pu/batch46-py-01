# GSB Bugfix Task

## 题面

渲染线程在窗口拉伸后频繁崩溃：池在上一帧仍被 GPU 引用时就整体重置，描述符集指针隔帧变成野指针；不同布局交替分配后空闲描述符回不来，两分钟后池耗尽；同一个 set 句柄被重复分配，画面采样到上一帧的阴影贴图。请修复 gsb/batch46-game-e-04 的 descriptor_pool_guard.py 中 DescriptorPool（Bugfix），负责按帧分配的 arena、按类型预算、重置时序和句柄世代。需要保持这些公开方法：define_layout(self, layout_id: str, *, counts: dict[str, int]) -> dict、begin_frame(self, frame_id: int) -> dict、allocate(self, frame: int, set_id: str, layout: str) -> dict、free(self, set_id: str) -> dict、retire_frame(self, frame: int) -> dict、reset_frame(self, frame: int) -> dict、set_of(self, set_id: str) -> dict、generation_of(self, set_id: str) -> int、usage(self) -> dict、stats(self) -> dict、snapshot(self) -> dict、restore(self, state: dict) -> dict。

故障与边界：1) 布局必须先在预算里声明类型，空 id、空 counts、非正数量或重复 id 分别报 DSC_LAYOUT_INVALID、DSC_DUP_LAYOUT，未声明类型报 DSC_UNKNOWN_TYPE，布局定义为不可变副本，后续外部修改 dict 不得影响池。2) allocate 前必须有 recording 状态的帧，未 begin 或已 retire 报 DSC_NO_ARENA，未知帧报 DSC_FRAME_UNKNOWN，未知布局报 DSC_UNKNOWN_LAYOUT。3) 活着的 set_id 重复分配报 DSC_DUP_SET；free 后的 id 可在同一帧重新分配且世代不变，同一 set_id 即使跨帧也不能同时存活，句柄按全局唯一校验。4) 按类型预算与 max_sets 双重限制，超限一律 DSC_POOL_EXHAUSTED，detail 的 kind 为 type 或 sets，失败必须整体回滚不得只扣一半计数，同一请求的多个类型要么全部扣减成功，要么全部不生效。5) free 归还原布局的全部描述符，旧句柄立即失效，set_of 与 generation_of 报 DSC_SET_INVALID，重复 free 必须失败而不是静默。6) 帧处于 recording 时 reset_frame 报 DSC_FRAME_IN_FLIGHT 且集合保持有效；retire_frame 回收该帧全部集合并返回 reclaimed 顺序；重复 retire 报 DSC_FRAME_RETIRED，只回收该帧仍存活的集合，已 free 的不重复扣减。7) 同一帧 id 再次 begin 世代加一，重新分配同名 set 的世代随之加一，旧世代句柄不可用。8) 在飞帧数超过 max_frames_in_flight 时 begin 报 DSC_FRAME_IN_FLIGHT；重复 begin 同一 recording 帧报 DSC_DUP_FRAME，且不得重置该帧已分配的集合与世代。9) 退役一帧不得影响另一帧的集合与计数，usage 的 sets、free_sets、types、frames 始终自洽，free_sets 必须等于上限减存活数，出现负数视为实现错误。10) 快照 version 为 4，恢复要保留未结帧、句柄世代与用量，并能继续分配与退役；用量与集合重算不一致、版本错误或集合计数与布局不匹配均报 DSC_SNAPSHOT_INVALID，恢复后 usage 与 stats 必须与快照记录一致，不能靠重新分配补齐。11) begin_frame 返回 frame、generation、active；define_layout 返回 layout 与 counts；每个已分配 set 的 counts 必须等于布局，不能部分分配。12) stats 返回 allocations、frees、retires、failures、high_water_sets、high_water_types，回收后的用量必须回到退役前水平，高水位只在成功分配后更新，失败请求不得推高。

硬约束：并发分配不同 set 时预算扣减必须原子且不丢；并发抢同一 set id 只能有一个成功；重启恢复后不能重复发放描述符；max_sets 与各类型预算都是硬上限。验收：python3 -m pytest -q tests 十五条全过，禁止修改测试、跳过或写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- difficulty: 困难
