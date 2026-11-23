# GSB Bugfix Task

## 题面

帧时间面板在驱动升级后开始出现负数与尖峰：同一帧主通道耗时比整帧还大，查询槽位在命令缓冲尚未执行完就被下一帧占用，统计图每隔几秒跳一次；跨零点录制的日志里四十八位时间戳回绕被当成巨大负数，p95 直接失去意义。请修复 gsb/batch46-game-e-01 目录下 gpu_timestamp_guard.py 里的 GpuTimestamp（任务类型 Bugfix），它负责逐帧时间戳采集、跨帧退役与分位数统计，四条调用路径共用同一份状态。需要保持这些公开方法：begin_frame(self, frame_id: int, *, queue: str = "graphics") -> dict、write_timestamp(self, frame_id: int, stage: str, ticks: int) -> dict、end_frame(self, frame_id: int, *, completed: bool = True) -> dict、frame_stats(self, frame_id: int) -> dict、percentiles(self) -> dict、calibrate(self, gpu_ticks: int, cpu_ns: int) -> dict、pool_usage(self) -> dict、snapshot(self) -> dict、restore(self, state: dict) -> dict。

具体故障与边界：1) 阶段顺序固定为 begin、shadow、main、post、end，只能严格向后，首阶段不是 begin 按 GTS_STAGE_ORDER 拒绝，重复阶段报 GTS_DUP_STAGE，未知阶段报 GTS_UNKNOWN_STAGE。2) 同一帧内时间戳减小且上一戳未过半圈时报 GTS_TIME_REWIND，失败不得改写已记录阶段或耗时。3) 上一戳位于半圈之后、新戳变小视为四十八位回绕，结果累加 2^48 且 wrap_count 加一，整帧耗时为末减首。4) 每帧占用一个查询槽，帧未结束不得复用；槽位耗尽报 GTS_POOL_EXHAUSTED，同时在飞帧超过上限报 GTS_FRAME_BUSY，重复 begin 报 GTS_DUP_FRAME，已完成帧再操作报 GTS_FRAME_CLOSED，未知帧报 GTS_UNKNOWN_FRAME。5) 完成帧返回 durations_ns（首阶段为 0，其余为相邻阶段差，按校准比例折算纳秒并四舍五入）与 gpu_ns、wrap_count；未完成帧 gpu_ns 为 0、durations_ns 为空且不进分位数。6) 校准比例 ticks_per_ns 等于 gpu_ticks 除以 cpu_ns，非正参数报 GTS_CALIBRATION_INVALID，校准只影响之后结束的帧，不追溯已完成帧。7) 分位数只统计已完成帧，按 gpu_ns 升序取最近秩 ceil(p/100*n)，输出 count、p50、p95、p99、frames，无数据为 0。8) 快照 version 必须为 1，含已完成帧与校准；恢复时丢弃未结帧、槽位全部回收，版本或结构不符报 GTS_SNAPSHOT_INVALID。9) pool_usage 的 slots、in_flight、free 必须随时自洽，begin 先判在飞上限再判槽位。10) 快照恢复后历史分位数与帧列表必须逐项一致。11) 允许跳过中间阶段但不能回头，相邻阶段时间戳相等合法且耗时为 0；begin_frame 返回 frame、slot、queue，queue 原样进入帧统计，帧号必须为整数。12) 任何错误都必须保持帧状态不变，错误码只用于拒绝非法输入，正常帧不得被误判，之后仍可写入合法阶段并正常结束；快照必须可 JSON 序列化，恢复后再次快照应与原快照等价，end_frame 与 frame_stats 对已完成帧返回同一份统计。

硬约束：多线程并发写同一实例时槽位分配、阶段追加、计数更新必须原子，不能重复占槽或丢计数；重启恢复必须与快照一致；查询槽位和在飞帧数属于硬上限。验收：python3 -m pytest -q tests 十五条必须全过，不得修改测试、跳过或用固定输入写死；并发与恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- difficulty: 困难
