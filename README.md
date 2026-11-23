# GSB Bugfix Task

## 题面

东南亚版本上线后，字幕组反馈同一部剧在 23.976 帧片源上正常，转成 25 帧后整条字幕提前将近一分钟；人工平移之后又发现相邻字幕被并成一条、切分点落在两句话中间；客服收到字幕提前零点四秒的批量投诉，回滚操作还把时间轴改成了负数，剪辑同事还发现合并后的字幕在播放器里只显示第一行，切分后的文本归属也说不清楚。代码在 gsb/batch46-game-h-03/subtitle_sync_guard.py 的 SubtitleSync，负责字幕装载校验、整体平移、帧率换算、重叠合并、单条切分和快照恢复，任务类型 Bugfix。

公开接口：load_cues(self, cues: list) -> int、shift(self, delta_ms: int) -> int、retime_fps(self, source_fps: float, target_fps: float) -> dict、cue_at(self, time_ms: int) -> dict | None、merge_overlaps(self, gap_ms: int = 0) -> int、split_cue(self, index: int, at_ms: int) -> dict、window(self, start_ms: int, end_ms: int) -> list、validate(self) -> list、snapshot(self) -> dict、restore(self, snapshot: dict) -> None、stats(self) -> dict、close(self) -> None。异常统一 SubtitleError，带 code 和 detail，stats 返回 loads、shifts、retimes、merges、splits、ignored、restores 七个计数的副本。close 幂等，重复调用不报错。

现场要修的行为：装载是整批事务，任何一条起点为负、时长小于 min_duration_ms、起点乱序或与前一条重叠，分别返回 SUB_BAD_CUE、SUB_ORDER、SUB_OVERLAP，整批不生效且旧字幕保留，成功装载返回装载条数，失败不改动任何内部状态，成功装载后偏移清零、帧率记录清空；条数超过 max_cues 返回 SUB_LIMIT；shift 平移全部字幕，单次或累计偏移绝对值超过 max_shift_ms 返回 SUB_SHIFT_LIMIT，任何一条平移后起点为负返回 SUB_NEGATIVE_TIME 且全部不动，成功返回累计偏移；retime_fps 按 source_fps 除以 target_fps 线性缩放并四舍五入到整数毫秒，同一对帧率重复调用返回 status 为 ignored、code 为 SUB_RETIME_DUP 且忽略计数加一；换算后任一条时长不足返回 SUB_BAD_CUE，整次换算不生效也不登记帧率对；换算后出现重叠返回 SUB_OVERLAP，同样不生效；cue_at 使用左闭右开区间，无命中返回 None；merge_overlaps 合并间距不超过 gap_ms 的相邻字幕，文本用换行拼接并重排 index，返回减少条数，gap_ms 为负返回 SUB_BAD_ARG；split_cue 在 at_ms 处切成两条，两段都不能短于 min_duration_ms，否则 SUB_BAD_CUE，index 越界返回 SUB_INDEX_UNKNOWN，成功返回 first、second、count 并重排 index，两段沿用同一条文本；window 返回与区间有交集的所有字幕，start 大于等于 end 返回 SUB_BAD_ARG；validate 在正常状态返回空列表，异常时给出 index 和 code；snapshot 保留字幕、累计偏移、已换算帧率对和统计，restore 对 version 不符或结构损坏返回 SUB_SNAPSHOT_INVALID 且不改现有状态，恢复后 restores 加一，重复的帧率换算仍会被识别为 SUB_RETIME_DUP。

硬约束：平移、换算、合并、切分统一在锁内先算新列表再整体替换，读线程任何时刻拿到的都是完整时间轴，不允许出现前两条已平移、后两条未平移的中间态，cue_at、window、snapshot 都基于同一份拷贝；重启后 restore 必须保留累计偏移和已换算帧率集合，重复换算不会再缩放一次；字幕条数受 max_cues 限制，装载先整体校验再替换，避免半份字幕进入内存；所有写操作先构造新列表再一次性替换引用。

验收按 python3 -m pytest -q tests 执行，15 条用例必须全过；不得修改测试、不得跳过、不得按固定输入写死结果；并发读和快照恢复要自行复跑；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- difficulty: 困难
