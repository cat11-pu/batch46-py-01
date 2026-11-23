# GSB Bugfix Task

## 题面

关卡组把深度预通道接进开放世界主渲染后，石墙后面的树丛照样被整片提交，半透明植被又被提前剔掉，画面出现空洞；同一场景第二次进关时深度图残留上一帧数据，远处山体整块消失；还出过一次单帧提交的绘制数量失控、命令缓冲直接爆掉的事故。排查下来，`gsb/batch46-game-f-03` 里的 `depth_prepass_guard.py` 中 `DepthPrepass` 还是个空壳，负责深度缓冲维护、保守遮挡查询、绘制预处理与排序、单 pass 资源上限和快照恢复，所有公开方法都没有行为。任务类型是 Bugfix，需要先补齐这套预通道管理。

需要实现并保持可导入的方法（签名沿用骨架）：`set_viewport(width: int, height: int, near: float = 0.1, far: float = 1000.0) -> dict`；`begin_pass() -> int`；`end_pass() -> dict`；`submit_draw(draw: dict) -> dict`；`write_depth(pixel: tuple[int, int], depth: float) -> dict`；`depth_at(pixel: tuple[int, int]) -> float | None`；`build_pyramid() -> list[dict]`；`hiz_query(rect: tuple[int, int, int, int], depth: float) -> bool`；`sorted_draws() -> list[dict]`；`filter_opaque(draws: list[dict]) -> list[str]`；`memory_usage() -> int`；`stats() -> dict`；`snapshot() -> dict`；`restore(snap: dict) -> dict`；`reset() -> int`。

具体故障与边界：1) 未设置 viewport 就 `begin_pass` 抛 `DP_NOT_READY`；宽高必须是正整数、`near >= 0` 且 `far > near`，否则抛 `DP_BAD_VIEWPORT` 且不得改动已有状态。2) `begin_pass` 每次清空深度缓冲与层级缓存、递增 pass 序号；重复 `begin_pass`，或没 begin 就 `end_pass`/`submit_draw`，一律抛 `DP_PASS_STATE`。3) `write_depth` 只接受 0..1，越界抛 `DP_DEPTH_RANGE`，像素越界抛 `DP_PIXEL_OOB`；同一像素保留更近（更小）的深度，数值相等时保留先写入的，`depth_writes` 只统计真正改变缓冲的写入。4) 绘制必须带 `id`、`depth_min`、`depth_max`、`bounds`；`depth_min > depth_max`、负深度或退化矩形抛 `DP_BAD_DRAW`；矩形超出 viewport 抛 `DP_DRAW_OOB`。5) 同一 pass 内重复 id 返回 `status="ignored"`、`code="DP_DUP_DRAW"`，不进入排序也不占名额。6) 单 pass 已调度数量达到 `max_draws` 后再提交抛 `DP_TOO_MANY_DRAWS`，已调度列表保持原样。7) 不透明绘制用整 tile 最大深度做保守剔除：覆盖到的每个 tile 的最大深度都不大于 `depth_min` 才判为 `occluded`，tile 内没有深度的像素按远平面 1.0 处理，不能把只覆盖半个 tile 的绘制误剔。8) `alpha_test=True` 的绘制永不参与遮挡测试，排序时统一排在不透明之后。9) `end_pass` 先按 `(depth_min, id)` 升序输出不透明 id，再输出同样排序的透明 id；`state_switches` 统计相邻材质变化次数，`draws` 为本 pass 输出条数，`occluded` 为本 pass 剔除数。10) `build_pyramid` 从 tile 最大深度逐级二分直到 1x1，返回每级 `width`/`height`；`hiz_query` 的矩形必须非空且落在 viewport 内（否则 `DP_RECT_OOB`），深度必须在 0..1（否则 `DP_DEPTH_RANGE`），没有任何几何的区域返回 `False`。11) `filter_opaque` 按 `depth_min` 升序返回不透明绘制的 id，缺字段抛 `DP_BAD_DRAW`；`sorted_draws` 返回当前 pass 的排序视图并带 `transparent` 标记。12) 快照要能 JSON 往返，包含 viewport、深度缓冲、当前 pass 的 active 状态、序号、已提交绘制、剔除数与计数器；恢复后可以直接继续 `end_pass`；版本或字段非法时抛 `DP_SNAPSHOT_INVALID` 且原状态不变。

并发与资源约束：`write_depth`、`submit_draw`、`end_pass`、`snapshot` 会被主渲染线程和后台烘焙线程同时调用，必须由同一把可重入锁保护，任何快照都不能看到写了一半的深度或绘制列表；八个线程各写 25 个不同像素后，`depth_pixels` 与 `depth_writes` 都必须精确等于 200。层级结构在深度写入后只重建一次并复用，连续多次 `hiz_query` 不得每次重新扫描整张深度图。

验收：`python3 -m pytest -q tests` 的 15 条必须全过；不得修改或跳过测试，不得针对固定输入写死结果；并发与快照恢复场景自行补测；只做本地实现，不涉及上游提交。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- difficulty: 困难
