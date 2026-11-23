# GSB Bugfix Task

## 题面

美术组验收新抗锯齿管线时发现远处栏杆边缘每隔一帧闪一次，同一份提交在集显机器上还会让显存占用一路涨到被驱动踢掉；工具组用同一份样本表做离线截图，出来的颜色和运行时对不上。排查下来，`gsb/batch46-game-f-01` 里的 `msaa_resolve_guard.py` 目前只是个空壳，`MsaaResolve` 负责多采样颜色与深度样本的写入、深度测试、按 tile 解析、显存预算和快照恢复，但所有公开方法都还没有行为。任务类型是 Bugfix，需要把这套样本管理补齐后才能继续验收。

需要实现并保持可导入的方法（签名沿用骨架）：`configure(*, sample_count: int | None = None, tile_size: int | None = None, resolve_mode: str | None = None, memory_budget: int | None = None) -> dict`；`resize(width: int, height: int) -> dict`；`add_sample(pixel: tuple[int, int], sample_index: int, color: tuple[float, float, float, float], coverage: float = 1.0, depth: float | None = None, stencil: int = 0) -> dict`；`resolve_pixel(pixel: tuple[int, int]) -> dict`；`resolve_depth(pixel: tuple[int, int]) -> dict`；`resolve_tile(tile: tuple[int, int]) -> dict`；`resolve_all() -> dict`；`flush_dirty() -> list[tuple[int, int]]`；`set_alpha_to_coverage(enabled: bool) -> bool`；`memory_usage() -> int`；`stats() -> dict`；`snapshot() -> dict`；`restore(snap: dict) -> dict`；`reset() -> int`。

具体故障与边界：1) `sample_count` 只接受 1/2/4/8/16，其它值抛 `MsaaError`，`code` 为 `MSAA_BAD_SAMPLE_COUNT`，且不得改动已有状态；2) 采样下标越界报 `MSAA_SAMPLE_INDEX`，像素超出 `resize` 设定的边界报 `MSAA_PIXEL_OOB`，颜色不是四通道 0..1 报 `MSAA_BAD_COLOR`；3) 同一像素同一下标写入与现有内容完全相同的样本时返回 `status="unchanged"`、`code="MSAA_DUP_WRITE"`，重复写计数加一，但不重复计显存、不再次标脏；4) 带深度的同下标覆盖走小于测试，新深度更远或相等时返回 `status="rejected"`、`code="MSAA_DEPTH_REJECT"`，旧样本保留且 `rejected_depth` 加一；5) 解析颜色按覆盖度加权平均，`coverage` 为参与样本覆盖度之和除以 `sample_count`，空像素返回 `resolved=False` 和全零颜色；6) `resolve_mode` 支持 `average`/`min`/`max`，`min`/`max` 逐通道取极值；7) 覆盖度为 0 的样本不参与颜色、深度和覆盖度统计；8) 开启 alpha-to-coverage 后，写入时 `coverage` 由 alpha 按 `1/sample_count` 四舍五入量化，显式传入的 `coverage` 被忽略；9) `resolve_depth` 返回最近覆盖样本的深度及其模板值，没有深度时返回 `None` 和 0；10) `flush_dirty` 按 tile 行主序（先 y 后 x）返回自上次清空以来变脏的 tile，解析后清空并累计 `tiles_resolved`；11) 新增像素使样本总字节超过 `memory_budget`（每样本 24 字节）时，按 tile 最近写入时间整块淘汰并让 `evictions` 加一，若只剩当前 tile 仍放不下则抛 `code="MSAA_MEMORY_BUDGET"` 且不得写入；12) 快照必须可 JSON 序列化并能还原样本、脏 tile、计数器与淘汰顺序，版本或字段非法时抛 `MSAA_SNAPSHOT_INVALID` 且原状态不变。

并发与一致性是硬约束：`add_sample`、`resolve_all`、`flush_dirty`、`snapshot`/`restore` 会被渲染线程与工具线程同时调用，必须由同一把可重入锁保护，任何时刻快照都不能看到写了一半的样本；八个线程各写 25 个不同像素后，样本总数必须精确等于 200。另外，离屏工具会把快照落盘后在新进程里恢复再继续解析，恢复前后同一像素的解析结果必须逐字段一致；单帧解析也不允许把已经解析过的 tile 重复整块扫描。改变 `sample_count` 或调用 `reset` 要递增 `epoch` 并清空样本，只改 tile 尺寸同样清空样本但不递增 `epoch`。

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
