# GSB Bugfix Task

## 题面

开放世界项目在集显机器上试点可变速率着色，关卡组反馈树冠与远景贴图交界处出现方块状清晰度跳变，UI 文字跟着 tile 一起发糊；更糟的是同一帧里同一块 tile 被两次写入不同速率，驱动直接丢弃整张率图，画面一半变黑。排查下来，`gsb/batch46-game-f-02` 下的 `variable_rate_shading_guard.py` 里 `VrsGuard` 目前是空壳，负责率图维护、内容自适应推导、附件合并、脏 tile 失效和快照恢复，所有公开方法都还没有行为。任务类型是 Bugfix，需要先把这套率图管理补齐再继续试点。

需要实现并保持可导入的方法（签名沿用骨架）：`normalize_rate(rate: str) -> str`；`supported_rates() -> list[str]`；`set_base_rate(rate: str) -> dict`；`set_tile_rate(tile: tuple[int, int], rate: str, *, source: str = "api") -> dict`；`set_rate_map(mapping: dict[tuple[int, int], str]) -> dict`；`rate_at(pixel: tuple[int, int]) -> str`；`derive_rates(tile_stats: list[dict]) -> dict`；`mark_dirty(tile: tuple[int, int]) -> bool`；`flush() -> list[tuple[int, int]]`；`apply_attachment(attachment: list[dict]) -> dict`；`coverage_image_size(width: int, height: int) -> dict`；`memory_usage() -> int`；`stats() -> dict`；`snapshot() -> dict`；`restore(snap: dict) -> dict`；`reset() -> int`。

具体故障与边界：1) 速率写成 `1x1`、`1x2`、`2x1`、`2x2` 这种形式，每边只允许 1/2/4，大小写与首尾空格不敏感，`3x3` 抛 `VRS_BAD_RATE`；构造时 `1x1` 必须在支持列表里，否则同样报 `VRS_BAD_RATE`。2) 率图按 tile 稀疏存储，未覆盖 tile 使用 `base_rate`；像素负坐标报 `VRS_BAD_PIXEL`，tile 负坐标报 `VRS_BAD_TILE`。3) 设置不支持的速率（默认集合下的 `4x4`、`2x4`）要回退到面积不超过请求值的最大支持速率，返回 `fallback=True` 并累计 `fallback_count`。4) `set_rate_map` 必须整体校验后一次性写入，任意一项速率非法或超出显存预算时抛错且一条都不能生效。5) 每个 tile 条目占 32 字节，新增条目超过 `memory_budget` 抛 `VRS_MEMORY_BUDGET`；覆盖已存在 tile 不增加占用。6) 修改 `base_rate` 只影响未覆盖 tile，并把当前所有已登记 tile 标脏；`base_rate` 未变时 `changed=False` 且不产生脏 tile。7) `derive_rates` 规则：`motion > 32` 强制 `1x1`；`variance < 1` 取支持列表里最粗的速率；`1 <= variance < 8` 取 `1x2`（不支持时退回最粗）；其它取 `1x1`；结果按 tile 坐标升序返回。8) `apply_attachment` 优先级高者胜，同优先级取面积更小（更精细）的速率，低优先级条目计入 `skipped` 且不覆盖已有速率。9) `flush` 按行主序返回脏 tile 并清空，没有脏 tile 时返回空列表且不计入 `flushes`。10) `coverage_image_size` 按每个 tile 的实际尺寸与速率计算着色调用次数，边缘不足一个 tile 时按剩余像素向上取整，`ratio` 保留六位小数。11) 快照要能被 JSON 往返，恢复率图、脏集合、计数器与序号；版本、配置或条目非法时抛 `VRS_SNAPSHOT_INVALID` 且原状态不变。12) `reset` 清空率图与脏集合、递增 `epoch` 并返回新的 `epoch`。

并发与预算约束：`set_tile_rate`、`set_rate_map`、`flush`、`snapshot` 会在渲染线程和编辑器导出线程里同时调用，必须由同一把可重入锁保护；八个线程各写 25 个不同 tile 后，率图恰好 200 条、`changes` 恰好 200，且 flush 能一次拿全。`coverage_image_size` 在 4K 分辨率、16x16 tile 下要在一帧预算内算完，只能按 tile 累加，不得逐像素查表；`flush` 只处理脏 tile，不做全图扫描。

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
