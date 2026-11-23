# GSB Bugfix Task

## 题面

场景组把远景树木改成公告板替身以后，玩家转身时整片树林会在两帧之间来回跳视角，像被人反复扇风；同一批树在 30 米附近 LOD 反复切换，阴影跟着一起闪；美术重新烘焙一版贴图后，图集里旧的替身格没有释放，新替身把图集挤爆，运行时报 atlas 分配失败。排查下来，`gsb/batch46-game-f-05` 的 `billboard_impostor_guard.py` 中 `ImpostorGuard` 目前是空壳，负责替身网格登记、图集格分配、alpha 轮廓、视角量化与滞回、LOD 切换和快照恢复，所有公开方法都没有行为。任务类型是 Bugfix，需要先补齐这套替身管理。

需要实现并保持可导入的方法（签名沿用骨架）：`register_mesh(mesh_id: str, *, bounds: tuple[float, float, float, float, float, float], vertex_count: int, material: str | None = None) -> dict`；`bake(mesh_id: str, view_index: int, *, samples: list[tuple[float, float, float]], alpha_cutoff: float = 0.5) -> dict`；`atlas_cell(mesh_id: str, view_index: int) -> dict`；`silhouette(mesh_id: str, view_index: int) -> dict`；`view_index(yaw: float) -> int`；`best_view(mesh_id: str, yaw: float) -> int`；`select_view(mesh_id: str, yaw: float) -> dict`；`lod_for(mesh_id: str, distance: float) -> dict`；`evict(count: int) -> list[dict]`；`memory_usage() -> int`；`stats() -> dict`；`snapshot() -> dict`；`restore(snap: dict) -> dict`；`reset() -> int`。

具体故障与边界：1) 构造时校验 `view_count` 取 4..64、`cell_size >= 1`、`atlas_size` 是 `cell_size` 的整数倍、`memory_budget` 至少能容纳一个格子（`cell_size^2*4` 字节）、`hysteresis_ratio` 在 0..1，否则抛 `IMP_BAD_CONFIG`。2) `register_mesh` 的 bounds 是六个有限数且包围盒非退化，`vertex_count >= 1`；同 id 且字段完全一致返回 `status="unchanged"`，不一致抛 `IMP_DUP_MESH`，缺字段或非法抛 `IMP_BAD_MESH`。3) `bake` 的 samples 非空、每个 `(u, v, alpha)` 都在 0..1，`alpha_cutoff` 也在 0..1，违反抛 `IMP_BAD_SAMPLES`；未知网格抛 `IMP_UNKNOWN_MESH`，视角越界抛 `IMP_BAD_VIEW`。4) 轮廓只统计 `alpha >= alpha_cutoff` 的样本，返回 `u0`/`v0`/`u1`/`v1` 与 `coverage`；没有任何覆盖样本时四个边界都是 0、`coverage` 为 0，烘焙仍然成功。5) 每个 `(mesh, view)` 只占一个图集格；重复烘焙复用原格并返回 `status="rebaked"`，格数与显存都不增长，但要更新轮廓和最近使用时间。6) 图集容量是 `(atlas_size // cell_size)^2`，新增格超出容量抛 `IMP_ATLAS_FULL` 且不自动淘汰；新增格使字节数超过 `memory_budget` 抛 `IMP_MEMORY_BUDGET`，同样不得分配。7) `atlas_cell` 返回 `index`/`x`/`y`/`size`，按行优先布局；未烘焙的组合抛 `IMP_NOT_BAKED`。8) `view_index` 把任意角度按 `360/view_count` 分桶，先归一到 `[0, 360)` 再加半桶取整取模；8 个视角时 0、22.5、44.9、200、-10、360 分别对应 0、1、1、4、0、0，非数值抛 `IMP_BAD_VIEW`。9) `select_view` 首次调用返回 `switched=True`、`reason="initial"`；当前视角与 yaw 的角度差不超过半个桶加一个滞回桶宽时保持原视角（`reason="kept"`），否则切到候选视角（`reason="switched"`）并累加 `view_switches`。10) `best_view` 是无状态的纯量化结果，不改变当前视角。11) `lod_for` 以 10/30/80 为距离阈值：升档要求距离不小于阈值乘 `(1+hysteresis_ratio)`，降档要求距离不大于较小阈值乘 `(1-hysteresis_ratio)`，避免在阈值附近抖动；首次调用返回 `changed=True`，非法距离抛 `IMP_BAD_DISTANCE`。12) 快照要能 JSON 往返，包含网格、格子（index、最近使用序号、轮廓）、当前视角、当前 LOD 和全部计数器；恢复后 `select_view`/`lod_for` 行为与原来一致；版本、配置、格索引重复或越界、轮廓越界等非法输入抛 `IMP_SNAPSHOT_INVALID` 且原状态不变。

并发与资源约束：`bake`、`atlas_cell`、`silhouette`、`evict`、`snapshot` 会被资源流送线程和编辑器预览线程同时调用，必须由同一把可重入锁保护，任何一次烘焙都不能拿到正在被淘汰的格子；八个线程各对 8 个网格烘 8 个视角、正好填满 64 格图集后，`cells` 必须等于 64，且 64 个 `index` 两两不同。`evict` 按最近使用时间从旧到新淘汰并返回实际淘汰的 `{mesh, view}` 列表，读轮廓和读格子坐标也要刷新使用时间。

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
