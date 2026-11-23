# GSB Bugfix Task

## 题面

关卡美术把镜面传送门做成可递归穿行的效果后，玩家站在门厅里就能看到门后房间再套一层同样的房间，走到第三层时模板值溢出、整面墙变成镂空；同一帧里两个相机各调用一次可见性规划，第二次直接把第一份计划覆盖掉，传送门里的物件凭空消失；还出现过帧预算已经超了却往命令缓冲写了半份计划、最终花屏的事故。排查下来，`gsb/batch46-game-f-04` 的 `stencil_portal_guard.py` 中 `StencilPortal` 目前是空壳，负责房间与传送门图、逐层模板标记、每帧可见性规划、预算拒绝和快照恢复，所有公开方法都没有行为。任务类型是 Bugfix，需要先补齐这套传送门管理再继续做镜面关卡。

需要实现并保持可导入的方法（签名沿用骨架）：`register_room(room_id: str, *, bounds: tuple[int, int, int, int] = (0, 0, 1, 1)) -> dict`；`unregister_room(room_id: str) -> dict`；`register_portal(portal_id: str, *, source: str, target: str, transform: list[float], enabled: bool = True) -> dict`；`set_portal_enabled(portal_id: str, enabled: bool) -> dict`；`describe_portal(portal_id: str) -> dict`；`stencil_tag(depth: int) -> int`；`reachable_rooms(start: str, max_depth: int | None = None) -> list[str]`；`begin_frame() -> int`；`end_frame() -> dict`；`render_plan(camera_room: str) -> list[dict]`；`validate() -> dict`；`stats() -> dict`；`snapshot() -> dict`；`restore(snap: dict) -> dict`；`reset() -> int`。

具体故障与边界：1) 构造时 `stencil_bits` 取 1..32、`max_depth >= 1` 且 `max_depth + 1 <= stencil_bits`、`frame_budget >= 1`，违反抛 `PORTAL_BAD_CONFIG`。2) `register_room` 同 id 同 bounds 返回 `status="unchanged"`，同 id 不同 bounds 抛 `PORTAL_DUP_ROOM`；bounds 必须是四个整数且矩形非退化，否则抛 `PORTAL_BAD_ROOM`。3) `register_portal` 校验 `source != target`（否则 `PORTAL_BAD_PORTAL`）、两端房间都已注册（否则 `PORTAL_UNKNOWN_ROOM`）、`transform` 必须是 16 个数（否则 `PORTAL_BAD_TRANSFORM`）；同 id 且字段完全相同时重复注册返回 `status="unchanged"`、不占新序号，字段不同抛 `PORTAL_DUP_ID`。4) `unregister_room` 删除房间并级联删除以它为 source 或 target 的传送门，返回按 id 升序的 `removed_portals`；未知房间抛 `PORTAL_UNKNOWN_ROOM`。5) `stencil_tag(depth)` 返回 `((1 << (depth + 1)) - 1)` 与 `stencil_bits` 掩码后的结果，深度越界或非整数抛 `PORTAL_BAD_DEPTH`；8 位、`max_depth=4` 时依次是 1、3、7、15、31。6) `begin_frame` 递增帧号、清零本帧 pass 计数并返回帧号；重复 begin，或没 begin 就 `end_frame`/`render_plan`，抛 `PORTAL_FRAME_STATE`。7) `render_plan` 用广度优先扩展启用的传送门，每个房间只在最近深度出现一次，结果按 `(depth, via, room)` 升序；首房间 `via=None`、`clip_count=0`，之后 `via` 是首次到达它的传送门 id，`ref` 为 `stencil_tag(depth)`，`clip_count` 等于 `depth`。8) 深度超过 `max_depth` 的房间不进入计划；禁用的传送门不参与遍历，但仍出现在 `stats` 和 `validate` 里。9) 同一帧内多次 `render_plan` 的 pass 数累加；本帧已用 pass 加新计划长度超过 `frame_budget` 时抛 `PORTAL_FRAME_BUDGET`，`budget_rejected` 加一，且本帧 passes、plans 与全局 passes 都不变。10) `end_frame` 返回 `frame`、本帧 `passes` 与 `budget_left`，并把帧标记为非活跃。11) `validate` 返回 `ok`、`rooms`、`portals`、`disabled`（禁用传送门 id 升序）和 `isolated`（没有任何启用传送门连接到的房间 id 升序）。12) 快照要能 JSON 往返，包含房间、传送门（含 16 元素 transform 与 enabled）、帧活跃状态、帧号、本帧 passes 和全部计数器；恢复后可以继续 `render_plan`/`end_frame`；版本、配置、端点、transform、帧 passes 越界等非法输入抛 `PORTAL_SNAPSHOT_INVALID` 且原状态不变。

并发与资源约束：`register_portal`、`describe_portal`、`render_plan`、`snapshot` 会被关卡编辑器与渲染线程并发调用，必须由同一把可重入锁保护，规划结果不能读到注册到一半的传送门；八个线程各注册 25 个以不同房间为 source 的传送门后，`portals` 与 `enabled_portals` 都必须精确等于 200。每帧 pass 上限 `frame_budget` 是硬预算，超出时整份计划拒绝而不是截断，也不能把已写入的 pass 计数留下。

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
