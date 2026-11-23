# GSB Bugfix Task

## 题面

开放世界切到夜间后，远处建筑的间接光一块亮一块黑：辐照度体素更新没有按预算切片，一帧里全量重算导致卡顿；脏区没合并，同一批体素被重复更新十几次；冻结关卡后美术还能改体素，快照回滚又把 generation 弄回旧值；三线性采样在边界上出现 NaN。这个问题在夜间关卡切图时最明显：角色从隧道走进广场，墙面间接光先闪一块黑斑再慢慢补上；性能面板显示辐照度更新一帧内跑了两万多体素，主线程尖峰 50ms；美术在冻结关卡后仍能通过调试面板改体素，回滚快照又把 generation 降回旧值，光照缓存直接失效。修复范围是 Python 模块 gsb/batch46-game-d-05，文件 irradiance_volume_guard.py，类 IrradianceVolume，任务类型 Bugfix。

接口：set_voxel(index: tuple[int, int, int], *, sh: tuple[float, ...]) -> dict；mark_dirty(box: tuple[int, int, int, int, int, int]) -> dict；update(frame: int) -> dict；sample(position: tuple[float, float, float]) -> dict；freeze() -> dict；unfreeze() -> dict；generation() -> int；clear() -> dict；另有 snapshot、restore、stats。错误统一抛 IrradianceVolumeError。

要求：1) dims 每轴至少 1 且三元乘积不超过 max_voxels，voxel_size 大于 0，max_updates_per_frame 至少 1，否则 IR_INVALID_CONFIG，构造失败不能留下半初始化对象；2) 体素坐标必须落在 dims 内，否则 IR_INDEX_RANGE，sh 必须是长度 9 的有限浮点序列，长度不符或含 NaN/Inf 报 IR_INVALID_VOXEL；3) set_voxel 自动把该坐标加入脏集，重复写同一坐标脏集仍只有一份，返回值给出 dirty 计数；4) mark_dirty 的 box 顺序为 minx,miny,minz,maxx,maxy,maxz，min 大于 max 报 IR_INVALID_BOX，越界坐标裁剪到体积范围并在返回值给出 clamped 与 added，完全在体外的 box 不报错但 added 为 0；5) update 按坐标字典序取前 max_updates_per_frame 个体素，返回 processed、remaining、generation，没有脏体素时返回 noop 且不增加 generation，processed 与 remaining 之和必须等于调用前的脏数；6) update 的 frame 等于上次返回 ignored/IR_DUP_FRAME，小于上次报 IR_STALE_FRAME，帧号不能回退，重复帧不得消耗预算；7) freeze 后 set_voxel、mark_dirty、clear 一律报 IR_FROZEN，unfreeze 恢复，冻结状态下 update 仍可消费已有脏集但不能新增内容；8) sample 采用三线性插值，节点中心在 (i+0.5)*voxel_size，位置先裁到 [0,dims*voxel_size]，u=p/voxel_size-0.5，i0=clamp(floor(u),0,dim-2)，frac=clamp(u-i0,0,1)，权重总和为 1，cell 返回下界索引，clamped 表示输入是否越界；9) 未写入的体素按 9 个 0 参与插值，不存在的角点不能被当作缺测跳过，否则边界会出现 NaN；10) clear 清空体素与脏集并把 generation 加 1，冻结状态下 clear 报 IR_FROZEN；11) snapshot 的 values 与 dirty 按坐标排序，restore 校验 version 后原子替换，版本不符 IR_SNAPSHOT_VERSION，结构缺失 IR_SNAPSHOT_INVALID，失败后当前体素、脏集与 generation 都不变；12) 统计至少包含 voxels、dirty、generation、frames，计数在并发写入后仍要精确。

硬约束：脏集与体素表共用一把锁，64 个线程并发写不同坐标后 voxels 与 dirty 都恰好 64，不能丢写或重复计数；snapshot 要保留冻结标志、脏集、generation 与帧号，恢复失败不得留下半份状态。

验收：python3 -m pytest -q tests 的 15 条全过；不得修改测试、跳过或按固定坐标写死；并发与快照恢复自行验证，至少覆盖多线程写入和恢复失败两条路径；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- difficulty: 困难
