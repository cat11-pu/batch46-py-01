# GSB Bugfix Task

## 题面

室内关卡换用光照探针以后，角色走到墙角颜色突然跳变，同一位置两次采样结果不同；摄影师把曝光调高，探针颜色溢出成纯白；程序化烘焙一批探针时中间一条坐标越界，整批既没写完又留下半份数据；删掉一盏灯对应的探针后，周围像素直接报错黑屏。美术在三个室内关卡里都复现了同一个现象：同一个角色站在门槛上左右各半步，探针颜色从暖黄直接跳到冷蓝，中间没有过渡；烘焙工具重跑后同一坐标的结果还会变，无法判断是数据问题还是插值问题。修复范围是 Python 模块 gsb/batch46-game-d-03，文件 light_probe_guard.py，类 LightProbe，任务类型 Bugfix。

接口：set_probe(coord: tuple[int, int, int], *, color: tuple[float, float, float], valid: bool = True) -> dict；remove_probe(coord: tuple[int, int, int]) -> dict；invalidate(coords: list[tuple[int, int, int]]) -> dict；probe_at(position: tuple[float, float, float]) -> dict；sample_many(positions: list[tuple[float, float, float]]) -> list[dict]；bake(frame: int, updates: list[dict]) -> dict；set_exposure(exposure: float) -> dict；grid_shape() -> tuple[int, int, int]；另有 snapshot、restore、stats。错误统一 LightProbeError。

行为要求：1) 网格由 bounds 与 spacing 推导，每轴节点数为 round((max-min)/spacing)+1，spacing 必须大于 0 且每轴至少 2 个节点，bounds 的 min 必须小于 max，否则构造即报 LP_INVALID_CONFIG；2) 坐标必须是整数三元组且落在网格内，浮点坐标或越界坐标报 LP_INDEX_RANGE；3) 角点顺序固定 c000,c100,c010,c110,c001,c101,c011,c111，权重按四面体插值计算并保证总和为 1，同一位置重复采样的权重必须逐位一致，不能依赖字典遍历顺序；4) 位置先 clamp 到 bounds，返回 clamped 标志与命中的 cell，clamp 只影响采样点，不修改已存探针；5) 某个角点 valid=False 时其权重必须为 0，其余角点权重重新归一化，若有效权重之和为 0 也要在有效角点内重新分配而不能除零，八个角点全不可用报 LP_NO_VALID_PROBE；6) 完全相同的坐标再次 set_probe 视为更新，不增加 probes 计数；新增坐标超过 max_probes 报 LP_BUDGET_EXCEEDED，更新已有坐标不受限，valid=False 的条目仍占名额；7) invalidate 只把存在的坐标置为不可用，返回 invalidated 与 missing 计数，重复失效同一坐标只算一次；8) bake 先整批校验再应用，任一坐标越界、颜色通道非有限或长度不为 3 报 LP_INVALID_UPDATE，且一个探针都不改动；成功时 generation 加 1，空批次返回 noop 不加代；9) bake 帧号等于上次返回 ignored/LP_DUP_FRAME，小于上次报 LP_STALE_FRAME，重复帧不得重复写探针；10) 曝光取 (0,16]，颜色乘曝光后每通道裁剪到 64，非法曝光报 LP_INVALID_EXPOSURE，曝光变化不改变已存颜色，只影响采样输出；11) sample_many 保持输入顺序并逐个返回 cell、weights、color、clamped，任一位置失败不能吞掉前面的结果；12) snapshot 的探针列表按坐标排序，restore 原子替换并校验 version，恢复后 generation 与帧号必须与快照一致。

硬约束：probe_at 与 set_probe 共用一把锁，300 次并发采样后 stats 的 samples 恰好 300，采样过程不得修改探针表和 generation；snapshot 覆盖 bounds、spacing、曝光、探针表、帧号与 generation，版本不符报 LP_SNAPSHOT_VERSION，结构缺失报 LP_SNAPSHOT_INVALID 且状态不变，失败后采样仍可继续。

验收：python3 -m pytest -q tests 的 15 条全部通过；不得修改测试、跳过或按固定坐标写死；并发与恢复场景自行验证，至少覆盖多线程采样和恢复失败两条路径；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- difficulty: 困难
