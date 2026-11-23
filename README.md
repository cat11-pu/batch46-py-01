# GSB Bugfix Task

## 题面

大厅的反射探针一开镜就闪黑：捕获请求按注册顺序而不是优先级执行，高优先级的角色镜面反射迟迟不更新；一帧里排了 20 个探针，渲染线程被捕获卡住两百毫秒；某个探针第 4 面捕获失败后，旧 cubemap 已被清掉，镜面变成黑块；静态探针被自动刷新系统反复重建，显存暴涨。这个问题在多人副本里最明显：玩家从走廊走进大厅，镜面地板先黑一帧再突然亮起；战斗高峰期捕获线程把主线程拖住，帧时间从 16ms 涨到 40ms；QA 连续切换画质后，静态探针被反复重建，显存占用一路涨到上限。修复范围是 Python 模块 gsb/batch46-game-d-04，文件 reflection_probe_guard.py，类 ReflectionProbe，任务类型 Bugfix。

接口：register_probe(probe_id: str, *, position: tuple[float, float, float], radius: float, priority: int = 0, static: bool = False) -> dict；unregister_probe(probe_id: str) -> dict；request_capture(probe_id: str, *, frame: int, reason: str = "manual") -> dict；dispatch(frame: int) -> dict；capture_face(probe_id: str, face: str, frame: int, *, checksum: str) -> dict；complete_capture(probe_id: str, *, frame: int, checksum: str) -> dict；abort_capture(probe_id: str, *, frame: int) -> dict；pending_captures() -> list[dict]；probe_state(probe_id: str) -> dict；resolve(position: tuple[float, float, float]) -> dict；mip_sizes() -> list[int]；另有 snapshot、restore、stats。错误抛 ReflectionProbeError。

要求：1) radius 必须大于 0，position 三个分量必须有限，priority 非负，重复 id 报 RP_DUPLICATE_PROBE，新增超过 max_probes 报 RP_PROBE_LIMIT，失败时不能留下半注册的探针；2) face_size 必须是 4 到 1024 的 2 的幂，mip_levels 限 1..log2(face_size)+1，否则 RP_INVALID_CONFIG，mip_sizes 从 face_size 逐级减半到不小于 1，末级不能出现 0；3) 未注册探针请求捕获报 RP_UNKNOWN_PROBE，同一探针已有未完成请求时再次请求返回 ignored/RP_ALREADY_PENDING，不能产生两个并发捕获；4) reason 为 auto 且探针 static=True 时返回 ignored/RP_STATIC_PROBE，manual 仍可排队，static 只影响自动刷新；5) 队列按 priority 降序、同优先级按请求序号升序，pending_captures 每行带 probe_id、priority、seq、status，序号从 1 单调递增且不重复；6) dispatch 每帧最多启动 frame_budget 个捕获，返回 started 与 deferred，同帧重复 dispatch 返回 cached 且 started 不变，不能重复启动同一探针；7) 面名只允许 px,nx,py,ny,pz,nz，重复面报 RP_DUP_FACE，非法面报 RP_INVALID_FACE，捕获面必须在已 dispatch 的帧上进行；8) complete 必须六个面齐全，缺面报 RP_INCOMPLETE_FACES，complete 的 frame 必须等于 dispatch 的 frame，否则 RP_STALE_FRAME，失败后已捕面保留供重试或回滚；9) abort 回滚该探针的部分面并把 checksum 恢复为上一次成功捕获值，captures 只统计成功次数，失败和回滚不计入；10) resolve 在半径内选择已有 checksum 的最近探针，等距按 probe_id 升序，半径内没有可用探针报 RP_NO_PROBE，未完成捕获的探针不参与解析；11) 静态探针只是跳过自动请求，不禁止手动捕获，也不影响 resolve 的距离计算；12) snapshot 保留探针表、队列、部分面与计数，restore 校验 version 后原子替换，恢复后队列顺序与序号必须一致。

硬约束：请求队列必须加锁，50 个线程并发请求不同探针后 requests 恰好 50 且 seq 是 1..50 的无重复序列，不能出现两个请求拿到同一个序号；snapshot/restore 版本不符报 RP_SNAPSHOT_VERSION，结构缺失报 RP_SNAPSHOT_INVALID 且状态不变，恢复失败不得破坏当前捕获队列。

验收：python3 -m pytest -q tests 的 15 条全过；不得改测试、跳过或按固定探针写死；并发与恢复自行验证，至少覆盖多线程请求和恢复失败两条路径；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- difficulty: 困难
