# GSB Bugfix Task

## 题面

海面在风暴关卡里像一块塑料布：Gerstner 波叠加后高度与法线各算各的，浪尖反光位置偏一帧；海面网格切 LOD 时接缝处顶点顺序随机，同一帧两次构建 checksum 对不上；泡沫只增不减，船开过去十分钟还在；改 8 个浪以后远处网格丢了，近处又超预算。这个问题在上周的性能回归里已经挂了三天：同一片海域从近岸开到远海，网格顶点数每帧跳变，帧率从 60 掉到 38；QA 用固定相机连拍 30 帧，checksum 每次都不一样，无法做逐帧对比。更麻烦的是，同一个浪高在 CPU 采样与网格顶点上对不上，浮力物体漂到波峰处会突然下沉。修复范围是 Python 模块 gsb/batch46-game-d-02，文件 water_wave_guard.py，类 WaterWaves，任务类型 Bugfix。

接口：set_water_level(level: float) -> dict；add_wave(wave_id: str, *, amplitude: float, wavelength: float, steepness: float, direction: tuple[float, float], speed: float) -> dict；remove_wave(wave_id: str) -> dict；sample_height(x: float, z: float, t: float | None = None) -> float；sample_normal(x: float, z: float, t: float | None = None) -> tuple[float, float, float]；splash(x: float, z: float, amount: float) -> dict；foam_at(x: float, z: float) -> float；step(dt: float, *, frame: int) -> dict；build_mesh(frame: int, *, rings: int = 3, center: tuple[float, float] = (0.0, 0.0)) -> dict；lod_for(distance: float) -> int；另有 snapshot、restore、stats。错误抛 WaterWaveError，带 code。

要求：1) 波幅、波长必须大于 0，steepness 在 [0,1]，direction 长度 2 且非零向量，speed 非负，否则 WW_INVALID_WAVE，方向为零向量时不能直接归一化；2) 活跃波数达到 max_waves 后新增报 WW_WAVE_LIMIT，且旧波、水位、泡沫全部不变；3) 高度为 water_level 加各波 amplitude*sin(k*(dx*x+dz*z)-speed*k*t)，k=2*pi/wavelength，方向先归一化，t 为空时用内部累计时间，同一 t 重复采样必须返回相同浮点结果；4) 法线由解析偏导归一化得到，不能只返回 (0,1,0)，波幅为 0 时也必须是单位向量，法线方向必须与高度场梯度一致，不能独立维护一份查表值；5) 泡沫按整数格 floor(x)、floor(z) 存储，splash 累加后裁剪到 [0,1]，负值和非有限值报 WW_INVALID_FOAM；6) step 的 dt 限定 (0,2.0]，按 FOAM_DECAY_PER_SECOND 线性衰减且不低于 0，帧号等于上次返回 ignored/WW_DUP_FRAME，小于上次报 WW_STALE_FRAME，时间不得回退；7) build_mesh 只接受当前帧，rings 限 1..4，先校验范围再算预算；第 r 环分辨率 max(2, resolution >> r)，每环 res*res 个顶点，顶点总数与环半径无关；8) 顶点顺序固定为环号升序、z 升序、x 升序，x/z 取 center 加 (下标-(res-1)/2)，每个顶点按 (x, z, height) 三元组返回，总数超 max_vertices 报 WW_BUDGET_EXCEEDED 且不落状态；9) 同一帧重复 build 返回 cached，只计一次 builds，换帧后必须重新构建而不是返回上一帧缓存；10) 波的插入顺序不得改变 mesh checksum，checksum 按 wave_id 排序计算，删除后重新添加同名波要得到相同 checksum；11) lod_for 阈值：小于 16 返回 0，小于 48 返回 1，小于 128 返回 2，其余 3，负距离或 NaN 报 WW_INVALID_DISTANCE；12) snapshot/restore 覆盖水位、波表、时间、泡沫、帧号与统计，恢复后下一次 step 必须从快照帧继续。

硬约束：sample_height 必须线程安全，200 次并发采样后 stats 的 samples 恰好 200，采样路径不得改写泡沫与时间；restore 先校验 version，版本不符 WW_SNAPSHOT_VERSION，结构缺失 WW_SNAPSHOT_INVALID 且原子失败，失败后内存里不能留下半份波表。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得改测试、跳过或按固定坐标写死；并发与恢复自行验证，至少覆盖多线程采样和恢复失败两条路径；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- difficulty: 困难
