# GSB Bugfix Task

## 题面

体积雾在夜战地图上突然整片发灰：同一帧先做深度重建再做散射，近处建筑边缘出现锯齿亮带；切镜头后上一帧的历史 Froxel 仍被采样，拖影要残留半秒；把 jitter 调到 0.25 以后画面抖动每帧还不一样，抓帧复现不了。这个问题在凌晨的压测里被放大：同一张地图连续跑 600 帧，GPU 抓帧显示雾层亮度逐帧抬升，只有重启客户端才恢复；策划要求今天下班前给出根因和补丁，明天上午用新的体积雾效果做版本验收。修复范围是 Python 模块 gsb/batch46-game-d-01，文件 volumetric_fog_guard.py，类 VolumetricFog，任务类型 Bugfix，深度重建、散射、重投影、解析四条调用路径共用同一份状态。

公开接口按现有骨架实现：set_camera(camera_id: str, *, near: float, far: float, reversed_z: bool = False, jitter: tuple[float, float] = (0.0, 0.0)) -> dict；add_light(light_id: str, *, intensity: float, position: tuple[float, float, float], radius: float, color: tuple[float, float, float] = (1.0, 1.0, 1.0)) -> dict；remove_light(light_id: str) -> dict；inject_media(media_id: str, *, density: float, height_falloff: float, extinction: float) -> dict；reconstruct_depth(frame_id: int, depth: list[float], *, width: int, height: int) -> dict；scatter(frame_id: int, *, samples_per_froxel: int = 8) -> dict；resolve(frame_id: int) -> dict；reproject(frame_id: int, motion: list[tuple[float, float]]) -> dict；另有 history_state、snapshot、restore、stats。错误统一抛 FogError，code 字段固定。

故障与边界逐条对齐：1) 未设置相机就重建必须报 FOG_NO_CAMERA，不能退化成单位矩阵继续算；2) 深度里的 NaN/Inf 按远平面距离处理并计入 invalid，不能参与 min/max；3) reversed_z 为真时原始值 1 对应 near、0 对应 far，标准深度则 0 对应 near；4) frame_id 等于上一次重建帧返回 cached 且复用上次的 linear，小于上次报 FOG_STALE_FRAME；5) 切镜头清空历史与帧计数，旧镜头的运动矢量不得再参与重投影，history_state 返回 frames=0、last_frame=None，新帧从 1 重新开始；6) jitter 按帧奇偶交替，奇数帧取 (jx, jy)，偶数帧取 (-jx, -jy)，均落在 resolve 返回的 jitter 字段，同一帧重复解析不得改变偏移；7) 光源 radius 必须大于 0，position 三个分量必须有限，否则 FOG_INVALID_LIGHT，删除不存在的光源返回 missing 而不是抛错；8) 每 Froxel 采样数限定 1..64，且 Froxel 数乘采样数不得超过 max_sample_units，超限报 FOG_SAMPLE_BUDGET 且不改任何状态，失败请求不能留下半份散射结果；9) 介质 density 必须在 [0,1]，extinction 不得为负，重复 id 返回 updated 而不新增；10) 网格 Froxel 总数超过 max_froxels 必须拒绝，构造失败后不能留下可用的半初始化对象；11) reproject 的 motion 长度等于 grid_x*grid_y，单轴位移绝对值超过 64 像素判失效，任一失效整帧历史清零并返回 accepted/rejected 计数，下一帧重新从零累积；12) 光源插入顺序不得影响散射 checksum，checksum 按 light_id 排序后计算，同一组输入重复散射必须得到同一个 checksum。

两条硬约束：所有写路径必须加锁，16 个线程并发注入不同介质后 stats 的 media 计数必须恰好为 16，不能出现丢写或重复计数，读路径也不能在遍历途中看到半更新的字典；snapshot 覆盖相机、光源、介质、帧号、历史与统计，restore 先校验 version 再原子替换，版本不符报 FOG_SNAPSHOT_VERSION，结构缺失报 FOG_SNAPSHOT_INVALID 且当前状态完全不变，失败后仍可继续正常渲染。

验收：在工作目录执行 python3 -m pytest -q tests，15 条测试必须全部通过；不得修改测试、跳过用例或按固定深度数组写死输出；并发与快照恢复要自行验证，至少覆盖多线程写入和失败回滚两条路径；只做本地实现，不涉及上游提交，也不要引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- difficulty: 困难
