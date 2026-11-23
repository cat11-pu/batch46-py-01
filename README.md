# GSB Bugfix Task

## 题面

内测的逃生关卡一开服就被投诉：贴着右侧墙走，脚步声明明在右边，耳机里却从左边出来；玩家原地转个身，远近十几个声源全糊在脑袋中间；五十米外的怪物嘶吼压过贴脸的开枪声；一次爆炸同时拉进八十多个音效，音频线程卡了四百毫秒，画面跟着掉帧。运营已经把声像、衰减、容量和并发这四类现象列为 P0，四个场景目前都能稳定复现，修复后要在同一台机器上同时跑通。gsb/batch46-game-g-01 的 spatial_audio_guard.py 里，SpatialAudio 负责听众与声源的注册、声像计算、距离衰减和混音汇总，任务类型是 Bugfix，战斗、场景、UI 和回放四条路径共用同一张声源表，任何改动都要对四条路径同时成立。

公开接口保持以下签名（Python 类型注解）：__init__(*, max_sources: int = 64, max_listeners: int = 4)；add_listener(listener_id: str, *, position: tuple[float, float, float] = (0.0, 0.0, 0.0), yaw: float = 0.0, master_gain: float = 1.0) -> dict；update_listener(listener_id: str, *, position=None, yaw=None, master_gain=None) -> dict；add_source(source_id: str, *, position=(0.0, 0.0, 0.0), gain: float = 1.0, priority: int = 0, category: str = "sfx") -> dict；move_source(source_id: str, position, *, velocity=None, sequence: int | None = None) -> dict；move_batch(updates: list[dict]) -> list[dict]；pan_gains(listener_id: str, source_id: str) -> dict；mix(listener_id: str) -> dict；set_environment(*, ref_distance: float = 1.0, max_distance: float = 100.0) -> dict；stats() -> dict；snapshot() -> dict；restore(snapshot: dict) -> None。

已定位到的具体故障和边界：

一、听众默认朝 +X，右耳方向是 -Y。声源在正右方时 pan 必须为 +1、左增益 0、右增益等于衰减值；正前方 pan 为 0，左右按等功率 cos/sin(π/4) 各分 0.707107。

二、yaw 要参与旋转：yaw=90 度时正右方声源落在正中，yaw=180 度时同一位置变成全左，不能只看世界坐标。

三、近场分母下限 0.5 米：水平距离 0.25 米的侧向声源 pan 只能到 0.5，不允许直接拉到正负 1。

四、衰减公式为 ref_distance / max(distance, ref_distance)，distance 到达 max_distance 时整段置零；pan_gains 同时返回 gain_l、gain_r、pan、distance、attenuation。

五、声源满 max_sources 时，只有新声源优先级严格高于现有最低优先级，才驱逐其中最老的一个，被驱逐 id 放进返回值的 evicted 字段；否则抛 SPA_SOURCE_LIMIT。

六、重复 id 抛 SPA_SOURCE_EXISTS，未知声源抛 SPA_SOURCE_UNKNOWN，remove_source 对未知 id 返回 False。

七、每个声源维护单调 sequence；小于等于已见值的移动返回 status=ignored、code=SPA_SEQUENCE_STALE，位置保持原样。move_batch 内旧序号跳过、新序号继续，结果顺序与入参一致。

八、move_batch 必须整批先校验：只要有一个 id 不存在就抛 SPA_SOURCE_UNKNOWN，整批位置一个都不改，moves 计数也不增加。

九、mix 按注册顺序给出每个声源的 id、gain_l、gain_r、pan、distance、attenuation，顶层带 count 和左右总增益；每调用一次 mix，mix_calls 加一。

十、stats 需要包含 sources、listeners、max_sources、max_listeners、mix_calls、moves、evictions、listener_updates。

十一、并发硬约束：多线程同时 move_source、add_source 和 mix 时，单个方法必须原子；压测里 moves 要精确等于成功移动次数，任何一次 mix 都不能读到半更新的坐标，所有左右增益落在 0 到 1 之间，声源数不得超过上限。

十二、快照硬约束：snapshot 必须是可直接 json 序列化的深拷贝；restore 后听众、声源、环境、sequence 和统计计数都回到快照时刻，恢复后继续加声源、混音的行为与未重启一致，不能残留旧对象引用。

验收：在项目根执行 python3 -m pytest -q tests，15 条测试全部通过；不允许改测试、跳过或用固定输入写死结果；并发与恢复场景自行补线程与快照验证；只做本仓库实现，不接外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- difficulty: 困难
