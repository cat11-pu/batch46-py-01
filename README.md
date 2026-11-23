# GSB Bugfix Task

## 题面

射击手感投诉集中爆发在跨区匹配上线之后：玩家瞄准高速横移的目标，客户端准星明明压在身上，服务端按当前坐标判定却全是空枪；观战回放里同一次开火在服务端被算到两个身位之外。反外挂组还发现有人伪造客户端 tick，把命中倒放回三秒前已经倒地的目标身上，而服务端只检查了目标当前是否存在就放行。延迟补偿的历史环形缓冲裁剪之后，旧 tick 不报错，直接拿最接近的一帧顶替，插值端点也被算反，目标在两帧之间来回抖；回滚进行中普通位置查询返回的是历史坐标，回滚结束后没有恢复，导致后续 AI 全部基于过期位置寻路；两个射手同时回滚时互相覆盖会话，甚至出现回滚没结束就写入新帧的错乱。Python 模块 gsb/batch46-game-c-03，文件 lag_compensation_guard.py，类名 LagCompensation，任务类型 Bugfix，需要把有界历史、插值、回滚窗口与会话隔离一次修好。

关键接口：`record(self, tick: int, entities: Mapping[str, Tuple[float, float]]) -> int`、`ticks(self) -> List[int]`、`latest(self) -> int`、`pose(self, tick: int, entity: str) -> Tuple[float, float]`、`begin_rewind(self, tick: int) -> int`、`rewinding(self) -> bool`、`rewound_pose(self, entity: str) -> Tuple[float, float]`、`rewound_hit(self, entity: str, point: Tuple[float, float], radius: float = 0.0) -> bool`、`end_rewind(self) -> bool`、`fire(self, shooter: str, target: str, tick: int, point: Tuple[float, float], *, radius: float = 0.0) -> dict`、`snapshot(self) -> dict`、`restore(self, snapshot: dict) -> None`。

需要逐条修掉的行为：

1. 命中 tick 正好等于已记录帧时返回该帧原始坐标，不得插值漂移；
2. tick 落在两帧之间按线性插值，比值由 tick 差计算，端点帧必须精确；
3. 查询早于最旧帧报 LAG_TICK_EXPIRED，晚于最新帧报 LAG_TICK_FUTURE，都不许静默夹取；
4. 重复 tick 写入报 LAG_TICK_DUP，历史保持原样；
5. 落后于最新帧的乱序写入报 LAG_TICK_ORDER，最新帧不被覆盖；
6. 历史容量超过 history 时自动淘汰最旧帧，被淘汰 tick 的查询按过期处理；
7. 回滚会话期间普通 pose 查询仍返回当前帧数据，结束回滚后行为完全恢复；
8. 已有回滚会话时再次 begin_rewind 报 LAG_REWIND_ACTIVE，外层会话不受影响；
9. 回滚 tick 早于 latest - max_rewind 报 LAG_REWIND_TOO_OLD，此时不能留下半开会话；
10. 没有活动会话时 end_rewind、rewound_pose、rewound_hit 一律报 LAG_NO_REWIND；
11. 实体在插值区间任一帧缺失时查询报 LAG_UNKNOWN_ENTITY，不能拿单边坐标凑；
12. fire 在返回值里带上 hit、tick 与 delta，内部自动开关回滚，任何失败路径都不能把会话留在打开状态。

硬约束：record、pose 和 fire 的整个回滚过程必须原子，多个线程同时开火时不得出现 LAG_REWIND_ACTIVE 误报，所有命中结果与单线程一致；快照要覆盖全部历史帧与统计计数，恢复后的 ticks、插值结果和回滚窗口与重启前一致，版本不符报 LAG_SNAPSHOT_VERSION，且恢复时必须清掉未结束的回滚；历史帧数与最大回滚距离都是硬上限，内存不随对局时长增长。验收以 python3 -m pytest -q tests 为准，15 条必须全过；不得修改测试、跳过或按固定输入写死；并发与恢复场景请自行压测确认；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
