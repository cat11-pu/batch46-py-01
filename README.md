# GSB Bugfix Task

## 题面

副本服进入晚高峰后出现规律性卡死：GC 停顿两秒，恢复后调度器把停顿期间欠下的四十多个 tick 一次性补算，玩家看到怪物瞬移、技能连放，下一轮停顿更深。策划还发现同一个波次刷新任务在每周四维护后提前十秒触发，越维护越早，原因是下次触发时间拿当前时间而不是上次执行时间推算。任务回调里只要有一个空指针，整个 tick 循环就停摆，其他玩法全部冻结；有的系统在回调里注册新任务，结果在同一 tick 内被立刻执行，重入把队列改乱。帧预算被写死成无限，单帧串行跑二十个重任务，帧率掉到个位数；任务表只增不删，跑三天积累十几万条；取消过的定时器仍在下一帧被拉起来。运维重启后当前 tick 归零，所有任务的相位重新对齐，同一批补偿奖励被再发一次。Python 模块 gsb/batch46-game-c-04，文件 tick_scheduler_guard.py，类名 TickScheduler，任务类型 Bugfix，要求修复 tick 推进、任务表、预算与快照。

关键接口：`schedule(self, task_id: str, handler: Callable[[], None], *, every: int = 1, delay: int = 0, priority: int = 0, cost: int = 0) -> dict`、`cancel(self, task_id: str) -> bool`、`advance(self, elapsed_ms: int) -> List[dict]`、`tick(self) -> dict`、`current_tick(self) -> int`、`now(self) -> int`、`pending(self) -> List[str]`、`due(self, tick: int) -> List[str]`、`drift(self) -> int`、`stats(self) -> dict`、`snapshot(self) -> dict`、`restore(self, snapshot: dict) -> None`。

需要逐条修掉的行为：

1. advance 以 tick_ms 为步长推进，不足一帧的余量留在 now 里成为 drift，不能提前执行；
2. 单次补算最多执行 max_catchup 个 tick，更早的欠账计入 dropped，并从目标 tick 往前取窗口；
3. 周期性任务按 next_due 相位推进，every 为 2 的任务在 tick 1、3、5 执行，不随补算漂移；
4. 同一 tick 内按优先级降序执行，同优先级按 task_id 升序，任务注册顺序不影响结果；
5. 回调抛异常只禁用该任务并记 failures，其余任务和后续 tick 继续；
6. 回调中注册的新任务从下一 tick 起参与调度，不能在当前 tick 内重入；
7. 单 tick 累计 cost 超过 budget_ms 时，剩余任务整体推迟到下一 tick 开头，overruns 与 deferred 有计数；
8. 取消过的任务永不再执行，取消不存在的任务报 TICK_UNKNOWN_TASK；
9. task_id 重复、every 小于 1、delay 为负、handler 不可调用统一报 TICK_TASK_DUP 或 TICK_INVALID_TASK；
10. 活跃任务数达到 max_tasks 后新注册报 TICK_TASK_LIMIT，取消后空出的名额可以复用；
11. 负的 elapsed_ms 报 TICK_INVALID_ELAPSED，且不能改动 now、tick 和任务相位；
12. 快照要包含 now、当前 tick、任务相位与累计统计，恢复后继续推进产生的执行序列与未重启时一致，版本不符报 TICK_SNAPSHOT_VERSION。

硬约束：schedule、cancel、advance 必须互斥，多线程同时注册任务时任务表不丢不重，回调内再注册也不能死锁；快照恢复必须还原 tick 编号和每个任务的 next_due，不允许把相位清零重排；max_tasks 与 budget_ms 是硬资源上限，任何异常路径都不能突破。验收以 python3 -m pytest -q tests 为准，15 条必须全过；不得修改测试、跳过或用固定输入写死；并发和重启场景请自行压测确认；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
