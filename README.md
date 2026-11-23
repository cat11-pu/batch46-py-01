# batch46-game-b-03 SpectatorDelay

## 题面

直播上线后，观战端比选手早三秒看到击杀，暂停恢复时同帧推两次，断线重连整场重放，慢消费者顶满网关内存，重复序号没拦，乱序帧让画面倒退，延迟按本地时区算差八小时。gsb/spectator_delay_guard 的 spectator_delay_guard.py、类 SpectatorDelay，任务类型 Bugfix。
接口（返回 dict）：subscribe(viewer: str, *, match: str)；ingest(match: str, frame: dict)；poll(viewer: str, *, now: str, max_items: int = 10) -> list[dict]；set_delay(match: str, seconds: int)；pause(match: str)；timeline(match: str) -> list[dict]。
故障：1）可见时刻为 occurred_at 加当时延迟，按 UTC 解析并换算偏移；2）按序号升序交付，队头未到点后面的帧不得越过；3）重复序号返回 ignored/SPECT_DUP_SEQ，不增缓冲；4）set_delay 只影响之后写入帧，已入队帧 deadline_ts 不变，timeline 可查；5）暂停时 poll 为空，恢复后按原序交付；6）超 queue_cap 丢最小序号未交付帧，dropped 递增；7）观众数达 viewer_cap 后新订阅抛 SPECT_FULL；8）重复订阅同场返回 existing 和游标；9）退订留游标，重订不重放已交付帧；10）poll 最多 max_items 条，其余留在 backlog；11）快照恢复只重放未交付帧；12）未知场次抛 SPECT_UNKNOWN_MATCH，未知观众抛 SPECT_UNKNOWN_VIEWER；queue_depth 给 buffered、dropped，stats 给 viewers、matches、delivered。
硬约束：八线程并发 poll 同一观众，每帧只交付一次，总数等于写入数且不重复；恢复后游标、缓冲、交付计数与快照一致。验收：python3 -m pytest -q tests 全过，不得改测试、跳过或写死输入；并发与快照自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- 所属领域：游戏、图形与多媒体
- 子方向：游戏开发
- 任务类型：Bugfix
- 难度：地狱
