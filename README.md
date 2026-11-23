# GSB Bugfix Task

## 题面

格斗游戏开放 120Hz 模式后，高刷屏玩家反馈画面一顿一顿：同一个招式在 60Hz 设备上顺滑，在 144Hz 显示器上却隔几帧猛跳一次；帧时间偶尔冲到 25 毫秒，画面直接卡住，声音却还在走；切后台再回前台，计时器倒退，帧队列错乱；连续掉帧几分钟后帧率越降越低，回到主菜单也恢复不了。gsb/batch46-game-g-05 的 frame_pacing_guard.py 中，FramePacer 负责 vsync 对齐、帧截止时间、迟到丢弃、自适应帧率和统计窗口，任务类型 Bugfix，渲染主循环、过场动画和录屏三条路径都要用。复现用的机器已经就位，60、120、144 三个刷新率档位都能压出同一条时间轴。

公开接口（Python 类型注解）：__init__(*, target_fps: float = 60.0, vsync_hz: float = 60.0, max_late_ms: float = 8.0, max_in_flight: int = 4, history: int = 240, min_fps: float = 30.0)；configure(**kwargs) -> dict；start(start_us: int = 0) -> dict；now_us() -> int；advance(now_us: int) -> int；begin_frame(frame_id: str) -> dict；end_frame(frame_id: str) -> dict；drop_frame(frame_id: str) -> bool；in_flight() -> list[str]；set_target_fps(fps: float) -> dict；adaptive_fps() -> float；percentile(p: float) -> float；stats() -> dict；snapshot() -> dict；restore(snapshot: dict) -> None。

现象与边界：

一、帧截止时间是严格晚于开始时刻的下一个 vsync 边界。vsync 100Hz 周期为 10000 微秒，开始于 0 或 5000 的帧截止都是 10000，开始于 10000 的帧截止是 20000，不能把边界上的时刻算进上一格。

二、按时结束返回 action=present、missed=False；迟到不超过 max_late_ms 仍算 present，但 missed=True，并给出正的 late_us；迟到超过 max_late_ms 时 action=drop、计入 dropped、missed 仍为 True，且不进入时长窗口。

三、重复的 frame_id，包括已经结束过的 id，再次 begin 抛 PAC_FRAME_EXISTS；end 未知 id 抛 PAC_FRAME_UNKNOWN；drop_frame 对未知 id 返回 False，对在飞帧返回 True 并同时累加 dropped 与 missed。

四、在飞帧数量达到 max_in_flight 时，新的 begin 抛 PAC_INFLIGHT_LIMIT；in_flight 按开始顺序返回 id，结束一个后可立刻补进一个。

五、时钟只前进不后退：advance 接收绝对微秒并返回增量，1000 之后再传 500 抛 PAC_CLOCK_REGRESS，now_us 保持 1000，任何状态都不许被这次失败调用改掉。

六、percentile 用最近排名法，覆盖只保留最后 history 条已呈现帧时长；无样本返回 0.0。四帧时长 1000、2000、3000、4000 时，p0 为 1000、p50 为 2000、p95 为 4000；history 为 3 而实际跑了五帧时，p0 应取最后三条里最小的 3000。

七、自适应降档：连续三次 missed（包括被丢弃的帧）后目标帧率减 10，60 降到 50、75 降到 65，但不得低于 min_fps 30；一次按时呈现会把连续 miss 计数清零。

八、自适应升档：连续 120 次按时呈现后目标帧率加 5，最高不超过 set_target_fps 设置的配置上限；从 50 出发先升到 55，再跑满 120 次升到 60。

九、set_target_fps 只接受 min_fps 到 240 之间的值，0、-1、1000 以及低于 30 的 10 都抛 PAC_FPS_RANGE；合法调用会同时更新配置上限和当前目标，并清空连续计数。

十、stats 要给出 frames（presented 加 dropped）、presented、dropped、missed、miss_rate、p95_us、target_fps、configured_fps、in_flight、now_us。两帧准时、一帧迟到但未超限、一帧超限被丢时，应为 frames=4、presented=3、dropped=1、missed=2、miss_rate=0.5、p95_us=12000。

十一、并发硬约束：八个线程各跑二十次 begin/end 时，计数更新必须在锁内完成；结束后 frames=160、presented=160、missed=0、in_flight=0，不允许重复计数或漏计。

十二、快照硬约束：snapshot 可 json 序列化，带时钟、计数、目标与配置帧率、在飞帧、时长窗口和已见 id；restore 后时钟回到快照值，在飞帧还能按快照起点正确结束，统计从快照计数继续累加。

验收：项目根执行 python3 -m pytest -q tests，15 条测试全过；不得修改测试、跳过或写死时间戳；并发与恢复场景自行补测；实现只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- difficulty: 困难
