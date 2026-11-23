# GSB Bugfix Task

## 题面

带屏音箱的免提通话上线后被大量投诉：对方能听到自己半秒前的声音，说话时自己的音量忽大忽小，安静时又冒出一串断续回声；有台设备从待机唤醒后参考信号整段丢失，回声直接穿过去；还有一批设备报告通话十几分钟后噪声越来越大。gsb/batch46-game-g-04 的 echo_cancel_guard.py 中，EchoCancel 负责参考信号环形缓冲、采集块对齐、延迟估计、双讲判定和会话统计，任务类型 Bugfix，通话、语音助手和录屏三条业务共用这套底层。

公开接口（Python 类型注解）：__init__(*, max_sessions: int = 8, max_push_samples: int = 4096, filter_len: int = 512, max_delay_ms: float = 50.0)；create_session(session_id: str, *, sample_rate: int = 16000, delay_hint_ms: float = 0.0) -> dict；close_session(session_id: str) -> bool；sessions() -> list[str]；push_reference(session_id: str, samples: list[float]) -> dict；reference(session_id: str, length: int | None = None) -> list[float]；push_capture(session_id: str, samples: list[float]) -> dict；align(session_id: str) -> dict；set_delay(session_id: str, delay_samples: int) -> dict；delay_samples(session_id: str) -> int；double_talk(session_id: str) -> bool；reference_level_db(session_id: str) -> float；flush(session_id: str) -> dict；stats(session_id: str) -> dict；snapshot() -> dict；restore(snapshot: dict) -> None。

现象与边界：

一、参考缓冲是容量 filter_len 的环形队列，只保留最新采样。容量 8 时先推 1 到 6 再推 7、8、1、2，缓冲应为 3 到 8 再接 1、2，本次 dropped 为 2、total_dropped 为 2；reference 返回全部，reference(session, 3) 返回最后三个。

二、单次推送长度超过 max_push_samples 抛 ECH_BUDGET_EXCEEDED；空列表、非数值、NaN 抛 ECH_SAMPLES_INVALID。两种拒绝都要在改动缓冲和计数之前发生，拒绝后 pushed_samples 仍为 0。

三、create_session 的 sample_rate 限定 8000 到 192000，max_delay_samples 等于 round(sample_rate * max_delay_ms / 1000)，16k、50ms 为 800；delay_hint_ms 换成的采样数写进初始延迟，10ms 对应 160。set_delay 只接受 0 到 max_delay_samples 的整数，越界抛 ECH_DELAY_RANGE。

四、align 对采集块和参考缓冲的候选窗口做减去均值后的归一化互相关，延迟从 0 枚举到 min(max_delay_samples, 缓冲长度减采集长度)，取分数最高者；最高分达到 0.5 才更新延迟并返回 aligned=True、delay、score、candidates，否则保持原延迟。

五、参考缓冲 64 点、采集块取参考索引 43 到 58 时应估出延迟 5、score 为 1.0；采集块取最后 16 点时应估出延迟 0。没有参考、采集不足 4 点或可用窗口不足时，align 返回 aligned=False、当前延迟、score=0.0、candidates=0。

六、push_capture 在没有参考信号时返回 underrun=True 并累加 underruns；参考到位后再推同一批采集块应为 False，且 underruns 不再增长。

七、double_talk 在采集 RMS 超过参考 RMS 两倍时返回 True，0.3 对 0.1 成立、0.15 对 0.1 不成立；采集或参考为空时返回 False。

八、reference_level_db 按缓冲 RMS 转 dBFS，空缓冲为 -180.0，0.5 常量缓冲约 -6.021。

九、flush 清空参考缓冲和最近采集块，返回 flushed 数量与 buffered=0；累计的 pushed_samples、underruns 等计数保持不变，清空后电平立刻回到 -180.0。

十、会话生命周期：重复 id 抛 ECH_SESSION_EXISTS，超过 max_sessions 抛 ECH_SESSION_LIMIT，close_session 对未知 id 返回 False 并释放名额，其余未知会话操作抛 ECH_SESSION_UNKNOWN。stats 必须给出 sample_rate、buffered、captures、pushed_samples、dropped_samples、underruns、alignments、delay_samples、max_delay_samples。

十一、并发硬约束：八个线程各向自己的会话连续推送时，加锁范围要覆盖缓冲写入与计数更新；结束后每路 pushed_samples 与 buffered 精确等于写入量，不允许出现半截样本或串会话。

十二、快照硬约束：snapshot 可以 json 序列化，包含配置、每个会话的参考缓冲、最近采集块、延迟和全部计数；restore 后 reference 内容与推送总量回到快照时刻，再跑一次 align 仍得到原来的延迟。

验收：项目根执行 python3 -m pytest -q tests，15 条测试全部通过；不得改测试、跳过或按固定输入硬编码；并发与恢复要自行验证；只允许标准库实现，不接真实声卡。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- difficulty: 困难
