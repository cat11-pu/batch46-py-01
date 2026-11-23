# GSB Bugfix Task

## 题面

客服昨天收到一段会议录音的转写结果：三十秒的空调噪声被当成连续发言，两个说话人之间只隔一次呼吸却切成了八段，安静房间里的底噪又被判成语音，整场会议的时间轴全乱了。gsb/batch46-game-g-03 的 voice_activity_guard.py 由 VoiceActivity 负责按帧能量判定、挂起时长、最短语音门槛、分段记录和阈值校准，任务类型 Bugfix，实时通话、会议转写和直播切片三条链路共用这套状态机，任何一处状态迁移写错都会同时影响三条链路。质检要求这次修复覆盖安静房间、嘈杂会议室和单人直播三种输入。

公开接口（Python 类型注解）：__init__(*, max_streams: int = 32, frame_ms: int = 20, threshold_db: float = -35.0, hangover_ms: int = 200, min_speech_ms: int = 60, margin_db: float = 9.0)；create_stream(stream_id: str, *, sample_rate: int = 16000) -> dict；drop_stream(stream_id: str) -> bool；streams() -> list[str]；frame_size(stream_id: str) -> int；feed(stream_id: str, frame: list[float]) -> dict；feed_batch(stream_id: str, frames: list[list[float]]) -> list[dict]；set_threshold(stream_id: str, threshold_db: float) -> dict；calibrate(stream_id: str, frames: list[list[float]]) -> dict；state(stream_id: str) -> dict；segments(stream_id: str) -> list[dict]；close_segment(stream_id: str) -> dict；stats() -> dict；snapshot() -> dict；restore(snapshot: dict) -> None。

现象与边界：

一、帧长由 sample_rate * frame_ms / 1000 得出，16k、20ms 为 320；长度不符抛 VAD_FRAME_SIZE。feed_batch 必须先校验整批，第二帧坏掉时第一帧也不能落库，stats 的 frames 和流的 index 保持原值。全零帧能量记为 -180.0。

二、能量用 RMS 转 dBFS，0.5 常量帧为 -6.021；采样必须是有限浮点且绝对值不超过 1，NaN 或 1.5 抛 VAD_FRAME_INVALID。

三、默认阈值 -35 dB，能量严格大于阈值才算语音；set_threshold 只接受 -90 到 0，越界抛 VAD_THRESHOLD_RANGE，设置成功后清空已校准的噪声底。

四、最短语音按 ceil(min_speech_ms / frame_ms) 帧计算，60ms、20ms 为 3 帧；feed 返回的 segment 在前两帧为 None，第三帧才给出 id。feed 与 state 都要带 index（首帧之前是 -1）、state、speech、threshold_db、noise_floor_db、hangover_left。

五、挂起帧数为 ceil(hangover_ms / frame_ms)，60ms、20ms 为 3；语音后连续三个静音帧仍是 speech=True、state=hangover，第四个静音帧才转 silence 且 speech=False。

六、分段记录字段为 id、start、end、frames、speech_frames；四个 0.5 帧加四个静音帧（挂起 3）应得到 start=0、end=6、frames=7、speech_frames=4；stats 里的 frames、speech_frames、segments、discarded、streams、max_streams 要同步准确。

七、短促噪声不能计入分段：一个 0.5 帧加三个静音帧、最短语音 3 帧时，segments 为空、discarded 加一、segments 计数不增加。

八、calibrate 用这批帧的平均能量作为噪声底，阈值取 min(0, 噪声底 + margin_db)；0.003 常量帧的噪声底约 -50.458，阈值约 -41.458，之后的 -46 dB 帧保持静音，-40 dB 帧判为语音，噪声底要从 state 读得到。

九、close_segment 强制结束当前段：有活动段时返回 closed=True 和完整 segment，状态回到 silence；没有活动段时返回 closed=False、segment=None。

十、流生命周期：重复 id 抛 VAD_STREAM_EXISTS，超过 max_streams 抛 VAD_STREAM_LIMIT，drop_stream 对未知 id 返回 False 并释放名额，其余未知流操作抛 VAD_STREAM_UNKNOWN。

十一、并发硬约束：八个线程各自向独立流喂帧时方法内部必须原子，统计的 frames 与 speech_frames 精确等于各线程总量，每路 index 停在最后一个已处理帧，不允许串帧或丢帧。

十二、快照硬约束：snapshot 可 json 序列化，停在一半挂起窗口时 restore 后 index、state、hangover_left 和活动段都要复原；随后继续喂同样的静音帧，得到的分段与未重启时完全一致。

验收：项目根运行 python3 -m pytest -q tests，15 条测试全过；不得修改测试、跳过或写死输入；并发与恢复场景要自己加线程和快照复测；实现限定在本地标准库内。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- difficulty: 困难
