# GSB Bugfix Task

## 题面

海外酒店机顶盒固件升级后，5.1 片源在立体声电视上人声几乎听不见、爆炸场面削顶失真；另一批设备把左右声道接反。追查后确认不同封装的声道顺序不一致，而混音矩阵直接按索引相乘。这两种现象听感上完全不同，一个是增益分配错，一个是声道映射错，必须分开修。问题在 gsb/batch46-game-h-04/audio_channel_layout_guard.py 的 ChannelLayout，负责声道布局登记、下混矩阵生成、矩阵缓存、流式处理、重排和峰值统计，任务类型 Bugfix。

公开接口：define(self, name: str, channels: list) -> tuple、layouts(self) -> list、channels(self, name: str) -> tuple、build_matrix(self, source: str, target: str, *, center_gain_db: float = -3.0, surround_gain_db: float = -3.0, normalize: bool = True) -> dict、activate(self, source: str, target: str, *, center_gain_db: float = -3.0, surround_gain_db: float = -3.0, normalize: bool = True) -> dict、process(self, frames: list) -> dict、downmix(self, source: str, target: str, frames: list, *, center_gain_db: float = -3.0, surround_gain_db: float = -3.0, normalize: bool = True) -> dict、remap(self, source: str, target: str, frames: list) -> dict、peak(self, frames: list) -> list、snapshot(self) -> dict、restore(self, snapshot: dict) -> None、stats(self) -> dict、reset_stats(self) -> None、close(self) -> None，close 幂等、重复调用不报错。异常统一 LayoutError，带 code 和 detail，stats 返回 builds、cache_hits、cache_evictions、frames_processed、clipped_samples、activations、restores 以及 cached_matrices。

现场行为要求：内置 mono、stereo、quad、5.1、7.1，声道顺序固定为 mono 只有 C、stereo 是 L 和 R、5.1 是 L、R、C、LFE、Ls、Rs，channels 按登记顺序返回，未知布局返回 LAYOUT_UNKNOWN；define 成功返回登记后的声道元组，重名返回 LAYOUT_DUP，空名或空列表返回 LAYOUT_BAD，未知声道返回 LAYOUT_UNKNOWN_CHANNEL，重复声道返回 LAYOUT_DUP_CHANNEL，超过 max_channels 返回 LAYOUT_LIMIT；下混规则是同名零分贝直通，目标缺 C 时源 C 以 center_gain_db 分到左右，目标缺 Ls 或 Rs 时源 Ls、Lb 折到左、Rs、Rb 折到右并使用 surround_gain_db，目标为 C 且源无 C 时左右以 center_gain_db 折到 C，目标没有 LFE 时源 LFE 丢弃；build_matrix 的 rows 按目标声道顺序给出，每行是源索引和增益分贝的二元组列表并按索引升序，normalize 为假时返回原始增益且 attenuation_db 全为零；normalize 为真时每个目标行线性增益和超过一就整体衰减到一，normalized 置真，attenuation_db 给出该行衰减分贝，衰减超过 max_attenuation_db 返回 LAYOUT_CLIP_RISK；矩阵缓存命中累计 cache_hits，缓存超过 cache_size 淘汰最旧一条并累计 cache_evictions，stats 的 cached_matrices 反映当前条数；activate 之后 process 使用当前矩阵，没有激活矩阵返回 LAYOUT_NO_ACTIVE；process 和 downmix 单次帧数超过 max_frames 返回 LAYOUT_FRAME_LIMIT，帧宽与源声道数不符返回 LAYOUT_FRAME_MISMATCH，两种失败都不增加处理计数；输出采样超出负一到一按符号截断并计入 clipped_samples，返回值里的 clipped 是本批削顶数；remap 只做等声道数的置换，返回值同样带 frames 和 clipped，声道数量或集合不一致返回 LAYOUT_COUNT_MISMATCH；peak 返回每个声道的绝对值峰值，空批次返回空列表，帧宽不一致返回 LAYOUT_FRAME_MISMATCH；snapshot 保留布局、激活矩阵和统计，restore 对 version 不符或结构损坏返回 LAYOUT_SNAPSHOT_INVALID 且不改现有状态，恢复后 restores 加一；reset_stats 清零计数但保留布局与激活矩阵。

硬约束：activate 必须在锁内完成矩阵构建和指针替换，process 只读取同一份矩阵快照，多线程下不允许前几帧按旧矩阵、后几帧按新矩阵的混合结果，缓存淘汰也在同一把锁内；重启后恢复自定义布局、激活矩阵和统计，process 结果要与恢复前逐样本一致；布局声道数、单批帧数、矩阵缓存条数都有硬上限；同一组参数只构建一次矩阵，重复构建不计入 builds；process 每次只持锁完成一次矩阵快照的读取和混音。

验收按 python3 -m pytest -q tests 执行，15 条用例必须全过；不得修改测试、不得跳过、不得针对固定输入硬编码；并发矩阵切换要自行复跑；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- difficulty: 困难
