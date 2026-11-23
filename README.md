# GSB Bugfix Task

## 题面

晚上八点的音乐直播连续翻车：鼓点一进来输出就被削平，回放里全是破音；主持人喊麦时人声被压成一条平线；安静下来音量又爬得特别慢；切歌瞬间一记爆音从监听窜出来；还有一次处理线程被一个十六万采样的巨型块卡住，整路音频断了半秒。gsb/batch46-game-g-02 的 dsp_limiter_guard.py 中，DspLimiter 负责前视延迟、峰值包络、声道联动和增益统计，任务类型 Bugfix，直播、录制、监听三条链路都调用它，修复要同时兼容三种采样率，不能只在 48k 下成立。值班同学已经把复现录音和三个采样率的工程放在同一台机器上，回归时可以直接对比。

公开接口（Python 类型注解）：__init__(*, sample_rate: int = 48000, ceiling_db: float = -1.0, attack_ms: float = 5.0, release_ms: float = 50.0, lookahead_ms: float = 2.0, max_block_size: int = 4096) -> None；configure(**kwargs) -> dict；ceiling() -> float；latency_samples() -> int；process_block(channel: int, samples: list[float]) -> dict；process_linked(channels: dict[int, list[float]]) -> dict；gain_reduction_db() -> float；channel_gain(channel: int) -> float；stats() -> dict；reset() -> None；snapshot() -> dict；restore(snapshot: dict) -> None。

现象与边界：

一、前视延迟等于 round(sample_rate * lookahead_ms / 1000)，48k、2ms 固定为 96 采样。在 200 长度的块里第 10 个采样放一个脉冲，前 106 个输出必须全零，第 106 个才以单位增益出现，块与块之间延迟线要接得上。

二、增益目标是 min(1, ceiling / max(|峰值|, 1e-12))；目标低于当前增益走 attack，否则走 release，系数为 exp(-1000 / (毫秒 * sample_rate))，不许用固定步长近似。

三、ceiling 为 -6 dB 时，先灌 3000 个 1.0 预热，再处理 1000 个 1.0，peak_out 落在 0.501187 正负 0.001 内，gain_reduction_db 约 6.0206；信号低于 ceiling 时保持单位增益，gain_reduction_db 为 0、limited_samples 为 0，输出与输入一致。

四、release 要真实生效：3000 个满幅后压缩量超过 5 dB；接着两万个静音采样，压缩量降到 0.1 dB 以下，通道增益回到 0.99 以上。

五、sample_rate 只接受 8000 到 192000，attack_ms 0.1 到 1000，release_ms 1 到 5000，lookahead_ms 0 到 50，max_block_size 1 到 65536，任一越界抛 DSP_CONFIG_RANGE 且原配置不变；ceiling_db 只接受 -60 到 0，越界抛 DSP_CEILING_RANGE。

六、空块、非数值、NaN、绝对值大于 8 的采样一律抛 DSP_BLOCK_INVALID；长度超过 max_block_size 抛 DSP_BUDGET_EXCEEDED。这两种拒绝都必须发生在写状态之前，延迟线、增益、计数一个都不能动。

七、声道只允许 0 和 1，process_block 与 process_linked 的键越界都抛 DSP_CHANNEL_UNKNOWN；process_linked 还要求各声道长度一致且非空，按所有声道同一帧的最大峰值算同一个增益，处理后两个声道的 channel_gain 完全相等，frames 只按帧数加一次。

八、process_block 返回 channel、samples、samples_out、peak_in、peak_out、gain、gain_reduction_db、limited_samples，samples_out 长度与输入一致。

九、stats 暴露 blocks、frames、limited_samples、gain_reduction_db、latency_samples、channels，计数要和实际处理量吻合。

十、reset 把各声道增益恢复为 1、清空延迟线、把计数清零，但采样率、前视延迟和 ceiling 等配置保持不变。

十一、并发硬约束：六个线程同时向同一通道 process_block，内部必须串行；结束后 blocks 与 frames 分别精确等于调用次数和采样总数，不允许丢计数或读到撕裂的增益。

十二、快照硬约束：snapshot 是可 json 序列化的深拷贝，包含配置、各声道增益、延迟线、联动增益与计数；restore 后 gain_reduction_db 与快照时刻一致，继续处理时包络连续，不允许突然跳回单位增益。

验收：项目根运行 python3 -m pytest -q tests，15 条测试全绿；不得改测试、跳过或针对样例写死；并发与恢复自行复测；实现只用标准库，不引入外部 DSP 库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- difficulty: 困难
