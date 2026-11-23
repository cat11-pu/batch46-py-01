# GSB Bugfix Task

## 题面

反外挂组接到一批“完美操作”举报，人工看录像发现客户端把关键帧的命中输入改成了必中，服务端校验却全部放行；原来校验只比对了帧数，逐帧摘要和链式关系都没验。另一批录像在回放时中途跳帧，seq 出现缺口、tick 往回走，播放器照单全收，结算出的比分和真实对局对不上。有人把整段录像的 ruleset 从排位改成娱乐模式重新上传，服务端仍按原签名通过；空录像也能作为“零死亡通关”提交。运营导入一场两小时的对局时，校验器把全部帧一次性读进内存，进程被 OOM 杀掉；断点续传的检查点被人改过帧数，续传后摘要静默分叉。还有一个隐蔽问题：同样的对局换一个玩家列表顺序，摘要就不同，导致同一场比赛在两地机房被判成两份录像；校验函数还会顺手给调用方的帧补 checksum，重试时二次加签直接失败。Python 模块 gsb/batch46-game-c-05，文件 replay_validation_guard.py，类名 ReplayValidator，任务类型 Bugfix，需要把录制、摘要链、校验、检查点一次修好。

关键接口：`begin(self, match_id: str, *, players: Sequence[str] = (), ruleset: str = "v1") -> dict`、`append(self, frame: dict) -> dict`、`finish(self) -> dict`、`abort(self) -> bool`、`digest(self) -> str`、`header(self) -> dict`、`frames(self) -> List[dict]`、`checkpoint(self) -> dict`、`resume(self, checkpoint: dict) -> dict`、`verify(self, frames: List[dict], *, header: Optional[dict] = None) -> dict`、`outcome(self) -> dict`、`stats(self) -> dict`。

需要逐条修掉的行为：

1. 相同比赛、相同玩家集合与规则集必须得到完全相同的 64 位十六进制摘要，玩家顺序不影响结果；
2. ruleset 或 match_id 不同的录像摘要必须不同，拿错 header 校验首帧即报 REPLAY_HEADER_MISMATCH；
3. 每一帧摘要覆盖上一帧摘要与 seq/tick/input，任何输入被改动都报 REPLAY_CHECKSUM_MISMATCH 并给出行号；
4. seq 必须从 0 开始逐帧加一，跳号、回退、首帧不从 0 开始都报 REPLAY_SEQ_GAP；
5. tick 只允许不减，允许相等，出现回退报 REPLAY_TICK_REGRESS；
6. 录制中再次 begin 报 REPLAY_ACTIVE，必须 finish 或 abort 后才能开新录像；
7. 没有打开录像时 append、finish、digest、checkpoint、abort 一律报 REPLAY_NO_SESSION；
8. 缺 tick、缺 seq 或不是字典的帧在入链前报 REPLAY_FRAME_INVALID，不得污染已有摘要；
9. 帧数达到 max_frames 后继续 append 报 REPLAY_FRAME_LIMIT，摘要与已存帧保持原样；
10. 检查点必须自校验，被改过帧数或摘要的检查点续传报 REPLAY_CHECKPOINT_INVALID，忙碌会话 resume 报 REPLAY_ACTIVE；
11. verify 传入空列表报 REPLAY_EMPTY，成功时返回 ok、frames、digest 三个字段；
12. frames() 返回深拷贝，调用方修改返回值或往列表里塞垃圾都不能影响内部状态与摘要；outcome 按帧内 score 累加，打平返回 draw。

硬约束：verify 只读、并发调用同一实例时结果完全一致，不得改动内部录制状态；检查点续传后的最终摘要必须与不中断录制逐位相同，players 与 ruleset 也要还原；max_frames 是硬内存上限，超限前就要拒绝，不能先收下再截断。验收以 python3 -m pytest -q tests 为准，15 条必须全过；不得修改测试、跳过或按固定输入写死；并发校验与断点续传请自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
