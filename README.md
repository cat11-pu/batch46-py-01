# GSB Bugfix Task

## 题面

新赛季的征召模式第一周就被投诉淹没。有队伍在禁用阶段连点两次同一个英雄，界面显示已禁，服务端却把第二次当成又一次禁用记进历史；选人阶段红方连续两手之间插进了蓝方的选择，双方看到的阵容不一致；一名选手在倒计时归零后还能提交，另一名选手网络卡了半秒就被判超时，重连回来发现回合数跳了两格；更常见的是赛事复盘时拿不出可靠的提交顺序，只能靠录像猜。赛事运营要求把征召过程做成可以重放的状态机：谁在第几手、禁了谁、选了谁、每一步的截止时间，都要能从服务端还原，掉线重连也不能让同一次提交生效两遍。模块路径 `gsb/batch46-game-b-07`，文件名 `pvp_draft_guard.py`，类型 `PvpDraft`，任务类型 Bugfix。骨架里的数据类和异常已经给出，方法体都是桩。

要实现的公开接口：

```python
def __init__(self, config: DraftConfig, champions: list[Champion], now: datetime) -> None
@classmethod
def from_snapshot(cls, config: DraftConfig, champions: list[Champion], data: bytes) -> "PvpDraft"
def submit(self, action: Action, now: datetime) -> DraftState
def state(self) -> DraftState
def timeout(self, now: datetime) -> DraftState
def deadline(self) -> datetime | None
def available(self, role: str | None = None) -> list[str]
def champions(self) -> list[Champion]
def history(self) -> list[Action]
def remaining_bans(self, team: Team) -> int
def picks(self, team: Team) -> list[str]
def snapshot(self) -> bytes
```

故障与边界：

- 回合顺序：禁用阶段蓝红交替；选择阶段按两手一组，蓝红、红蓝、蓝红……交替，`picks_per_team=2` 时的实际顺序是蓝、红、红、蓝。
- `turn` 从 0 开始，每次成功提交或有效超时加一；禁用用完进入 `Phase.PICK`，选择用完进入 `Phase.DONE`，结束态 `team` 为 `None`、`deadline()` 返回 `None`。
- `action_id` 是幂等键：重复动作号按 `DRAFT_DUPLICATE_ACTION` 拒绝，这项检查排在阶段、回合与英雄校验之前，即使当前不是该队回合也先报重复。
- 动作类型必须与阶段匹配，禁用阶段提交选人（或反过来）按 `DRAFT_INVALID_PHASE` 拒绝。
- 非当前回合队伍的提交按 `DRAFT_NOT_YOUR_TURN` 拒绝，状态一点都不能动。
- 英雄必须在池子里，否则 `DRAFT_UNKNOWN_CHAMPION`；已被禁用或已被选走的英雄再次提交按 `DRAFT_CHAMPION_TAKEN`；构造时池子里出现重复英雄 ID 按 `DRAFT_DUPLICATE_CHAMPION` 拒绝。
- 已经结束的征召，提交和超时都按 `DRAFT_CLOSED` 拒绝。
- 截止时间初值是创建时间加 `turn_seconds`，每次成功提交或超时后重置为本次时间加 `turn_seconds`。
- 超时只推进回合、不写历史：`now` 早于截止时间按 `DRAFT_TURN_NOT_EXPIRED` 拒绝，恰好等于或晚于截止时间则推进；被跳过的那一手不算禁选，英雄回到可选池。
- `available(role)` 返回未被禁用和选走的英雄 ID 升序列表，`role` 为 `None` 或空串时不做过滤；`remaining_bans` 和 `picks` 只统计已经成功落账的动作。
- `snapshot` 返回 bytes，必须恢复回合序号、历史、已用动作号和当前截止时间；恢复后重复动作号仍要拒绝，超时推进出来的回合也要保留。
- `history`、`champions` 和 `state` 返回的内容与内部状态隔离，调用方清空或改写返回的列表不影响后续判定。

硬约束：同一个 `action_id` 的并发提交只能生效一次；重连后从快照恢复不能让已生效的动作再落一次账；每个回合的截止时间是硬边界，早一秒都不算超时。

验收：`python3 -m pytest -q tests` 的 15 条测试必须全部通过，不得修改测试、跳过或用固定输入写死结果；并发与重连场景自行验证；只做本地实现，不涉及上游提交与平台操作。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
