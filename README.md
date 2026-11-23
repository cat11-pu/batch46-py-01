# GSB Bugfix Task

## 题面

周四晚上团队副本的开怪记录全乱了。指挥把名单锁上之后，替补还在往里挤，锁名单的按钮点第二次直接把状态改回可编辑；两个替补换人同时点确认，结果一个替补进了两个位置，另一个被挤出了名单；治疗配额只有两个，第三个治疗照样被塞进来，BOSS 战的减伤循环完全错位；更糟的是已经打过的 BOSS 被重复开怪，掉落统计多算了一整份，客服按统计补发了双倍装备。副本长要求这次把名单和开怪记录做成一份能追责的账：谁在什么时候进的本、谁在替补席、名单锁在哪个时间点、每个 BOSS 最后一次开怪的出勤名单，都要能还原，维护重启后锁窗口不能重置。模块路径 `gsb/batch46-game-b-10`，文件名 `raid_roster_guard.py`，类型 `RaidRoster`，任务类型 Bugfix。骨架里的数据类和异常已经给出，方法体都是桩。

要实现的公开接口：

```python
def __init__(self, config: RaidConfig, raid_id: str) -> None
@classmethod
def from_snapshot(cls, config: RaidConfig, data: bytes) -> "RaidRoster"
def add(self, raider: Raider, now: datetime) -> None
def bench(self, name: str, now: datetime) -> None
def swap(self, benched_name: str, active_name: str, now: datetime) -> None
def lock(self, now: datetime) -> None
def unlock(self) -> None
def locked(self) -> bool
def pull(self, boss_id: str, now: datetime) -> PullRecord
def unlock_boss(self, boss_id: str) -> None
def roster(self) -> list[Slot]
def bench_list(self) -> list[str]
def attendance(self, boss_id: str) -> list[str]
def count(self, role: Role) -> int
def snapshot(self) -> bytes
```

故障与边界：

- `add` 的判定顺序：名单已锁定返回 `RAID_LOCKED`；同名已在主力或替补席返回 `RAID_DUP_MEMBER`；主力人数达到 `size` 返回 `RAID_FULL`；该角色人数达到配额返回 `RAID_ROLE_QUOTA`。
- `bench` 只对主力成员生效，陌生人按 `RAID_NOT_IN_RAID` 拒绝；替补席已满按 `RAID_BENCH_FULL` 拒绝，失败时主力与替补两边都不能变。
- 已锁定时再调 `lock` 按 `RAID_ALREADY_LOCKED` 拒绝；锁定之后 `add` 和 `bench` 都按 `RAID_LOCKED` 拒绝，只有 `swap` 与 `pull` 还能用。
- `unlock` 在未锁定时按 `RAID_ROSTER_UNLOCKED` 拒绝；解锁不清理 BOSS 的开怪记录。
- `swap` 只在已锁定且 `now` 不晚于锁定时间加 `swap_window_seconds` 时允许，否则一律 `RAID_SWAP_CLOSED`，未锁定也用这个码；替补名不在替补席或主力名不在主力名单按 `RAID_NOT_IN_RAID`。
- 换人是原子的：两人的角色与装备分跟着人走，交换后各角色人数不变，失败时两边都不动。
- `pull` 要求名单已锁定，未锁定按 `RAID_ROSTER_UNLOCKED`；主力为空按 `RAID_EMPTY_ROSTER` 拒绝且不能留下开怪记录；同一 BOSS 的记录未清除前再次开怪按 `RAID_LOCKOUT`。
- `pull` 返回的记录里 `members` 是开怪时刻主力名单按名字升序的元组，`at` 是本次时间；`attendance` 返回该 BOSS 最近一次开怪的名单副本，从未开过按 `RAID_UNKNOWN_BOSS`。
- `unlock_boss` 只清除指定 BOSS 的记录，没开过的 BOSS 按 `RAID_UNKNOWN_BOSS`，其他 BOSS 的锁定不受影响。
- `roster` 先按角色（坦克、治疗、输出）再按名字排序，替补统一排在最后并按名字排序、`bench` 为 `True`，录入顺序不影响输出；`bench_list` 返回替补名字升序副本，`count` 只统计主力。
- `snapshot` 返回 bytes，要恢复主力、替补、锁定状态与锁定时间、各 BOSS 最近一次开怪记录；恢复后 swap 窗口从原锁定时间继续算，锁定期间 `add` 仍拒绝，已开过的 BOSS 仍按 `RAID_LOCKOUT`。
- 并发开怪同一个 BOSS 只能成功一次，其余必须拿到 `RAID_LOCKOUT`，出勤名单不能出现重复成员。

硬约束：名单锁、人数与角色配额、替补席上限必须在一次提交里同时校验并一起生效；进程重启后锁定时间与开怪记录不能重置；同一 BOSS 的并发开怪只能落账一次；出勤名单以开怪时刻为准，后续换人不回溯修改。

验收：`python3 -m pytest -q tests` 的 15 条测试必须全部通过，不得修改测试、跳过或用固定输入写死结果；并发与重启场景自行验证；只做本地实现，不涉及上游提交与平台操作。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
