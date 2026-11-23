# GSB Bugfix Task

## 题面

组队频道这周被刷屏投诉占满了。有人把同一条邀请连点二十次，被邀请人收件箱里堆了二十张一模一样的卡，接受第一张之后其余全部报错；有人被拒一次之后换个队长接着邀，五秒内连发七条；跨服好友从别的服务器发出邀请，进队后角色数据直接错位；更常见的是队伍已经满员，邀请还能发出去，被邀请人点了接受才被告知进不来，卡在半小时的过期窗口里什么也做不了。队长交接也有问题：原队长下线，系统把队长给了最后一个进队的人，而不是最早进队的那个；队伍解散后残留的邀请还能被点接受，接受者进了一个并不存在的队伍。运营要求把邀请链路收成一套可解释的规则：谁能邀、邀几次、多久能再邀、过期怎么清、队长怎么交接，都要有稳定的错误码，掉线重连后这些状态不能靠内存重建。模块路径 `gsb/batch46-game-b-09`，文件名 `party_invite_guard.py`，类型 `PartyInviteGuard`，任务类型 Bugfix。骨架里的数据类和异常已经给出，方法体都是桩。

要实现的公开接口：

```python
def __init__(self, config: PartyConfig) -> None
@classmethod
def from_snapshot(cls, config: PartyConfig, data: bytes) -> "PartyInviteGuard"
def create_party(self, party_id: str, leader: str, realm: str, now: datetime) -> None
def invite(self, party_id: str, inviter: str, invitee: str, realm: str, now: datetime) -> Invite
def accept(self, invite_id: str, now: datetime) -> Party
def decline(self, invite_id: str, now: datetime) -> None
def cancel(self, party_id: str, invitee: str) -> None
def pending_for(self, invitee: str) -> list[Invite]
def party_of(self, player: str) -> Party | None
def leader(self, party_id: str) -> str
def promote(self, party_id: str, new_leader: str) -> None
def leave(self, player: str, now: datetime) -> None
def expire(self, now: datetime) -> int
def snapshot(self) -> bytes
```

故障与边界：

- 队伍号唯一，重复创建按 `PARTY_DUP_ID` 拒绝；队长已经在别的队伍里按 `PARTY_PLAYER_BUSY` 拒绝，新队伍一个成员都不能有。
- 只有队长能发邀请，其余人按 `PARTY_NOT_LEADER`；邀请自己按 `PARTY_SELF_INVITE`；目标服务器与队伍服务器不同的按 `PARTY_CROSS_REALM`；未知队伍按 `PARTY_UNKNOWN`。
- 队伍人数达到 `max_size` 后不能再邀请，按 `PARTY_FULL`；被邀请人已经在任何队伍里按 `PARTY_PLAYER_BUSY`。
- 同一队伍对同一被邀请人只能有一张待处理邀请，重复按 `PARTY_INVITE_PENDING`；被邀请人收件箱（所有队伍合计）达到 `max_pending_per_invitee` 按 `PARTY_INBOX_FULL`。
- 邀请的 `expires_at` 等于创建时间加 `invite_ttl_seconds`；`invite` 处理前先清掉该被邀请人已过期的邀请，过期邀请不占重复位和收件箱额度；`accept` 遇到 `expires_at` 不晚于 `now` 的邀请要先删除再报 `PARTY_INVITE_EXPIRED`，队伍已满按 `PARTY_FULL` 且邀请保留，被邀请人已在其他队伍按 `PARTY_PLAYER_BUSY`。
- `decline` 删除邀请，并按 `cooldown_seconds` 给（邀请人，被邀请人）记一段冷却，冷却未过再邀请按 `PARTY_COOLDOWN` 拒绝，到点即放行；未知邀请号按 `PARTY_INVITE_NOT_FOUND`。
- `cancel` 按队伍和被邀请人撤回邀请：队伍不存在按 `PARTY_UNKNOWN`，没有待处理邀请按 `PARTY_INVITE_NOT_FOUND`。
- `promote` 只能提升本队成员，非成员按 `PARTY_NOT_IN_PARTY`；提升后 `members` 把新队长挪到第一位，其余成员保持原来的相对顺序。
- `leave` 对不在队伍里的玩家按 `PARTY_NOT_IN_PARTY`；队长离队时由剩余成员里最早进队的人接任，最后一名成员离队则队伍解散，之后 `leader()` 按 `PARTY_UNKNOWN`。
- `pending_for` 返回该玩家尚未清理的邀请，按创建时间升序，返回副本；`expire` 删除所有 `expires_at` 不晚于 `now` 的邀请并返回条数，未到期的一个都不能动。
- `snapshot` 返回 bytes，要恢复队伍、邀请（含到期时间）、冷却和邀请号计数；恢复后重复队伍号仍拒绝，冷却仍生效，新邀请号不能与已用过的号冲突。
- 并发 `accept` 同一张邀请只能成功一次，另一个必须拿到 `PARTY_INVITE_NOT_FOUND`，队伍里不能出现重复成员。

硬约束：邀请、冷却、队伍成员三者在一次提交里一起生效或一起回滚；进程重启后待处理邀请、冷却和邀请号计数不能重置；收件箱与队伍人数都有硬上限；同一张邀请的并发接受只能落账一次。

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
