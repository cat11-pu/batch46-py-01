# GSB Bugfix Task

## 题面

日常任务板在上周三开始出乱子：玩家连点重随按钮，任务换了两次却只扣一张重随券；另一批人把客户端时间往前拨一天，任务板直接换了一套，当天领过的完成奖励又领了一遍；跨天结算后未用完的券凭空消失，客服补发时又因为重放请求多发了几十张。运营手里还有一份对不上的日报：同一账号在两张任务板上各领了一次奖励，重随次数却记在旧板子上，补发的券也对不上账。现在要修 `gsb/batch46-game-a-06` 模块，文件 `mission_reroll_guard.py`，类 `MissionReroll`，任务类型 Bugfix，分配、重随、完成、跨天四条路径共用同一份状态，任何一步失败都不能留下半条记录。

要补齐的公开接口：

```python
def define_pool(self, slot_kind: str, missions: Sequence[str]) -> dict
def assign_day(self, account: str, day: str, slots: int = 3, seed: int = 0) -> dict
def current(self, account: str, day: str) -> dict
def reroll(self, account: str, day: str, slot: str, request_id: str) -> dict
def lock_slot(self, account: str, day: str, slot: str) -> dict
def complete(self, account: str, day: str, slot: str, event_id: str) -> dict
def grant_tokens(self, account: str, amount: int, reason: str = "grant") -> dict
def rollover(self, account: str, from_day: str, to_day: str) -> dict
def claims(self, account: str, day: str) -> list[dict]
def stats(self, account: str) -> dict
def snapshot(self) -> dict
def restore(self, payload: Mapping[str, Any]) -> None
```

故障与边界：

- 同一天重复分配必须返回原任务板，created 标出首次与复用，不能按新的 seed 重排；day 不是合法 YYYY-MM-DD 抛 MissionError，code 为 MISSION_BAD_DAY，slots 超过池子大小抛 MISSION_POOL_TOO_SMALL，非正数抛 MISSION_BAD_SLOTS。
- 重随只扣一张券，并跳到池中第一个未被其他槽位占用的任务；券为零抛 MISSION_NO_TOKEN，板子与券都不变；单日重随次数到上限抛 MISSION_REROLL_LIMIT，检查顺序要保证失败时券不动。
- 同一 request_id 再次重随返回 status=duplicate，带回第一次的任务与剩余券数，不重复扣券，也不改任务；request_id 为空按 MISSION_BAD_REQUEST 拒绝。
- 已锁定槽位重随抛 MISSION_SLOT_LOCKED，已完成槽位重随抛 MISSION_SLOT_COMPLETED，未知槽位抛 MISSION_UNKNOWN_SLOT。
- 跨天后对旧日期重随、完成、锁定一律抛 MISSION_STALE_DAY；rollover 只能按当前活动日推进，重复同一组 from_day/to_day 返回 MISSION_DUP_ROLLOVER，不重复结转。
- rollover 结转未用券上限 5 张，超出部分计入 discarded，新日期任务板的 rerolls_used 归零，之后重随重新从 1 计数。
- 完成槽位发放 1 张券；同一 event_id 重复到达返回 MISSION_DUP_EVENT，同一槽位换 event_id 再来返回 MISSION_ALREADY_CLAIMED，两者都不加券，claims 列表与 stats 的 claims 计数必须一致。
- 任务池为空、id 重复、超过 200 条分别按 MISSION_BAD_POOL、MISSION_BAD_POOL、MISSION_POOL_TOO_LARGE 拒绝；未定义池子就分配按 MISSION_NO_POOL 拒绝。
- grant_tokens 非正整数抛 MISSION_BAD_AMOUNT；发放记录要能承受重复调用，返回值里的 tokens 是发放后的总数。
- 所有状态修改必须原子：多线程同时重随同一天同一槽位，成功次数必须等于剩余次数上限，券的消耗与成功次数严格一致；并发发放券不能丢更新。
- snapshot 必须可 JSON 序列化；恢复后任务板、券、request 去重记录、领取记录、活动日、rollover 记录与序号原样可用，版本不符抛 MISSION_BAD_SNAPSHOT。
- 读接口 current 与 claims 返回副本，调用方改动返回值不能影响内部状态。

硬约束：券的扣减、板子的换任务、次数累计必须一次成功或一次失败；进程重启后去重记录与当日板子不能丢；单日重随次数与券余额都有硬上限；并发下不能出现同一 request 扣两张券。

验收：`python3 -m pytest -q tests` 的 15 条测试必须全部通过，不得修改测试、跳过或用固定输入写死结果；并发与快照恢复场景自行验证；只做本地实现，不涉及上游提交与平台操作。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
