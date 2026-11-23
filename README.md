# GSB Bugfix Task

## 题面

团队副本换成需求优先分配后，队长收到大量申诉：需求点比贪婪低的人反而拿了装备；同点数的两个人谁先 roll 谁后到说不清；一件掉落明明有两份却只发出去一份；团长手动分配没有次数限制，同一件装备被重复发放；交易窗口早就过期，物品还能在玩家之间转手；还有人把已绑定的装备挂到交易行，界面显示可交易，点下去才报错；服务器重启后已分配的记录消失，同一件装备又分了一次。会长要求这次把 roll 点、排序、团长分配、交易与绑定全部做成可复盘的记录。相关逻辑都压在 gsb/batch46-game-a-04 的 loot_distribution_guard.py，类型 LootDistributor，任务类型 Bugfix，骨架里只有桩，请补齐整套掉落分配流程。

公开接口：open_raid(self, raid_id: str, *, now=None) -> dict；add_player(self, raid_id: str, player_id: str, *, need_score: int = 0, role: str = "dps") -> dict；add_drop(self, raid_id: str, drop_id: str, items: list, *, now=None) -> dict；claim(self, raid_id: str, drop_id: str, item_id: str, player_id: str, *, mode: str = "need", roll: int, now=None) -> dict；resolve(self, raid_id: str, drop_id: str, item_id: str, *, now=None) -> dict；award(self, raid_id: str, drop_id: str, item_id: str, player_id: str, *, reason: str, now=None) -> dict；trade(self, from_player: str, to_player: str, copy_id: str, *, now=None) -> dict；bind / inventory / ledger / unclaimed / snapshot / restore。

1. need 永远优先于 greed，与点数高低无关；同模式的两人比较点数，点数相同再比较 need_score。
2. need_score 也相同时，claim 时间更早的排前面；时间也相同则按 player_id 升序，保证每次结算结果一致。
3. 一件物品有 qty 份时按上述顺序取前 qty 名，其余玩家不得获得，返回的 winners 与 copies 顺序一一对应。
4. 同一玩家对同一件物品重复 claim 抛 LOOT_DUP_CLAIM，非团员抛 LOOT_UNKNOWN_PLAYER，点数不在 1 到 100 或模式非法抛 LOOT_BAD_ROLL、LOOT_BAD_MODE。
5. 掉落有 300 秒领取窗口，超过后新的 claim 抛 LOOT_DROP_EXPIRED，但已经结算过的物品不受影响。
6. 没有任何 claim 时 resolve 抛 LOOT_NO_CLAIM；已结算物品再次 claim 抛 LOOT_ITEM_RESOLVED。
7. resolve 幂等：第二次调用返回 status=replayed，winners 与 copies 与第一次完全一致，不得重复入库。
8. 团长 award 可以跳过 roll 直接分配，每次 raid 限 2 次，超出抛 LOOT_OVERRIDE_EXHAUSTED，返回 override=true 并记录 reason。
9. 交易校验归属与绑定：非拥有者抛 LOOT_NOT_OWNER，已绑定抛 LOOT_ITEM_BOUND，距离获得超过 30 分钟抛 LOOT_TRADE_WINDOW_CLOSED；成功交易后副本归属立即变更，原主人 inventory 里不再出现该副本。
10. bind 只对拥有者生效，绑定后该副本永久不可交易，归属变更必须直接拒绝而不是先转移再回滚；inventory 返回副本明细，unclaimed 返回尚未结算的掉落项。
11. snapshot 可 JSON 序列化（version=1），restore 后 claim、已分配副本与流水一致；版本或字段不符抛 LOOT_BAD_SNAPSHOT，拒绝前不得改动现有数据。
12. 单个 raid 的掉落条数与 claim 总数都有上限，超出抛 LOOT_LIMIT；并发 resolve 同一件物品只能产生一份奖励，其余线程拿到 replayed。

并发与恢复：多名队长同时点击分配或交易时，同一件物品只能被结算一次；进程重启后从快照恢复，副本归属、绑定状态和交易窗口起点都要保持原样，不能靠重建数据再发一份。

验收：python3 -m pytest -q tests 的 15 条用例全部通过；不得修改测试、跳过用例或对固定输入写死；并发与快照恢复要自行压测验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 地狱
