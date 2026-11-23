# GSB Bugfix Task

## 题面

PvP 赛季结算后，排行榜上一批长期不上线的账号依旧占着前几名，回归玩家则投诉自己被扣了几十分却拿不到任何补偿，客服工单堆了一整屏。数据组同时发现同一场对局被结算两次，胜负分加了两遍，有人靠重复上报把分数刷到三千以上；批量补结算的旧事件没有按发生时间排序，后到的更早事件把分数改了回去；跨区榜单还把不同赛区的玩家混在一起排名。运营希望这次把评分、衰减、回归补偿和快照恢复一次做对，周报上的分数曲线能直接对上。问题集中在 gsb/batch46-game-a-01 的 rating_decay_guard.py，类型 RatingDecay，任务类型 Bugfix，骨架里的方法都是桩，请按下面的契约补齐整套评分事务。

公开接口：register(self, player_id: str, rating: int = 1500, region: str = "global", *, now=None) -> dict；record_match(self, match_id: str, winner: str, loser: str, *, occurred_at=None, season: str = "s1") -> dict；record_matches(self, matches) -> list；rating(self, player_id: str) -> int；apply_decay(self, season: str, now) -> list；claim_comeback(self, player_id: str, *, now=None) -> dict；leaderboard(self, region: str | None = None, limit: int = 10) -> list；snapshot(self) -> dict；restore(self, state: dict) -> None。

1. 期望胜率按 1/(1+10^((负方分-胜方分)/400)) 计算；K 由胜者状态决定，胜者前 5 场 K=64，定级结束后 K=32；变动量四舍五入（0.5 向上）取整，负方扣同一数值，返回值用 k 字段标明本场使用的 K 值。
2. 分数硬夹在 100 到 3000 之间，夹紧后的真实变动写入 winner_delta 与 loser_delta，不再要求双方对称，winner_rating 与 loser_rating 给出结算后的分数。
3. 同一 match_id 重复上报必须返回 status=ignored、code=RATING_DUP_MATCH，分数只变一次，历史里也只保留一条。
4. 定级场次用满后，快照里 players[p]["provisional_left"] 归零，与同分对手交手时变动固定为 16。
5. 14 天内活跃过不衰减，未满 14 天返回 status=skipped、code=RATING_DECAY_GRACE；满 14 天后每满 7 天扣 25，单赛季最多扣 100，逐玩家报告包含 player、season、status、code、delta、rating 字段。
6. 衰减不得把分数压到 1000 以下；同一赛季对同一玩家重复调用返回 skipped 与 RATING_DECAY_APPLIED，不能二次扣除。
7. 衰减后打满 3 场才能领取回归补偿，返还未领取衰减量的一半并向下取整，上限 60，只能领一次。
8. 提前领取抛 RatingError，code=RATING_COMEBACK_NOT_READY；已经领完返回 status=empty、code=RATING_NO_COMEBACK、refund=0。
9. 未知玩家、重复注册、自己打自己分别抛 RATING_UNKNOWN_PLAYER、RATING_DUPLICATE_PLAYER、RATING_SELF_MATCH。
10. record_matches 先按 occurred_at 升序排序再逐场结算，返回列表的顺序与结算顺序一致。
11. leaderboard 按分数降序、player_id 升序，支持 region 过滤与 limit 截断；退役玩家不上榜，但 rating 仍可查询；history 返回该玩家最近的对局，最新的排在最前。
12. snapshot 返回可 JSON 序列化的深拷贝（version=1），之后继续操作不得影响快照内容；restore 遇到版本或字段不符抛 RATING_BAD_SNAPSHOT，拒绝前不得改动现有数据。

并发与恢复：record_match 会被多个线程同时调用，同一 match_id 只能有一方结算成功，其余全部返回 RATING_DUP_MATCH，结束后双方分数之和必须守恒；从快照恢复后历史、定级余量、衰减账本都要与恢复前一致，重启不会重复发补偿。

验收：python3 -m pytest -q tests 的 15 条用例全部通过，不得改测试、跳过或按固定输入写死，并发与重启自行验证，只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 地狱
