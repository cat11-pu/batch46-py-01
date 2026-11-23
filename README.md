# batch46-game-b-02 BracketGuard

## 题面

城市赛报名截止日，对阵表把一号和二号种子放进同一半区，首轮顺序与直播脚本不符，轮空重复计分，开赛后仍有人补报，退赛种子没重排，冠军产生后还能改结果。gsb/tournament_bracket_guard 的 tournament_bracket_guard.py、类 BracketGuard，任务类型 Bugfix。
接口（返回 dict）：register(player: str, *, rating: int = 1000)；withdraw(player: str)；seed_order() -> list[str]；build_round(round_no: int) -> list[dict]；record_result(match_id: str, winner: str, *, score: str = "2-0")；standings() -> list[dict]。
故障：1）重复报名 ignored/BKT_DUP_PLAYER，报名返回 count；2）首轮生成后报名关闭，再报名或退赛抛 BKT_LOCKED；3）种子按评分降序，同分按报名先后而非昵称；4）八人首轮依次一对八、四对五、二对七、三对六，场次 r1-m1 起；5）人数不足时空位落在最低种子侧，轮空记一胜；6）同轮重复生成返回相同副本，改返回值不影响内部；7）同一场二次录结果抛 BKT_MATCH_DONE，胜者保持首次；8）胜者不在双方内抛 BKT_UNKNOWN_WINNER，未知场次抛 BKT_UNKNOWN_MATCH；9）上一轮未出完就生成下一轮抛 BKT_ROUND_PENDING，超 max_rounds 抛 BKT_ROUND_LIMIT；10）决赛录完才出冠军，此后提交抛 BKT_SEASON_CLOSED；11）积分榜胜场降序、种子升序，含 player、wins、losses、seed，轮空计胜；current_round 为已生成最大轮次，快照恢复后下一轮与冠军作废；12）审计只记报名退赛，倒序、上限 audit_limit。
硬约束：十二名选手并发报名各只出现一次，种子顺序长度与人数一致且最高分第一；快照恢复让后续轮次和冠军完全回退。验收：python3 -m pytest -q tests 全过，不得改测试、跳过或写死输入；并发与快照自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- 所属领域：游戏、图形与多媒体
- 子方向：游戏开发
- 任务类型：Bugfix
- 难度：困难
