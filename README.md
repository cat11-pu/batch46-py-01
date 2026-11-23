# GSB Bugfix Task

## 题面

新赛季的排位结算一上线，客服就收到一批“幽灵击杀”申诉：同一发狙击子弹在服务端结算了两次，计分板给同一个人加了两个人头；重甲单位被步枪打掉的血量忽高忽低，排查发现护甲吸收和爆头倍率的计算先后顺序写反了。更严重的是反外挂批量撤销命中后，被撤销那一枪的伤害没有退回，被误杀的玩家仍停在死亡状态，后续击杀奖励也照发；同一次刷新里两发命中的撤销顺序颠倒，血量甚至被恢复到比重伤前更高的值。还有玩家用延迟包把命中打在已经消失的世界 BOSS 上，结算代码只查了当前状态，命中照样生效；待处理命中队列没有上限，卡顿期间积压几千条后整场对局一起补算。Python 模块 gsb/batch46-game-c-02，文件 hit_registration_guard.py，类名 HitRegistration，任务类型 Bugfix，要求把目标注册、待定命中、结算和回滚全部修到一致。

关键接口：`join(self, player_id: str, team: str) -> None`、`spawn(self, target_id: str, *, hp: int = 100, armor: int = 0, team: str = "red", tick: int = 0) -> dict`、`despawn(self, target_id: str, *, tick: int) -> dict`、`submit(self, shot_id: str, *, shooter: str, target: str, damage: int, tick: int, headshot: bool = False) -> dict`、`resolve(self, shot_id: str) -> dict`、`resolve_pending(self) -> List[dict]`、`rollback(self, shot_id: str, *, reason: str = "cheat") -> dict`、`damage_log(self, target_id: str) -> List[str]`、`pending(self) -> List[str]`、`snapshot(self) -> dict`、`restore(self, snapshot: dict) -> None`。

需要逐条修掉的行为：

1. 同一 shot_id 重复提交只允许第一次进入待定，后续返回 ignored 与 HIT_DUP_SHOT，伤害只能落一次；
2. 有效伤害先按爆头翻倍，再由护甲吸收其一半向下取整，剩余部分扣血；
3. 护甲按吸收量同步减少，不能出现扣了血却保留满甲；
4. 血量下限为 0，溢出伤害不得为负，死亡只记一次击杀，对尸体继续提交结算返回 HIT_TARGET_DEAD；
5. 射手与目标同队只扣血、不计击杀，统计里记入 friendly_kills；
6. 命中 tick 早于目标出生或晚于其移除时间，返回 HIT_STALE_TARGET 且不改变血量；
7. 回滚只能从最近一次已结算命中开始，按严格后进先出；越序或重复回滚报 HIT_ROLLBACK_ORDER，状态保持原样；
8. 回滚要精确还原血量、护甲、存活状态和击杀数，并把该 shot 从伤害日志里移除；
9. resolve_pending 按 (tick, shot_id) 升序结算，与提交顺序无关，返回值逐条带上 shot_id 与 status；
10. 待定队列达到 max_pending 后新提交报 HIT_QUEUE_FULL，队列和目标状态都不能被改动；
11. 已取消的命中结算时返回 HIT_SHOT_CANCELLED，已结算的命中不能再取消，返回 HIT_CANCEL_STATE；
12. 重复生成目标、负护甲、零伤害、未知目标分别按 HIT_TARGET_DUP、HIT_INVALID_STAT、HIT_INVALID_DAMAGE、HIT_UNKNOWN_TARGET 拒绝。

硬约束：结算、撤销、取消必须在同一把锁内完成，多线程并发提交不同 shot 时总伤害精确等于命中数，同一 shot 的并发提交只有一条生效；快照要覆盖目标、待定队列、伤害日志与计数，恢复后继续结算与未重启时完全一致，版本不符报 HIT_SNAPSHOT_VERSION；待定队列上限是硬资源约束，任何异常路径都不能让它超出。验收以 python3 -m pytest -q tests 为准，15 条必须全过；不得修改测试、跳过或写死输入；并发与快照恢复请自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
