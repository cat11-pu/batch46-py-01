# batch46-game-b-01 TeamBuilder

## 题面

组队上线后，五人队进七人，同一角色重复入册，两队友同圣物进本，队长退队后无队长，回滚后人数战力不符。gsb/team_builder_guard 的 team_builder_guard.py、类 TeamBuilder，任务类型 Bugfix。
接口（返回 dict）：create_team(team_id: str, owner: str)；join(team_id: str, member: str, *, role: str, power: int = 0, server: str = "s1", relic: str | None = None)；validate(team_id: str)；snapshot(team_id: str)；restore(team_id: str, snapshot: dict)；stats(team_id: str)。
问题：1）建队把队长记为成员（leader/0 战力），容量含队长；2）重复入队 ignored/TEAM_DUP_MEMBER，不写审计；3）满员抛 TeamError/TEAM_FULL；4）同圣物抛 TEAM_DUP_RELIC，总战力超 power_cap 抛 TEAM_POWER_CAP；5）role_limit 由 validate 汇总（rule、TEAM_ROLE_LIMIT、members），change_role 转受限角色抛 TEAM_ROLE_LIMIT；6）power_min 只查非队长，逐人 TEAM_POWER_MIN；7）跨服无 allow 规则抛 TEAM_CROSS_SERVER；8）restore 只退一版，更早 TEAM_SNAPSHOT_STALE，别队快照 TEAM_SNAPSHOT_MISMATCH；9）审计只记成功变更，倒序、上限 audit_limit；10）队长离队由最早入队者接任，离队陌生人抛 TEAM_NOT_MEMBER；11）stats 给 member_count、total_power、roles；12）ticket 含 member_count、total_power、version，深拷贝且入队后不变。
硬约束：八线程同入三人队，成功数等于空位；恢复后名单、战力、版本与快照一致。验收：python3 -m pytest -q tests 全过，不得改测试、跳过或写死输入，并发与快照自验。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- 所属领域：游戏、图形与多媒体
- 子方向：游戏开发
- 任务类型：Bugfix
- 难度：困难
