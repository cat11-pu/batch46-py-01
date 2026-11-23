# batch46-game-b-05 AccountMerge

## 题面

合服后账号合并两次金币翻倍；大号并进小号。gsb/account_merge_guard 的 account_merge_guard.py、类 AccountMerge，任务类型 Bugfix。
接口：register_field(field: str, *, strategy: str = "max", cap=None)；create_account(account: str, *, fields=None)；plan(merge_id: str, primary: str, secondary: str)；apply(merge_id: str)；cancel(merge_id: str)；account(account: str)。
故障：1）max 取大，sum 按 cap 截断，primary 留主，union 按主序去重；2）manual 冲突按名排序，apply 前须全解否则 MERGE_UNRESOLVED，resolve 非冲突字段 MERGE_UNKNOWN_FIELD；3）字段超 field_limit 抛 MERGE_FIELD_LIMIT；4）冲突超 max_conflicts 截断并给 conflict_truncated/conflict_total；5）重复建号/字段抛 MERGE_DUP_ACCOUNT、MERGE_DUP_FIELD；6）主副相同 MERGE_SELF，副账号已合并 MERGE_SECONDARY_MERGED，缺号 MERGE_UNKNOWN_ACCOUNT；7）apply 后副账号 merged、记 merged_into，重复 already_applied；8）取消后再 apply/取消 MERGE_NOT_PLANNED；9）审计只记计划、取消、解决、应用，倒序、上限 history_limit；10）account 给 status/merged_into/fields，conflicts 给 field/primary/secondary；11）plan 返 planned，cancel 返 cancelled，恢复后主账号字段、副账号状态、计划回退。
硬约束：两线程同 apply 只一次写入，另一次 already_applied，金币不翻倍；恢复后重跑同首次。验收：python3 -m pytest -q tests 全过，不得改测试、跳过或写死输入，并发与快照自验。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- 所属领域：游戏、图形与多媒体
- 子方向：游戏开发
- 任务类型：Bugfix
- 难度：困难
