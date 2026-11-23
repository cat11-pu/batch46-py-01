# GSB Bugfix Task

## 题面

体力系统改成按时间恢复后，玩家发现离线一整天只多了一百多点，和公告写的规则对不上；恢复进度在扣体力后清零，差几十秒的那一点永远拿不到；跨天重置按服务器本地时区计算，海外玩家在一天里领到两次满体力；领体力任务并发提交时体力被扣成负数；购买体力没有次数上限，付费玩家一天能买十几次。运营希望这次把恢复、扣减、赠送、每日重置和购买次数做成一套说得清的逻辑。这次要补的是 gsb/batch46-game-a-05 的 energy_regen_guard.py，类型 EnergyRegen，任务类型 Bugfix，骨架里的方法都是桩，按下列规则把实现补上。

公开接口：create_account(self, account_id: str, *, energy: int | None = None, cap: int | None = None, now=None) -> dict；state(self, account_id: str, now=None) -> dict；regen(self, account_id: str, now) -> dict；spend(self, account_id: str, amount: int, *, now=None, ref: str | None = None) -> dict；grant(self, account_id: str, amount: int, *, now=None, allow_overflow: bool = False) -> dict；daily_reset(self, account_id: str, now) -> dict；buy_refill(self, account_id: str, *, now=None) -> dict；next_full_at / history / snapshot / restore。

1. 每 300 秒恢复 1 点，不足一点的余数秒继续保留，下一次在此基础上累计，state 返回 energy、cap、remainder、last_at 与 next_full_at。
2. 到达上限后停止恢复并把余数清零，避免到顶后攒进度；之后扣体力要重新按整段 300 秒开始计时。
3. 单次补算最多 12 小时即 43200 秒，离线更久的部分不再累计，上限较大的账户也只能补到这段额度。
4. 时间回退抛 ENERGY_CLOCK_REGRESSION，且不得改动体力、余数或 last_at，异常之后仍能按原状态继续。
5. spend 扣减体力；数量为 0、负数、浮点或布尔值抛 ENERGY_INVALID_AMOUNT，体力不足抛 ENERGY_INSUFFICIENT，且扣减失败时体力保持不变。
6. 带 ref 的扣减幂等：同一账户同一 ref 第二次调用返回 status=replayed，体力不会被重复扣除。
7. grant 默认不超过上限，超出部分计入 wasted；allow_overflow=True 时最多到上限加 60，再多的同样算浪费，返回值用 granted 与 wasted 说明实际发放量。
8. daily_reset 按 UTC 日期每天一次，重复调用返回 status=skipped、code=ENERGY_RESET_DONE；当天已经花掉的体力不会因为再次调用被补回。
9. buy_refill 在满体力时抛 ENERGY_ALREADY_FULL；每天最多 3 次，超出抛 ENERGY_REFILL_LIMIT，成功时把体力补到上限、清零余数，并返回 refills_today 计数。
10. next_full_at 返回预计满体力的时间，已经满体力则返回 None；history 返回该账户最近的操作，最新的在前。
11. snapshot 可 JSON 序列化（version=1），restore 后体力、余数秒、上次更新时间、当日重置与购买计数均与恢复前一致，下一次恢复仍按原节奏推进。
12. restore 遇到版本或字段不符抛 ENERGY_BAD_SNAPSHOT，拒绝前不得改动现有数据；未知账户、重复开户分别抛 ENERGY_UNKNOWN_ACCOUNT、ENERGY_ACCOUNT_EXISTS。

并发与恢复：多个线程同时 spend 时，扣减与校验必须在同一临界区内完成，体力不能被扣成负数，成功次数必须正好等于可用体力；重启后恢复的快照要能接着累计余数秒，不能白送一次完整恢复。

验收：运行 python3 -m pytest -q tests 必须 15 条全过；测试不可改、不可跳过、不可按固定输入写死；并发扣减与重启恢复自行验证；只实现本地逻辑。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
