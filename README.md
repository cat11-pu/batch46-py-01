# GSB Bugfix Task

## 题面

批量制作功能上线后，玩家把同一份材料同时排进多个订单，实际库存被扣成负数；公会委托的高优先级订单总被后来的普通订单插队，等半天也开不了工；取消进行中的订单时材料全退，失败订单反而把材料吞掉；服务器重启后队列清空，已排好的订单和预留材料全部丢失，玩家截图来投诉；还有人发现排队中的订单取消后仍占着工位，新订单一直提示队列已满；公会仓库也抱怨同一份委托被重复提交，预留表的数字和实际库存长期对不上。策划希望这次把排队、预留、开工、完成、取消和重启恢复做成一条完整链路。需要改的是 gsb/batch46-game-a-03 的 crafting_queue_guard.py，类型 CraftingQueue，任务类型 Bugfix，骨架里的方法都是桩，请把这条链路在骨架里补全。

公开接口：add_station(self, name: str, capacity: int = 3, parallel: int = 1) -> dict；register_recipe(self, recipe_id: str, inputs: dict, output: dict, duration: int, station: str) -> dict；deposit(self, account: str, item: str, qty: int) -> dict；enqueue(self, account: str, recipe_id: str, count: int = 1, *, priority: int = 0, request_id: str | None = None, now=None) -> dict；tick(self, now) -> dict；cancel(self, account: str, job_id: str, *, now=None) -> dict；fail(self, job_id: str, *, reason: str = "", now=None) -> dict；withdraw / inventory / available / queue_view / job / snapshot / restore。

1. enqueue 只预留不扣材料：inventory 总数不变，available 相应减少，job 视图带 reserved 与 output 明细；图纸不存在抛 CRAFT_UNKNOWN_RECIPE，数量非法抛 CRAFT_BAD_COUNT。
2. 材料不足抛 CRAFT_INSUFFICIENT_MATERIALS，且不能发生部分预留，重试时库存必须还是原样。
3. 工位容量按 pending 与 running 之和计算，排满抛 CRAFT_QUEUE_FULL；同时最多 parallel 个任务运行。
4. 晋升顺序按 priority 降序、入队序号升序，高优先级先开工，同优先级严格先来先做。
5. ready_at 为开工时间加 duration×count，tick 在到达 ready_at 时消耗预留材料并发放产物，同一任务重复 tick 不得重复发放，返回值用 completed 与 started 两个任务号列表说明本次结果。
6. 取消 pending 任务全额释放预留，库存与可用量都回到排队前的数值，被占用的工位立即释放，等待中的订单能在下一次 tick 被晋升。
7. 取消 running 任务时每种材料只退一半并向下取整，其余算真实消耗，不足一份的不退。
8. withdraw 只能取可用部分，超出抛 CRAFT_INSUFFICIENT_AVAILABLE，已被预留的材料不得被取走。
9. request_id 幂等：同一账户重复提交返回同一个 job 且 replayed=True，不重复预留材料，也不新增队列项。
10. 单账户在制任务默认上限 20，可由构造参数 max_jobs_per_account 调整，超出抛 CRAFT_ACCOUNT_LIMIT。
11. fail 只对 running 任务生效，半额返还且不发放产物，并保留 reason 供客服复盘；已完成抛 CRAFT_JOB_DONE，已取消或已失败抛 CRAFT_JOB_CLOSED。
12. snapshot 可 JSON 序列化（version=1），restore 后任务状态、ready_at、预留表与 job 序号都与恢复前一致，下一次 tick 仍按原时间完成；坏快照抛 CRAFT_BAD_SNAPSHOT 且不改动现有状态。

并发与恢复：多个线程同时 enqueue 时，可用材料的检查与预留必须在同一临界区内完成，绝不能超额预留；重启后恢复的队列要能继续推进，序号不能回退导致 job_id 重复。

验收：python3 -m pytest -q tests 必须全部通过，15 条一条不少；测试文件不可改动，不允许跳过或针对样例写死；并发、取消与重启场景需要自行验证；实现只落在本地代码里。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
