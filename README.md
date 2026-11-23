# GSB Bugfix Task

## 题面

战地双端战斗校验连续三天报红：同一场 PVE 结算，服务器和客户端的暴击序列从第三只怪开始分叉，回放里玩家打出三连暴击，观战端只显示普通伤害；上周换服重启后，正在进行的爬塔自动战斗随机数从头重跑，一路刷出同一组掉落，社区帖直接说“读档刷装备”。策划用同一颗种子在本地复现，只要中间多调一次掉落 roll，战斗序列就整体错位；异步任务共用一条默认流，抽卡模块把洗牌顺序也带偏了。战斗、掉落和洗牌本应各有一条可复现的独立随机源，现在却互相踩状态；运营还要求每局开打前按模式预设抽取总量，超了直接熔断，不能把整场对局拖垮。任务在 Python 模块 gsb/batch46-game-c-01，文件 deterministic_rng_guard.py，类名 DeterministicRng，任务类型 Bugfix，需要把种子派生、抽取、分叉、快照和预算控制一次修好。

公开接口包括：`create_stream(self, label: str, seed: Optional[int] = None, *, parent: Optional[str] = None) -> dict`、`next_u32(self, label: str = "default") -> int`、`next_int(self, label: str, low: int, high: int) -> int`、`next_below(self, label: str, bound: int) -> int`、`chance(self, label: str, probability: float) -> bool`、`shuffle(self, label: str, items: Sequence) -> List`、`pick(self, label: str, items: Sequence)`、`fork(self, label: str, child_label: str) -> dict`、`position(self, label: str = "default") -> int`、`snapshot(self) -> dict`、`restore(self, snapshot: dict) -> None`。

需要逐条修掉的行为：

1. 相同种子、相同调用顺序必须逐值一致，不同种子必须分叉；
2. 每条命名流独立推进，交错抽取与单独抽取结果相同；
3. 默认流在实例化时即存在，重复创建同名流报 RNG_STREAM_DUP；
4. 未登记的流标签一律报 RNG_UNKNOWN_STREAM，detail 带上原标签；
5. next_int 是闭区间，low 等于 high 时返回该值；low 大于 high 报 RNG_INVALID_RANGE，且不消耗预算、不推进位置；
6. next_below 的 bound 必须为正；next_float 落在 [0.0, 1.0)；chance 概率越界报 RNG_INVALID_PROBABILITY，0 与 1 两端必须稳定；
7. shuffle 返回新列表、不改入参，空列表合法，同一状态重复洗牌顺序一致；
8. pick 遇到空池报 RNG_EMPTY_POOL；
9. fork 从父流种子派生新流且不推进父流位置，子流重名报 RNG_STREAM_DUP，父流不存在报 RNG_UNKNOWN_STREAM；
10. 快照覆盖每条流的完整内部状态，恢复后继续抽取与未中断逐值相同，position 一并还原，版本不符报 RNG_SNAPSHOT_VERSION；
11. 抽取预算按实例全局共享、跨流累计，耗尽后任何取值报 RNG_BUDGET_EXCEEDED，remaining() 返回剩余次数；
12. shuffle、pick、chance 的非法入参要在扣预算之前拦下，失败调用不能留下半个状态。

硬约束：所有抽取与位置更新在并发调用下必须原子，多线程共用一个实例时位置连续、无重复值、总计数精确；快照覆盖每条流的完整内部状态，恢复后与线程调度无关，服务重启接续不能出现重放或跳号；预算是硬资源上限，异常路径不许偷跑计数，抽取失败、预算耗尽、快照版本不符都要显式报错，不能把半截状态留给下一次调用。验收以 python3 -m pytest -q tests 为准，15 条必须全过；不得修改测试、跳过或用固定输入写死；并发和快照恢复场景请自行压测确认；只做本地实现，不涉及平台或仓库提交。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
