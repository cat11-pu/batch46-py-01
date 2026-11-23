# GSB Bugfix Task

## 题面

跨服拍卖行上线第一天，客服就被三类工单淹没：买家限价 100 金却按 120 金成交，差价没退；同一件材料卖给了两个人，卖家背包里多出一份；有人用大号挂单、小号吃单，把手续费返还刷成了负库存。撤单那边更离谱，撤掉一半成交的卖单，物品只退了一半，另一半锁在系统里谁都拿不到。运维重启交易节点后，剩余挂单全部消失，成交序号也从 1 重来，对账表直接对不上。现在要修 `gsb/batch46-game-a-07` 模块，文件 `market_orderbook_guard.py`，类 `OrderBook`，任务类型 Bugfix，下单、撤单、撮合、快照四条路径共用同一本账。

要补齐的公开接口：

```python
def deposit(self, account: str, currency: str, amount: int) -> int
def balance(self, account: str, currency: str) -> int
def place(self, order_id: str, account: str, side: str, price: int, qty: int, item: str = "ore", quote: str = "gold") -> dict
def cancel(self, order_id: str, account: str) -> dict
def match(self, max_fills: int | None = None) -> list[dict]
def order(self, order_id: str) -> dict
def open_orders(self, account: str | None = None) -> list[dict]
def book(self, side: str | None = None) -> dict
def depth(self, side: str, levels: int = 5) -> list[dict]
def trades(self, since: int = 0) -> list[dict]
def fees_collected(self, currency: str = "gold") -> int
def audit(self) -> dict
def snapshot(self) -> dict
def restore(self, payload: Mapping[str, Any]) -> None
```

故障与边界：

- 成交价取先入簿一方（maker）的价格；买单按自身限价冻结金币，成交后差价立即退回，卖方按成交额与 fee_bps 扣税，税费单独记账。
- 价格优先、同价时间优先：最高买价先成交，同价按入簿序号；成交记录里的 maker_order、taker_order、buyer、seller、price、qty、notional、fee、seq 都要与账实一致。
- 部分成交后剩余继续挂单，状态保持 open，remaining 正确；全部成交转 filled 并离开簿；挂单状态变化不能让深度少算或多算。
- 撤单按剩余数量退冻结，买单退金币、卖单退物品；订单不存在抛 ORDER_NOT_FOUND，非本人抛 ORDER_NOT_OWNER，已成交或已撤抛 ORDER_NOT_OPEN，失败时余额不变。
- 同一 order_id 重复下单返回 status=duplicate，不二次冻结，价格与数量以首次为准。
- 余额或物品不足抛 ORDER_INSUFFICIENT_FUNDS，订单不入簿、余额不变；deposit 非正金额抛 ORDER_BAD_AMOUNT，不给负余额留口子。
- 自成交必须拦截：同账号的买卖单不得互相成交，跳过该挂单继续找下一家，双方挂单都完整保留，不能出现自己吃自己。
- price、qty 非正，side 不是 buy/sell，单号为空，都按 ORDER_BAD_ORDER 拒绝；未成交订单数达到 max_open_orders 时新单按 ORDER_BOOK_FULL 拒绝，且不冻结资金。
- match(max_fills) 是本次撮合的次数预算，用完后剩余的交叉盘口保留，下次调用继续；成交序号从 1 单调递增，trades(since) 只返回序号更大的成交。
- depth 按价位聚合剩余量，买盘价格降序、卖盘升序，只取前 levels 档；book(side) 返回该方向按优先级排序的挂单列表，book() 返回买卖两侧的字典。
- 账本必须守恒：金币总量等于各账户余额加买单冻结加已收税费，物品总量等于余额加卖单冻结；audit 给出 gold_total、gold_locked、item_total、item_locked、fees、open_orders。
- snapshot 必须能 JSON 往返；恢复后余额、挂单、成交、税费、订单序号与成交序号继续可用，版本不符抛 ORDER_BAD_SNAPSHOT。

硬约束：冻结、成交、退款、记账必须在一次事务里一起成功或一起失败，并发入金与下单不允许丢更新或出现负余额；未成交订单有硬容量上限；单次撮合有明确预算，不能因为一次调用扫全簿拖垮交易线程。

验收：`python3 -m pytest -q tests` 的 15 条测试必须全部通过，不得修改测试、跳过或用固定输入写死结果；并发与重启恢复场景自行验证；只做本地实现，不涉及上游提交与平台操作。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 地狱
