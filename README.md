# GSB Bugfix Task

## 题面

商城退款通道上周被人钻了空子：同一笔 648 订单提交两次退款，钱包加了两次；一笔已经退过 60% 的订单又退了全款，账面直接变成正收益；还有玩家在退款窗口最后一天用不同时区的时间戳反复试探，客服按本地时间算通过了，财务按 UTC 算已经过期。冻结那边同样乱：预订扣款把可用余额扣成负数，释放冻结时又把钱退了两遍，结算流水里却只有一条记录。财务要求这次把余额、冻结、退款累计、冲正和流水合成一本账，重启后逐笔能对上。现在要修 `gsb/batch46-game-a-08` 模块，文件 `refund_ledger_guard.py`，类 `RefundLedger`，任务类型 Bugfix。

要补齐的公开接口：

```python
def credit(self, account: str, amount: int, tx_id: str, at: str) -> dict
def debit(self, account: str, amount: int, tx_id: str, at: str, reason: str = "purchase") -> dict
def refund(self, account: str, tx_id: str, amount: int, refund_id: str, at: str) -> dict
def chargeback(self, account: str, tx_id: str, chargeback_id: str, at: str) -> dict
def balance(self, account: str) -> dict
def outstanding(self, account: str) -> int
def hold(self, account: str, amount: int, hold_id: str) -> dict
def release(self, account: str, hold_id: str) -> dict
def settle(self, account: str, hold_id: str, at: str) -> dict
def history(self, account: str) -> list[dict]
def statement(self, account: str, from_at: str, to_at: str) -> dict
def snapshot(self) -> dict
def restore(self, payload: Mapping[str, Any]) -> None
```

故障与边界：

- 扣款超出信用额度按 REFUND_CREDIT_LIMIT 拒绝，余额一分不动；可用余额等于余额减未结冻结，已冻结的钱不能被普通扣款花掉。
- credit 与 debit 共用 tx_id 去重，重复提交返回 status=duplicate，不重复记账；金额非正抛 REFUND_BAD_AMOUNT。
- 退款只能针对同一账号的扣款单累计：原单不存在抛 REFUND_TX_NOT_FOUND，对入账单退款抛 REFUND_NOT_REFUNDABLE，跨账号抛 REFUND_TX_ACCOUNT，累计超额抛 REFUND_OVER_REFUND。
- 退款窗口按 UTC 计算，恰好第 14 天允许，多一秒或换个时区表示的同一超窗时刻都抛 REFUND_WINDOW_EXPIRED；时间不带时区按 REFUND_BAD_TIME 拒绝。
- 同一 refund_id 重复提交返回 status=duplicate，带回累计退款额，余额不再变化。
- hold 占用可用余额，release 解冻；重复 release 返回 status=ignored、code=REFUND_HOLD_CLOSED；未知冻结抛 REFUND_HOLD_NOT_FOUND。
- settle 把冻结转成一条 settle 流水并扣减余额；已释放或已结算的冻结再结算返回 ignored 与 REFUND_HOLD_CLOSED，不能二次扣款。
- 可用余额不足时 hold 抛 REFUND_INSUFFICIENT_AVAILABLE；未结冻结数到达上限抛 REFUND_TOO_MANY_HOLDS，先判可用额再判数量。
- chargeback 只能冲正入账单，重复冲正返回 REFUND_ALREADY_REVERSED，对扣款单冲正抛 REFUND_NOT_CHARGEABLE；冲正可以把余额打到负，但不得低于负的 credit_limit，否则抛 REFUND_CREDIT_LIMIT。
- history 的 seq 单调递增，balance_after 与逐笔金额首尾相接；冻结与释放不产生流水，只有 credit、debit、refund、chargeback、settle 五类。
- statement 起止都是闭区间，opening、closing、total、entries 与流水对得上；起始时间晚于结束时间抛 REFUND_BAD_TIME。
- snapshot 必须可 JSON 序列化；恢复后余额、冻结、流水、退款累计、冲正记录与序号原样可用，版本不符抛 REFUND_BAD_SNAPSHOT。

硬约束：余额、冻结、退款累计、流水必须一次事务内同时成功或同时失败；进程重启后已用单号与冻结状态不能丢；单账户流水有硬容量上限；并发扣款不能突破信用额度，成功笔数必须精确。

验收：`python3 -m pytest -q tests` 的 15 条测试必须全部通过，不得修改测试、跳过或用固定输入写死结果；并发与快照恢复场景自行验证；只做本地实现，不涉及上游提交与平台操作。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
