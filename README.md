# GSB Bugfix Task

## 题面

拍卖行的税务结算在版本更新后开始对不上账：同一批 37 笔成交被两个结算任务各结了一次，卖家被扣了两遍税；标价 3 金的低价材料本来在免税额内，结算单却按最低税额收了 1 金；截止时间用服务器本地时区截断，跨时区的成交要么早结一天要么晚结一天。更麻烦的是退款冲正只改了订单状态，没有把钱回冲给卖家，付款超额也没有拦住，财务月底核账时 outstanding 是个负数。现在要修 `gsb/batch46-game-a-09` 模块，文件 `tax_ledger_guard.py`，类 `TaxLedger`，任务类型 Bugfix，成交录入、批次结算、冲正、付款四条路径共用一份税务账。

要补齐的公开接口：

```python
def tax_for(self, gross: int, category: str = "item") -> int
def set_category_rate(self, category: str, rate_bps: int, exempt_below: int = 0) -> dict
def record_sale(self, sale_id: str, seller: str, buyer: str, gross: int, occurred_at: str, category: str = "item") -> dict
def pending(self, seller: str | None = None) -> list[dict]
def settle(self, seller: str, upto: str, batch_id: str, limit: int | None = None) -> dict
def settle_all(self, upto: str, batch_id: str, limit: int | None = None) -> dict
def waiver(self, seller: str, sale_id: str, reason: str) -> dict
def reversal(self, sale_id: str, reversal_id: str, at: str) -> dict
def pay(self, seller: str, amount: int, payment_id: str, at: str) -> dict
def totals(self, seller: str) -> dict
def ledger(self, seller: str) -> list[dict]
def snapshot(self) -> dict
def restore(self, payload: Mapping[str, Any]) -> None
```

故障与边界：

- tax_for 按 bps 向下取整；成交额低于该分类起征额按 0；应纳低于 min_fee 且成交额为正时按 min_fee；超过 cap 按 cap；成交额非正抛 TAX_BAD_AMOUNT。
- set_category_rate 覆盖默认税率，未登记分类沿用默认；bps 超出 0 到 10000 或起征额为负抛 TAX_BAD_RATE，分类为空抛 TAX_BAD_CATEGORY。
- record_sale 按 sale_id 幂等，重复返回 status=duplicate；卖家与买家相同抛 TAX_SELF_TRADE；单号或买卖家为空抛 TAX_BAD_SALE；发生时间必须带时区，否则抛 TAX_BAD_TIME。
- pending 按发生时间升序、同一时刻按录入顺序；可按卖家过滤；已豁免的单仍出现在待结列表里，但税额为 0。
- settle 只结发生时间小于等于 upto 的待结单，等号那一笔要算进去；税按笔累加进批次；重复 batch_id 返回 status=duplicate，不得重复计费。
- settle 的 limit 是单批预算，先结最老的，剩余留在待结状态并通过 remaining 回报；不传 limit 时用 batch_limit。
- settle_all 跨卖家按发生时间全局排序取预算，批次按卖家分摊税额，之后 totals 能还原每个卖家已结的税。
- waiver 只能在结算前使用，税归零但 gross 仍计入总量；结算后再申请抛 TAX_ALREADY_SETTLED；重复申请返回 duplicate；越权操作抛 TAX_SALE_OWNER。
- reversal 对已结算销售产生负调整并把 outstanding 冲回去，重复冲正返回 duplicate；对未结算销售直接作废、不计税；冲正时间早于销售时间抛 TAX_BAD_ORDER，单号不存在抛 TAX_SALE_NOT_FOUND。
- pay 只允许支付未结清金额，超额抛 TAX_OVERPAY；payment_id 幂等；返回值与 totals 的 paid、outstanding 必须一致。
- totals 的 gross 与 tax_accrued 不含作废单，outstanding 等于已结算税加调整减已付，pending 是待结笔数。
- snapshot 必须可 JSON 序列化；恢复后销售、批次、冲正、支付、分类税率与序号继续可用，版本不符抛 TAX_BAD_SNAPSHOT。

硬约束：一条成交的入账、批次归属、冲正、付款必须一次事务内一致生效；进程重启后批次与幂等集合不能丢；单卖家待结笔数有硬上限，超过按 TAX_PENDING_LIMIT 拒绝；并发录入不能丢销售，同一个 batch_id 并发提交只能生效一次。

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
