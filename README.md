# GSB Bugfix Task

## 题面

钻石商城的账在促销周彻底乱了：同一礼包被客户端重试扣了两次钻，玩家背包只到账一份；过期三个月的活动钻石还能在限时商店里花出去；预订了 198 钻的皮肤，提交时那批钻正好到期，系统照样扣了余额，事后既不能退也不能追；每日消耗上限在并发点击下形同虚设，有账号一分钟刷掉三倍额度。退款窗口用运营本地时间算，跨时区玩家差一天，返还的钻石又带着新的永久有效期，等于白送。现在要修 `gsb/batch46-game-a-10` 模块，文件 `gem_sink_guard.py`，类 `GemSink`，任务类型 Bugfix，发放、预订、消耗、退款四条路径共用一份钻石账。

要补齐的公开接口：

```python
def grant(self, account: str, amount: int, grant_id: str, expires_at: str | None = None) -> dict
def balance(self, account: str, at: str) -> dict
def lots(self, account: str, at: str) -> list[dict]
def reserve(self, account: str, amount: int, reservation_id: str, at: str) -> dict
def commit(self, account: str, reservation_id: str, at: str) -> dict
def release(self, account: str, reservation_id: str, at: str) -> dict
def spend(self, account: str, amount: int, spend_id: str, at: str) -> dict
def refund(self, account: str, spend_id: str, amount: int, refund_id: str, at: str) -> dict
def expire(self, account: str, at: str) -> dict
def daily_spent(self, account: str, at: str) -> int
def history(self, account: str) -> list[dict]
def snapshot(self) -> dict
def restore(self, payload: Mapping[str, Any]) -> None
```

故障与边界：

- grant 按 grant_id 幂等，重复发放返回 duplicate 不叠加；金额非正抛 GEM_BAD_AMOUNT；单账户批次数量到达 max_lots 时新发放抛 GEM_TOO_MANY_LOTS。
- balance 按 at 过滤批次，到期时刻小于等于 at 即视为过期；返回 total、reserved、available 三项，total 等于两者之和。
- spend 按批次入账顺序 FIFO 消耗最老的有效份额；可用不足抛 GEM_INSUFFICIENT，余额与批次都不变；spend_id 幂等，重复返回 duplicate。
- 每日上限按 at 换算成 UTC 后的自然日累计，spend 与 commit 都要计入；超限抛 GEM_DAILY_CAP，这一笔不扣钻石、不占额度。
- reserve 把额度从批次移到预订，available 减少、reserved 增加；同一 reservation_id 重复预订返回 duplicate，不重复占用。
- release 把预订额度按原到期时间退回可用余额；重复 release 返回 status=ignored、code=GEM_RESERVATION_CLOSED；未知预订抛 GEM_RESERVATION_NOT_FOUND。
- commit 消耗预订并计入当日额度；预订里任一份额在 at 已过期抛 GEM_RESERVATION_STALE，预订保持原状仍可 release，不能悄悄吞掉。
- expire 丢弃到期批次与含到期份额的未决预订，返回 lots、gems、reservations、reserved_gems；同一时刻重复调用各项返回 0。
- refund 只能退本人账号的 spend，窗口按 UTC 计算，恰好第 7 天允许，超窗抛 GEM_REFUND_WINDOW；累计超额抛 GEM_OVER_REFUND；spend 不存在抛 GEM_SPEND_NOT_FOUND；refund_id 幂等。
- 退款生成新的批次，到期时刻为退款时刻加 retention_days 天，到期后不再计入余额，不能借退款洗出永久钻石。
- 账户之间完全隔离，余额、预订、spend 与每日额度互不影响；lots(at) 只返回有效且 remaining 大于 0 的批次，daily_spent(at) 返回该 UTC 日的累计消耗。
- snapshot 必须可 JSON 序列化；恢复后批次顺序与到期时间、预订、spend、退款、每日额度与序号原样可用，版本不符抛 GEM_BAD_SNAPSHOT。

硬约束：扣钻、写 spend、累加当日额度必须一次事务内同时成功或同时失败；进程重启后批次顺序、预订状态与幂等集合不能丢；批次数量与流水长度都有硬上限；并发消耗不能超过每日额度或把余额扣成负值。

验收：`python3 -m pytest -q tests` 的 15 条测试必须全部通过，不得修改测试、跳过或用固定输入写死结果；并发与快照恢复场景自行验证；只做本地实现，不涉及上游提交与平台操作。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 地狱
