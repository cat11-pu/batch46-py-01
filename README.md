# GSB Bugfix Task

## 题面

公会仓库在版本更新后被人搬空了半页材料。值班同学对着客户端日志还原出经过：一个见习成员点开军官页签照样取走了两组矿石；额度早该用完的账号在 UTC 零点前后又连续取出十几份；两名军官同时点取货，同一堆材料被扣了两次库存，流水里却只留下一条。更麻烦的是客服拿到的审计记录是拼接的纯文本，谁都能改完再存回去，事后说不清哪条是真人操作、哪条是补录。仓库长要求这次把每个动作都做成可复核的凭证：能说清谁在什么时候从哪个页签动了多少东西，重登维护之后这些凭证仍然对得上。模块路径 `gsb/batch46-game-b-06`，文件名 `guild_bank_guard.py`，类型 `GuildBankGuard`，任务类型 Bugfix。骨架里的数据类和异常已经就位，方法体全是桩，按下面的契约补齐。

要实现的公开接口：

```python
def __init__(self, config: BankConfig) -> None
@classmethod
def from_snapshot(cls, config: BankConfig, data: bytes) -> "GuildBankGuard"
def add_member(self, member: Member) -> None
def set_rank(self, name: str, rank: Rank) -> None
def create_tab(self, index: int, min_rank: Rank = Rank.MEMBER) -> None
def lock_tab(self, index: int) -> None
def deposit(self, op_id: str, member: str, tab_index: int, item: Item, at: datetime) -> AuditEntry
def withdraw(self, op_id: str, member: str, tab_index: int, item_id: str, count: int, at: datetime) -> AuditEntry
def tab_contents(self, index: int) -> list[Item]
def ledger(self) -> list[AuditEntry]
def verify_chain(self) -> bool
def snapshot(self) -> bytes
def daily_total(self, member: str, day: date) -> int
```

故障与边界：

- 重复添加同名成员按 `BANK_MEMBER_EXISTS` 拒绝，重复页签号按 `BANK_TAB_EXISTS` 拒绝；`set_rank` 遇到未知成员按 `BANK_UNKNOWN_MEMBER` 拒绝，等级变化后立刻影响权限判断。
- 未知成员、未知页签、页签已上锁、等级低于页签要求分别按 `BANK_UNKNOWN_MEMBER`、`BANK_UNKNOWN_TAB`、`BANK_TAB_LOCKED`、`BANK_RANK_DENIED` 拒绝，存入和取出都要判，失败不能留下任何痕迹。
- 数量必须大于 0，否则 `BANK_INVALID_COUNT`；库存不足按 `BANK_INSUFFICIENT`，库存一份都不能扣。
- 每个成员每个 UTC 自然日的取货总量受 `daily_quota` 限制，跨多次操作累加；带时区偏移的时间戳先换算成 UTC 再判日期，`2026-11-24T02:00+08:00` 算前一天；超出按 `BANK_QUOTA_EXCEEDED`，这一笔不扣库存、不写流水、不占额度。
- `op_id` 是幂等键：成功执行过的操作号再次提交，无论存取、调用方是谁、参数是否合理，都按 `BANK_DUPLICATE_OP` 拒绝，这项检查排在其他所有校验之前。
- 同一页签内相同 `item_id` 的入库合并数量并保留原位置，新物品追加到队尾；取到 0 的堆从页签移除，剩余堆的相对顺序不变。
- 审计序号从 1 递增；`entry_hash` 是 SHA-256(`prev_hash|op_id|member|tab_index|item_id|count`) 的十六进制，`count` 用十进制字符串，字段用竖线连接；首条 `prev_hash` 是 64 个 0，后续 `prev_hash` 必须等于上一条 `entry_hash`；`verify_chain` 逐条重算，不一致抛 `BANK_CHAIN_BROKEN`。
- 流水条数达到 `ledger_capacity` 后，新操作按 `BANK_LEDGER_FULL` 拒绝，且库存、额度和流水都不能变。
- `snapshot` 返回 bytes，必须能恢复成员与等级、页签与库存、审计流水、额度累计和已用过的操作号；恢复后重复操作号仍要拒绝，`verify_chain` 仍通过，新流水的序号与哈希链接得上。
- 并发扣减必须原子：同一堆只剩 4 份时，12 个并发取 1 份的请求只能成功 4 个，其余全部 `BANK_INSUFFICIENT`，不允许出现负库存，成功笔数与流水条数必须一致。
- `tab_contents` 和 `ledger` 返回副本，调用方清空或追加返回的列表不能影响仓库内部状态。
- `daily_total` 只统计成功取货的数量，按成员和 UTC 日期分开计算，入库和失败请求都不计入。

硬约束：额度、库存、流水必须在一次事务里一起成功或一起失败；进程重启后去重集合与审计链不能断；流水有硬容量上限；并发扣减不能超卖。

验收：`python3 -m pytest -q tests` 的 15 条测试必须全部通过，不得修改测试、跳过或用固定输入写死结果；并发与重启场景自行验证；只做本地实现，不涉及上游提交与平台操作。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
