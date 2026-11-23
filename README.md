# GSB Bugfix Task

## 题面

商城跨币种兑换上线后，运营发现同一笔报价被兑换了两次，玩家白拿一份金币；有人在下单和成交之间反复刷新汇率，成交价与展示价对不上；押金冻结只挡住了界面上的数字，实际余额仍能被兑换扣走，账户被打成负数；小数位处理也不统一，几笔小额兑换的手续费被抹成 0，账目对不平；客服还发现同一批报价被不同账号轮番使用，冻结与结算的先后顺序也说不清。财务要求这次把报价、成交、冻结、结算和流水做成一套可复算的事务。出问题的模块是 gsb/batch46-game-a-02 的 currency_exchange_guard.py，类型 CurrencyExchange，任务类型 Bugfix，骨架里只有桩，请补齐钱包与兑换的完整实现。

公开接口：add_rate(self, base: str, quote: str, rate, *, effective_at=None) -> dict；rate(self, base: str, quote: str) -> Decimal；open_wallet(self, account_id: str, balances: dict | None = None) -> dict；quote(self, account_id: str, from_currency: str, to_currency: str, amount, *, now=None) -> dict；exchange(self, account_id: str, quote_id: str, *, now=None) -> dict；freeze(self, account_id: str, currency: str, amount, *, reason: str = "hold", now=None) -> dict；release(self, freeze_id: str) -> dict；settle(self, freeze_id: str, *, currency: str | None = None, amount=None, now=None) -> dict；balance / available / history / snapshot / restore。

1. 汇率支持直接、反向（1/x，8 位小数）以及经基准币 GOLD 的交叉折算，缺少路径抛 FX_UNKNOWN_RATE，同币种返回 1；add_rate 不接受同币种对，遇到就抛 FX_BAD_CURRENCY。
2. 报价锁定报价时的汇率快照，之后 add_rate 改价不影响已开报价；报价 60 秒过期，过期兑换抛 FX_QUOTE_EXPIRED，余额一分不动。
3. 报价单次使用，重复兑换抛 FX_QUOTE_USED；其他账户使用抛 FX_QUOTE_OWNER；报价号不存在抛 FX_UNKNOWN_QUOTE。
4. 金额一律用 Decimal 两位小数：兑出金额向下取整，手续费为兑出金额的 0.5% 四舍五入到分，最低 0.01；兑换结果返回 spent、received、fee、rate。
5. 冻结只减少可用余额，总余额保持不变；超过可用抛 FX_INSUFFICIENT_AVAILABLE，非正金额抛 FX_BAD_AMOUNT。
6. settle 把冻结额从总余额永久扣除；币种不符抛 FX_CURRENCY_MISMATCH 且冻结保持 open，金额不符抛 FX_AMOUNT_MISMATCH。
7. 已关闭的冻结再次 release 或 settle 抛 FX_FREEZE_CLOSED；正常 release 只把额度还给可用余额，不扣总余额。
8. 兑换余额不足抛 FX_INSUFFICIENT_FUNDS，被冻结的部分不得参与兑换，也不得作为报价扣款来源。
9. 单账户同时有效的未使用报价默认上限 32，可由构造参数 max_quotes 调整，超出抛 FX_QUOTE_LIMIT，过期报价不占名额。
10. 未知账户、重复开户分别抛 FX_UNKNOWN_ACCOUNT、FX_WALLET_EXISTS；history 按时间倒序返回流水，运营可据此复算每种币的进出。
11. snapshot 必须可 JSON 序列化，金额以字符串保存；restore 版本或字段不符抛 FX_BAD_SNAPSHOT，拒绝前不得改动现有数据，恢复后余额、冻结、报价与流水一致。
12. 同一账户并发兑换不能把余额扣成负数，成功笔数必须正好等于可用额度，多余请求返回 FX_INSUFFICIENT_FUNDS。

并发与恢复：多线程同时下单时，可用余额的计算与扣减必须是一个原子动作；进程重启后从快照恢复，再继续兑换不能重复给同一报价入账，冻结押金仍能正常释放或结算。

验收标准：python3 -m pytest -q tests 必须 15 条全绿；不要改测试、不要跳过、不要按固定输入写死答案；并发与重启场景自己验证，只在本地完成实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
