# batch46-game-b-04 CrossServerTransfer

## 题面

转服灰度一周，两服都能登录，重复提交生成两条单，单据不释放名额，满员仍能提交，回滚未恢复源服人数。gsb/cross_server_transfer_guard 的 cross_server_transfer_guard.py、类 CrossServerTransfer，任务类型 Bugfix。
接口：register_server(server: str, *, capacity: int = 1000, used: int = 0)；begin(transfer_id: str, *, account: str, source: str, target: str, payload: dict, created_at: str)；commit(transfer_id: str)；expire(now: str)；quota(server: str)；snapshot()。
故障：1）服未注册 TRF_UNKNOWN_SERVER，源目标相同 TRF_SAME_SERVER；2）payload 超限抛 TRF_PAYLOAD_TOO_LARGE；3）begin 返 pending，重复单号返 existing，账号有待处理单抛 TRF_PENDING_CONFLICT；4）源服待处理达 quota_per_source 抛 TRF_QUOTA_EXCEEDED，全局满 max_pending 抛 TRF_QUEUE_FULL；5）begin 把归属记为源服，commit 才迁目标服并调 used；6）重复 commit 抛 TRF_ALREADY_COMMITTED，容量记一次；7）回滚只对待处理单生效，其余 TRF_NOT_PENDING；8）超 ttl 单置 expired，重复 expire 为空；9）目标服余量提交时仲裁，满员 TRF_TARGET_FULL 且单据仍 pending；10）quota 给剩余额度；未知单号 TRF_UNKNOWN_TRANSFER；审计只记提交、回滚、过期，倒序、上限 history_limit。
硬约束：八线程同提一单只成功一次，其余 TRF_ALREADY_COMMITTED，used 只加一；快照恢复让已提交单回待处理，归属与容量回退。验收：python3 -m pytest -q tests 全过，不得改测试、跳过或写死输入，并发与快照自验。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- 所属领域：游戏、图形与多媒体
- 子方向：游戏开发
- 任务类型：Bugfix
- 难度：地狱
