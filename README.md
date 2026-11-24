# GSB Bugfix Task

## 题面

凌晨两点，值班同学发现 AppRole 登录接口的令牌签发量是平时的七倍：同一个 SecretID 在一次登录成功后仍能反复换票，把它拷到办公网段也照样通过；轮换 role_id 之后旧 role_id 依然能登录，巡检脚本扫出的活动 SecretID 数量和后台对不上。上周的安全演练里，红队用一个从构建日志里捡到的 SecretID 在办公网换到了生产策略的令牌，事后复盘发现登录路径根本没有读取绑定信息；灰度环境还出现过两个请求同时通过单次使用 SecretID 的情况，额度被重复扣减。任务在 `gsb/batch46-safety-b-01`，文件 `vault_approle_guard.py`，任务类型 Bugfix，修 `AppRoleGuard`，发放、登录、吊销、巡检四条路径共用同一份内存状态，任何一条路径漏判都会让其余三条的账目失真。

公开接口（与骨架一致）：`__init__(self, *, now=0)`；`create_role(self, role, *, policies, secret_id_ttl=3600, secret_id_num_uses=0, bind_cidrs=(), require_metadata=None, max_logins_per_minute=0) -> dict`；`generate_secret_id(self, role, *, cidr=None, metadata=None, ttl=None, num_uses=None, now=None) -> dict`；`login(self, role_id, secret_id, *, cidr, metadata=None, now=None) -> dict`；`revoke_secret_id(self, accessor, *, now=None) -> dict`；`rotate_role_id(self, role, *, now=None) -> dict`；`role_info(self, role) -> dict`；`sweep_expired(self, *, now=None) -> int`；`stats(self) -> dict`；`audit_log(self) -> list`；`snapshot(self) -> dict`；类方法 `restore(cls, state, *, now=0)`。

需要修的点：

1. `create_role` 返回 role 与 role_id，同名角色报 APPROLE_ROLE_EXISTS；`generate_secret_id` 返回以 `s.` 开头的 secret_id、accessor 和 expires_at（等于 now 加 ttl），每次生成的 secret_id 互不相同，不传 ttl 或 num_uses 时继承角色配置。
2. num_uses=0 表示不限次；额度用完再登录报 APPROLE_SECRET_CONSUMED，now 大于等于 expires_at 报 APPROLE_SECRET_EXPIRED，这两种失败都不能扣减剩余额度。
3. 登录成功返回 `hvs.` 前缀的唯一 token、role、按升序排列的 policies 和 accessor；stats 的 tokens_issued 只统计成功签发次数，失败登录不计入。
4. CIDR 校验：SecretID 自带 cidr 时以它为准，不再叠加角色绑定；否则使用角色的 bind_cidrs。地址不在网段或 cidr 字符串无法解析，一律报 APPROLE_CIDR_DENIED，判定用标准库 ipaddress，不要用字符串前缀比较。
5. require_metadata 与登录请求里的 metadata 做子集比对，缺键或值不相等报 APPROLE_METADATA_MISMATCH，请求里多出来的键不算错，比较区分大小写。
6. 轮换 role_id 只让旧 role_id 失效（APPROLE_ROLE_ID_MISMATCH），已经发放的 SecretID 继续可用；未知角色名报 APPROLE_UNKNOWN_ROLE，未知 role_id 与轮换后的旧值同码。
7. `revoke_secret_id` 按 accessor 立即生效且可重复调用，再次登录报 APPROLE_SECRET_REVOKED；role_info 必须给出 active_secret_ids 与 revoked_secret_ids 两个计数。
8. 单角色每分钟成功登录数超过 max_logins_per_minute（0 为不限）报 APPROLE_LIMIT_EXCEEDED，按 60 秒滑动窗口统计，窗口外的旧记录要滑出。
9. role_info、stats、audit_log 属于对外查询，不得出现任何 SecretID 明文，只允许出现 accessor；审计返回可 JSON 序列化的字典列表，能追溯是哪次登录被哪种错误码拒绝。
10. 并发硬约束：同一个 SecretID 被八个线程同时登录、num_uses=1 时只能有一个成功，其余全部 APPROLE_SECRET_CONSUMED，令牌计数和额度扣减都不得多记，共享状态的读写要加锁。
11. 快照恢复：snapshot 必须可 JSON 序列化，restore 之后已用次数、吊销状态、过期时间、role_id 和计数器全部延续，恢复后不能因为内存重建而让已用 SecretID 复活。
12. `sweep_expired` 只清理 expires_at 小于等于 now 的 SecretID，返回清理条数，被清理的 SecretID 再登录报 APPROLE_SECRET_UNKNOWN，未到期的不受影响。

验收：在项目根执行 `python3 -m pytest -q tests`，15 条必须全部通过；不得修改测试、跳过或按固定输入写死；并发与重启恢复场景请自行验证；只做本地实现，除 pytest 外不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
