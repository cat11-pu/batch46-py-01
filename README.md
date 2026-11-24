# GSB Bugfix Task

## 题面

周五下午，某条 GitHub Actions 流水线被一条来自 fork 仓库的 pull_request 触发，OIDC 令牌里写着目标仓库的主分支 subject，云上角色照样被承担，安全团队从 CloudTrail 里翻出十几条异常会话。排查发现信任策略只按仓库名做了前缀匹配，`acme/app-extra` 能骗过 `repo:acme/app`；带 pipeline 后缀的 subject 也被当成主分支放行；另有一条 deny 规则写在 allow 后面，代码遇到第一个命中就返回，deny 形同虚设。同一个令牌在重试脚本里被换到两次凭证，会话时长按策略上限硬给，令牌只剩十分钟也发一小时票。任务在 `gsb/batch46-safety-b-02`，文件 `ci_oidc_trust_guard.py`，任务类型 Bugfix，修 `CiOidcGuard`，策略注册、求值、换取凭证、解释拒绝原因四条路径共用同一份内存状态。

公开接口（与骨架一致）：`__init__(self, *, issuer, now=0)`；`register_policy(self, name, *, audiences, subjects=(), claims=None, max_session=3600, deny=False, enabled=True) -> dict`；`set_policy_enabled(self, name, enabled) -> dict`；`rotate_issuer(self, issuer) -> dict`；`evaluate(self, token, *, now=None) -> dict`；`assume(self, token, *, now=None) -> dict`；`explain(self, token, *, now=None) -> dict`；`purge_used_jti(self, *, now=None) -> int`；`policies(self) -> list`；`stats(self) -> dict`；`audit_log(self) -> list`；`snapshot(self) -> dict`；类方法 `restore(cls, state)`。

令牌是字典，必须带 iss、aud、sub、jti、iat、exp，可选 claims；缺字段或时间戳不是整数，抛 CiOidcError 并带 OIDC_MALFORMED_TOKEN。需要修的点：

1. 求值顺序固定：iss 不等于当前签发者报 OIDC_ISSUER_MISMATCH；now 大于等于 exp 报 OIDC_TOKEN_EXPIRED；iat 超过 now 加 60 秒报 OIDC_CLOCK_SKEW；jti 已消费报 OIDC_REPLAY_DETECTED。
2. 策略按注册顺序参与匹配，只有 enabled 的策略生效；aud 是字符串或列表，只要与策略 audiences 有交集即可，不命中报 OIDC_AUDIENCE_MISMATCH。
3. subject 用整串匹配，`*` 可以匹配任意字符但不跨冒号，大小写敏感；subjects 为空表示不限制。前缀相同不算命中，尾随 `:pr` 也不算。
4. claims 条件逐键比对，值可以是标量或列表，必须精确相等且区分大小写，缺键或不等报 OIDC_CLAIM_MISMATCH，令牌里多出的 claim 不算错。
5. deny 优先：任何命中的 deny 策略都压过命中的 allow 策略，与注册顺序无关，报 OIDC_DENY_POLICY 并带上该策略名；没有启用的策略统一报 OIDC_NO_MATCHING_POLICY。
6. 命中的 allow 策略返回 allowed 为真、policy 名、code 为 None，会话时长取 max_session 与 exp 减 now 的较小值；evaluate 的 session 在拒绝时为 0。
7. assume 在 allowed 时消费 jti 并返回 policy、session、expires_at、sub、jti 与一份凭证字典；拒绝时抛 CiOidcError，code 与 evaluate 一致。
8. evaluate 对已消费的 jti 只报重放、不再消费；explain 返回 allowed 与 reasons，reasons 按 issuer、audience、expired、skew、replay、subject、claims、deny 的固定顺序列出全部失败项，其中 audience、subject、claims 三个维度各自独立判定，某个维度没有任何启用策略通过就记一条失败；通过的令牌 reasons 为空列表，explain 本身不消费 jti。
9. rotate_issuer 返回新 issuer 和 previous，旧 issuer 的令牌立即报 OIDC_ISSUER_MISMATCH，已注册策略与已消费 jti 保留；policies 按注册顺序返回策略字典且元素含 enabled 字段，set_policy_enabled 对未知策略报 OIDC_UNKNOWN_POLICY。
10. purge_used_jti 只清理令牌 exp 小于等于 now 的已消费记录，返回清理条数；stats 至少包含 evaluations、assumed、denied、used_jti 四个计数。
11. 并发硬约束：同一个 jti 被八个线程同时 assume，只能有一个成功，其余七个全部 OIDC_REPLAY_DETECTED，assumed 计数只能加一，jti 消费与计数器在同一临界区内完成。
12. 快照恢复：snapshot 必须可 JSON 序列化，restore 之后 issuer、策略、已消费 jti 及其 exp、计数器全部延续，恢复后重放仍被拦住。

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
