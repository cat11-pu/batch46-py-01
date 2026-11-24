# GSB Bugfix Task

## 题面

身份平台上周接了两个企业 IdP，SAML 单点登录的故障单一天涨到七十多张。同一个断言被浏览器重放两次，两次都建了会话；第三方签发的断言 audience 指向别家 SP 却照样换到票据；签名证书轮换后旧指纹签的断言仍在放行；Recipient 指向另一个 ACS 地址也返回登录成功；上一轮请求的 InResponseTo 被当成当前应答接受；时间窗口只按本地时区比较，跨时区客户提前一小时被判过期，NotBefore 在未来两分钟的断言又被直接拒掉；攻击者往重放缓存灌几十万个 ID，进程内存被撑爆；集群滚动重启后缓存清空，上周用过的断言重新生效；批量补发回调里同一 ID 出现两次，两条都回成功；运维撤销被入侵的 IdP 之后，新断言仍在通过；还有一条告警说某租户单个 SP 的断言量十分钟内翻了几十倍，重放命中却一次都没记上。

范围是 gsb/batch46-safety-a-01 下的 saml_assertion_replay_guard.py，类 SamlReplayGuard，任务类型 Bugfix，负责 SP 注册、签发方信任、断言消费与重放缓存。公开接口（Python 类型注解）：`SamlReplayGuard(*, clock_skew: int = 120, max_seen: int = 1000, batch_limit: int = 100, clock=None)`；`register_service_provider(sp_id: str, *, entity_id: str, audiences, acs_url: str) -> dict`；`trust_issuer(issuer: str, *, fingerprints, allowed_audiences=None) -> dict`；`revoke_issuer(issuer: str) -> None`；`consume(assertion: dict, *, sp_id: str, now=None, request_id: str | None = None) -> dict`；`consume_batch(assertions, *, sp_id: str, now=None) -> list`；`is_seen(assertion_id: str) -> bool`；`purge(now=None) -> int`；`snapshot() -> dict`；`restore(state: dict) -> None`；`stats() -> dict`；`reset_stats() -> None`。校验失败统一抛 SamlError(code, detail)，code 用下面的字符串。

故障与边界：一、同一断言 ID 第二次消费返回 {"status": "replayed", "code": "SAML_REPLAY"}，不抛异常也不重复计数；二、未注册 SP 抛 SAML_UNKNOWN_SP，同一 sp_id 重复注册但 acs_url 不同抛 SAML_CONFLICT，完全相同则幂等返回；三、未登记签发方抛 SAML_UNTRUSTED_ISSUER，已撤销签发方抛 SAML_ISSUER_REVOKED，撤销未登记签发方抛 SAML_UNKNOWN_ISSUER；四、指纹不在该签发方信任集合抛 SAML_SIGNATURE_UNTRUSTED；五、audience 必须在 SP 登记受众内，若签发方登记了允许受众也需命中，否则抛 SAML_AUDIENCE_MISMATCH；六、Recipient 必须与注册的 acs_url 完全相等，否则抛 SAML_RECIPIENT_MISMATCH；七、传入 request_id 时必须等于断言的 in_response_to，缺失同样算不匹配，抛 SAML_INRESPONSETO_MISMATCH；八、时间窗口按 UTC 换算：now 早于 not_before 减 clock_skew 抛 SAML_NOT_YET_VALID，now 大于等于 not_on_or_after 加 clock_skew 抛 SAML_EXPIRED，正好落在边界算过期；九、缓存上限 max_seen，写满前先清理已过期条目，仍满抛 SAML_CACHE_FULL 且该断言不写入；十、consume_batch 逐条处理并逐条给出 accepted/replayed/rejected，超过 batch_limit 抛 SAML_BATCH_TOO_LARGE，单条失败不影响后面的断言；十一、purge 删除到期条目并返回条数，is_seen 只看当前缓存；十二、snapshot/restore 必须覆盖 SP、签发方、撤销名单、缓存和统计，恢复后已消费的断言仍按重放处理，结构非法抛 SAML_SNAPSHOT_INVALID 且原状态不变。

硬约束：consume 全程持锁，多线程同时消费同一断言只能有一个 accepted，其余全部 replayed；快照必须是深拷贝，能跨进程恢复且不受恢复前后续写入影响；缓存按断言到期时间淘汰，不允许无界增长；stats 精确区分 accepted、replayed、rejected，reset_stats 归零。

验收：`python3 -m pytest -q tests` 的 15 条测试全部通过；不得修改测试、跳过或按固定输入写死；并发与重启恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
