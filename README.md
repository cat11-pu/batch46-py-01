# GSB Bugfix Task

## 题面

多租户集群升级到投射服务账号令牌后，审计报出一串问题：给监控用的令牌 audience 只有 metrics，却能被 API Server 接受，跨服务调用没有隔离；标记了 pod UID 的令牌在别的 pod 里照样通过，节点绑定的令牌换台机器也能用；令牌过期时间比配置的 ttl 长出一大截，最长的一次签了十二小时；Refresh 接口在令牌刚签发十秒就把有效期续满，客户端因此从不真正轮换；同一个 UID 被并发签发两次，两把令牌内容不同却都进了令牌表；吊销某个服务账号之后，之前签出的令牌还在用，新签的也被误伤；密钥轮换后旧令牌瞬间全灭，滚动升级中的工作负载集体 401；令牌表只增不减，节点重启之后内存直接翻倍；快照恢复后吊销时间和密钥环丢了，已吊销账号又能通过；审计统计和实际签发数对不上，并发下 issued 少记。模块路径 gsb/batch46-safety-a-10，文件名 k8s_bound_token_guard.py，类名 BoundTokenGuard，任务类型 Bugfix。

接口以骨架为准：issue(subject: str, *, audiences: Sequence[str], now: int, ttl: int = 600, pod: str | None = None, node: str | None = None, uid: str | None = None, not_before: int | None = None) -> dict；decode(token: str) -> dict；validate(token: str, *, now: int, audiences: Sequence[str] = (), pod: str | None = None, node: str | None = None) -> dict；refresh(token: str, *, now: int, ttl: int = 600) -> dict；revoke(subject: str, *, now: int) -> dict；rotate_key(*, now: int) -> dict；purge_expired(*, now: int) -> int；snapshot() -> dict；restore(state: Mapping[str, Any]) -> None；stats() -> dict。

具体规则与边界。令牌是三段式紧凑串，头部含 alg 为 HS256、typ 为 JWT、kid 为当前密钥编号，载荷含 sub、aud、iat、nbf、exp、jti，以及可选 pod_uid 和 node，段用无填充 base64url，签名用 kid 对应密钥做 HMAC-SHA256。audiences 必须是非空字符串序列，去重排序后最多八项，为空抛 BoundTokenError 且 code 为 TOK_INVALID_AUDIENCE，超过八项返回 TOK_AUDIENCE_LIMIT；ttl 小于等于零返回 TOK_INVALID_LIFETIME，超过 max_token_lifetime 返回 TOK_LIFETIME_TOO_LONG；uid 已存在且未过期返回 TOK_DUPLICATE_UID；令牌表满时先清理 exp 小于等于 now 的记录，仍然满才返回 TOK_LIMIT。validate 按解析、签名、密钥退休、过期、生效时间、audience、pod、node、吊销的顺序判断：段数或编码错误返回 TOK_MALFORMED，签名不符返回 TOK_BAD_SIGNATURE，旧密钥超过退休时刻返回 TOK_KEY_RETIRED，now 大于等于 exp 返回 TOK_EXPIRED，nbf 大于 now 加 clock_skew 返回 TOK_NOT_YET_VALID，要求列表里任一 audience 不在令牌里返回 TOK_AUDIENCE_MISMATCH，给了 pod 而令牌 pod_uid 不一致或缺失返回 TOK_BOUND_OBJECT_MISMATCH，给了 node 而令牌 node 不一致或缺失返回 TOK_NODE_MISMATCH，subject 已被吊销且令牌 iat 小于等于吊销时刻返回 TOK_REVOKED。成功返回 TOK_OK 以及 sub、aud、exp、pod_uid、node、kid。revoke 记录吊销时刻并返回 subject、revoked_at、invalidated 三个字段，invalidated 是当前令牌表里该 subject 且 iat 不大于 now 的条数。rotate_key 生成下一个 kid，把上一个 kid 的退休时刻设为 now 加 key_grace，返回 new_kid、retired_kid、retired_at。refresh 只在令牌剩余生命期不超过原始生命期的两成时允许，否则返回 TOK_REFRESH_NOT_NEEDED；刷新后保留同一个 jti、同一个 pod 与 node 绑定，iat 和 nbf 取 now，exp 取 now 加 ttl，用当前密钥签名；ttl 越界按签发规则报错。purge_expired 删除 exp 小于等于 now 的令牌并返回条数。

硬约束：同一 uid 的签发判定与写入必须原子，八路并发签发同一 uid 只能有一个成功、七个 TOK_DUPLICATE_UID，issued 只记一次；令牌表受 max_tokens 上限约束，不能靠无限增长兜底；snapshot 深拷贝密钥环、当前 kid、退休时刻、吊销表、令牌表和统计，restore 完整替换，恢复后快照时刻之前吊销的令牌仍然拒绝、快照之后对原对象的吊销不影响恢复结果。stats 至少包含 issued、validated、refreshed、rejected 四个计数。

验收：python3 -m pytest -q tests 的 15 条测试必须全部通过；不得修改测试、跳过或按固定输入写死；并发与快照恢复需要自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
