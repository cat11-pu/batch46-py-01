# GSB Bugfix Task

## 题面

跨集群的服务身份联邦上线两周，安全组收到三类告警：只在测试域注册过的工作负载，被生产域节点成功签出了 SVID；节点重新做证明后 facts 变了，旧 SVID 在有效期内继续被接受，等于换一台机器不用换身份；签发器密钥轮换后，新签的凭据全被判签名错误，旧凭据反而还能通过。此外续期没有窗口限制，拿到一张就能无限续，序列号在服务重启后从头开始，同一个序号对应过两张不同的凭据。请修 `gsb/batch46-safety-b-10` 下的 `workload_identity_guard.py`，暴露类型 `WorkloadIdentityGuard`，任务类型 Bugfix，只改这一个文件，不得改测试。

题目已提供签名工具 `svid_signature(secret: str, claims: dict) -> str`，它对 serial、trust_domain、sa、subject、node、fact_digest、issued_at、expires_at、renewals、parent 这十个字段按固定顺序拼成 `字段=值`，再用竖线连接并追加 `|secret` 取 sha256；chain 和 status 不参与签名。保持这些公开接口：

- `register_issuer(trust_domain: str, *, secret: str, issuer_id: str | None = None) -> dict`
- `rotate_issuer(trust_domain: str, *, secret: str) -> dict`
- `register_workload(trust_domain: str, sa: str, *, selectors: dict[str, str]) -> dict`
- `attest_node(node_id: str, *, trust_domain: str, facts: dict[str, str], ttl_seconds: int = 1800, now: str = ...) -> dict`
- `issue_svid(node_id: str, *, sa: str, ttl_seconds: int | None = None, now: str = ...) -> dict`
- `renew_svid(serial: str, *, ttl_seconds: int | None = None, now: str = ...) -> dict`
- `revoke_serial(serial: str, *, reason: str = "manual") -> dict`
- `verify_svid(svid: dict, *, now: str = ..., expected_trust_domain: str | None = None) -> dict`
- `node_state(node_id: str) -> dict`、`workload_state(trust_domain: str, sa: str) -> dict`、`sweep(now: str = ...) -> dict`、`snapshot() -> dict`、`restore(snap: dict) -> None`、`audit(limit: int = 20) -> list`、`stats() -> dict`

构造参数 max_ttl、min_ttl、renew_window_ratio、max_outstanding_per_node、max_renewals、audit_capacity 默认 3600、60、0.2、4、2、256。签发器 secret 必须 64 位十六进制，否则 `WI_ISSUER_SECRET_INVALID`，重复注册报 `WI_ISSUER_DUPLICATE`，轮换不存在的域报 `WI_ISSUER_UNKNOWN`。选择器必须是非空字符串映射，否则 `WI_SELECTOR_INVALID`；重复注册相同选择器返回 unchanged，选择器不同报 `WI_WORKLOAD_DUPLICATE`。节点 facts 的规则同选择器，非法报 `WI_FACT_INVALID`，证明 ttl 非正报 `WI_TTL_INVALID`，未注册的域报 `WI_ISSUER_UNKNOWN`。

签发时节点不存在报 `WI_NODE_UNKNOWN`，证明过期报 `WI_NODE_UNATTESTED`；工作负载在本域没注册，但同一 sa 注册在别的域，报 `WI_TENANT_MISMATCH`，哪儿都没有报 `WI_WORKLOAD_UNKNOWN`；任一声明选择器与 facts 不等报 `WI_SELECTOR_MISMATCH`；节点未过期 SVID 达到 4 张报 `WI_OUTSTANDING_LIMIT`；ttl 小于 60 报 `WI_TTL_INVALID`，大于 3600 截断到 3600。序列号为 `<域>/svid-%06d`，全局从 1 起只增不减，subject 为 `spiffe://<域>/sa/<sa>`，返回值里带 chain 列表（从根到父，根为空）。续期只允许在有效期的最后 20%，过早报 `WI_RENEW_TOO_EARLY`，已吊销报 `WI_REVOKED`，已过期报 `WI_SVID_EXPIRED`，renewals 达到 2 次报 `WI_RENEW_LIMIT`；续出的新 SVID renewals 加一、parent 指向旧序号、chain 追加旧序号，旧 SVID 到期前继续有效。吊销不存在的序号报 `WI_SVID_UNKNOWN`，重复吊销幂等返回 revoked，吊销父序号要级联把它的续期后代一起置为吊销，返回值 cascaded 为本次被吊销的条数。

验签顺序固定：缺字段报 `WI_SVID_INVALID`，expected_trust_domain 不匹配报 `WI_TRUST_DOMAIN_MISMATCH`，域没有签发器报 `WI_ISSUER_UNKNOWN`，签名不符报 `WI_SIGNATURE_INVALID`，序号不认识报 `WI_SVID_UNKNOWN`，已吊销报 `WI_REVOKED`，已过期报 `WI_SVID_EXPIRED`，节点重新证明后 fact_digest 与签发时不同报 `WI_FACT_DRIFT`；通过时返回 status="valid" 与 serial、trust_domain、sa、subject、node、expires_at、renewals。`node_state` 返回 fact_digest、expires_at、outstanding，`workload_state` 返回 selectors 与 issued。

硬约束：snapshot/restore 必须可 JSON 序列化，保留签发器、工作负载、节点、SVID、序列号计数器和代数，版本号不认识报 `WI_SNAPSHOT_INVALID`，代数小于当前的旧快照报 `WI_SNAPSHOT_STALE`，被拒的恢复不得改动状态，恢复后不得出现序号复用；30 个线程同时为同一节点签发时，恰好 4 个成功、26 个 `WI_OUTSTANDING_LIMIT`，序列号互不相同；签发、续期、吊销、序号分配与审计写入都在同一把可重入锁内完成。audit 新的在前，超出容量丢最旧的。

验收：`python3 -m pytest -q tests` 的 15 条必须全过，不得改测试、跳过或按固定输入写死；并发与重启恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
