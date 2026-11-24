# GSB Bugfix Task

## 题面

内容平台把附件下载换成 Azure Blob 直连之后，客户成功团队连续收到投诉：分享链接里的读权限被前端改成了读写，签名却没变，上传接口因此放行了越权写入；带存储访问策略的链接在策略撤销后还能用整整一天，缓存里一直是旧权限；策略窗口比 SAS 本身短，过期时间取了较长的那个，链接多活了两小时；只允许 HTTPS 的链接用 HTTP 也能下载；限制来源网段的 SAS 换个出口 IP 照样通过；容器级 SAS 能读到同账号下别的容器；密钥轮换后旧链接没有宽限期，正在跑的数据迁移全断，也没有任何过期拒绝的记录；签发的 SAS 记录只增不减，一周就把内存撑满；并发的权限校验和策略撤销之间出现一边放行一边已撤销的时序问题；审计统计和快照恢复后对不上。模块路径 gsb/batch46-safety-a-08，文件名 azure_sas_guard.py，类名 SasGuard，任务类型 Bugfix。

接口以骨架为准：register_key(version: str, secret: str) -> dict；rotate_key(version: str, *, now: int, overlap: int = 300) -> dict；define_policy(name: str, *, permissions: str, start: int, expiry: int) -> dict；revoke_policy(name: str, *, now: int) -> dict；check_permissions(granted: str, required: str) -> dict；build_sas(account: str, *, resource: str, permissions: str | None = None, start: int, expiry: int, key_version: str | None = None, policy: str | None = None, ip: str | None = None, protocol: str = "https") -> dict；string_to_sign(fields: Mapping[str, str]) -> str；verify(sas: Mapping[str, Any] | str, *, operation: str, now: int, target: str, client_ip: str | None = None, protocol: str = "https") -> dict；purge_expired(*, now: int) -> int；snapshot() -> dict；restore(state: Mapping[str, Any]) -> None；stats() -> dict。

具体规则与边界。权限字符只允许 r、a、c、w、d、x、l、t、m、e、o、p，按 racwdxltmeop 排序去重，出现别的字符抛 SasError，code 为 SAS_UNKNOWN_PERMISSION；check_permissions 返回 allowed、missing、effective 三个键。SAS 字段固定顺序 sa、skv、sv、ss、srt、sp、st、se、spr、sip、si、sdd，最后是 sig，其中 sv 固定 2024-11-01、ss 固定 b，resource 里不含斜杠时 srt 为 c 否则为 o，sdd 保存去掉首尾斜杠后的资源路径，sip 和 si 没有值时也要占位为空串。string_to_sign 把前十二个字段按该顺序用换行连接，签名是 HMAC-SHA256 后转 Base64，密钥取 skv 对应的那一条。build_sas 返回 fields、token、signature，token 按字段顺序拼接。未指定 key_version 用当前密钥；policy 与 permissions 同时给出抛 SAS_POLICY_CONFLICT，策略不存在抛 SAS_UNKNOWN_POLICY，密钥不存在抛 SAS_UNKNOWN_KEY；expiry 不大于 start 或超过 max_lifetime 抛 SAS_INVALID_WINDOW，resource 为空抛 SAS_INVALID_SCOPE，protocol 只接受 https 或 https,http 否则抛 SAS_BAD_PROTOCOL，ip 不是合法 CIDR 抛 SAS_BAD_IP。带策略时权限改为策略权限，生效起点取 SAS 与策略的较大值，生效终点取两者较小值；策略被撤销后所有引用它的链接立即返回 SAS_POLICY_REVOKED。verify 支持字段字典或原始 token 字符串，按签名、密钥退休、协议、来源 IP、时间窗、权限、资源范围依次判断：签名不符 SAS_BAD_SIGNATURE，旧密钥超过宽限 SAS_KEY_RETIRED，只允许 HTTPS 而请求是 HTTP 返回 SAS_DENY_PROTOCOL，来源不在网段或缺少来源返回 SAS_DENY_IP，未到起点 SAS_NOT_YET_VALID，到达终点 SAS_EXPIRED，权限不足 SAS_DENY_PERMISSION，容器 SAS 只能访问该容器及其子路径、Blob SAS 只能访问精确路径，越界返回 SAS_DENY_SCOPE，成功返回 SAS_OK。密钥轮换把旧密钥的退休时刻设为 now 加 overlap，now 大于等于退休时刻即拒绝旧签名。

硬约束：签发记录有 max_records 上限，满了继续签发抛 SAS_RECORD_LIMIT，purge_expired 删除 expiry 小于等于 now 的记录并返回条数；verify 与 revoke_policy 必须并发安全，八路各五十次校验全部成功后再撤销策略，下一次校验必须立即拒绝，计数不能丢；snapshot 深拷贝密钥、当前密钥、退休时刻、策略、签发记录和计数器，restore 完整替换，恢复后的策略状态与快照时刻一致，不能被之后对原对象的撤销污染。

验收：python3 -m pytest -q tests 的 15 条测试必须全部通过；不得修改测试、跳过或按固定输入写死；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
