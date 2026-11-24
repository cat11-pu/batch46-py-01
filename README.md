# GSB Bugfix Task

## 题面

海外区对象存储的签名网关换成本地 SDK 后，跨天批量任务开始整批返回 403，同一批请求在巴黎节点能过、在弗吉尼亚节点全挂。排查发现签名串里的查询参数没有按编码后的键值排序，空格一会儿是 %20 一会儿是加号；请求头里的 User-Agent 被算进签名，但网关转发时会改写它；路径里的 ./ 和重复斜杠没有归一化，桶名后面多一个斜杠就换了另一个签名；Content-Type 带连续空格时修剪规则不一致；预签名链接有的过期判断差一小时，有的把有效期设成一年也照签；重放检测只在单进程内存里生效，滚动重启后同一个签名可以再用一次；并发校验时同一份签名会同时通过两次，账单上出现双份请求；快照恢复后统计和重放缓存全丢，审计对不上。模块路径 gsb/batch46-safety-a-07，文件名 sigv4_canonical_guard.py，类名 SigV4Guard，任务类型 Bugfix。

接口以骨架为准：canonical_query(query: Mapping[str, Any]) -> str；canonical_headers(headers: Mapping[str, str]) -> tuple[str, str]；canonical_uri(path: str, *, normalize: bool = True) -> str；build_canonical_request(request: Mapping[str, Any]) -> dict；string_to_sign(request: Mapping[str, Any], *, timestamp: str, scope: str, algorithm: str = "AWS4-HMAC-SHA256") -> dict；signing_key(secret_key: str, *, date: str, region: str, service: str) -> str；sign(request, credentials, *, now: int) -> dict；verify(request, credentials, *, now: int) -> dict；presign(request, credentials, *, expires: int, now: int) -> dict；verify_presigned(request, credentials, *, now: int) -> dict；purge_replays(cutoff: int) -> int；snapshot() -> dict；restore(state: Mapping[str, Any]) -> None；stats() -> dict。

具体规则与边界。规范查询串只保留 A-Za-z0-9-_.~ 不编码，空格编成 %20，其余按 UTF-8 字节大写十六进制百分号编码，键和值都编码后先按键再按值升序排列，同名多值逐条输出。规范请求头名转小写、值去首尾空白并把内部连续空白压成一个空格，排除 authorization、user-agent、x-amzn-trace-id、expect，按名字升序输出 name:value 加换行，签名头列表用分号连接。规范 URI 先合并重复斜杠、解析 . 和 ..，根路径输出 /，末尾斜杠保留，再逐段编码。build_canonical_request 返回 canonical_request、canonical_uri、canonical_query、signed_headers、payload_hash，整体按方法、URI、查询串、请求头块、空行、签名头、负载哈希排列，payload 为 None 或空串都取空串的 SHA-256，标记 unsigned_payload 时写 UNSIGNED-PAYLOAD。string_to_sign 返回 string_to_sign 和 canonical_hash 两个键，四行依次是算法、时间戳、scope、规范请求的哈希。signing_key 走 AWS4 前缀的四段 HMAC-SHA256 链，返回六十四位小写十六进制。sign 要求请求带 Host，注入 X-Amz-Date 并返回带 authorization 的完整请求，格式是 AWS4-HMAC-SHA256 Credential=密钥/日期/区域/服务/aws4_request, SignedHeaders=..., Signature=...。verify 的检查顺序是格式、时钟偏差、签名、重放；偏差绝对值超过 clock_skew 返回 SIG_CLOCK_SKEW，签名不符返回 SIG_SIGNATURE_MISMATCH，签名已用过返回 SIG_REPLAY，成功返回 SIG_OK。预签名失败时抛 SigV4Error，code 为 SIG_INVALID_EXPIRY；expires 必须大于零且不超过 604800，now 大于等于签发时刻加 expires 判为 SIG_EXPIRED。purge_replays 删除 seen_at 小于等于 cutoff 的记录并返回条数。stats 至少包含 signed、presigned、verified、rejected 四个计数。

硬约束：重放登记必须与签名校验在同一临界区完成，八路并发校验同一份签名只能有一个 SIG_OK、七个 SIG_REPLAY，verified 记一次、rejected 记七次；snapshot 深拷贝重放缓存和计数器，restore 完整替换，恢复后已用签名仍然判 SIG_REPLAY，快照不能被后续操作污染；重放缓存有 max_replays 上限，超出时按先进先出淘汰最旧记录，不能无限增长。验收：python3 -m pytest -q tests 的 15 条测试必须全部通过；不得修改测试、跳过或按固定输入写死；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
