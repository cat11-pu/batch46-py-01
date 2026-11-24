# GSB Bugfix Task

## 题面

授权服务器上了 PAR 之后，前端先把授权参数推到后台换 request_uri，压测当天暴露了一串问题。同一个 request_uri 被两个标签页并发兑换，两次都换出了授权码；凌晨发出的 request_uri 过了一小时仍能兑换；客户端把 redirect_uri 写成相似域名也能通过；公开客户端不传 code_challenge 照样拿到 request_uri，code_challenge_method 写 plain 也放行；scope 里塞了没申请过的 admin 也过；网关把重复参数拼成两份，后台按后一个值处理；单客户端挂起请求没有上限，脚本刷了十几万条把内存打满；另一个客户端拿着别人的 request_uri 来兑换，后台直接认了；进程重启后已经兑换过的 request_uri 重新可用；审批页只是预览一次，请求就被标记成已用；监控上 pushed 和 redeemed 对不上授权账单；客服还反馈有客户拿着两周前的授权链接反复重放，账单里冒出一批陌生 client_id，财务对账时才发现。

范围是 gsb/batch46-safety-a-03 下的 oauth_par_request_guard.py，类 ParGuard，任务类型 Bugfix，负责客户端登记、请求对象校验、request_uri 发放与一次性兑换。公开接口（Python 类型注解）：`ParGuard(*, request_ttl: float = 60.0, max_pending: int = 100, max_per_client: int = 10, clock=None)`；`register_client(client_id: str, *, redirect_uris, confidential: bool = True, allowed_scopes=(), require_pkce=None) -> dict`；`revoke_client(client_id: str) -> None`；`push(request: dict, *, now=None) -> dict`；`redeem(request_uri: str, *, client_id: str, now=None) -> dict`；`peek(request_uri: str) -> dict`；`quota(client_id: str) -> dict`；`purge(now=None) -> int`；`snapshot() -> dict`；`restore(state: dict) -> None`；`stats() -> dict`；`reset_stats() -> None`。校验失败统一抛 ParError(code, detail)。

故障与边界：一、push 返回的 request_uri 必须以 urn:ietf:params:oauth:request_uri: 开头，expires_in 等于 request_ttl；二、未登记客户端抛 PAR_UNKNOWN_CLIENT，重复登记内容不同抛 PAR_CONFLICT，内容相同幂等，撤销客户端后 push 抛 PAR_CLIENT_REVOKED，撤销未登记客户端抛 PAR_UNKNOWN_CLIENT；三、request 里 duplicates 非空视为重复参数，抛 PAR_DUPLICATE_PARAM；四、response_type 只接受 code，其余抛 PAR_UNSUPPORTED_RESPONSE_TYPE；五、redirect_uri 必须与登记的某个值逐字符相等，抛 PAR_REDIRECT_MISMATCH；六、公开客户端必须带 code_challenge 且 code_challenge_method 为 S256，缺 challenge 抛 PAR_PKCE_REQUIRED，带 challenge 但方法不是 S256 抛 PAR_PKCE_METHOD_UNSUPPORTED，机密客户端可通过 require_pkce=True 强制；七、scope 按空白切分去重排序，超出 allowed_scopes 抛 PAR_SCOPE_NOT_ALLOWED；八、挂起数达到 max_per_client 或总量达到 max_pending 抛 PAR_QUOTA_EXCEEDED，已过期请求不占额度；九、redeem 成功返回 redeemed、client_id、redirect_uri、scopes、state、code_challenge、code_challenge_method，第二次兑换抛 PAR_REQUEST_URI_USED；十、持有时间达到或超过 request_ttl 的 request_uri 抛 PAR_REQUEST_EXPIRED，purge 清理过期挂起与已用标记并返回条数，清理后再兑换抛 PAR_UNKNOWN_REQUEST_URI；十一、其他客户端兑换抛 PAR_CLIENT_MISMATCH，且该次失败不能消耗请求；十二、peek 只读元数据不消耗请求，snapshot/restore 覆盖客户端、撤销名单、挂起、已用标记与统计，结构非法抛 PAR_SNAPSHOT_INVALID 且原状态不变。

硬约束：redeem 全程加锁，多线程抢同一个 request_uri 只能成功一次，其余必须是 PAR_REQUEST_URI_USED；push 的额度判断和写入必须是一个原子步骤，不能超发；已用标记要保留到原请求过期，重启恢复后也不能重新兑换；挂起表和已用表都受 TTL 与容量约束，禁止无界增长；stats 的 pushed 与 redeemed 必须和实际成功次数一致，reset_stats 归零。

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
