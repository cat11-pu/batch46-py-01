# GSB Bugfix Task

## 题面

办公网递归解析器换上新检测插件，第二天两类工单同时爆：公司 CDN 域名因子域带长哈希被误封，安全组却发现一台终端一天发二十多万条 TXT 查询、插件零告警。日志显示，白名单 good.com 把 notgood.com 和 good.com.evil.net 一起放过；超长 base32 子域只在首个标签超过 30 字符时告警；同域名重复查询把唯一子域计数刷过阈值，正常业务被误杀；滑动窗口不按时间淘汰，昨天的查询今天还在算分；被封客户端换一个大小写不同的域名继续查；封禁写错后永不解封；截断响应和 SERVFAIL 也被计入统计；告警列表跑一天吃掉两 G 内存；乱序补发日志导致窗口前后算错；进程重启后白名单与封禁全部丢失；查询没见过的客户端直接抛 KeyError。

范围是 gsb/batch46-safety-d-03 下的 dns_tunnel_guard.py，类 DnsTunnelGuard，任务类型 Bugfix，负责白名单、按客户端的滑动窗口特征、打分、封禁与快照。公开接口（Python 类型注解）：`DnsTunnelGuard(*, window: int = 60, unique_threshold: int = 20, label_threshold: int = 30, max_events: int = 500, block_seconds: int = 300, max_alerts: int = 200, public_suffixes: tuple = DEFAULT_SUFFIXES)`；`allow_domain(domain: str, *, note: str = "") -> dict`；`revoke_domain(domain: str) -> None`；`base_domain(qname: str) -> str`；`ingest(event: dict, *, now: int | None = None) -> dict`；`ingest_batch(events: list, *, now: int | None = None) -> list`；`client_state(client: str, *, now: int | None = None) -> dict`；`alerts(*, client: str | None = None, limit: int | None = None) -> list`；`block_client(client: str, seconds: int, *, now: int | None = None) -> dict`；`unblock_client(client: str) -> dict`；`blocked(*, now: int | None = None) -> list`；`expire(now: int) -> list`；`snapshot() -> dict`；`restore(snapshot: dict) -> None`。配置与入参错误抛 DnsTunnelError(code, detail)，单条事件问题用返回值表达。

故障与边界：一、allow_domain 先转小写并去掉末尾点，非法域名抛 DNS_BAD_DOMAIN，首次返回含 domain、note、status 的字典，status 为 allowed，重复添加返回 unchanged；revoke_domain 撤销不存在的域名抛 DNS_UNKNOWN_DOMAIN。二、白名单按标签边界匹配，qname 等于域名或以 “.” 加域名结尾才算命中，返回 allow + DNS_ALLOWLISTED、score 为 0、reasons 为空且不写入窗口；notgood.com 与 good.com.evil.net 不算命中。三、ingest 的 client 必须非空，否则抛 DNS_BAD_CLIENT；qname 归一化为小写去尾点后必须至少两个标签、总长不超过 253、每个标签 1 到 63 字符、只含字母数字下划线和连字符，否则返回 drop + DNS_BAD_QNAME、score 为 0 且不建客户端状态；base_domain 用 public_suffixes 做最长后缀匹配，a.b.example.co.uk 得到 example.co.uk，没有命中时退化为最后两个标签。四、打分固定四项：任一标签长度超过 label_threshold 记 LONG_LABEL 加 40；qtype 为 TXT 或 NULL 记 SUSPICIOUS_QTYPE 加 25；同一客户端同一 base_domain 在窗口内唯一 qname 数达到 unique_threshold 记 HIGH_UNIQUE 加 25；size 大于等于 400 记 LARGE_RESPONSE 加 10；总分封顶 100，reasons 按此固定顺序输出。五、唯一 qname 按归一化完整域名去重，重复查询只算一个；统计按客户端加 base_domain 隔离。六、窗口以当前事件 now 为基准，ts 小于等于 now 减 window 的事件先淘汰再打分；max_events 是每个客户端保留上限，超出丢最旧；client_state 返回 events、unique、base_domains、recent、blocked_until，recent 按时间升序给 qname，未见过的客户端返回全零状态而不是抛异常。七、总分达到 80 返回 block + DNS_BLOCKED 并封禁 block_seconds 秒，达到 40 返回 alert + DNS_ALERT，其余返回 allow + DNS_ALLOWED；触发封禁的事件仍按打分记录。八、封禁中的客户端直接返回 block + DNS_CLIENT_BLOCKED、score 为 0，不再解析 qname；封禁截止时间小于等于 now 时自动解除，blocked(now) 按字典序返回封禁中客户端。九、block_client 的 seconds 必须大于 0，否则抛 DNS_BAD_BLOCK，返回 {"client","until","status"}；unblock_client 解封并返回 status 为 unblocked；expire(now) 清理并返回到期客户端列表，按字典序排列。十、rcode 不为 0 返回 allow + DNS_RCODE_IGNORED，truncated 为真返回 allow + DNS_TRUNCATED，两者都不写入窗口；ingest_batch 忽略传入顺序，按 ts 升序逐条处理并返回同序结果。十一、告警记录含 client、qname、score、reasons、ts、action，按发生顺序追加，超过 max_alerts 丢最旧；alerts(client) 只返回该客户端，limit 取最近 limit 条但仍按时间升序。十二、snapshot 带 version=1，覆盖白名单、每个客户端的窗口事件与封禁截止时间、告警列表，必须深拷贝；restore 校验版本与字段类型，非法抛 DNS_SNAPSHOT_CORRUPT 且原状态不变。

硬约束：ingest、ingest_batch、expire、block_client 与 restore 全程持锁；多线程并发写同一客户端时事件数不得超过 max_events，unique 不能重复或丢失；每个客户端的窗口与告警列表分别受 max_events 和 max_alerts 约束，不随查询量线性膨胀；快照恢复后封禁客户端继续被拦，已到期封禁不得复活。

验收：`python3 -m pytest -q tests` 的 15 条测试全部通过；不得修改测试、跳过或按固定输入写死；并发与重启恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
