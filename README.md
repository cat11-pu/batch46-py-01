# GSB Bugfix Task

## 题面

区域出口上个月把 FlowSpec 引流从观察切到自动执行，三小时里骨干被打挂两次。客户侧路由器通告 0.0.0.0/0 的 discard，边界把全部上行流量丢掉；同一邻居重复通告同一条规则，表里堆了七百多条相同表项；同前缀两条不同优先级的规则实际生效的是低优先级那条；customer 把不属于自己的 /16 塞进来照样落表；redirect 下一跳写成公网地址，流量被整段引走；一条规则塞十二个组件让解析线程抛异常；端口范围写成 443-80 没人拦；运维按 rule_id 撤规则找不到只能重启；滚动重启后规则表清空；单对端一分钟推两千条规则把内存打满；被拉黑的对端仍能继续注入；TTL 到期的规则还在参与匹配。

范围是 gsb/batch46-safety-c-01 下的 bgp_flowspec_guard.py，类 FlowspecGuard，任务类型 Bugfix，负责对端注册、规则校验、冲突裁决、限速与快照。公开接口（Python 类型注解）：`FlowspecGuard(*, max_rules: int = 256, max_components: int = 8, rate_limit: int = 20, rate_window: int = 60, violation_threshold: int = 3, block_seconds: int = 300, allowed_next_hops: tuple = ())`；`register_peer(peer: str, *, role: str, asn: int, prefixes: tuple = ()) -> dict`；`ingest(rule: dict, *, peer: str, now: int | None = None) -> dict`；`ingest_batch(rules: list, *, peer: str, now: int | None = None) -> list`；`rules(*, peer: str | None = None, now: int | None = None) -> list`；`effective(destination: str, *, now: int | None = None) -> list`；`withdraw(rule_id: str) -> dict`；`stats(peer: str | None = None) -> dict`；`block_peer(peer: str, seconds: int, *, now: int | None = None) -> dict`；`release_peer(peer: str) -> dict`；`blocked(*, now: int | None = None) -> list`；`expire(now: int) -> list`；`snapshot() -> dict`；`restore(snapshot: dict) -> None`。注册类错误抛 FlowspecError(code, detail)，规则类问题用返回值表达。

故障与边界：一、role 只接受 edge/customer/upstream/untrusted，否则抛 FSP_BAD_ROLE；asn 不在 1 到 4294967295 之间抛 FSP_BAD_ASN；prefixes 非法抛 FSP_BAD_PREFIX；同一对端内容一致重复注册返回 status 为 unchanged，内容不同抛 FSP_PEER_CONFLICT；注册成功返回含 peer、role、asn、prefixes、status 的字典。二、ingest 返回 {"action","code","peer","rule_id","priority"}，action 取 accept、duplicate、rejected、rate_limited、blocked；成功 code 为 FSP_ACCEPTED，替换旧规则为 FSP_REPLACED。三、未注册对端返回 FSP_PEER_UNKNOWN；untrusted 与 upstream 一律 FSP_PEER_DENIED；customer 只能注入 owned 前缀本身或其子网，超网与外前缀返回 FSP_PREFIX_NOT_OWNED。四、destination 必填且可解析，缺失或类型不对返回 FSP_BAD_RULE，解析失败返回 FSP_BAD_PREFIX；IPv4 与 IPv6 都要支持。五、匹配组件只允许 destination/source/protocol/port/tcp_flags/packet_length/dscp/icmp_type，未知键返回 FSP_BAD_COMPONENT，总数超过 max_components 返回 FSP_TOO_MANY_COMPONENTS；端口倒序或越界返回 FSP_BAD_PORT_RANGE；protocol 越界与非法 tcp_flags 返回 FSP_BAD_RULE。六、action 只允许 discard/rate-limit/redirect；redirect 必须带 allowed_next_hops 内的 next_hop，缺失或多带返回 FSP_BAD_ACTION，不在白名单返回 FSP_NEXT_HOP_DENIED。七、同一对端归一化匹配完全相同的规则只留一条，第二次返回 duplicate + FSP_DUPLICATE，rule_id 相同且不重复计数；不同对端的相同规则各自成立且 rule_id 不同。八、同一匹配键按 priority 数值小者胜；新规则优先级更大或相等返回 rejected + FSP_CONFLICT，更小则替换旧规则并返回 FSP_REPLACED。九、规则数达到 max_rules 后新增匹配键返回 FSP_CAPACITY；替换已有匹配键不受上限影响。十、rate_window 秒内成功接纳超过 rate_limit 条后多出的返回 rate_limited + FSP_RATE_LIMIT；限速违规计入违规，窗口内违规达到 violation_threshold 立即封禁 block_seconds 秒，触发封禁的那条仍返回原结果，之后返回 blocked + FSP_PEER_BLOCKED，到期自动恢复；block_peer 直接封禁，release_peer 立即解封，blocked(now) 按字典序返回封禁中对端；stats 返回 accepted、rejected、rate_limited、duplicates、active、blocked，peer 为空时返回聚合值并附 peers 计数。十一、rules 每行含 rule_id、destination、priority、action、expires_at，按 (priority,destination,rule_id) 升序；effective 只返回覆盖该地址且未过期的规则，按前缀长度降序、priority 升序、rule_id 升序排列，跨地址族返回空列表；ttl 从注入时刻起算，expire(now) 删除 expires_at 小于等于 now 的规则并按 rule_id 升序返回。十二、withdraw 未知 rule_id 抛 FSP_UNKNOWN_RULE，成功后该匹配键可重新注入；snapshot 含 version、peers、rules、stats、blocked，version 为 1，覆盖对端、规则、计数与封禁截止时间，必须深拷贝；restore 校验版本与结构，非法抛 FSP_SNAPSHOT_CORRUPT 且原状态不变。

硬约束：ingest、ingest_batch、withdraw、expire 与 restore 全程持锁；并发注入下规则数不得超过 max_rules，accepted 必须等于成功落表次数，不能重复计数或丢计数；规则表、限速窗口与封禁表都有界，不随报文数量膨胀；快照恢复后的封禁继续生效，已过期的封禁不得复活。

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
