# GSB Bugfix Task

## 题面

某高校数据中心接入层上个月把 IPv6 路由通告防护从观察模式切到生产，第二天开始整栋楼的 IPv6 出口随机中断。抓包发现是接入口收到了伪造的 RA，把默认路由指到一台学生机；防护策略只看报文类型不看跳数，hop_limit 为 64 的 RA 也放行；源地址是全局地址的 RA 照样收下；目的地址写成 ff02::2 也能过；一条 RA 里塞九个前缀直接把前缀表写爆；/48 的前缀被当成合法 SLAAC 前缀；preferred 大于 valid 的组合没人拦；valid 只有 300 秒的前缀反复刷新，终端地址一天掉线十几次；接入口下挂的路由器广告默认路由，交换机照单全收；前缀不在放行清单里也进了表；RA 洪泛时没有任何限速，CPU 被打到 100%；连续违规的端口一直在线，只能人工 shutdown。

范围是 gsb/batch46-safety-c-02 下的 ipv6_ra_guard.py，类 RaGuard，任务类型 Bugfix，负责端口角色、RA 校验、前缀表、限速与端口隔离。公开接口（Python 类型注解）：`RaGuard(*, rate_limit: int = 5, rate_window: int = 1, violation_threshold: int = 3, quarantine_seconds: int = 300)`；`configure_port(port: str, role: str, *, vlan: int = 1, allowed_prefixes: tuple = (), default_route: bool = False) -> dict`；`ingest(packet: dict) -> dict`；`ingest_batch(packets: list) -> list`；`port_stats(port: str) -> dict`；`violations(port: str | None = None) -> list`；`prefix_table(vlan: int) -> list`；`effective_prefixes(port: str, *, now: int | None = None) -> list`；`quarantine(port: str, seconds: int) -> dict`；`release_port(port: str) -> dict`；`expire(now: int) -> list`；`snapshot() -> dict`；`restore(snapshot: dict) -> None`。配置类错误抛 RaError(code, detail)，报文类问题通过返回值表达。

故障与边界：一、configure_port 的角色只接受 uplink/host/untrusted，其他抛 RA_BAD_ROLE；vlan 必须在 1 到 4094 之间，否则抛 RA_BAD_VLAN；allowed_prefixes 每项必须能解析为 IPv6 网络，否则抛 RA_BAD_PREFIX_CONFIG；同一端口重复配置完全一致时幂等返回，配置不同抛 RA_PORT_CONFLICT。二、ingest 返回 {"action", "code", "port"}，action 取 accept、drop、rate_limited、quarantined，成功时 code 为 RA_ACCEPTED。三、未登记端口返回 drop + RA_PORT_UNKNOWN；untrusted 端口丢弃全部邻居报文 RA_ROLE_DENIED；host 端口收到 RA 同样 RA_ROLE_DENIED，NS 与 NA 正常处理。四、所有报文跳数必须为 255，否则 drop + RA_HOP_LIMIT。五、RA 目的地址必须是 ff02::1，否则 RA_DST_INVALID；RA 与 NA 源地址必须在 fe80::/10，NS 源为 :: 时豁免，否则 RA_SRC_NOT_LINK_LOCAL。六、RA 的 router_lifetime 大于 0 时，端口未配置 default_route=True 就返回 RA_DEFAULT_ROUTE_DENIED；lifetime 为 0 的 RA 只更新前缀。七、一条 RA 携带超过 8 个前缀返回 RA_TOO_MANY_PREFIXES。八、逐前缀校验：长度必须为 64 否则 RA_PREFIX_LEN；preferred 不得大于 valid 否则 RA_LIFETIME_ORDER；valid 小于 600 返回 RA_LIFETIME_TOO_SHORT；不在 allowed_prefixes 覆盖范围内返回 RA_PREFIX_NOT_ALLOWED；任一失败整条 RA 不落表。九、同一端口 rate_window 秒内成功接纳的 RA 超过 rate_limit 条后，多出的返回 rate_limited + RA_RATE_LIMIT，其他端口不受影响。十、每个端口 60 秒窗口内累计违规达到 violation_threshold 时立即隔离 quarantine_seconds 秒，触发隔离的那条报文仍按原原因返回 drop，之后的报文返回 quarantined + RA_PORT_QUARANTINED；expire(now) 在隔离截止时间小于等于 now 时解除并按字典序返回端口列表。十一、前缀表按 vlan 隔离，只接受该 vlan 的 uplink 写入；同一前缀收到更短的 valid 不得缩短已有到期时间，该报文仍按 accept 返回，但对应前缀不更新并计入 ignored。十二、prefix_table(vlan) 按前缀数值排序，effective_prefixes(port, now) 只返回该端口所属 vlan 内未到期的前缀；snapshot 带 version=1，覆盖端口配置、前缀表、限速与违规计数、隔离截止时间，restore 校验版本与结构，非法抛 RA_SNAPSHOT_CORRUPT 且原状态不变。

硬约束：ingest 与 restore 全程持锁，同一端口并发灌包时限速计数和违规计数不得丢失或翻倍；前缀表每 vlan 最多 8 个前缀、限速窗口固定长度，不允许随报文数量无界增长；快照必须深拷贝，恢复后的隔离端口继续拒绝报文，已过期的隔离不得复活。

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
