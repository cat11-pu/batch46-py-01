# GSB Bugfix Task

## 题面

连锁零售的门店网关升级 IPv6 以后，收银台和电子价签每天下午集中掉线，重连后过几分钟又断。现场抓包看到网关的邻居缓存被一条伪造的邻居通告改写，收银台的 IPv6 地址指向了办公区一台笔记本；攻击脚本不需要先收到 NS，直接发不请自来的 NA 就能写缓存；收银机的静态绑定被动态条目顶掉，MAC 校验形同虚设；缓存条目只增不减，一台门店网关跑到四十多万条邻居记录，内存告警一周三次；同一个 MAC 在十分钟里认领几百个地址，缓存被单个终端占满；链路闪断后旧条目仍然显示可达，流量被黑洞；门店重启一次，静态绑定和当前缓存全丢，只能等 DHCPv6 重新下发；DAD 阶段的 NS 源地址是 ::，也被当成正常邻居学进缓存，攻击者用它提前占坑；stale 条目查询结果和可达条目一模一样，排障时根本分不清。

范围是 gsb/batch46-safety-c-03 下的 ndp_cache_guard.py，类 NdpGuard，任务类型 Bugfix，负责网口配置、静态绑定、请求票据、邻居学习、容量淘汰、老化与快照。构造签名 `NdpGuard(*, max_entries: int = 256, max_per_mac: int = 4, stale_after: int = 300, pending_ttl: int = 3, clock=None)`，clock 返回整数秒。公开接口（Python 类型注解）：`configure_iface(iface: str, *, max_entries: int | None = None, max_per_mac: int | None = None) -> dict`；`bind_static(iface: str, address: str, mac: str) -> dict`；`solicit(iface: str, address: str) -> dict`；`learn(packet: dict) -> dict`；`lookup(iface: str, address: str, *, now: int | None = None) -> dict`；`purge(now: int) -> list`；`link_change(iface: str) -> list`；`entries(iface: str | None = None) -> list`；`stats(iface: str | None = None) -> dict`；`violations(iface: str | None = None) -> list`；`snapshot() -> dict`；`restore(snapshot: dict) -> None`。配置与查询类错误抛 NdpError(code, detail)，报文类问题用 learn 的返回值表达。

故障与边界：一、configure_iface 登记网口并给出 per-iface 的 max_entries 与 max_per_mac，缺省继承构造参数；未登记网口参与学习返回 drop + NDP_IFACE_UNKNOWN；网口名称为空抛 NDP_BAD_IFACE。二、bind_static 要求地址是合法 IPv6、MAC 为六段十六进制，否则抛 NDP_BAD_ADDRESS 或 NDP_BAD_MAC；同一地址重复绑定相同 MAC 幂等，MAC 不同抛 NDP_STATIC_CONFLICT；静态条目不参与老化与淘汰。三、solicit 为指定地址登记待答票据并返回 status=pending 与 expires_at，重复 solicit 刷新票据；票据超过 pending_ttl 秒未答，learn 返回 NDP_PENDING_EXPIRED。四、learn 返回 {"action", "code", "iface", "address"}，action 取 accept 或 drop；校验顺序固定为先 MAC 与目标地址、再 solicited 与票据、最后绑定冲突与容量：MAC 或目标地址非法分别返回 NDP_BAD_MAC、NDP_BAD_TARGET，NA 不是 solicited=True 返回 NDP_UNSOLICITED_NA，没有票据返回 NDP_NO_PENDING。五、动态条目改 MAC 必须显式 override=True，否则返回 NDP_BINDING_CONFLICT 并保留原绑定；静态绑定任何情况下都不允许改写。六、NS 在 MAC 与目标地址校验之后先看源地址：为 :: 时按 DAD 处理，返回 accept + NDP_DAD 且不写缓存；其余 NS 源地址必须是 fe80::/10，合法时学习源地址绑定并返回 NDP_NS_LEARNED。七、单个 MAC 在全部网口上认领的地址数达到 max_per_mac 后，新地址返回 NDP_MAC_FLOOD。八、网口条目数达到 max_entries 时先淘汰 last_seen 最早的动态条目，淘汰计入 evicted；没有可淘汰的动态条目则返回 NDP_CACHE_FULL，静态条目不淘汰。九、lookup 在 now 与 last_seen 相差超过 stale_after 时返回 state=stale 并给出 age，静态条目 state=static；不存在的条目抛 NDP_NOT_FOUND。十、purge(now) 清理 stale 动态条目与过期票据，返回按字典序排序的 "网口/地址" 列表，票据只清理不进入返回列表；link_change(iface) 只清理该网口的动态条目与票据并返回地址列表，静态条目保留。十一、entries 按 (网口, 地址数值) 排序；stats 返回 received、accepted、dropped、evicted 与 by_code 计数；violations 按处理顺序记录每次丢弃的 code。十二、snapshot 带 version=1，覆盖网口配置、条目、票据、统计与违规记录；restore 校验版本、网口是否存在、地址唯一与 MAC 格式，非法抛 NDP_SNAPSHOT_CORRUPT 且原状态不变。

硬约束：learn、solicit、link_change、restore 全程持锁，同一地址并发收到多个 MAC 的 NA 时只能有一个成功绑定，其余全部冲突，缓存里不得出现两条同地址记录；缓存容量与单 MAC 地址数都是硬上限，不允许靠追加绕过；快照必须深拷贝并可 JSON 往返，恢复后静态绑定、stale 状态与计数保持一致。

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
