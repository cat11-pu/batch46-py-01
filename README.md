# GSB Bugfix Task

## 题面

集团把四个子公司的目录接到统一 LDAP 网关，跨域搜索改走 referral 之后，故障集中在下午的权限核查时段。一条 referral 指向未登记的第三方目录，网关照样带着服务账号口令去连；两个域互相引用，搜索在两边来回弹，连接池十分钟被打空；同一台主机写成大写或省略默认端口，环路检测就认不出来；referral 链一路追到第七层，请求超时前还在往下钻；某台 referral 主机只允许匿名绑定，网关却把 bind 凭据转了过去；入口域和 referral 域返回同一个 DN，结果里出现两条同名用户；单次搜索返回几十万条，网关内存直接顶满；批量核查跑到一半超出时间预算，整个请求报错，前面抓到的结果全丢；其中一台 referral 服务器连不上，整次搜索跟着失败；快照恢复后无法从上次中断的 referral 队列继续；两个相同查询并发进来，各自把整棵 referral 树爬了一遍；运维拉黑某台目录后，referral 仍然能绕过去。

范围是 gsb/batch46-safety-a-05 下的 ldap_referral_guard.py，类 LdapReferralGuard，任务类型 Bugfix，负责主机白名单、URL 规范化、referral 跟随、预算控制与快照。公开接口（Python 类型注解）：`LdapReferralGuard(*, max_hops: int = 3, deadline_seconds: float = 5.0, max_entries: int = 100, clock=None)`；`allow_host(host: str, *, allow_auth: bool = True) -> dict`；`revoke_host(host: str) -> None`；`validate_url(url: str) -> str`；`search(base_url: str, *, dn: str, scope: str = "sub", filter: str = "(objectClass=*)", resolver, bind_dn: str | None = None, now=None) -> dict`；`resume(continuation: dict, *, resolver, bind_dn: str | None = None, now=None) -> dict`；`continuation() -> dict | None`；`visited() -> list`；`budget() -> dict`；`snapshot() -> dict`；`restore(state: dict) -> None`；`stats() -> dict`；`reset_stats() -> None`。所有失败抛 LdapError(code, detail)，resolver 的签名固定为 resolver(url, dn, scope, filter, bind_dn)，返回 {"entries": [...], "referrals": [...]}。

故障与边界：一、URL 只接受 ldap 与 ldaps，主机不能为空也不能带用户信息，端口必须是 1 到 65535 的数字，非法输入抛 LDAP_INVALID_URL；二、validate_url 返回 scheme://host:port/dn 形式的规范串，host 与 dn 统一小写，ldap 缺省端口 389、ldaps 缺省 636，同一主机的大小写和省略端口写法必须判成同一条 URL；三、入口主机未登记或已撤销抛 LDAP_HOST_NOT_ALLOWED，同一主机重复登记但 allow_auth 不同抛 LDAP_CONFLICT，撤销未登记主机抛 LDAP_UNKNOWN_HOST；四、入口带 bind_dn 而该主机 allow_auth 为 false 抛 LDAP_AUTH_NOT_ALLOWED，referral 遇到同样情况只跳过该分支并记 LDAP_AUTH_NOT_ALLOWED，不把凭据发给目标；五、referral 主机未登记或已撤销跳过并记 LDAP_REFERRAL_BLOCKED，URL 解析失败记 LDAP_INVALID_REFERRAL；六、每个 referral 的深度从入口的零开始累加，深度超过 max_hops 记 LDAP_HOP_LIMIT，不再入队；七、同一规范 URL 在一次搜索里只解析一次，重复出现记 LDAP_REFERRAL_LOOP，包括入口被 referral 指回自身；八、条目按 DN 去重并保持首次出现顺序，每条结果输出 dn 与来源 url；九、总条目数达到 max_entries 时立即停止，status 为 partial、continuation 为 None，并记 LDAP_ENTRY_BUDGET；十、每次解析前检查时间预算，超出后返回 partial 与 continuation，continuation 里带剩余队列、已抓条目、已访问 URL 和跳过记录，resume 继续跑并返回累计结果；十一、resolver 抛异常只把当前分支记为 LDAP_REFERRAL_FAILED，其他分支照常处理；十二、continuation 结构非法抛 LDAP_CONTINUATION_INVALID，snapshot/restore 覆盖主机白名单、撤销名单、统计、最近 continuation 与 visited，结构非法抛 LDAP_SNAPSHOT_INVALID 且原状态不变。

硬约束：同一组参数的并发 search 只能真正遍历一次，其余线程直接拿到同一份结果，不允许每个线程各爬一遍 referral 树；visited、跳过列表和状态变更要在线程安全的前提下维护；单次运行受 max_hops、deadline_seconds、max_entries 三重预算约束，任何一重都不能被绕过；continuation 必须能在新实例恢复后继续，且恢复后不能重复解析已访问 URL；stats 的 searches、resumes、completed、partials、followed、skipped、entries 必须与行为一致，reset_stats 归零。

验收：`python3 -m pytest -q tests` 的 15 条测试全部通过；不得修改测试、跳过或按固定输入写死；并发与重启恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
