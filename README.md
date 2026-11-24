# GSB Bugfix Task

## 题面

凌晨的告警是这样来的：三地机房的递归解析器把一批不属于委派区的 A 记录写进了共享缓存，内网门户随后被指到一台陌生地址，值班同学手动清缓存才恢复。复盘发现解析器对上游响应几乎不做校验，谁先回包谁就能改缓存，大小写、授权区、粘附记录全都没有管。这次修复落在 gsb/batch46-safety-d-06 的 dns_cache_poison_guard.py，DnsCacheGuard 要成为缓存写入口的唯一闸门，任务类型 Bugfix，公共调用方不许改。

需要落地的接口（签名与骨架一致）：define_zone(self, zone: str, *, parent: str = "") -> dict；register_query(self, qname: str, qtype: str, *, zone: str) -> dict；validate_response(self, response: dict) -> dict；lookup(self, qname: str, qtype: str) -> dict；expire(self, now=None) -> int；flush_zone(self, zone: str) -> int；trim(self) -> int；snapshot(self) -> dict；restore(self, state: dict) -> None；stats(self) -> dict；pending_count(self) -> int。

返回结构和统计键名固定下来：validate_response 返回 status、code、cached、dropped_glue、answers、additional；lookup 返回 hit、records、ttl；票据字段为 query_id、qname、qtype、zone、case_token；stats 至少包含 pending、cache_entries、accepted、rejected、dropped_glue、pending_evicted、evicted、replays。所有拒绝路径都要先记录拒绝计数再返回，不能因为提前 return 漏计；被淘汰的票据计入 pending_evicted，被容量淘汰的缓存条目计入 evicted，重复回包计入 replays，重启恢复后统计数值要与快照对上，不能从零开始。

具体故障与边界：一、出站查询只能在 define_zone 注册过的区内发起，未注册的区或区外域名按 DNS_UNKNOWN_ZONE、DNS_OUT_OF_BAILIWICK 拒绝；二、每张票据带一个大小写混排的 qname 令牌，回包 qname 必须逐字符匹配，否则 DNS_CASE_MISMATCH，令牌只能用一次，二次回包按 DNS_REPLAY 拒绝；三、答案和权威区记录的名字必须在查询所属区内，越界分别按 DNS_OUT_OF_BAILIWICK、DNS_AUTHORITY_ESCAPE 整包拒收，一条都不许入缓存；四、CNAME 目标落在区外按 DNS_CNAME_ESCAPE 拒收；五、附加区里区外的粘附记录只丢该条，计数进 dropped_glue，不能因此丢整包；六、同一 RRset 重复记录去重，TTL 取最小值，名字统一小写；七、TTL 超过 max_ttl 要截断，TTL 小于等于零的答案可以接受但不入缓存；八、票据数超过 max_pending 时淘汰最老的一张，被淘汰票据的回包按 DNS_UNKNOWN_QUERY 拒绝；九、缓存条目超过 max_entries 时优先淘汰最早到期的条目；十、lookup 命中返回剩余秒数，过期条目必须顺手删除；十一、flush_zone 只清该区及其子域，不能误伤平级区；十二、快照要能序列化，恢复后按绝对到期时间续算剩余 TTL，版本不符抛 DNS_SNAPSHOT_VERSION 且原缓存不受影响。

硬约束：validate_response 和 lookup 会被八个刷新线程同时调用，同一张票据并发回包只能有一个 accepted，其余必须是 DNS_REPLAY，计数不能重复；快照恢复要么整体成功要么整体不动，不允许半份状态；缓存和待查票据都有上限，任何路径都不能突破，也不存在绕过缓存的旁路。验收：python3 -m pytest -q tests 的 15 条测试全过，不得改测试、跳过或按固定输入写死，并发与重启场景自己造数据验证，只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
