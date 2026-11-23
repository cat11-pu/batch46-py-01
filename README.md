# GSB Bugfix Task

## 题面

周五凌晨，外网递归解析器被上游递来的记录带偏：值班同学在缓存里看到 bank.example.net 指向 203.0.113.9，而这条记录是 example.com 的权威应答塞进来的。最初怀疑上游被黑，把回包逐字段拆开才发现，入库时只看了记录名能不能解析，没看它是否属于回包的 zone，也不区分记录类型和 class，于是任何上游都能顺带把别家的 A 记录写进来，驻留一小时后才过期。更麻烦的是，一条越界记录混在正常应答里时，前面几条合法记录已经进了缓存，回滚只能靠人工逐条删，第二天同一批用户又解析到了错误地址。任务在 gsb/batch46-safety-d-06 中完成，实现文件 dns_cache_poison_guard.go，类型 DnsCacheGuard，任务类型 Bugfix。

需要保留的公开能力：

- NewDnsCacheGuard(cfg Config) *DnsCacheGuard
- NewDnsCacheGuardFromSnapshot(cfg Config, data []byte) (*DnsCacheGuard, error)
- (c *DnsCacheGuard) InBailiwick(zone, name string) bool
- (c *DnsCacheGuard) Insert(zone string, rr RR, now time.Time) error
- (c *DnsCacheGuard) InsertResponse(resp Response, now time.Time) (int, error)
- (c *DnsCacheGuard) Lookup(name string, qtype uint16, now time.Time) ([]RR, error)
- (c *DnsCacheGuard) Delete(name string) int
- (c *DnsCacheGuard) PurgeExpired(now time.Time) int
- (c *DnsCacheGuard) Len() int
- (c *DnsCacheGuard) Stats() Stats
- (c *DnsCacheGuard) Snapshot() ([]byte, error)

故障与边界：1) 记录 owner 不在回包 zone 内（包括 notexample.com 这种同后缀但非子域的写法，以及 zone 写成 corp.internal、owner 写成 example.com 的情况）必须返回 ErrBailiwick，且不能写入缓存；2) 一份应答里只要有一条越界记录，整份 Answers 都不许落库，返回的插入计数为 0，之前已经判过的合法记录也要一并回滚；3) TTL 为 0 的记录返回 ErrTTLZero，不能按最小 TTL 兜底；4) class 不是 IN 的记录返回 ErrBadClass；5) 正向 TTL 要夹在 MinTTL 与 MaxTTL 之间，上游给 2 秒和 86400 秒都要按配置收敛；6) 过期记录不能再被 Lookup 命中，此时返回 ErrNotFound 并计入 Misses，命中一次要计入 Hits；7) 名字比较忽略大小写，单个结尾点可有可无，同一 owner 的不同类型分别缓存，A 记录不能回答 AAAA 或 TXT 查询；8) MaxEntries 满了以后新 key 返回 ErrCacheFull，不允许为了腾位置淘汰仍在有效期内的记录，但过期 key 必须在写入前先被回收；9) NXDOMAIN 应答按 NegativeTTL 做负缓存，窗口内 Lookup 返回 ErrNXDomain，窗口后回到 ErrNotFound，负缓存不占用正向记录的 key；10) 被拒绝的写入要计入 Stats.Rejected，且不能留下半条记录；11) Delete 要删掉该名字下所有类型和负缓存条目并返回删除的 key 数，名字不存在时返回 0；12) 快照为空字节或内容损坏时，恢复函数返回 ErrCorruptSnapshot，不能返回一个半初始化的缓存。

硬约束：同一份应答的写入要么全部生效要么全部不生效，并发写同一批名字时缓存里只能留下一致结果，Len 与 Stats 的计数不能和实际 key 数对不上；Snapshot 必须带上每条记录的绝对过期时刻，重启恢复后剩余 TTL 从原截止时间继续算，不能重新起算，也不能把已经过期的记录带回来；PurgeExpired 返回清理条数并同步收缩 Len，正常 Lookup 不应因为清理而少返回仍然有效的记录。

验收：go test ./... 的 15 条用例全部通过；不得修改测试、跳过用例或按固定输入写死；并发与重启恢复需要自行验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 地狱
