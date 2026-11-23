# GSB Bugfix Task

## 题面

监控 agent 把 inotify watch 用满，日志大量 IN_IGNORED，之后新增目录加不上 watch，配额却显示空闲；另一次同一目录被两个采集任务订阅，内核出现两个 watch，一个被忽略后另一个也失效。代码在模块 gsb/batch46-safety-e-04 的 inotify_watch_guard.go，类型 InotifyGuard，任务类型 Bugfix，Config 的 MaxWatches/MaxPerRoot 是硬配额。请补齐 NewInotifyGuard(cfg Config) *InotifyGuard、NewInotifyGuardFromSnapshot(cfg Config, data []byte) (*InotifyGuard, error)、Add(path string, mask Mask) (int, error)、Remove(wd int) error、HandleIgnored(wd int) error、EvictRoot(root string) (int, error)，Watch 含 WD、Path、Mask、Refs。Add 只收绝对已清理路径 ErrInvalidPath；mask 0 ErrInvalidMask；同路径异 mask ErrMaskConflict；同路径同 mask 复用 wd 且 Refs+1；wd 超 MaxWatches ErrQuotaExceeded；同根超 MaxPerRoot ErrRootQuota；Lookup 先规范化，未订阅 ErrUnknownWatch；Remove 减引用、最后一个释放 wd，再删 ErrUnknownWatch；HandleIgnored 无视引用整条删除，重复调用 ErrUnknownWatch；EvictRoot 删 root 及子路径、返回数、按路径边界（/data/app 不碰 /data/application）并释放配额；多协程同时 Add 成功数恰为剩余配额，其余 ErrQuotaExceeded；Snapshot 跨重启恢复 wd、路径、mask、引用数，新 wd 须大于此前最大。验收：go test ./... 15 条全过，不改测试/跳过/写死，并发/重启自验，只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 困难
