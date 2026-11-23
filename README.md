# GSB Bugfix Task

## 题面

流水线升级后，删掉的文件又出现，.wh. 白障进镜像，opaque 缓存没清；重跑同层解包两遍。代码在模块 gsb/batch46-safety-e-05 的 overlayfs_whiteout_guard.go，类型 OverlayGuard，任务类型 Bugfix，Entry 有 Path/Kind/Size，Config 的 MaxLayers/MaxEntriesPerLayer 拦住超限。请补齐 NewOverlayGuard(cfg Config) *OverlayGuard、NewOverlayGuardFromSnapshot(cfg Config, data []byte) (*OverlayGuard, error)、AddLayer(layer Layer) error、Resolve(path string) (Resolved, error)、Plan(fromLayer int, toLayer int) ([]Op, error)、Orphans() []string，Op 的 Kind/Path。层号从 1 递增，倒序/重复/超 MaxLayers ErrLayerOrder/ErrDuplicateLayer/ErrTooManyLayers；单层超额 ErrTooManyEntries；层内重复 ErrDuplicateEntry；同层条目+白障 ErrWhiteoutConflict；opaque 非本层目录 ErrOpaqueWithoutDir；Resolve 取高层，白障删下层同名 ErrNotFound，高层再加后可见；opaque 目录只留本层及以上，下层子项不可见、目录自身保留；List 返回直接子项按路径序，缺失/非目录 ErrNotFound/ErrNotDir；Plan 先删后建、创建按路径序，坏区间 ErrInvalidRange；Orphans 返回无下层目标白障，升序；Stats 的 Layers/Visible/Whiteouts 准；Snapshot 跨重启恢复所有层、白障、opaque，已用层号不可加；并发同层号只一个成功，另一个 ErrDuplicateLayer。验收：go test ./... 15 条全过，不改测试/跳过/写死，并发/重启自验，只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 地狱
