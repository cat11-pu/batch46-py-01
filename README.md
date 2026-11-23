# GSB Bugfix Task

## 题面

合规扫描报中危：脚本打开 httpd_can_network_connect 后重启复原，另一批开 httpd_use_nfs 中途失败。代码在模块 gsb/batch46-safety-e-02 的 selinux_bool_guard.go，类型 SelinuxGuard，任务类型 Bugfix，Config 的 MaxPending/MaxChanges 是硬上限。补齐 NewSelinuxGuard(cfg Config) *SelinuxGuard、NewSelinuxGuardFromSnapshot(cfg Config, data []byte) (*SelinuxGuard, error)、RegisterBool(name string, def bool) error、SetBool(name string, want bool, persistent bool) error、AddContext(spec ContextSpec) error、Apply() (Report, error)；BoolState/Report 的 Name、Value、Persistent、Revision、Bools、Contexts、Removed 要对。重复注册/空名 ErrBoolExists/ErrInvalidBoolName；未知开关 ErrUnknownBool；值/持久化一致时 SetBool 空操作；仅持久化需暂存；暂存超 MaxPending ErrCapReached；无变更 Apply ErrNothingToApply；超 MaxChanges ErrTooManyChanges，整批不生效、暂存留；Apply 成功让开关、全局 Revision 各加一，Bools 按名、Contexts 按路径序；路径须绝对干净 ErrInvalidPath；类型非 _t ErrInvalidContextType；同路径双标签 ErrConflict；User/Role 留空补 system_u/object_r；删未标路径 ErrNotFound；并发 Apply 只一个成功；Snapshot 只存持久化开关、标签、Revision，易失回默认。验收：go test ./... 15 条全过，不改测试/跳过/写死，并发/重启自验，只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 困难
