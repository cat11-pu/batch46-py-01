# GSB Bugfix Task

## 题面

批量换 AppArmor 策略后三台 nginx 仍按旧规则跑，两台回滚后进程被踢。代码在模块 gsb/batch46-safety-e-01 的 apparmor_profile_guard.go，类型 AppArmorGuard，任务类型 Bugfix，Config 的 MaxProfiles、MaxRulesPerProfile、MaxAttachments、MaxHistory 要生效。补齐 NewAppArmorGuard(cfg Config) *AppArmorGuard、NewAppArmorGuardFromSnapshot(cfg Config, data []byte) (*AppArmorGuard, error)、Stage(p Profile) error、Commit(tenant, name string) (Profile, error)、Rollback(tenant, name string) (Profile, error)、Attach(tenant, name string, pid int) error。profile 名须带租户前缀 ErrInvalidName；Mode 仅收 enforce/complain ErrInvalidMode；重复规则/超额 ErrDuplicateRule/ErrTooManyRules；profile 超 MaxProfiles ErrCapReached；重复 Stage ErrStagedExists；无暂存 Commit ErrNotStaged；版本不递增 ErrVersionConflict；Commit 后旧版入历史、旧进程解绑、Generation+1；并发提交同一暂存只一个成功；Rollback 回退最近版、Generation+1，无历史 ErrNoHistory；重复 Attach/超 MaxAttachments ErrAlreadyAttached/ErrAttachCap，Attachments 升序；History 留最近 MaxHistory 条、Stats 的 History 准；Snapshot 跨重启恢复生效、暂存、历史、绑定，之后提交暂存要成功。验收：go test ./... 15 条全过，不改测试/跳过/写死，并发/重启自验，只本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 地狱
