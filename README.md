# GSB Bugfix Task

## 题面

支付网关的密钥服务上周做了两次演练，暴露出的问题比预想严重：一个会话连续输错三次 PIN 之后仍然能被正常登录，因为失败次数只记在本地变量里，请求一多就被盖掉；运维同学把会话关掉以后，旧的密钥句柄还在别的连接上继续做签名；轮换策略上线后客户端拿到的句柄 ID 居然和三天前的一模一样，审计根本分不清是哪一次会话在用；服务重启过一次，句柄计数从头开始，已经作废的句柄又变成了有效；还有客户端把关闭会话当成注销，结果会话计数和句柄预算都没有释放。密钥服务这边需要一个统一的会话与句柄管理组件：模块路径 gsb/batch46-safety-b-09，文件名 hsm_session_guard.go，类型名 HsmSessionGuard，任务类型 Bugfix。

需要补齐的公开接口（签名以骨架为准）：NewHsmSessionGuard(Config) *HsmSessionGuard；SetPIN(tenantID, pin string) error；ProvisionKey(KeyInfo) error；OpenSession(tenantID, sessionID string, now time.Time) error；Login(tenantID, sessionID, pin string, now time.Time) error；OpenKey(tenantID, sessionID, label string, now time.Time) (Handle, error)；Perform(tenantID, sessionID, handleID, op string, now time.Time) (OpResult, error)；CloseHandle(tenantID, sessionID, handleID string) error；CloseSession(tenantID, sessionID string) error；SessionOps(tenantID, sessionID string) (int, error)；Snapshot() ([]byte, error)；NewHsmSessionGuardFromSnapshot(Config, []byte) (*HsmSessionGuard, error)。

必须修掉的点和边界：

1. 会话未登录时做任何操作都返回 ErrNotLoggedIn，OpenKey 和 Perform 都一样；
2. 连续输错 PIN 达到 MaxLoginAttempts 后会话被锁定，之后即使输对也返回 ErrPINLocked；登录成功一次就把失败计数清零；
3. 同租户内会话 ID 重复打开返回 ErrDuplicateSession；关闭后的会话继续用 Perform、OpenKey、SessionOps 都返回 ErrSessionClosed；
4. 只有本会话打开的句柄能用：拿别的会话的句柄返回 ErrCrossSession，随机编造的句柄返回 ErrHandleInvalid；
5. 句柄超过 HandleTTL 返回 ErrHandleStale；达到 OpsPerRotation 次成功操作后自动轮换，旧句柄立刻失效并同样报 ErrHandleStale，OpResult 要带上新句柄 ID 和当前会话累计成功次数，Handle 至少带 ID、KeyLabel、TenantID、Epoch 和 IssuedAt；
6. 密钥按租户和标签注册，重复标签返回 ErrKeyDuplicate，字段不全返回 ErrKeyInvalid；不在密钥允许列表里的操作返回 ErrOpNotAllowed，失败的操作不占轮换次数也不增加会话计数；
7. 单会话同时打开的句柄数超过 MaxHandlesPerSession 返回 ErrHandleLimit，关闭句柄后可以再开；
8. 用别的租户的密钥标签打开句柄返回 ErrKeyUnknown；
9. SetPIN 遇到空租户或空 PIN 返回 ErrPINInvalid，允许随时轮换；未配置 PIN 的租户无法登录；
10. 会话 ID 在同一租户内唯一，不同租户可以使用相同 ID 且状态互不可见；Login 遇到不存在的会话报 ErrSessionUnknown，已关闭的会话报 ErrSessionClosed；
11. CloseHandle 只能关闭本会话的句柄，否则 ErrHandleInvalid；关闭之后再 Perform 或 CloseHandle 同样报 ErrHandleInvalid；
12. 快照只保留密钥、PIN、会话计数、锁定状态和句柄计数，登录状态与已打开句柄不恢复，恢复后必须重新 Login。

硬约束：同一个句柄上的并发操作必须串行化，轮换阈值只允许被满足一次，两个并发请求只能有一个成功；句柄 ID 全局单调、永不复用，重启后也不能和之前发出去的 ID 重复，旧句柄在重启后一律无效；轮换留下的失效句柄记录要按 TTL 清理，不能无限堆积。

验收：go test ./... 的 15 条用例必须全过，不许改测试、跳过或按固定输入写死；并发和重启场景自己跑过；只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
