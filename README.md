# GSB Bugfix Task

## 题面

周一登录故障复盘会上，值班同学还原了经过：某支付服务通过 Vault AppRole 换取令牌，同一张 SecretID 在一分钟内被连续兑换三次，而它配置为一次性；有运维把凭证 TTL 写成 48 小时，超过挂载点 24 小时上限，挂载点也没有拦截；一台来自 192.168.1.5 的机器申请到了只允许 10.0.0.0/8 的凭证；被 response-wrap 的 SecretID 还没拆包就直接登录成功；已经撤销的凭证仍然能换到新令牌；跨角色拿到的 SecretID 也能登录另一个角色。这些问题叠加后，攻击者只要截获一张一次性凭证就能反复换取令牌，审计日志也无法区分正常重试和重放。请在模块 gsb/batch46-safety-b-01 的 vault_approle_guard.go 中修复类型 AppRoleGuard，任务类型 Bugfix，把凭证签发、包装、撤销、登录和快照恢复串成一条可信链路。

需要保持的接口：NewAppRoleGuard(cfg Config) *AppRoleGuard；NewAppRoleGuardFromSnapshot(cfg Config, data []byte) (*AppRoleGuard, error)；RegisterRole(p RolePolicy) error；IssueSecretID(roleID, cidr string, now time.Time) (SecretID, error)；WrapSecretID(accessor string, now time.Time) (string, error)；Login(req LoginRequest, now time.Time) (Token, error)；Snapshot() ([]byte, error)。

故障与边界：1) 注册角色时 SecretIDTTL 与 SecretIDUses 必须按 MaxSecretIDTTL、MaxSecretIDUses 截断，48h/50 次分别落到 24h/5 次，GetRole 读回来也必须是截断后的值；2) 同名角色重复注册返回 ErrRoleExists，BoundCIDRs 里出现非法网段返回 ErrInvalidPolicy，角色数超过 MaxRoles 返回 ErrTooManyRoles；3) 角色绑定 10.0.0.0/8 时给 192.168.1.5 签发凭证返回 ErrCIDRMismatch，角色没有绑定网段时不限制来源；4) 一个角色存活凭证数超过 MaxSecretIDsPerRole 返回 ErrTooManySecretIDs，签发出来的 SecretID 的 Value 与 Accessor 必须非空且互不相同；5) Login 必须按 Value 找到凭证，依次判定过期 ErrSecretIDExpired、仍在包装 ErrSecretIDWrapped、角色不符 ErrRoleMismatch、客户端地址与签发地址不一致 ErrCIDRMismatch、次数耗尽 ErrSecretIDExhausted，成功返回的 Token 要带 RoleID 和非空 Value，错误码必须彼此可区分，值班同学能直接判断是过期、包装、角色错误还是次数问题；6) 一次性凭证第一次登录成功后 UsesLeft 归零，多个请求并发登录只能有一个成功，其余必须得到次数耗尽；7) 已包装的凭证再次包装返回 ErrSecretIDWrapped，wrap token 只能拆一次，重复拆返回 ErrWrapTokenUsed，拆包后的 SecretID 的 Wrapped 必须为 false 且 Value 不变；8) 已撤销凭证登录返回 ErrSecretIDNotFound，撤销同时清掉指向它的 wrap token；9) Snapshot 保存角色策略、每个凭证的剩余次数、accessor 与 wrap token，重启恢复后已消耗的次数不得复活，CountSecretIDs 仍返回 1；10) 所有共享状态的读写必须在同一把锁内完成，不能出现两个并发登录都读到 UsesLeft=1 的窗口。

并发、重启恢复和凭证上限这三类约束都要真正落到代码里，不能只在串行路径上正确；快照只保存仍在有效期内的凭证和包装票据，过期数据不能无限增长。验收：go test ./... 的 15 条用例必须全部通过；不得修改测试、跳过用例或按固定输入写死；并发和重启场景要自行验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
