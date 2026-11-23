# GSB Bugfix Task

## 题面

会话服务上线本地加密令牌后，风控连续收到投诉：被登出的用户拿着旧 token 仍能访问账本接口，撤销表根本没有生效；前端重复调用撤销接口时返回 500，用户看到退出失败；签发侧也没有限速，一个脚本一分钟 mint 了数万枚 token，把密钥服务打满；一次密钥轮换后旧 key 被立即删除，尚未过期的 token 全部验不过；测试环境里把 token 中间几位改掉后居然也能通过。运维临时回滚了令牌版本才恢复，但代价是所有在线会话被强制重新登录，风控要求一周内补齐撤销与限速，而撤销量在高峰期骤增时服务内存也跟着上涨。请在模块 gsb/batch46-safety-b-04 的 paseto_v4_guard.go 中修复类型 PasetoGuard，任务类型 Bugfix，令牌格式固定为 v4.local.<kid>.<sealed>，加解密由注入的 Sealer 完成。

需要保持的接口：NewPasetoGuard(cfg Config, sealer Sealer) *PasetoGuard；NewPasetoGuardFromSnapshot(cfg Config, sealer Sealer, data []byte) (*PasetoGuard, error)；AddKey(k Key) error；RotateKey(k Key, now time.Time) error；Mint(c Claims, now time.Time) (string, error)；Verify(token string, now time.Time) (Claims, error)；Revoke(jti string, now time.Time) error；IsRevoked(jti string, now time.Time) (bool, error)；PruneRevoked(now time.Time) int；ActiveKey(now time.Time) (string, error)；Snapshot() ([]byte, error)。

故障与边界：1) Subject、Issuer、Audience、JTI 任一为空，或 ExpiresAt 不晚于 IssuedAt 时，Mint 返回 ErrInvalidClaims，空 JTI 不能绕过撤销表；2) issuer 与 audience 和配置不符分别返回 ErrIssuerMismatch、ErrAudienceMismatch；3) 有效期超过 MaxTTL 返回 ErrTokenLifetime，不做静默截断，过期时间由调用方提供，但服务端必须自己再判一次；4) 每个 MintWindow 最多 MintLimit 次，超限返回 ErrRateLimited，窗口滚动后恢复，限速按 guard 维度统计而不是按进程随意清零；5) Verify 要求 token 恰好四段且前缀为 v4.local，kid 未注册返回 ErrKeyNotFound，key 过了 RetireAt 返回 ErrKeyExpired，密文被改或无法解封返回 ErrInvalidToken，解析失败不能把原始密文当明文继续使用，解封失败一律按非法令牌处理，不能泄露内部错误；6) 过期返回 ErrTokenExpired，NotBefore 未到返回 ErrTokenNotYetValid，ClockSkew 内放行；7) RotateKey 让新 key 立即成为 ActiveKey，旧 key 停止签发但在 RetireAt 前仍能验旧 token，新 key 非法时旧 key 不得改动并返回 ErrKeyInvalid，轮换是原子操作，不能留下半新半旧的两套 key；8) Revoke 幂等，重复调用返回 nil，撤销后 Verify 返回 ErrRevoked，IsRevoked 返回 true，撤销记录超过 RevocationTTL 后由 PruneRevoked 清理，清理后同一 token 重新通过，记录要按 TTL 回收而不是永久占用内存，撤销只针对 jti，同一 subject 的其他令牌不受影响；9) 二十个并发 Mint 在 MintLimit=5 时只能成功 5 个，其余必须是 ErrRateLimited；10) Snapshot 保存 key、撤销表和当前窗口计数，重启后撤销仍生效，配额继续累计而不是清零，恢复后 KeyCount 保持为 1，ActiveKey 仍指向原来的签发密钥。

并发签发、重启恢复、撤销幂等和配额上限都要一起满足，不能只保证顺序调用的结果；解封失败与业务拒绝要能区分。验收：go test ./... 的 15 条用例必须全部通过；不得修改测试、跳过用例或按固定输入写死；并发、重启和轮换场景要自行验证；只做本地实现，不涉及上游提交。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
