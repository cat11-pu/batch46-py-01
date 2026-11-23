# GSB Bugfix Task

## 题面

存储网关的共享访问签名连续出问题：权限字符串顺序不同就被拒，下载链接过期后还能取文件，容器级签名被拿去读单个 blob，存储策略吊销后旧链接照样能用，IP 白名单形同虚设。代码在模块 gsb/batch46-safety-a-08 的 azure_sas_guard.go，类型 SasGuard，任务类型 Bugfix。这套网关同时服务三套环境，白天以读为主，夜里跑批量导入，签名有效期和策略吊销都会直接影响业务；上一轮临时改过一个排序函数，结果权限字符串一换顺序就全部被拒。运维还要求出问题时要能只看一条令牌就判断它属于哪个资源、哪种权限、受哪条策略约束。

接口：NewSasGuard(cfg Config) *SasGuard、NewSasGuardFromSnapshot(cfg Config, data []byte) (*SasGuard, error)、RegisterAccountKey(account string, key []byte) error、CanonicalPermissions(perms string) (string, error)、StringToSign(t Token, account, container, blob string) string、Mint(req MintRequest, now time.Time) (string, error)、Parse(raw string) (Token, error)、Validate(raw, account, container, blob, requiredPerm, sourceIP string, now time.Time) error、SetPolicy(container, policyID, perms string, start, expiry time.Time) error、RevokePolicy(container, policyID string) error、PolicyCount() int、PrunePolicies(now time.Time) int、Snapshot() ([]byte, error)。

问题与边界：1）权限只允许 r/a/c/w/d/l，去重后按 racwdl 输出；空串、未知字母、大写、空格都 ErrMalformed。2）Mint 返回按参数名排序的查询串 se、sp、spr、sr、ss、st、sv（有则 sip、si），最后追加 &sig=；值用大写十六进制百分号编码，RFC3339 的冒号成为 %3A，相同输入必须同串；账户未注册 ErrUnknownAccount，Parse 遇到缺字段或坏转义返回 ErrMalformed。3）StringToSign 固定十二行：账户、服务、资源、容器、blob、权限、开始、到期、协议、IP 范围、策略号、版本；开始或到期为空、IP 或策略号为空时用短横线，时间取 UTC RFC3339。4）版本必须是 2022-11-02，服务必须在 AllowedServices，资源只接受 b/c/d，协议必须正好是 https，否则 ErrMalformed。5）到期必须晚于开始，有效期不得超过 MaxLifetime（ErrLimit）；Mint 时已经过期 ErrExpired。6）blob 资源必须带 blob 名，容器或目录资源带 blob 名一律 ErrPermission。7）签名用账户密钥做 HMAC-SHA256 后 base64url 编码，签名被改返回 ErrSignature；资源形态检查在签名校验之前。8）now 晚于 expiry 加 ClockSkew 返回 ErrExpired（正好等于边界仍有效），now 加 ClockSkew 早于 start 返回 ErrNotYet。9）IP 范围支持单地址或起止区间，来源为空、非法或越界都 ErrIP，Mint 时区间写坏 ErrMalformed。10）requiredPerm 的每个字母都必须包含在令牌权限里，否则 ErrPermission。11）挂策略的令牌权限必须是策略权限子集（ErrPermission），到期不得晚于策略到期（ErrExpired）；策略被吊销后 Mint 与 Validate 都返回 ErrRevoked，未知策略 ErrMalformed，重复吊销不算错。12）Snapshot 保存策略及吊销位，重启后重新注册账户密钥，未吊销令牌仍有效、已吊销仍是 ErrRevoked；PrunePolicies 清掉吊销和过期策略并返回数量，PolicyCount 反映剩余；并发校验与并发吊销必须安全。

硬约束：策略读写在锁内完成，吊销必须立即可见且可重复调用；令牌与策略的存储规模受保留期约束，不能无界增长。签名串一旦算错，所有客户端会同时被拒，所以每个字段的含义和为空时的占位必须固定下来，不能随实现漂移；策略变更要平滑下发，已签发的令牌在吊销前继续可用，吊销后立刻失效，不允许出现半生效状态。

验收：go test ./... 的 15 条测试全部通过，不得修改测试、跳过或按固定输入写死；重启与并发场景自行验证；只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
