# GSB Bugfix Task

## 题面

边缘网关最近把正常请求判成篡改、又把篡改请求放了过去：查询参数排序随遍历顺序乱跳，空格被编成加号，头名大小写不统一，同一个签名十分钟内能反复使用，预签名链接过期后仍能下载。问题集中在模块 gsb/batch46-safety-a-07 的 sigv4_canonical_guard.go，类型 SigV4Guard，任务类型 Bugfix。审计还要求所有被拒请求都能明确归因，不能把时钟问题报成签名问题。

需要补齐的接口：NewSigV4Guard(cfg Config) *SigV4Guard、NewSigV4GuardFromSnapshot(cfg Config, data []byte) (*SigV4Guard, error)、RegisterKey(id, secret, tenantID string) error、CanonicalQuery(rawQuery string) (string, error)、CanonicalURI(path string) (string, error)、CanonicalHeaders(headers map[string]string) (string, string, error)、CanonicalRequest(req Request) (string, error)、Sign(req Request, accessKeyID string, at time.Time) (string, error)、Verify(req Request, now time.Time) (string, error)、Presign(req Request, accessKeyID string, at time.Time, expires time.Duration) (string, error)、VerifyPresigned(method, rawURL string, now time.Time) error、ReplaySize() int、PruneReplay(now time.Time) int、Snapshot() ([]byte, error)。

故障与边界：1）规范查询串只保留 A-Za-z0-9-._~，其余按大写十六进制百分号编码，原始加号编成 %2B、空格编成 %20，已有 %2f 先解码再输出 %2F；按编码后的名、再按值升序，裸参数补等号，空段跳过，坏转义 ErrMalformed。2）规范路径空串为 "/"，必须以 "/" 开头，点段和反斜杠 ErrMalformed，逐段编码并保留空段。3）规范头名小写、值去首尾空白并把连续空白（含制表符）压成一个空格、Host 值转小写、按名排序；Authorization 不参与签名，缺 Host 返回 ErrMissingHeader，头数超过 MaxHeaders 返回 ErrLimit，大小写不同的重名头 ErrMalformed。4）规范请求把方法转大写，只接受 https 且必须有 Host；正文取小写十六进制 SHA-256，空正文为 e3b0c442 开头的那串固定值，各行严格按方法、路径、查询、头块、空行、签名头列表、载荷哈希排列。5）Sign 对未注册的 key 返回 ErrUnknownKey，输出形如 AWS4-HMAC-SHA256 Credential=编号/日期/us-east-1/服务/aws4_request, SignedHeaders=列表, Signature=64 位小写十六进制，同输入必须同输出。6）Verify 缺 Authorization 或 x-amz-date 返回 ErrMissingHeader；凭据段不是五段、结尾不是 aws4_request、region 或 service 与配置不符、日期与 x-amz-date 不一致返回 ErrMalformed；时间差超过 MaxSkew 返回 ErrClockSkew；签名头列表变了或 HMAC 不符返回 ErrSignature，未知 key 返回 ErrUnknownKey，成功时返回 access key id。7）同一签名在 ReplayTTL 内第二次出现返回 ErrReplay，并发校验只能有一个成功，ReplaySize 反映缓存条目，PruneReplay 只清过窗口的条目。8）Presign 的 expires 非正或超过 PresignLimit 返回 ErrLimit，参数按名排序后追加 &X-Amz-Signature=，签名头固定 host，载荷固定 UNSIGNED-PAYLOAD。9）VerifyPresigned 缺参数或算法不符 ErrMalformed，X-Amz-Expires 超上限 ErrLimit，now 晚于起始加有效期 ErrExpired（正好等于截止时刻仍有效），方法或路径被改返回 ErrSignature。10）重放、签名、时钟三类错误不能互相冒充。11）Snapshot 只保存已用签名集合，恢复后重新注册密钥，重启后同一签名仍要拦住。

硬约束：签名判定与重放登记必须原子，缓存按 TTL 清理且规模有界；并发与重启后的结果要一致。网关前面还有一层 CDN，请求头会被改写，签名校验必须以到达网关时的原始内容为准，不能依赖上游排序；预签名链接主要给外部合作方使用，过期和越权都必须当场拒绝，不能靠后端再兜底。

验收：go test ./... 的 15 条测试全部通过，不得修改测试、跳过或按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
