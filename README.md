# GSB Bugfix Task

## 题面

投影卷令牌出过一次越权：一个 Pod 的令牌被同命名空间的另一个 Pod 拿去访问 Vault，节点迁移后旧令牌还在用，轮换出的新令牌生效了但旧令牌同时还能过，Pod 删掉之后令牌一直有效，申请的 TTL 也被随手写成几小时。代码在模块 gsb/batch46-safety-a-10 的 k8s_bound_token_guard.go，类型 BoundTokenGuard，任务类型 Bugfix。集群规模已经到几千个 Pod，节点每周都在滚动替换，令牌的生命周期比 Pod 短，轮换和删除必须同时生效；审计要求任何一条令牌都能追溯到唯一的 Pod UID 与节点。采集端会周期性检查剩余寿命，太晚触发轮换会直接把业务打断，太早又会产生大量无谓的签发。

接口：NewBoundTokenGuard(cfg Config) *BoundTokenGuard、NewBoundTokenGuardFromSnapshot(cfg Config, data []byte) (*BoundTokenGuard, error)、RegisterServiceAccount(namespace, name string) error、RegisterPod(b PodBinding) error、RequestToken(req TokenRequest, now time.Time) (Token, error)、Validate(c Claims, requiredAudience, nodeName string, now time.Time) error、NeedsRefresh(podUID string, now time.Time) (bool, error)、TokenFor(podUID string) (Token, error)、Rotate(podUID string, now time.Time) (Token, error)、RevokePod(podUID string) int、ActiveTokens() int、Prune(now time.Time) int、Snapshot() ([]byte, error)。

问题与边界：1）申请令牌要求 namespace、serviceAccount、audience、PodUID、PodName、NodeName 全部非空，否则 ErrMalformed；service account 未注册 ErrUnknownSA，注册类接口参数为空同样 ErrMalformed。2）绑定必须与注册的 Pod 完全一致（命名空间、Pod 名、节点），不一致 ErrBinding；重复注册同一绑定幂等，改绑到另一节点 ErrMalformed。3）audience 必须在 Audiences 里，否则 ErrAudience；校验时 requiredAudience 非空则必须出现在 claims.Audiences。4）TTL 小于 MinTTL 或大于 MaxTTL 返回 ErrLimit；每个 Pod 同时存活令牌数达到 MaxTokensPerPod 再申请 ErrLimit。5）令牌值与 JTI 相同，均为 64 位小写十六进制，每次签发唯一，ExpiresAt 等于 now 加 TTL。6）Validate 对签名无效 ErrSignature；Subject 必须是 system:serviceaccount:命名空间:名字，段数不对 ErrMalformed，账号未注册 ErrUnknownSA。7）时间上 now 晚于 exp 加 ClockSkew 返回 ErrExpired（正好等于边界仍有效），now 加 ClockSkew 早于 iat 返回 ErrNotYet。8）claims 的 PodUID、PodName、NodeName 必须与注册绑定一致，否则 ErrBinding；调用方给出 nodeName 且与 claims 不同也 ErrBinding，未给出则不校验节点。9）令牌被轮换、吊销或从未登记时 JTI 查不到，返回 ErrRevoked。10）Rotate 继承最新令牌的 TTL 与 audience，清掉该 Pod 全部旧令牌再签发一条，旧令牌立刻 ErrRevoked，ActiveTokens 保持 1；并发轮换后只能有一条令牌可校验，且各次返回值互不相同。11）RevokePod 删除该 Pod 全部令牌并返回数量，之后 RequestToken、TokenFor 返回 ErrRevoked，所有 claims 校验 ErrRevoked，重复吊销返回 0。12）NeedsRefresh 在 now 加 RefreshWindow 到达或超过 ExpiresAt 时为 true，未知 Pod 返回 ErrMalformed；TokenFor 返回最新令牌；Prune 删除过期令牌并返回数量，ActiveTokens 同步；Snapshot 保存账号、绑定、令牌与吊销位，重启后存活令牌仍可校验、被吊销 Pod 仍 ErrRevoked、Prune 仍生效；并发申请、轮换、校验必须安全。

硬约束：轮换与吊销必须原子，同一 Pod 任何时刻只保留一条可用令牌；被拒的申请不能留下令牌或计数；令牌、绑定与吊销记录受 TTL 与 Prune 约束。节点回收是常态，令牌的节点归属一旦变化就必须重新签发，绝不能沿用旧值，Pod 重建同样要换新的 UID；所有拒绝都要能落到具体字段，值班同学拿到一条错误就能判断是绑定、受众、时间还是吊销问题。

验收：go test ./... 的 15 条测试全部通过，不得修改测试、跳过或按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
