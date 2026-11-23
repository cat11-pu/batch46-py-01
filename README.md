# GSB Bugfix Task

## 题面

数据中心的合规审计给了我们一张整改单：过去两个月里有 37 台机器上报的启动度量证明，其中若干份被原样重放了不止一次，还有两台在更换主板后依然用旧证明通过了校验，另有一台机器的固件被降级后证明照样被接受。现在的校验逻辑把证明当成一次性校验函数，既没有记录服务端下发的随机数，也没有把度量值和每台机器的基准策略核对，TPM 时钟是不是往前走更是没人管。整改要求我们重写校验组件：模块路径 gsb/batch46-safety-b-07，文件名 tpm_quote_guard.go，类型名 TpmQuoteGuard，任务类型 Bugfix。

骨架里的公开方法有：NewTpmQuoteGuard(Config) *TpmQuoteGuard；RegisterAK(AK) error；RevokeAK(tenantID, name string) error；SetPolicy(PCRPolicy) error；Policy(tenantID, nodeID string) (PCRPolicy, error)；IssueNonce(tenantID, nodeID string, now time.Time) (string, error)；Verify(Quote, time.Time) (Verdict, error)；LastVerdict(tenantID, nodeID string) (Verdict, error)；Evaluations() int；Snapshot() ([]byte, error)；NewTpmQuoteGuardFromSnapshot(Config, []byte) (*TpmQuoteGuard, error)。

现场必须逐条满足的行为：

1. 只有服务端为这台机器签发、且未超过 NonceTTL 的随机数才能用；同一个随机数第二次进来报 ErrNonceReplay；拿 A 机器的随机数给 B 机器用属于未知随机数 ErrNonceUnknown。
2. 证明里的度量值必须逐项等于 SetPolicy 里的基准值，缺项或少项都算 ErrPCRMismatch；一份证明携带的 PCR 条目数超过 MaxPCRsPerQuote 时按 ErrQuoteInvalid 拒绝，空摘要同样按结构错误处理。
3. 签名密钥按租户注册，重复注册同名密钥报 ErrAKDuplicate，吊销后报 ErrAKRevoked，且重新注册不能复活；用别的租户的密钥名来证明要报 ErrTenantMismatch 而不是未知密钥。
4. 证明签名校验失败报 ErrSignatureInvalid；AttestedAt 偏离当前时间超过 MaxQuoteAge 报 ErrQuoteStale，偏早和偏晚都算。
5. 每台机器的 TPM Clock 必须严格大于上一次通过校验时的值，倒退报 ErrClockRollback，与基线相等也算倒退。
6. 结构不完整（租户、节点、密钥名、随机数、时间戳缺失，或 PCR 为空）一律 ErrQuoteInvalid；尚未配置基准策略的节点报 ErrPolicyMissing。
7. 通过的证明返回 Verdict，带上节点、固件版本、Clock、实际核对的 PCR 数量和校验时刻；LastVerdict 能取回最近一次结果，没有结果时 ErrNoVerdict。
8. 被拒绝的证明不得消耗随机数、不得推进时钟基线、不得覆盖已有 Verdict，也不计入 Evaluations。
9. IssueNonce 遇到空租户或空节点返回 ErrQuoteInvalid；Policy 返回基准策略的副本，调用方改动副本不能影响已安装的策略。
10. 每通过一次校验 Evaluations 加一；快照恢复后继续累计，不清零。
11. 快照要带回 AK 及其吊销标记、基准策略、待用与已用随机数、每台机器的时钟基线和最近一次 Verdict，恢复后重放与时钟倒退继续被拦住。

硬约束：同一随机数的两个并发校验只能有一个成功，检查与标记必须落在同一个临界区内；随机数与已用表按 TTL 清理，不能让内存随节点数量和时间线性膨胀；快照必须自包含，恢复时不依赖任何外部状态。

验收：go test ./... 跑满 15 条且全部通过；不允许改测试、跳过用例或针对固定输入写死结果；并发与重启场景请在本地自行验证；改动只留在当前模块。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 困难
