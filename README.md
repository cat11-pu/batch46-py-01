# GSB Bugfix Task

## 题面

云网关联调时发现，封装网关会把带未知 critical 选项的 Geneve 报文当成普通流量放行，报文进了租户 VPC 后无人处理又原路丢弃，业务侧表现为持续几十秒的黑洞；同一批抓包里还有选项长度越界、同一个 class/type 重复出现、选项值超过规则上限却照收的情况。更麻烦的是 VNI 归属表没有租户校验，B 租户构造的 VNI 可以直接落到 A 租户的段里，两个租户的网关都以为自己才是合法入口。

请修复 gsb/batch46-safety-c-08 中 geneve_option_guard.go 的 GeneveGuard，任务类型 Bugfix，只改本地实现。

需要遵守的公开接口（签名不得改动）：

- NewGeneveGuard(policy Policy) *GeneveGuard
- NewGeneveGuardFromSnapshot(policy Policy, data []byte) (*GeneveGuard, error)
- (*GeneveGuard) ParseHeader(raw []byte) (Header, error)
- (*GeneveGuard) Validate(h Header, tenantID string) error
- (*GeneveGuard) RegisterVNI(vni int, tenantID string) error / UnregisterVNI(vni int) error / TenantForVNI(vni int) (string, error)
- (*GeneveGuard) RegisteredVNIs() []int / ProtocolAllowed(proto uint16) bool
- (*GeneveGuard) Snapshot() ([]byte, error) / Stats() Stats

具体现象与边界：

1. 版本字段只接受 0，出现 1、2、3 时在读取选项之前就返回 ErrVersion；解析结果要给出 Header.VNI 与 Header.Protocol，协议只支持 0x6558 和 0x0800。
2. 头部第二字节的 optlen 以 4 字节为单位，声明的选项区必须完整出现在报文里，短一字节就返回 ErrMalformed；optlen 上限按字段位宽处理，不能读越界。
3. 单个选项的 length 同样以 4 字节为单位，选项头加值必须按 4 字节对齐且不得越过声明区域，越界返回 ErrMalformed。
4. 选项 type 字节最高位是 critical 位，解析后 Option.Critical 单独给出，Option.Type 只保留低 7 位。
5. 同一个 class/type 在一个头里出现两次即返回 ErrDuplicateOption，判定只看 class 与低 7 位 type，无论两次的 critical 位是否相同。
6. 选项数量超过 MaxOptions 返回 ErrTooManyOptions；单个选项值超过 MaxValueBytes 返回 ErrOptionTooLong，即使它命中规则也不能豁免。
7. 规则里的 MaxValueBytes 可以比全局上限更严，命中规则后按更小的值判断，超限同样返回 ErrOptionTooLong。
8. 未知选项且 critical 为真返回 ErrCriticalOption；未知且非 critical 则跳过并累加 Stats 的 IgnoredOptions，本次校验仍算 Validated。
9. VNI 可用范围是 1 到 16777214，0、16777215、负数和超 24 位的值返回 ErrVNIRange，不能先登记再报错，失败时现有归属表不得改动。
10. Validate 时 VNI 未登记返回 ErrVNIUnknown，登记在别的租户名下返回 ErrTenantMismatch，只有归属租户可以通过。
11. 同一 VNI 被两个租户并发登记时只能有一个成功，失败方拿到 ErrVNIBound；快照恢复后 TenantForVNI 与 RegisteredVNIs 的升序结果要和恢复前一致，登记时间与计数不做保留要求。
12. 选项计数、值长度与 VNI 归属的检查要在同一把锁下完成，不能出现登记被撤销后仍按旧归属放行。

硬约束：选项数量与单值长度都有硬上限，解析器不能因为对端声明更大的长度就分配更多内存；VNI 登记是排他事务；快照恢复必须保留全部归属关系。

验收：go test ./... 的 15 条测试全部通过；不得修改测试、跳过或用固定输入写死结果；并发与恢复场景自行验证；只做本地实现，不涉及上游提交。

交付：修改后的源码与测试通过记录，附一段简要说明，讲清解析错误与策略拒绝各自使用的错误值。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
