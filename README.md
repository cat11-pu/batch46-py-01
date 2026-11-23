# GSB Bugfix Task

## 题面

虚拟化平台的值班工程师这两天被同一组 MSR 告警拖住：某批 vCPU 写 APIC_BASE 时被兜底拒绝规则误拦，另一批机器上标了掩码的 MSR 却把完整值原样落库；批量下发中间一条被拒，前面几条已经生效，回滚定位不到位置；运维重放同一批次号，计数和审计又加一遍；两个 VM 用相同 vCPU 编号时 MSR 值互相串；删除 vCPU 再重建，旧值原样回来；审计缓冲没有上限地涨；策略改过之后旧判定仍从缓存返回；宿主机重启恢复后批次台账丢失；VM 已经关闭，写接口还在收值。问题集中在模块 gsb/batch46-safety-e-06 的 kvm_msr_guard.py，类型 KvmMsrGuard，任务类型 Bugfix，只用 Python 标准库，失败统一抛 MsrGuardError，异常对象带 code 与 detail。

接口按骨架保持：define_policy(self, vm_id: str, rules: list[tuple[int, int, str, int | None]], *, default: str = "deny") -> int、policy_of(self, vm_id: str) -> dict、create_vcpu(self, vm_id: str, vcpu_id: int) -> dict、remove_vcpu(self, vm_id: str, vcpu_id: int) -> bool、check(self, vm_id: str, vcpu_id: int, index: int, value: int = 0, *, write: bool = True) -> dict、set_msr(self, vm_id: str, vcpu_id: int, index: int, value: int) -> dict、read_msr(self, vm_id: str, vcpu_id: int, index: int) -> int、apply_batch(self, vm_id: str, vcpu_id: int, accesses: list[dict], *, batch_id: str | None = None) -> dict、close_vm(self, vm_id: str) -> bool、cache_size(self, vm_id: str) -> int、stats(self, vm_id: str | None = None) -> dict、audit(self, limit: int | None = None) -> list[dict]、snapshot(self) -> str、restore(cls, data: str) -> "KvmMsrGuard"。

规则以 (start, end, action, mask) 定义，action 取 allow、deny、mask；单条索引精确命中的规则优先于任何范围规则，范围规则按定义顺序取第一条，都不命中才用 default；规则格式非法或条数超过 max_rules 分别抛 MSR_BAD_RULE、MSR_RULE_LIMIT。allow 原值通过，mask 在写入和读取时都做 value & mask，deny 抛 MSR_DENIED 且 detail 为索引；check 与 set_msr 返回 allowed、action、value，read_msr 直接返回值，读取未写过的索引返回 0。未定义策略的 VM 不能建 vCPU（MSR_NO_POLICY），重复 vCPU 为 MSR_VCPU_EXISTS，超过 max_vcpus 为 MSR_VCPU_LIMIT，未知 VM 为 MSR_VM_UNKNOWN，未知 vCPU 为 MSR_VCPU_UNKNOWN，索引越界为 MSR_BAD_INDEX。批量操作全有或全无：任一条被拒就抛 MSR_BATCH_REJECTED，detail 为失败位置，已写入的值不变，checks 与 allowed 不增加，只有 denied_batches 加一。同一 batch_id 且内容相同再次提交返回 status 为 duplicate、results 为空、duplicates 加一；内容不同抛 MSR_BATCH_CONFLICT；失败批次不能占用 batch_id，修好策略后可用同一批次号重试。批内按输入顺序执行，同索引后写覆盖先写，读访问返回当时已提交的值，results 每项含 index、allowed、action、value，顺序与输入一致。

不同 VM 的规则、vCPU 和值完全隔离；删除 vCPU 清掉值但统计与审计保留，重建后从零开始。审计环形缓冲最多 audit_capacity 条，stats 给出 checks、allowed、denied、batches、denied_batches、duplicates，传入 vm_id 时返回该 VM 的同一组计数，audit(limit) 只取最近 limit 条，审计行带 allowed 与 code（成功 MSR_OK、拒绝 MSR_DENIED）。判定缓存不超过 cache_capacity，define_policy 后必须立即失效；policy_of 返回 configured、default 与规则副本，cache_size 对未知 VM 抛 MSR_VM_UNKNOWN。close_vm 幂等，已关闭 VM 上建删 vCPU、读写 MSR、改策略、批量提交都抛 MSR_VM_CLOSED，但 snapshot 仍可用；对未知 VM 调用 close_vm 抛 MSR_VM_UNKNOWN，重复关闭返回 False。snapshot 生成可恢复 JSON，restore 还原规则、default、vCPU 值、关闭状态、batch 台账、统计与审计；恢复后缓存为空，旧批次仍判 duplicate；坏数据抛 MSR_SNAPSHOT_INVALID，恢复后的实例可以继续建 vCPU 并记账。八个线程各做 25 轮写后读，不得丢更新，最终值与每轮统计可逐条对上；缓存命中的两万次判定要在两秒内完成。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过或用固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 困难
