# GSB Bugfix Task

## 题面

上个月安全基线平台把一批生产机的 SELinux 布尔值从关闭批量改成开启，commit 走到一半报错，一部分 boolean 已经生效、另一部分还停在旧值，策略处于半开状态；紧接着文件上下文规则升级又出问题，/srv 下本该命中高优先级规则的目录落到了低优先级标签，审计报告整段缺失。更麻烦的是重启之后待提交队列、策略版本和 relabel 记录全部消失，回滚脚本只能靠猜，runtime 值与持久值也一直互相覆盖，persistent_value 从来没有单独保存过。对应位置是 gsb/batch46-safety-e-02 的 selinux_bool_guard.py，SelinuxGuard 负责布尔值声明与暂存、依赖校验、上下文规则解析、relabel 以及策略快照，任务类型 Bugfix。请按下面的接口补齐实现：

define_boolean(self, name: str, *, default: bool = False, persistent: bool = False, requires: tuple[str, bool] | None = None, description: str | None = None) -> dict
set_boolean(self, name: str, value: bool, *, persistent: bool = False) -> dict
get_boolean(self, name: str, *, persistent: bool = False) -> dict
pending_changes(self) -> list[dict]
commit(self, *, policy_version: int | None = None) -> dict
abort(self) -> dict
mode(self) -> str
set_mode(self, mode: str) -> dict
add_context_rule(self, path: str, context: str, *, priority: int = 100) -> dict
resolve_context(self, path: str) -> dict
relabel(self, path: str, context: str) -> dict
label_of(self, path: str) -> dict
snapshot(self) -> dict
restore(self, snapshot: dict) -> dict
audit(self, limit: int | None = None) -> list[dict]

需要修正的行为：

1. 重复声明同名 boolean 报 SELINUX_DUP_BOOLEAN；requires 指向未声明布尔报 SELINUX_UNKNOWN_BOOLEAN；requires 指向自身报 SELINUX_DEPENDENCY_CYCLE；default 非 bool 报 SELINUX_VALUE_INVALID。
2. set_boolean 遇到未声明名字报 SELINUX_UNKNOWN_BOOLEAN，值不是 bool 报 SELINUX_VALUE_INVALID，对非持久布尔传 persistent=True 报 SELINUX_NOT_PERSISTENT。
3. set_boolean 只写入暂存区：get_boolean 的 value 仍是已提交值，pending 字段显示待提交值，policy_version 不变；commit 之后 value 更新、pending 清空、版本加一。
4. 把值设回当前已提交值要取消该条暂存，返回 status=cancelled 且 pending 为空；对同一目标值重复 set 只保留一条暂存记录，返回 pending。
5. commit 必须原子校验依赖：child 为 True 而 requires 的前置不满足时整批拒绝，报 SELINUX_DEPENDENCY_UNMET，暂存和 policy_version 都保持原样；补齐前置后一次提交两条一起生效，版本只加一次。
6. commit 可以带上预期的 policy_version，与当前值不符报 SELINUX_POLICY_MISMATCH，且不消费暂存区。
7. abort 丢弃全部暂存、不推进 policy_version；get_boolean 对持久布尔要能单独读到 persistent_value。
8. disabled 模式下 set_boolean 与 commit 都报 SELINUX_DISABLED；还有暂存时切 disabled 报 SELINUX_BUSY；重复设置当前 mode 返回 unchanged，非法 mode 报 SELINUX_MODE_INVALID。
9. boolean 数量超过 max_booleans 报 SELINUX_LIMIT，拒绝后已声明集合不变。
10. 上下文解析先按 priority 取最高，再在同优先级内取最长路径前缀；同优先级、同长度但 context 不同报 SELINUX_CONTEXT_CONFLICT；完全没有匹配报 SELINUX_CONTEXT_UNKNOWN；返回里要带 path、context、priority、rule_path 和 matched 来源。
11. relabel 只能作用于能解析出规则的路径，否则报 SELINUX_CONTEXT_UNKNOWN；label_of 要区分 source=relabel 与 source=rule；上下文规则数量超过 max_context_rules 报 SELINUX_LIMIT。
12. snapshot 要深拷贝 boolean、暂存、规则、label、mode、policy_version 和审计；restore 后这些表整体回到快照时点，非法快照报 SELINUX_SNAPSHOT_INVALID 且当前状态不变。

硬约束：两个线程同时 commit 同一份暂存时，只能有一个返回 applied、另一个返回 empty，policy_version 只增加一次，所有读写都在同一把可重入锁内；快照恢复要能当作重启后的冷启动路径，把暂存和版本一起带回；audit 只保留最近 max_audit 条并按 seq 递增，规则表和布尔表都有硬上限。

验收标准：在项目根执行 python3 -m pytest -q tests，15 条测试必须全部通过；不得修改测试、跳过或用固定输入写死结果；并发提交和快照往返请自行用线程与 restore 验证；只做本地实现，不依赖真实 selinuxfs。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 困难
