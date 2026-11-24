# GSB Bugfix Task

## 题面

夜间割接后，运维在边界路由器上启用了新写的标签栈校验，结果多个车队的专线同时出现转发环路和标签误配。复现发现：显式空标签被压到栈中间时设备照样接受；超过 20 位的标签值被截断后当成另一个标签下发；某个租户把栈压到十二层，转发表直接被打爆；还有一批标签落在别的租户号段里却通过了校验。更麻烦的是，同一台设备重启后从快照恢复，旧会话的标签栈和租户号段配置对不上，新的压栈请求被当成合法流量放行。修复范围：模块路径 gsb/batch46-safety-d-01，文件 mpls_label_guard.py，类 MplsGuard，任务类型 Bugfix，异常类 MplsError 携带 code 字段。

接口：MplsGuard(*, max_depth: int = 8, max_sessions: int = 64)、register_tenant(tenant: str, *, label_min: int = 16, label_max: int = 1048575, max_depth: int | None = None) -> dict、validate_stack(tenant: str, labels: Sequence[int]) -> dict、push(tenant: str, session: str, label: int, *, token: str | None = None) -> dict、pop(tenant: str, session: str, count: int = 1) -> dict、swap_top(tenant: str, session: str, label: int) -> dict、read_stack(tenant: str, session: str) -> list[int]、close_session(tenant: str, session: str) -> bool、audit(tenant: str | None = None, limit: int = 100) -> list[dict]、snapshot() -> dict、restore(payload: Mapping[str, object]) -> dict、metrics() -> dict。

故障与边界：一、0 和 3 两个空标签只允许出现在栈底（labels[-1]），出现在其他位置按 MPLS_RESERVED_POSITION 拒绝；1、2、4 至 6、8 至 15 一律按 MPLS_RESERVED_LABEL 拒绝。二、熵标签 7 只能紧贴栈底上方（labels[-2]），深度不足或位置不对按 MPLS_ENTROPY_POSITION 拒绝。三、标签必须是 0 到 1048575 的整数，越界或传 bool、字符串按 MPLS_LABEL_RANGE 拒绝，空栈按 MPLS_STACK_EMPTY。四、默认深度上限 8，租户注册时可覆盖；超限按 MPLS_DEPTH_EXCEEDED。五、租户号段默认 16 到 1048575，超出已注册号段按 MPLS_TENANT_RANGE；重复注册同一租户按 MPLS_TENANT_EXISTS，非法号段同样拒绝。六、push 后必须对整条栈重新校验，例如先压 3 再压 16 会因空标签不在栈底而失败，且失败时栈不变。七、pop 的 count 小于 1 按 MPLS_BAD_COUNT，大于当前深度按 MPLS_UNDERFLOW，返回的 removed 按栈顶到栈底顺序；swap_top 空栈按 MPLS_UNDERFLOW，替换失败时原栈保持。八、push 可带 token，同一会话内重复 token 返回 status 为 duplicate、code 为 MPLS_DUP_TOKEN，不增加深度也不计入 pushes。九、并发创建最多 max_sessions 个会话，超出按 MPLS_SESSION_LIMIT；close_session 对存在会话返回 True，重复关闭返回 False，之后读栈按 MPLS_SESSION_MISSING；会话号与租户名都按字符串精确匹配，大小写不同视为不同会话。十、所有拒绝写审计，audit 按时间倒序返回，limit 必须在 1 到 1000，否则 MPLS_BAD_LIMIT；审计最多保留最近 500 条，只记录拒绝，不记录成功压栈，避免日志被正常流量淹没。十一、snapshot 覆盖租户配置、各会话标签栈、已用 token 和计数器；restore 必须原子，非法版本或结构按 MPLS_SNAPSHOT_INVALID 且原状态不变。十二、metrics 返回 pushes、pops、rejects、sessions、max_depth_seen，深度水位只升不降。

硬约束：所有读写在同一把可重入锁内完成，多线程对同一会话连续 push 不得丢标签，计数必须等于实际成功次数；快照恢复后继续 push/pop、租户号段和审计行为与恢复前一致。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得改测试、不得跳过、不得按固定输入写死。并发与重启场景自行验证；只做本地实现，不涉及其他目录。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
