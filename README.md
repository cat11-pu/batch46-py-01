# GSB Bugfix Task

## 题面

核心转储采集端最近连续被安全审计打回：进程崩溃后抓到的环境变量里，数据库口令和接口密钥原样躺在归档里；同名但 kind 不同的字段被去重规则一起吞掉；PRIVATE_ 前缀的字段删掉后，剩余字段的顺序对不上；单个 dump 字段数超限时接口先写了一半才报错；同一份崩溃被采集器重投，计数翻倍；dump 号相同但内容不同的两批记录互相覆盖；租户配额只按全局算，一个租户把另一个挤掉；超长参数值在脱敏之前被截断，密钥片段仍能拼出来；快照文件里还能搜到明文；审计环形缓冲把关键拒绝记录冲掉。修复范围在模块 gsb/batch46-safety-e-07 的 coredump_redact_guard.py，类型 CoreDumpGuard，任务类型 Bugfix，只用 Python 标准库，失败统一抛 CoreDumpError，异常对象带 code 与 detail。

接口按骨架保持：register_rule(self, pattern: str, *, kind: str | None = None, action: str = "mask", replacement: str = "***") -> int、rules(self) -> list[dict]、process(self, dump_id: str, records: list[dict], *, tenant: str = "default") -> dict、get(self, dump_id: str, name: str, *, tenant: str = "default") -> dict、list_names(self, dump_id: str, *, tenant: str = "default") -> list[str]、purge(self, dump_id: str, *, tenant: str = "default") -> bool、usage(self, tenant: str = "default") -> dict、set_tenant_quota(self, tenant: str, limit: int) -> int、stats(self) -> dict、audit(self, limit: int | None = None) -> list[dict]、snapshot(self) -> str、restore(cls, data: str) -> "CoreDumpGuard"。

规则匹配字段名与 kind，pattern 用通配符；精确模式优先于通配符，同为通配符时更长的优先，仍然相同则后注册的优先。action 取 mask、hash、drop：mask 写入 replacement（默认 ***），hash 写入 sha256: 加前 16 位十六进制，drop 直接丢弃该字段并计入 dropped；模式为空、动作非法或规则数超过 max_rules 分别抛 CD_BAD_RULE、CD_RULE_LIMIT。process 校验每条记录的 name、value 为字符串、kind 属于 env、arg、mem、reg、file，否则抛 CD_BAD_RECORD；记录数超过 max_records 时在任何状态变化之前抛 CD_DUMP_TOO_LARGE。同一 dump 内按 (kind, name) 去重，保留第一条并累计 duplicates，list_names 按保留顺序返回，查不到的字段抛 CD_FIELD_UNKNOWN。

同一 tenant 下 dump_id 相同且规范化内容一致时，第二次提交返回 status 为 duplicate，kept 与 dropped 沿用首次结果，processed 不增、duplicates 加一；内容不同抛 CD_DUMP_ID_CONFLICT，原始记录不受影响。purge 成功后 usage 立即减少，usage 返回 dumps 与 limit，之后 get 抛 CD_UNKNOWN_DUMP，用同一 dump 重投只返回 status 为 purged 且不会复活数据，重复 purge 返回 False。不同 tenant 的相同 dump_id 互相独立，读、列名、卸载时必须带对 tenant，否则抛 CD_TENANT_MISMATCH。每个租户的存活 dump 数受 max_dumps_per_tenant 限制，超限抛 CD_TENANT_QUOTA，set_tenant_quota 可按租户覆盖上限，非法上限抛 CD_BAD_QUOTA。

值只在脱敏之后处理长度：没有命中规则的原始值超过 max_value_bytes 时截成前 max_value_bytes 个字符再加一个 …，mask 与 hash 的结果不再截断。process 返回 status、dump_id、tenant、digest、kept、dropped、duplicates，digest 为规范化内容的 64 位十六进制。stats 给出 processed、duplicates、rejected、purged；审计环形缓冲最多 audit_capacity 条，记录 action 与 code。snapshot 只保存规则、脱敏后的记录、租户配额、统计与审计，任何原始密钥都不得出现在快照文本里；restore 恢复后重复提交仍判 duplicate、purge 仍生效，坏数据抛 CD_SNAPSHOT_INVALID。

八个线程同时提交同一个 dump，只允许一个 processed、其余 duplicate；八个不同 dump 并发提交都要成功且 usage 计数准确。两千条记录在三条规则下完成脱敏要在三秒内。

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
