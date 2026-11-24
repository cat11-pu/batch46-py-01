# GSB Bugfix Task

## 题面

HR 系统通过 SCIM 向四个租户同步员工账号，上季度人员调整时同步链路出了一连串事故。增量事件乱序到达，版本一的旧记录把已经改好的职位覆盖回去；同一事件被上游重试两次，用户资料被写了两遍；版本号相同但内容不同的事件也照写；员工离职后账号删除，三个月后重新入职用同一个 user id 时新旧数据打架；删除的用户仍出现在全量列表里，下游又把权限发了一遍；一条 PATCH 里两个操作，前一个改成功、后一个路径不支持，结果脏数据留在库里；没带版本条件的 PATCH 覆盖了页面正在编辑的字段；批量补发里混进别家租户的记录，前半批已经写进去才发现；单租户用户数没有上限，测试租户一次灌了四十万条；两个租户用了相同的 user id，查询串到另一边；某客户 offboarding 之后残留用户仍能被搜到；进程重启后版本号和已处理事件列表全丢，重复事件又开始生效。

范围是 gsb/batch46-safety-a-04 下的 scim_provisioning_guard.py，类 ScimGuard，任务类型 Bugfix，负责租户登记、用户增量写入、PATCH、停用、批量补发与快照。公开接口（Python 类型注解）：`ScimGuard(*, max_users_per_tenant: int = 1000, max_batch: int = 200)`；`register_tenant(tenant: str, *, source: str, allowed_domains=()) -> dict`；`upsert(tenant: str, resource: dict) -> dict`；`patch(tenant: str, user_id: str, operations, *, expected_version=None) -> dict`；`deactivate(tenant: str, user_id: str, *, expected_version=None) -> dict`；`get(tenant: str, user_id: str) -> dict`；`list_users(tenant: str, *, include_deleted: bool = False) -> list`；`apply_batch(tenant: str, events) -> dict`；`is_applied(tenant: str, event_id: str) -> bool`；`purge_tenant(tenant: str) -> int`；`snapshot() -> dict`；`restore(state: dict) -> None`。所有失败抛 ScimError(code, detail)。

故障与边界：一、resource 必须带非空字符串 id、非空 userName 和大于等于一的整数 version，active 必须是布尔值，否则抛 SCIM_INVALID_RESOURCE，version 为 True 也按非法处理；二、未登记租户一律抛 SCIM_UNKNOWN_TENANT，重复登记 source 或 allowed_domains 不同抛 SCIM_CONFLICT，完全相同幂等；三、version 小于或等于已存版本返回 stale 与 SCIM_VERSION_STALE，不得改动数据，返回已存版本；四、event_id 命中已处理集合时优先返回 duplicate 与 SCIM_DUPLICATE_EVENT，即使版本更高也不再写入；五、PATCH 支持 add、replace、remove，path 仅限 userName、displayName、active、externalId，未知 op 抛 SCIM_UNSUPPORTED_OPERATION，未知 path 抛 SCIM_UNSUPPORTED_PATH，remove userName 或 active 抛 SCIM_REQUIRED_ATTRIBUTE，空操作列表抛 SCIM_INVALID_OPERATION；六、PATCH 必须整批原子，任一操作非法则整个调用不产生任何修改，成功时版本只加一；七、expected_version 与当前版本不一致抛 SCIM_VERSION_CONFLICT；八、deactivate 把 active 置 false 并留下 deleted 墓碑，版本加一，重复停用抛 SCIM_ALREADY_DELETED，墓碑不出现在默认列表、带 include_deleted 时可见，之后更高版本的 upsert 可以复活该用户；九、apply_batch 先整体校验租户归属与字段合法性，任一记录 tenant 与参数不一致抛 SCIM_TENANT_MISMATCH，任一字段非法抛 SCIM_INVALID_RESOURCE，两种情况都不能留下半批数据；十、apply_batch 按 version 升序应用，返回 applied、stale、duplicate、noop 计数与逐条 results，长度超过 max_batch 抛 SCIM_BATCH_TOO_LARGE；十一、get 返回 id、userName、displayName、active、version、deleted、externalId 七个字段，未知用户抛 SCIM_NOT_FOUND，已删除用户 PATCH 抛 SCIM_DELETED；十二、租户容量 max_users_per_tenant 把墓碑也算在内，purge_tenant 删除整个租户并返回用户数，之后访问该租户抛 SCIM_UNKNOWN_TENANT。

硬约束：PATCH 与 deactivate 在校验版本后必须在同一把锁内完成版本递增，八线程带同一个 expected_version 并发修改只能有一个成功；apply_batch 的预校验与排序应用必须保证原子校验，不能先写后报错；租户之间的用户表和事件去重表完全隔离，禁止跨租户读写；snapshot/restore 覆盖租户配置、用户记录、墓碑和已处理事件，恢复后重复事件仍被识别，结构非法抛 SCIM_SNAPSHOT_INVALID 且原状态不变。

验收：`python3 -m pytest -q tests` 的 15 条测试全部通过；不得修改测试、跳过或按固定输入写死；并发与重启恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- difficulty: 地狱
