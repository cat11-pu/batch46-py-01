# GSB Bugfix Task

## 题面

文件网关接上 fanotify 做实时病毒拦截后，周一上午扫描器升级把整层目录都纳入了监控，权限事件在十分钟内堆到几千条，客户端打开共享盘一直转圈；运维紧急重启 daemon，内核把同一批 cookie 重新投递，同一次 open 被弹了两次审批；队列打满后新事件既没有拒绝也没有排队，实际文件却已经被放行。更严重的是两个工作线程同时回执同一个事件，allow 指标被扣了两次，事后追责时分不清是谁放行的。当晚客诉单翻了四倍，网关组要求先把回执、超时和队列做成可验证的状态机，再谈性能。代码在 gsb/batch46-safety-e-03 的 fanotify_permission_guard.py，FanotifyGuard 负责 mark 合并、权限事件排队、超时拒绝、cookie 去重、allowlist 与快照，任务类型 Bugfix。请按这些接口实现：

add_mark(self, path: str, mask: Sequence[str]) -> dict
remove_mark(self, path: str) -> dict
allowlist_add(self, path: str) -> dict
allowlist_remove(self, path: str) -> dict
submit_event(self, event_id: str, path: str, mask: str, *, pid: int | None = None, cookie: str | None = None, timeout: float | None = None, now: float = 0) -> dict
decide(self, event_id: str, decision: str, *, pid: int | None = None, reason: str | None = None, now: float | None = None) -> dict
expire(self, now: float) -> list[dict]
pending(self) -> list[dict]
status(self) -> dict
metrics(self) -> dict
close(self) -> dict
snapshot(self) -> dict
restore(self, snapshot: dict) -> dict

需要修正的行为：

1. add_mark 对同一路径重复下发相同 mask 返回 unchanged，新增 mask 合并后返回 updated 且 wd 不变；mask 为空或含未知位报 FAN_MASK_INVALID，相对路径报 FAN_PATH_INVALID。
2. mark 总数超过 max_marks 报 FAN_LIMIT，拒绝后 mark 表不变；remove_mark 未登记路径报 FAN_MARK_UNKNOWN。
3. 事件匹配按最长路径 mark 生效：父目录 mark 订阅 open_perm、子目录 mark 只订阅 access_perm 时，子目录下的 open_perm 必须报 FAN_MASK_UNWATCHED；删掉子 mark 后要回落到父 mark。
4. 未标记路径提交事件返回 FAN_NO_MARK 且不入队；重复 event_id 提交返回 FAN_EVENT_DUP，不能产生第二条待决记录。
5. 入队事件返回 status=pending，并带 deadline 与 seq；deadline 由 now 加上 timeout 得出，未给 timeout 用 default_timeout；pending() 按 seq 升序，队列长度受 max_pending 限制。
6. 队列已满时新事件直接返回 denied、decision=deny、code=FAN_QUEUE_FULL，既不排队也不挤掉已有事件。
7. decide 只能生效一次：重复回执返回 FAN_DECISION_DUP，并保持第一次的 decision 与 reason；未知事件报 FAN_EVENT_UNKNOWN，非法 decision 报 FAN_DECISION_INVALID，pid 与入队时不符报 FAN_PID_MISMATCH 且事件仍留在队列。
8. expire(now) 找出 deadline 已到的事件，按 deadline 升序批量置为 deny，code=FAN_TIMEOUT；过期事件再 decide 返回 FAN_EVENT_EXPIRED，不得改写结果或重复计数。
9. 带 cookie 的内核重投要合并到仍在 pending 的那条事件，返回 FAN_COOKIE_COALESCED 并带上原 event_id；已经决策过的事件不参与 cookie 合并。
10. allowlist 按路径前缀命中后直接返回 allowed、decision=allow、code=FAN_ALLOWLISTED，不占待决队列但计入 suppressed 与 allowed；移除未登记项报 FAN_ALLOWLIST_UNKNOWN。
11. metrics 至少维护 submitted、allowed、denied、coalesced、ignored、expired、queue_full、suppressed，重复回执和过期后的 decide 都不能重复累加。
12. close 之后 submit_event 与 decide 报 FAN_CLOSED；snapshot 保存 marks、allowlist、pending、decisions、metrics、seq 与 closed，restore 后待决事件和 cookie 索引都要能继续工作，非法快照报 FAN_SNAPSHOT_INVALID。

硬约束：多个线程同时 decide 同一个事件时只能有一个拿到 decided，其余全部 duplicate，allowed 计数只能加一；快照恢复视同 daemon 重启，待决事件、死线、cookie 和已决策记录必须完整带回；待决队列、mark 表和 allowlist 都是硬上限，满了就拒绝，不允许静默丢弃已有条目。

验收标准：在项目根执行 python3 -m pytest -q tests，15 条测试必须全部通过；不得修改测试、跳过或用固定输入写死结果；并发回执、超时与重启恢复请自行用线程和快照往返验证；只做本地实现，不接真实 fanotify fd。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 地狱
