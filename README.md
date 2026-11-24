# GSB Bugfix Task

## 题面

容器防篡改 agent 最近在两百个节点上被用户投诉：给业务目录挂 inotify watch 时，配额只剩一半，agent 却按整棵目录树先挂后报错，留下半个子树，卸载脚本又找不到这些半挂的 wd；更奇怪的是删掉的 wd 很快被复用到新目录，旧进程的 IN_IGNORED 事件回来把新 watch 一起摘了；节点重启后 owner 配额计数和下一个 wd 归零，控制台显示的用量和内核实际值始终对不上。代码在 gsb/batch46-safety-e-04 的 inotify_watch_guard.py，InotifyGuard 负责 watch 注册与去重、wd 分配与回收、owner 配额、批量原子性、IN_IGNORED 处理与快照，任务类型 Bugfix。请按下面接口实现：

add_watch(self, path: str, mask: Sequence[str], *, owner: str = "root", is_dir: bool = False) -> dict
add_watch_batch(self, entries: Sequence[tuple[str, Sequence[str]]], *, owner: str = "root", is_dir: bool = False) -> dict
remove_watch(self, target: int | str, *, owner: str = "root") -> dict
move_watch(self, old_path: str, new_path: str, *, owner: str = "root") -> dict
watch_for(self, path: str, *, owner: str = "root") -> int
path_for(self, wd: int) -> str
event(self, wd: int, mask: str, *, name: str | None = None, cookie: str | None = None) -> dict
ignored(self, limit: int | None = None) -> list[dict]
stats(self) -> dict
set_limit(self, *, max_watches: int | None = None, max_per_owner: int | None = None) -> dict
snapshot(self) -> dict
restore(self, snapshot: dict) -> dict

需要修正的行为：

1. wd 从 1 开始单调分配，任何情况下都不复用旧号；删除后的 wd 进入 stale 集合，事件、按 wd 删除、path_for 命中 stale 都报 INOTIFY_WD_STALE，完全未知的 wd 报 INOTIFY_WD_UNKNOWN。
2. 同一 owner 对同一路径重复添加且 mask 相同返回 unchanged，wd 不变；追加新 mask 时合并并返回 updated；路径先按 normpath 归一，/a、/a/、/a/./b/.. 视为同一个 watch。
3. mask 为空或包含未知位报 INOTIFY_MASK_INVALID，相对路径报 INOTIFY_PATH_INVALID，空 owner 报 INOTIFY_OWNER_INVALID，且都不消耗 wd。
4. 全局 watch 数超过 max_watches 报 INOTIFY_QUOTA；单个 owner 超过 max_per_owner 报 INOTIFY_OWNER_QUOTA，后者的拒绝不能影响其他 owner。
5. add_watch_batch 必须先完整校验再落盘：任一 entry 非法、批内路径重复（INOTIFY_DUP_BATCH）或超出任一配额时整批回滚，watches、owner 计数和 next_wd 都保持原值，不能只挂上前面几条。
6. 成功批量添加按 entries 顺序分配连续 wd，返回 wds 列表和 new 计数；批内已存在的路径只做 mask 合并，不额外占用配额。
7. IN_IGNORED 事件要自动摘除 watch、释放 owner 配额并写入 ignored 历史（带自增 seq、wd、path、owner）；之后同一 wd 再收事件报 INOTIFY_WD_STALE，重新添加得到全新的 wd。
8. 目录 watch 收到带 name 的事件要把 name 拼到目录路径后；文件 watch 带 name 报 INOTIFY_NAME_INVALID；事件 mask 未被该 watch 订阅时返回 filtered，且不计入 delivered。
9. move_watch 保留原 wd，同时更新双向索引：旧路径查不到、新路径可查到该 wd，移动后目录事件仍能拼出正确子路径；目标路径已有 watch 报 INOTIFY_EXISTS，新旧路径相同返回 unchanged。
10. 同一路径由不同 owner 分别 watch 时各自独立分配 wd，删除其中一个不影响另一个，stats 的 owners 计数分别统计。
11. set_limit 把上限缩到低于当前用量时报 INOTIFY_QUOTA 且不修改上限，调大则立即返回新 limits，之后新增按新上限执行。
12. snapshot 保存 watches、by_path、owner_counts、next_wd、stale、ignored 历史、delivered 与 limits；restore 后配额用量、stale 判断和 wd 分配都要延续，非法快照报 INOTIFY_SNAPSHOT_INVALID 且当前状态不变。

硬约束：并发添加必须串行化配额判断，12 个线程用同一个 owner 抢 max_per_owner=4 时只能成功 4 个、其余 8 个报 INOTIFY_OWNER_QUOTA，最终 watches 与 owner 计数都恰好为 4，wd 不允许重复；批量操作要么全成要么全不成；快照要能当作进程重启后的恢复路径，把 wd 分配器和配额计数一起还原；ignored 历史只保留最近 max_ignored 条。

验收标准：在项目根执行 python3 -m pytest -q tests，15 条测试必须全部通过；不得修改测试、跳过或用固定输入写死结果；并发与快照恢复请自行构造线程和重启往返；只做本地实现，不依赖真实 inotify fd。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 困难
