# GSB Bugfix Task

## 题面

安全代理上线后，部分进程打开配置卡十几秒再被拒；排查发现权限事件在内核排队，应答线程没按时回 verdict，超时后又补发一次，卸载的 mark 未清。代码在模块 gsb/batch46-safety-e-03 的 fanotify_permission_guard.go，类型 FanotifyGuard，任务类型 Bugfix，Config 的 ResponseTimeout、MaxMarks、MaxPending 必须生效。补齐 NewFanotifyGuard(cfg Config) *FanotifyGuard、NewFanotifyGuardFromSnapshot(cfg Config, data []byte) (*FanotifyGuard, error)、Begin(path string, op Op, now time.Time) (Event, error)、Respond(id EventID, d Decision, now time.Time) error、Unmark(id int) error、Snapshot() ([]byte, error)。mark 路径空/相对/未清理 ErrInvalidPath；mask 无权限位 ErrInvalidMask；重复 mark ErrAlreadyMarked；超 MaxMarks ErrCapReached；Unmark 未知 id/尚有事件 ErrUnknownMark/ErrBusy；Begin 无覆盖 mark/超 MaxPending ErrNoMark/ErrQueueFull；Respond 未知 id/非法 Decision/二次应答 ErrUnknownEvent/ErrInvalidDecision/ErrAlreadyAnswered，Decision 非法不消费事件；Deadline（含等于）后 Sweep 按拒绝并返回数，随后 Respond ErrExpired，再 Sweep 返回 0；Stats 准；同一事件并发应答只一个成功；Marks 按路径序；Snapshot 存 mark、计数、事件号游标，不留未应答事件，重启后旧号 ErrUnknownEvent。验收：go test ./... 15 条全过，不改测试/跳过/写死，并发/重启自验，只做本地实现。

## 运行方式

```bash
go test ./...
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 困难
