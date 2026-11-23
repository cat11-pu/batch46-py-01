# GSB Bugfix Task

## 题面

拖动窗口边缘时整个画面卡住：每收到一次尺寸变化就重建交换链，一秒钟重建上百次；旧交换链在图像仍被呈现引擎持有时被销毁，驱动直接设备丢失；最小化后仍往零尺寸表面提交，恢复时又沿用旧代导致持续 out-of-date。请修复 gsb/batch46-game-e-05 的 swapchain_resize_guard.py 中 SwapchainResize（Bugfix），负责尺寸防抖、代际管理、退役保留与显存预算。需要保持这些公开方法：observe(self, width: int, height: int, *, format: str | None = None, present: str | None = None, frame: int = 0) -> dict、poll(self, frame: int = 0) -> dict、rebuild(self, frame: int = 0) -> dict、acquire(self, generation: int) -> dict、present(self, generation: int, frame: int = 0) -> dict、suspend(self, frame: int = 0) -> dict、resume(self, width: int, height: int, *, format: str | None = None, present: str | None = None, frame: int = 0) -> dict、retire(self, generation: int) -> dict、config(self) -> dict、history(self) -> list[dict]、estimate_bytes(self, width: int | None = None, height: int | None = None, *, generation: int | None = None) -> int、snapshot(self) -> dict、restore(self, state: dict) -> dict。

故障与边界：1) 期望表面与当前完全一致时 observe 返回 action 为 none；有变化返回 pending，必须连续 debounce_frames 次轮询稳定后 poll 才返回 rebuild，提前 rebuild 报 SWR_DEBOUNCE_PENDING，无待处理重建报 SWR_NO_PENDING，轮询未稳定时不得改变当前世代，也不得清空待处理配置。2) 宽高同时为零进入最小化，poll 返回 suspend，宽或高只有一个为零报 SWR_SIZE_INVALID，负尺寸同样拒绝，挂起期间再次观察零尺寸应保持挂起，不重复累计次数。3) 重建后世代自增，返回 generation、width、height、format、present、images、required_bytes、cause；cause 只能是 resize、format、present、resume 之一，重建成功才清空待处理，失败时保留以便按新预算重试。4) fifo 与 immediate 的图像数为 min_images，mailbox 为 min_images 加一但不超过 max_images；未知 present 报 SWR_PRESENT_INVALID，图像数只由 present 模式与上下限决定，与窗口尺寸无关。5) acquire 与 present 必须成对，未 acquire 就 present 报 SWR_NOT_ACQUIRED；图像索引按 0 到 images 减一循环，present 成功后 in_flight 递减，计数不得低于零。6) 非当前世代的操作报 SWR_STALE_SWAPCHAIN，present 的陈旧次数进入 stats 的 stale_presents，acquire 使用陈旧世代同样拒绝，但不计入 stale_presents。7) 有未 present 的已获取图像时 rebuild 报 SWR_IN_FLIGHT；重建成功后 in_flight 归零，acquire 与 present 使用同一把锁，不得出现负在飞数。8) 最小化状态 present 或 acquire 报 SWR_SUSPENDED，suspend 会清空待处理与在飞；非挂起状态调用 resume 报 SWR_NOT_SUSPENDED，resume 之后必须重新经过防抖与重建，不直接复用旧配置。9) max_bytes 下重建所需字节超过预算报 SWR_BUDGET_EXCEEDED，detail 带 required 与 budget，当前世代和配置保持不变，预算检查发生在创建之前。10) retire 不能退役当前世代并报 SWR_CURRENT_GENERATION，重复退役报 SWR_GENERATION_RETIRED，未知世代报 SWR_GENERATION_UNKNOWN，保留数超过 max_retained 时销毁最旧并记入 stats，返回的 retained 与 destroyed 都按退役先后排列。11) 快照 version 为 5，恢复要保住当前配置、待处理、保留代与历史，版本或配置校验失败报 SWR_SNAPSHOT_INVALID。12) config 返回 width、height、format、present、images、generation、suspended、in_flight；history 每条含 generation、cause、required_bytes、frame；estimate_bytes 按宽乘高乘图像数乘四计算，也可指定历史世代，history 长度必须等于 rebuilds，被预算拒绝的尝试不得写入，历史世代必须递增。

硬约束：多线程同时 present 与 rebuild 必须串行且计数准确；并发重建只能有一个成功；重启恢复后代际、配置与历史一致；显存估算与 max_bytes 是硬预算。验收：python3 -m pytest -q tests 十五条全过，不得改测试、跳过或写死；并发和恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- difficulty: 困难
