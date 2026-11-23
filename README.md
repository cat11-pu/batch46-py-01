# GSB Bugfix Task

## 题面

世界杯点播回看上线后，运营收到投诉：同一场比赛在 4K 和 1080p 之间手动切档，画面先卡半秒再跳一段，音画对不上；CDN 日志显示播放器请求的 4K 分片编号和 1080p 对不上，两个 Representation 的分片边界根本不在同一时刻。受影响的不只是点播，直播时移复用同一套编号，切档编号错位会让回看直接跳到错误位置。问题定位在 gsb/batch46-game-h-02/dash_segment_guard.py 的 DashSegment 类，它维护 MPD 各 Representation 的对齐关系、按编号和时间查询分片、给出跨档切换的目标编号，并支持窗口过期和快照，任务类型 Bugfix。

对外接口是 add_representation(self, rep_id: str, *, bandwidth: int, codecs: str = "avc1.4d401f", width: int = 1920, height: int = 1080) -> dict、align_representation(self, rep_id: str, *, start_number: int, durations: list, timescale: int | None = None) -> dict、segment_at(self, rep_id: str, number: int) -> dict、segment_for_time(self, rep_id: str, time_ms: int) -> dict | None、gap_report(self, rep_id: str, numbers: list) -> list、alignment_report(self, rep_a: str, rep_b: str) -> dict、switch_representation(self, from_rep: str, to_rep: str, *, at_number: int) -> dict、current(self) -> dict | None、expire_before(self, number: int) -> int、snapshot(self) -> dict、restore(self, snapshot: dict) -> None、stats(self) -> dict、close(self) -> None，close 幂等、重复调用不报错。异常统一是 DashError，带 code 和 detail，stats 返回 representations、alignments、switches、expired、ignored、restores 六个计数。所有查询返回的字典和列表都是副本，调用方修改返回值不影响内部状态。

现场要落地的行为：分片时长按 timescale 换算毫秒并四舍五入到整数，timescale 为 90000 时 180000 tick 必须换算成 0 到 2000 毫秒；durations 为空或含非正数返回 DASH_BAD_SEGMENT，整次对齐不生效，该档位保持未对齐；单档分片数超过 max_segments 返回 DASH_SEGMENT_LIMIT；同一档位换 timescale 返回 DASH_TIMESCALE_LOCK；新 start_number 小于已对齐值时返回 status 为 ignored、code 为 DASH_SEQ_REGRESS 且原窗口不动，不小于原值时按新 durations 重建窗口并从零起算，成功对齐返回 status、start_number、timescale、segment_count、duration_ms；segment_at 对低于 start_number 的编号返回 DASH_SEGMENT_EXPIRED，超出末尾返回 DASH_SEGMENT_UNKNOWN，未对齐返回 DASH_REP_UNAVAILABLE，未登记返回 DASH_REP_UNKNOWN；segment_for_time 使用左闭右开区间，正好等于最后一个 end_ms 返回 None，负数返回 DASH_BAD_TIME；gap_report 只列出不在起止编号范围内的编号并升序返回；alignment_report 比较两个档位的起始毫秒序列，返回 aligned、mismatch_ms、a_segments、b_segments，mismatch_ms 取目标档第一个不落在对方边界上的起始时刻；switch_representation 要求 at_number 的起始时刻在目标档也是边界，否则 DASH_SWITCH_MISALIGN，成功返回 status、variant、number、start_ms 并更新 current；expire_before 对所有已对齐档位同时裁掉编号小于参数的分片，累加基准时间保持时间轴不变，返回删除总条数；分片 uri 固定为 rep_id/seg-number.m4s，snapshot 保留对齐窗口、current 和统计，restore 对 version 不符或结构损坏返回 DASH_SNAPSHOT_INVALID 且不改现有状态，恢复后 restores 加一。

硬约束：对齐、切换、过期都要在锁内完成，多线程对同一实例操作时不能读到只写了一半 durations 的档位，快照里的每个档位要么未对齐要么是完整窗口；重启后从 snapshot 恢复必须让 alignment_report、segment_at、current 与快照前一致，过期计数和切换计数一并还原；每档分片数、档位数量都有硬上限，过期裁剪要真正释放列表而不是只标记不可见，expire_before 返回的是所有档位删除条数之和。

验收按 python3 -m pytest -q tests 执行，15 条用例必须全过；不得修改测试、不得跳过、不得针对固定输入硬编码；并发对齐和快照恢复请自行复跑，切换前先用 alignment_report 复核边界；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- difficulty: 困难
