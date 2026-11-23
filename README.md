# GSB Bugfix Task

## 题面

凌晨的体育赛事直播又出现画面在 720p 和 1080p 之间来回跳、客户端每次切换黑屏两秒的问题，值班同学把播放器日志拉出来，发现同一条码流十秒内被切了七次，切片窗口里还混着上一条播放列表的旧分片，CDN 回源也跟着重复下载。问题出在 gsb/batch46-game-h-01/hls_playlist_guard.py 的 HlsPlaylist 类：它维护 HLS 媒体播放列表的滑动窗口、码率档切换、断点标记和状态快照，播放器、录制回源、运维后台三条链路共用同一实例，录制侧还会按过期接口清理旧分片，运维看板每秒拉一次统计，任何状态不一致都会放大成线上事故，任务类型 Bugfix。

需要保留的公开方法是 register_variant(self, variant_id: str, *, bandwidth: int, codecs: str = "avc1.4d401f,mp4a.40.2", resolution=None) -> dict、variant_info(self, variant_id: str) -> dict、update_media_playlist(self, variant_id: str, *, media_sequence: int, segments: list, target_duration: float | None = None) -> dict、switch_variant(self, from_variant: str, to_variant: str, *, at_sequence: int | None = None) -> dict、current(self) -> dict、segments(self, variant_id: str | None = None) -> list、pending_discontinuity(self, variant_id: str) -> bool、expire_before(self, media_sequence: int) -> int、snapshot(self) -> dict、restore(self, snapshot: dict) -> None、stats(self) -> dict、close(self) -> None。异常统一用 HlsError，带 code 和 detail 两个属性。variant_info 要原样带回带宽、codecs 和 resolution 供切档决策，stats 返回 updates_applied、updates_ignored、switches、expired、restores 五个计数。

现场要修的点：重复登记同一档位返回 HLS_VARIANT_DUP，带宽非正返回 HLS_BAD_VARIANT，档位数超过 max_variants 返回 HLS_VARIANT_LIMIT；单次提交分片数超过 window_size 整批拒绝并返回 HLS_WINDOW_OVERSIZE，窗口不能只写一半；任一分片时长超过 target_duration 返回 HLS_DURATION_DRIFT 且整批不生效；media_sequence 小于期望值时返回 status 为 ignored、code 为 HLS_SEQ_REGRESS，并带回当前序号，大于期望值返回 HLS_SEQ_GAP，只有恰好等于才落库并把序号推进 len(segments)；窗口只保留最后 window_size 条，返回 trimmed 和 trimmed_uris，每条分片按序号连续编号；切到 codecs 不同的档位必须给出 discontinuity 为真，并让目标档下一条分片带断点标记后清除 pending，codecs 相同则不带；同一 at_sequence 的切换次数超过 switch_budget 返回 HLS_SWITCH_THRASH，切到自身返回 HLS_SWITCH_SAME，未登记档位返回 HLS_VARIANT_UNKNOWN；expire_before 删除指定序号之前的全部档位分片并返回删除条数；snapshot 要包含配置、档位、窗口、当前档、pending、切换计数和统计，restore 遇到 version 不符或结构损坏返回 HLS_SNAPSHOT_INVALID 且不能改动现有状态，恢复成功后 restores 加一；close 幂等，关闭后写操作返回 HLS_CLOSED，读取和快照仍可用；stats 返回副本，外部修改不能污染内部计数。

硬约束有三类。并发与原子性：提交、切换、过期必须在同一把锁内完成校验和写入，任一步失败都不能留下半截窗口，多线程同时提交后最终序号必须等于成功提交次数，窗口内序号连续无洞。快照恢复：跨进程重启后 restore 必须还原 pending 断点和切换预算，恢复实例的行为与快照时一致。资源上限：档位数、窗口长度、切换计数表都有硬上限，切换计数表最多保留六十四个序号，长时间直播内存不能单调增长，窗口裁剪只保留引用，不要整表深拷贝拖慢提交。

验收按 python3 -m pytest -q tests 执行，15 条用例必须全过；不得修改测试、不得跳过、不得按固定输入写死返回值；并发和重启场景要自行用多线程和 restore 复跑；只做本地实现，不改上游播放器；实现完成后用多线程把提交、快照、恢复各跑一遍。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- difficulty: 困难
