# GSB Bugfix Task

## 题面

短视频 App 的清晰度在 480p 和 1080p 之间来回跳，用户每隔几秒就看到画面糊一下；日志里同一分钟切了十几次档，还有新上传的档位把 720p 配成四兆、把 1080p 配成九百 K，播放器选到高分辨率反而更糊；运营还发现新档位配置完全没有校验，上传后台可以随意填写分辨率和码率。问题在 gsb/batch46-game-h-05/abr_ladder_guard.py 的 AbrLadder，负责码率阶梯登记校验、按吞吐和缓冲选档、升档滞回、切换频率限制、吞吐平滑估计和会话快照，任务类型 Bugfix。

公开接口：add_rung(self, name: str, *, width: int, height: int, bitrate_kbps: int, codec: str = "h264") -> dict、rungs(self) -> list、remove_rung(self, name: str) -> None、current(self) -> dict | None、observe(self, throughput_kbps: float) -> float、select(self, throughput_kbps: float, *, device_cap_kbps: int | None = None, buffer_s: float | None = None) -> dict、select_auto(self, *, device_cap_kbps: int | None = None, buffer_s: float | None = None) -> dict、reset_session(self) -> None、snapshot(self) -> dict、restore(self, snapshot: dict) -> None、stats(self) -> dict、close(self) -> None，close 幂等、重复调用不报错。异常统一 AbrError，带 code 和 detail，stats 返回 rungs_added、rungs_removed、selections、up_switches、down_switches、resets、restores 以及 active_rungs。

现场要落地的规则：add_rung 重名返回 ABR_DUP，宽高或码率非正返回 ABR_BAD_RUNG，码率超出 min_bitrate_kbps 到 max_bitrate_kbps 返回 ABR_BITRATE_RANGE，档位数超过 max_rungs 返回 ABR_RUNG_LIMIT；码率密度按 bitrate_kbps 乘一千除以宽高乘三十计算，必须落在 0.02 到 0.15 之间，否则 ABR_RATIO；阶梯必须同时按像素数和码率单调，任何一对档位出现码率更高但像素更少或相等返回 ABR_ORDER，rungs 按码率升序；remove_rung 删除当前档时 current 变为 None，未登记档位返回 ABR_UNKNOWN；select 的返回值固定包含 rung、bitrate_kbps、changed、code 四个字段，切档被拒绝时 changed 为假；选档先按 device_cap_kbps 过滤，再在吞吐乘 safety_factor 以内取最高档，没有可负担档位时保持当前并返回 ABR_UNDERFLOW；首次选中返回 ABR_INIT 且 changed 为真；升档除了可负担还要求吞吐乘 safety_factor 不小于目标码率乘 upscale_margin，否则返回 ABR_HOLD，显式给出 buffer_s 且小于 low_buffer_s 时也只挡升档、不挡降档；目标低于当前立即降档并返回 ABR_DOWN，相等返回 ABR_STABLE；最近 window_size 次观测内成功切换达到 max_switches_per_window 时新的切换被拒绝，返回 ABR_SWITCH_LIMIT 且 current 不变，观测推进窗口后恢复；observe 使用 alpha 做指数平滑，首个样本直接作为均值并返回平滑值，非正样本返回 ABR_BAD_SAMPLE，select_auto 用当前平滑值调用 select；reset_session 清空 current、平滑值和切换窗口但保留档位，resets 加一；snapshot 保留档位、current、平滑值、观测序号、切换事件和统计，restore 对 version 不符或结构损坏返回 ABR_SNAPSHOT_INVALID 且不改现有状态，恢复后 restores 加一。

硬约束：登记、选档、观测、重置全部串行化，选档读取的档位列表、当前档和切换窗口必须来自同一时刻，不允许按旧阶梯选档却写入新阶梯状态；重启后 restore 必须还原当前档、平滑值和切换预算，紧接着的 select 行为与快照前一致；档位数、切换事件窗口、单次选档遍历次数都有上限，切换事件只保留窗口内记录，长时间运行内存不增长，平滑值只保留一个标量而不保存全部历史样本，档位在个位数时单次选档必须线性完成。

验收按 python3 -m pytest -q tests 执行，15 条用例必须全过；不得修改测试、不得跳过、不得按固定输入写死；快照恢复要自行复跑；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- difficulty: 困难
