# GSB Bugfix Task

## 题面

S12 赛季结算当天，客服后台被奖励工单打满：同一玩家收到三份冠军框；补发脚本跑两遍，解封账号拿到双倍点券；运营把积分从 120 改成 80，已领的 100 分档奖励还挂着；新赛季提前十分钟开放，时间判断用本地时区，跨区错开一天；先领三级再回头领二级被允许；两个互斥外观被同一账号同时领走；补偿队列重复投递 event_id，积分加两遍；批量补发一次传两万账号，进程 OOM；补发窗口只开三十天，次月申请全被吞；删号重建后领取记录丢失，奖励又发一份；重启后账本回到前一天，已撤销的作弊奖励重新可领；结算期两个请求同时领取，同一档位发了两份奖励。

范围是 gsb/batch46-game-b-08 下的 season_reward_grant.py，类 SeasonReward，任务类型 Bugfix，负责赛季窗口、档位、积分账本、领取、撤销、补发与快照。公开接口（Python 类型注解）：`SeasonReward(*, max_tiers: int = 20, max_claims_per_batch: int = 50, max_points: int = 10_000_000)`；`open_season(season: str, *, starts_at: int, ends_at: int, grace: int = 0, name: str | None = None) -> dict`；`define_tier(season: str, tier: int, *, requirement: int, rewards: tuple = (), exclusive_group: str | None = None) -> dict`；`grant_points(account: str, season: str, points: int, *, event_id: str | None = None, reason: str = "match", now: int | None = None) -> dict`；`claim(account: str, season: str, tier: int, *, now: int | None = None) -> dict`；`claim_batch(accounts: list, season: str, tier: int, *, now: int | None = None) -> list`；`revoke(account: str, season: str, tier: int, *, reason: str, now: int | None = None) -> dict`；`reissue(account: str, season: str, tier: int, *, reason: str, now: int | None = None) -> dict`；`snapshot() -> dict`；`restore(snapshot: dict) -> None`。配置、窗口、账本与领取类错误一律抛 SeasonRewardError(code, detail)。

故障与边界：一、open_season 要求 starts_at 小于 ends_at、grace 非负，否则抛 SR_BAD_WINDOW；同赛季重复开启抛 SR_SEASON_EXISTS；返回含 season、name、starts_at、ends_at、grace、status，初始为 open。二、season_state 按 now 推导 open、grace、expired；close_season 记录首次 closed_at 并置 closed，重复调用返回同值，结算后加分拒绝但宽限期内可领取；expire 只标记宽限期结束的赛季并返回名称。三、define_tier 的 tier 必须正整数，否则 SR_BAD_TIER；同档重复抛 SR_TIER_EXISTS；requirement 必须非负且严格大于低档、小于已定义高档，否则 SR_TIER_ORDER；rewards 每项形如 gold:100，否则 SR_BAD_REWARD；档位数达 max_tiers 抛 SR_CAPACITY；成功返回 status 为 defined 与 rewards。四、grant_points 的 account 必须非空，否则 SR_BAD_ACCOUNT；赛季不存在抛 SR_UNKNOWN_SEASON；积分非零，负数仅 reason 为 correction，否则 SR_BAD_POINTS；now 早于 starts_at 抛 SR_SEASON_NOT_STARTED，晚于 ends_at 抛 SR_SEASON_CLOSED；累计超 max_points 抛 SR_POINTS_CAP 且不写。五、event_id 按赛季加账号去重，重复投递返回 duplicate + SR_DUP_EVENT 和当前总分，积分不变；不同账号同一 event_id 各自生效；不带 event_id 不去重。六、加分返回 applied + SR_POINTS_GRANTED 与 account、season、points、delta；correction 后总分不得低于有效领取档位 requirement 之和，否则 SR_POINTS_FLOOR 分数不变，撤销领取后下限释放。七、points 返回 account、season、points、claimed_tiers，claimed_tiers 为有效档位升序，无记录返回 0 与空列表；claims 按赛季和档位升序返回 season、tier、status、rewards、reissued、reason，撤销记录保留。八、claim 必须按档位升序，低档未领就领高档抛 SR_TIER_ORDER；积分不足 SR_REQUIREMENT_NOT_MET；已领取 SR_ALREADY_CLAIMED；被撤销未补发 SR_CLAIM_REVOKED；档位未定义 SR_UNKNOWN_TIER。九、now 超过 ends_at 加 grace 抛 SR_CLAIM_EXPIRED；同 exclusive_group 有有效领取抛 SR_EXCLUSIVE_CONFLICT；成功返回 claimed + SR_CLAIMED 与 rewards。十、claim_batch 超 max_claims_per_batch 抛 SR_BATCH_TOO_LARGE；否则按输入顺序处理，每行含 account，单行失败不打断整批，成功行 claimed 带 rewards，失败行 rejected 带 code。十一、revoke 只接受有效领取，无记录抛 SR_CLAIM_NOT_FOUND，已撤销抛 SR_ALREADY_REVOKED，只改状态与原因、不回滚积分；reissue 只对已撤销领取生效，不存在抛 SR_CLAIM_NOT_FOUND，仍有效抛 SR_REISSUE_DENIED，已补发再调抛 SR_DUP_REISSUE，超过宽限期抛 SR_CLAIM_EXPIRED；补发不重校验积分、不重复累加，成功后 status 回 active、reissued 为 True，返回 reissued + SR_REISSUED 与 rewards。十二、snapshot 含 version、seasons、tiers、points、claims、events，version 为 1，覆盖积分、领取（含撤销/补发标记）与 event_id 去重集合，必须深拷贝；restore 校验版本、字段类型与档位可见性，非法抛 SR_SNAPSHOT_CORRUPT 且原状态不变，恢复后重复 event_id 仍被识别。

硬约束：grant_points、claim、claim_batch、revoke、reissue、expire 与 restore 全程持同一把可重入锁；同一 event_id 并发加分只入账一次，同一档位并发领取只成功一次，其余返回 SR_ALREADY_CLAIMED；档位、积分与去重集合按赛季和账号有界；批量领取不因单行失败回滚；快照恢复后已撤销领取不得重新可领取，补发标记与结算时间原样保留。

验收：`python3 -m pytest -q tests` 的 15 条测试全部通过；不得修改测试、跳过或按固定输入写死；并发与重启恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- difficulty: 困难
