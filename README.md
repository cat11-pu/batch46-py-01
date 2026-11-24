# GSB Bugfix Task

## 题面

证券清算系统的授时客户端去年还能用，今年三月交易所把时钟偏差告警阈值收紧到五十毫秒以后，运维每天都要处理时间相关工单。抓包发现有台内网机器冒充上游时间服务器，报文没有通过任何 MAC 校验就被采纳；旧报文被原样重放，本机时钟被拨回半小时，撮合序号整段错乱；stratum 为 0 和 16 的应答都能进算法；root delay 超过两秒的链路照样参与计算；leap 指示器已经标记未同步的源还在投票；单个源给出二百秒偏移时客户端直接步进，日志里连一条拒绝都没有；两台服务器相差三秒，系统取了先到的那台；密钥只有七位也允许登记，重复 key_id 直接覆盖旧密钥；服务器列表没有上限，一次误配置写进两百多台；重启后快照把密钥明文落盘，审计直接判高危；故障切换后拿旧快照恢复，重放窗口清空，上周的报文又能用。

范围是 gsb/batch46-safety-c-04 下的 ntp_auth_guard.py，类 NtpAuthGuard，任务类型 Bugfix，负责密钥登记、服务器登记、请求票据、应答校验、漂移决策、投票与快照。偏移按 ((t2 - t1) + (t3 - t4)) / 2 计算，t1 为 originate_time、t2 为 receive_time、t3 为 transmit_time、t4 为 arrived_at。MAC 的规范串为 key_id|server|leap|stratum|originate_time|receive_time|transmit_time|root_delay|root_dispersion，五个时间与延迟字段一律用 "{:.6f}" 格式化，再用 HMAC-SHA256 取小写十六进制。公开接口（Python 类型注解）：`NtpAuthGuard(*, clock=None, max_servers: int = 8)`；`add_key(key_id: int, secret: str, *, algorithm: str = "sha256") -> dict`；`add_server(server: str, *, key_id: int, stratum: int = 2, max_root_delay: float = 1.5) -> dict`；`make_request(server: str, *, transmit_time: float | None = None) -> dict`；`receive(packet: dict) -> dict`；`offset() -> float`；`state() -> dict`；`adjust(*, steps: int = 1) -> dict`；`clear_panic() -> dict`；`health() -> dict`；`snapshot() -> dict`；`restore(snapshot: dict) -> None`。配置错误抛 NtpError(code, detail)，应答问题用 receive 的 {"status", "code", "offset"} 表达。

故障与边界：一、密钥长度至少 8，过短抛 NTP_WEAK_KEY；algorithm 只支持 sha256，其他抛 NTP_UNSUPPORTED_ALGORITHM；同 key_id 重复登记相同密钥幂等，不同密钥抛 NTP_KEY_CONFLICT。二、add_server 的 key_id 必须已登记，否则抛 NTP_UNKNOWN_KEY；重复服务器抛 NTP_SERVER_EXISTS；超过 max_servers 抛 NTP_TOO_MANY_SERVERS。三、make_request 登记待答票据并返回 originate_time，同一服务器重复请求以最后一次为准。四、receive 依次校验服务器、密钥归属、MAC、重放、跳变、同步位、层级、根延迟与票据：未知服务器 NTP_UNKNOWN_SERVER，密钥未登记 NTP_UNKNOWN_KEY，密钥不属于该服务器 NTP_KEY_MISMATCH，MAC 不符 NTP_AUTH_FAILED。五、同一 (server, transmit_time) 重复出现返回 NTP_REPLAY；transmit_time 小于等于该服务器上次采纳值返回 NTP_STALE_PACKET。六、leap 为 3 返回 NTP_UNSYNC；stratum 必须在 1 到 15，否则 NTP_BAD_STRATUM；root_delay 超过服务器登记上限返回 NTP_ROOT_DELAY；originate_time 找不到待答票据返回 NTP_BAD_ORIGINATE。七、偏移绝对值超过 128 秒返回 NTP_OFFSET_TOO_LARGE 并进入 panic，panic 状态下除 clear_panic 外的应答一律 NTP_PANIC_LOCKED，但 make_request 仍可正常登记票据。八、单一来源且偏移绝对值超过 0.5 秒返回 NTP_STEP_NEEDS_CONSENSUS，不改变待校正量。九、两个以上来源的样本中位数互相落在 0.25 秒内时按中位数设定待校正量；三个以上来源出现离群样本时，离群来源本次返回 NTP_FALSETICKER，其余按内点中位数处理；两个来源相差超过 0.25 秒返回 NTP_DISAGREEMENT。十、adjust 每次最多朝零方向移动 0.1 秒，返回 applied、remaining、phase；剩余绝对值小于等于 0.01 时 phase 为 locked，否则为 slewing，初始为 idle。十一、health 按服务器给出 accepted、rejected、last_code、last_offset、last_transmit，last_transmit 只记录最近一次采纳值。十二、snapshot 带 version=1，覆盖服务器配置、票据、采样、待校正量与统计，但绝不包含密钥明文；restore 后服务器仍登记但密钥缺失，应答按 NTP_UNKNOWN_KEY 拒绝，必须重新 add_key；版本或结构非法抛 NTP_SNAPSHOT_CORRUPT 且原状态不变。

硬约束：receive、adjust、restore 全程持锁，多线程并发送同一报文时重放窗口只允许一次采纳；每台服务器保留的已见 transmit_time 与待答票据数量必须有上限，不允许随请求无限增长；快照必须深拷贝并可 JSON 往返，恢复后的去重窗口、panic 与待校正量保持一致，密钥不得随快照落盘。

验收：`python3 -m pytest -q tests` 的 15 条测试全部通过；不得修改测试、跳过或按固定输入写死；并发与重启恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 地狱
