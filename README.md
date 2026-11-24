# GSB Bugfix Task

## 题面

跨境电商的出口代理集群上个月被扫描器盯上，SOCKS5 入口两天内出现二十多万次认证尝试。安全复盘列出七类问题：认证列表里只要带 no-auth 就真的允许匿名转发；连续输错密码没有锁定，单账号被撞库一晚上；用户名和密码长度不做限制，超长凭据把解析缓冲撑破；BIND 和 UDP ASSOCIATE 命令照样放行，代理被当成反向监听器；目标地址不看白名单，也不拦回环和私网，攻击者用代理打通内网数据库；单用户开会话没有上限，一个账号占满连接池；流量配额只在报表里统计，超额连接不断，月底账单翻了三倍；重复 close 会把在线计数减两次，运维面板出现负数；进程重启后会话表清空，正在跑的抓取任务全部中断；迁移快照把用户密码明文写进文件，被扫描到公开对象存储。

范围是 gsb/batch46-safety-c-05 下的 socks5_auth_guard.py，类 Socks5Guard，任务类型 Bugfix，负责用户登记、方法协商、RFC 1929 认证、目标策略、会话与流量配额、快照。公开接口（Python 类型注解）：`Socks5Guard(*, max_sessions: int = 64, require_auth: bool = True, default_max_sessions: int = 4, clock=None)`；`add_user(username: str, password: str, *, max_sessions: int | None = None, quota_bytes: int | None = None, allow_targets: tuple = (), allow_private: bool = False) -> dict`；`set_password(username: str, password: str) -> dict`；`hello(session_id: str, methods: list) -> dict`；`authenticate(session_id: str, username: str, password: str) -> dict`；`connect(session_id: str, cmd: int, host: str, port: int) -> dict`；`record_traffic(session_id: str, *, up: int = 0, down: int = 0) -> dict`；`close(session_id: str) -> dict`；`session(session_id: str) -> dict`；`list_sessions(username: str | None = None) -> list`；`usage(username: str) -> dict`；`expire(now: int | None = None) -> list`；`unlock(username: str) -> dict`；`snapshot() -> dict`；`restore(snapshot: dict) -> None`。策略错误抛 Socks5Error(code, detail)，协商结果用返回值表达。

故障与边界：一、hello 对未知会话号自动建会话；require_auth 为真时只接受 0x02，客户端没提供就返回 method=0xFF、status=rejected、code=SOCKS_NO_METHOD；require_auth 为假时优先 0x00，其次 0x02；methods 为空或元素越界抛 SOCKS_BAD_METHODS；会话已协商过再 hello 抛 SOCKS_BAD_STATE。二、authenticate 必须在 hello 选中 0x02 之后调用，否则抛 SOCKS_BAD_STATE；未知会话抛 SOCKS_SESSION_UNKNOWN；用户名与密码长度必须在 1 到 255，否则 SOCKS_BAD_CREDENTIAL_FORMAT。三、密码比较必须常量时间；同一用户连续失败三次即锁定 300 秒，第三次失败与锁定期间的正确密码都返回 SOCKS_USER_LOCKED，前两次返回 SOCKS_AUTH_FAILED；expire(now) 解锁到期用户并按字典序返回用户名列表，unlock 手工解锁。四、connect 按固定顺序校验：未知会话抛 SOCKS_SESSION_UNKNOWN；命令不是 0x01 抛 SOCKS_CMD_UNSUPPORTED；地址与端口非法抛 SOCKS_BAD_ADDRESS；随后才看状态，未认证抛 SOCKS_NOT_AUTHENTICATED、已连接抛 SOCKS_ALREADY_CONNECTED、已关闭抛 SOCKS_BAD_STATE。五、host 为空或长度超过 255、port 不在 1 到 65535，一律抛 SOCKS_BAD_ADDRESS。六、allow_targets 非空时按后缀匹配：登记 .example.com 允许 example.com 与任意子域，badexample.com 必须拒绝并抛 SOCKS_TARGET_DENIED。七、目标是 IP 字面量且属于回环、私网、链路本地、保留或组播时，用户没有 allow_private=True 就抛 SOCKS_TARGET_DENIED。八、单用户在线会话数达到 max_sessions（缺省取 default_max_sessions）抛 SOCKS_SESSION_LIMIT；全局在线数达到构造参数 max_sessions 抛 SOCKS_SERVER_BUSY；两个上限先判用户再判全局。九、record_traffic 只对 open 会话生效，否则 SOCKS_NOT_OPEN；up 或 down 为负抛 SOCKS_BAD_TRAFFIC；累计用量超过 quota_bytes 时立即关闭会话、closed_reason 记为 SOCKS_QUOTA_EXCEEDED 并抛同名错误。十、close 第一次返回 status=closed，重复 close 返回 status=noop 与 code=SOCKS_ALREADY_CLOSED，在线计数只减一次；未连接就关闭的会话同样按 closed 处理。十一、session 返回会话快照；usage 返回 sessions（在线）、total（累计连接）、up、down、quota、remaining，remaining 不足时取 0。十二、snapshot 带 version=1，覆盖用户策略、会话、配额用量与锁定状态，但绝不包含密码；restore 后所有密码失效，认证按 SOCKS_AUTH_FAILED 拒绝，必须由 set_password 重新下发；版本非法、会话号重复或会话引用未知用户抛 SOCKS_SNAPSHOT_CORRUPT 且原状态不变。

硬约束：hello、authenticate、connect、close、restore 全程持锁，二十个线程同时用同一账号建连时成功数必须精确等于用户上限，不能多发也不能少发；在线会话、每用户累计用量与快照大小都必须有界；快照必须深拷贝并可 JSON 往返，恢复后的在线计数、剩余配额与锁定截止时间保持一致，密码不得随快照落盘。

验收：`python3 -m pytest -q tests` 的 15 条测试全部通过；不得修改测试、跳过或按固定输入写死；并发与重启恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
