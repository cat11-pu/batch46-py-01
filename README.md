# GSB Bugfix Task

## 题面

邮件网关上线 STARTTLS 强制策略后，安全组在流量回放里发现三类问题：对端 EHLO 里根本没有 STARTTLS，网关仍把邮件以明文投递；某银行域名昨天还宣布支持 STARTTLS，今天被中间设备抹掉能力项，网关只当成普通明文会话；还有会话在 EHLO 之前就上报 TLS 版本，状态机直接接受并把密文参数写进日志。值班组临时把这套状态机塞进网关进程后，明文会话在 EHLO 之后直接发 MAIL FROM，策略引擎也没有拦截；能力缓存还按连接而不是按域名记，换一条连接就重新信任对端。修复范围：模块路径 gsb/batch46-safety-d-02，文件 smtp_starttls_guard.py，类 StarttlsGuard，任务类型 Bugfix，异常类 StarttlsError 携带 code。

接口：StarttlsGuard(*, cache_ttl: int = 600, max_sessions: int = 64)、set_policy(domain: str, *, mode: str = "require", min_version: str = "TLSv1.2") -> dict、policy_for(domain: str) -> dict、begin_session(session_id: str, *, peer_ip: str, ehlo_domain: str, now: int = 0) -> dict、observe_ehlo(session_id: str, capabilities: Sequence[str], *, now: int = 0) -> dict、decide(session_id: str, now: int = 0) -> dict、mark_tls(session_id: str, *, version: str, cipher: str) -> dict、cache_lookup(domain: str, now: int) -> dict、downgrade_report(limit: int = 50) -> list[dict]、close_session(session_id: str) -> bool、snapshot() -> dict、restore(payload: Mapping[str, object]) -> dict、metrics() -> dict。

故障与边界：一、策略只有 require 和 opportunistic 两种，其他值按 SMTP_POLICY_INVALID；域名空按 SMTP_DOMAIN_INVALID；min_version 只认 TLSv1.3 与 TLSv1.2，其余按 SMTP_TLS_VERSION。二、未配置域名默认 require 加 TLSv1.2；策略按域名精确匹配，不做后缀通配，未注册子域不会继承父域设置。三、EHLO 能力项先 strip 再转大写去重排序，STARTTLS 按首词识别；能力项里带参数（如 SIZE 1000）时只取首词判断，重复项和大小写差异不能影响结果；空列表按 SMTP_EHLO_EMPTY，非字符串项按 SMTP_EHLO_INVALID。四、require 策略下缺少 STARTTLS，决策为 reject、code 为 SMTP_STARTTLS_MISSING，rejections 只加一次，重复 EHLO 不能把拒绝计数刷高。五、缓存记录某域名曾支持 STARTTLS 后，若在 cache_ttl 内再次看到能力项缺失，必须判为 SMTP_STARTTLS_STRIPPED，即使策略是 opportunistic，并写入降级报告。六、同一会话重复上报完全相同的能力项返回 status duplicate，不重复计数，也不能产生第二条降级记录。七、状态机只允许 begun 到 ehlo 到 tls；EHLO 之前 mark_tls 或 decide、TLS 建立后再 EHLO，都按 SMTP_STATE_ORDER 拒绝。八、mark_tls 的版本低于策略下限按 SMTP_TLS_VERSION，密文为空按 SMTP_TLS_CIPHER，失败时状态仍停在 ehlo 可重试。九、cache_lookup 在 now 减写入时刻大于 cache_ttl 时返回 hit 为 False、starttls 为 None，命中时返回 age；缓存未命中或过期时按从未见过该域名处理，不能沿用旧结论。十、会话号重复按 SMTP_SESSION_EXISTS，超过 max_sessions 按 SMTP_SESSION_LIMIT，close_session 返回是否真的关闭，关闭后调用按 SMTP_SESSION_MISSING；会话建立后域名为只读，后续 EHLO 不能换域名绕过策略。十一、downgrade_report 倒序返回，limit 必须在 1 到 500，否则 SMTP_BAD_LIMIT。十二、snapshot 必须保存策略、能力缓存、活动会话状态与计数器；restore 原子，坏版本或坏结构按 SMTP_SNAPSHOT_INVALID 且状态不变。metrics 至少给出 sessions_started、ehlo_observed、tls_established、rejections、downgrades、duplicates、active_sessions。

硬约束：所有会话状态与缓存读写在一把锁内完成，多线程各自建会话时计数不得丢失；恢复后会话能继续 decide 和关闭，缓存命中结果与恢复前一致。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得改测试、不得跳过、不得按固定输入写死。并发与重启场景自行验证；只做本地实现，不涉及其他目录。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
