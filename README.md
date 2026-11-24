# GSB Bugfix Task

## 题面

上周三凌晨，边缘网关切到新的四层负载均衡后，风控发现一批请求的客户端地址全变成公网出口 IP，真实来源在日志里消失；同一天又有人绕过负载均衡直连业务端口，自己拼了一段 PROXY 头，把会话挂到别人的内网地址上。值班同学临时把头部信任开关关掉，结果正常玩家也登不进来，客服工单堆到两百多张，监控面板上内网来源占比从九成掉到不足一成。请修 `gsb/batch46-safety-c-06` 里的 `proxy_protocol_guard.py`，核心类型 `ProxyProtocolGuard`，任务类型 Bugfix。所有校验失败必须抛出 `ProxyProtocolError(code, detail=None)`，调用方按 `code` 分支处理。

需要保留这些公开方法：`__init__(self, *, trusted_peers: Iterable[str] = (), max_header_bytes: int = 536, max_tlv_bytes: int = 256, max_connections: int = 1024, source_ttl: float = 5.0) -> None`、`allow_peer(self, peer: str) -> None`、`revoke_peer(self, peer: str) -> None`、`is_trusted(self, peer: str) -> bool`、`parse(self, raw: bytes, *, peer: str, connection: str | None = None, now: float = 0.0) -> dict`、`trust_source(self, source_ip: str, *, now: float, ttl: float | None = None) -> dict`、`check_source(self, source_ip: str, *, now: float) -> bool`、`purge_sources(self, *, now: float) -> int`、`stats(self) -> dict`、`recent(self, limit: int = 10) -> list[dict]`、`snapshot(self) -> dict`、`restore(self, state: dict) -> None`。

具体故障与边界：一、不受信的 peer 必须在看头之前拒绝，报 `PPX_UNTRUSTED_PEER`；`allow_peer` 同时支持单个 IP 和 CIDR，非法 peer 报 `PPX_BAD_PEER`，`revoke_peer` 只移除对应网段。二、v1 只认 `PROXY TCP4`、`PROXY TCP6` 和 `PROXY UNKNOWN`，其它协议令牌报 `PPX_BAD_PROTOCOL`，地址或端口非法报 `PPX_BAD_ADDRESS`，端口必须在 1 到 65535 之间，整行超过 `max_header_bytes` 报 `PPX_TOO_LARGE`，找不到 CRLF 报 `PPX_TRUNCATED`，CRLF 之后还有多余字节报 `PPX_TRAILING_DATA`。三、v2 的 12 字节签名不符报 `PPX_BAD_SIGNATURE`，版本不是 2 报 `PPX_BAD_VERSION`，命令不是 LOCAL/PROXY 报 `PPX_BAD_COMMAND`，地址族不是 0x00/0x11/0x21 报 `PPX_BAD_FAMILY`，声明长度与实际 body 不一致报 `PPX_LENGTH_MISMATCH`；TCP4 与 TCP6 的地址版本必须与族匹配，PROXY 命令下 family 0x00 表示不带地址。四、TLV 只允许 0x01 ALPN、0x02 AUTHORITY、0x03 UNIQUE_ID、0x04 SSL，长度上限依次 32/128/64/64，未知类型报 `PPX_TLV_TYPE`，超长报 `PPX_TLV_LEN`，重复报 `PPX_TLV_DUP`，TLV 总字节超过 `max_tlv_bytes` 报 `PPX_TLV_TOO_LARGE`，截断报 `PPX_TLV_TRUNCATED`。五、成功时 code 为 None，结果固定含 status、code、version、command、source、destination、tlvs、header_bytes；source/destination 是 `(ip, port)` 或 None，UNKNOWN 与 LOCAL 不带地址，v2 的 header_bytes 是整段输入长度；ALPN/AUTHORITY/UNIQUE_ID 按 UTF-8 解码，SSL 返回十六进制字符串。六、同一 connection 再次携带头部报 `PPX_DUPLICATE`，被拒请求不占用连接记录，重复请求也不刷新该连接的最近使用顺序；连接表按最近使用受 `max_connections` 限制，表满时淘汰最久未用的连接并累加 evicted，被淘汰的连接可以重新建头。七、`trust_source` 返回 source_ip 与 expires_at，`check_source` 仅在 now 严格小于 expires_at 时为真，过期后 `purge_sources` 返回清理条数。八、`stats` 至少含 accepted、rejected、codes、connections、sources、recent、evicted，拒绝按 code 累计；`recent` 最多保留 100 条，按发生顺序，接受和拒绝都要记，拒绝记录带 code 和 peer。九、快照含 version、trusted_peers、connections、sources、counters、recent、evicted，`restore` 要深拷贝并整体替换现有状态，改快照不能影响原对象，版本不符报 `PPX_STATE_VERSION`。十、多个线程同时 `parse` 不同连接时，计数和 LRU 不能丢更新；`stats`、`snapshot` 与解析互斥。

硬约束：并发调用必须原子，计数器与 recent 的写入和解析在同一临界区内完成；快照恢复后连接去重、信任列表、计数和来源有效期要一致；v1 行、v2 TLV、连接表和 recent 各自有上限，先做总量校验再逐项解析，错误码必须稳定，不允许同类故障在不同分支里换成两个名字。验收标准是 `python3 -m pytest -q tests` 的 15 条全部通过；不得改测试、跳过或按固定输入写死，并发与重启恢复自行验证，只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
