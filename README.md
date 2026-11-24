# GSB Bugfix Task

## 题面

周一切片割接后，计费系统发现 A 切片一批用户面流量被记到了 B 切片头上，两个切片的 TEID 在上游网关里撞了号；同一条下行报文还从错误的对端地址灌进来，被当成合法隧道继续转发。Echo 响应也出了乱子：同一个序列号在两百毫秒内回来三次，网关回回都确认，探活状态一直是绿的，直到用户面真的断了才报丢包。请修 `gsb/batch46-safety-c-09` 下的 `gtp_teid_guard.py`，核心类型 `GtpGuard`，任务类型 Bugfix；所有校验失败统一抛 `GtpError(code, detail=None)`，调用方按 `code` 处理。

需要保留这些公开方法：`__init__(self, *, max_tunnels: int = 1024, max_ext_headers: int = 4, idle_ttl: float = 300.0, seq_window: int = 64) -> None`、`open_tunnel(self, tenant: str, *, local_teid: int, peer_teid: int, peer_ip: str, slice_id: int = 0, now: float = 0.0) -> dict`、`close_tunnel(self, local_teid: int, *, now: float = 0.0) -> dict | None`、`tunnel(self, local_teid: int) -> dict | None`、`tunnels_for(self, tenant: str) -> list[dict]`、`classify(self, message: dict, *, peer_ip: str, tenant: str | None = None, now: float = 0.0) -> dict`、`echo(self, message: dict, *, peer_ip: str, now: float = 0.0) -> dict`、`expire_idle(self, *, now: float) -> list[int]`、`stats(self) -> dict`、`snapshot(self) -> dict`、`restore(self, state: dict) -> None`。

具体故障与边界：一、TEID 合法范围是 1 到 4294967295，0 是保留值报 `GTP_TEID_RESERVED`，负数、非整数或超过上限报 `GTP_BAD_TEID`；peer_ip 非法报 `GTP_BAD_PEER`，slice_id 不在 0 到 255 报 `GTP_BAD_SLICE`，租户名为空报 `GTP_BAD_TENANT`。二、同一 local_teid 用完全相同租户、对端 TEID、对端地址和切片重复开会话要幂等返回 created=False，成功结果固定含 tenant、local_teid、peer_teid、peer_ip、slice_id、created、created_at、last_seen；任何一项不同或换租户抢同一 TEID 报 `GTP_TEID_CONFLICT`；会话数超过 `max_tunnels` 报 `GTP_TUNNEL_LIMIT`。三、`close_tunnel` 返回被删记录并累加 closed，第二次返回 None；TEID 关闭后可以重新打开；`tunnels_for` 按 local_teid 升序返回副本，改返回值不能影响内部状态。四、`classify` 先校验 version 必须为 1、pt 必须为 1、msg_type 只能是 1、2、255，否则分别报 `GTP_BAD_VERSION`、`GTP_BAD_PT`、`GTP_BAD_TYPE`；再查 TEID、租户和对端地址，分别报 `GTP_UNKNOWN_TEID`、`GTP_TENANT_MISMATCH`、`GTP_PEER_MISMATCH`。五、payload_bytes 必须在 0 到 65535，G-PDU（255）的载荷不能为 0，否则报 `GTP_BAD_LENGTH`。六、E 位置位时扩展头链不能为空，长度不能超过 `max_ext_headers`，类型在 1 到 255，重复类型视为环路，分别报 `GTP_EXT_EMPTY`、`GTP_EXT_LIMIT`、`GTP_EXT_TYPE`、`GTP_EXT_LOOP`；E 位未置位却带扩展头报 `GTP_EXT_UNEXPECTED`。

七、S 位置位时 seq 必须在 0 到 65535，否则报 `GTP_BAD_SEQ`；通过后更新 last_seen 为当前时间和旧值的较大者，返回 status 为 accepted、code 为 None，以及 tenant、local_teid、peer_teid、msg_type、payload_bytes、slice_id、last_seen、extensions 字段，G-PDU 另计 g_pdu。八、`echo` 要求对端地址至少属于一条隧道，否则报 `GTP_UNKNOWN_PEER`；请求必须带 S 位和合法 seq，请求返回 status、code、response、peer_ip、seq、msg_type，response 为 True，请求不去重。九、Echo 响应按对端维护最高序列号和已见集合：seq 小于最高值减 `seq_window` 报 `GTP_STALE_SEQ`，等于已见序列号报 `GTP_DUP_SEQ`，通过后更新最高值并清掉窗口外记录，返回值含 highest。十、`expire_idle` 只清理 now 减去 last_seen 严格大于 `idle_ttl` 的隧道，返回按 TEID 升序的列表，清理后 classify 报未知 TEID，TEID 可重新打开。十一、`stats` 给出 tunnels、tenants、accepted、rejected、closed、echo_requests、echo_responses、g_pdu 和 codes；快照固定含 version、tunnels、echo、counters，恢复要深拷贝并重建已见序列集合，版本不符报 `GTP_STATE_VERSION`。十二、八个线程并发打开不同 TEID 并各分类一条报文，隧道数、租户数和 accepted 必须精确，不能因为字典扩容丢条目。

硬约束：会话表、echo 序列窗口和统计由同一把可重入锁保护，打开、关闭、分类必须原子；快照恢复后 TEID 归属、对端地址、序列窗口和计数要一致；隧道数、扩展头数和序列窗口都有上限，已见序列集合大小不得超过 `seq_window` 加一。验收标准是 `python3 -m pytest -q tests` 的 15 条全部通过；不得改测试、跳过或按固定输入写死，并发与重启恢复自行验证，只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
