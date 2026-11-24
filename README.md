# GSB Bugfix Task

## 题面

浏览器侧灰度开启 permessage-deflate 后，客服系统出现两类严重故障：一条 40KB 的正常消息在服务端被判定为超限，压缩上下文直接作废，后续所有消息都报错；攻击者用几百字节的压缩炸弹把单条消息解成几十兆，进程内存瞬间打满；协商里 server_no_context_takeover 和 client_no_context_takeover 被搞混，同一连接上压缩端重置了字典、解压端还在用旧字典；网关重启后再也解不开历史连接上残留的消息。压测时还发现上下文数量没有上限，每条连接都保留一份字典，内存持续上涨。修复范围：模块路径 gsb/batch46-safety-d-05，文件 websocket_compression_guard.py，类 WsCompressionGuard，任务类型 Bugfix，异常类 WsCompressionError 携带 code。

接口：WsCompressionGuard(*, max_message: int = 65536, max_contexts: int = 16, history: int = 8)、open_session(session: str) -> dict、negotiate(session: str, params: Mapping[str, object]) -> dict、compress(session: str, payload: bytes) -> bytes、decompress(session: str, data: bytes) -> bytes、context_state(session: str) -> dict、set_limit(session: str, max_message: int) -> dict、reset_context(session: str) -> dict、close_session(session: str) -> bool、inflight() -> list[str]、snapshot() -> dict、restore(payload: Mapping[str, object]) -> dict、metrics() -> dict。

故障与边界：一、必须先 open_session 再 negotiate；未协商就 compress 或 decompress 按 WS_STATE_ORDER；未知或已关闭会话按 WS_SESSION_MISSING，空会话号按 WS_SESSION_INVALID。二、协商参数只允许四个键：两个 no_context_takeover 必须是 bool，两个 max_window_bits 接受 8 到 15 的整数或数字字符串；未知键、越界、类型错误一律 WS_PARAM_INVALID，失败的协商不能改变会话状态。三、同一会话用完全相同参数再次协商返回 status duplicate，换参数按 WS_ALREADY_NEGOTIATED。四、compress 使用原始 deflate 并去掉末尾 00 00 ff ff，decompress 自动补回；压缩后消息长度不得超过会话 max_message，超限按 WS_MESSAGE_TOO_LARGE，且上下文保持可用。五、decompress 的输出超过 max_message 或还有未消费的输入时按 WS_DECOMPRESS_BOMB，并把上下文标记为 failed；非法 deflate 流按 WS_DEFLATE_INVALID 同样标记 failed。六、failed 上下文在任何压缩或解压前按 WS_CONTEXT_FAILED 拒绝，只有 reset_context 能清零失败标记并重建两端上下文。七、no_context_takeover 为真的那一侧每处理一条消息就重建上下文并累加对应重置计数；context_state 返回 server_resets、client_resets、resets、failed、max_message 和收发消息数。八、set_limit 每次只能调低或调高到 1 到 1048576，越界按 WS_LIMIT_INVALID，只影响该会话。九、open_session 的上下文总数受 max_contexts 限制，超出按 WS_CONTEXT_LIMIT；重复会话号按 WS_SESSION_EXISTS；close_session 返回是否真的关闭，重复关闭返回 False。十、snapshot 每个会话只保留最近 history 条已发送明文和已接收的压缩数据，用十六进制保存；restore 必须原子校验版本、参数、计数与长度，坏快照按 WS_SNAPSHOT_INVALID 且现有会话不变。十一、restore 后要按历史重建压缩和解压上下文，context_state 的收发计数、重置计数、失败标记和协商参数与快照一致，并能继续正常收发。十二、metrics 给出 contexts、negotiated、sent_messages、received_messages、bytes_sent、bytes_received、resets、failures、duplicates。

硬约束：同一会话的压缩与解压必须串行，多个线程各自持有一条会话连续收发 15 条消息，不得串包或丢计数；快照恢复后的连接必须能继续解压新消息，重启不改变 no_context_takeover 语义。

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
