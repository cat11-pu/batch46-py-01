# GSB Bugfix Task

## 题面

上周三凌晨，海外分支的 DoT 探针突然被上游限速，抓包发现我们发出的查询长度参差不齐，同一条链路上查询和响应尺寸差距明显，被运营商按长度指纹识别；同时长连接复用写错了租户维度，一个客户的连接被另一个客户复用，审计直接标红。值班同学最初以为是 TLS 版本问题，后来发现填充块大小、长度前缀和连接池各自为政，代码里没有任何一处把三者对齐。修复范围在 gsb/batch46-safety-d-07 的 dot_padding_guard.py，DotPaddingGuard 负责帧封装、填充校验和连接复用，任务类型 Bugfix，公共接口不许改。

需要落地的接口（签名与骨架一致）：encode(self, message: dict, *, block: int | None = None) -> bytes；decode(self, frame: bytes) -> dict；open(self, tenant: str, peer: str) -> str；submit(self, conn_id: str, message: dict, *, timeout: float | None = None) -> dict；complete(self, conn_id: str, frame: bytes) -> dict；close(self, conn_id: str) -> dict；pending(self, conn_id: str) -> list[int]；sweep(self) -> dict；snapshot(self) -> dict；restore(self, state: dict) -> None；stats(self) -> dict。

帧格式固定为：两字节大端长度前缀、两字节消息号、负载，末尾跟 12 号填充选项（两字节选项码、两字节长度、若干零字节），整帧长度必须是 block 的整数倍，默认 468；组帧选最小填充量。返回字段固定：submit 返回 conn_id、message_id、frame、padded_to、deadline；complete 返回 status、message_id、payload、padding、wait；sweep 返回 closed、expired；stats 至少包含 connections、pending、sent、received、duplicates、expired、reused、dropped、closed、closed_idle、evicted。

具体故障与边界：一、block 小于 16 或不是 4 的倍数按 DOT_INVALID_BLOCK 拒绝；二、消息号超出 0 到 65535、负载不是 bytes，分别按 DOT_INVALID_MESSAGE_ID、DOT_INVALID_PAYLOAD 拒绝；三、解帧声明的长度与真实长度不一致按 DOT_LENGTH_MISMATCH；四、整帧不是 block 整数倍按 DOT_PADDING_MISALIGNED；五、填充选项后面还有字节按 DOT_PADDING_NOT_LAST；六、填充字节不全是零按 DOT_PADDING_NOT_ZERO；七、同一租户同一对端要复用连接并累加 reused，跨租户必须新建；八、连接数达到 max_connections 时先淘汰最老的空闲连接并累加 evicted，没有空闲连接才抛 DOT_CONN_LIMIT；九、单连接待回消息达到 max_pending 抛 DOT_PENDING_LIMIT，同一消息号重复提交抛 DOT_DUPLICATE_MESSAGE；十、响应按消息号匹配，可以乱序到达，重复响应返回 status 为 duplicate 并累加 duplicates，出现在别的连接上按 DOT_CROSS_CONNECTION 拒绝；十一、sweep 要把超过 deadline 的待回消息清掉并统计 expired，把超过 idle_timeout 的空闲连接关掉列进 closed；十二、快照必须能直接 json.dumps，恢复后待回消息、绝对 deadline 和计数都要对上，版本不符抛 DOT_SNAPSHOT_VERSION 且原状态不动。

硬约束：submit 与 complete 会被多线程并发调用，八个线程同时提交同一消息号只能成功一次，其余必须收到 DOT_DUPLICATE_MESSAGE，计数不能多记；恢复快照要么整体生效要么整体回退；连接数、单连接待回数都有上限，任何路径都不能越界；关闭连接时要先把丢弃的待回消息数报出来，不允许静默丢包，统计口径在重启后必须连续，不能出现负数或回退。验收：python3 -m pytest -q tests 的 15 条测试全过，不得改测试、跳过或按固定输入写死，并发和重启场景自己写脚本验证，只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
