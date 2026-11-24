# GSB Bugfix Task

## 题面

智能家居的 MQTT 接入层最近连续出事：设备断网重连后订阅全部丢失，离线期间的告警没有补发；有用户正常关机却收到了自己的遗嘱消息，家属被误报吓到；设备只是网络抖动五秒，遗嘱延迟还没到就重新连上，结果延迟遗嘱照样发出去；同一客户端重连触发会话接管时，旧连接的遗嘱反而没发；QoS2 的下游重复收到同一条指令，packet id 被重复分配；离线队列没有上限，一次故障攒了几十万条把内存打满。修复范围在 gsb/batch46-safety-d-10 的 mqtt_session_guard.py，MqttSessionGuard 负责订阅、离线队列、in-flight 表、遗嘱和会话接管，任务类型 Bugfix，调用方不改。

需要落地的接口（签名与骨架一致）：match(self, topic: str, topic_filter: str) -> bool；connect(self, client_id: str, *, clean_start: bool = False, will: dict | None = None, keepalive: int = 60, now: float | None = None) -> dict；subscribe(self, client_id: str, topic_filter: str, qos: int = 0) -> dict；unsubscribe(self, client_id: str, topic_filter: str) -> dict；deliver(self, client_id: str, topic: str, payload: bytes, *, qos: int = 0, expire_at: float | None = None) -> dict；acknowledge(self, client_id: str, packet_id: int, *, kind: str = "puback") -> dict；disconnect(self, client_id: str, *, graceful: bool = True, now: float | None = None) -> dict；keepalive_check(self, client_id: str, now: float | None = None) -> dict；pending(self, client_id: str) -> dict；will_for(self, client_id: str) -> dict | None；wills(self) -> list[dict]；purge(self, now: float | None = None) -> dict；session_state(self, client_id: str) -> dict；snapshot(self) -> dict；restore(self, state: dict) -> None；stats(self) -> dict。

返回字段固定：connect 返回 client_id、session_present、replayed、queued、inflight；deliver 返回 status、packet_id、qos，status 取 delivered、queued、dropped；disconnect 返回 client_id、graceful、will、session_removed；pending 返回 queued、queued_count、inflight、inflight_count；purge 返回 wills、expired；stats 至少包含 sessions、connections、delivered、queued、offline_dropped、expired、wills_published、wills_scheduled、wills_cancelled、takeovers、duplicates、replayed。

具体故障与边界：一、主题过滤器里 + 只匹配一层、# 只能出现在末尾并匹配剩余所有层，过滤器为空、# 不在末尾、+ 混在层级中间都按 MQTT_INVALID_FILTER 拒绝，发布主题带通配符按 MQTT_INVALID_TOPIC，客户端为空按 MQTT_INVALID_CLIENT，QoS 不在 0 到 2 按 MQTT_INVALID_QOS；二、clean_start 连接要丢掉旧的订阅、队列和 in-flight，正常断开后会话整体删除，下次连接 session_present 为假；三、持久会话断开期间的消息按先来后到排队，重连时按 FIFO 回放并把已回放消息计入 replayed；四、离线队列超过 max_offline 时丢最老的一条并累加 offline_dropped；五、投递 QoS 要取发布 QoS 和匹配订阅的最大 QoS 的较小值，一个订阅都不匹配时返回 dropped 和 MQTT_NO_MATCH；六、PUBACK 清掉 in-flight，包号不存在按 MQTT_PACKET_UNKNOWN；七、QoS2 的重复 PUBREC 只能返回 duplicate 并累加 duplicates，不能重复投递，PUBREL 之后才移出 in-flight；八、包号从 1 开始分配，总是取当前 in-flight 里没有的最小号，释放后可以复用；九、正常断开必须抑制遗嘱，非正常断开且延迟为 0 立即发布，延迟大于 0 先挂起并累加 wills_scheduled；十、同一客户端在延迟遗嘱到期前重连要取消遗嘱并累加 wills_cancelled，purge 到期后发布遗嘱并累加 wills_published，同时清掉 expire_at 已过的排队消息并累加 expired；十一、keepalive 超过 1.5 倍周期没心跳按非正常断开处理，返回 action 为 will_published，会话接管时旧连接的遗嘱按同一规则处理并累加 takeovers；十二、快照要能 json.dumps，恢复后订阅、队列、in-flight 和计数都要对上，版本不符抛 MQTT_SNAPSHOT_VERSION 且原状态一个字段都不许动。

硬约束：二十个线程同时对同一个离线会话投递不同消息，队列里必须一条不少、一条不重，计数不能多记也不能漏记；回放必须保持入队顺序；离线队列和 in-flight 表都有硬上限，任何路径都不能突破；快照恢复要么整体生效要么整体回退。验收：python3 -m pytest -q tests 的 15 条测试全过，不得改测试、跳过或按固定输入写死，并发和重启场景自己造数据验证，只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
