# GSB Bugfix Task

## 题面

周二上午，跨机房的 Geneve 隧道升级后，OAM 检测帧开始把带了未知选项的包整条丢掉，可同一个未知选项在控制面看又完全正常；另一批包因为选项下发顺序不同被判定摘要不一致，补偿任务重复跑了两遍，计数直接翻倍。更严重的是某个非关键选项长度超限后没有被拦住，接收端解析越界，隧道口开始随机重启。升级窗口只剩一个小时，回滚脚本又依赖旧的选项顺序。请修 `gsb/batch46-safety-c-08` 下的 `geneve_option_guard.py`，核心类型 `GeneveGuard`，任务类型 Bugfix；所有校验失败统一抛 `GeneveError(code, detail=None)`，调用方按 `code` 处理。

需要保留这些公开方法：`__init__(self, *, max_options: int = 8, max_option_bytes: int = 128, allowed_classes: Iterable[int] = (0x0108,), cache_capacity: int = 64) -> None`、`register_option(self, opt_class: int, opt_type: int, *, critical: bool = False, max_len: int = 16, encoding: str = "raw") -> dict`、`unregister_option(self, opt_class: int, opt_type: int) -> bool`、`list_options(self) -> list[dict]`、`parse(self, packet: dict, *, request_id: str | None = None) -> dict`、`audit(self, packet: dict) -> dict`、`cache_size(self) -> int`、`clear_cache(self) -> int`、`stats(self) -> dict`、`snapshot(self) -> dict`、`restore(self, state: dict) -> None`。

具体故障与边界：一、packet 必须含 version、vni、options，version 只接受 0，vni 合法范围是 1 到 16777215，否则分别报 `GENEVE_BAD_VERSION`、`GENEVE_BAD_VNI`；options 不是列表报 `GENEVE_BAD_PACKET`。二、注册选项时 class 必须在 0 到 65535，type 在 0 到 255，max_len 在 0 到 1024，encoding 只认 raw、utf8、ipv4，非法组合报 `GENEVE_BAD_REGISTRATION`；重复注册同一键要覆盖旧记录，`list_options` 按 class 和 type 升序返回，解绑返回布尔值。三、选项个数超过 `max_options` 报 `GENEVE_OPT_COUNT`；每个选项占 4 加 value 长度个字节，总和超过 `max_option_bytes` 报 `GENEVE_OPTS_OVERFLOW`，这两项都在逐项字段校验之前判定，避免先解析再溢出。四、同一 class 和 type 在一次报文里出现两次报 `GENEVE_OPT_DUP`。五、class 不在 allowed_classes 或 type 未注册时，critical 为真报 `GENEVE_CRITICAL_UNKNOWN`，critical 为假则跳过，把 `[class, type]` 记入 skipped，不算失败。六、已注册选项的 critical 位必须与注册表一致，否则报 `GENEVE_CRITICAL_MISMATCH`。七、value 长度超过注册的 max_len 报 `GENEVE_OPT_LEN`，空 value 报 `GENEVE_OPT_EMPTY`。八、encoding 为 utf8 时必须能按 UTF-8 解码，encoding 为 ipv4 时必须恰好 4 字节且能解析成 IPv4 地址，否则报 `GENEVE_OPT_ENCODING`。

九、成功结果固定含 status、code、version、vni、options、skipped、option_bytes、cached，首次解析 cached 为 False；options 按 class 和 type 排序，每项含 class、type、critical、value（bytes）和 length，skipped 是排序前的二元组列表。十、`audit` 不增加统计也不写缓存，一次返回全部问题，检查顺序是 version、vni、选项数量、总字节，再按选项顺序检查重复、未注册、关键位、长度和编码；结果含 ok、issues、vni、option_bytes。十一、带 request_id 的相同请求返回缓存副本并标 cached=True，不增加 parsed；缓存按 `cache_capacity` 做 LRU 淘汰，返回和保存都要深拷贝，调用方改返回值不能影响后续命中，`cache_size` 与 `clear_cache` 分别返回当前条数和清理条数。十二、`stats` 给出 parsed、accepted、rejected、replayed、skipped_options 和 codes；快照固定含 version、registered、allowed_classes、cache、counters，`restore` 深拷贝并重建注册表与缓存，版本不符报 `GENEVE_STATE_VERSION`。

硬约束：parse、缓存和统计由同一把可重入锁保护，八个线程并发处理四十个不同 request_id 时，parsed、accepted 和缓存条数必须精确；快照恢复后注册表、允许 class、缓存命中和计数要与恢复前一致；单次解析的工作量受 `max_options` 和 `max_option_bytes` 限制，缓存条数不得超过 `cache_capacity`。验收标准是 `python3 -m pytest -q tests` 的 15 条全部通过；不得改测试、跳过或按固定输入写死，并发与重启恢复自行验证，只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 地狱
