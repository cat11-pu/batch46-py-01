# GSB Bugfix Task

## 题面

周五下午，A 租户的运维在虚机里抓到了 B 租户的 ARP 广播，紧接着两边都出现 MAC 地址漂移告警；排查发现新上线的接入脚本把两个 VNI 配到了同一组端口，广播域直接被打通。更麻烦的是有人伪造源 MAC 往全网段刷广播，接入交换机 CPU 被抬到九成，监控一直报警。请修 `gsb/batch46-safety-c-07` 下的 `vxlan_tenant_guard.py`，核心类型 `VxlanGuard`，任务类型 Bugfix；所有拒绝路径统一抛 `VxlanError(code, detail=None)`，调用方按 `code` 处理。

需要保留这些公开方法：`__init__(self, *, max_vnis: int = 4096, max_ports: int = 512, rate_limit_pps: int = 1000, rate_window: float = 1.0, max_frame_bytes: int = 1500) -> None`、`register_tenant(self, tenant: str, vni: int, *, mc_group: str | None = None) -> dict`、`release_tenant(self, tenant: str) -> dict | None`、`tenant_for_vni(self, vni: int) -> str | None`、`vni_for_tenant(self, tenant: str) -> int | None`、`bind_port(self, port: str, tenant: str, mac: str) -> dict`、`unbind_port(self, port: str) -> dict | None`、`learn(self, vni: int, mac: str, port: str) -> dict`、`lookup(self, vni: int, mac: str) -> str | None`、`ingress(self, frame: dict, *, port: str, now: float) -> dict`、`stats(self) -> dict`、`snapshot(self) -> dict`、`restore(self, state: dict) -> None`。

具体故障与边界：一、VNI 合法范围是 1 到 16777214，0 和 16777215 属于保留值，必须报 `VX_VNI_RESERVED`；租户名为空报 `VX_TENANT_INVALID`。二、同一租户用相同 VNI 和组播组重复注册要幂等返回 created=False，注册结果固定含 tenant、vni、mc_group、created 四个字段；同租户换 VNI 报 `VX_TENANT_CONFLICT`，VNI 已被别的租户占用报 `VX_VNI_CONFLICT`，两个租户共用同一组播组报 `VX_MC_CONFLICT`，非组播地址报 `VX_MC_INVALID`，超过 `max_vnis` 报 `VX_VNI_LIMIT`。三、释放租户返回 tenant、vni、ports 三个字段，同时删掉该租户全部端口、限速历史和 VNI 下的转发条目；再释放一次返回 None。四、绑定端口对同租户同 MAC 幂等并返回 port、tenant、vni、mac；租户不存在报 `VX_UNKNOWN_TENANT`，端口已属于别的租户报 `VX_PORT_CONFLICT`，MAC 不是六段十六进制报 `VX_MAC_INVALID`，超过 `max_ports` 报 `VX_PORT_LIMIT`；MAC 统一转小写，解绑返回原记录或 None。五、`learn` 要校验 VNI 存在、端口存在且端口所属租户就是 VNI 的主人，否则分别报 `VX_UNKNOWN_VNI`、`VX_UNKNOWN_PORT`、`VX_PORT_TENANT_MISMATCH`；同一 VNI 下 MAC 换端口算一次 move 并累加计数，learn 返回 vni、mac、port、moved，未知组合的 `lookup` 返回 None。

六、`ingress` 必须按固定顺序检查：端口未绑定报 `VX_UNKNOWN_PORT`；以太类型 0x8100 或 0x88A8 的双层标签报 `VX_DOUBLE_TAG`；帧长超过 `max_frame_bytes` 报 `VX_MTU_EXCEEDED`；帧内 VNI 与端口所属 VNI 不一致报 `VX_VNI_MISMATCH`；源 MAC 非法报 `VX_MAC_INVALID`，与端口绑定 MAC 不符报 `VX_MAC_SPOOF`。前置检查失败的帧不能学习源 MAC。七、限速按端口做滑动窗口：窗口内已放行的帧数达到 `rate_limit_pps` 就报 `VX_RATE_LIMIT`，被限速的帧同样不学习，另计 rate_dropped。八、广播和未知单播只能在同租户端口内泛洪，egress 按端口名排序且排除入端口；已知单播转发到学习到的端口；目的端口就是入端口时按 `VX_HAIRPIN` 丢弃。返回结果固定含 action、code、tenant、vni、egress，放行时 code 为 None，丢弃时 egress 为空列表。九、`stats` 要给出 tenants、ports、fdb_entries、forward、flood、drop、moves、rate_dropped 和 codes；每次丢弃按错误码累计。十、快照固定含 version、tenants、ports、fdb、rate、counters，恢复时重建 VNI 反查和组播占用表，恢复过程要深拷贝；版本不符报 `VX_STATE_VERSION`。

硬约束：所有公开方法由同一把可重入锁保护，八个线程并发绑定不同端口并泛洪时，端口数、泛洪次数和 FDB 条目不能丢更新；快照恢复后租户映射、端口绑定、FDB、限速窗口和计数要一致；VNI 数、端口数、FDB 和每端口限速队列都有上限，限速队列长度不得超过 `rate_limit_pps`。验收标准是 `python3 -m pytest -q tests` 的 15 条全部通过；不得改测试、跳过或按固定输入写死，并发与重启恢复自行验证，只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- difficulty: 困难
