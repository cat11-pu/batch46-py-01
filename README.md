# GSB Bugfix Task

## 题面

对外网关给合作方开了 gRPC 反射，第二天安全组就看到有人把 ops 包的服务名、方法名全量拉走。internal 服务在未授权列表里照常出现；private 服务不在列表里，按符号解析仍能拿到方法名；分页游标是偏移量原文，第三页又出现第一页的服务；page_size 传 5000 就返回 5000 个方法，内存被打高；单调用方一分钟两千次请求没有限速；探测失败几百次不封禁；封禁写成永久，误封账号只能重启；重启后注册、授权、封禁全丢；审计只记成功调用；撤销服务后授权表留旧名导致 KeyError；游标任意字符串不校验；带斜杠的符号把不存在的方法当服务返回。

范围是 gsb/batch46-safety-d-09 下的 grpc_reflection_guard.py，类 ReflectionGuard，任务类型 Bugfix，负责服务注册、按调用方授权、反射列表与符号解析、限速封禁、审计与快照。公开接口（Python 类型注解）：`ReflectionGuard(*, max_services: int = 64, max_methods_per_response: int = 50, rate_limit: int = 10, rate_window: int = 60, enumeration_threshold: int = 5, block_seconds: int = 120, audit_limit: int = 200)`；`register_service(name: str, *, visibility: str = "public", methods: tuple = (), labels: dict | None = None) -> dict`；`revoke_service(name: str) -> dict`；`grant(caller: str, *, services: tuple = ()) -> dict`；`list_services(caller: str, *, page_size: int | None = None, cursor: str | None = None, now: int | None = None) -> dict`；`list_methods(caller: str, service: str, *, page_size: int | None = None, cursor: str | None = None, now: int | None = None) -> dict`；`resolve_symbol(caller: str, symbol: str, *, now: int | None = None) -> dict`；`audit(*, caller: str | None = None, limit: int | None = None) -> list`；`block_caller(caller: str, seconds: int, *, now: int | None = None) -> dict`；`unblock_caller(caller: str) -> dict`；`blocked(*, now: int | None = None) -> list`；`snapshot() -> dict`；`restore(snapshot: dict) -> None`。注册、授权、访问与限速类错误一律抛 ReflectionError(code, detail)。

故障与边界：一、服务名至少两段、每段字母开头、只含字母数字下划线，否则抛 RFG_BAD_SERVICE；visibility 只接受 public/internal/private，否则 RFG_BAD_VISIBILITY；methods 重复或非法抛 RFG_BAD_METHOD；重复注册内容一致返回 unchanged，否则 RFG_SERVICE_CONFLICT；服务数达 max_services 抛 RFG_CAPACITY；注册成功返回含 service、visibility、methods、status 的字典。二、grant 的 caller 必须非空，否则 RFG_BAD_CALLER；services 任一项不存在抛 RFG_UNKNOWN_SERVICE；授权整体替换，返回去重升序的 services；撤销服务同步清掉授权中的该名，之后解析返回 RFG_NOT_FOUND。三、public 对所有调用方可见可解析；internal/private 只对显式授权方可解析，未授权抛 RFG_DENIED；internal 授权后进入列表，private 永不进列表但授权后可解析方法。四、list_services 返回 {"services","next_cursor"}，名称升序且只含 public 与已授权 internal；list_methods 返回 {"service","methods","next_cursor"}，方法名升序，服务不存在抛 RFG_NOT_FOUND，无权限抛 RFG_DENIED。五、page_size 缺省为 max_methods_per_response，小于 1 抛 RFG_BAD_PAGE，超过上限截断；游标必须原样回传，无法解析抛 RFG_BAD_CURSOR，越界偏移返回空列表且 next_cursor 为 None。六、resolve_symbol 的符号为“服务”或“服务/方法”，服务或方法不存在抛 RFG_NOT_FOUND，空符号或多斜杠抛 RFG_BAD_SYMBOL；成功返回 {"kind","service","method"}，服务级解析的 method 为 None。七、同一调用方列表与解析调用在 rate_window 秒内超过 rate_limit 次后抛 RFG_RATE_LIMIT，其他调用方不受影响；失败调用也占额度；窗口按 now 滑动，过期记录先淘汰。八、未授权、未找到、限速、坏游标/分页/符号都计入违规；rate_window 内违规达 enumeration_threshold 立即封禁 block_seconds 秒，触发那次抛原错误；封禁中入口直接抛 RFG_BLOCKED，截止时间小于等于 now 自动解除。九、block_caller 的 seconds 必须大于 0，否则抛 RFG_BAD_BLOCK，返回 {"caller","until","status"}；unblock_caller 返回 status 为 unblocked；blocked(now) 按字典序；expire 清理到期封禁并按字典序返回。十、审计只记失败调用、封禁（RFG_BLOCKED）、解封（RFG_UNBLOCKED）、过期事件，条目 {"caller","op","code","ts"}，op 取 list_services、list_methods、resolve_symbol、block、unblock、expire；按序追加，超过 audit_limit 丢最旧；audit(caller) 过滤，limit 取最近 limit 条仍按时间升序；入口被封禁的拒绝不重复记。十一、stats 返回 services、callers、requests、denied、not_found、rate_limited、blocked、audit 八个计数；requests 统计未被入口封禁挡掉的列表与解析调用，blocked 为当前封禁人数。十二、snapshot 含 version、services、grants、blocked、rate、violations、audit、stats，version 为 1，必须深拷贝；restore 校验版本、可见性与字段类型，非法抛 RFG_SNAPSHOT_CORRUPT 且原状态不变。

硬约束：注册、撤销、授权、列表解析、封禁与 restore 全程持同一把可重入锁；并发注册时服务总数不超过 max_services，并发探测同一调用方只能产生一次封禁审计；限速与违规时间戳按调用方有界保留，审计受 audit_limit 约束；快照恢复后的封禁继续生效，已过期封禁不得复活，授权与撤销级联结果与快照一致。

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
