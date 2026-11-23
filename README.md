# GSB Bugfix Task

## 题面

节点安全巡检最近被 eBPF 加载器折腾得很惨：一个带无条件回跳的程序把加载线程卡住，校验器没拦住；最后一条不是 exit 的程序也被放行，运行时直接掉核；跳转偏移越界只在运行期崩；xdp 程序调用了只有 kprobe 才有的 helper 仍然加载成功；声明的 map 超过配额时，程序已经建了一半的 map；两个程序声明同名 map 但容量不同，后一个把前一个的数据冲掉；map 满了以后更新已有键也报错；hook 已被占用，第二个程序仍能挂上去；关闭程序后 map 配额没有释放；两个租户之间的 map 与 hook 互相看得见；重启后 program id 从 1 重新发，快照里的 hook 全丢。修复范围在模块 gsb/batch46-safety-e-09 的 ebpf_verifier_guard.py，类型 EbpfGuard，任务类型 Bugfix，只用 Python 标准库，失败统一抛 EbpfError，异常对象带 code 与 detail。

接口按骨架保持：verify(self, spec: dict, *, tenant: str = "default") -> dict、load_program(self, spec: dict, *, tenant: str = "default") -> dict、program_info(self, program_id: int, *, tenant: str = "default") -> dict、programs(self, tenant: str = "default") -> list[dict]、maps(self, tenant: str = "default") -> list[dict]、map_update(self, name: str, key: str, value: str, *, tenant: str = "default") -> dict、map_lookup(self, name: str, key: str, *, tenant: str = "default") -> str | None、attach(self, program_id: int, hook: str, *, tenant: str = "default") -> dict、detach(self, program_id: int, hook: str, *, tenant: str = "default") -> bool、close_program(self, program_id: int, *, tenant: str = "default") -> dict、set_quota(self, tenant: str, *, max_programs: int | None = None, max_maps: int | None = None, max_map_bytes: int | None = None) -> dict、stats(self) -> dict、audit(self, limit: int | None = None) -> list[dict]、snapshot(self) -> str、restore(cls, data: str) -> "EbpfGuard"。

spec 含 name、type、instructions、maps；type 只接受 xdp、kprobe、tracepoint；指令条数超过 max_instructions 抛 EBPF_TOO_MANY_INSNS，最后一条不是单元素 exit 抛 EBPF_NO_EXIT，指令形状不对抛 EBPF_BAD_INSN。jump 的偏移不能为 0，目标必须落在指令范围内，越界抛 EBPF_BAD_JUMP；向后跳必须带 1 到 1000 的循环上界，缺上界抛 EBPF_UNBOUNDED_LOOP，上界非法抛 EBPF_BAD_BOUND。call 只能调用当前程序类型允许的 helper，未知 helper 抛 EBPF_HELPER_UNKNOWN，越权 helper 抛 EBPF_HELPER_DENIED；map_lookup 与 map_update 调用必须带第三个 map 名，缺名抛 EBPF_BAD_INSN，名字没在 spec 的 maps 里声明抛 EBPF_MAP_UNKNOWN。map 声明的 max_entries 与 value_size 必须为正，同名重复声明抛 EBPF_DUPLICATE_MAP。

load_program 是全有或全无：校验失败、程序数或 map 数超配额、map 字节超预算时，不得创建任何 map 或 program，rejected 加一；成功时返回 id、name、type、instructions 与 maps，id 从 1 单调递增且关闭后不回收，未知 program 抛 EBPF_PROG_UNKNOWN。每个租户分别计算 max_programs、max_maps、max_map_bytes，超过程序数抛 EBPF_PROG_QUOTA，超过 map 数抛 EBPF_MAP_QUOTA，超过字节预算抛 EBPF_MAP_MEMORY；set_quota 可逐项覆盖，非法值抛 EBPF_BAD_QUOTA。两个程序声明同名、同 max_entries、同 value_size 的 map 时共享同一份存储并增加 refs，任一项不同抛 EBPF_MAP_CONFLICT；close_program 自动摘掉该程序全部 hook，map 的 refs 减到 0 才释放并返还配额，返回 detached 与 freed_maps。

map_update 要求 key 长度 1 到 32，value 的 UTF-8 字节数超过 value_size 抛 EBPF_VALUE_TOO_LARGE，键不存在且已达 max_entries 时抛 EBPF_MAP_FULL，更新已有键不受容量限制；成功返回 name、key、used 与 created，map_lookup 对不存在的键返回 None，map 不存在抛 EBPF_MAP_UNKNOWN。program_info 返回 id、name、type、tenant、instructions、maps 与 attached，programs 与 maps 按租户列出，maps 每项含 name、max_entries、value_size、used、refs 与 bytes。attach 的 hook 全局唯一，已被占用抛 EBPF_HOOK_BUSY，空 hook 抛 EBPF_BAD_HOOK，成功返回 id、hook 与 attached；detach 只在确实由该程序持有时返回 True。程序的读写都必须带 tenant，跨租户访问程序抛 EBPF_TENANT_MISMATCH，同名 map 和 hook 在不同租户之间互不可见。stats 给出 loads、rejected、attaches、detaches、closed、map_updates、map_rejects、hook_busy；审计环形缓冲最多 audit_capacity 条。

snapshot 保存配额、next_id、程序、map 内容、hook、统计与审计；restore 之后下一次 load 的 id 必须大于快照里的最大 id，hook 与 map 数据保持可用，坏数据抛 EBPF_SNAPSHOT_INVALID。八个线程并发向容量为 5 的 map 写不同键时只能成功 5 次，其余全部抛 EBPF_MAP_FULL，map_updates 与 map_rejects 必须严格对应。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过或用固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 困难
