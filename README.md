# GSB Bugfix Task

## 题面

机房灰度批次连续两次因为 kexec 镜像校验被回滚：运维把已吊销的签名密钥又拿回来签了一个救援内核，加载接口照收；同一张镜像被重复 load，槽位里的字节数按两份计算，总预算提前耗尽；镜像摘要大小写混用也能过；没有签名的调试镜像在策略关闭之前混进了生产槽位；镜像从槽位 boot 之后还能重新 load 并再 boot 一次；镜像加载后密钥被吊销，boot 仍然放行；被拉黑的摘要照样能启动；两个槽位被不同租户的镜像交叉占用；槽位下标越界只返回空；重启后已启动摘要的墓碑丢了，旧镜像可以重放；八个运维同时 boot 同一个槽位，全部报成功。修复范围在模块 gsb/batch46-safety-e-10 的 kexec_image_guard.py，类型 KexecGuard，任务类型 Bugfix，只用 Python 标准库，失败统一抛 KexecError，异常对象带 code 与 detail。

接口按骨架保持：expected_signature(key_id: str, image_name: str, digest: str) -> str、add_key(self, key_id: str, *, kind: str = "rsa") -> dict、revoke_key(self, key_id: str) -> bool、key_info(self, key_id: str) -> dict、load_image(self, slot: int, image: dict, *, tenant: str = "default") -> dict、staged(self, slot: int, *, tenant: str = "default") -> dict | None、unload(self, slot: int, *, tenant: str = "default") -> bool、boot(self, slot: int, *, tenant: str = "default") -> dict、blacklist(self, digest: str) -> bool、usage(self) -> dict、stats(self) -> dict、audit(self, limit: int | None = None) -> list[dict]、snapshot(self) -> str、restore(cls, data: str) -> "KexecGuard"。

expected_signature 固定返回 sha256("key_id:image_name:digest") 的十六进制串，load_image 收到的 image 含 name、digest、size、key_id、signature。digest 必须是 64 位小写十六进制，否则抛 KEXEC_BAD_DIGEST；name 为空或 size 非正整数抛 KEXEC_BAD_IMAGE。密钥 kind 只接受 rsa 与 ecdsa，重复添加抛 KEXEC_KEY_EXISTS，非法 key 抛 KEXEC_BAD_KEY，未知密钥抛 KEXEC_KEY_UNKNOWN；revoke_key 对已吊销的密钥返回 False，吊销后再加载该密钥签名的镜像抛 KEXEC_KEY_REVOKED。

未带密钥且未带签名的镜像默认抛 KEXEC_UNSIGNED，只有构造参数 allow_unsigned 为真时才接受并把 verified 记为 False；带密钥却缺签名也抛 KEXEC_UNSIGNED，签名值与 expected_signature 不符抛 KEXEC_BAD_SIGNATURE。单张镜像超过 max_image_bytes 或所有槽位合计超过 max_total_bytes 都抛 KEXEC_IMAGE_TOO_LARGE，失败时槽位与字节计数都不能变化。slot 必须在 0 到 slot_count-1 之间，越界抛 KEXEC_BAD_SLOT；槽位已占用时，同 name、同 digest、同 size 的重复加载返回 status 为 already 且不重复计字节，内容不同则抛 KEXEC_SLOT_BUSY。

load_image 返回 status、slot、name、digest、size、verified 与 usage，usage 至少含 bytes、slots、slot_count、limit_bytes，重复加载计入 duplicates。boot 是一次性的：成功后清空槽位、返还字节、把摘要记入已启动墓碑，再次 boot 同一槽位抛 KEXEC_SLOT_EMPTY；已启动过的摘要重新加载抛 KEXEC_ALREADY_BOOTED；成功 boot 返回 slot、name、digest 与 verified。加载后密钥被吊销，boot 抛 KEXEC_KEY_REVOKED 且镜像留在槽位；摘要被加入黑名单后 boot 抛 KEXEC_BLACKLISTED，槽位同样保留；所有失败的 boot 都计入 denied_boots。staged、unload、boot 都要校验 tenant，租户不符抛 KEXEC_TENANT_MISMATCH，unload 成功才返还字节，空槽位 unload 返回 False。

stats 给出 loads、rejected、boots、denied_boots、unloads、duplicates；审计环形缓冲最多 audit_capacity 条，审计行含 event 与 code，记录 load、duplicate、reject、boot、boot_denied、unload。staged 返回 slot、name、digest、size、key_id、verified、tenant，空槽位返回 None；key_info 返回 kind 与 revoked 标记，unknown 密钥抛 KEXEC_KEY_UNKNOWN。snapshot 保存密钥及吊销状态、槽位内容、已启动墓碑、黑名单、统计和审计；restore 后 staged、boot 判定、黑名单、usage 与统计必须一致，坏数据抛 KEXEC_SNAPSHOT_INVALID。

八个线程同时 boot 同一个已装载槽位，只能有一个成功，其余必须拿到 KEXEC_SLOT_EMPTY；八个线程同时向同一个空槽位加载不同镜像，只能有一个 staged，其余 KEXEC_SLOT_BUSY，usage 只计一份字节。

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
