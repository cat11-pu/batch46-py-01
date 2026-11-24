# GSB Bugfix Task

## 题面

镜像构建机的 overlay 清理任务上个月出了一次事故：安全组把一份含密钥的配置文件从镜像里删掉，构建产物里它却原样从 lower 层复活了，因为清理脚本把 upper 里的 whiteout 当普通文件删了；同时 opaque 目录下堆积了上千个已经没用的 whiteout，每层 diff 越滚越大；并发清理同一 layer 时 journal 只留下最后一条，机器断电后无法判断哪些 whiteout 是完整的；另一个小组复现时还发现，rename 一个上层目录会把 lower 的旧内容重新暴露出来，根因是源目录没有留下 opaque。代码在 gsb/batch46-safety-e-05 的 overlayfs_whiteout_guard.py，OverlayGuard 负责 lower/upper 层表、合并视图解析、whiteout 与 opaque 的生成、rename、orphan 清理、compact、journal 与快照，任务类型 Bugfix。请按下面接口实现：

add_lower(self, layer: str, entries: Sequence[dict]) -> dict
add_upper(self, path: str, kind: str, *, content: str | None = None, origin: str | None = None) -> dict
resolve(self, path: str) -> dict
list_merged(self, path: str, *, recursive: bool = False) -> list[dict]
remove(self, path: str, *, recursive: bool = False) -> dict
rename(self, src: str, dst: str) -> dict
cleanup(self, *, dry_run: bool = False) -> dict
compact(self) -> dict
stats(self) -> dict
journal(self, limit: int | None = None) -> list[dict]
snapshot(self) -> dict
restore(self, snapshot: dict) -> dict

需要修正的行为：

1. resolve 的优先级固定为 upper 精确项、opaque 祖先、lower 层登记顺序、absent，返回要带 path、kind、layer、content、hidden_by、opaque；upper 普通文件覆盖同名 lower。
2. whiteout 只遮住 lower 的同名项，返回 kind=absent、hidden_by=whiteout；opaque 目录遮住其下全部 lower 项，返回 hidden_by=opaque:<目录>，但之后新加在 opaque 下的 upper 子项必须仍然可见。
3. remove 一个只存在 upper 的文件时直接删除，不得留下 whiteout；remove 一个 lower 也存在的文件时必须留下 whiteout；对已经 whiteout 的路径重复 remove 返回 unchanged；完全不存在报 OP_NOT_FOUND。
4. remove lower 目录且其下有子项时必须 recursive=True，否则报 OP_NOT_EMPTY；递归删除生成 opaque 目录；lower 空目录可以直接用非递归 remove 生成 opaque。
5. remove upper 目录存在 upper 子项时非递归报 OP_NOT_EMPTY；递归时要先清掉整棵 upper 子树，再按 lower 是否存在生成 opaque。
6. add_upper 遇到已存在路径报 OP_EXISTS，kind 不是 file/dir/whiteout/opaque 报 OP_KIND_INVALID，upper 条目数超过 max_entries 报 OP_LIMIT 且不写入。
7. rename 目录要搬走整棵 upper 子树，源路径按 lower 情况生成 opaque 或什么也不留，目标路径下所有子项仍能解析；rename 文件到 lower 同名文件允许覆盖，源只有在 lower 有同名项时才留 whiteout。
8. rename 源不存在或是 whiteout 报 OP_NOT_FOUND，目标是已有 upper 或 lower 目录报 OP_DST_EXISTS，目标落在源子树内报 OP_INVALID_MOVE，源与目标相同返回 unchanged。
9. cleanup 只删除没有 lower 对应项的 orphan whiteout 和 orphan opaque，dry_run 只报告不改状态，同一状态第二次 cleanup 的 count 必须为 0，有 lower 对应项的 whiteout 不能删。
10. compact 只删除被 opaque 祖先覆盖的冗余 whiteout，opaque 外的 whiteout 保留；compact 后这些路径仍要因 opaque 祖先返回 absent。
11. add_upper、remove、rename、cleanup、compact 每次都要写 journal，seq 严格自增，只保留最近 max_journal 条；stats 要给出 lowers、upper、whiteouts、opaque、journal、seq。
12. snapshot 必须深拷贝 lowers、upper、journal 与 seq，restore 后 upper 表和 journal 一起回退到快照时点；非法快照报 OP_SNAPSHOT_INVALID，且当前层表不被破坏。

硬约束：8 个线程同时删除不同的 lower 文件时，每一个都必须生成 whiteout，最终 whiteouts=8，journal 在 max_journal=5 下保留连续 seq 4 到 8，不能丢中间记录也不能重复编号；remove 和 rename 的层表更新要么整体成功要么不留痕迹；快照恢复要能当作崩溃后的重启路径，把 diff 与 journal 一起还原；upper 条目和 journal 都是硬上限。

验收标准：在项目根执行 python3 -m pytest -q tests，15 条测试必须全部通过；不得修改测试、跳过或用固定输入写死结果；并发删除与快照恢复请自行用线程和 restore 验证；只做本地实现，不操作真实挂载点。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- difficulty: 困难
