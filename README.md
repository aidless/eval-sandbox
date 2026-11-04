# eval-sandbox

任务级沙盒隔离执行器：给每一条 LLM 评测任务一个独立的网络/挂载/PID 命名空间 + 独立 cgroup v2，
把"任务跑了但不知道是不是被隔离了"变成"每条限制都有可执行断言和归因证据"。

> **放在 `/home/liuzewen/eval-sandbox` 的原因**：与 `eval-gate`（判决层）、`rubric-support-qa`（判据层）
> 同级，是同一套求职作品集里的独立可 clone 仓库；不改动并行开发中的另外两个目录。

## 一条命令

```bash
python3 -m eval_sandbox.cli check
```

输出逐条 PASS/FAIL 与 `evidence/run.json`，任一判据不通过即非 0 退出。

前置条件（不满足则**直接拒绝执行**，不会降级成"没隔离也算过"）：

| 依赖 | 本机实测值 |
|---|---|
| bubblewrap | `/usr/bin/bwrap` 0.9.0 |
| 非特权 user namespace | `unprivileged_userns_clone = 1` |
| cgroup v2 可写子树 | `/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service`（systemd 用户管理器 Delegate） |
| Python | 3.12.3（仅标准库 + pytest） |

## 三层隔离与各自的可观测点

| 层 | 实现 | 结果里能看到什么 |
|---|---|---|
| 网络 | `bwrap --unshare-all`（net/pid/uts/ipc/user/cgroup 全断），仅保留 `lo` | `stderr` 里的 `[Errno 101] Network is unreachable`、耗时 0.09s |
| 文件系统 | 挂载白名单：`/usr` `/lib` `/lib64` 只读，仅 `workdir` 可写挂到 `/work` | 越权读 `ENOENT`、越权写 `[Errno 30] Read-only file system` |
| 资源 | 自建 cgroup v2 子组：`memory.max` / `memory.swap.max=0` / `cpu.max` / `pids.max` | `memory.events.oom_kill`、`memory.peak`、`cpu.stat.throttled_usec` |
| 墙钟 | 监督者 deadline + `cgroup.kill` 整树击杀 | `outcome=wall_timeout`、`exit=-9` |
| 判决 | canonical JSON（task_id/outcome/exit/输出哈希/limits）→ sha256 | `verdict_sha256` |

关键实现细节：bwrap 的 `--unshare-pid` 会再 fork 出真正的负载，所以"把 Popen 的 pid 写进
`cgroup.procs`"只关得进 bwrap 自己（实测 `memory.current=0`，限额完全不生效）。正确做法是在
`preexec_fn` 里让即将 exec 的子进程自写 cgroup，之后所有后代天然继承成员关系。

## 判据 → 断言对照

| 判据 | case | 断言 |
|---|---|---|
| 外连失败且报错可读 | `net_external_denied` | `outcome != ok` + stderr 含 `DENIED` + 耗时 < 2s（排除静默超时） |
| 允许的本地资源可访问 | `net_loopback_allowed` | 沙盒内 `127.0.0.1` 自连成功、回传 `ping` |
| 越权读被拒 | `fs_read_outside_denied` | 宿主路径在沙盒内 `ENOENT` |
| 越权写被拒 | `fs_write_system_denied` | 写 `/usr/lib` 得到 `EROFS` |
| 工作目录可写 | `fs_workdir_readwrite` | 写入后读回字节一致 |
| 死循环被墙钟杀 | `res_wall_timeout` | `outcome=wall_timeout`，实际 2.02s（上限 2s） |
| 内存超限被拒且可归因 | `res_memory_oom` | `outcome=oom`、`oom_kill=1`、`peak=67108864/67108864` |
| CPU 限额生效 | `res_cpu_quota` | 50% 配额下 `usage=1045066us`、`throttled=998918us`（2.07s 墙钟） |
| 进程数限额生效 | `res_pids_limit` | `pids.max=16` 时 fork 40 个得到 `EAGAIN` |
| 确定性 | `det_repeat3` | 3 次运行 `verdict_sha256` 全部相同 |

## 实测证据（2026-11-04，本机）

```
net_external_denied      network      nonzero_exit     PASS
    stderr='DENIED OSError: [Errno 101] Network is unreachable' 0.09s
net_loopback_allowed     network      ok               PASS
    stdout='LOOPBACK_OK ping'
fs_read_outside_denied   filesystem   nonzero_exit     PASS
    stderr="DENIED FileNotFoundError: [Errno 2] No such file or directory: '.../secret.txt'"
fs_write_system_denied   filesystem   nonzero_exit     PASS
    stderr="DENIED OSError: [Errno 30] Read-only file system: '/usr/lib/.esbx-write-probe'"
fs_workdir_readwrite     filesystem   ok               PASS
res_wall_timeout         resource     wall_timeout     PASS
    outcome=wall_timeout exit=-9 2.02s
res_memory_oom           resource     oom              PASS
    outcome=oom oom_kill=1 peak=67108864/67108864
res_cpu_quota            resource     ok               PASS
    usage=1045066us throttled=998918us wall=2.07s
res_pids_limit           resource     nonzero_exit     PASS
    stderr='DENIED BlockingIOError: [Errno 11] Resource temporarily unavailable'
det_repeat3              determinism  ok               PASS
    3 次 sha256=c8731d03843141c7ce5c7d01cb4178cf50013d0b17da771db89b13e7b402d23b（全部一致）

SUMMARY: 10/10 PASS        （墙钟 5.2s）
```

pytest：`27 passed in 13.29s`（`python3 -m pytest -q`）。

### 负控制（证明不是"碰巧没网/碰巧没内存"）

| 对照 | 沙盒内 | 去掉该层隔离 |
|---|---|---|
| 外连 | `ENETUNREACH`，0.09s | `--share-net` 保留宿主 netns：`TimeoutError: timed out`，3.07s |
| 读宿主文件 | `ENOENT` | 不经沙盒直接读：`READ_UNEXPECTEDLY_OK` |
| 200MB 分配 | 被 OOM 杀 | 不经 cgroup 直接跑：`ALLOC_OK`，exit 0 |

前两条已固化为测试（`test_denial_comes_from_netns_not_from_upstream`、
`test_memory_bomb_would_succeed_without_cgroup_limit`），防止把"宿主本来就没网"误判成隔离生效。

## 明确没做的事（不要当成已实现）

1. **没有白名单出网**：只支持 `network="none"`。白名单需要 veth/slirp 一类，无 root 做不到；
   `Policy(network="whitelist")` 会直接 `ValueError`，不放假开关。
2. **不是容器**：没有镜像、没有文件系统快照、没有镜像内依赖隔离；只把宿主目录只读挂进去。
3. **越权读是"未挂载→ENOENT"，不是 DAC/ACL 拒绝**；越权写才是 `EROFS`。
4. **依赖非特权 userns**：内核关闭 userns 时整体不可用（fail-closed）。
5. **依赖 systemd 用户级 cgroup 委托**：拿不到可写子树时抛 `SandboxUnavailable` 并判 FAIL，
   **不退回 `prlimit` 假装"有内存上限"**。
6. **未做**：并发 fleet / 20 任务容器编排、GPU 隔离、seccomp 系统调用过滤、DNS 与流量统计、
   cgroup I/O 限额。这些属于 `eval-fleet` 与后续里程碑，不在本仓。
7. **无 CI 配置**：本机无远端仓库，未接 GitHub Actions；徽章待推送后再生效。

## 简历写法（LLM 评测工程师）

> 自研任务级沙盒执行器（Python + bubblewrap + cgroup v2）：为每条评测任务创建独立
> net/pid/uts/ipc/user/mount 命名空间与独立 cgroup，`memory.max`/`cpu.max`/`pids.max` 硬限额，
> 10 条隔离判据全部可执行通过，含 3 条负控制（证明隔离来自命名空间而非宿主环境）；
> 超时/OOM/越权三类失败可归因（`oom_kill` 计数、`cgroup.kill` 整树击杀），
> 同一任务重复 3 次判决 sha256 一致（`c8731d03…`）；27 个 pytest 全绿。

不写"实现了容器编排""支持白名单出网"——这两条没做。
