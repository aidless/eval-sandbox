# eval-sandbox

任务级沙盒隔离执行器 + 并发评测车队（`eval-fleet`）：给每一条 LLM 评测任务一个独立的网络/挂载/PID 命名空间 + 独立 cgroup v2，
把"任务跑了但不知道是不是被隔离了"变成"每条限制都有可执行断言和归因证据"；再多任务并发时，逐个任务断言隔离没有退化。

> **放在 `/home/liuzewen/eval-sandbox` 的原因**：与 `eval-gate`（判决层）、`rubric-support-qa`（判据层）
> 同级，是同一套求职作品集里的独立可 clone 仓库；不改动并行开发中的另外两个目录。

## 一条命令

```bash
python3 -m eval_sandbox.cli check    # 单任务隔离判据：10/10
python3 -m eval_sandbox.cli fleet    # 并发车队判据（N=20）：7/7
```

两条都输出逐条 PASS/FAIL 与证据 JSON（`evidence/run.json`、`evidence/fleet.json`），
任一判据不通过即非 0 退出。

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
`cgroup.procs`"只关得进 bwrap 自己（实测 `memory.current=0`，限额完全不生效）。正确做法是在 exec
之前让即将变成 bwrap 的那个进程自己写 `cgroup.procs`：用 `/bin/sh -c 'printf %s "$$" > "$1"; shift; exec "$@"'`
启动器完成——**不用 `preexec_fn`**，因为它在多线程编排器里 fork 后可能死锁，而 fleet 正是多线程并发调用。之后 fork 出来的后代天然继承成员关系。

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

pytest：`27 passed in 13.29s`（`python3 -m pytest -q`；加入 fleet 测试后共 43 个）。

### 负控制（证明不是"碰巧没网/碰巧没内存"）

| 对照 | 沙盒内 | 去掉该层隔离 |
|---|---|---|
| 外连 | `ENETUNREACH`，0.09s | `--share-net` 保留宿主 netns：`TimeoutError: timed out`，3.07s |
| 读宿主文件 | `ENOENT` | 不经沙盒直接读：`READ_UNEXPECTEDLY_OK` |
| 200MB 分配 | 被 OOM 杀 | 不经 cgroup 直接跑：`ALLOC_OK`，exit 0 |

前两条已固化为测试（`test_denial_comes_from_netns_not_from_upstream`、
`test_memory_bomb_would_succeed_without_cgroup_limit`），防止把"宿主本来就没网"误判成隔离生效。

## eval-fleet：并发车队（同一仓库的第二个能力点）

```bash
python3 -m eval_sandbox.cli fleet              # N=20（默认），一条命令跑完 7 条判据
python3 -m eval_sandbox.cli fleet --tasks 40 --spin 0.4
```

判据不是"能并发跑 20 个"，而是"20 个并发时**每一个**仍然被正确隔离和限额"。

### 并发模型：ThreadPoolExecutor（不是进程池，不是 asyncio）

- 每个任务本身就是独立 OS 进程（`bwrap`），线程只做 `Popen` + `communicate` + 收账，Python 侧没有共享可变状态；隔离来自命名空间和 cgroup，不来自 Python 的进程/线程边界。
- 不用进程池：会多复制 N 份解释器，除了增加内存开销并不带来额外隔离。
- 不用 asyncio：这里全部等待都是"等子进程退出"，`asyncio.create_subprocess_exec` 的收益不足以抵消复杂度。
- **它怎么保证判据 2、4**：`run()` 每次调用都独立 `CgroupLimit(...)`（uuid 后缀唯一）+ 独立 `mkdir` 出来的 workdir，然后 `--bind` 到该任务自己的 `/work`；cgroup 成员关系由启动器在 exec 前自写。线程之间不共享 cgroup、不共享目录，所以 20 个并发 = 20 个互不相干的隔离域；一个任务 OOM 只会打中自己那个 `memory.max`。
- 一处必须分开的东西：`run()` 的 `task_id`（进判决摘要，跨重跑稳定）与 `label`（进 cgroup 目录名，携带本轮 token 用于按标识查孤儿）。

### 8 条判据 → 可执行断言

| # | 判据 | CLI check id | 断言（全部为代码断言，不是描述） |
|---|---|---|---|
| 1 | 并发执行、显著快于串行 | `C1_concurrency` | 同 20 个任务先 `workers=1` 再 `workers=20`，断言 `t_conc < 0.5 * t_serial` |
| 2 | 并发下隔离不退化 | `C2_isolation_no_degradation` | 逐个断言：`RESULT.net == "denied:101"`（20/20）、`memory_peak <= 该任务自己的 memory.max`（20/20）、`cpu.stat.throttled_usec > 0` 且 `usage <= 配额×墙钟 + 一个 100ms 周期`（20/20）、20 个 `cgroup_path` 互不相同（20/20） |
| 3 | 互不干扰（反证） | `C3_cross_task_invisible` | 任务 A 写 `/work/shared.txt` 得到 `visible`；任务 B 对**同名文件**重试 10 次仍 `absent:2`（ENOENT） |
| 4 | 限额互相独立 | `C4_oom_isolated` | 20 个里恰好 1 个 `outcome=oom`，其余 19 个 `outcome=ok` |
| 5 | 无孤儿进程（含 leak test） | `C5_no_orphans` | 跑完后按 token 扫 `/proc/*/cgroup` 为空；再杀编排器（SIGKILL）复测：先观测到沙盒 pid，杀后 `residual=[]`，并清掉遗留空 cgroup 目录 |
| 6 | 每任务资源账 + 四类归因 | `C6_ledger_attribution` | 逐任务输出 wall / peak / cpu_ms；归因集必须覆盖 `{wall_timeout, oom, denied_fs, denied_network, nonzero_exit}` |
| 7 | 确定性 | `C7_determinism` | 同 20 个任务跑 3 次：逐任务 `verdict_sha256` 与汇总 sha256 全部一致 |
| 8 | 一条命令 + pytest | `SUMMARY` / pytest | 7/7 PASS 且非 0 退出即失败；pytest 43 个全绿 |

### 实测证据（2026-11-04，本机 16 核，纯 CPU）

并发 vs 串行（20 任务，每任务 0.4s 空转 + 网络/文件自检）：

| 轮次 | 串行 | 并发 | 加速 |
|---|---|---|---|
| #1 | 11.03s | 1.76s | 6.3x |
| #2 | 11.19s | 1.80s | 6.2x |
| #3 | 11.30s | 2.30s | 4.9x |
| #4（最终取证） | 15.94s | 2.08s | 7.6x |

逐任务资源账（最终取证那一轮；`cpu_quota=50%`，标准任务 `memory.max=128MB`，OOM 任务 `64MB`）：

```
task_id              kind       outcome       attribution      wall_s   peak_MB   cpu_ms  sha256
fleet-t00            standard   ok            ok                 0.49       8.4      253  bd322fc251
fleet-t01            standard   ok            ok                 0.52       6.4      256  e9bd493c50
fleet-t02            standard   ok            ok                 0.48       6.2      253  2d4108cdb4
fleet-t03            standard   ok            ok                 0.46       6.6      246  f2853ad933
fleet-t04            standard   ok            ok                 0.47       6.0      252  bc704464f9
fleet-t05            standard   ok            ok                 0.60       6.1      238  7a7e2e2bc3
fleet-t06            standard   ok            ok                 0.63       5.8      279  eea6d26b18
fleet-t07            standard   ok            ok                 0.65       5.7      293  0f69877644
fleet-t08            standard   ok            ok                 0.69       6.0      263  4e71ef9010
fleet-t09            standard   ok            ok                 0.73       6.1      289  75654eb5b7
fleet-t10            standard   ok            ok                 0.67       6.1      260  1812742f3e
fleet-t11            standard   ok            ok                 0.66       6.0      282  4e97b5e10b
fleet-t12            standard   ok            ok                 0.61       5.9      257  56db331e4c
fleet-t13            standard   ok            ok                 0.71       6.7      284  5aebfe23f8
fleet-t14            standard   ok            ok                 0.70       5.8      281  50016c5426
fleet-t15            standard   ok            ok                 0.67       6.0      270  4862b756e8
fleet-t16            standard   ok            ok                 0.70       5.8      288  cc806ccfa3
fleet-fs_writer      writer     ok            ok                 0.72       5.9      269  7b47d2fdf9
fleet-fs_reader      reader     ok            ok                 1.69       6.9      292  d025e55c7e
fleet-mem_oom        oom        oom           oom                0.83      64.0      346  8097e8a234
fleet-fault_timeout  timeout    wall_timeout  wall_timeout       3.25       5.2     1624  29da90c520
fleet-fault_fs       fs_denied  nonzero_exit  denied_fs          0.07       4.5       36  f5886972b5
fleet-fault_net      net_denied nonzero_exit  denied_network     0.09       7.6       51  49ea01e64d
fleet-fault_nonzero  nonzero    nonzero_exit  nonzero_exit       0.16       4.3       35  78ea6a0ddd
```

注：标准任务的峰值约 6MB 是 Python 解释器本身，和 128MB 上限差得很远——所以"没有超过上限"这条在
正常任务是宽松的；真正卡住上限的是 `fleet-mem_oom`（64.0MB / 64MB）。

OOM 只杀一个（前后计数）：`started=20 ok=19 oom=1 oom_task=mem_oom`；该任务 `memory.events.oom_kill>=1`，
其余 19 个任务的 `RESULT.net` 仍为 `denied:101` 且正常退出。

三次重跑（**三个独立进程**，不只是同一个进程内重复）：

```
run1 65c4936a847ddb92e2e7a8e4ba6889be0ec80395007f29ee87fd07a0e1b0b2af
run2 65c4936a847ddb92e2e7a8e4ba6889be0ec80395007f29ee87fd07a0e1b0b2af
run3 65c4936a847ddb92e2e7a8e4ba6889be0ec80395007f29ee87fd07a0e1b0b2af
aggregate all equal: True    per-task all equal: True    (24 条判决/轮)
```

孤儿进程检查：

```
after_run=[]                  跑完 20+4 个任务后按 token 扫 /proc/*/cgroup：空
leak_probe_observed=[3948997] 杀编排器前先证明"确实有沙盒进程在跑"
residual_after_kill=[]        对编排器发 SIGKILL 之后：空
swept=1 dirs                  同时清掉 1 个遗留空 cgroup 目录
```

一条设计决策需要说明：**OOM 的判决摘要不收录进程侧退出码和 stderr**。内核 OOM 与解释器自身
抛 `MemoryError` 存在竞态，机器忙时同一个负载可能拿到 137，也可能留下 MemoryError 栈并返回 1。
判决依据是内核事件 `memory.events.oom_kill`，把竞态噪声算进 sha 会让"重跑一致性"变成假失败。

pytest：`43 passed`（`python3 -m pytest -q`，三次连跑稳定），其中 `tests/test_fleet.py` 16 个。

## 明确没做的事（不要当成已实现）

1. **没有白名单出网**：只支持 `network="none"`。白名单需要 veth/slirp 一类，无 root 做不到；
   `Policy(network="whitelist")` 会直接 `ValueError`，不放假开关。
2. **不是容器**：没有镜像、没有文件系统快照、没有镜像内依赖隔离；只把宿主目录只读挂进去。
3. **越权读是"未挂载→ENOENT"，不是 DAC/ACL 拒绝**；越权写才是 `EROFS`。
4. **依赖非特权 userns**：内核关闭 userns 时整体不可用（fail-closed）。
5. **依赖 systemd 用户级 cgroup 委托**：拿不到可写子树时抛 `SandboxUnavailable` 并判 FAIL，
   **不退回 `prlimit` 假装"有内存上限"**。
6. **fleet 没有做的事**（这些不是"以后再补"，是目前确实没有）：
   - 没有任务队列/持久化/优先级/重试退避：一次 `fleet` 就是一轮内存里的 20 个任务，进程退出即结束；不是常驻服务。
   - 没有多机调度：并发上限受本机核数约束（本机 16 核，`cpu_quota=50%` 时 20 个任务 = 10 核）；40 个任务也能跑但会排到 CPU 后面。
   - 没有 GPU 维度、没有 `cgroup` I/O 限额、没有 seccomp 系统调用过滤、没有 DNS/流量统计。
   - 孤儿检查是"按本轮 cgroup token 扫 `/proc`" + "清空目录"，不是内核级进程树审计；不覆盖宿主上与本轮无关的进程。
   - 隔离强度仍受第 1–5 条限制（无白名单出网、非容器、依赖 userns 与 cgroup 委托）。
7. **无 CI 配置**：本机无远端仓库，未接 GitHub Actions；徽章待推送后再生效。

## 简历写法（LLM 评测工程师）

> 自研任务级沙盒执行器 + 并发评测车队（Python + bubblewrap + cgroup v2，仅标准库）：
> 每条任务独立 net/pid/uts/ipc/user/mount 命名空间与独立 cgroup，`memory.max`/`cpu.max`/`pids.max` 硬限额；
> 单任务 10 条隔离判据、车队 7 条判据全部可执行通过（含 3 条负控制证明隔离来自命名空间而非宿主环境）；
> 20 个任务并发时逐个断言外连仍 `ENETUNREACH`、峰值不超各自 `memory.max`、CPU 配额独立生效，
> 并发 2.08s vs 串行 15.94s（7.6x）；一个有意的 OOM 只杀它自己、其余 19 个正常完成；
> 杀编排器后无沙盒子进程残留；同一组任务重跑 3 次逐任务与汇总判决 sha256 一致（`65c4936a…`）；
> 43 个 pytest 全绿。

不写"实现了容器编排""分布式调度""支持白名单出网""千级批量压测"——这些没做。
