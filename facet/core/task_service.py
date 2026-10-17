# -*- coding: utf-8 -*-
"""facet 任务服务（供 MCP 等任务型入口共用）。

任务型入口不复制扫描逻辑，而是通过这里统一启动现有 CLI 子进程。
这样各入口使用同一套配置解析、限速、报告和合规门控。
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

def _default_output_dir() -> Path:
    """MCP 任务输出目录的默认基准（懒计算）。

    **绝不落进 site-packages**: pip 安装后包位于 site-packages，旧实现
    `PROJECT_ROOT = Path(__file__).parent.parent.parent` 会把默认输出目录
    解析成 `site-packages/output/gui`（系统 Python 上 mkdir 直接
    PermissionError；用户安装则污染安装目录且卸载不清）。委托
    `output.paths.project_root()`（源码检出→仓库根；pip 安装→当前工作目录；
    `FACET_OUTPUT_DIR` 显式指定优先）——与 CLI 产物同一基准。
    """
    from ..output.paths import project_root as _project_root
    return _project_root() / 'output' / 'gui'

# 任务型入口(MCP)只允许这些配置进入 CLI，避免把任意命令行参数暴露成远程执行入口。
# CLI 已精简为仅必要项：限速/并发/扩展侦察/规则库/代理/调试等调参全部下沉到
# ~/.facet/config.yaml / FACET_* 环境变量，不再经 CLI 暴露，故此处也不再透传。
# 如需调参，统一走 config.yaml；身份类(cookie/token)仍是必要 CLI 项，予以保留。
# **本表是 options 的唯一权威**: 调用方传未列出的键 → `_build_options` 直接报错(不静默忽略)，
# MCP `scan.options` 的 schema 也须与本表一致(由 `tests/test_entry_contract.py` 守护)。
VALUE_OPTIONS = {
    "cookie": "--cookie",
    "token": "--token",
}

# 调度/任务分配相关常量（"调度节点"审计轮新增）。
#   · 并发上限: 同时运行的扫描子进程数硬上限(此前**无上限**, 多任务请求会无限拉起完整
#     recon 子进程、无背压 → 主机资源耗尽风险); 超额任务进入**真实队列**(状态 'queued')。
#   · 父进程侧硬墙钟: 子进程自身的 SIGALRM 看门狗(`core/watchdog.py`)只在主线程生效,
#     极端情况下(不可中断的系统调用 / 子进程忽略 SIGTERM)可能失效 → 子进程永不退出、
#     `_collect` 永久阻塞、任务卡 'running' 永不终态。父进程收割线程作**兜底**。
MAX_CONCURRENT_DEFAULT = 2
PARENT_HARD_CEILING_SECONDS = 3600      # 单任务父侧存活硬上限(兜底, 远超正常 max_duration)
REAPER_INTERVAL_SECONDS = 30            # 收割线程巡检间隔


class TaskNotFound(KeyError):
    """任务 id 不存在（从未提交, 或已被终态修剪回收）。

    🔴 与"内部错误"语义**不同** —— 旧实现 `get()` 抛裸 `KeyError`, 被入口层的泛化
    `except Exception` 吞成同一种 `isError`, 调用方**无法区分**"id 打错了"与"服务出错了"。
    单列此异常类型, 让入口层能回**结构化 NotFound**(机器可读的 error code)。
    """

    def __init__(self, task_id: str):
        super().__init__(task_id)
        self.task_id = task_id


@dataclass
class TaskRecord:
    task_id: str
    target: str
    status: str = "queued"
    started_at: float = field(default_factory=time.time)
    # 实际**拉起子进程**(进入 'running')的时间戳; 与 `started_at`(入队时间)区分 ——
    # 收割线程的墙钟判定必须以"拉起时刻"为准, 否则长排队后刚拉起的任务会被误杀(缺陷 C)。
    launched_at: Optional[float] = None
    finished_at: Optional[float] = None
    returncode: Optional[int] = None
    logs: List[str] = field(default_factory=list)
    report_path: Optional[str] = None
    html_report_path: Optional[str] = None
    error: Optional[str] = None
    process: Optional[subprocess.Popen] = field(default=None, repr=False)
    # 内部字段(不进 snapshot): 调度用选项 + 停止请求标志。
    options: Optional[Dict[str, Any]] = field(default=None, repr=False)
    stop_requested: bool = field(default=False, repr=False)
    # 🔴 RLock(可重入): 旧实现用普通 Lock, 但 `_collect` 需在同一把锁内"持有锁 → 调 append_log
    #   (它也持同一把锁)" → 非重入锁会死锁; 且 `snapshot()` 在锁内读全部字段, 写入侧也必须统一经
    #   同一把锁, 否则读写竞争(读到半更新的 status/returncode)。
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def append_log(self, line: str) -> None:
        with self._lock:
            self.logs.append(line.rstrip("\n"))
            if len(self.logs) > 5000:
                del self.logs[:-5000]

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "task_id": self.task_id,
                "target": self.target,
                "status": self.status,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "returncode": self.returncode,
                "logs": list(self.logs),
                "report_path": self.report_path,
                "html_report_path": self.html_report_path,
                "error": self.error,
            }


class TaskManager:
    """线程安全的后台任务管理器（供 MCP 等任务型入口共用）。"""

    def __init__(self, output_dir: Optional[Path] = None,
                 max_concurrent: Optional[int] = None):
        self.output_dir = Path(output_dir or _default_output_dir()).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._tasks: Dict[str, TaskRecord] = {}
        self._lock = threading.Lock()
        # 并发上限: 同时运行的扫描子进程数硬上限(默认 2); 超额进入真实队列。
        mc = max_concurrent if max_concurrent is not None else MAX_CONCURRENT_DEFAULT
        self.max_concurrent = max(1, int(mc))
        # 父进程侧收割线程状态(懒启动, 仅在有任务时)。
        self._reaper_started = False
        self._reaper_stop: Optional[threading.Event] = None

    @staticmethod
    def _validate_target(target: str) -> str:
        target = str(target or "").strip()
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("目标必须是完整的 http/https URL")
        return target

    @staticmethod
    def _build_options(options: Optional[Dict[str, Any]]) -> List[str]:
        """把调用方给的 options 映射为 CLI 参数。

        🔴 **未知键必须报错, 不得静默忽略**: 旧实现只挑白名单键、其余**悄悄丢掉** ——
        MCP 的 `scan.options` schema 曾宣称支持 `modules/rate/threads/max_rpm`, 而这里
        只认 `cookie/token` → 调用方(尤其 AI 工作流)以为参数生效, 实际扫描用的是默认配置
        ("声明了却不生效"类缺陷, 与 generality 检查 M 同源)。现在未知键 → `ValueError`,
        错误信息同时给出**正确做法**(调参走 `~/.facet/config.yaml`)。
        """
        options = options or {}
        # 🔴 未知键**一律**报错(与值是否为空无关): 旧实现 `值非空才报` → `{"rate": ""}`
        #   被静默放过, 调用方以为传了参(全库审计 M14)。
        unknown = sorted(k for k in options if k not in VALUE_OPTIONS)
        if unknown:
            raise ValueError(
                "不支持的扫描参数: %s（仅支持 %s；其余调参请走 ~/.facet/config.yaml）"
                % (", ".join(unknown), ", ".join(sorted(VALUE_OPTIONS))))
        args: List[str] = []
        for key, flag in VALUE_OPTIONS.items():
            value = options.get(key)
            if value is not None and str(value).strip() != "":
                args.extend([flag, str(value).strip()])
        return args

    def start(self, target: str, options: Optional[Dict[str, Any]] = None,
              authorized: bool = False) -> Dict[str, Any]:
        if not authorized:
            raise PermissionError("必须确认目标属于自有资产或已获书面授权范围")
        target = self._validate_target(target)
        task_id = uuid.uuid4().hex[:12]
        html_path = self.output_dir / f"facet_{task_id}.html"
        task = TaskRecord(task_id=task_id, target=target,
                          report_path=str(html_path),
                          html_report_path=str(html_path),
                          options=options)
        with self._lock:
            self._tasks[task_id] = task
            self._prune_locked()
        self._ensure_reaper()
        # 调度: 有空闲槽位则立即提升为 running, 否则保持 'queued' 进入**真实队列**(有背压)。
        self._try_promote()
        return task.snapshot()

    # ---------- 调度 / 并发控制 ----------

    def _try_promote(self) -> List["TaskRecord"]:
        """持锁决策: 把排队的任务提升为 'starting'(预留槽位), 返回需实际拉起的列表。

        锁序约定: 始终 **先拿 TaskManager._lock, 再拿 task._lock**; `_collect` 终态后释放自身
        task._lock 再调用本方法, 不会反向持锁 → 无死锁。
        """
        to_launch: List["TaskRecord"] = []
        with self._lock:
            running = [t for t in self._tasks.values()
                       if t.status in ('running', 'starting')]
            if len(running) >= self.max_concurrent:
                return []
            queued = sorted([t for t in self._tasks.values() if t.status == 'queued'],
                            key=lambda t: t.started_at)
            for t in queued[:self.max_concurrent - len(running)]:
                with t._lock:
                    if t.stop_requested or t.status != 'queued':
                        continue
                    t.status = 'starting'
                to_launch.append(t)
        for t in to_launch:
            self._launch(t)
        return to_launch

    def _launch(self, task: "TaskRecord") -> None:
        """在 **锁外** 拉起子进程(避免持锁阻塞); 拉起失败即标记 failed。"""
        with task._lock:
            if task.stop_requested or task.status in ('stopped', 'completed', 'failed'):
                return
        cmd = [sys.executable, "-m", "facet.apps.cli", "-u", task.target,
               "-o", task.report_path, "--yes"]
        cmd.extend(self._build_options(task.options))
        env = os.environ.copy()
        env["FACET_NO_COLOR"] = "true"   # 保持 GUI 日志无 ANSI 颜色(等价旧 --no-color)
        # 子进程基准目录 = 任务输出目录的祖父目录(即 output/ 的基准, 与 CLI 产物
        # 同一解析规则 `output.paths.project_root`)。旧实现用
        # `Path(__file__).parent.parent.parent` —— pip 安装后即 **site-packages**,
        # 子进程 cwd/PYTHONPATH 钉进安装目录 → 扫描产物(report/downloads/state/
        # 审计日志)全落进 site-packages(只读环境直接失败, 可写环境污染安装目录)。
        root = str(self.output_dir.parent.parent)
        env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
        try:
            process = subprocess.Popen(
                cmd, cwd=root, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding='utf-8', errors='replace', bufsize=1,
            )
            with task._lock:
                task.process = process
                task.status = "running"
                task.launched_at = time.time()
                task.append_log("[GUI] 已启动 facet CLI 子进程")
            threading.Thread(target=self._collect, args=(task,),
                            daemon=True, name=f"collect-{task.task_id}").start()
        except Exception as exc:
            with task._lock:
                task.status = "failed"
                task.error = str(exc)
                task.finished_at = time.time()
                task.append_log("[GUI] 启动失败: %s" % exc)

    def _collect(self, task: "TaskRecord") -> None:
        process = task.process
        assert process is not None
        code = None
        try:
            assert process.stdout is not None
            for line in process.stdout:
                task.append_log(line)
            code = process.wait()
        except Exception as exc:
            with task._lock:
                task.error = str(exc)
        finally:
            with task._lock:
                task.finished_at = time.time()
                task.process = None
                if code is not None:
                    task.returncode = code
                if code is None:
                    # 采集异常路径: 从未拿到退出码。
                    if task.stop_requested:
                        task.status = "stopped"
                    else:
                        task.status = "failed"
                        if not task.error:
                            task.error = "子进程采集异常"
                elif code == 0:
                    task.status = "completed"
                elif task.stop_requested:
                    # 🔴 被本服务主动停止: 标记 'stopped'(而非 'failed') —— 终态可达
                    #   (旧实现 'stopping' 被 `_collect` 无条件覆盖成 'failed', 'stopped' 永不出现)。
                    task.status = "stopped"
                    task.error = None
                else:
                    task.status = "failed"
                    task.error = f"CLI 退出码: {code}"
        # 释放 task._lock 后再做"终态后清理 + 提升排队任务"(避免锁序反转死锁)。
        # 🔴 缺陷 A 修复: 旧实现 `_prune_locked` 仅在 `start()` 内调用 —— 任务全部终态后若不再
        #   有新的 `start()`, 内存任务表**永不修剪** → 长驻 MCP 进程无界增长。此处(每个任务终态
        #   的必经之路)调用, 保证即便没有新任务提交, 已完成的任务也会在超过 `_MAX_FINISHED_TASKS`
        #   后被回收(同时触发磁盘报告清理, 见 `_prune_locked`)。
        self._prune_locked()
        self._try_promote()

    # 已完成任务的保留上限(审计 OBS): 长驻进程(MCP)曾**永不清除**任务表, 无界增长。
    _MAX_FINISHED_TASKS = 200

    def _prune_locked(self):
        """持锁调用: 清理最早的**已完成**任务(运行中的永不清理)。

        🔴 缺陷 B 修复: 旧实现只把任务从**内存表**移除, 磁盘上的报告文件(HTML + JSON 两个主文件,
        以及任何未来点扩展名侧车)**从不删除** —— 长驻 MCP 进程的 `output_dir` 只增不减, 无界增长。
        现对每个被移除的任务调用 `_cleanup_task_files` 一并清理磁盘产物。
        """
        done = [t for t in self._tasks.values()
                if t.status in ('completed', 'failed', 'stopped') and not t.process]
        if len(done) <= self._MAX_FINISHED_TASKS:
            return
        done.sort(key=lambda t: t.finished_at or 0)
        for t in done[:len(done) - self._MAX_FINISHED_TASKS]:
            self._tasks.pop(t.task_id, None)
            self._cleanup_task_files(t)

    def _cleanup_task_files(self, task: "TaskRecord") -> None:
        """删除某任务在磁盘上的产出文件(被修剪出内存表时调用), 防止长驻进程无界增长。

        🔴 安全约束: 只删 **output_dir 内** 且文件名以 `facet_{task_id}.` 开头(点分隔扩展名)
        的文件 —— 既覆盖 HTML/JSON 两个主文件 + 任何未来侧车扩展名, 又**不会**误删其它任务的文件:
        任务 id 等长 12 hex, 点分隔确保不会前缀匹配到别的 id(例如 `facet_abc…4567.png`
        不会被 `facet_abc…456.*` 命中, 因为 456 之后是 `7` 而非点)。`report_path` /
        `html_report_path` 显式删除前均做 realpath 归属校验, 越界路径一律跳过。
        """
        out = self.output_dir
        tid = task.task_id
        candidates: List[str] = []
        # 显式主文件(report_path / html_report_path): 路径必须在 output_dir 内。
        for p in (task.report_path, task.html_report_path):
            if not p:
                continue
            try:
                rp = os.path.realpath(p)
                if os.path.commonpath([str(out), rp]) == str(out):
                    candidates.append(rp)
            except (ValueError, OSError):
                pass
        # 同 id 的全部点扩展名侧车(动态、不硬编码扩展名; 点分隔天然隔离其它 id)。
        for p in glob.glob(str(out / f"facet_{tid}.*")):
            candidates.append(os.path.realpath(p))
        for c in set(candidates):
            try:
                if os.path.isfile(c):
                    os.remove(c)
            except OSError:
                pass

    def stop(self, task_id: str) -> Dict[str, Any]:
        task = self.get(task_id)
        with task._lock:
            status = task.status
            process = task.process
            if status in ('completed', 'failed', 'stopped', 'cancelled'):
                # 已终态: 不再动(旧实现会把已完成任务的 status 误翻成 'stopping')。
                return task.snapshot()
            if status in ('queued', 'starting'):
                # 尚未拉起成子进程: 直接取消, 永不启动(槽位随之释放, _try_promote 会补位)。
                task.stop_requested = True
                task.status = "stopped"
                task.finished_at = time.time()
                task.append_log("[GUI] 已取消排队任务")
                return task.snapshot()
            # 运行中: 标记停止请求 + 短暂 'stopping' 瞬态, 待 `_collect` 终态为 'stopped'。
            task.stop_requested = True
            task.status = "stopping"
            task.append_log("[GUI] 已请求停止任务")
        # 终止在锁外(避免持锁阻塞 wait()); 升级 kill(子进程无视 SIGTERM 时强制杀)。
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=3)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        return task.snapshot()

    # ---------- 父进程侧兜底收割(孤儿任务保护) ----------

    def _ensure_reaper(self) -> None:
        with self._lock:
            if self._reaper_started:
                return
            self._reaper_started = True
            self._reaper_stop = threading.Event()
        th = threading.Thread(target=self._reaper_loop, daemon=True,
                              name="facet-task-reaper")
        th.start()

    def _reaper_loop(self) -> None:
        assert self._reaper_stop is not None
        while not self._reaper_stop.wait(timeout=REAPER_INTERVAL_SECONDS):
            self._reap_once()

    def _reap_once(self) -> None:
        """单次巡检: 终止超过父侧硬墙钟的 running/starting 任务(孤儿兜底)。

        🔴 缺陷 C 修复: 墙钟判定必须以**拉起时刻**(`launched_at`)为准, 而非入队时刻
        (`started_at`)。旧实现用 `started_at` → 一个"长期排队、刚被提升拉起"的任务会被立即误杀
        (排队时间被算进存活时间)。`launched_at` 未设置(仍 'starting' 瞬态)时回退到 `started_at`。
        提取为独立方法以便单测(不必等待 30s 巡检间隔)。锁序: self._lock → t._lock。"""
        try:
            over: List["TaskRecord"] = []
            with self._lock:
                for t in self._tasks.values():
                    if t.status in ('running', 'starting'):
                        age_base = t.launched_at if t.launched_at is not None else t.started_at
                        if (time.time() - age_base) > PARENT_HARD_CEILING_SECONDS:
                            over.append(t)
            for t in over:
                with t._lock:
                    if t.stop_requested or t.status not in ('running', 'starting'):
                        continue
                    t.stop_requested = True
                    proc = t.process
                    t.status = "stopping"
                if proc is not None and proc.poll() is None:
                    try:
                        proc.terminate()
                        proc.wait(timeout=3)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
            # 兜底修剪: 即便没有新 `start()` / 新 `_collect`, 周期巡检也能回收过量已完成任务。
            self._prune_locked()
        except Exception:
            pass

    def shutdown(self) -> None:
        """停止收割线程(进程退出前调用; 已 daemon, 非必须)。"""
        stop = self._reaper_stop
        if stop is not None:
            stop.set()

    def get(self, task_id: str) -> TaskRecord:
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            # 结构化异常: 入口层据此回 NotFound(而非与内部错误混同)。
            raise TaskNotFound(task_id)
        return task

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            tasks = list(self._tasks.values())
        return [task.snapshot() for task in reversed(tasks)]
