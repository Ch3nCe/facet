# -*- coding: utf-8 -*-
"""Hard wall-clock watchdog for a single scan.

``recon_deep`` is synchronous; individual I/O and subprocess ops are guarded by their
own timeouts, but a pathological case (a stalled socket read that never EOFs, a
CPU-bound regex spin, an orphaned child) could still block forever. This installs a
SIGALRM-based deadline that raises ``ScanGlobalTimeout`` in the main thread,
interrupting even a blocking read, so a scan can never hang indefinitely.

Disabled automatically when not on the main thread (signals are main-thread only) or on
non-POSIX platforms — the per-operation timeouts and the between-request time budget
(``max_duration``) still provide best-effort bounds there.
"""
import os
import signal
import threading


class ScanGlobalTimeout(BaseException):
    """Raised when a scan exceeds its global time budget.

    **必须继承 `BaseException` 而非 `Exception`**（实测缺陷）：管线里大量「增强能力失败不影响
    主流程」的广谱 `except Exception as e: log(...)` 会把本异常**当成普通错误吞掉**，而
    `signal.alarm` 是**一次性**的 → 吞掉之后整条扫描**再无期限**。实测表现：`max_duration=300`
    的扫描跑满 **20 分钟以上**仍未结束（日志里可见
    `[-] JS 阶段指纹补判异常: scan exceeded global budget of 1200s` 这类被吞掉的痕迹）。

    继承 `BaseException` 后，广谱 `except Exception` 不再拦截它；CLI 顶层的
    `except ScanGlobalTimeout`（显式捕获）与各层 `finally` 仍照常生效。
    """


# 兼容性说明: `except Exception` 捕获不到本异常是**有意为之**（见上）；调用方必须显式
#   `except ScanGlobalTimeout` —— CLI 已如此处理（`apps/cli.py`）。


# 重新武装的**短宽限**(秒)。
#   超时异常若在传播路径上被上层收尾挡住(asyncio 事件循环关闭 / 子进程清理 / `finally`)，
#   看门狗必须**再次投递**才生效 —— 这是重新武装存在的理由。
#   🔴 但旧实现按**完整** `limit_seconds` 重新武装：首次投递被挡后要再等**一整个预算**才二次
#   触发 → **有效墙钟 = 2 × max_duration**（实测：`max_duration=600` 的扫描跑了 **20m05s**，
#   而预算确实在 600s 被切断过）。改为短宽限后，预算在首次投递后 ≤ 本值秒内强制生效，
#   有效墙钟 ≈ 1 × 预算 + 宽限。
_REARM_GRACE_SECONDS = 5


def _rearm_seconds(limit_seconds):
    """重新武装的间隔 —— 取**短宽限**（不得按完整预算再等一轮）。

    预算比宽限还小时仍用预算（保持"最多再等 limit"的语义）；至少 1s，避免退化成
    `signal.alarm(0)`（= 取消，反而使看门狗彻底失效）。
    """
    try:
        return max(1, min(int(limit_seconds), int(_REARM_GRACE_SECONDS)))
    except (TypeError, ValueError):
        return 1


_warned_unavailable = False


def _warn_unavailable(reason):
    """看门狗不可用的**一次性**可见告警 —— 此前静默返回 None, 用户以为有硬墙钟(审计 M12/L)。"""
    global _warned_unavailable
    if _warned_unavailable:
        return
    _warned_unavailable = True
    try:
        print(f'[i] 全局看门狗不可用({reason}): max_duration 本次不生效, '
              f'其余护栏(请求预算/熔断)仍有效')
    except Exception:
        pass


def install_scan_watchdog(limit_seconds):
    """Install a SIGALRM deadline. Returns the previous handler (a token) or None."""
    if not limit_seconds or limit_seconds <= 0:
        return None
    if os.name != 'posix' or not hasattr(signal, 'alarm'):
        _warn_unavailable('当前平台不支持 SIGALRM(非 POSIX)')
        return None
    if threading.current_thread() is not threading.main_thread():
        _warn_unavailable('非主线程(SIGALRM 只投递给主线程)')
        return None

    def _handler(signum, frame):  # pragma: no cover - signal delivery path
        # **重新武装**: `signal.alarm` 是一次性的。若超时异常在传播路径上被某段 `finally`/
        #   子进程清理（如 `subprocess` 收尾等待 Node/webcrack 子进程退出）**挡住**，一次性
        #   deadline 就再也不会触发 → 扫描照样无限挂起（实测：`max_duration=300` 的扫描跑满
        #   20 分钟以上，而同参数的另一次运行 5 分钟就正常结束 = 非确定性卡死）。
        #   重新武装后，最多再等 `_rearm_seconds()`（短宽限）就会被再次中断 —— **不得**按
        #   完整 `limit_seconds` 武装，否则有效墙钟会变成 2 × 预算（见 `_REARM_GRACE_SECONDS`）。
        #   调用方**必须在捕获本异常后立即 `cancel_scan_watchdog()`**，否则报告生成阶段会被误中断。
        try:
            signal.alarm(_rearm_seconds(limit_seconds))
        except (ValueError, OSError):
            pass
        raise ScanGlobalTimeout(
            'scan exceeded global budget of %ss' % int(limit_seconds))

    try:
        old = signal.signal(signal.SIGALRM, _handler)
        signal.alarm(int(limit_seconds))
        return old
    except (ValueError, OSError):
        return None


def cancel_scan_watchdog(token):
    """Cancel the watchdog and restore the previous handler."""
    if token is None:
        return
    try:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, token)
    except (ValueError, OSError, TypeError):
        pass
