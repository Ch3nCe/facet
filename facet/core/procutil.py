# -*- coding: utf-8 -*-
"""Robust external-process execution.

The naive ``subprocess.run(..., capture_output=True, timeout=X)`` is unsafe when the
child spawns grandchildren that inherit the stdout/stderr pipe FDs: on timeout,
``subprocess.run`` only SIGTERMs the *direct* child, so its internal
``communicate()`` blocks forever waiting for the pipe's EOF (the classic
pipe-deadlock). That let a single Node/webcrack subprocess hang an entire scan with
no recovery.

``run_capture`` uses ``start_new_session=True`` so the child gets its own process
group, and on timeout kills the *whole group* (SIGKILL) before draining — guaranteeing
the call always returns.
"""
import os
import signal
import subprocess

_POSIX = os.name == 'posix'


def run_capture(args, timeout, input_text=None, env=None, text=True, encoding='utf-8'):
    """Run a command, capturing stdout/stderr, killing the process group on timeout.

    Returns ``(returncode, stdout, stderr)``. On timeout the whole process group is
    SIGKILLed and ``subprocess.TimeoutExpired`` is re-raised so callers can degrade
    gracefully (exactly as they did with the old ``subprocess.run`` call).
    """
    if _POSIX:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=(subprocess.PIPE if input_text is not None else None),
            start_new_session=True,
            env=env,
            text=text,
            encoding=encoding,
            errors='replace',
        )
    else:  # pragma: no cover - non-POSIX fallback (no process-group kill available)
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=(subprocess.PIPE if input_text is not None else None),
            env=env,
            text=text,
            encoding=encoding,
            errors='replace',
        )
    try:
        out, err = proc.communicate(input=input_text, timeout=timeout)
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        if _POSIX:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        else:  # pragma: no cover
            try:
                proc.kill()
            except Exception:
                pass
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            out, err = ('', '') if text else (b'', b'')
        raise
    except BaseException:
        # 非 TimeoutExpired 的意外异常(信号中断/内存错误)此前直接外抛 → 子进程与
        #   管道 FD 靠 GC 回收, 子进程可能残留。先杀干净再抛(审计 L)。
        try:
            if _POSIX:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except Exception:
            pass
        raise

