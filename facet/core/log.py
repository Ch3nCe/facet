# -*- coding: utf-8 -*-
"""输出 / 日志工具（**基础设施层**）—— 原从 `core/engine.py` 下沉（该门面已删除）。

动机（架构一致性）：`report/` 与 `recon/` 需要 `log`，若从编排层（原 `core/engine.py`）导入即为
**向上依赖**（领域层 → 编排层）。下沉到本模块后，各层都向下引用，依赖方向单一。

含：`Color` / `SEV_STYLE` / `clog` / `log` / `dbg`。
"""
import os


class Color:
    RESET = '\033[0m'; BOLD = '\033[1m'
    RED = '\033[31m'; GREEN = '\033[32m'; YELLOW = '\033[33m'
    MAGENTA = '\033[35m'; CYAN = '\033[36m'; GREY = '\033[90m'
    BG_RED = '\033[41;97m'; BG_YELLOW = '\033[43;30m'


SEV_STYLE = {'CRITICAL': (Color.BG_RED + Color.BOLD, '!'),
             'HIGH': (Color.RED, '!'),
             'MED': (Color.YELLOW, '~'),
             'LOW': (Color.DIM if hasattr(Color, 'DIM') else '', '.'),
             'INFO': (Color.CYAN, 'i')}


def _enable_win_color():
    if os.name == 'nt':
        try:
            import colorama
            colorama.just_fix_windows_console()
        except Exception:
            pass


_enable_win_color()


def clog(tag, msg, color=Color.CYAN):
    print(f'{Color.BOLD}{color}{tag}{Color.RESET} {msg}', flush=True)


def log(m):
    print(f'[+] {m}', flush=True)


def dbg(m):
    """调试通道: 仅在 `FACET_DEBUG` 环境变量置位时输出。

    用于原本被 `except Exception: pass` 静默吞掉的增强能力(SCA / 自定义规则 / 解码层等)——
    正常运行时保持安静, 排障时 `FACET_DEBUG=1` 即可看到失败原因, 不再"黑盒吞异常"。
    """
    if os.environ.get('FACET_DEBUG'):
        print(f'[dbg] {m}', flush=True)
