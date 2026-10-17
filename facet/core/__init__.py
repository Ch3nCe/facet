# -*- coding: utf-8 -*-
"""核心子包：配置 / 上下文 / 字典（单一事实来源）/ 共享基础设施。

本门面只 re-export **基础设施层(layer1)与数据层(layer0)** 的符号
（config / dicts / context / log / rate / history / util）。
编排层（orchestrator / task_service, layer3）**不在此 re-export** ——
保持门面不越层（见 audit/generality 检查 K）：外部统一从**具体子模块**导入
（如 `from facet.core.orchestrator import recon_deep`）。
"""
from .config import *  # noqa: F401,F403
from .config import KNOWN_MODULES, expand_modules, load_config  # noqa: F401
from .context import ScanContext  # noqa: F401
from .dicts import *  # noqa: F401,F403
from .history import ScanHistory  # noqa: F401  (扫描历史 / diff)

# 基础设施层符号直接 re-export（同源子模块, 非经 engine 中转 —— 门面不越层）
from .log import SEV_STYLE, Color, clog, dbg, log  # noqa: F401  (着色 / 日志)
from .rate import RateManager  # noqa: F401  (限速器)
from .util import _extract_paths_from_obj, _host_of  # noqa: F401  (URL 工具)
