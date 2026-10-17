# -*- coding: utf-8 -*-
"""报告子包：单页 HTML 总览 + 机器可读 JSON / 侧车。

人读报告各章节合并在一个 HTML 文件中，页内导航跳转；JSON 与 SARIF/Burp/ZAP 等机器消费格式独立输出。
（已弃用的 Markdown 渲染器 report() 已移除；人读报告统一为单页 HTML。）
"""
from .exporters import (  # noqa: F401
    write_burp,
    write_exports,
    write_sarif,
    write_zap,
)
from .report import (  # noqa: F401
    build_recon_matrix,
    report_html,
    report_json,
    write_diff_json,
    write_endpoints_json,
    write_recon_matrix,
    write_recovered_json,
    write_replay_sh,
)
