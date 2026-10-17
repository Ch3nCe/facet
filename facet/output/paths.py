# -*- coding: utf-8 -*-
"""统一输出路径。

所有运行产物（报告 / 端点标注 / 词表 / 抓取到的 JS / 状态 / 审计日志 / Web GUI 报告）
默认落在**项目根的 `output/`** 下，便于集中管理与清理。

    output/
    ├── surfacesight_report.html / .recon_matrix.json    # CLI 默认产物
    ├── downloads/<host>/                                  # 抓取到的 JS
    ├── gui/                                               # Web GUI 任务报告
    ├── surfacesight_audit.log                             # 审计日志
    └── .surfacesight_state.json / surfacesight_state.db    # 断点续扫状态
"""
from __future__ import annotations

import os
from pathlib import Path

OUTPUT_NAME = "output"


def _reject_traversal(label, value):
    """纵深防御: 拒绝 name/sub 中的 '..' 或解析为绝对路径, 防止路径穿越逃出 output/ 基准目录。

    返回 None 表示安全; 否则抛 ValueError。归一后若含 '..' 段(或本就是绝对路径)即拒绝。
    """
    if not value:
        return
    v = str(value)
    if os.path.isabs(v):
        raise ValueError(f"{label} 不允许为绝对路径: {v!r}")
    parts = [p for p in os.path.normpath(v).split(os.sep) if p not in ('', '.')]
    if any(p == '..' for p in parts):
        raise ValueError(f"{label} 不允许包含路径穿越片段('..'): {v!r}")


def project_root() -> Path:
    """产物基准目录。

    - **源码检出**：仓库根（与 `surfacesight/` 同层存在 `pyproject.toml`）。
    - **pip 安装**：包位于 `site-packages`，其上层没有 `pyproject.toml` → 回退到**当前工作目录**。

    绝不把产物写进 `site-packages`：那会污染安装目录，目录只读时直接失败，且多环境互相覆盖。
    可用环境变量 `SURFACESIGHT_OUTPUT_DIR` 显式指定基准目录。
    """
    env = os.environ.get("SURFACESIGHT_OUTPUT_DIR")
    if env:
        return Path(env).expanduser()
    root = Path(__file__).resolve().parent.parent.parent   # 仓库根 或 site-packages
    if (root / "pyproject.toml").is_file():
        return root
    return Path.cwd()


def output_dir(sub: str | None = None, create: bool = True) -> Path:
    """返回 output/ 目录（可指定子目录）；默认确保存在。"""
    _reject_traversal('sub', sub)
    d = project_root() / OUTPUT_NAME
    if sub:
        d = d / sub
    if create:
        d.mkdir(parents=True, exist_ok=True)
    return d


def output_path(name: str, sub: str | None = None, create: bool = True) -> Path:
    """返回 output/ 下某个文件路径（不创建文件本身）。"""
    _reject_traversal('name', name)
    _reject_traversal('sub', sub)
    return output_dir(sub, create=create) / name


def default_output_file(name: str, sub: str | None = None) -> str:
    """默认输出文件的**字符串路径**（不建目录，供配置默认值使用）。"""
    _reject_traversal('name', name)
    _reject_traversal('sub', sub)
    d = project_root() / OUTPUT_NAME
    if sub:
        d = d / sub
    return str(d / name)


def ensure_parent(path) -> None:
    """确保某文件路径的**父目录存在**（报告 / 导出 / 侧车写入前调用）。

    修复 D5: `default_output_file()` 只拼路径、**不建目录**; 而此前唯一建目录的是
    `orchestrator.save_js`(仅当有 JS 落盘时才建 `output/`)。因此"输出目录不存在 +
    未落盘任何 JS"(如熔断导致 0 JS) 时, 报告写入会 `FileNotFoundError`(实测复现)。
    写入前统一 `mkdir -p` 父目录, 与"落没落 JS"解耦。

    纵深防御: 拒绝路径穿越片段('..')。**威胁模型**: 路径来自本机调用方(CLI -o /
    配置文件), 非攻击者可控 —— 此检查是防**笔误**(如 `out/../x` 写到意料之外),
    而非安全边界; `-o` 允许绝对路径(用户写自己机器的任意位置是合法意图),
    故这里不像 `_reject_traversal` 那样拒绝对路径(审计: 两道防线强度不同是有意的)。
    """
    p = str(path)
    # normpath 后若仍含 '..' 段, 即存在穿越意图 → 拒绝
    if '..' in [seg for seg in os.path.normpath(p).split(os.sep)]:
        raise ValueError(f"输出路径不允许包含穿越片段('..'): {p!r}")
    d = os.path.dirname(os.path.abspath(p))
    if d:
        os.makedirs(d, exist_ok=True)
