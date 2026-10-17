# -*- coding: utf-8 -*-
"""Node 运行环境探测（单一真源）。

node 可执行文件与 node_modules 目录的定位逻辑统一收口于此，三处消费方
（`core.ast_sidecar` / `core.deobf` / `recon.unbundle`）共用同一套策略，
避免各写一份候选链随环境漂移（历史上三处顺序/回退各不相同，已合并）。

**定位原则：环境驱动、动态发现，不钉死任何版本号或机器路径。**
开发期发现「把开发机路径写进源码」是移机失效的头号原因（换台机器整段失效、
还把开发者家目录带进发布物），故 managed 布局一律**动态扫描**（列版本目录
取最新，不写死 `22.x.y-z` 这类具体版本）：

  · node 二进制候选链：
      显式（配置键 `ast_node_bin` / 环境变量 `FACET_NODE_BIN`）
      → PATH（`shutil.which('node')`）
      → managed 布局动态扫描（`versions/<ver>/bin/node`，取最新存在者）
      → 常见系统路径（/usr/local/bin、/usr/bin）
  · node_modules 目录候选链：
      环境变量 `FACET_NODE_MODULES`（宽容两种约定：指向
      node_modules 本身或其父目录，两者都入候选）
      → managed workspace 动态探测（`workspace/node_modules`，存在才用）
      → 当前工作目录及父目录的标准 Node 解析（向上 3 层）

任何一环找不到即跳过或返回 None —— 由调用方决定降级（可用性**如实披露**，
不谎称可用），绝不因探测失败抛异常中断扫描。
"""
from __future__ import annotations

import os
import shutil

# managed Node 布局: <home>/.workbuddy-ai/binaries/node/{versions,workspace}
_MANAGED_HOME = os.path.join('.workbuddy-ai', 'binaries', 'node')
# 常见系统安装位置(仅作最后回退; PATH 优先)
_SYSTEM_NODE_PATHS = ('/usr/local/bin/node', '/usr/bin/node')
# 标准 Node 解析向上层数(当前目录 + 3 层父目录)
_CWD_WALK_DEPTH = 3


def _managed_root():
    """managed Node 布局根（`~/.workbuddy-ai/binaries/node`）；不存在返回 None。"""
    p = os.path.join(os.path.expanduser('~'), _MANAGED_HOME)
    return p if os.path.isdir(p) else None


def managed_node_bin():
    """managed 布局里的 node：列 `versions/` 取**最新**版本目录下的 bin/node。

    动态扫描（不钉版本号）—— 环境升级 Node 版本后无需改代码。
    """
    vroot = os.path.join(_managed_root() or '', 'versions')
    if not os.path.isdir(vroot):
        return None
    try:
        vers = sorted(os.listdir(vroot), reverse=True)
    except OSError:
        return None
    for ver in vers:
        p = os.path.join(vroot, ver, 'bin', 'node')
        if os.path.exists(p):
            return p
    return None


def managed_node_modules():
    """managed workspace 的 node_modules 目录（acorn / webcrack 等随环境预装位置）。"""
    p = os.path.join(_managed_root() or '', 'workspace', 'node_modules')
    return p if os.path.isdir(p) else None


def find_node(cfg=None):
    """node 可执行文件路径；全候选失败返回 None（调用方决定降级方式）。

    顺序: 配置键 `ast_node_bin` → 环境变量 `FACET_NODE_BIN` →
    PATH → managed 动态扫描 → 系统路径。`cfg` 仅 ast_sidecar 传入
    （其余消费方无配置上下文，走 env/PATH 即可）。
    """
    _c = (cfg or {}).get('ast_node_bin')
    if _c and os.path.exists(_c):
        return _c
    _e = os.environ.get('FACET_NODE_BIN')
    if _e and os.path.exists(_e):
        return _e
    _w = shutil.which('node')
    if _w:
        return _w
    _m = managed_node_bin()
    if _m:
        return _m
    for _p in _SYSTEM_NODE_PATHS:
        if os.path.exists(_p):
            return _p
    return None


def node_modules_dirs():
    """候选 node_modules 目录（去重保序；**不保证存在**，调用方按需 isdir 校验）。

    顺序: 环境变量 `FACET_NODE_MODULES`（宽容「目录本身/父目录」
    两种约定，两者都入候选）→ managed workspace（存在才用）→
    当前工作目录及父目录的标准 Node 解析（向上 3 层，与
    `recon.unbundle` 历史行为一致）。
    """
    dirs = []

    def _add(p):
        if p and p not in dirs:
            dirs.append(p)

    env_nm = os.environ.get('FACET_NODE_MODULES')
    if env_nm:
        _add(env_nm)                                  # 约定①: 直接指向 node_modules
        _add(os.path.join(env_nm, 'node_modules'))    # 约定②: 指向其父目录
    _add(managed_node_modules())
    cur = os.path.abspath(os.getcwd())
    for _ in range(_CWD_WALK_DEPTH + 1):
        _add(os.path.join(cur, 'node_modules'))
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return dirs


def find_module_dir(pkg):
    """在候选 node_modules 里找包 `pkg` 的目录；找不到返回 None。"""
    for d in node_modules_dirs():
        cand = os.path.join(d, pkg)
        if os.path.isdir(cand):
            return cand
    return None
