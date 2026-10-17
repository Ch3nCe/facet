# -*- coding: utf-8 -*-
"""构建产物拆包（webpack / browserify，webcrack 可选 sidecar）
  · 把 **webcrack 作为可选外部工具**调用（需要 Node）：
        webcrack bundle.js -o out-dir   →  还原出模块树
  · facet 对**每个模块**单独跑 deep_analyze，并把"模块 → 源 chunk"映射记入报告
    （可复用于 chunk 覆盖率校验）。
  · **降级**：Node / webcrack 不可用 → 调用方自动退回现有 `_beautify_js` + 正则通道，
    行为与未开启时完全一致（本模块 `webcrack_available()` 返回 False 即可判定）。

**结构还原（模块边界）与语义还原（表达式/拼接）互补。**

本模块零硬依赖：webcrack 的定位顺序为
  ① 环境变量 `FACET_WEBCRACK`（webcrack CLI 的 .js 路径或可执行文件）
  ② PATH 上的 `webcrack`
  ③ 候选 `node_modules` 动态探测（env `FACET_NODE_MODULES` / managed
     workspace / cwd 标准解析，委托 `core.nodeenv` 单一真源）
找不到时**不报错**，仅令 `webcrack_available()` 为 False。
"""
import glob
import os
import shutil
import subprocess
import time

from ..core import nodeenv
from ..core.procutil import run_capture

# 构建产物特征标记（用于判断"是否值得拆包"）—— P1: 从 webpack/browserify 拓宽到
#   vite / rollup / esbuild / swc / parcel，使这些产物被**识别并尝试拆包 + 如实披露**，
#   而不是当普通 JS 静默跳过（现代前端 esbuild/vite 占比已很高）。
BUNDLE_MARKERS = (
    # webpack
    '__webpack_require__', 'webpackChunk', 'webpackJsonp',
    '/******/', '__webpack_modules__',
    # browserify
    'browserify',
    # vite / rollup（ESM chunk 化: 运行时预加载/依赖映射/查询注入）
    '__vite__mapDeps', '__vitePreload', '__vite__injectQuery', '__vite__rewrite',
    # esbuild（注入的 CJS/ESM 互操作助手）
    '__commonJS(', '__toESM(', '__toCommonJS(', '__esbuild',
    # swc（注入的类/模块助手）
    '_interop_require_default', '_interop_require_wildcard',
    '_class_call_check', '_inherits(',
    # parcel（模块运行时）
    'parcelRequire', '$parcel$',
)

# 构建器类型识别（报告如实披露"识别到哪类产物"，也用于决定拆包预期）。
#   注: webcrack 原生强项是 webpack/browserify；vite/esbuild/swc/parcel 先"识别 + 尝试 + 披露"，
#   拆包不理想时由调用方的"原文 ∪ 还原产物并集"兜底（见 orchestrator._unbundle_and_analyze）。
_BUNDLE_KIND_MARKERS = (
    ('webpack', ('__webpack_require__', 'webpackChunk', 'webpackJsonp', '__webpack_modules__')),
    ('browserify', ('browserify',)),
    ('vite', ('__vite__mapDeps', '__vitePreload', '__vite__injectQuery', '__vite__rewrite')),
    ('esbuild', ('__commonJS(', '__toESM(', '__toCommonJS(', '__esbuild')),
    ('swc', ('_interop_require_default', '_interop_require_wildcard', '_class_call_check')),
    ('parcel', ('parcelRequire', '$parcel$')),
)


def detect_bundle_kind(text):
    """识别构建产物类型（webpack/browserify/vite/esbuild/swc/parcel），未识别返回 None。

    仅做特征串判定（不执行、不解析），用于报告如实披露与拆包预期判断。
    """
    if not text:
        return None
    for name, markers in _BUNDLE_KIND_MARKERS:
        if any(m in text for m in markers):
            return name
    return None


def _node_bin():
    """定位 node：环境驱动优先（显式 → PATH → managed 动态扫描 → 系统路径 → 'node'）。

    委托 core.nodeenv 单一真源（与 core/deobf、core/ast_sidecar 同一候选链）。
    """
    return nodeenv.find_node() or 'node'


def _candidate_roots():
    """webcrack 可能的 node_modules 目录候选（去重保序）—— 委托 core.nodeenv 单一真源。"""
    return nodeenv.node_modules_dirs()


def webcrack_cmd():
    """返回调用 webcrack 的 argv 前缀（不含输入文件），找不到返回 None

    返回形如 ['node', '/path/to/webcrack.js'] 或 ['/usr/local/bin/webcrack']。
    """
    env = os.environ.get('FACET_WEBCRACK')
    if env:
        if env.endswith('.js'):
            return [_node_bin(), env]
        return [env]
    w = shutil.which('webcrack')
    if w:
        return [w]
    for nm in _candidate_roots():
        # ① 优先用 npm 生成的 .bin 软链（版本无关，最稳）
        binp = os.path.join(nm, '.bin', 'webcrack')
        if os.path.exists(binp):
            return [binp]
        # ② 退而解析 package.json 的 bin 字段（webcrack 实际入口是 src/cli-wrapper.js）
        pkg = os.path.join(nm, 'webcrack', 'package.json')
        if os.path.exists(pkg):
            try:
                import json
                with open(pkg, encoding='utf-8') as f:
                    data = json.load(f)
                b = data.get('bin')
                if isinstance(b, dict):
                    b = b.get('webcrack')
                if b:
                    return [_node_bin(), os.path.join(nm, 'webcrack', b)]
            except Exception:
                pass
    return None


def webcrack_available():
    """webcrack 是否可用（决定是否走拆包通道 / 是否降级）"""
    return webcrack_cmd() is not None


def is_bundle(text, min_len=15000):
    """粗判"是否是值得拆包的构建产物"

    需同时满足：文本足够长(默认 >=15KB) 且 含 webpack/browserify 特征标记。
    宁可漏判(退回普通分析)也不误判(对普通 JS 调用 webcrack 白耗时间)。
    """
    if not text or len(text) < min_len:
        return False
    return any(m in text for m in BUNDLE_MARKERS)


def collect_modules(out_dir):
    """收集拆包产物里的模块文件（.js），排序返回"""
    if not out_dir or not os.path.isdir(out_dir):
        return []
    return sorted(glob.glob(os.path.join(out_dir, '**', '*.js'), recursive=True))


def prune_unbundled(parent_dir, keep, keep_dir=None):
    """保留 `parent_dir` 下**最近**的 `keep` 个产物目录, 删除更早的（`keep<=0` → 不清理）。

    背景: `unbundle_file` 在目标目录已存在时改用**唯一名**（见其 docstring: 为避开
    "rmtree 批量删除被环境护栏拦断"）→ **每次重扫都会新增一个目录** → 产物随重跑**无界累积**
    （实测 `output/.../unbundled/` 越跑越大）。此处按 mtime 保留最近 N 个: 既限制增长,
    又保留近期产物作为可审计证据。

    `keep_dir`（本次正在使用的目录）**永不删除**。删除**尽力而为**: 单个目录失败只计数, 不影响扫描。
    返回 (已删除数, 失败数)。并发跑同一目标时可能误删对方的新目录 —— 本工具为单进程顺序扫描, 不涉及。
    """
    try:
        if not parent_dir or not os.path.isdir(parent_dir):
            return (0, 0)
        keep = int(keep or 0)
        if keep <= 0:
            return (0, 0)
        entries = []
        for nm in os.listdir(parent_dir):
            p = os.path.join(parent_dir, nm)
            if not os.path.isdir(p):
                continue
            try:
                entries.append((os.path.getmtime(p), p))
            except OSError:
                continue
        entries.sort(key=lambda t: t[0], reverse=True)      # 最新在前
        dropped = failed = 0
        for _mt, p in entries[keep:]:
            if keep_dir and os.path.abspath(p) == os.path.abspath(keep_dir):
                continue
            try:
                shutil.rmtree(p)
                dropped += 1
            except Exception:
                failed += 1
        return (dropped, failed)
    except Exception:
        return (0, 0)


def unbundle_file(js_path, out_dir, timeout=120):
    """对单个 bundle 执行 webcrack 拆包

    Returns: {'ok': bool, 'modules': [abs paths], 'cmd': str, 'err': str}
    · webcrack 不可用 → ok=False, err='webcrack not found'（调用方据此降级）
    · 执行异常/超时/非 0 退出 → ok=False 且 err 带原因；**绝不抛异常**
    """
    cmd = webcrack_cmd()
    if cmd is None:
        return {'ok': False, 'modules': [], 'cmd': '', 'err': 'webcrack not found'}
    # 注意: webcrack **要求 -o 目录不存在**（存在即报 "output directory already exists"）。
    #   **旧实现**在目录已存在时 `shutil.rmtree` 清掉上次产物 —— 重跑同一目标时会**一次性删除
    #   数百个文件**（实测 531 个），被运行环境的安全护栏（批量删除需确认）**拦断整个进程**
    #   （实测 `EXIT=1`，扫描在拆包阶段直接死掉，报告都出不来）。
    #   现改为**每次用唯一目录、不做任何删除**：唯一名天然满足"目录不存在"的前置条件，
    #   既不需要 rmtree（去掉不可逆删除），也不会覆盖上次的产物（保留为可审计证据）。
    try:
        os.makedirs(os.path.dirname(out_dir) or '.', exist_ok=True)
        if os.path.isdir(out_dir):
            out_dir = '%s-%d-%d' % (out_dir.rstrip(os.sep), os.getpid(),
                                    int(time.time() * 1000) % 100000)
    except Exception as e:
        return {'ok': False, 'modules': [], 'cmd': '', 'err': f'prepare out_dir failed: {e}',
                'out_dir': out_dir}
    full = list(cmd) + [js_path, '-o', out_dir]
    try:
        rc, _out, err = run_capture(full, timeout)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'modules': collect_modules(out_dir),
                'cmd': ' '.join(full), 'err': 'timeout', 'out_dir': out_dir}
    except Exception as e:
        return {'ok': False, 'modules': [], 'cmd': ' '.join(full), 'err': str(e),
                'out_dir': out_dir}
    return {'ok': rc == 0, 'modules': collect_modules(out_dir),
            'cmd': ' '.join(full), 'err': (err or '')[:500], 'out_dir': out_dir}
