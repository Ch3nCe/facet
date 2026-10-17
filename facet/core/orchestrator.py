# -*- coding: utf-8 -*-
"""扫描调度 / 编排层 —— 原从 `core/engine.py` 拆出（便于维护）。

职责：**只做流程编排**（按步骤调用下层能力），不实现具体算法。
主入口 `recon_deep(ctx, base, mods, token)` —— 一次扫描的完整步骤序列：
  启动准备 → 步骤0-2 被动打点/指纹/首页 → 2.5-2.56 页面/JS 收割 → 2.7-2.10 扩展枚举
  → 步骤3 JS 管线 → 3.5-3.6 运行时/复盘 → 步骤4 探活/模块 → 4.5 表单→端点关联
  → 5-7 元数据/可选验证/落盘 → 收尾（归一去重/路径推断/表单关联/历史）。

依赖：从下层子模块取用能力（const / dicts / http / js_extract / probe 等）；下层不反向依赖本模块。
"""
import hashlib
import json
import os
import re
import time
import traceback
from contextlib import closing
from urllib.parse import urljoin, urlparse, urlsplit

from ..recon.fingerprint import ROUTE_RULES, get_enabled_rules
from .asset_enum import (
    _looks_non_english,
    crawl_site,
    extract_page_links,
    passive_recon,
)
from .const import _DEV_SERVER_HINTS, _output_dir, plugins
from .deobf import _beautify_js, decode_layer, looks_like_js_encoding
from .dicts import (
    FRONTEND_STACKS,
    GENERIC_API_GUESS_PATHS,
    JS_EXTS,
    JS_FILE_NAMES_COMMON,
    RE_LINK_JS,
    RE_SRC,
    ROUTE_ENTRY_GUESSES,
    ROUTE_ENTRY_GUESSES_I18N,
    apply_extract_rules,
    derive_ext_vocab,
    entry_like,
    get_hidden_paths,
    get_js_priority,
    infer_path_variants,
    is_static_or_malformed_path,
    is_third_party,
    load_extract_rules,
    normalize_endpoint,
    static_asset_exts,
    VENDOR_SNIFF_BANNERS,
    VENDOR_SNIFF_LIBS,
    VENDOR_URL_TOKENS,
)
from .guard import _fingerprint_resp, classify_page_type, should_run_runtime
from .html_extract import (
    _drain_wasm_ref,
    _extract_html_apis,
    _extract_html_forms_comments,
    _extract_inline_scripts,
    _extract_sourcemap,
    _fetch_build_manifests,
    _resolve_form_body_links,
)
from .http import REQ, _fetch_js, normalize_base, warm_up_session
from .js_extract import _is_plausible_api_path, _same_origin, deep_analyze, modules_of
from .log import dbg, log
from .probe import (
    _ensure_catchall_baseline,
    _probe_req,
    detect_and_probe,
    hidden_probe,
    options_probe,
    probe,
    probe_new_fingerprints,
)
from .secret import _check_url_leak, _verify_secrets_pass
from .tls import _tls_cert_info
from .util import _extract_paths_from_obj


# ---------- 端点证据分级(演进建议 R1 · 借鉴 JsOwl evidence 分级) ----------
#   采集渠道天然分四桶: 运行时观测 > 规格/baseURL 重建 > 静态字面量 > 字典/推断猜测。
#   同一路径多来源命中时**只升不降**(bump), 保留最强证据。
_EV_RANK = {'runtime': 3, 'full-url': 2, 'static': 1, 'dict': 0}


def _ev_bump(out, tier, paths):
    """把 paths 标记为 tier(只升不降)。out['evidence'] 为 path → tier 映射。"""
    if not paths:
        return
    ev = out.setdefault('evidence', {})
    r = _EV_RANK.get(tier, 1)
    for p in paths:
        if _EV_RANK.get(ev.get(p), -1) < r:
            ev[p] = tier


# ---------- 库 bundle 嗅探(演进建议 R2 · 借鉴 JsOwl skip_library_bundles) ----------
def _vendor_sniff(url, text, nbytes=None):
    """判断 JS 是否第三方库 bundle。返回 None(业务) 或判据标签('banner' / 'path')。

    双重判据(保守优先, 防误杀业务代码):
      · banner: **文件头的许可注释块内**同时出现版权标记与已知库名 → vendor。
        (库名只在注释块里找, 不在整个 sniff 窗口找 —— 业务包带 `@license` 头注释、
         下方代码调用 axios 极常见, 窗口放大会把自有业务包误判为库。)
      · path:   URL 路径命中库产物形态 token(vendor/chunk-vendors/polyfills…) → vendor。
    命中后调用方跳过深度分析(AST/正则/sourcemap/拆包/反混淆), 但保留资源清单与
    指纹补判的头尾采样 —— 省下的是纯开销, 不损失"目标接口"发现与框架识别。
    """
    if not text:
        return None
    _zone = text[:int(nbytes or 2048)].lower()
    # 仅取**第一个**许可注释块(文件头)作为 banner 区。
    # 关键: 不可放大到后续注释块 —— 首方应用 dist 常把所依赖第三方库的 license 注释
    #   紧随其后(如 prosemirror/lodash 的 @license 头, 内含库名), 若并入 banner 区会把
    #   首方业务包误判为 vendor 而整体跳过(实测 TOAST UI Editor 即此情形)。本函数本就
    #   以"库名只在文件头注释块里找"为原则, 此前 range(3) 的窗口放大正好踩中该误杀。
    _p = _zone.find('*/')
    _banner_end = _p + 2 if _p >= 0 else -1
    if _banner_end > 0:
        _head_block = _zone[:_banner_end]
        if any(b in _head_block for b in VENDOR_SNIFF_BANNERS):
            if any(lib in _head_block for lib in VENDOR_SNIFF_LIBS):
                return 'banner'
    h = (url or '').lower()
    if any(t in h for t in VENDOR_URL_TOKENS):
        return 'path'
    return None


# 文档站**代码块 chunk**(VitePress 把 Markdown 代码块编译为 `<page>.html-<hash>.js`) ——
#   内容为**文档代码示例**(非目标自身代码), 其中的 `/api/...` 是示例而非真实接口
#   (实测 macrozheng 的 `/api/CommonResult`·`/api/api` 即来自这类 chunk)。
#   按**文件名形态**识别(非站点白名单): `<name>.html-<hash>.js`。
_DOC_CODE_CHUNK_RE = re.compile(r'\.html-[A-Za-z0-9_-]+\.(?:m)?js$', re.I)


def _is_doc_code_chunk(url):
    """是否文档站代码块 chunk(→ 跳过深度分析, 避免把文档示例当真实端点; 仍计入清单并披露)。"""
    try:
        return bool(_DOC_CODE_CHUNK_RE.search(urlsplit(url or '').path))
    except Exception:
        return False


def _harvest_page_assets(ctx, base, url, html, out, js_urls, enabled, fp_hits):
    """从**一个页面**的 HTML 收割 JS 引用与端点。

    **入口页收割(步骤2.6)与 SPA 路由收割(步骤3.7)共用同一实现** —— 两处各写一份必然漂移
    (项目铁律: 同一判断只留一处实现)。

    ②  `<script src>` 的同源 .js → js_urls(步骤3 统一分析 / SourceMap / 递归抓取);
    ②a `<link rel=modulepreload / preload-as-script href>` 声明的 JS chunk —— SPA 常以此预加载
        路由懒加载包, 这些 .js 不在 `<script src>` 里(RE_SRC 抓不到), 但静态 GET 页面即可拿到;
    ②b 页面声明的端点(与首页同逻辑: action=/href=/data-* 属性);
    ②c 表单字段 / 隐藏域 / HTML 注释(可能带 token/key);
    ②d 内联脚本(也可能含端点 / 写操作)。

    返回**新增**的 JS 引用数。
    """
    n_js = 0
    for su in RE_SRC.findall(html):
        sau = urljoin(url, su)
        if urlsplit(sau).path.endswith(JS_EXTS) and _same_origin(sau, base):
            if sau not in js_urls:
                js_urls.add(sau)
                n_js += 1
    for su in RE_LINK_JS.findall(html):
        sau = urljoin(url, su)
        if urlsplit(sau).path.endswith(JS_EXTS) and _same_origin(sau, base):
            if sau not in js_urls:
                js_urls.add(sau)
                n_js += 1
    try:
        out['apis'] |= _extract_html_apis(html, url)
    except Exception as e:
        dbg(f'页面端点提取 {url}: {e}')
    try:
        _extract_html_forms_comments(html, ctx, out, url)
    except Exception as e:
        dbg(f'页面表单/注释提取 {url}: {e}')
    try:
        for _i, _blk in enumerate(_extract_inline_scripts(html)):
            _dec = decode_layer(_beautify_js(_blk))
            _res = deep_analyze(ctx, _dec, f'{url}#inline-{_i}', base, enabled, fp_hits,
                                allow_source_only=False)
            _merge_out(out, _res)
            out['write_apis'].update(_res.get('write_apis', {}))
    except Exception as e:
        dbg(f'页面内联脚本分析 {url}: {e}')
    return n_js


def _harvest_route_entry_js(ctx, base, html, out, js_urls, enabled, fp_hits):
    """非首页"入口页"JS 收割（默认开; 同源只读 GET; 受全局护栏约束）

    解决: 接口/JS 藏在 /login /dashboard /admin 等非首页路由——这些页要么**不在首页**
    静态 HTML 里被链接(BFS 爬取抓不到), 要么 SPA 客户端渲染(静态也看不到其懒加载 chunk)。
    本阶段不替代 crawl_site(后者是更深的 BFS), 而是补一组**高价值入口页猜测**, 让
    "非首页才加载的 JS" 默认就能被覆盖:
       ① 候选页 = 首页发现的同源链接 + ROUTE_ENTRY_GUESSES 猜测;
       ② 对每个候选页被动 GET, 提取其 <script src> JS(同源 .js)并入 js_urls(步骤3 统一分析 /
          SourceMap / 递归), 同时抽取页面声明的端点 / 表单参数 / 内联脚本(与首页同逻辑);
       ③ 边界: 同源 / GET-only / 不提交表单 / 不登录 / 受 max_pages 上限与 REQ 限速·熔断·预算约束;
          404/403 仅记录路径(可能是隐藏接口线索), 不解析 JS。
    返回 (n_pages_fetched, n_js_added) 供日志与披露。
    """
    if not ctx.config.get('route_harvest', True):
        return (0, 0)
    _mp = int(ctx.config.get('max_pages', 15) or 15)
    if _mp <= 0:
        return (0, 0)
    _bp = urlsplit(base)
    # ① 首页发现的同源链接(已经在首页 HTML 里被链接的二级页) —— 真实存在的页面, 优先级最高
    _link_seeds = extract_page_links(html, base) if html else set()
    # ①b 高价值入口页猜测(同源); 非英文站点再追加本地化猜测(避免英文站白跑一堆 404)
    _guess_seeds = {f'{_bp.scheme}://{_bp.netloc}/{g}' for g in ROUTE_ENTRY_GUESSES}
    if _looks_non_english(html):
        _guess_seeds |= {f'{_bp.scheme}://{_bp.netloc}/{g}' for g in ROUTE_ENTRY_GUESSES_I18N}
    seeds = _link_seeds | _guess_seeds
    # 过滤: 排除首页本身 / 非同源 / 静态资源; 去 fragment
    seeds = {s.split('#', 1)[0] for s in seeds
             if s.split('#', 1)[0].rstrip('/') != base.rstrip('/')
             and urlsplit(s).netloc == _bp.netloc
             and not urlsplit(s).path.lower().endswith(static_asset_exts())}
    # 排序(关键): 真实首页链接里"形似入口页"的**最优先**(最可能藏接口/JS), 其次其它真实链接,
    #   最后才是猜测 —— 避免"猜测"把 max_pages 配额挤占光, 也避免字母序丢掉高价值页。
    def _tier(u):
        _is_link = u in _link_seeds
        _el = entry_like(urlsplit(u).path)
        return 0 if (_is_link and _el) else (1 if _is_link else 2)
    seeds = sorted(seeds, key=lambda u: (_tier(u), u))
    # 自适应上限: 真实"入口页"链接多于默认上限时**抬高上限**以覆盖它们(硬顶 60 或 max_pages*3),
    #   避免高价值入口页被低默认值截断; 仍被截断的如实登记(报告"扫描完整性"披露)。
    _n_entry_links = sum(1 for u in seeds if u in _link_seeds and entry_like(urlsplit(u).path))
    _mp_eff = min(max(_mp, _n_entry_links), max(_mp, min(_mp * 3, 60)))
    if len(seeds) > _mp_eff:
        ctx.note_truncated('route_harvest_pages', len(seeds) - _mp_eff)
        log(f'[*] 入口页收割: 候选 {len(seeds)} 个, 按自适应上限取前 {_mp_eff} 个(其余已登记截断)')
    seeds = seeds[:_mp_eff]
    n_pages, n_js = 0, 0
    for url in seeds:
        r = REQ(ctx, 'GET', url)
        if r is None:
            continue
        _st = getattr(r, 'status_code', 0)
        if _st >= 400:
            # 401/403 = 受保护(可能存在)的入口页, 记录路径作"隐藏接口"线索;
            # 404 = 不存在的猜测, 不污染候选集。均不解析 JS。
            if _st in (401, 403):
                _lp = urlsplit(url).path or '/'
                if _lp and _lp != '/':
                    out['apis'].add(_lp)
            continue
        _html = getattr(r, 'text', '') or ''
        _ctype = ''
        try:
            _ctype = (r.headers.get('Content-Type') or '')
        except Exception as e:
            dbg(f'入口页 Content-Type 读取: {e}')
        if 'html' not in _ctype.lower() and not _html.lstrip().startswith('<'):
            # 非 HTML(如 /api 直接返回 JSON)—— 只记录路径(可能是接口), 不解析
            _lp = urlsplit(url).path or '/'
            if _lp and _lp != '/':
                out['apis'].add(_lp)
            continue
        n_pages += 1
        n_js += _harvest_page_assets(ctx, base, url, _html, out, js_urls, enabled, fp_hits)
    if n_pages:
        ctx.add_finding('INFO', f'非首页入口页 JS 收割: {n_pages} 页 / 新增 {n_js} 个 JS 引用',
                        base, '同源只读 GET; 候选=首页链接+入口页猜测(login/dashboard/admin…)')
        log(f'[*] 非首页入口页 JS 收割: {n_pages} 页, 新增 {n_js} 个 JS(待步骤3分析)')
    return (n_pages, n_js)


# SPA 路由收割的硬上限与"连续无新增"停止阈值(形态常量, 非站点特化)。
_SPA_ROUTE_MAX_PAGES = 30
_SPA_ROUTE_BARREN_LIMIT = 3


def _harvest_spa_routes(ctx, base, out, js_urls, enabled, fp_hits):
    """SPA 路由感知抓取(B2): 用**目标自己声明的路由表**当种子页再收割一轮 JS/端点。

    与步骤2.6 的 `_harvest_route_entry_js`(种子 = 首页链接 + login/dashboard 等猜测)互补 ——
    这里用 C1 提取的 `out['routes']`(前端路由表 / 菜单表里的路径字面量)。

    诚实边界(这正是此前评估为"暂缓"的原因, 故显式处理而非假装有效):
      · **纯客户端渲染的 SPA** 对任意路由都回**同一份 shell** → 拿不到新 JS/端点。故按
        "连续 N 个路由零新增"提前**停止**并如实披露(不把预算耗在重复请求上);
      · **SSR / 多页应用**(Nuxt/Next/传统多页)才会回该路由**自己的** HTML → 能真正收割到
        其 `<script src>` / modulepreload 与页面端点。
    边界: 同源 / GET-only / 受 `max_pages` 上限与 REQ 限速·熔断·预算约束; 模板路由(`/x/:id`)
      不是可直接 GET 的真实页, 跳过。
    返回 (n_pages, n_js_added)。
    """
    if not ctx.config.get('spa_route_harvest', True):
        return (0, 0)
    routes = {str(r) for r in (out.get('routes') or set()) if r}
    if not routes:
        return (0, 0)
    _bp = urlsplit(base)
    seeds = set()
    for r in routes:
        if r.startswith(('http://', 'https://')):
            u = r
        elif r.startswith('/'):
            u = f'{_bp.scheme}://{_bp.netloc}{r}'
        else:
            u = urljoin(base.rstrip('/') + '/', r)
        u = u.split('#', 1)[0].split('?', 1)[0]
        _sp = urlsplit(u)
        if _sp.netloc != _bp.netloc:
            continue
        if _sp.path.lower().endswith(static_asset_exts()):
            continue
        # 模板 / 参数化路由(`/order/:id`、`/x/{id}`)→ 不是可直接 GET 的真实页
        if '{' in _sp.path or ':' in _sp.path:
            continue
        if _sp.path.rstrip('/') == _bp.path.rstrip('/'):
            continue          # 与首页同一路径
        seeds.add(u)
    if not seeds:
        return (0, 0)
    _mp = int(ctx.config.get('max_pages', 15) or 15)
    _cap = max(1, min(_mp, _SPA_ROUTE_MAX_PAGES))
    seeds = sorted(seeds)
    if len(seeds) > _cap:
        ctx.note_truncated('spa_route_harvest_pages', len(seeds) - _cap)
        seeds = seeds[:_cap]
    n_pages = n_js = 0
    _barren = 0
    for i, url in enumerate(seeds):
        _before = len(js_urls) + len(out['apis'])
        r = REQ(ctx, 'GET', url)
        if r is None:
            continue
        if getattr(r, 'status_code', 0) >= 400:
            continue
        _html = getattr(r, 'text', '') or ''
        _ctype = ''
        try:
            _ctype = (r.headers.get('Content-Type') or '')
        except Exception as e:
            dbg(f'SPA 路由 Content-Type 读取: {e}')
        if 'html' not in _ctype.lower() and not _html.lstrip().startswith('<'):
            continue
        n_pages += 1
        n_js += _harvest_page_assets(ctx, base, url, _html, out, js_urls, enabled, fp_hits)
        if len(js_urls) + len(out['apis']) <= _before:
            _barren += 1
            if _barren >= _SPA_ROUTE_BARREN_LIMIT:
                ctx.note_truncated('spa_route_barren', len(seeds) - i - 1)
                log(f'[*] SPA 路由收割: 连续 {_barren} 个路由无新增(纯客户端 SPA 回同一 shell) '
                    f'→ 提前停止(已如实披露)')
                break
        else:
            _barren = 0
    if n_pages:
        ctx.add_finding('INFO', f'SPA 路由收割: {n_pages} 页 / 新增 {n_js} 个 JS 引用',
                        base, '种子=目标自述前端路由; 同源只读 GET; 无新增即提前停止')
        log(f'[*] SPA 路由收割(步骤3.7): {n_pages} 页, 新增 {n_js} 个 JS')
    return (n_pages, n_js)


def _looks_js_resp(r):
    """响应是否"像 JS"(200 + Content-Type javascript/ecmascript 或正文含 JS 特征)。"""
    ct = (r.headers.get('Content-Type') or '').lower()
    body = (r.text or '')[:400]
    return ('javascript' in ct or 'ecmascript' in ct
            or 'function' in body or '=>' in body
            or 'const ' in body or 'var ' in body or 'import ' in body)


def _fp_stack_js_probe(ctx, base, js_urls, fp_hits):
    """指纹专属 JS 路径探活(只读 GET) —— 命中框架 → 该栈在 `HIDDEN_PATHS_BY_STACK` 里声明的
    `.js`/`.mjs`(Angular `/main.js`·`/polyfills.js`·`/runtime.js`、Livewire `/livewire/livewire.js`、
    Nuxt/前端栈的 `/config.js`·`/env.js`·`/service-worker.js` …)。返回命中集(**未并入** js_urls)。

    这是"指纹分支 → 提取更多 JS 文件"的闭环点: 此前这些路径只被 `hidden_probe`(在 JS 管线
    **之后**)登记为"端点", 从不进 JS 管线(实测缺口)。实测 COMMON 层不含 .js —— 过滤后即"栈专属 JS"。
    """
    stack_js = []
    try:
        for _p in get_hidden_paths(list(fp_hits or [])):
            if str(_p).lower().split('?')[0].endswith(JS_EXTS) and _p not in stack_js:
                stack_js.append(_p)
    except Exception as e:
        dbg(f'指纹专属 JS 路径解析: {e}')
    hits = set()
    if not stack_js:
        return hits
    try:
        _max = int(ctx.config.get('js_dir_fuzz_max', 300) or 0)
    except (TypeError, ValueError):
        _max = 300
    _sp = urlsplit(base)
    _origin = f'{_sp.scheme}://{_sp.netloc}'
    # 预算与 js_dir_fuzz 主通道**共享**同一计数器(ctx 级) —— 此前两条子通道各拿一份满额,
    #   总发包可达 2×配置值, 与"控制请求数(默认 300)"的配置语义漂移(全库审计 M8)。
    sent = int(getattr(ctx, '_jsdir_sent', 0))
    for p in stack_js:
        if _max and sent >= _max:
            break
        url = _origin + p
        if url in (js_urls or set()):
            continue
        sent += 1
        ctx._jsdir_sent = sent
        r = _probe_req(ctx, url)
        if r is not None and r.status_code == 200 and _looks_js_resp(r):
            hits.add(url)
    return hits


def js_dir_fuzz(ctx, base, js_urls, fp_hits=None):
    """隐藏 JS 发现 —— 两条来源, 只读 GET, 命中即返回(由调用方并入 js_urls 走步骤3 分析):

      (a) **目录爆破**: 从已发现 JS 的**目录**派生候选 × 常见 JS 文件名 —— 发现
          `/static/js/admin.js` 这类"未被页面引用但存在"的隐藏 JS, 补齐"引用驱动发现"的盲区。
      (b) **指纹专属路径**: 见 `_fp_stack_js_probe` —— 命中框架 → 该栈声明的 `.js`/`.mjs`。

    合规: 只读 GET, 走 _probe_req(统一限速/熔断/预算/catch-all); 命中 = 200 且像 JS。
    上限: `js_dir_fuzz_max` 控制请求数(默认 300, 0=不限); 词表可用 `js_dir_fuzz_names` 追加。
    """
    # 1) 派生 JS 目录(已发现 JS 的父目录, 同源)
    dirs, seen_d = set(), set()
    for u in (js_urls or set()):
        try:
            p = urlsplit(u).path or ''
        except Exception:
            continue
        d = (p.rsplit('/', 1)[0] + '/') if '/' in p else '/'
        if d and d not in seen_d:
            seen_d.add(d)
            dirs.add(d)
    # 2) 词表(内置 + config 追加)
    names = list(JS_FILE_NAMES_COMMON)
    # `js_dir_fuzz_names` 既可是**内联名列表**, 也可是**字符串**——内置词表名
    #   (`js_common`/`js_highvalue`/`js_full`/`all`) 或 `.txt`/`.json` 词表文件路径。
    #   后者让随包发布的文件名词表**可用**(此前只能内联几十条; 词表文件无任何代码路径读取)。
    _extra = ctx.config.get('js_dir_fuzz_names')
    if isinstance(_extra, str):
        from .dicts import load_wordlist
        _extra = load_wordlist(_extra, kind='names')
    for _n in (_extra or []):
        _n = str(_n).strip()
        if _n and _n not in names:
            names.append(_n)
    # 2b) 指纹专属 JS 路径(先探: 定向/高价值)
    hits = _fp_stack_js_probe(ctx, base, js_urls, fp_hits)
    if not dirs and not hits:
        return set()
    try:
        _max = int(ctx.config.get('js_dir_fuzz_max', 300) or 0)
    except (TypeError, ValueError):
        _max = 300
    _sp = urlsplit(base)
    _origin = f'{_sp.scheme}://{_sp.netloc}'
    # 与 `_fp_stack_js_probe` 共享同一预算计数器(见其注释, 全库审计 M8)
    sent = int(getattr(ctx, '_jsdir_sent', 0))
    # (a) 目录 × 词表
    for d in sorted(dirs):
        for n in names:
            if _max and sent >= _max:
                break
            url = _origin + d + n + '.js'
            if url in js_urls:
                continue
            sent += 1
            ctx._jsdir_sent = sent
            r = _probe_req(ctx, url)
            if r is not None and r.status_code == 200 and _looks_js_resp(r):
                hits.add(url)
    if hits:
        log(f'[+] 隐藏 JS 发现: 命中 {len(hits)} 个未引用的 JS'
            f'(目录 {len(dirs)} 个 × 词表 {len(names)} 条 · 实发 {sent})')
    else:
        log(f'[*] 隐藏 JS 发现: {len(dirs)} 目录 × {len(names)} 名 · 实发 {sent} · 无命中')
    return hits


def _looks_obfuscated(text):
    """廉价预筛：文本是否疑似混淆（避免对每个普通 JS 无意义地拉起 node 子进程）。

    命中条件：体积够大 + 任一特征——
      · javascript-obfuscator 类（`_0x` 十六进制标识符大量出现）；
      · **字符串数组轮转 IIFE**（`while(!![]){…push(…shift())}` —— javascript-obfuscator 标配）；
      · VM / 字节码打包（`Function("in...")` 解释器入口）；
      · 字面零宽转义序列（`\\u200B/C/D/FEFF` 的 ASCII 文本，VM 运行期才变零宽）；
      · **高密度 `\\xHH` / `\\uHHHH` 转义**（字符串 / 标识符编码混淆）。
    """
    if not text or len(text) < 500:
        return False
    tl = text.lower()
    if 'function("in' in tl or "function('in" in tl:
        return True
    if text.count('_0x') > 30:
        return True
    # 字符串数组轮转 IIFE（去空白后匹配, 兼容 `while (!![])`）
    _nospace = tl.replace(' ', '').replace('\t', '').replace('\n', '')
    if 'while(!![])' in _nospace or 'while(![])' in _nospace:
        return True
    # 零宽转义：**按密度**判（与 `_looks_vm_packer` 同口径），不按"出现即判"。
    #   实测误判：ag-grid 1.5MB 里只有 **4 处** `\u200b`（库里的普通转义），旧写法直接判
    #   "疑似混淆" → 白拉一次 node/webcrack。真正的零宽混淆是**成百上千处**。
    if _zero_width_count(tl) > 20:
        return True
    # 高密度转义（编码混淆）: `\xHH` / `\uHHHH` 各自 ≥30 处
    if text.count('\\x') >= 30 or text.count('\\u') >= 30:
        return True
    return False


def _zero_width_count(tl):
    """零宽转义计数(`\u200b/c/d/FEFF`) —— `_looks_obfuscated` 与 `_looks_vm_packer`
    共用的单一真源(此前两处各写一份, 口径漂移即静默改变混淆判定, 审计 S14)。"""
    return (tl.count('\\u200b') + tl.count('\\u200c')
            + tl.count('\\u200d') + tl.count('\\ufeff'))


def _looks_vm_packer(text):
    """VM / 字节码打包检测（比 `_looks_obfuscated` 更严格）。

    仅命中「静态强反混淆（webcrack / 零宽标记化）无法处理」的情况才返回 True：
      · 自定义解释器入口（`Function("in...")` —— ConfuserEx 风格 VM）；
      · 字面零宽转义序列密度较高（字节码 VM 常以 \\u200B/C/D/FEFF 编码标识符/常量）。
    用于 `dynamic_deobf: auto` 的 per-file 自动触发：普通 javascript-obfuscator（`_0x`）由
    静态 webcrack 还原，不应触发动态解包（避免无谓地执行目标代码、也避免误报）。
    """
    if not text or len(text) < 500:
        return False
    tl = text.lower()
    if 'function("in' in tl or "function('in" in tl:
        return True
    if _zero_width_count(tl) > 20:
        return True
    return False


def _strong_on(cfg):
    """强反混淆是否启用（三态）：auto = node+deobf_strong.cjs+webcrack 可用才启用；
    True = 仅按文件 `_looks_obfuscated` 门控（依赖缺失时逐文件降级）；False = 关。

    接受 config 字典或含 `.config` 的 ctx（与 cli 解混淆子命令共用同一三态解释，避免 'auto' 语义分裂）。"""
    cfg = getattr(cfg, 'config', cfg)
    v = cfg.get('strong_deobf')
    if v == 'auto':
        try:
            from .deobf import strong_available
            return strong_available()
        except Exception:
            return False
    return bool(v)


def _dynamic_deobf_should_run(cfg, text):
    """动态解包是否对单份 JS 启用（三态 + per-file 路由），与 cli 解混淆子命令共用。

    False=关；True=疑似混淆即启用(`_looks_obfuscated`)；'auto'=仅 VM/字节码包(`_looks_vm_packer`)。
    动态解包**在密封沙箱内运行目标代码**，故 'auto' 必须严格按 VM/字节码包门控，不能随意执行。"""
    dd = cfg.get('dynamic_deobf')
    if not dd:
        return False
    if dd == 'auto':
        return _looks_vm_packer(text)
    return _looks_obfuscated(text)


def _unbundle_on(ctx):
    """构建产物拆包是否启用（三态）：auto = node+webcrack 可用才启用；True = 启用（内部再自检）；False = 关。"""
    v = ctx.config.get('unbundle')
    if v == 'auto':
        try:
            from ..recon.unbundle import webcrack_available
            return webcrack_available()
        except Exception:
            return False
    return bool(v)


def _skip_bytes_limit(ctx, key):
    """读取"体积上限"配置(字节)。返回正整数, 或 None = 不限(0/未设/非法值)。

    用于拆包(`unbundle_max_bytes`)与强反混淆(`strong_deobf_max_bytes`)：两者都要起 Node
    子进程, 对 MB 级巨物极贵 —— 超阈值**跳过并如实披露**, 不静默丢弃。
    """
    try:
        v = int((getattr(ctx, 'config', None) or {}).get(key) or 0)
    except (TypeError, ValueError):
        return None
    return v if v > 0 else None


def _unbundle_decision(ctx, u, text):
    """拆包门控的**纯决策**(便于单测): 'run' / 'skip_oversize' / 'skip_third_party' / 'off'。

    顺序即优先级: ①体积超限(省预算) → ②开关关闭 → ③第三方包(路径/文件名形态)。
    前两条都**如实披露**(见调用点的 note_truncated / log), 不静默丢弃能力。
    """
    _lim = _skip_bytes_limit(ctx, 'unbundle_max_bytes')
    if _lim and len(text or '') > _lim:
        return 'skip_oversize'
    if not _unbundle_on(ctx):
        return 'off'
    if is_third_party(u):
        return 'skip_third_party'
    return 'run'


def _strong_deobf_batch(ctx, items):
    """批量强反混淆 pre-pass —— 对本批"疑似混淆"的文件**一次性**调用(单次 Node)。

    决策权仍归本层(编排层)：按 `ctx.config['strong_deobf']` 门控 + per-file `_looks_obfuscated`
    路由；只是把命中的多个文件合并成一次 Node 调用，省掉逐文件的 webcrack 启动开销。
    返回 {url: 反混淆后文本}（仅命中项）；默认关闭 / 无命中 → {}（行为与逐文件版一致）。
    """
    if not _strong_on(ctx):
        return {}
    hits = [(u, t) for (u, t) in items if t and _looks_obfuscated(t)]
    # 体积上限: 超大文件跳过(省预算), 并登记披露 —— 否则使用者会以为"该文件没被混淆"。
    _lim = _skip_bytes_limit(ctx, 'strong_deobf_max_bytes')
    if _lim and hits:
        _kept = [(u, t) for (u, t) in hits if len(t) <= _lim]
        _over = len(hits) - len(_kept)
        if _over:
            ctx.note_truncated('strong_deobf_oversize', _over)
            log(f'[i] {_over} 个超大文件跳过强反混淆(>{_lim} 字节, 省预算; 见报告"扫描完整性")')
        hits = _kept
    if not hits:
        return {}
    try:
        from .deobf import deobfuscate_strong_batch
        results = deobfuscate_strong_batch([t for _, t in hits])
    except Exception as e:
        if ctx.config.get('debug'):
            import traceback as _tb
            _tb.print_exc()
        dbg(f'批量强反混淆异常(已退回静态): {e}')
        return {}
    out_map = {}
    for (u, t), res in zip(hits, results):
        try:
            o, rep = res
        except Exception:
            continue
        if rep.get('ok') and o and o != t:
            ctx.add_finding('INFO', '强反混淆(webcrack/VM 可读化)', ctx.base or '',
                            'detected=%s；方法=%s（仅静态 AST / 转义解码，未执行目标代码）'
                            % (rep.get('detected'), ','.join(rep.get('methods', [])) or '-'))
            out_map[u] = o
    return out_map


def _dynamic_deobf_pass(ctx, text):
    """动态解包 pre-pass —— 调度模块（编排层）的决策点：是否对单份 JS 用动态解包。

    决策权：facet 工具能力（`core/deobf.deobfuscate_dynamic` 暴露密封离线沙箱）；
    如何走：本函数（编排层）按 `ctx.config['dynamic_deobf']` **门控**并做 per-file 路由
    （疑似混淆才调用，普通 JS 原样返回）。默认关闭 —— 默认扫描仍是纯静态只读，合规姿态不变。

    与 `deobfuscate_strong`（静态 webcrack / 转义解码，不执行目标代码）不同，动态解包会
    **在本地密封离线沙箱里运行目标代码**以展开 VM / 字节码混淆。这是合规红线的例外：
    默认关闭 + 显式 opt-in（`FACET_DYNAMIC_DEOBF=true` 或配置开启）+ 报告明示警示。
    沙箱内零网络，fetch/XHR/WebSocket/http/https/net/dns 全部替换为「只记录、不发送」的桩，
    绝对不向目标或第三方发包。

    降级纪律：`deobfuscate_dynamic` 不可用 / 文本不像混淆 / 解包失败 → **静默退回**原文本，
    不改变任何既有行为。返回（可能已动态解包的 文本, 报告 或 None）。

    三态（`ctx.config['dynamic_deobf']`）：
      · False —— 关闭（默认），绝不执行目标代码；
      · True  —— 对任意疑似混淆的 JS 启用（per-file 预筛 `_looks_obfuscated`）；
      · 'auto'—— 仅对静态无法处理的 VM/字节码打包（per-file 预筛 `_looks_vm_packer`）自动启用，
                 普通 javascript-obfuscator 由静态 webcrack 还原、不触发。
    门控决策由 `_dynamic_deobf_should_run` 统一（与 cli 解混淆子命令同源）。
    """
    if not _dynamic_deobf_should_run(ctx.config, text):
        return text, None
    try:
        from .deobf import deobfuscate_dynamic
        tier = int(ctx.config.get('dynamic_deobf_tier') or 4)
        out_code, rep = deobfuscate_dynamic(text, tier=tier)
        if rep.get('ok') and out_code and out_code != text:
            cap = rep.get('captured', {}) or {}
            # 在发现项里**直接列出还原了什么**（配置键 / 端点名 / 全局），主报告即可见，不必翻侧车
            _mx = rep.get('module_exports') or {}
            _cfgk = list((_mx.get('config') or {}).keys()) if isinstance(_mx.get('config'), dict) else []
            _epn = list((_mx.get('endpoints') or {}).keys()) if isinstance(_mx.get('endpoints'), dict) else []
            _glb = list((rep.get('globals') or {}).keys()) if isinstance(rep.get('globals'), dict) else []
            _what = []
            if _cfgk:
                _what.append('还原配置键=' + ','.join(_cfgk[:12]))
            if _epn:
                _what.append('还原端点=' + ','.join(_epn[:12]))
            if _glb:
                _what.append('还原全局=' + ','.join(_glb[:8]))
            _tail = ('；' + '；'.join(_what)) if _what else ''
            ctx.add_finding(
                'INFO', '动态解包(L%d 密封沙箱)' % tier, ctx.base or '',
                '本地密封离线沙箱展开混淆(零网络, 网络原语只记录不发送); '
                '捕获内层源码=%d, URL=%d, 明文串=%d, 配置键=%d%s; '
                '仅作发现级线索(启发式·非定级), 未向目标发送任何请求'
                % (rep.get('inner_sources', 0),
                   len(cap.get('urls', []) or []),
                   len(cap.get('strings', []) or []),
                   len(cap.get('config', {}) or {}), _tail))
            return out_code, rep
        return text, rep
    except Exception as e:
        if ctx.config.get('debug'):
            import traceback as _tb
            _tb.print_exc()
        dbg(f'动态解包异常(已退回静态): {e}')
    return text, None


def _encoding_on(ctx):
    """简单 JS 编码解码是否启用（三态）：auto = node + deobf_encodings.cjs 可用才启用；
    True = 仅按文件指纹门控（依赖缺失时逐文件降级）；False = 关。与 `_strong_on` 同构。

    接受 config 字典或含 `.config` 的 ctx（与 cli 解混淆子命令共用同一三态解释，避免 'auto' 语义分裂）。"""
    cfg = getattr(ctx, 'config', ctx)
    v = cfg.get('js_encoding')
    if v == 'auto':
        try:
            from .deobf import encodings_available
            return encodings_available()
        except Exception:
            return False
    return bool(v)


def _encoding_decode_pass(ctx, text):
    """简单 JS 编码（JSFuck / AAencode 颜文字 / JJencode / Jother）解码 pre-pass。

    决策权归编排层（R2）：按 `ctx.config['js_encoding']` 门控 + per-file 指纹
    (`deobf.looks_like_js_encoding`) 路由。解码在**密封、离线、零网络**的 vm 沙箱内进行
    （执行入口/输出口为捕获桩，网络原语只记录不发送）—— **不向目标发送任何请求**。
    明文以注释字面量补回，供下游 deep_analyze 提取。降级纪律：不可用 / 失败 / 无命中 → 原样返回。
    返回 (文本, 报告或 None)。
    """
    # 先做**廉价指纹预筛**（避免对每个普通 JS 都去探测 Node 可用性）；命中才判依赖/解码。
    if not looks_like_js_encoding(text):
        return text, None
    if not _encoding_on(ctx):
        return text, None
    try:
        from .deobf import decode_js_encodings
        out, rep = decode_js_encodings(text)
        if rep.get('ok'):
            ctx.add_finding(
                'INFO', '简单 JS 编码解码(JSFuck/AAencode/JJencode)', ctx.base or '',
                '密封离线沙箱解码简单编码; 明文=%d 条(见"完整发现清单"); '
                '未向目标发送任何请求(仅作发现级线索, 启发式·非定级)'
                % len(rep.get('decoded', [])))
            return out, rep
        return text, rep
    except Exception as e:
        if ctx.config.get('debug'):
            import traceback as _tb
            _tb.print_exc()
        dbg(f'简单编码解码异常(已退回原文): {e}')
    return text, None


def _merge_dynamic_captures(ctx, out, base, rep, src=None):
    """把动态解包在密封沙箱里捕获的 URL/端点并入发现集，并**落存还原产物**。

    · captured.urls（同源→apis，跨域→external_apis）；
    · module_exports.endpoints[*].path（以 config.baseURL 拼接后同上分区）；
    · module_exports 整体落存 `out['recovered'][src]`（供报告侧车）；其 `config` 再喂给
      既有 `_scan_sensitive_block` 分类 —— 还原出的密钥/凭据走**同一套发现与脱敏口径**。

    属发现级「未探活候选」，与 deep_analyze 提取到的端点同口径（不自动探活）。
    """
    if not rep:
        return
    _src = src or base

    def _tag(u):
        """给动态解包还原的端点打来源标注(供 endpoints 侧车 extractor/来源列)。"""
        out.setdefault('api_extractor', {})[u] = 'dynamic_deobf'
        out.setdefault('api_srcline', {}).setdefault(u, (_src, None, None))
        out.setdefault('api_conf', {}).setdefault(u, 'HIGH')

    cap = rep.get('captured', {}) or {}
    for url in (cap.get('urls', []) or []):
        abs_url = url
        try:
            if not urlsplit(url).scheme:
                abs_url = urljoin(base, url)
        except Exception:
            pass
        if _same_origin(abs_url, base):
            out['apis'].add(abs_url)
        else:
            out['external_apis'].add(abs_url)
        _tag(abs_url)
    mx = rep.get('module_exports') or {}
    if not isinstance(mx, dict) or not mx:
        return
    _jsconf = mx.get('config')           # 注意: 这是**被解包 JS 的** config, 非 facet 配置
    _b = (_jsconf.get('baseURL') if isinstance(_jsconf, dict) else None) or base
    _eps = mx.get('endpoints')
    if isinstance(_eps, dict):
        for _name, _e in _eps.items():
            _p = (_e.get('path') if isinstance(_e, dict) else None)
            if not _p or not isinstance(_p, str):
                continue
            try:
                full = _p if urlsplit(_p).scheme else urljoin(_b, _p)
            except Exception:
                continue
            if _same_origin(full, base):
                out['apis'].add(full)
            else:
                out['external_apis'].add(full)
            _tag(full)
    # 落存还原产物（供报告侧车）+ 还原出的 config/globals 走既有密钥分类（同一脱敏口径）。
    _rec = {
        'config': _jsconf if isinstance(_jsconf, dict) else {},
        'endpoints': _eps if isinstance(_eps, dict) else {},
        'keys': [k for k in mx.keys()],
    }
    if rep.get('globals'):
        _rec['globals'] = rep['globals']     # 目标代码挂到沙箱全局(window.X)上的配置
    out.setdefault('recovered', {})[_src] = _rec
    _scan_blobs = [b for b in (_jsconf, rep.get('globals')) if isinstance(b, dict) and b]
    if _scan_blobs:
        try:
            import json as _json

            from .secret import _scan_sensitive_block
            _scan_sensitive_block(ctx, _json.dumps(_scan_blobs, ensure_ascii=False), _src)
        except Exception as e:
            # 还原产物里的密钥分类失败被静默 = 还原 config/globals 里的密钥**不会进发现项**
            #   且零日志(密钥漏报的静默失效面) —— 必须留痕(全库审计 M9)。
            dbg(f'动态解包还原产物敏感扫描失败({_src}): {e}')


def _refresh_fingerprints_from_bodies(ctx, base, state, fetched):
    """每批 JS 分析前, 用"已累积的全部 JS 正文(含本批)"补判指纹并刷新门控规则。

    通用鲁棒: 不假设"框架标记必出现在入口包"。任何批次(含步骤3.5.2 追打的
    懒加载 chunk / 运行时通道捕获的路由专属 JS)只要引入新框架, 即即时抬升
    `state['enabled']`, 本批及后续 JS 的 `deep_analyze` 都能启用其栈专属提取通道
    (VUE_ROUTER / SSR_EXTRA / NUXT_FETCH / GRAPHQL …)。

    旧实现只在首批一次性刷新(`fp_refreshed` 一次性开关), 隐含"标记必在入口包"的
    硬编码假设 —— 路由级代码分割会把 feature 模块(连同其库标记)拆进晚到的 chunk,
    这些框架直到管线结束后的步骤3.4 才被补判, 而 `deep_analyze` 早已用旧 enabled 跑完,
    对应文件的栈专属提取永久漏抓。本函数消除该假设。

    `state['_fp_total']` 仅作去重: 本批无新增正文(全部为空/已扫)则跳过指纹正则扫描,
    避免对相同正文重复计算。`fetched` 为 `(url, text)` 列表(与管线同口径), 计数按文件数
    对齐 `js_bodies` 的逐文件追加, 保证去重准确。

    Returns:
        bool: 本批是否命中了新框架并刷新了 enabled。
    """
    batch_texts = [t for _, t in fetched if t]
    if not batch_texts:
        return False
    _cur = len(state['js_bodies']) + len(fetched)
    if _cur == state.get('_fp_total'):
        return False
    try:
        # **只扫本批**（不再把累积的全部正文重新喂一遍）。
        #   `probe_new_fingerprints` 是**增量可加**的：它读 `ctx.fingerprints['hits']` 作为
        #   `known_hits`、只返回**新增**命中并把它们并回 ctx —— 所以"逐批扫本批"与"每批扫全量"
        #   得到的最终命中集合**完全相同**，但复杂度从 O(n²) 降到 O(n)。
        #   实测影响：全量分析 ~1200 个 JS 时，旧写法每批重扫全部累积正文（beautify 后可达数倍
        #   体积）→ CPU 与内存双双爆掉，正是"全量跑不完"的真因。
        if probe_new_fingerprints(ctx, base, batch_texts):
            state['fp_hits'] = list((getattr(ctx, 'fingerprints', None) or {}).get('hits', []))
            state['enabled'] = get_enabled_rules(getattr(ctx, 'route', None)
                                                or ROUTE_RULES['_DEFAULT'])
            state['_fp_total'] = _cur
            return True
        state['_fp_total'] = _cur
        return False
    except Exception as e:
        if ctx.config.get('debug'):
            traceback.print_exc()
        log(f'[-] 批次指纹补判异常: {e}')
        state['_fp_total'] = _cur
        return False


# P2: 无 sourceMappingURL 声明时, 机会性探测同源 `<js>.map` 的最小 JS 体积门槛(字节)。
#   仅对"像真包"的文件探测, 避免为海量小 chunk 各发一次 .map 请求(控制额外发包量)。
_SM_PROBE_MIN_BYTES = 8192


def _process_external_sourcemap(ctx, base, js_url, sm, out, enabled, fp_hits):
    """外部 `.map`(`sourceMappingURL` 指向独立文件): **仅抓同源**, 解析 `sourcesContent` 并分析。

    🔴 **同源护栏(与 `_fetch_js` 同口径)**: `sourceMappingURL` 可能是**跨域 CDN 绝对 URL** ——
    若照抓会向第三方发请求, 与"跨域只登记不抓取"的合规定位相悖(且把扫描暴露给 CDN)。
    跨域只登记(日志)不抓。
    """
    sm_url = urljoin(js_url, sm)
    if not _same_origin(sm_url, base):
        log(f'[!] SourceMap 跨域, 不抓取(仅登记): {sm_url}')
        return
    # R2: SourceMap 黑名单 —— map URL 命中任一片段(chunk-vendors / node_modules /
    #   axios / lodash…)即跳过下载: 库/vendor 的 map 体量大且无业务价值。跳过事实记
    #   日志(可配 sourcemap_blacklist 覆盖), 不静默丢弃。
    _sm_bl = ctx.config.get('sourcemap_blacklist') or []
    if any(str(_x).lower() in sm_url.lower() for _x in _sm_bl if str(_x).strip()):
        log(f'[i] SourceMap 命中黑名单, 跳过下载: {sm_url}')
        return
    sm_r = REQ(ctx, 'GET', sm_url)
    if sm_r is None or sm_r.status_code != 200:
        return
    try:
        sm_data = json.loads(sm_r.text)
        # 外部 .map 可公开读取 = **源码映射文件暴露**(独立发现项)
        if isinstance(sm_data, dict) and (sm_data.get('mappings') or sm_data.get('sources')):
            _srcs = sm_data.get('sources') or []
            # SPA 的 .map **常为公开资产** → 默认 MED; 仅当**内嵌完整源码**
            #   (sourcesContent) 时才 HIGH(源码实质泄露)。
            _has_src = bool(sm_data.get('sourcesContent'))
            ctx.add_finding('HIGH' if _has_src else 'MED',
                            '源码映射文件暴露', sm_url,
                            f'可公开读取, {len(_srcs)} 个源文件'
                            + ('(含 sourcesContent 完整源码)' if _has_src
                               else '(仅映射, 未含源码)'))
        for src_content in sm_data.get('sourcesContent', []):
            dec = decode_layer(_beautify_js(src_content))
            res = deep_analyze(ctx, dec, js_url + '#sourcemap', base, enabled, fp_hits)
            _merge_out(out, res)
    except Exception as e:
        dbg(f'外部 SourceMap 解析 {sm_url}: {e}')


def _drain_js_refs(out, base, js_urls):
    """把 `out['js_refs']` 里**同源**的 `.js/.mjs` 并入 `js_urls` —— 闭环"发现即抓取"。

    背景(实测缺口 D4): `_fetch_build_manifests`(构建清单)把枚举到的 JS 只写进
    `out['js_refs']`, 而**全仓无人读取它** → 构建清单枚举出的 chunk(含"从未被引用的
    chunk")**从不被抓取分析**, 整个"构建清单"获取方案形同虚设。
    本函数把它(以及其它来源汇入 out['js_refs'] 的同源 JS)统一并入 js_urls 走 JS 管线。
    跨域条目**不并入**(同源只读护栏); 返回新增条数。
    """
    n = 0
    for u in list(out.get('js_refs') or ()):
        try:
            au = urljoin(base, u)
            if (urlsplit(au).path.endswith(JS_EXTS) and _same_origin(au, base)
                    and au not in js_urls):
                js_urls.add(au)
                n += 1
        except Exception:
            continue
    return n


def _run_js_pipeline(ctx, base, out, new_urls, state):
    """步骤3 JS 分析管线(可多次调用, 用于追打 SPA 路由懒加载 chunk)。

    把 JS 分析这一整段(批量抓取 → 首批指纹补判 → 源码映射 → deep_analyze →
    js_refs 同源递归 → 写操作记录 → 可选 webcrack 拆包)封装为**可重入**管线,
    跨次共享同一 `state`:
        state['seen']       已分析 JS URL 集合(去重, 不重复分析)
        state['queue']      待分析队列(含 js_refs 递归追加)
        state['js_bodies']  全部 JS 正文(每批分析前用于指纹补判; 步骤3.4 收尾再扫一次)
        state['max_js']     分析上限
        state['_fp_total']  已扫描 JS 正文计数(指纹补判去重: 本批无新增正文则跳过)
        state['enabled'] / state['fp_hits']  指纹命中后的门控规则(每批分析前刷新)
    new_urls: 本轮要追加到队列的 JS URL(已分析的会被跳过)。

    返回: 本轮实际分析的 JS 文件数。

    合规不变: 仅 deep_analyze(只读提取端点/路由/参数/敏感串), 不发送任何写/攻击载荷;
    同源护栏与全局限速·熔断·预算在 REQ / _fetch_js 内部已生效。
    """
    from .config import effective_max_js  # 自适应 JS 上限(惰性导入, 避免环)
    seen = state['seen']
    queue = state['queue']
    js_bodies = state['js_bodies']
    # 本轮新增 JS URL 入队(去重: 不在 seen、不在 queue)
    for u in new_urls:
        if u not in seen and u not in queue:
            queue.append(u)
    # **来源档**: 首次调用的入参 = 页面**直接声明**的 JS(`<script src>` + `<link modulepreload>`)
    #   —— 它们属于"应用入口图"，比后来经 `js_refs`/运行时**间接发现**的 chunk 更可能承载共享
    #   代码（如 RPC 接口表 / 字段字典）。据此给它们一个更高的排序档，使**预算截断时优先保它们**。
    #   判据是**来源/出处**（provenance），不是文件名白名单。
    _declared = state.get('declared') or set()
    if _declared and not state.get('_declared_logged'):
        state['_declared_logged'] = True
        log(f'[*] JS 来源档: 页面直接声明 {len(_declared)} 个 JS 优先分析'
            f'(其余为间接发现的 chunk)')
    n = 0
    # **时间感知预算**: JS 阶段最多占用"剩余时间"的 `js_budget_frac`(默认 0.8 = 覆盖优先),
    #   其余留给探活/报告 —— 否则自适应上限(硬顶 1000)会把大站拖到全局 `max_duration` 被硬截断,
    #   连探活都来不及跑。无全局预算(`budget_left()` 返回 None)时不生效。
    #   截断**必然**损失信息(少扫的 chunk 里可能有业务接口), 故默认偏向覆盖, 并在报告
    #   报告「覆盖与边界」里如实披露"业务面可能不完整"。
    try:
        _frac = float(ctx.config.get('js_budget_frac', 0.8) or 0.8)
    except (TypeError, ValueError):
        _frac = 0.8
    try:
        _left0 = ctx.budget_left()
    except Exception:
        _left0 = None                      # 桩 ctx / 无预算实现 → 不做时间约束
    # 时长口径统一用 monotonic(与 `ctx.budget_left()` 同一时钟), 免受系统改钟影响。
    _js_deadline = (time.monotonic() + _left0 * _frac) if (_left0 and _left0 > 0) else 0.0
    while queue:
        if _js_deadline and time.monotonic() >= _js_deadline:
            _rem = len([u for u in queue if u not in seen])
            if _rem:
                ctx.note_truncated('js_time', _rem)
                log(f'[!] JS 队列因**时间预算**截断: 剩余 {_rem} 个未扫 '
                    f'(js_budget_frac={_frac}; 预留时间给探活/报告)')
            break
        # **自适应上限**: 按"已发现总数"(seen+queue) 上浮, 硬顶 `max_js_hard_cap` ——
        #   大 SPA chunk 动辄上千, 固定 max_js 会**静默漏掉大半**(接口随之漏)。0=不限。
        max_js = effective_max_js(ctx.config, len(seen) + len(queue))
        state['max_js'] = max_js          # 供收尾的"未扫完"披露使用
        if max_js and len(seen) >= max_js:
            break
        _room = (max_js - len(seen)) if max_js else 8
        # **按业务价值排序取批**(而非 FIFO): 入口包 > **页面直接声明** > 业务 chunk > 第三方产物
        #   —— 与 `_fetch_js` 的排序同口径(同一 `get_js_priority`/`is_third_party` 真源)。
        #   目的: 一旦被上限或时间预算截断, **被丢掉的也是价值最低的**(vendor/间接发现的 chunk),
        #   而"应用入口图"里承载的共享代码(接口表/字段字典)优先进入分析。
        #   **文档站代码块 chunk(VitePress `*.html-*.js`)在此剔除**: 内容为文档代码示例,
        #   既不分析(降噪)也**不抓取**(省去上千次无谓请求 → 提速); 仅登记披露。
        _pend = []
        for _u in (u for u in queue if u not in seen):
            if _is_doc_code_chunk(_u):
                if not state.get('_doc_code_logged'):
                    state['_doc_code_logged'] = True
                    log('[*] 文档站代码块 chunk(VitePress *.html-*.js)不入队分析: '
                        '内容为文档示例, 非目标代码')
                out.setdefault('doc_code_js', []).append(
                    {'url': _u, 'bytes': 0, 'reason': 'vitepress-code-block'})
                seen.add(_u)          # 标记已处理, 避免被 js_refs 递归反复排出
                state['doc_code_skipped'] = int(state.get('doc_code_skipped', 0) or 0) + 1
                continue
            _pend.append(_u)
        _pend = sorted(_pend,
                       key=lambda u: (get_js_priority(u), 0 if u in _declared else 1,
                                      is_third_party(u), len(u)))
        batch = _pend[:min(8, _room)]
        if not batch:
            break
        for u in batch:
            seen.add(u)
        # 异步批量获取
        fetched = _fetch_js(ctx, batch)
        # **每批指纹补判 —— 必须在分析之前做**(覆盖累积全部 JS 正文)。
        #   旧实现仅在首批一次性刷新(`fp_refreshed` 一次性开关), 隐含"框架标记必出现
        #   在入口包"的硬编码假设。实测 SPA 的路由级代码分割会把 feature 模块(连同其
        #   专属库标记)拆进懒加载 chunk, 这些 chunk 在步骤3.5.2 才被追打、晚于首批刷新 →
        #   其框架直到步骤3.4(管线结束后)才被补判, 而 deep_analyze 早已用旧 enabled 跑完,
        #   栈专属提取(VUE_ROUTER / SSR_EXTRA / NUXT_FETCH …)对该文件永久漏抓。
        #   现改为: 每批分析前用"已累积的全部 JS 正文(含本批)"重新补判, 只要出现新框架
        #   即时抬升 enabled, 本批及后续 JS 都能启用其专属通道 —— 不依赖任何"标记在哪"
        #   的假设(通用鲁棒, 不写死)。详见 _refresh_fingerprints_from_bodies。
        if _refresh_fingerprints_from_bodies(ctx, base, state, fetched):
            log(f'[*] 批次指纹补判(先于分析): {state["fp_hits"]} '
                f'—— 本批及后续 JS 均启用其专属提取通道')
        enabled = state['enabled']
        fp_hits = state['fp_hits']
        # **本批按体积升序分析**（小文件先出结果）—— 大文件（vendor/库包动辄 MB 级）放在批尾，
        #   避免"一个 2MB 包 + 拆包"把整批的产出时间整体拖后；截断时先拿到的也是小文件的结果。
        fetched = sorted(fetched, key=lambda _it: len(_it[1] or ''))
        # 本批"疑似混淆"文件一次性做强反混淆(单次 Node, 复用 webcrack 实例) —— 省逐文件启动
        _strong_map = _strong_deobf_batch(ctx, fetched)
        for u, text in fetched:
            path = save_js(ctx, u, text)
            out['nfiles'] += 1
            # 记录真实 JS 清单, 供报告"JS 资源清单"章节使用
            out['js_files'].append((u, len(text or ''), path))
            # R2 库 bundle 嗅探(借鉴 JsOwl skip_library_bundles): 命中第三方库 →
            #   跳过后续深度分析(AST/正则/sourcemap/拆包/反混淆均为纯开销), 但保留:
            #     · 资源清单(本行已计 nfiles, 报告"JS 资源清单"可见);
            #     · 头尾采样入 js_bodies(供指纹补判识别框架, 不丢 SPA 识别能力)。
            #   关闭: config vendor_bundle_skip=false 恢复全量分析。跳过的文件记入
            #   out['vendor_js'] 并单列披露, 不假装"分析过零产出"。
            if ctx.config.get('vendor_bundle_skip', True):
                _vr = _vendor_sniff(u, text, ctx.config.get('vendor_sniff_bytes'))
                if _vr:
                    out.setdefault('vendor_js', []).append(
                        {'url': u, 'bytes': len(text or ''), 'reason': _vr})
                    js_bodies.append(_body_sample(text or ''))
                    state['vendor_skipped'] = int(state.get('vendor_skipped', 0) or 0) + 1
                    continue
            # 注: 文档站代码块 chunk(VitePress `*.html-*.js`)已**在入队阶段剔除**(不抓取),
            #   见上方 `_run_js_pipeline` 的 `_pend` 过滤; 此处无需再判(避免双重计数)。
            # SourceMap 处理
            sm = _extract_sourcemap(text, u)
            if sm:
                if isinstance(sm, dict):
                    # 内联 sourcemap —— 源码随 JS 一起下发(无独立 .map 文件, 故 MED)
                    _sc = sm.get('sourcesContent') or []
                    if _sc:
                        ctx.add_finding('MED', '内联 SourceMap 源码泄露', u,
                                        f'{len(_sc)} 个源文件随 JS 一起下发')
                    for src_content in _sc:
                        dec = decode_layer(_beautify_js(src_content))
                        res = deep_analyze(ctx, dec, u + '#sourcemap', base, enabled, fp_hits)
                        _merge_out(out, res)
                elif isinstance(sm, str):
                    _process_external_sourcemap(ctx, base, u, sm, out, enabled, fp_hits)
            elif (ctx.config.get('sourcemap_probe', True)
                  and len(text or '') >= _SM_PROBE_MIN_BYTES):
                # P2 机会性收割: JS **未声明** sourceMappingURL 时, 同源探测 `<js>.map`
                #   (只读 GET; 404/跨域/黑名单由 _process_external_sourcemap 静默兜底)。
                #   命中且含 sourcesContent → 原始源码作为高优分析输入, 补静态逆向盲区。
                #   带 fallback: 抓不到即静默退回现通道, 不影响主路径。
                #   调度护栏: 全局上限 `sourcemap_probe_max`(默认 50; <=0 不限), 防 chunk 密集
                #     站点逐文件探测把 JS 阶段发包/时间预算吃光。
                _sm_max = int(ctx.config.get('sourcemap_probe_max', 50) or 0)
                if _sm_max <= 0 or int(state.get('_sm_probes', 0)) < _sm_max:
                    state['_sm_probes'] = int(state.get('_sm_probes', 0)) + 1
                    _process_external_sourcemap(
                        ctx, base, u, u.split('?', 1)[0] + '.map', out, enabled, fp_hits)
            # 动态解包 pre-pass（在**原文**上；调度模块按 config 决策；默认关闭）
            text, _dyn_rep = _dynamic_deobf_pass(ctx, text)
            # 简单 JS 编码 pre-pass（JSFuck/AAencode/JJencode；密封沙箱解码, 明文以注释字面量补回）
            text, _enc_rep = _encoding_decode_pass(ctx, text)
            # 主文本分析（**原文**）—— 本层 unpack 能还原混淆字符串（含碎片拼接标记）
            dec = decode_layer(_beautify_js(text))
            # 只留**头尾采样**（指纹标记通常落在包首/字符串区）—— 全量分析下逐文件保留整份
            #   beautify 正文会让内存无界增长（实测 ~1200 文件可到 GB 级）。逐批扫描已覆盖每个
            #   文件的**完整原文**，此处仅作步骤3.4 收尾补判的兜底，采样足够。
            js_bodies.append(_body_sample(dec))
            res = deep_analyze(ctx, dec, u, base, enabled, fp_hits)
            _merge_out(out, res)
            # "体量够大却零产出" → 登记, 报告如实披露（纯本地统计, 零发包）
            _note_silent_js(ctx, out, u, text, res)
            # 强反混淆产物**另跑一遍** deep_analyze 取并集 —— **不替换也不拼接**：
            #   · 替换: webcrack 对个别文件**有损**(实测 4.4KB→377B 丢端点) → 丢端点；
            #   · 拼接: 会干扰本层 unpack 的碎片拼接 → 同样丢端点(均实测)。
            #   各自分析再并集, 两种形态互补, 覆盖最全。
            _so = _strong_map.get(u)
            if _so and _so != text:
                _res_s = deep_analyze(ctx, decode_layer(_beautify_js(_so)),
                                      u, base, enabled, fp_hits)
                _merge_out(out, _res_s)
            # 把密封沙箱里捕获的运行期 URL/端点并入发现集，并落存还原产物（未探活候选）
            _merge_dynamic_captures(ctx, out, base, _dyn_rep, src=u)
            # 新发现的JS入队 (归一化为绝对URL, 以当前文件为基准, 且必须同源)
            for nu in res.get('js_refs', set()):
                nu_abs = urljoin(u, nu)
                if not urlsplit(nu_abs).path.endswith(JS_EXTS):
                    continue
                if not _same_origin(nu_abs, base):
                    continue
                if nu_abs not in seen and nu_abs not in queue:
                    queue.append(nu_abs)
            # wasm 字符串提取通道(§3.7-G2): 同源只读 GET .wasm → 扫二进制字符串
            #   以"当前 JS 文件"为基准 urljoin(与 js_refs 同源递归同口径)。
            for _wr in res.get('wasm_refs', set()):
                _drain_wasm_ref(ctx, _wr, u, base, out)
            # 写操作记录
            out['write_apis'].update(res.get('write_apis', {}))
            # 构建产物拆包(webcrack 可选 sidecar)
            #   **第三方包不拆**：拆包是为还原**应用代码**的模块边界；对 vendor/库包(动辄 MB 级)
            #   拆包既无业务价值、又极贵(每文件最长 120s) —— 实测正是它把 JS 阶段预算吃光，
            #   导致承载接口表的业务 chunk 永远轮不到。判据用 `is_third_party`(路径/文件名形态)。
            _dec = _unbundle_decision(ctx, u, text)
            if _dec == 'run':
                _unbundle_and_analyze(ctx, path, u, text, base, enabled, fp_hits, out, seen, queue)
            elif _dec == 'skip_oversize':
                # 超大文件跳过拆包 —— 与"第三方包不拆"同理(webcrack 每文件最长 120s),
                #   但**必须披露**: 否则使用者会以为"这个包拆过、里面就这些模块"。
                ctx.note_truncated('unbundle_oversize', 1)
                if not state.get('_unbundle_oversize_logged'):
                    state['_unbundle_oversize_logged'] = True
                    log(f'[i] 超大文件跳过拆包(>{_skip_bytes_limit(ctx, "unbundle_max_bytes")} '
                        f'字节, 省预算给业务 chunk; 见报告"扫描完整性")')
            elif _dec == 'skip_third_party' and not state.get('_unbundle_skip_logged'):
                state['_unbundle_skip_logged'] = True
                log('[i] 第三方包跳过拆包(webcrack 只用于应用代码, 省预算给业务 chunk)')
            n += 1
    _vs = int(state.get('vendor_skipped', 0) or 0)
    if _vs:
        log(f'[*] 库 bundle 跳过深度分析: {_vs} 个(版权注释/路径形态判定 · 仍计入 JS '
            f'清单与指纹补判 · vendor_bundle_skip=false 可关闭)')
    # 文档站代码块 chunk(VitePress)披露: 不入队/不分析/不抓取(内容为文档示例)
    _dc = int(state.get('doc_code_skipped', 0) or 0)
    if _dc:
        log(f'[*] 文档站代码块 chunk(VitePress *.html-*.js)不入队分析: {_dc} 个'
            f'(内容为文档代码示例, 非目标代码; 明细见 out["doc_code_js"])')
        ctx.add_finding('INFO', f'文档站代码块 chunk 跳过 {_dc} 个', base or '',
                        'VitePress 把 Markdown 代码块编译为 *.html-<hash>.js; 内容为文档示例, '
                        '不入队分析(避免把示例路径当真实接口), 详见 doc_code_js')
    return n


def _unbundle_and_analyze(ctx, js_path, u, text, base, enabled, fp_hits, out, seen, queue):
    """构建产物拆包(webcrack 可选 sidecar)

    对 webpack/browserify bundle 调用 webcrack 还原模块树, 再对**每个模块**单独跑
    `deep_analyze`, 并把"模块 → 源 chunk"映射记入 `out['bundle_modules']`（供报告与
    chunk 覆盖率校验复用）。

    降级纪律: webcrack 不可用 / 文本不像 bundle / 拆包失败 → **静默退回**, 不改变
    任何既有行为（与未开启时完全一致）。返回模块相对路径列表(或 None)。

    结构还原(模块边界)与语义还原(表达式/拼接)互补。
    """
    try:
        from ..recon import unbundle as _ub
        if not _ub.webcrack_available():
            log('[i] webcrack 不可用, 跳过拆包(退回 _beautify_js + 正则)')
            return None
        if not _ub.is_bundle(text):
            return None
        # P1: 如实披露识别到的构建器类型(webpack/browserify/vite/esbuild/swc/parcel)。
        _kind = _ub.detect_bundle_kind(text) or 'unknown'
        log(f'[*] 构建产物拆包: 识别为 {_kind} 产物, 尝试 webcrack 还原模块')
        _od = os.path.join(os.path.dirname(js_path) or '.', 'unbundled',
                           hashlib.md5(u.encode('utf-8', 'ignore')).hexdigest()[:8])
        _ubr = _ub.unbundle_file(js_path, _od)
        if not (_ubr.get('ok') and _ubr.get('modules')):
            log(f'[i] webcrack 拆包未产出模块({(_ubr.get("err") or "")[:60]}), 已退回普通分析')
            return None
        # 上限按**该 bundle 实际模块数**自适应（配置值为下限，硬顶 2000）—— 而不是固定 200。
        from .adapt import effective_module_cap, note
        _maxm = effective_module_cap(ctx.config, len(_ubr['modules']))
        note(ctx, 'unbundle_max_modules', ctx.config.get('unbundle_max_modules', 200), _maxm,
             f'该 bundle 实际模块数 {len(_ubr["modules"])}')
        _mods = _ubr['modules'][:_maxm]
        # 实际产物目录可能被 `unbundle_file` 换成**唯一名**（避免 rmtree 批量删除）—— 以它为准。
        _od = _ubr.get('out_dir') or _od
        # 产物目录**保留上限**（默认 3）: 唯一名机制会让每次重扫新增一个目录 → 无界累积。
        #   仅清理更早的目录, 本次正在用的目录由 `keep_dir` 保护。
        _keep = int(ctx.config.get('unbundle_keep_dirs', 3) or 0)
        if _keep > 0:
            _dn, _fn = _ub.prune_unbundled(os.path.dirname(_od.rstrip(os.sep)), _keep,
                                           keep_dir=_od)
            if _dn or _fn:
                log(f'[i] 拆包产物保留最近 {_keep} 个: 已清理 {_dn} 个更早目录'
                    + (f'（{_fn} 个清理失败）' if _fn else ''))
        _rel = [os.path.relpath(m, _od) for m in _mods]
        out.setdefault('bundle_modules', {})
        out['bundle_modules'][u] = _rel
        ctx.add_finding('INFO', f'构建产物拆包(webcrack/{_kind}): {len(_mods)} 模块', u,
                        'webcrack 还原模块边界; 已逐模块深析')
        # 读入模块文本；拆出的模块也过 strong/dynamic deobf（此前绕过 → 模块内混淆/VM 打包会漏）。
        _mod_texts = []
        for _m in _mods:
            try:
                with open(_m, encoding='utf-8', errors='ignore') as _mf:
                    _mod_texts.append((_m, _mf.read()))
            except Exception:
                continue
        _ub_strong = _strong_deobf_batch(ctx, _mod_texts)   # 本批模块一次 Node（默认关→{}）
        for _m, _mt in _mod_texts:
            _mt, _dyn_rep = _dynamic_deobf_pass(ctx, _mt)
            _mt, _enc_rep = _encoding_decode_pass(ctx, _mt)
            _msrc = f'{u}#module:{os.path.basename(_m)}'
            _mres = deep_analyze(ctx, decode_layer(_beautify_js(_mt)),
                                 _msrc, base, enabled, fp_hits)
            _merge_out(out, _mres)
            # 强反混淆产物**另跑一遍**取并集（同主管线：不替换/不拼接，防有损产物丢端点）
            _so_m = _ub_strong.get(_m)
            if _so_m and _so_m != _mt:
                _mres_s = deep_analyze(ctx, decode_layer(_beautify_js(_so_m)),
                                       _msrc, base, enabled, fp_hits)
                _merge_out(out, _mres_s)
            _merge_dynamic_captures(ctx, out, base, _dyn_rep, src=_msrc)
            for _nu in _mres.get('js_refs', set()):
                _nu_abs = urljoin(u, _nu)
                if (urlsplit(_nu_abs).path.endswith(JS_EXTS)
                        and _nu_abs not in seen and _nu_abs not in queue):
                    queue.append(_nu_abs)
        return _rel
    except Exception as e:
        if ctx.config.get('debug'):
            traceback.print_exc()
        log(f'[-] 拆包异常(已忽略): {e}')
        return None


def _run_form_link_step(ctx, base):
    """步骤4.5: 表单字段 → 端点 的**数据流关联收尾**(零推断: 表单 id 唯一对应一个端点才关联)。

    必须在参数消费方(param_probe / 报告参数列)之前执行, 否则关联结果不可见。
    """
    try:
        _n_fbl = _resolve_form_body_links(ctx, base)
        if _n_fbl:
            log(f'[+] 表单→端点 关联: {_n_fbl} 个参数条目'
                f'(按 JS 数据流链 FormData→body→fetch, 唯一对应才关联)')
    except Exception as e:
        if ctx.config.get('debug'):
            traceback.print_exc()
        log(f'[-] 表单→端点 关联异常: {e}')


class _Prof:
    """轻量阶段计时(仅在 `config.profile` 开启时记录) —— **只读**, 不改变任何行为。

    用法: `p = _Prof(ctx)` → 各阶段 `p.mark('阶段名')` → 末尾 `p.dump()`。
    未开启时 mark()/dump() 均为 no-op(零开销)。用于性能基准: 量化各阶段耗时占比,
    据此判断"是否有安全的高收益优化点", 而不是盲目动并发(会动摇统一限速/熔断保证)。
    """
    def __init__(self, ctx):
        self.ctx = ctx
        self.on = bool(ctx.config.get('profile'))
        self._t = time.monotonic()
        self.marks = []

    def mark(self, name):
        if not self.on:
            return
        now = time.monotonic()
        self.marks.append((name, now - self._t))
        self._t = now

    def dump(self):
        if not self.on or not self.marks:
            return
        total = sum(d for _, d in self.marks)
        # 结构化留存, 供 tools.perf_baseline / 程序化消费(不只打到 stdout)。
        try:
            self.ctx.stage_times = {n: round(d, 3) for n, d in self.marks}
            self.ctx.stage_total = round(total, 3)
        except Exception:
            pass
        log(f'[*] ===== 阶段耗时(合计 {total:.1f}s) =====')
        for name, d in sorted(self.marks, key=lambda x: -x[1]):
            pct = (d / total * 100) if total else 0
            log(f'[*]   {d:6.2f}s ({pct:4.1f}%)  {name}')
        # 发现性提示: 探活占主导时, 指出**可调的合规旋钮**(不改默认, 只提示)。
        _top = max(self.marks, key=lambda x: x[1])
        if total > 0 and '探活' in _top[0] and _top[1] / total >= 0.4:
            log('[*] 提示: 探活占主导 —— 耗时 ≈ 探活数 × rate(合规限速, 非 bug)。'
                '提速请调 `rate` / `max_probe`(配置文件); '
                '并发/异步**不能**突破统一限速(设计如此)。')


def _apply_dev_server_downgrade(ctx, base):
    """识别到**开发服务器** → 强制低并发 + 加大间隔(方案六)。返回说明串(未命中则 None)。"""
    if not ctx.config.get('dev_server_downgrade'):
        return None
    fp = getattr(ctx, 'fingerprints', None) or {}
    _hits = ' '.join(str(h) for h in (fp.get('hits') or [])).lower()
    _hit = next((k for k in _DEV_SERVER_HINTS if k in _hits), None)
    if not _hit:
        return None
    try:
        _old_rate = float(ctx.config.get('rate') or 0.5)
    except (TypeError, ValueError):
        _old_rate = 0.5
    ctx.config['rate'] = max(_old_rate, 1.0)
    try:
        ctx.config['threads'] = 1
    except Exception:
        pass
    try:
        _mr = int(ctx.config.get('max_rpm') or 0)
        ctx.config['max_rpm'] = 60 if _mr == 0 else min(_mr, 60)
    except (TypeError, ValueError):
        ctx.config['max_rpm'] = 60
    # 🔴 降速必须**落到已构建的限速器**上: RateManager 在 `ScanContext.__init__` 就以
    #   **当时的 rate 快照**构建, 只改 config 对它毫无作用 —— 此前日志宣称"间隔 ≥1.0s",
    #   实际限速器仍按旧值放行(全库审计 M6: 声称的保护没保护)。
    try:
        _rm = getattr(ctx, 'rm', None)
        if _rm is not None:
            _rm.base_rate = max(float(_rm.base_rate), 1.0)
            _rm.rate = max(float(_rm.rate), 1.0)
            if getattr(_rm, 'max_rpm', 0):
                _rm.max_rpm = min(int(_rm.max_rpm), 60)
    except Exception as e:
        dbg(f'反脆弱降级回写限速器失败: {e}')
    _msg = (f'识别到开发服务器指纹({_hit}) → 已强制低并发(threads=1) + '
            f'请求间隔 ≥1.0s + 速率上限 60/分(只降速, 不减覆盖)')
    log(f'[!] 反脆弱降级: {_msg}')
    try:
        ctx.add_finding('INFO', '反脆弱降级(开发服务器)', base or '', _msg)
    except Exception:
        pass
    return _msg


# ---- 信号驱动的自动调度规则表(**单一真源**) ----
#   键 = 能力开关名; 值 = (所需信号元组, 判定函数)。仅当开关值为 `'auto'` 时按规则定值。
#   新增"信号门控"能力 = **在此加一行**(无需再散落 `if cfg.get(k) == 'auto'` 判断)。
#   约定: 判定异常 → 视为 True(**宁多扫、不漏扫**)。
_AUTO_DISPATCH_RULES = {
    # 非 HTTPS 无 TLS 证书可谈 → 省一次注定失败的握手。
    'tls_cert':      (('is_https',), lambda s: s['is_https']),
    # 无端点可探 → OPTIONS 方法发现无意义。
    'options_probe': (('has_endpoints',), lambda s: s['has_endpoints']),
    # 有端点、或已观测 401/403(存在受保护资源) → 值得做未授权确认。
    'unauth_probe':  (('has_endpoints', 'has_protected'),
                      lambda s: s['has_endpoints'] or s['has_protected']),
}


def _collect_dispatch_signals(ctx, out):
    """采集调度信号(纯读, **零发包**)。"""
    try:
        _scheme = urlsplit(getattr(ctx, 'base', '') or '').scheme.lower()
    except Exception:
        _scheme = ''
    return {
        'is_https': _scheme == 'https',
        'has_endpoints': bool(out.get('apis') or out.get('recomb') or out.get('write_apis')),
        'has_protected': any(st in (401, 403)
                             for _p, _m, st, _n in (getattr(ctx, 'all_found', None) or [])),
    }


def resolve_dispatch(ctx, out, only=None):
    """单一调度解析(信号驱动, 替代参数驱动) —— 把 config 里取值为 `'auto'` 的开关按
    **目标信号**解析为 bool 并**写回 `ctx.config`**, 供 `plugins.enabled` / `config.get` 统一消费。

    这是"懒人式使用"的核心: 用户**不指定模块**, 由工具看信号决定。规则表见 `_AUTO_DISPATCH_RULES`。
    显式 `true` / `false` 一律尊重(用户覆盖优先); 仅当值为 `'auto'` 时改写。

    `only`: 只解析指定的键。某些键的信号要到较晚相位才就绪(如 `options_probe` 需先发现端点) ——
    早相位调用时用 `only=('tls_cert',)`, 避免拿"尚未就绪的信号"误判。
    """
    cfg = getattr(ctx, 'config', None)
    if not isinstance(cfg, dict):
        return
    keys = list(only) if only is not None else list(_AUTO_DISPATCH_RULES)
    sig = None
    for k in keys:
        rule = _AUTO_DISPATCH_RULES.get(k)
        if not rule:
            continue
        v = cfg.get(k)
        if not (isinstance(v, str) and v.strip().lower() == 'auto'):
            continue                       # 非 'auto' → 尊重用户显式值
        if sig is None:
            sig = _collect_dispatch_signals(ctx, out)
        try:
            cfg[k] = bool(rule[1](sig))
        except Exception:
            cfg[k] = True                  # 降级: 判定失败 → 不跳过(宁多扫)




def _analyze_home(ctx, base, out, mods, enabled, fp_hits):
    """步骤2: 主页请求 + HTML 分析 + 被动打点/TLS（从 recon_deep 抽出的首页相位）。

    返回 (base, js_urls, declared_js, home_headers, home_html, enabled, fp_hits)
    —— base 可能因重定向归一化而改变；enabled/fp_hits 可能因内联脚本指纹补判而刷新。
    """
    js_urls = set()
    # 「页面直接声明」的 JS(入口图): 首页 + 入口页 HTML 里写出的 <script src> / modulepreload。
    #   与"间接发现"(js_refs 递归 / 目录爆破 / 运行时捕获)区分, 排序时给更高档 —— 见步骤3。
    _declared_js = set()
    home_html = ''           # 供步骤2.55 非首页入口页 JS 收割复用(避免 re-fetch 主页)
    ctx._homepage_fingerprint = ''
    # 不再无条件清空 _catchall_baseline —— 步骤1(detect_and_probe)可能已惰性
    #   建立过基线, 清空会导致步骤4的探测函数拿不到基线而失去 catch-all 保护。
    #   仅在新目标(不同 base)时重置。
    if getattr(ctx, '_catchall_base', None) != base:
        ctx._catchall_baseline = None
        ctx._catchall_tried = False
        ctx._catchall_base = base
    html = ''                # 首页正文; 首页失败时保持空串(下游一律 `html or ''` 守卫)
    r = REQ(ctx, 'GET', base)
    if r is not None:
        html = r.text
        home_html = html
        # 重定向后归一化 base。裸域→www / http→https 的站点若不归一,
        #   后续每个请求都要先吃一次 302 —— 实测服务端 148 次请求 vs 自报 74 次,
        #   流量翻倍且请求计数全部偏小。
        nb = normalize_base(ctx, base, r)
        if nb != base:
            base = nb
            ctx.base = base
            ctx._catchall_base = base
        ctx._homepage_fingerprint = _fingerprint_resp(r)
        # 主页 HTML 的页面类型(SPA / MPA / …) —— 供"场景自动启用运行时通道"等使用。
        #   注意: deep_analyze 里也判页面类型, 但它只收到 **JS 文本 / 内联脚本**;
        #   主页 HTML **从不进 deep_analyze**(除非开 crawl) → page_types 恒空, SPA 信号失效。
        #   这里显式对主页 HTML 判一次, 让 page_types 真正可用。
        out.setdefault('page_types', {})[base] = classify_page_type(html)
        # 发送 canary 随机路径建立 catch-all 基线(取代的"主页指纹"基线)
        # 改为惰性建立 —— 步骤1 的探测函数已经可能先触发它(见 _ensure_catchall_baseline)
        _ensure_catchall_baseline(ctx, base)
        # 从HTML提取初始JS (统一归一化为绝对URL, 防相对路径请求报MissingSchema)
        js_urls = {urljoin(base, u) for u in RE_SRC.findall(html)}
        # 首页**同样**要收 <link rel=modulepreload> 声明的 chunk —— 旧实现只对"非首页入口页"
        #   做这件事(`_harvest_route_entry_js`), 首页仅取 <script src>。Vite 类 SPA 的首页
        #   只有一个入口包在 <script src> 里, 其余 60+ 个 chunk 全在 modulepreload ——
        #   于是**首页直接声明的 chunk 从未被登记**, 只能靠入口包内部的间接引用去发现
        #   (顺序与预算都不可控; 实测承载 RPC 接口表的 chunk 因此没被扫到)。
        _home_link_js = {urljoin(base, u) for u in RE_LINK_JS.findall(html)}
        js_urls |= {_u for _u in _home_link_js
                    if urlsplit(_u).path.endswith(JS_EXTS) and _same_origin(_u, base)}
        # 「页面直接声明」的来源档：首页 + 入口页 HTML 里直接写出的 JS（入口图）。
        _declared_js = set(js_urls)
        # 检测架构
        if 'recon-deep' in mods:
            arch = detect_arch(ctx, html)
            if arch:
                out['apis'] |= arch.get('apis', set())
                out['routes'] |= arch.get('routes', set())
                out['baseurls'] |= arch.get('baseurls', set())
                if arch.get('next_build_id'):
                    out['next_build_id'] = arch['next_build_id']   # 步骤2.4: 内联 <script> 分析
        _inline_blks = _extract_inline_scripts(html)
        # 步骤2.4-α: **内联脚本指纹补判（先于获取步骤）** —— 缺口 D1。
        #   指纹驱动的**获取**步骤(构建清单 2.4c / 隐藏 JS 2.56)此前只吃 step-1(HTML/响应头)指纹,
        #   而只在内联脚本里可见的前端框架(Next.js __NEXT_DATA__ / Nuxt payload / Vite /
        #   webpack runtime…)要到 step3.4(JS 管线内)才补判 → **永远赶不上获取步骤**。
        #   这里用刚提取的内联脚本正文先补判一次, 让获取步骤立即用上这些指纹; 其后的内联分析
        #   也用新鲜 `enabled`(栈专属提取通道)。
        if _inline_blks:
            try:
                if probe_new_fingerprints(ctx, base, _inline_blks):
                    fp_hits = list((getattr(ctx, 'fingerprints', None) or {}).get('hits', []))
                    enabled = get_enabled_rules(getattr(ctx, 'route', None)
                                               or ROUTE_RULES['_DEFAULT'])
                    log(f'[*] 内联脚本指纹补判(先于获取步骤): {fp_hits}')
            except Exception as e:
                dbg(f'内联脚本指纹补判: {e}')
        _inline_api_n = 0
        for _i, _blk in enumerate(_inline_blks):
            try:
                _dec = decode_layer(_beautify_js(_blk))
                _res = deep_analyze(ctx, _dec, f'{base}#inline-{_i}', base, enabled, fp_hits, allow_source_only=False)
                _before = len(out['apis']) + len(out.get('write_apis', {}))
                _merge_out(out, _res)
                out['write_apis'].update(_res.get('write_apis', {}))
                _inline_api_n += len(out['apis']) + len(out.get('write_apis', {})) - _before
            except Exception as e:
                if ctx.config.get('debug'):
                    import traceback as _tb
                    _tb.print_exc()
                log(f'[-] 内联脚本分析异常(block {_i}): {e}')
        if _inline_blks:
            log(f'[*] 内联脚本分析: {len(_inline_blks)} 块, 新增 '
                f'{_inline_api_n} 条接口/写操作候选')
        # 步骤2.4b: 首页 HTML 声明的接口
        #   服务端渲染栈(Django/Rails/Laravel/Spring MVC/ASP.NET/PHP)的接口常写在 HTML 的
        #   action=/href=/data-* 属性里而非 JS; 旧实现只扫 JS → 实测 10 栈"仅 HTML"端点 0/2 全漏。
        try:
            _html_apis = _extract_html_apis(html, base)
            _new_html = _html_apis - out['apis']
            out['apis'] |= _html_apis
            if _html_apis:
                log(f'[*] HTML 声明接口: 提取 {len(_html_apis)} 条, 新增 {len(_new_html)} 条')
        except Exception as e:
            if ctx.config.get('debug'):
                import traceback as _tb
                _tb.print_exc()
            log(f'[-] HTML 接口提取异常: {e}')
        # 步骤2.5: Schema 源探测（OpenAPI/Swagger/GraphQL） —— Phase A 缺口①
        #   最准确、信息量最大的接口+参数+类型来源; 只读 GET / 受限内省 POST,
        #   全部走 REQ(统一限速+熔断+预算), 同源, 不请求跨域、不写、不爆破。
        try:
            from facet.recon import schema as _schema_mod
            _oa, _gq, _auth = _schema_mod.discover_schema(ctx, base, out, REQ)
            if _oa or _gq:
                log(f'[*] Schema 源: OpenAPI/Swagger {_oa} 端点, GraphQL {_gq} 字段端点'
                    + (f', 认证机制 {len(_auth)} 种' if _auth else ''))
        except Exception as e:
            if ctx.config.get('debug'):
                import traceback as _tb
                _tb.print_exc()
            log(f'[-] Schema 探测异常: {e}')
        # 步骤2.4b-2: 表单字段 / 隐藏域 / HTML 注释提取
        #   服务端渲染栈的接口参数写在 <form><input name=...> 里, 隐藏域常带 token/key,
        #   注释常泄露端点/凭据。旧实现只取 action/href 端点, 这三块完全漏掉。
        try:
            _nf, _nfld, _nhid, _ncmt = _extract_html_forms_comments(html, ctx, out, base)
            if _nf or _nfld or _ncmt:
                ctx.add_finding('INFO', 'HTML 表单/注释提取', base,
                                f'表单 {_nf} 个 / 字段 {_nfld} 个(隐藏域 {_nhid}) '
                                f'/ 注释 {_ncmt} 条已扫描')
                log(f'[*] HTML 表单/注释: 表单 {_nf} / 字段 {_nfld}(隐藏 {_nhid}) / 注释 {_ncmt}')
        except Exception as e:
            if ctx.config.get('debug'):
                import traceback as _tb
                _tb.print_exc()
            log(f'[-] HTML 表单/注释提取异常: {e}')
        # 步骤2.4c: 构建清单下载与解析
        #   一份 asset-manifest.json / build-manifest.json 即可直接枚举全部打包产物,
        #   比逐个猜 chunk 路径高效得多, 且能发现"从未被引用"的 chunk。
        #   仅对**前端指纹命中**的目标执行(遵守"指纹是门禁"原则)。
        # 前端栈集合来自**数据层**(dicts.FRONTEND_STACKS), 不在代码里硬编码。
        if any(h in FRONTEND_STACKS for h in fp_hits):
            try:
                _mn = _fetch_build_manifests(ctx, base, out)
                if _mn:
                    log(f'[*] 构建清单: 枚举 {_mn} 个 JS 产物')
            except Exception as e:
                if ctx.config.get('debug'):
                    import traceback as _tb
                    _tb.print_exc()
                log(f'[-] 构建清单解析异常: {e}')
        # 步骤2.5: 被动打点  —— 复用刚拿到的主页响应做安全头审计,
        #   并抓 robots/sitemap/security.txt/favicon。发现的路径并入 out['apis'],
        #   与后续探活共用同一条流水线(仍受限速/熔断/缓存护栏约束)。
        try:
            out['apis'] |= passive_recon(ctx, base, out, home_resp=r)
        except Exception as e:
            if ctx.config.get('debug'):
                traceback.print_exc()
            log(f'[-] 被动打点异常: {e}')
        # 步骤2.6: TLS 证书信息  —— SAN 是子域发现的重要来源。
        #   零 HTTP 请求(只做一次裸 TLS 握手), 失败不影响主流程。
        if ctx.config.get('tls_cert', True):
            try:
                _tls_cert_info(ctx, base)
            except Exception as e:
                if ctx.config.get('debug'):
                    traceback.print_exc()
                log(f'[-] TLS 证书提取异常: {e}')
    else:
        # 主页请求失败**不再等于整轮扫描失败**。
        #   现在: 主页失败也继续做被动打点(无主页响应 → 跳过安全头审计)与 TLS 提取。
        log('[!] 主页请求未成功, 仍继续被动打点与 TLS 提取')
        try:
            out['apis'] |= passive_recon(ctx, base, out, home_resp=None)
        except Exception as e:
            if ctx.config.get('debug'):
                traceback.print_exc()
            log(f'[-] 被动打点异常: {e}')
        if ctx.config.get('tls_cert', True):
            try:
                _tls_cert_info(ctx, base)
            except Exception as e:
                if ctx.config.get('debug'):
                    traceback.print_exc()
                log(f'[-] TLS 证书提取异常: {e}')
    return base, js_urls, _declared_js, home_html, enabled, fp_hits


def _run_crawl(ctx, base, home_html, out, enabled, fp_hits, js_urls):
    """步骤2.5: 同源多页爬取（从 recon_deep 抽出; 默认关闭, 需 --crawl-depth）。

    解决"接口藏在二级页面 / 表单里"的漏抓: BFS 跟随同源 <a>/<form action>, 逐页
    deep_analyze(提取内联脚本/表单/接口), 并把新发现的 JS 入队。
    """
    _cd_raw = ctx.config.get('crawl_depth', 0)
    if _cd_raw == 'auto':
        # auto: 首页**同源链接足够多**(站点确是多页) 才爬, 深度温和取 2; 否则不爬(守最小发包)。
        #   `html` 已在函数入口初始化为 ''(见上) → 直接引用。旧写法 `locals().get('html')`
        #   是**反射读局部变量**: 上游一旦改名, 这里静默取空 → crawl auto 静默失效(审计)。
        _hh = home_html or ''
        _same_links = {urljoin(base, _h) for _h in re.findall(r'href=["\']([^"\']+)["\']', _hh)}
        _same_links = {u for u in _same_links
                       if _same_origin(u, base) and u.rstrip('/') != base.rstrip('/')}
        _cd = 2 if len(_same_links) >= 10 else 0
    else:
        try:
            _cd = int(_cd_raw or 0)
        except (TypeError, ValueError):
            _cd = 0
    if _cd > 0:
        try:
            # 页数上限按**首页实际链接数**自适应（配置值为下限，硬顶 1000）
            from .adapt import effective_page_cap, note
            _cmp = effective_page_cap(ctx.config, len(RE_LINK_JS.findall(home_html))
                                      + len(re.findall(r'<a\b', home_html or '', re.I)))
            note(ctx, 'crawl_max_pages', ctx.config.get('crawl_max_pages', 30), _cmp,
                 '按首页 <a> 链接数 + 声明资源数派生')
            _cr = crawl_site(ctx, base, _cd, _cmp)
            _newp = {p for p in _cr['paths'] if p and p != '/'}
            if _newp:
                out['apis'] |= _newp
            _extra_pages = [(_pu, _ph) for (_pu, _ph) in _cr['pages']
                            if _pu.rstrip('/') != base.rstrip('/')]
            for _pu, _ph in _extra_pages:
                _pres = deep_analyze(ctx, _ph, _pu, base, enabled, fp_hits, allow_source_only=False)
                _merge_out(out, _pres)
                for _nu in _pres.get('js_refs', set()):
                    _nabs = urljoin(_pu, _nu)
                    if urlsplit(_nabs).path.endswith(JS_EXTS) and _same_origin(_nabs, base):
                        js_urls.add(_nabs)
                # wasm 引用(HTML 页面里也可能直接预加载 .wasm)
                for _wr in _pres.get('wasm_refs', set()):
                    _drain_wasm_ref(ctx, _wr, _pu, base, out)
            if _cr['pages']:
                ctx.add_finding('INFO',
                                f'多页爬取: {len(_cr["pages"])} 页 / {len(_newp)} 个同源路径',
                                base, '同源 BFS(<a>/<form action>)')
            log(f'[*] 多页爬取(深度{_cd}): {len(_cr["pages"])} 页, 新增路径 {len(_newp)} 个')
        except Exception as e:
            if ctx.config.get('debug'):
                traceback.print_exc()
            log(f'[-] 多页爬取异常: {e}')


def _run_js_phase(ctx, base, out, js_urls, enabled, fp_hits, home_html, declared_js, _prof):
    """步骤2.55–3.7: 入口页 JS 收割 / 发现即抓取 / JS 管线(首轮+运行时追打) /
    JS 阶段指纹补判 / 二次获取 / SPA 路由收割 / 断点续扫状态保存（从 recon_deep 抽出）。
    """
    # 步骤2.55: 非首页"入口页"JS 收割（默认开; 同源只读 GET）
    #   接在 crawl_site 之后: 后者只跟随首页静态 <a>/<form>, 抓不到"不在首页链接里"的
    #   入口页(登录/后台/账户…常如此, 尤其 SPA)。本阶段补一组**高价值入口页猜测**, 被动 GET
    #   这些页、提取其专属 <script src> JS 并入 js_urls(步骤3 统一分析), 补齐"非首页才加载的
    #   JS"缺口。纯被动、不登录、受 max_pages 上限与全局护栏约束。
    try:
        _harvest_route_entry_js(ctx, base, home_html, out, js_urls, enabled, fp_hits)
    except Exception as e:
        if ctx.config.get('debug'):
            traceback.print_exc()
        log(f'[-] 非首页入口页 JS 收割异常: {e}')
    # 入口页 HTML 直接声明的 JS 也属"入口图" —— 并入来源档（**不含** 2.56 的目录爆破猜测）
    declared_js |= set(js_urls)
    # 步骤2.56: 隐藏 JS 发现(默认开, 只读) —— 两条来源, 命中者并入 js_urls 走步骤3 分析
    #     ① 目录爆破: 已发现 JS 的目录 × 常见文件名;
    #     ② **指纹专属 JS 路径**: 命中框架 → `HIDDEN_PATHS_BY_STACK` 里该栈声明的 .js/.mjs
    #        (Angular /main.js…、Livewire /livewire/livewire.js…) —— 闭环"指纹分支 → 更多 JS"。
    #   受 js_dir_fuzz_max 与全局护栏约束。
    if plugins.enabled('collector', 'jsdir', ctx.config):
        try:
            _jd = js_dir_fuzz(ctx, base, js_urls, fp_hits)
            for _u in _jd:
                js_urls.add(_u)
            # `hidden_js` 产出曾只写不读(报告从不引用, 审计 D5) —— 已删除该死产出;
            #   命中的 JS 仍进入 js_urls 正常分析, 无信息损失。
        except Exception as e:
            if ctx.config.get('debug'):
                traceback.print_exc()
            log(f'[-] JS 目录爆破异常: {e}')
    # 步骤2.9: **发现即抓取** —— 把 `out['js_refs']`(构建清单枚举 + 各来源 JS 引用)里
    #   **同源**的 JS 并入 js_urls。缺口 D4: 此前 `out['js_refs']` 只写不读 → 构建清单
    #   (`asset-manifest.json` / Next.js `_buildManifest.js` 等)枚举出的 chunk **从不被抓取分析**。
    _drained = _drain_js_refs(out, base, js_urls)
    if _drained:
        log(f'[*] 发现即抓取: 并入 {_drained} 个 out[js_refs] 同源 JS 走步骤3 分析')
    # 步骤3: 递归JS分析(管线可多次调用 —— 首轮分析首页/入口页发现的 JS; 运行时通道
    #   捕获的 SPA 路由懒加载 chunk 在步骤3.5.2 追打第二轮, 见下方 _run_js_pipeline 二次调用)
    from .config import effective_max_js
    state = {
        'seen': set(),
        'queue': [],
        'js_bodies': [],          # 供 JS 阶段指纹补判使用(步骤3.4 覆盖两轮累积正文)
        # 自适应上限(初值按已发现 JS 数; 管线循环内会按发现总量再上浮, 硬顶 max_js_hard_cap)
        'max_js': effective_max_js(ctx.config, len(js_urls)),
        'declared': set(declared_js),   # 页面**直接声明**的 JS(入口图) —— 排序时给更高档(来源驱动)
        '_fp_total': 0,           # 指纹补判去重计数(每批刷新前比对, 见 _refresh_fingerprints_from_bodies)
        'enabled': enabled,       # 指纹命中后的门控规则(每批分析前刷新)
        'fp_hits': fp_hits,
    }
    # 断点续扫恢复
    if ctx.config.get('resume'):
        state_store = _get_state_store(ctx.config)
        state['seen'] = ctx.load_state(base, 'js', state_store)
        saved_queue = ctx.load_state(base, 'js_queue', state_store)
        if saved_queue:
            state['queue'] = list(saved_queue)
    n_js_pass1 = _run_js_pipeline(ctx, base, out, js_urls, state)
    log(f'[*] 步骤3 JS 管线(首轮: 首页/入口页发现): 分析 {n_js_pass1} 个 JS 文件')
    _prof.mark('步骤3 JS 管线(首轮: 首页/入口页 JS)')
    # 步骤3.5: 运行时侦察（Playwright）—— runtime 三态: false / true / auto
    #   auto: 仅 SPA 目标启用(静态 JS 覆盖最弱、运行时收益最大), 非 SPA 保持关闭。
    rt_result = None
    _run_rt, _rt_why = should_run_runtime(ctx, out)
    # 能力宣称 = 真实执行: 默认"未运行", 只有浏览器会话**确实启动并跑完**才置 True。
    #   旧实现 `= bool(_run_rt)` 记的是**意图** —— 显式 runtime=true 但 Playwright 缺失时,
    #   `runtime_recon` 直接返回空, 而报告仍据 `_run_rt` 把"没跑"说成"已启用"(实测缺陷)。
    ctx.runtime_ran = False
    ctx.runtime_reason = ''
    # 区分"未请求"(auto 未触发 / false)与"请求了但没跑成" —— 报告披露文案按此分流,
    #   不再把 auto 未触发也说成"⚠️ 已请求但未实际运行"(误导: 它本就是设计不跑)。
    ctx.runtime_requested = bool(_run_rt)
    if _run_rt:
        log(f'[*] 运行时通道: 已请求 ({_rt_why})')
        try:
            from ..recon.runtime import runtime_recon
            rt_result = runtime_recon(ctx, base)
            ctx.runtime_ran = bool(rt_result.get('ran'))
            ctx.runtime_reason = rt_result.get('reason') or ''
            if not ctx.runtime_ran:
                log(f'[-] 运行时通道未实际运行: {ctx.runtime_reason or "未知原因"} '
                    f'(报告将如实披露为"未启用", 不得谎称已启用)')
            else:
                out['apis'] |= rt_result.get('apis', set())
                # R1: 浏览器真实观测到的端点 = 最强证据(runtime) —— 只升不降。
                _ev_bump(out, 'runtime', rt_result.get('apis', set()))
                out['websockets'] |= rt_result.get('websockets', set())
                # 运行时观测到的**跨域端点**(route 层已 abort, 只登记不请求) —— 并入 external_apis。
                #   实测真实 SPA 的业务 API 常在跨域主机(api.* / conduit.* 等), 不登记就"什么都看不到"。
                out.setdefault('external_apis', set())
                out['external_apis'] |= rt_result.get('external_requests', set())
                # DevTools 等价: 把浏览器捕获的**真实参数**与**响应状态**并入扫描上下文,
                #   直接补上"端点发现 + 参数提取"两个最大缺口(纯静态 JS 分析拿不到)。
                _rt_params = rt_result.get('params') or {}
                for _rp, _ps in _rt_params.items():
                    for _pn in _ps:
                        ctx.link_param(_rp, _pn)
                # 取值形态(只记形态, 不存原值): 并入 ctx.param_shapes, 供报告判断 IDOR 可利用性。
                for _rp, _pm in (rt_result.get('param_shapes') or {}).items():
                    _dst = ctx.param_shapes.setdefault(_rp, {})
                    for _pn, _ss in _pm.items():
                        _dst.setdefault(_pn, set()).update(_ss)
                _rt_resp = rt_result.get('responses') or set()
                for _rp, _rm, _rst in _rt_resp:
                    ctx.add_all_found(_rp, _rm, _rst, 'runtime捕获')
                # R5: 被只读护栏**拦截**的写请求(浏览器观测到但未发送) —— 留证登记:
                #   finding + write_apis(只登记方法, 探活仍走只读可达性验证, 零写流量)。
                _rt_wb = rt_result.get('write_blocked') or []
                out.setdefault('runtime_write_blocked', [])
                for _w in _rt_wb:
                    _wm = str(_w.get('method') or 'POST').upper()
                    _wu = str(_w.get('url') or '')
                    _wp = urlsplit(_wu).path or _wu
                    out['runtime_write_blocked'].append({'method': _wm, 'url': _wp})
                    ctx.add_finding('INFO', f'运行时观测写接口({_wm})', _wu,
                                    '浏览器观测到但被只读护栏拦截 · 未发送任何请求(观测≠发送)')
                    if _wp not in out['write_apis']:
                        out['write_apis'][_wp] = _wm
                    _ev_bump(out, 'runtime', [_wp])
                if _rt_wb:
                    log(f'[*] Runtime通道: {len(_rt_wb)} 个写请求被只读护栏拦截'
                        f'(观测≠发送, 已登记为只读观察项)')
                log(f'[*] Runtime通道完成: +{len(rt_result.get("apis", set()))} API, '
                    f'+{sum(len(v) for v in _rt_params.values())} 参数, '
                    f'+{len(_rt_resp)} 响应')
        except Exception as e:
            if ctx.config.get('debug'):
                # 注意: **不可**在此 `import traceback` —— 模块顶部已导入(第 17 行),
                #   函数内再裸导入会把 `traceback` 变成**函数局部名**, 使本函数更早处
                #   (会话预热 except)的 `traceback.print_exc()` 抛 `UnboundLocalError`
                #   (F823, "函数内 import 遮蔽模块级同名"陷阱)。
                traceback.print_exc()
            # 异常 = 未成功运行 → 保持 runtime_ran=False, 并记录原因供报告如实披露。
            ctx.runtime_ran = False
            ctx.runtime_reason = f'Runtime 通道异常: {e}'
            log(f'[-] Runtime通道异常: {e}')
    else:
        # 未请求(auto 未触发 / runtime=false) —— 原因入 ctx, 供报告区分披露
        #   "已配置但未触发"与"已请求但未实际运行", 不再把 auto 未触发说成"⚠️ 已请求但未实际运行"。
        ctx.runtime_reason = _rt_why or 'runtime 未触发'
    _prof.mark('步骤3.5 运行时通道(Playwright)')
    # 步骤3.5.2: 追打运行时通道捕获的 SPA 路由懒加载 chunk。
    #   背景: 纯 client-routed SPA 的路由专属 .js 只在浏览器**导航**该路由时才被
    #     `import()` 动态加载 —— 静态 GET /dashboard 仅返回 SPA shell(同一主包已分析),
    #     故静态收割对 SPA 常"新增 0 个 JS"。只有运行时(Playwright)导航这些入口路由
    #     才能真正捕获其懒加载 chunk。这里把运行时观测到的**同源 .js** 再喂入 JS 管线
    #     _run_js_pipeline 做 deep_analyze, 补齐"非首页才加载的 JS"缺口。
    #   约束: 同源 / 只 deep_analyze(只读提取端点·路由·参数, 不利用) / 全局限速·熔断·
    #     预算 / 已扫文件(state['seen'])自动跳过(首页主包等不重复分析)。
    if rt_result:
        _rt_js = set()
        for _u in (rt_result.get('js_urls') or rt_result.get('urls') or set()):
            try:
                if urlsplit(_u).path.endswith(JS_EXTS) and _same_origin(_u, base):
                    _rt_js.add(_u)
            except Exception as e:
                dbg(f'运行时 JS URL 解析 {_u}: {e}')
        if _rt_js:
            n_js_rt = _run_js_pipeline(ctx, base, out, _rt_js, state)
            # 如实披露: 运行时捕获的同源 JS 总数 vs 其中**首轮未覆盖**的新增数(可能为 0 ——
            #   如目标无路由级代码分割, 或 chunk 已被首轮 js_refs 递归枚举)。避免"无输出"被
            #   误读成"通道没跑"。
            log(f'[*] 运行时通道捕获同源 JS {len(_rt_js)} 个(含首轮已扫), 新增分析 {n_js_rt} 个')
            if n_js_rt:
                ctx.add_finding('INFO', f'运行时通道捕获并分析 {n_js_rt} 个路由专属 JS chunk',
                                base, '同源只读导航; 仅 deep_analyze 提取端点/路由/参数, 不利用')
                log(f'[*] 步骤3 JS 管线(运行时追打): 分析 {n_js_rt} 个 SPA 路由懒加载 JS 文件')
    # 步骤3.4: JS 阶段指纹补判(覆盖首轮 + 步骤3.5.2 累积的全部 js_bodies)
    #   HTML 阶段只能看到 body/headers, 有一类指纹(tRPC / Rollup / esbuild / Parcel /
    #   SolidJS)的 body 规则为空, 结构性不可能在 HTML 阶段命中 → 其专属探测
    #   (如 _trpc_probe) 永远是死代码。JS 下载完成后补判一次, 并追加其门控探测。
    if state['js_bodies']:
        try:
            new_fp = probe_new_fingerprints(ctx, base, state['js_bodies'])
            if new_fp:
                state['fp_hits'] = list((getattr(ctx, 'fingerprints', None) or {}).get('hits', []))
                state['enabled'] = get_enabled_rules(getattr(ctx, 'route', None)
                                                   or ROUTE_RULES['_DEFAULT'])
        except Exception as e:
            if ctx.config.get('debug'):
                traceback.print_exc()
            log(f'[-] JS 阶段指纹补判异常: {e}')
    # 步骤3.6: 指纹补判后**二次获取**(闭环缺口 D1) —— 只在**外部 JS**里可见的前端框架
    #   (Rollup / esbuild / Parcel / tRPC / SolidJS …)在 step3.4 才补判, 而获取步骤(2.4c/2.56)
    #   早已跑完 → 其构建清单与栈专属 JS 永久漏获。此处用**刷新后的指纹**补跑一次获取, 命中
    #   并入 js_urls 再跑一轮管线(仅当出现新指纹时触发, 故开销有界)。
    _fp2 = list((getattr(ctx, 'fingerprints', None) or {}).get('hits', []))
    if set(_fp2) - set(fp_hits):
        try:
            _js2 = set()
            if any(h in FRONTEND_STACKS for h in _fp2):
                _mn2 = _fetch_build_manifests(ctx, base, out)
                if _mn2:
                    log(f'[*] 步骤3.6 二次获取: 构建清单补枚举 {_mn2} 个 JS 产物')
            _js2 |= _fp_stack_js_probe(ctx, base, js_urls, _fp2)
            _drained2 = _drain_js_refs(out, base, js_urls)
            for _u in _js2:
                js_urls.add(_u)
            if _js2 or _drained2:
                _n2 = _run_js_pipeline(ctx, base, out, js_urls, state)
                log(f'[*] 步骤3.6 指纹补判后二次获取: 新增 {len(_js2) + _drained2} 个 JS, '
                    f'本轮分析 {_n2}')
        except Exception as e:
            if ctx.config.get('debug'):
                traceback.print_exc()
            log(f'[-] 步骤3.6 二次获取异常: {e}')
    # 步骤3.7: SPA 路由感知抓取(B2) —— 用**目标自己声明的路由表**(`out['routes']`)当种子页
    #   再收割一轮 JS/端点。步骤2.6 的入口页收割只用"首页链接 + login/dashboard 猜测";
    #   本步骤补上 C1 提取的前端路由。纯客户端 SPA 各路由回同一 shell → 内部自动提前停止
    #   并如实披露; SSR / 多页应用才真正有新增。新增 JS 走**同一条** JS 管线分析。
    try:
        _n_rp, _n_rjs = _harvest_spa_routes(ctx, base, out, js_urls,
                                            state['enabled'], state['fp_hits'])
        if _n_rjs:
            _n_r2 = _run_js_pipeline(ctx, base, out, js_urls, state)
            log(f'[*] 步骤3.7 SPA 路由收割: {_n_rp} 页 / 新增 {_n_rjs} 个 JS, 本轮分析 {_n_r2}')
    except Exception as e:
        if ctx.config.get('debug'):
            traceback.print_exc()
        log(f'[-] 步骤3.7 SPA 路由收割异常: {e}')
    # 保存状态(断点续扫)
    #   `persist_state` 必须入此门控(见 _should_save_state 注释): 仅按 `--resume` /
    #   撞 max_js 上限才落盘时, 小站(seen 远小于 max_js、未传 --resume)只传
    #   `--persist-state` 的状态文件**永不生成** —— 随后 `--resume` "按空状态开始"
    #   却无任何提示(假成功), 与三处设计注释的声明不一致。显式开启即显式落盘。
    if _should_save_state(ctx.config, len(state['seen']), state['max_js']):
        state_store = _get_state_store(ctx.config)
        ctx.save_state(base, 'js', state['seen'], state_store)
        remaining = [u for u in state['queue'] if u not in state['seen']]
        ctx.save_state(base, 'js_queue', remaining, state_store)
        if remaining:
            log(f'[!] JS队列未扫完: {len(remaining)} 个待续扫 (--resume)')
            # 同上: 未扫完的 JS 必须在报告"扫描完整性"里如实披露,
            #   否则"接口少"会被误读成"目标接口就这些"。
            #   修复 chunk 枚举后, 一个 runtime 可枚举上百个 chunk, 触发概率显著上升。
            ctx.note_truncated('js_queue_unscanned', len(remaining))
            log(f'[!] 提示: 当前 max_js={state["max_js"]}; 大站建议在 ~/.facet/config.yaml 提高到 300+ '
                f'(max_js: 300) 以覆盖全部 chunk')
    _prof.mark('步骤3.5.2 追打 + 3.4 + 状态保存')


def _postprocess_endpoints(ctx, base, out):
    """步骤4 前置: baseURL 归一 / 噪声过滤 / 隐藏字典 / 路径推断 / 同族去重 / URL 泄露检测
    （从 recon_deep 抽出）。返回去重后的探活代表列表 _all_apis_dedup。
    """
    # R1 证据分级快照: baseURL 归一化/噪声过滤**之前**的提取路径集合。
    #   变换后仍存在的路径保持原证据(如 runtime 标记不被扰动); 变换**新产生**的
    #   路径(补了 JS 声明的 baseURL 前缀)标 full-url —— 强于裸 static 字面量。
    _pre_extracted = (set(out['apis']) | set(out['recomb']) | set(out['write_apis']))
    # 应用 JS 中声明的 baseURL —— 旧实现只采集不使用, 导致
    #   `axios.create({baseURL:'/api'})` 的站点**所有接口路径都缺前缀**:
    #   探活全部命中 SPA catch-all 被判"伪命中"排除 → "接口 0 条" → idor/sqli 无目标。
    if out.get('baseurls'):
        _n_before = len(out['apis']) + len(out['write_apis'])
        out['apis'] = _apply_baseurls(out['apis'], out['baseurls'], base)
        out['recomb'] = _apply_baseurls(out['recomb'], out['baseurls'], base)
        _wa = {}
        for _op, _m in out['write_apis'].items():
            for _np in _apply_baseurls({_op}, out['baseurls'], base):
                _wa[_np] = _m
        out['write_apis'] = _wa
        # 跨域 baseURL 必须**显式披露**。旧实现静默跳过却照样打印"按 baseURL [...]
        #   归一化接口路径", 造成"已生效"的假象 —— 实测目标接口主机 api.luffycity.com
        #   与站点不同源, 11 条候选一条都没被归一化, 而日志毫无异常迹象。
        _prefixes, _cross_bu = _classify_baseurls(out['baseurls'], base)
        if _cross_bu:
            out['external_apis'] |= set(_cross_bu)
            ctx.add_finding('MED', '跨域接口基址(不探活)',
                            base,
                            f'{len(_cross_bu)} 个: ' + ', '.join(sorted(_cross_bu)[:3])
                            + ' —— 与站点不同源, 本工具不向其发包; 上述接口路径的真实'
                              '前缀需人工按该主机补全')
            log(f'[!] 跨域接口基址 {len(_cross_bu)} 个(不探活, 已披露): '
                f'{sorted(_cross_bu)[:3]}')
        log(f'[*] 按 baseURL {sorted(_prefixes)} 归一化接口路径 '
            f'({_n_before} → {len(out["apis"]) + len(out["write_apis"])} 条候选)'
            + (f' | 跨域基址 {len(_cross_bu)} 个未应用(已披露)' if _cross_bu else ''))
    # R2 route-rebase: 前端路由按 baseURL 反查后端端点(纵深防御)
    #   场景: SPA 用 `axios({baseURL:'/api'})` + 路由 `path:"/admin/user/list"`, 真实后端是
    #   `/api/admin/user/list`。懒加载 chunk(含真实 `u.get("/admin/user/list")` 调用)若未被
    #   运行时通道捕获(无浏览器 / 未导航到受登录门禁的 admin 路由), 仅路由串落入 out['routes'],
    #   而 _apply_baseurls 不处理 routes → 后端端点永久漏掉。此处用已发现的 baseURL 把每条
    #   "深层"前端路由重建为后端候选并入 apis, 由探活阶段判定真伪(与已知 baseURL 归一同口径)。
    #   仅在确实存在 baseURL 时启用(强信号: 该 SPA 用相对调用 + 基址), 避免无谓候选膨胀。
    if out.get('baseurls') and out.get('routes'):
        _rebased = {p for p in _apply_baseurls(out['routes'], out['baseurls'], base)
                    if _is_plausible_api_path(p)
                    and len([_s for _s in p.split('/') if _s]) >= 2}
        _new = _rebased - out['apis']
        if _new:
            out['apis'] |= _new
            _ae = out.setdefault('api_extractor', {})
            for _p in _new:
                _ae[_p] = 'route-rebase'
            log(f'[*] 按 baseURL 反查前端路由推导出 {len(_new)} 个后端端点候选'
                f'({", ".join(sorted(_new)[:3])}{"…" if len(_new) > 3 else ""})')
    # 噪声过滤: 丢弃明显非端点路径的候选(开发库 JS 注释/标签片段等被正则误抓),
    #   仅保留路径层面合理的条目, 避免污染 apis / extracted_endpoints。
    #   **无条件执行**(不依赖 baseURL 是否存在) —— 否则无 baseURL 的站点会跳过本过滤。
    #   + **静态资源 / 畸形形态**过滤(中段静态目录、中段扩展名、残缺结尾) —— 与
    #     `infer_path_variants` 基址校验、动态基址门禁**同口径**, 避免 `/x/images/sps/-`
    #     这类路径进入 apis 再被派生出一堆扩展名变体。
    out['apis'] = {_p for _p in out['apis']
                   if _is_plausible_api_path(_p) and not is_static_or_malformed_path(_p)}
    out['recomb'] = {_p for _p in out['recomb']
                     if _is_plausible_api_path(_p) and not is_static_or_malformed_path(_p)}
    # R1: 经 baseURL 归一化**重建**出的新路径 → full-url(只升不降, 不扰动已有
    #   runtime 标记 —— bump 语义保证强证据永不被降级)。
    _now_extracted = (set(out['apis']) | set(out['recomb']) | set(out['write_apis']))
    _ev_bump(out, 'full-url', _now_extracted - _pre_extracted)
    # 隐藏接口字典叠加 — 无 JS 引用的接口只能靠主动探测发现, 该能力保留;
    #   但**必须与"目标真实线索"分区存放**。旧实现把 12 条字典路径直接
    #   `out['apis'].update(...)`, 与 JS/HTML 提取到的真实接口混为一谈。实测某 SPA
    #   的 152 个 JS 文件里这 12 条路径出现 **0 次**, 报告却把它们当"目标接口"呈现 ——
    #   使用者无法分辨哪些来自目标、哪些来自通用字典。现在单独成集, 报告按
    #   "字典候选"单列; 探活时仍一并纳入(all_apis 合并), **能力不减**。
    # 泛 API 路径猜测 —— 单一事实来源在 dicts.GENERIC_API_GUESS_PATHS(**通用**, 不依赖技术栈)。
    #   注: **栈专属路径不在此列** —— `/actuator*`、`/druid/index.html`、`/swagger.json`、
    #   `/api-docs` 由**指纹门控**的分层字典(`get_hidden_paths` → `HIDDEN_PATHS_BY_STACK`)
    #   按栈加载(Spring / Swagger 命中才探); 旧实现把它们硬编码在此 → 绕过门控, 导致
    #   **Express 站(jsonplaceholder)也出现 `/actuator`、`/actuator/env`** 等非本栈候选。
    #   (`/swagger.json`、`/api-docs` 另由 schema 源探测通道无条件探测, 不丢覆盖。)
    _HIDDEN_DICT = list(GENERIC_API_GUESS_PATHS)
    _dict_seen = out.setdefault('dict_candidates', set())
    _missing = [p for p in _HIDDEN_DICT
                if p not in out['apis'] and p not in out['recomb'] and p not in _dict_seen]
    if _missing:
        log(f'[+] 叠加隐藏接口**字典候选** {len(_missing)} 个'
            f'(JS/HTML 之外 · 主动探测通道 · 与目标真实线索分区统计)')
        _dict_seen.update(_missing)
    # ---- 路径推断(方案 4.6): 由**目标提取到**的路径派生同族候选 ----
    #   纯字符串变换(动词族 / 单复数 / 扩展名 / 批量↔单品), 不做语义猜测;
    #   产出**与提取结果分区存放**(`out['inferred_paths']`), 报告按来源单列 ——
    #   绝不把"推断出来的"混进"提取到的"。
    # catch-all 站: 任意路径都回**同一 2xx** → 派生变体**无法验证**, 只会放大噪声 → 跳过。
    #   判定用 **canary 回 2xx**(真 catch-all: 任意路径都"存在")—— 而非 `multi_path_catchall`:
    #   普通 404 站多个 canary 的 404 页本就近乎相同, 该标志会误报为 True, 用它会把**普通站的
    #   路径推断全部误杀**(实测本地 404 靶标即被误判)。与 hidden_probe 的 `_catchall_regime`
    #   (`status==200`) 同口径。无基线时不改行为。
    _site_catchall = bool((getattr(ctx, '_catchall_baseline', None) or {}).get('status') == 200)
    if plugins.enabled('collector', 'infer', ctx.config) and not _site_catchall:
        _known = (out['apis'] | out['recomb'] | set(out['write_apis'])
                  | set(out.get('dict_candidates', set()))
                  | set(out.get('inferred_paths', set())))
        # 扩展名词汇由**目标自身信号**归纳(指纹 + 已观测端点扩展名) —— 无证据则不加/不换扩展名,
        #   消除"栈盲加 .php/.aspx"噪声(实测 Vite/React 站被无脑加出 40+ 垃圾变体)。
        _ext_vocab = derive_ext_vocab(
            out['apis'] | out['recomb'],
            (getattr(ctx, 'fingerprints', None) or {}).get('hits', []))
        _mv = int(ctx.config.get('path_infer_max_variants', 6) or 6)
        _inf = set()
        for _p in sorted(out['apis'] | out['recomb']):
            for _v in infer_path_variants(_p, _mv, allowed_exts=_ext_vocab):
                if _v not in _known:
                    _inf.add(_v)
        # 派生条数上限按**已提取端点数**自适应（配置值为下限）—— 该阶段**零发包**，
        #   上限是"噪声控制"而非时间控制，故用发现量信号而非预算信号。
        from .adapt import effective_page_cap as _epc
        from .adapt import note as _note
        _cap = _epc(ctx.config, len(out['apis'] | out['recomb']),
                    key='path_infer_max_total', hard=5000)
        _note(ctx, 'path_infer_max_total', ctx.config.get('path_infer_max_total', 200), _cap,
              f'已提取端点 {len(out["apis"] | out["recomb"])} 条')
        if _cap and len(_inf) > _cap:
            _inf = set(sorted(_inf)[:_cap])
        if _inf:
            out.setdefault('inferred_paths', set()).update(_inf)
            _vtxt = ','.join(sorted(_ext_vocab)) if _ext_vocab else '无(不派生扩展名)'
            log(f'[+] 路径推断: 派生同族候选 {len(_inf)} 个'
                f'(动词族/单复数/扩展名/批量↔单品 · 扩展名词汇: {_vtxt} · 与提取结果分区统计)')
    all_apis = (out['apis'] | out['recomb'] | set(out['write_apis'])
                | set(out.get('dict_candidates', set()))
                | set(out.get('inferred_paths', set())))
    # 同族端点归一去重 —— 数字/UUID/哈希/日期/长随机段视为动态,
    #   每个家族只探测一个真实代表(首个变体), 既省配额又避免报告同族爆炸。
    #   归一键与探测代表分开: 探测用的是**真实变体路径**(如 /api/user/1),
    #   绝不能拿 {id} 占位符去探测(目标无此字面量会 404 误判)。
    _api_families = {}
    for _p in sorted(all_apis):
        _api_families.setdefault(normalize_endpoint(_p), []).append(_p)
    _all_apis_dedup = [v[0] for v in _api_families.values()]
    out['api_families'] = _api_families
    _n_collapsed = len(all_apis) - len(_all_apis_dedup)
    if _n_collapsed:
        log(f'[*] 端点归一去重: {len(all_apis)} → {len(_all_apis_dedup)} '
            f'(合并 {_n_collapsed} 个同族变体)')
    # URL 敏感参数检测 —— 只对**目标来源**的路径做, 且每个路径只查一次。
    #   这些路径来自 JS/HTML 提取, 若其中带 `?token=`/`?key=` 等, 才是目标的真实泄露。
    # URL 泄露检测必须遍历**全部**变体 —— 归一化会抹掉 query,
    #   而 `?token=`/`?key=` 这类泄露是 query 的属性, 与路径同族无关;
    #   若只查去重代表会漏掉"带敏感参数的变体"(回归保护)。
    #   探测去重则只看路径同族(见下), 不影响泄露检测完整性。
    for _p in sorted(all_apis):
        _check_url_leak(ctx, urljoin(base, _p))
    # R1: 字典候选 / 路径推断 → dict(最弱证据; 与"目标真实提取"分区存放)。
    _ev_bump(out, 'dict', out.get('dict_candidates', set()))
    _ev_bump(out, 'dict', out.get('inferred_paths', set()))
    ctx.write_apis = out['write_apis']  # 同步写方法表, probe据此标记写接口(零发包)
    # 路径推断候选同步给报告层(来源列标"路径推断", 与提取结果分区)
    ctx.inferred_paths = set(out.get('inferred_paths') or set())
    return _all_apis_dedup


def _run_probes(ctx, base, out, extracted, extras, all_apis_dedup, token):
    """步骤4: 调度解析 + 探活 / OPTIONS / 未授权访问确认（从 recon_deep 抽出）。

    · 探活是**必做项**(用户明确), 不受 `mods` 门控;
    · 提取到的接口不受 `max_probe` 上限; 字典候选 / 路径推断(猜测)另探, 仍受上限;
    · 写方法仅以 GET/HEAD 验证可达性, **绝不发写请求**(合规红线不变);
    · 仍受统一限速/熔断/预算约束(保护目标)。
    """
    # 调度解析(信号驱动): 把 'auto' 的探活开关(options_probe / unauth_probe)按**目标信号**定值
    #   —— 替代"用参数调度模块"(懒人式)。显式 true/false 不被改写。
    resolve_dispatch(ctx, out)
    # 探活排序用"证据/来源"分层(复用 `_EV_RANK`; 启发式反查候选 `route-rebase` 归最低档 0)。
    #   背景: 端点证据分级(out['evidence'])此前**已计算却从未用于探活排序** —— 于是低证据的
    #   route-rebase / 字典候选与运行时观测 / AST 端点**同权**, 在预算或上限截断时可能挤占
    #   已验证端点。此处把数值档写入 ctx.evidence, 由 probe() 的排序键消费(零新增发包)。
    _ae = out.get('api_extractor') or {}
    ctx.evidence = {p: _EV_RANK.get(t, 1) for p, t in (out.get('evidence') or {}).items()}
    for _p, _x in _ae.items():
        if _x == 'route-rebase':
            ctx.evidence[_p] = 0
    # 门控统一走插件注册表(`plugins.enabled`) —— 单一调度来源。`prober.probe` 恒开。
    if plugins.enabled('prober', 'probe', ctx.config):
        try:
            # 提取到的接口必探活, 但仍受 max_probe_extracted 硬顶保护(默认 2000; 0=不限) ——
            # 防巨型 JS / 超大 sitemap 提取出的上千路径突破流量/时间控制(审计 D1)。
            try:
                _ext_cap = int((ctx.config or {}).get('max_probe_extracted', 2000) or 0)
            except (TypeError, ValueError):
                _ext_cap = 2000
            probe(ctx, base, sorted(extracted), token, no_cap=True, hard_cap=_ext_cap)
        except Exception as e:
            if ctx.config.get('debug'):
                traceback.print_exc()
            log(f'[-] 探活异常: {e}')
        if extras:
            try:
                probe(ctx, base, sorted(extras), token)
            except Exception as e:
                if ctx.config.get('debug'):
                    traceback.print_exc()
                log(f'[-] 附加探活异常: {e}')
    # OPTIONS / Allow 方法发现(方案 2-B): 只读 OPTIONS, 拿目标**自述**支持的方法(按代表探, 省包)
    if plugins.enabled('prober', 'options', ctx.config):
        try:
            options_probe(ctx, base, all_apis_dedup, token)
        except Exception as e:
            if ctx.config.get('debug'):
                traceback.print_exc()
            log(f'[-] OPTIONS 方法发现异常: {e}')
    if plugins.enabled('prober', 'unauth', ctx.config):
        hidden_probe(ctx, base, token)
    # 注: 本工具定位为**纯侦察 / 攻击面测绘** —— 原 `cors` / `param` / `idor` / `sqli`
    #   四个**主动验证模块已整体移除**(不设计攻击操作)。`probe`(探活)与 `unauth`
    #   (未授权访问**确认**)属"发现性确认", 保留 —— 它们只回答"这个端点是否存在 /
    #   是否需要鉴权", 不做任何利用。


def _run_secret_verify(ctx, base):
    """步骤6: 可选密钥实时验证（从 recon_deep 抽出; 默认关闭, 向第三方发起只读验证）。

    正则命中 ≠ 真实有效(可能是示例/占位/已吊销)。对部分云密钥做**只读**验证,
    把"疑似泄露"升级为"已确证泄露"。仅发只读端点, 不修改任何远端资源。
    """
    if ctx.config.get('verify_secrets'):
        # 合规披露(审计 D2): 本能力向第三方 provider 发起"语义只读"校验, 但:
        #   ① 存在 POST 形式的校验端点(如 slack auth.test)—— 虽不改写资源, 仍属**写向第三方**;
        #   ② **疑似密钥以完整明文经网络传输**至 provider(报告/审计日志仅留脱敏回显 {value[:4]}…);
        #   ③ provider 侧可能产生日志/审计/速率限制等副作用。
        #   故默认关闭(verify_secrets: False), 开启即视为已理解上述外联性质。
        try:
            log('[!] 合规告警: 已开启密钥实时验证 —— 将向第三方服务(api.github.com / '
                'gitlab.com / slack.com / stripe.com / openai / anthropic / npm / '
                'sendgrid / heroku) 发起**语义只读**验证请求。')
            log('[!] 合规告警: 上述验证会把疑似密钥以**完整明文**经网络传输至对应 provider'
                '(报告与审计日志仅保存脱敏回显); 个别 provider 使用 POST 校验端点。'
                '仅限自有/已授权资产开启。')
            ctx.add_finding(
                'INFO', '密钥实时验证(第三方外联)', base,
                '已开启 verify_secrets: 向第三方 provider 发起语义只读校验; 疑似密钥以'
                '完整明文经网络传输(报告仅留脱敏回显); 仅限自有/已授权资产使用')
            _n_v, _n_i, _n_u = _verify_secrets_pass(ctx, base)
            if _n_v or _n_i:
                ctx.add_finding('INFO', '密钥实时验证汇总', base,
                                f'有效 {_n_v} / 无效 {_n_i} / 未知 {_n_u} '
                                f'(未知=无对应 provider 或网络不可达, 未改变结论)')
        except Exception as e:
            if ctx.config.get('debug'):
                import traceback as _tb
                _tb.print_exc()
            log(f'[-] 密钥实时验证异常: {e}')


def recon_deep(ctx, base, mods, token=None):
    """指纹驱动的深度侦察主入口"""
    log(f'[*] recon-deep: {base} | 模块 {mods}')
    # 外部提取规则(动态获取): 覆盖内置过滤词表 / 禁用内置调用点模式。缺省回退内置(行为不变)。
    apply_extract_rules(load_extract_rules((ctx.config or {}).get('extract_rules')))
    _prof = _Prof(ctx)
    # 目标根写入 ctx, 供 _probe_req / _ensure_catchall_baseline 使用
    ctx.base = base
    # 调度层裁决 SCA 是否启用(能力在 recon/sca.py; "是否启用"的路由决策归编排层,
    #   见 CONTRIBUTING.md「设计约定」R2)。deep_analyze 只消费此裁决, 不在此自决 —— 消除
    #   "领域模块读 config 决定是否调兄弟能力"的反模式。
    ctx.sca_enabled = plugins.enabled('enricher', 'sca', ctx.config)
    # 全局时间预算。429 退避可把单请求拖到 RATE_MAX=60s, 没有总预算时
    #   一次扫描能挂到几小时(实测 800 条 sitemap 在默认限速下 150s 仍未完成)。
    #   预算耗尽后 REQ 直接返回 None, 由报告披露"截断", 而不是无限等待。
    ctx.start_budget(ctx.config.get('max_duration', 0))
    # 会话预热。需要认证的目标必须先建立会话(cookie), 否则 recon 阶段
    #   全程 401、JS 一个都抓不到 —— 实测该场景提取到的接口数为 0。
    #   只发 GET, 不做任何登录提交, 保持只读定位。
    try:
        warm_up_session(ctx, base)
    except Exception as e:
        if ctx.config.get('debug'):
            traceback.print_exc()
        log(f'[-] 会话预热异常: {e}')
    # R4 登录态采集(opt-in, login_capture): 可见浏览器里**手动**登录 → 抓 storage_state
    #   → 回灌 HTTP 长驻会话(浏览器通道上下文同样注入)。凭据**仅内存态**: 不落盘、
    #   不进报告/审计(审计仅记"已采集")。失败/超时按原认证态继续并如实披露。
    if ctx.config.get('login_capture'):
        try:
            log('[*] [login-capture] 登录态采集(opt-in): 即将打开**可见**浏览器, '
                '请在窗口内手动完成登录, 再回终端按 Enter 结束采集')
            from ..recon.runtime import runtime_capture_login, apply_captured_state
            _cap = runtime_capture_login(ctx, base)
            if _cap.get('ran') and _cap.get('state'):
                _n = len(apply_captured_state(ctx, _cap.get('state')) or {})
                ctx.add_finding('INFO', '登录态采集完成', base,
                                f'已采集并回灌 {_n} 个 cookie(仅内存态, 不落盘)')
                log(f'[+] [login-capture] 已回灌 {_n} 个 cookie(凭据仅内存态)')
            else:
                ctx.add_finding('INFO', '登录态采集未完成', base,
                                f"{_cap.get('reason') or '未采集'} —— 以原认证态继续")
                log(f'[-] [login-capture] {_cap.get("reason") or "未采集"}; 以原认证态继续')
        except Exception as e:
            if ctx.config.get('debug'):
                traceback.print_exc()
            log(f'[-] [login-capture] 登录态采集异常(以原认证态继续): {e}')
    out = {'apis': set(), 'params': set(), 'recomb': set(), 'routes': set(),
           'baseurls': set(), 'nfiles': 0, 'write_apis': {}, 'api_methods': {}, 'subdomains': set(),
           'websockets': set(), 'sse': set(), 'grpc': set(), 'ws_messages': [],
           # route_switches 必须在此初始化 —— _merge_out() 会对它执行
           #   `out[k] |= res[k]`, 缺键直接 KeyError, 每次扫描都会崩在第一次 deep_analyze 之后。
           'route_switches': set(),
           # R1 端点证据分级: path → tier(runtime > full-url > static > dict)。
           #   只由 _ev_bump 写入(只升不降); 报告层读取时缺省 'static'。
           'evidence': {},
           # 报告需要"JS 资源清单"的真实来源。
           'js_files': [],
           # JS 文件引用(import/require/chunk), 只用于递归抓取
           'js_refs': set(),
           # .wasm 引用 / 从 wasm 提取的己方接口(§3.7-G2)
           'wasm_refs': set(),
           'wasm_apis': set(),
           # /4.7.16: 附属结构(供报告读取; 缺省为空, 由 _merge_out 填充)
           'page_types': {}, 'api_conf': {}, 'api_srcline': {}, 'api_extractor': {},
           'api_snippet': {},
           # 动态解包(opt-in)还原出的 module.exports 产物 —— {源JS: {config, endpoints, keys}}
           'recovered': {},
           'sca_libs': {}, 'sca_vulns': [],
           # 构建产物拆包映射 —— {bundle_url: [模块相对路径, ...]}
           'bundle_modules': {},
           # 跨域绝对 API 调用 / 跨域 baseURL(只登记不探活) —— 与己方 apis 分区
           'external_apis': set(),
           # **相对端点片段**(基址在配置里, 非本站绝对路径) —— 只登记不探活。
           'relative_apis': set(),
           # 隐藏路径**字典候选**(通用字典, 非目标真实线索) —— 与 apis 分区存放,
           #   探活时合并进 all_apis, 但报告计数与展示必须分开, 否则使用者无法分辨
           #   哪些接口来自目标、哪些来自通用字典。
           'dict_candidates': set(),
           # 跨域 JS(构建产物 chunk 里指向第三方域的绝对 URL) —— 只登记不抓取,
           #   与同源 js_refs 分区, 报告里单列。
           'external_js': set(),
           # Phase A（缺口①）: Schema 源(OpenAPI/Swagger/GraphQL)解析结果
           'schema_apis': set(),     # Schema 来源的端点(同源, 已并入 apis)
           'schema_params': {},      # 端点 → {method, source, params:[{name,in,type,required}]}
           'schema_auth': []}        # 解析到的认证机制(securitySchemes)
    # **部分结果句柄**: 把 `out` 挂到 ctx 上。看门狗(SIGALRM → `ScanGlobalTimeout`)在任意阶段
    #   中止扫描时, 调用方(CLI)仍能取到**已收集的部分结果**并如实导出 —— 旧实现 CLI 里写死
    #   `meta = {}`, 于是日志说"导出已完成的部分报告"却导出了**空报告**(实测: `js_files: 0`)。
    #   `out` 全程**原地变更**(不重新赋值), 故该引用始终指向最新状态。
    ctx._partial_out = out

    # 早期调度解析(信号已就绪的键): `tls_cert` 只需"目标是否 HTTPS"(零发包, 立即可判) ——
    #   非 HTTPS 目标跳过 TLS 证书提取(省一次注定失败的握手)。其余键(options_probe /
    #   unauth_probe)的信号要到探活相位才齐, 由彼处再次调用 resolve_dispatch 解析。
    resolve_dispatch(ctx, out, only=('tls_cert',))

    # 初始化响应指纹集合(用于聚类去重)
    ctx._resp_fingerprints = set()

    # 步骤1: 框架条件化探测
    enabled = detect_and_probe(ctx, base)
    if enabled is None:
        enabled = get_enabled_rules(ROUTE_RULES['_DEFAULT'])

    # 指纹命中列表 — 用于专属正则注入与隐藏路径按栈加载
    fp_hits = list((getattr(ctx, 'fingerprints', None) or {}).get('hits', []))
    log(f'[*] 指纹命中 {len(fp_hits)} 项: {fp_hits if fp_hits else "无(仅启用通用规则)"}')
    # 框架识别降级(方案六): 识别到开发服务器 → 强制低并发 + 加大间隔(尽早生效, 覆盖后续 JS 抓取与探活)
    _dev_downgrade = _apply_dev_server_downgrade(ctx, base)

    # 步骤2: 主页HTML分析（已抽为独立函数 _analyze_home）
    base, js_urls, _declared_js, home_html, enabled, fp_hits = (
        _analyze_home(ctx, base, out, mods, enabled, fp_hits))

    _prof.mark('步骤0-2 被动打点/指纹/首页/被动发现')
    # 步骤2.5: 同源多页爬取（已抽为独立函数 _run_crawl）
    _run_crawl(ctx, base, home_html, out, enabled, fp_hits, js_urls)

    _prof.mark('步骤2.5 多页爬取(crawl)')
    # 步骤2.55–3.7: JS 相位（已抽为独立函数 _run_js_phase）
    _run_js_phase(ctx, base, out, js_urls, enabled, fp_hits, home_html, _declared_js, _prof)

    # 步骤4: 模块执行
    # 步骤4 前置: 端点后处理（已抽为独立函数 _postprocess_endpoints）
    _all_apis_dedup = _postprocess_endpoints(ctx, base, out)

    # 【强制要求·探活必做】对**所有提取到的接口**一律探活一次, 真实结果写入报告。
    #   · 不再受 `mods` 门控 —— 探活是**必做项**(用户明确), 不是可选增强;
    #   · 不再因"同族归一去重"只探代表 —— 每个端点(含同族变体)都探一次;
    #   · **提取到的接口不受 `max_probe` 上限**(用户: 所有提取接口必探活);
    #   · 字典候选 / 路径推断(猜测·非提取)另探, 仍受 `max_probe` 上限(控流量);
    #   · 写方法仅以 GET/HEAD 验证可达性, **绝不发写请求**(合规红线不变);
    #   · 仍受统一限速/熔断/预算约束(保护目标)。
    _extracted = out['apis'] | out['recomb'] | set(out['write_apis'])
    _extras = (set(out.get('dict_candidates', set()))
               | set(out.get('inferred_paths', set()))) - _extracted
    _run_probes(ctx, base, out, _extracted, _extras, _all_apis_dedup, token)

    # 注: 本工具定位为**纯侦察 / 攻击面测绘** —— 原 `cors` / `param` / `idor` / `sqli`
    #   四个**主动验证模块已整体移除**(不设计攻击操作)。`probe`(探活)与 `unauth`
    #   (未授权访问**确认**)属"发现性确认", 保留 —— 它们只回答"这个端点是否存在 /
    #   是否需要鉴权", 不做任何利用。

    _prof.mark('步骤4 探活/模块执行')
    # ---------- 步骤4.5: 表单字段 → 端点 的**数据流关联收尾**(零推断 · 纯分析) ----------
    #   必须在参数消费方(param_probe / 报告参数列)之前执行, 否则关联结果不可见。
    _run_form_link_step(ctx, base)

    _prof.mark('步骤4.5 表单→端点关联')
    # 步骤5: 元数据
    out['modules'] = modules_of([p for p, _, _, _ in ctx.all_found])
    out['fingerprints'] = getattr(ctx, 'fingerprints', {})

    # 步骤6: 可选密钥实时验证（已抽为独立函数 _run_secret_verify）
    _run_secret_verify(ctx, base)


    # 步骤7: 落盘用全量发现集（供 ScanHistory 角色差分对比）。
    #   out['apis'] 含"全部提取端点"(确认 + 候选 + Schema + 浏览器复盘并入)，
    #   是目标暴露面的**全集**；而 ctx.all_found(apis 表)只是"探活确认"的子集(常很稀疏，
    #   如 Petstore 仅 1 条)。角色差分若要定位"仅认证可见的端点"，必须对比全集，否则几乎无差异。
    ctx.discovery = set(out.get('apis') or set())
    _prof.mark('步骤5-7 元数据/可选验证/落盘准备')
    _prof.dump()
    return out


_SILENT_SAMPLES = 60          # 报告里列出的"零产出"文件样本上限（计数不受此限）

# 解包链特征：文件里出现"运行时再解释/解码"的调用 —— 静态层看不到它真正的内容。
_RE_UNPACK_CHAIN = re.compile(
    r'\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*["\']|\batob\s*\('
    r'|\bString\.fromCharCode\b|\bdecodeURIComponent\s*\(')


def _eff_silent_min(ctx, out):
    """"零产出披露"的体积门槛 —— 由**本站 JS 体积分布**派生（`adapt.effective_silent_min`）。

    固定 20KB 的问题很实在：小站（文件都 5KB）会把**全部**文件滤掉 = 等于不披露；
    大站（文件都 200KB）又会**全报** = 噪声。改用本站体积 **P90**（最大的那 10%），
    夹在 [8KB, 128KB]。每 32 个文件重算一次（样本在增长），并记录来源供报告披露。
    """
    cfg = getattr(ctx, 'config', None) or {}
    _sizes = [_s[1] for _s in (out.get('js_files') or ()) if len(_s) > 1 and _s[1]]
    _n = len(_sizes)
    _cached = getattr(ctx, '_eff_silent_min', None)
    if _cached is not None and not (_n and _n % 32 == 0):
        return _cached
    try:
        from .adapt import effective_silent_min, note, percentile
        _v = effective_silent_min(cfg, _sizes)
        ctx._eff_silent_min = _v
        _p90 = percentile(_sizes, 0.90)
        note(ctx, 'silent_js_min_size', cfg.get('silent_js_min_size', 20480), _v,
             f'本站 JS 体积 P90={(_p90 or 0) / 1024:.0f}KB（样本 {_n}）')
        return _v
    except Exception:
        return int(cfg.get('silent_js_min_size', 20480) or 20480)


def _bundler_of(text):
    """命中已知**打包器签名** → 返回打包器名（如 `'webpack'`）；否则 `None`。

    判据取自数据层 `dicts.BUNDLER_SIGNATURES`（单一真源），只用高特异度字面量标记。
    动机: 「零产出」里有一大类其实是**打包产物**（代码都在, 只是模块化封装了）—— 它与
    「混淆」该给的建议**完全不同**（打包 → `unbundle` 拆模块; 混淆 → `strong_deobf`/`dynamic_deobf`）。
    """
    if not text:
        return None
    try:
        from .dicts import BUNDLER_SIGNATURES
    except Exception:
        return None
    for _name, _marks in BUNDLER_SIGNATURES:
        for _m in _marks:
            if _m in text:
                return _name
    return None


def _silence_reason(text, cfg=None, min_size=None):
    """文件**零产出**时，给出"为什么读不出"的可核查归类（纯本地文本判定，零发包）。

    返回 `''`（不算静默）/ `'疑似打包产物(<打包器>)'` / `'疑似混淆'` / `'含解包链'` / `'无产出'`。
    `min_size`（体积门槛）由 `_eff_silent_min` 按**本站体积分布**派生；缺省回退配置值。
    """
    if not text:
        return ''
    if min_size is None:
        try:
            min_size = int((cfg or {}).get('silent_js_min_size', 20480) or 0)
        except (TypeError, ValueError):
            min_size = 20480
    _min = int(min_size or 0)
    if _min and len(text) < _min:
        return ''
    # 打包器判定**先于**混淆判定: 打包产物是"读得懂但没拆"（非混淆）—— 建议方向不同, 不能混为一谈。
    _bundler = _bundler_of(text)
    if _bundler:
        return f'疑似打包产物({_bundler})'
    if _looks_obfuscated(text) or _looks_vm_packer(text):
        return '疑似混淆'
    if _RE_UNPACK_CHAIN.search(text):
        return '含解包链'
    return '无产出'


def _note_silent_js(ctx, out, url, text, res):
    """登记"**体量够大却一条都提取不出**"的 JS —— 报告必须如实披露。

    动机（实测）：全量扫 1370 个 JS，只有 22 个有端点归属。绝大多数零产出是合理的
    （第三方库/小组件），但**报告此前无法区分"本来就没有接口"与"我们没读懂"** ——
    后者会被静默当成"那里没有接口"（正是"假成功"）。此处在**零发包**前提下把这件事说出来。
    """
    try:
        _yield = (len(res.get('apis') or ()) + len(res.get('routes') or ())
                  + len(res.get('rpc_apis') or {}) + len(res.get('labels') or {})
                  + len(res.get('field_dict') or {}) + len(res.get('params') or ())
                  + len(res.get('write_apis') or {}))
    except Exception:
        return
    if _yield:
        return
    # 门槛由**本站 JS 体积分布**派生（固定 20KB 在小站会把全部文件滤掉、在大站又全报）。
    _why = _silence_reason(text, getattr(ctx, 'config', None),
                           min_size=_eff_silent_min(ctx, out))
    if not _why:
        return
    _n = len(text)
    out['silent_js_n'] = int(out.get('silent_js_n', 0)) + 1
    out['silent_js_bytes'] = int(out.get('silent_js_bytes', 0)) + _n
    if _why in ('疑似混淆', '含解包链'):
        out['silent_js_unreadable_n'] = int(out.get('silent_js_unreadable_n', 0)) + 1
    # **真实计数**按归类累计（样本列表另有上限，二者不可混用 —— 否则"59 个样本"会被
    #   误读成"只有 59 个文件"）。
    _by = out.setdefault('silent_js_by_reason', {})
    _by[_why] = int(_by.get(_why, 0)) + 1
    _s = out.setdefault('silent_js', [])
    if len(_s) < _SILENT_SAMPLES:
        _s.append({'url': url, 'bytes': _n, 'reason': _why})


_BODY_SAMPLE = 32 * 1024      # 每份 JS 正文保留的头/尾采样字节数


def _body_sample(dec, size=_BODY_SAMPLE):
    """JS 正文 → **有界采样**（头 + 尾）—— 供指纹补判兜底用，避免全量分析时内存无界增长。"""
    if not dec or len(dec) <= 2 * size:
        return dec or ''
    return dec[:size] + '\n' + dec[-size:]


def _merge_out(out, res):
    """合并 deep_analyze 结果到 out"""
    for k in ('apis', 'params', 'recomb', 'routes', 'baseurls', 'subdomains',
              'websockets', 'sse', 'grpc', 'route_switches', 'js_refs',
              'wasm_refs', 'wasm_apis',
              'external_apis', 'relative_apis', 'dict_candidates', 'external_js'):
        if k in res:
            out.setdefault(k, set())
            out[k] |= res[k]
    if 'write_apis' in res:
        out['write_apis'].update(res['write_apis'])
    if 'ws_messages' in res and res['ws_messages']:
        out.setdefault('ws_messages', []).extend(res['ws_messages'])
    # 字典类附属结构(页面类型 / 接口来源行号 / 置信度)逐键合并
    for k in ('page_types', 'api_conf', 'api_srcline', 'api_extractor', 'api_methods',
              'labels', 'rpc_apis', 'field_dict', 'param_taint', 'ast_results',
              'api_snippet'):
        if k in res and res[k]:
            out.setdefault(k, {}).update(res[k])
    # SCA —— 库(同名时"带版本"优先覆盖"无版本"); 漏洞按 (name,id) 去重
    if res.get('sca_libs'):
        out.setdefault('sca_libs', {})
        for name, info in res['sca_libs'].items():
            old = out['sca_libs'].get(name)
            if old is None or (not old.get('version') and info.get('version')):
                out['sca_libs'][name] = info
    if res.get('sca_vulns'):
        out.setdefault('sca_vulns', [])
        seen = {(v.get('name'), v.get('id')) for v in out['sca_vulns']}
        for v in res['sca_vulns']:
            key = (v.get('name'), v.get('id'))
            if key not in seen:
                out['sca_vulns'].append(v)
                seen.add(key)


def _classify_baseurls(baseurls, base):
    """把发现的 baseURL 分成"可用前缀"与"跨域(不探活)"两类。

    返回 (prefixes, cross)。`cross` 是跨域绝对 URL 列表 —— 调用方**必须显式披露**,
    而不是静默丢弃。旧实现只做静默 `continue`, 调用方却仍打印
    `按 baseURL [...] 归一化接口路径 (11 → 11 条候选)` —— 数字看起来"生效了",
    实际一条都没归一化。实测目标接口主机为 api.luffycity.com(与站点 www 不同源),
    于是全部接口路径保持无前缀, 探活全部落空, 而日志没有任何异常迹象。
    """
    b = urlsplit(base or '')
    prefixes, cross = [], []
    for bu in baseurls:
        bu = (bu or '').strip()
        if not bu or bu in ('/', '.'):
            continue
        if bu.startswith(('http://', 'https://')):
            u = urlsplit(bu)
            if (u.scheme, u.netloc) != (b.scheme, b.netloc):
                cross.append(bu)               # 跨域: 不探活, 但必须披露
                continue
            p = u.path
        else:
            p = bu
        p = '/' + p.strip('/')
        if p != '/':
            prefixes.append(p)
    return prefixes, cross


def _apply_baseurls(paths, baseurls, base):
    """把 JS 里声明的相对路径与发现的 baseURL 组合成**真实**接口路径 

    为什么必须做:
      SPA 普遍写 `axios.create({baseURL:'/api'})` + `axios.get('/admin/orders')` ——
      **真实接口是 `/api/admin/orders`**。旧实现把 baseURL 采集到 out['baseurls']
      后**从未使用**(全项目只有写入/合并/返回, 无消费点), 于是探的是 `/admin/orders`:
        · 命中 SPA catch-all(任意未知路径都回 index.html 且 200) → 判"伪命中"排除
        · 结论变成"接口 0 条", 且 idor / sqli 两个模块**没有目标可测**

    规则:
      · 只接受"像路径"的 baseURL(`/api`)或**与站点同源**的绝对 URL;
        跨域绝对 URL 跳过(跨域不探活, 与合规定位一致) —— 分类逻辑见 `_classify_baseurls`,
        调用方负责把跨域项**披露**出来。
      · 已带该前缀的路径不重复拼接(`/api/x` 不会变成 `/api/api/x`)。
      · 绝对 URL(http/https/`//` 开头)不受影响。
      · **相对路径按 axios 语义"替换"为拼接后的路径** —— axios 的
        `buildFullPath()` 对非绝对 URL 一律 `baseURL + url`(即便 url 以 `/` 开头),
        因此原路径**不是**可达路径, 保留它只会污染"写操作接口"表并白耗请求。
      · 未匹配到任何可用 baseURL 时**原样返回**, 不做任何猜测。
    """
    paths = set(paths)
    if not baseurls:
        return paths
    prefixes, _cross = _classify_baseurls(baseurls, base)
    if not prefixes:
        return paths
    # baseURL 的**首段**集合 —— 用于识别"已是本站绝对路径"(见下方判据)。
    _prefix_heads = {p.strip('/').split('/')[0].lower() for p in prefixes if p.strip('/')}
    out = set()
    for path in paths:
        if not path or path.startswith(('http://', 'https://', '//')):
            out.add(path)                      # 绝对 URL 不受影响
            continue
        p2 = path if path.startswith('/') else '/' + path
        if any(p2 == pre or p2.startswith(pre + '/') for pre in prefixes):
            out.add(p2)                        # 已带**完整**该前缀 → 原样保留
            continue
        # **已是本站绝对路径** → 不再拼 baseURL。
        #   判据(纯形态, 由 baseURL 自身派生, 无站点白名单): 路径的**首段**与 baseURL 的
        #   首段相同 → 该路径本就写全了应用上下文, 再拼就是重复前缀。
        #   实测(weikayun, baseURL=`/wls_prs_sps/action/router`): 路径 `/wls_prs_sps/action/
        #   autoLookup/truckAutoLookup`(已是绝对)被拼成 `/wls_prs_sps/action/router/wls_prs_sps/
        #   action/autoLookup/truckAutoLookup`(双前缀), 且**全部**提取路径被套上该前缀 →
        #   业务域聚类塌缩成单一伪域 `wls_prs_sps`(n=30), 「按业务分组」失去意义。
        if p2.strip('/').split('/')[0].lower() in _prefix_heads:
            out.add(p2)
            continue
        for pre in prefixes:
            out.add(pre + p2)                  # 按 axios 语义拼接
    return out


def detect_arch(ctx, html):
    """架构分型(SPA SSR payload 解析: Next.js / Nuxt)

    Next.js(__NEXT_DATA__) 与 Nuxt(__NUXT__) 的 SSR payload **各自独立解析**, 互不
    借用对方结果 —— 历史上曾让 Nuxt 分支复用 Next 的解析对象, 导致双框架同页时
    Nuxt 提取跑在错误对象上(真实代码缺陷, 已修正)。
    """
    try:
        m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.S)
        nuxt = re.search(r'window\.__NUXT__\s*=\s*(\{.*?\});?\s*</script>', html, re.S)
        if m or nuxt:
            apis = set()
            extra = {}
            # Next.js(__NEXT_DATA__) 与 Nuxt(__NUXT__) 的 SSR payload **各自独立解析**,
            #   不复用对方结果, 且任一侧解析失败不连累另一侧(旧实现两分支共享同一 try,
            #   Next 异常会中断 Nuxt 提取 —— 真实缺陷, 已修正)。
            if m:                              # Next.js: props.pageProps 中可能有API路径
                try:
                    nd = json.loads(m.group(1))
                    pp = nd.get('props', {}).get('pageProps', {})
                    _extract_paths_from_obj(pp, apis)
                    # Next.js 的 chunk 清单位于 /_next/static/<buildId>/_buildManifest.js,
                    #   而 buildId 只写在 __NEXT_DATA__ 里 —— 不取出来就永远定位不到该清单,
                    #   于是 Next.js 的 chunk 一个都枚举不出。
                    if nd.get('buildId'):
                        extra['next_build_id'] = str(nd['buildId'])
                    # `next_page` 曾在此产出但全库无消费点(审计 D4) —— 已删, 免得
                    # 读者以为"翻页跟随"存在。
                except Exception as e:
                    dbg(f'SSR payload(__NEXT_DATA__)解析: {e}')
            if nuxt:                           # Nuxt: 独立解析自己的 payload
                try:
                    _extract_paths_from_obj(json.loads(nuxt.group(1)), apis)
                except Exception as e:
                    dbg(f'SSR payload(__NUXT__)解析: {e}')
            _arch = {'apis': apis, 'routes': set(), 'baseurls': set()}
            _arch.update(extra)
            return _arch
    except Exception as e:
        dbg(f'架构分型 detect_arch: {e}')
    return None


# 注: `_extract_paths_from_obj` 已下沉到 core/util.py。

# ---------- JS 保存 ----------
def save_js(ctx, u, t):
    """JS落盘: 按域名归档"""
    host = urlparse(u).netloc.replace(':', '_')
    d = os.path.join(_output_dir('downloads'), host)
    os.makedirs(d, exist_ok=True)
    name = os.path.basename(urlparse(u).path) or 'index.js'
    p = os.path.join(d, name)
    i = 1
    while os.path.exists(p):
        try:
            with open(p, encoding='utf-8', errors='ignore') as _f:
                if _f.read() == t:
                    return p
        except Exception:
            pass
        p = os.path.join(d, f'{i}_{name}'); i += 1
    with open(p, 'w', encoding='utf-8') as f:
        f.write(t)
    return p


# ---------- 状态存储 ----------
class MemoryStateStore:
    """内存态状态存储: 默认不落盘, 避免默认扫描在目录里额外写一个状态文件。

    断点续扫状态仅在用户显式开启(`--resume` / `persist_state: true`)时落盘
    （`_get_state_store` 据此返回文件 / SQLite 存储）。
    """
    def save(self, base, phase, data):
        pass
    def load(self, base, phase):
        return set()

def _should_save_state(config, seen_n, max_js):
    """断点续扫状态落盘门控: 显式开启(`--resume` / `--persist-state`)或 seen 撞 max_js 上限。

    `persist_state` 必须入此门控: 仅按 `--resume` / 撞上限才落盘时, 小站(seen 远小于
    max_js、未传 `--resume`)只传 `--persist-state` 的状态文件**永不生成** —— 随后
    `--resume` "按空状态开始"却无任何提示(假成功), 与 `_get_state_store` /
    `MemoryStateStore` / DEFAULT_CONFIG 三处 "resume / persist_state 才落盘"
    的声明不一致。`max_js=0`(不限)保持旧语义(`seen>=0` 恒真)。
    """
    return bool(config.get('resume') or config.get('persist_state')
                or seen_n >= max_js)


def _get_state_store(config):
    stype = str(config.get('state_store') or 'file').strip().lower()
    # 默认不持久化(内存态): 仅当用户显式开启续扫持久化(resume / persist_state)才落盘,
    #   保证"默认扫描目录只剩 HTML + JSON 两个主文件"。
    if not (config.get('persist_state') or config.get('resume')):
        return MemoryStateStore()
    # 仅保留 stdlib-only 的 file / sqlite 两类后端。redis 远程后端已移除: 其依赖从未在
    #   pyproject 声明, `import redis` 失败只走 dbg()(FACET_DEBUG 才可见) → 续扫状态被
    #   **静默丢弃**(假成功), 违反"能力缺失必须留痕"纪律。对未知/已移除后端**显式披露**并回退
    #   默认(不静默), 与 runtime 缺依赖同口径。
    if stype not in ('file', 'sqlite'):
        log(f'[!] 不支持的 state_store 后端: {stype!r}(redis 等远程后端已移除), 回退 file')
        stype = 'file'
    if stype == 'sqlite':
        return SQLiteStateStore(config.get('state_path') or str(_output_dir() / 'facet_state.db'))
    return FileStateStore(config.get('state_path') or str(_output_dir() / '.facet_state.json'))


class FileStateStore:
    def __init__(self, path=None):
        self.path = path or str(_output_dir() / '.facet_state.json')
        self._save_failed_logged = False   # 保存失败只警告一次, 避免批量目标刷屏
    def save(self, base, phase, data):
        try:
            import json as _json
            # 父目录预建: 状态文件默认落在 output/ 下, 该目录在"无 JS 落盘"的扫描里
            # 可能尚不存在(实测: 0 JS + --persist-state 首扫 → open('w') 抛
            # FileNotFoundError → 被 except 吞 → 续扫按空状态开始, 假成功)。
            from ..output.paths import ensure_parent
            ensure_parent(self.path)
            st = {}
            if os.path.exists(self.path):
                with open(self.path, encoding='utf-8') as f:
                    st = _json.load(f)
            st.setdefault(base, {}).setdefault(phase, [])
            st[base][phase] = sorted(set(st[base][phase]) | set(data))
            with open(self.path, 'w', encoding='utf-8') as f:
                _json.dump(st, f, ensure_ascii=False, indent=1)
        except Exception as e:
            # --persist-state 是用户显式开启的能力, 失败必须留痕(否则"已保存"是假成功)。
            # 可见化一次(此前仅 dbg, 非 debug 运行下完全静默)。
            dbg(f'状态保存失败({self.path}): {e}')
            if not self._save_failed_logged:
                self._save_failed_logged = True
                log(f'[!] 续扫状态保存失败({self.path}): {e} —— 中断后续扫将按空状态开始')
    def load(self, base, phase):
        try:
            import json as _json
            with open(self.path, encoding='utf-8') as f:
                st = _json.load(f)
            return set(st.get(base, {}).get(phase, []))
        except Exception as e:
            dbg(f'状态恢复失败({self.path}, 视为空): {e}')
            return set()


class SQLiteStateStore:
    def __init__(self, path=None):
        self.path = path or str(_output_dir() / 'facet_state.db')
    def _ensure_table(self):
        import sqlite3
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS state (base TEXT, phase TEXT, data TEXT, PRIMARY KEY(base, phase))')
    def save(self, base, phase, data):
        self._ensure_table()
        import json as _json
        import sqlite3
        with closing(sqlite3.connect(self.path)) as conn:
            old = set()
            cur = conn.execute('SELECT data FROM state WHERE base=? AND phase=?', (base, phase))
            row = cur.fetchone()
            if row:
                old = set(_json.loads(row[0]))
            merged = sorted(old | set(data))
            conn.execute('INSERT OR REPLACE INTO state VALUES (?, ?, ?)', (base, phase, _json.dumps(merged)))
    def load(self, base, phase):
        self._ensure_table()
        import json as _json
        import sqlite3
        try:
            with closing(sqlite3.connect(self.path)) as conn:
                cur = conn.execute('SELECT data FROM state WHERE base=? AND phase=?', (base, phase))
                row = cur.fetchone()
                return set(_json.loads(row[0])) if row else set()
        except Exception as e:
            dbg(f'状态恢复失败({self.path}, 视为空): {e}')
            return set()
