# -*- coding: utf-8 -*-
"""HTML / 构建产物 / JS 引用 / wasm 提取 —— 从 `core/engine.py` 拆出（便于维护）。"""
import base64
import json
import re
from urllib.parse import urljoin, urlparse, urlsplit

from facet.core.log import log

from .const import (
    _BUILD_MANIFEST_PATHS,
    _FORM_ACTION_RE,
    _FORM_BLOCK_RE,
    _FORM_FIELD_RE,
    _FORM_ID_RE,
    _FORM_OPEN_RE,
    _HTML_ATTR_OPT,
    _HTML_COMMENT_RE,
    _JS_AXIOS_BODY_RE,
    _JS_BODY_FETCH_RE,
    _JS_FORM_VAR_RE,
    _JS_FORMDATA_VAR_RE,
    _JS_FROMENTRIES_VAR_RE,
    _JS_MANIFEST_MARKERS,
    _JS_REF_PATTERNS,
    _MAX_WASM_REFS,
    _NAME_ATTR_RE,
    _RE_WP_IDMAP,
    _RE_WP_INLINE_MAP,
    _TYPE_ATTR_RE,
    _VALUE_ATTR_RE,
    _WASM_PATH_HINT,
    _WASM_PATH_RE,
    _WASM_PRINTABLE,
    _WASM_REF_RE,
    _WASM_URL_RE,
    MAX_JS_REFS_PER_FILE,
    _html,
)
from .dicts import RE_API, normalize_extracted_path
from .log import dbg
from .util import _host_of


# ---------- 子域名提取 ----------
def _extract_subdomains(text, base):
    host = urlparse(base).hostname or ''
    if not host or '.' not in host:
        return set()
    root = '.'.join(host.split('.')[-2:])
    out = set()
    for m in re.finditer(r'https?://([a-zA-Z0-9_\-\.]+\.' + re.escape(root) + r')', text):
        out.add(m.group(1))
    for m in re.finditer(r'["\']([a-zA-Z0-9_\-]{2,40}\.' + re.escape(root) + r')["\']', text):
        out.add(m.group(1))
    # 排除IP和本地
    return {d for d in out if not re.match(r'\d+\.\d+\.\d+\.\d+', d) and not d.startswith('localhost')}


# ---------- SourceMap 处理 ----------
def _extract_sourcemap(text, src):
    """提取 SourceMap URL; `data:` 内联映射**就地解析**, 远程 URL 原样返回。

    (远程 map 的下载解析由编排层统一做 —— 此前 docstring 声称"下载解析"与实现不符, 审计更正。)
    """
    m = re.search(r'//#\s*sourceMappingURL\s*=\s*(.+)', text)
    if not m:
        return None
    sm_url = m.group(1).strip()
    if sm_url.startswith('data:'):
        # inline sourcemap (base64)
        try:
            prefix, b64 = sm_url.split(',', 1)
            if 'base64' in prefix:
                raw = base64.b64decode(b64)
                return json.loads(raw.decode('utf-8', 'ignore'))
        except Exception as e:
            from .log import dbg
            dbg(f'内联 sourcemap 解析失败({src}): {e}')
        return None
    return sm_url


def _extract_js_refs(text):
    """提取 JS 内部引用的其他 JS 文件

    真实 SPA 的接口大量分布在懒加载 chunk 里 —— 不做 JS-in-JS 递归会大面积漏提取。
    返回的是**相对/绝对引用原样**, 由调用方以"引用它的那个文件"为基准做 urljoin。
    """
    out = set()
    for pat in _JS_REF_PATTERNS:
        for m in pat.finditer(text):
            ref = (m.group(1) or '').strip()
            if not ref:
                continue
            # 外链与 data URI 不是"要抓的 chunk", 交给第三方过滤逻辑处理
            if ref.startswith(('data:', 'http://', 'https://', '//', 'blob:')):
                continue
            out.add(ref)
            if len(out) >= MAX_JS_REFS_PER_FILE:
                return out
    return out


def _extract_wasm_refs(text):
    """从 JS / HTML 文本提取 .wasm 引用(相对/绝对原样, 由调用方 urljoin)。

    覆盖 `import('x.wasm')` / `fetch('x.wasm')` / `WebAssembly.instantiateStreaming` /
    `<link rel=preload href=x.wasm>` / `new URL('x.wasm', import.meta.url)` 等。
    只取**以 .wasm 结尾的引号串**, 不含跨域 data/blob 前缀。
    """
    out = set()
    if not text:
        return out
    for m in _WASM_REF_RE.finditer(text):
        ref = (m.group(1) or '').strip()
        if not ref or ref.startswith(('data:', 'blob:')):
            continue
        out.add(ref)
        if len(out) >= _MAX_WASM_REFS:
            break
    return out


def _scan_wasm(data, base):
    """从 wasm 二进制字节提取接口路径 / URL。返回 (apis, external_apis)。

    仅做**静态字符串扫描**(可打印 ASCII 串 → URL / 绝对路径形态过滤), 不执行 wasm。
    apis      —— 同源绝对路径(形如 /api/...); 经 _is_api_path 二次过滤。
    external  —— 跨域绝对 URL(完整 http(s)/ws URL)。
    """
    from .js_extract import _is_api_path, _is_plausible_api_path
    apis, external = set(), set()
    if not data:
        return apis, external
    try:
        text = data.decode('latin-1', 'ignore')
    except Exception:
        return apis, external
    target_host = _host_of(base) if base else ''
    for tok in _WASM_PRINTABLE.finditer(text):
        s = tok.group(0)
        # 绝对 URL(可能不在 token 最前, 故在 run 内再找)
        for mu in _WASM_URL_RE.finditer(s):
            raw = mu.group(0).rstrip('.,;')
            _u = urlsplit(raw)
            if not _u.hostname:
                continue
            if target_host and _u.hostname.lower() == target_host.lower():
                p = _u.path + (f'?{_u.query}' if _u.query else '')
                if _is_api_path(p):
                    apis.add(p)
            else:
                external.add(raw)
        # 绝对路径形态(以 / 开头且带接口前缀 hint)
        for mp in _WASM_PATH_RE.finditer(s):
            p = mp.group(0).split('#')[0]
            if _WASM_PATH_HINT.match(p) and _is_plausible_api_path(p):
                apis.add(p)
    return apis, external


def _drain_wasm_ref(ctx, ref, src_url, base, out):
    """解析单个 .wasm 引用 → 只读 GET → 字符串扫描 → 并入 out。

    同源护栏: 仅抓取与 base 同源的 .wasm(跨域 .wasm 不抓, 与只读/合规定位一致)。
    落盘无副作用: 不保存 .wasm 到 JS 清单(它不是 JS)。
    """
    from .http import REQ
    from .js_extract import _same_origin
    if not ref:
        return
    try:
        abs_url = urljoin(src_url, ref)
    except Exception:
        return
    if not abs_url.endswith('.wasm'):
        return
    if not _same_origin(abs_url, base):
        dbg(f'wasm 跨域跳过(只读同源): {abs_url}')
        return
    try:
        r = REQ(ctx, 'GET', abs_url,
                timeout=max(20, ctx.config.get('timeout', 10) * 2))
    except Exception as e:
        dbg(f'wasm 获取异常 {abs_url}: {e}')
        return
    if r is None or r.status_code != 200 or not r.content:
        return
    apis, external = _scan_wasm(r.content, base)
    if not (apis or external):
        return
    for p in apis:
        out['apis'].add(p)
        out.setdefault('wasm_apis', set()).add(p)
        # 端点来源坐标: 标记来自哪份 wasm(§9 来源可解释率) —— 二进制无行号, 行/列留空
        out.setdefault('api_srcline', {})[p] = (abs_url, None, None)
        out.setdefault('api_extractor', {})[p] = 'wasm'
    for e in external:
        out.setdefault('external_apis', set()).add(e)
    ctx.add_finding('INFO', f'wasm 字符串提取 ({len(apis)} 己方 / {len(external)} 外部)',
                    abs_url, 'Blazor/emscripten 类产物: 二进制内硬编码接口路径/URL')
    log(f'wasm 提取: {abs_url} → 己方 {len(apis)} / 外部 {len(external)}')


def _extract_webpack_chunks(text):
    """从 webpack runtime 还原 chunk 文件名候选。返回 (names, mode)。

    mode ∈ {'jsonp', 'import', None}。names 为**相对 publicPath 的名称**(由调用方 urljoin)。
    支持四种命名形态, 任一命中即产出, 避免对普通 JS 过度生成:
      A/B/C —— `.u`(chunk 命名函数): 单常量 / 拼接模板 / 无 hash 映射
      D     —— 内联映射表(压缩产物无 `.u`, chunk 表直接内联在 `<script src>` 构造处)
    """
    names, mode = set(), None
    if not text:
        return names, mode
    # 加载模式: import 模式有 n.l 里调用 import(); JSONP 模式有 webpackChunk*/jsonpScriptSrc/installedChunks
    #   (压缩后 `installedChunks` 会被改名, 故一并识别 `webpackJsonp` / `.oe=` 等 runtime 指纹)
    if re.search(r'\.l\s*=[^;]{0,160}?\bimport\s*\(', text, re.S):
        mode = 'import'
    if re.search(r'webpackChunk|jsonpScriptSrc|installedChunks|webpackJsonp|\.oe\s*=', text):
        mode = mode or 'jsonp'
    # publicPath: 为空则 chunk 名相对"当前脚本目录"(由调用方 urljoin 还原) —— 与 webpack auto 语义一致
    pm = re.search(r'\.p\s*=\s*["\']([^"\']*)["\']', text)
    pub = pm.group(1) if pm else ''
    # ---- 形态 D: 内联映射表 ----
    #   对压缩产物, 本段是 chunk 的**唯一**还原入口(旧实现要求 `.u` 存在, 会整站枚举不出任何 chunk)
    for _m in _RE_WP_INLINE_MAP.finditer(text):
        _idmap = _RE_WP_IDMAP.findall(_m.group('map'))
        if not _idmap:
            continue
        _pre = _m.group('pre') or ''
        _mid = _m.group('mid') or ''
        _suf = _m.group('suf') or '.js'
        _has_id = bool(_m.group('id'))
        for _cid, _h in _idmap:
            names.add(pub + _pre + (_cid if _has_id else '') + _mid + _h + _suf)
    # `.u` 定义: `.u = <var> => <expr>` / `.u = (var) => <expr>` / `.u = function(v){return <expr>}`
    #   或 `.u = <expr>`; 截到下一个 `,x.y` 或 `;`
    #   注意: **非 ESM(classic script)产物用 `function(e){return ...}`** —— 旧正则只剥 `e=>`,
    #   导致 `function(e){return "static/js/"+e+"."+{...}[e]+".js"}` 的**路径前缀被吞掉**
    #   (`static/js/1.a.js` 错成 `1.a.js` → 404 → 整类 chunk 漏抓)。此处一并剥离函数头。
    um = None
    if '.u' in text:
        um = re.search(
            r'\.u\s*=\s*(?:'
            r'\(?\s*(?P<ap>[A-Za-z_$][\w$]*)\s*\)?\s*=>'                 # 箭头: e=> / (e)=>
            r'|function\s*\(\s*(?P<fp>[A-Za-z_$][\w$]*)[^)]*\)\s*\{\s*return'  # 非 ESM: function(e){return
            r')?\s*(?P<expr>.{1,400}?)(?=,\s*[A-Za-z_$][\w$]*\.\w|\Z)', text, re.S)
    if not um:
        names = {n for n in names if n.endswith(('.js', '.mjs')) and '{' not in n and '$' not in n}
        return names, mode
    # 去掉非 ESM 函数体的尾随 `}` / `;`(否则单常量形态与后缀匹配都会失配)
    expr = um.group('expr').strip().rstrip('};').rstrip()
    # chunkId 是否出现在文件名模板里: `…+e+"."+{…}[e]+…`(含) vs `…+{…}[e]+…`(不含, 如 hash-only
    #   chunkFilename `[contenthash].js`)。不含时**不得**把 cid 拼进名字 —— 否则 `static/js/a1b2.js`
    #   会被错拼成 `static/js/1a1b2.js` → 404 → 该 chunk 漏抓。判据: 参数是否作为**独立拼接操作数**(`+e+`)出现。
    #   参数作为独立操作数出现: `+e+`(字符串拼接) 或 `.concat(e,`(TS/Babel 把模板字面量编译成 .concat)。
    _ap = um.group('ap') or um.group('fp')
    _incl_cid = (True if not _ap
                 else bool(re.search(r'\+\s*' + re.escape(_ap) + r'\s*\+', expr)
                           or re.search(r'\.concat\s*\(\s*' + re.escape(_ap) + r'\s*[,)]', expr)))
    # 形态 A: 单常量  `.u = t => "admin.chunk.js"`
    cst = re.fullmatch(r'["\']([^"\']+\.(?:m)?js)["\']', expr)
    if cst:
        names.add(pub + cst.group(1))
        return names, mode
    # 形态 B/C: 拼接模板。取 前缀 / chunkId→hash 映射 / 后缀
    pre_m = re.match(r'["\']([^"\']*)["\']', expr)
    pre = pre_m.group(1) if pre_m else ''
    suf_m = re.search(r'["\']([^"\']*\.(?:m)?js)["\']\s*\)?\s*$', expr)
    suf = suf_m.group(1) if suf_m else '.js'
    mid = '.' if re.search(r'["\']\.["\']', expr) else ''
    idmap = {}
    for mm in re.finditer(r'\{([^{}]{2,1200})\}', expr):
        for k, v in _RE_WP_IDMAP.findall(mm.group(1)):
            idmap[k] = v
    if idmap:
        for cid, h in idmap.items():
            names.add(pub + pre + (cid if _incl_cid else '') + mid + h + suf)
    else:
        # 无 hash 映射(如 `"static/js/"+t+".js"`): chunkId 取自 installedChunks 键 / `.e(id)` 调用
        #   id 可为数字或具名(`{admin:0}` / `.e("admin")`)。
        ids = set(re.findall(r'["\']?([\w$]+)["\']?\s*:\s*(?:void 0|0|\[)', text))
        ids |= set(re.findall(r'\.e\s*\(\s*["\']?([\w$]+)["\']?\s*\)', text))
        for cid in sorted(ids)[:200]:
            names.add(pub + pre + cid + suf)
    # 只保留像 chunk 的名称(含 .js 且不含模板残留)
    names = {n for n in names if n.endswith(('.js', '.mjs')) and '{' not in n and '$' not in n}
    return names, mode


def _extract_bundler_chunks(text):
    """统一的"构建产物 chunk"枚举 —— webpack(JSONP/import) + Vite + Worker。

    返回 (chunk_names, mode)。chunk_names 只含"可同源抓取"的名称(相对/绝对路径);
    **Module Federation 的远程入口**不在此列(可能跨域), 由 `_extract_federation_remotes` 单独识别。
    """
    names, mode = _extract_webpack_chunks(text)
    if not text:
        return names, mode

    # ---- Vite / Rollup: __vite__mapDeps 的依赖数组字面量 ----
    #   __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/index.abc.js","assets/vendor.def.js"])))
    vm = re.search(r'\.f\s*\|\|\s*\(\s*\w+\.f\s*=\s*\[([^\]]{0,6000})\]', text)
    if not vm:
        vm = re.search(r'\.f\s*=\s*\[([^\]]{0,6000})\]', text)
    if vm:
        for p in re.findall(r'["\']([^"\']+\.(?:m)?js)["\']', vm.group(1)):
            names.add(p)
        mode = mode or 'vite'
    if '__vite__mapDeps' in text or 'import.meta.glob' in text:
        mode = mode or 'vite'
    # Vite 的 assets/*.js 字面量(无 mapDeps 时的兜底)
    if '__vite__mapDeps' in text or 'vite' in text.lower():
        for p in re.findall(r'["\'](assets/[A-Za-z0-9_.\-]+\.(?:m)?js)["\']', text):
            names.add(p)

    # ---- Worker: importScripts('...') ----
    for m in re.finditer(r'importScripts\s*\(\s*["\']([^"\']+\.(?:m)?js)["\']', text):
        names.add(m.group(1))
    if 'importScripts' in text:
        mode = (mode + '+worker') if mode else 'worker'

    names = {n for n in names if n.endswith(('.js', '.mjs')) and '{' not in n and '$' not in n}
    return names, mode


def _extract_federation_remotes(text):
    """webpack Module Federation 的远程入口(可能跨域, 只登记不自动抓)。

    形态: `remotes:{app1:"app1@https://cdn.example.com/app1/remoteEntry.js"}` 或裸 remoteEntry.js。
    """
    out = set()
    if not text:
        return out
    for m in re.finditer(r'["\']([\w.\-]+)@(https?://[^"\']+?\.(?:m)?js)["\']', text):
        out.add(m.group(2))
    for m in re.finditer(r'["\']([^"\']*remoteEntry\.(?:m)?js)["\']', text):
        v = m.group(1)
        if '@' in v:          # `name@url` 形态已由上面的正则按 URL 收录, 避免重复
            continue
        out.add(v)
    return out


def _extract_inline_scripts(html):
    """提取首页内联 <script> 块正文（不含带 src 的外部引用，不含 JSON/模版数据块）

    """
    if not html:
        return []
    blocks = []
    # 匹配 <script ...>正文</script>; re.S 跨行, re.I 忽略大小写
    for m in re.finditer(r'<script\b([^>]*)>(.*?)</script>', html, re.S | re.I):
        attrs = m.group(1)
        if re.search(r'\bsrc\s*=', attrs, re.I):
            continue  # 外部 JS, 已由 RE_SRC 收集, 避免重复分析
        if re.search(r'\btype\s*=\s*["\']?(?:application/(?:ld\+)?json|importmap|text/template)',
                     attrs, re.I):
            continue  # JSON/importmap/模板 数据块, 非可执行代码
        body = m.group(2)
        if body and body.strip():
            blocks.append(body)
    return blocks


def _html_attr_value(m):
    """取属性值(第 2~4 组: 双引号/单引号/裸值) —— 委托 `_gv`(单一实现, 审计 S10)。"""
    return _gv(m, skip=1)


def _extract_html_apis(html, base=None):
    """从首页 **HTML 正文** 提取接口路径(属性 action/href/formaction/data-* + /api/ 路径)。

    背景: 服务端渲染栈(Django/Rails/Laravel/Spring MVC/ASP.NET/PHP)的接口大量出现在
    HTML 的 `action=` / `href=` / `data-*` 属性里, 而非 JS。旧实现只把 JS(外部+内联)喂给
    `RE_API`, 首页 HTML 正文从不扫描 —— 实测 10 个后端栈样例里"仅写在 HTML"的端点 **0/2 全漏**。
    属性值引号可选 —— 压缩 HTML(`href=/api/x`)同样能提取。
    """
    from .js_extract import _is_api_path, _is_web_endpoint, _same_origin
    apis = set()
    if not html:
        return apis
    for m in RE_API.finditer(html):
        # HTML 属性里的 URL 常以实体形式出现(`&amp;`), 不反转义会导致 query 串被
        # 原样存成 `a=1&amp;b=2`(探活时发出错误请求)。属性/正文均来自 HTML, 反转义正确。
        g = _html.unescape(m.group(1))
        if _is_api_path(g):
            apis.add(g)
    for m in _HTML_ATTR_OPT.finditer(html):
        v = _html_attr_value(m)
        if not v:
            continue
        v = _html.unescape(v)
        # **同源护栏(与 JS 通道 `_extract_api_calls` 的跨域跳过口径一致)**: 绝对 URL 若非同源
        #   (如社交分享 `https://twitter.com/intent/tweet?url=…`、CDN `https://cdn.x/api/v1/y`),
        #   其 **path 不得当"同源端点"** —— 否则会产出 `/intent/tweet?url=…` 这类**假同源端点**
        #   并丢失真实 host(且会被无谓探活)。跨域链接既非同源端点也非 API 调用, 直接跳过。
        if v.startswith(('http://', 'https://')) and not _same_origin(v, base):
            continue
        # 相对路径（如 `subscribe.jsp`、`default.jsp?content=x`）→ 用页面 base 解析为绝对路径
        cand = v
        if base and not v.startswith(('/', 'http://', 'https://', '#',
                                      'data:', 'javascript:', 'mailto:', 'tel:')):
            try:
                cand = urljoin(base, v)
            except Exception:
                cand = v
        # 先归一化（绝对 URL → path；模板占位统一化），再用更宽判定
        p = normalize_extracted_path(cand)
        if p and _is_web_endpoint(p):
            apis.add(p)
    # Inertia.js: 根元素 `data-page='{component,url,props}'` —— 当前页 `url` + `props` 里的接口路径。
    #   props 常含**服务端预取的数据**(内嵌 API 路径); 只取经 `_is_api_path` 形态判定者(保守降噪),
    #   props 走与 runtime/orchestrator 同源的 `_extract_paths_from_obj`(单一真源)。
    from .util import _extract_paths_from_obj
    for m in re.finditer(r'''\bdata-page\s*=\s*["']([^"']+)["']''', html):
        try:
            d = json.loads(_html.unescape(m.group(1)))
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        _url = d.get('url')
        if isinstance(_url, str):
            _p = normalize_extracted_path(urljoin(base, _url) if base else _url)
            if _p and _is_api_path(_p):
                apis.add(_p)
        _pp = set()
        _extract_paths_from_obj(d.get('props'), _pp)
        for _s in _pp:
            _p = normalize_extracted_path(_s)
            if _p:
                apis.add(_p)
    return apis


def _gv(m, skip=0):
    """取属性匹配里第一个非空捕获组(可跳过前 `skip` 个组, 如属性名组)。"""
    if m is None:
        return None
    for g in m.groups()[skip:]:
        if g is not None:
            return g
    return None


def _form_endpoint(action, base=None):
    """把 form 的 action 属性归一成可链接参数的端点路径。

    相对 action(无前导 `/`, 如 `subscribe.jsp`)用 base 解析为绝对路径 —— 与
    `_extract_html_apis` 的 `_HTML_ATTR_OPT` 分支口径一致(后者已对相对 href/action
    走 urljoin), 否则同一表单字段会与"已发现的相对端点"失联(旧实现相对 action 返回 None)。
    空/无法解析返回 None。
    """
    if not action:
        return None
    if action.startswith('/'):
        return normalize_extracted_path(action)
    if action.startswith('http://') or action.startswith('https://'):
        # **同源护栏(与 `_extract_html_apis` 同口径)**: 跨域 form action(如第三方支付/SSO)
        #   的 path 不得当**同源端点** —— 否则会把它与同源端点/表单字段错误关联。
        from .js_extract import _same_origin
        if not _same_origin(action, base):
            return None
        from urllib.parse import urlparse
        p = urlparse(action).path
        return normalize_extracted_path(p) if p else None
    if base:
        try:
            return normalize_extracted_path(urljoin(base, action))
        except Exception:
            return None
    return None


def _extract_html_forms_comments(html, ctx, out, base):
    """提取表单字段名(入参表) + 隐藏域敏感值 + HTML 注释敏感值。

    返回统计 (num_forms, num_fields, num_hidden, num_comments), 供 INFO 发现项佐证覆盖。
    """
    from .secret import _scan_sensitive_block
    if not html:
        return 0, 0, 0, 0
    num_forms = len(_FORM_OPEN_RE.findall(html))
    num_fields = 0
    num_hidden = 0
    # 1) 表单块内字段: ① 有 action → 直接链接到 action 端点; ② 无 action → 记下 (表单 id → 字段名),
    #    留给 JS 数据流通道(_extract_form_body_links/_resolve_form_body_links)按**代码依据**关联
    #    —— 这类表单的提交被 JS 接管(`new FormData(form)` → `body` → `fetch(端点)`)。
    for block in _FORM_BLOCK_RE.findall(html):
        ep = _form_endpoint(_gv(_FORM_ACTION_RE.search(block)), base)
        _fid = _gv(_FORM_ID_RE.search(block))
        _fnames = set()
        for fm in _FORM_FIELD_RE.finditer(block):
            nm = _NAME_ATTR_RE.search(fm.group(0))
            if not nm:
                continue
            name = _gv(nm)
            if not name:
                continue
            out['params'].add(name)
            num_fields += 1
            _fnames.add(name)
            if ep:
                ctx.link_param(ep, name)
            tm = _TYPE_ATTR_RE.search(fm.group(0))
            ftype = (_gv(tm) or 'text').lower() if tm else 'text'
            if ftype == 'hidden':
                num_hidden += 1
                vm = _VALUE_ATTR_RE.search(fm.group(0))
                val = _gv(vm) if vm else ''
                if val:
                    _scan_sensitive_block(ctx, val, base, allow_source_only=False)
        if _fid and _fnames and not ep:
            ctx.form_fields.setdefault(_fid, set()).update(_fnames)
    # 2) 表单块外的字段(落在 <form> 之外, 仍计入参表, 不强行链接)
    #    表单块用非贪婪匹配, 嵌套/未闭合场景可能漏块外字段 ——
    #    全局再扫一遍, 用 (name, 出现位置) 去重避免与块内重复计数。
    _seen_field = set()
    for fm in _FORM_FIELD_RE.finditer(html):
        key = fm.group(0)
        if key in _seen_field:
            continue
        _seen_field.add(key)
        nm = _NAME_ATTR_RE.search(fm.group(0))
        if not nm:
            continue
        name = _gv(nm)
        if not name:
            continue
        # 已在块内计过数的(name 已入参表)不重复增计数, 但仍确保入表
        if name in out['params']:
            continue
        out['params'].add(name)
        num_fields += 1
        tm = _TYPE_ATTR_RE.search(fm.group(0))
        ftype = (_gv(tm) or 'text').lower() if tm else 'text'
        if ftype == 'hidden':
            num_hidden += 1
            vm = _VALUE_ATTR_RE.search(fm.group(0))
            val = _gv(vm) if vm else ''
            if val:
                _scan_sensitive_block(ctx, val, base, allow_source_only=False)
    # 3) HTML 注释: 扫描敏感值(端点已由 _extract_html_apis 的 RE_API 覆盖, 不重复)
    comments = _HTML_COMMENT_RE.findall(html)
    for c in comments:
        _scan_sensitive_block(ctx, c, base, allow_source_only=False)
    # 4) htmx 写方法端点: `hx-post/put/patch/delete="<url>"` → write_apis(零发包登记)。
    #   路径已由 `_extract_html_apis`(经 `_HTML_ATTR_OPT` 的 `hx-*`)登记为端点; 此处补**写方法**
    #   (hx-get 属只读, 不登记写)。同源护栏与 `_extract_html_apis` 一致(跨域不登记)。
    from .js_extract import _same_origin
    for _hm in re.finditer(r'\bhx-(post|put|patch|delete)\s*=\s*["\']([^"\']+)["\']', html, re.I):
        _method, _raw = _hm.group(1).upper(), _html.unescape(_hm.group(2))
        _u = urljoin(base, _raw) if base else _raw
        if base and not _same_origin(_u, base):
            continue
        _np = normalize_extracted_path(_u)
        if _np:
            out.setdefault('write_apis', {})[_np] = _method
    return num_forms, num_fields, num_hidden, len(comments)


def _extract_form_body_links(text):
    """JS 数据流: 页面表单字段经 `FormData` → 请求体 → 发送到的端点(**只认变量赋值链**)。

    识别模式(全部有代码依据, 不做任何猜测):
      `const v = document.getElementById("X")` → `new FormData(v)` →
      `Object.fromEntries(fd.entries())` → `fetch(url, { body: JSON.stringify(payload) })`
      ⟹  表单 `X` 的字段 → `url`。

    返回 {form_id: {endpoint, ...}}; 一个 form 命中多个端点时由调用方按"歧义即不关联"处理。
    """
    if not text or 'FormData' not in text or 'fromEntries' not in text:
        return {}
    var_form = {}
    for m in _JS_FORM_VAR_RE.finditer(text):
        _fid = m.group(2) or m.group(3)
        if _fid:
            var_form[m.group(1)] = _fid
    fd_var = {}
    for m in _JS_FORMDATA_VAR_RE.finditer(text):
        fd_var[m.group(1)] = m.group(2)
    pay_var = {}
    for m in _JS_FROMENTRIES_VAR_RE.finditer(text):
        pay_var[m.group(1)] = m.group(2)
    body_ep = {}
    for m in _JS_BODY_FETCH_RE.finditer(text):
        _u = m.group(1) or m.group(2) or m.group(3)
        if _u:
            body_ep.setdefault(m.group(4), set()).add(_u)
    for m in _JS_AXIOS_BODY_RE.finditer(text):
        _u = m.group(1) or m.group(2)
        if _u:
            body_ep.setdefault(m.group(3), set()).add(_u)
    links = {}
    for _pv, _fdv in pay_var.items():
        _fv = fd_var.get(_fdv)
        _fid = var_form.get(_fv) if _fv else None
        if not _fid:
            continue
        for _ep in body_ep.get(_pv, ()):
            links.setdefault(_fid, set()).add(_ep)
    return links


def _resolve_form_body_links(ctx, base):
    """把"表单字段 → 端点"的数据流关联落库到 `ctx.pmap`(**歧义即不关联**, 保持零推断)。

    仅当某表单 id 经数据流链**唯一**对应到一个端点时才关联; 对应 0 个或 ≥2 个端点一律放弃
    (宁可留"未归属参数", 也不错挂到端点)。返回关联的参数条目数。
    """
    ff = getattr(ctx, 'form_fields', None) or {}
    fb = getattr(ctx, 'form_body_links', None) or {}
    if not ff or not fb:
        return 0
    linked = 0
    for _fid, _eps in fb.items():
        _names = ff.get(_fid)
        if not _names:
            continue
        _norm = set()
        for _u in _eps:
            _p = _form_endpoint(_u, base)
            if _p:
                _norm.add(_p)
        if len(_norm) != 1:      # 0 个(归一化失败) 或 ≥2 个(歧义) → 放弃关联
            continue
        _ep = next(iter(_norm))
        for _nm in sorted(_names):
            ctx.link_param(_ep, _nm)
            linked += 1
    return linked


def _fetch_build_manifests(ctx, base, out):
    """下载并解析构建清单, 把枚举到的 JS 并入 out['js_refs']。返回枚举到的 JS 数。

    仅对**前端指纹命中**的目标执行(遵守"指纹是门禁"原则); 每个清单 1 发 GET。
    ① 支持 **JS 形态清单**(Next.js `_buildManifest.js` / workbox `precache-manifest.js`);
                 ② Next.js 的清单路径含 buildId(来自 `__NEXT_DATA__`), 需动态拼;
                 ③ 产物后缀兼容 `.mjs`。
    """
    from .http import REQ
    n = 0
    paths = list(_BUILD_MANIFEST_PATHS)
    _bid = out.get('next_build_id')
    if _bid:
        paths += [f'/_next/static/{_bid}/_buildManifest.js',
                  f'/_next/static/{_bid}/_ssgManifest.js']
    # 以下三条 JS 形态清单路径此前**内联第二份**(审计 S9) —— 已并入 const 清单真源。

    for p in paths:
        url = urljoin(base, p)
        try:
            r = REQ(ctx, 'GET', url)
        except Exception:
            continue
        if r is None or getattr(r, 'status_code', 0) != 200:
            continue
        files = set()

        def _walk(o, _files=files):
            # `files` 通过默认参数**绑定到本次迭代的值** —— 闭包直接引用循环变量的话,
            #   一旦将来改成"先收集函数、循环后再调用", 所有调用都会落到最后一个 files 上。
            if isinstance(o, str):
                if o.endswith(('.js', '.mjs')):
                    _files.add(o)
            elif isinstance(o, dict):
                for v in o.values():
                    _walk(v)
            elif isinstance(o, list):
                for v in o:
                    _walk(v)

        data = None
        try:
            data = r.json()
        except Exception:
            try:
                import json as _json
                data = _json.loads(r.text)
            except Exception:
                pass
        if isinstance(data, (dict, list)):
            _walk(data)
        else:
            # JS 形态清单: 仅在正文含清单标记时按正则取 .js/.mjs
            txt = getattr(r, 'text', '') or ''
            if any(mk in txt for mk in _JS_MANIFEST_MARKERS):
                for mm in re.findall(r'["\']([^"\']+\.(?:m)?js)["\']', txt):
                    files.add(mm)

        if files:
            out.setdefault('js_refs', set()).update(files)
            n += len(files)
            ctx.add_finding('INFO', '构建清单可读', url, f'{p} 枚举出 {len(files)} 个 JS 产物')
    return n
