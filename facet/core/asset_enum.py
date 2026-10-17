# -*- coding: utf-8 -*-
"""被动打点 / sitemap 遍历 / 同源多页爬取 —— 从 `core/engine.py` 拆出（便于维护）。

注: 子域 / 历史资产枚举(CT / Wayback / DNS 爆破)与端口探测已**整体移除** —— 本模块
  现只保留**被动打点**(robots / sitemap / security.txt / favicon)与同源多页爬取(纯 HTTP)。
"""
import hashlib
import re
from urllib.parse import urljoin, urlsplit

from facet.core.log import log

from .const import _NON_LATIN_RE
from .dicts import WELLKNOWN_SECURITY_PATHS, static_asset_exts
from .util import _host_of


def _fetch_sitemap(ctx, url, discovered, _depth=0, _seen=None, _state=None):
    """sitemap 抓取入口 —— 负责**归属**截断登记, 递归逻辑交给 _sitemap_walk

    拆成两层的原因: 递归会把 `_state` 一路传下去, 若每一层都登记截断
    就会重复计数; 而若只在调用方(passive_recon)登记, 那么**直接调用本函数**的
    场景(如单元测试、其它入口)就完全不会登记 —— 实测这正是一条回归:
    截断被静默丢弃, 报告里看不到"丢了多少条"。

    因此: **谁创建了状态, 谁负责登记**。顶层调用创建状态 → 顶层登记一次;
    递归层复用上层状态 → 不重复登记。
    """
    owns = _state is None
    if _seen is None:
        _seen = set()
    if _state is None:
        limit = ctx.config.get('max_sitemap', 500)
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 500
        _state = {'left': limit if limit > 0 else None, 'dropped': 0}
    _sitemap_walk(ctx, url, discovered, _depth, _seen, _state)
    if owns and _state.get('dropped'):
        ctx.note_truncated('sitemap', _state['dropped'])


def _sitemap_walk(ctx, url, discovered, _depth, _seen, _state):
    """sitemap.xml / sitemapindex 递归解析

    增加条数上限。此前对 <loc> **无任何上限** —— 一个 50k 条的
    sitemap 会直接变成 50k 个探活目标, 实测 800 条即产生 835 次服务端请求
    (11.3×), 按 1k 外推约 8 分钟、50k 约 7.2 小时。这是本项目最大的流量放大源。

    补上 <sitemapindex> **递归**。

    注意: 上限是**跨整棵树全局共享**的(`_state`), 不是每个子 sitemap 各一份 ——
      否则 500 个子 sitemap × 每个 500 条 = 25 万条路径, 等于没有上限。
    """
    from .http import REQ
    if url in _seen:
        return
    _seen.add(url)
    r = REQ(ctx, 'GET', url)
    if r is None or r.status_code != 200 or not r.text:
        return
    low = r.text[:2000].lower()
    is_index = '<sitemapindex' in low
    if not is_index and '<urlset' not in low:
        return
    locs = re.findall(r'<loc>\s*([^<\s]+)\s*</loc>', r.text, re.I)
    if not locs:
        return

    # ---- sitemapindex: 递归抓子 sitemap, 不把子 sitemap URL 当页面路径 ----
    if is_index:
        max_depth = 3
        if _depth >= max_depth:
            log(f'[!] sitemapindex 已达递归深度上限 {max_depth}, 停止下钻: {url}')
            ctx.note_truncated('sitemap_index_depth', len(locs))
            return
        child_n = 0
        for loc in locs:
            if ctx.budget_exhausted() or ctx.check_circuit(5):
                log('[!] 预算/熔断触发, sitemapindex 递归提前结束')
                break
            # 全局额度用完就不再下钻(子 sitemap 本身也要发一次请求)
            if _state['left'] is not None and _state['left'] <= 0:
                _state['dropped'] += len(locs) - child_n
                break
            child = loc.strip()
            if not child:
                continue
            # **同源校验**: 被劫持/恶意目标的 sitemapindex 可声明任意第三方主机的
            #   子 sitemap, 诱导分析器向其发包。此前只靠 REQ 内部 scope 护栏兜底
            #   (把红线押在单点上) —— 现在源头就拒绝跨域子站(审计 F)。
            if _host_of(child) != _host_of(url):
                _state['dropped'] += 1
                continue
            child_n += 1
            _sitemap_walk(ctx, child, discovered, _depth + 1, _seen, _state)
        if child_n:
            log(f'[*] sitemapindex 递归: {url} → {child_n} 个子 sitemap')
        return

    # ---- 普通 urlset: 收路径 ----
    dropped = 0
    if _state['left'] is not None and len(locs) > _state['left']:
        dropped = len(locs) - _state['left']
        locs = locs[:_state['left']]
        _state['dropped'] += dropped
    if _state['left'] is not None:
        _state['left'] -= len(locs)

    paths = set()
    for loc in locs:
        try:
            sp = urlsplit(loc)
        except Exception:
            continue
        if sp.path and sp.path != '/':
            paths.add(sp.path)
    if paths:
        discovered |= paths
        ctx.add_finding('INFO', 'sitemap.xml 披露路径', url, f'{len(paths)} 条')
    if dropped:
        log(f'[!] sitemap 截断: 丢弃 {dropped} 条 <loc> (全局上限 max_sitemap)')


def passive_recon(ctx, base, out, home_resp=None):
    """步骤0: 被动打点 —— robots / sitemap / security.txt / favicon + 安全响应头审计"""
    from .http import REQ
    from .probe import _is_catchall
    from .tls import _audit_security_headers
    if not ctx.config.get('passive_recon', True):
        return set()
    discovered = set()

    # sitemap 的全局额度与去重跨**所有**入口共享 —— robots.txt 里的 Sitemap: 行
    # 与默认 /sitemap.xml 可能指向同一批子 sitemap, 各建一份状态会重复抓取并
    # 让上限失效(每个入口都重新获得一份额度)。
    #   注意: 状态必须**在这里**创建再传下去。若交给 _fetch_sitemap 内部惰性创建,
    #   调用方手里的变量会一直是 None, 第二个入口就又拿到一份全新额度。
    sm_seen = set()
    _sm_limit = ctx.config.get('max_sitemap', 500)
    try:
        _sm_limit = int(_sm_limit)
    except (TypeError, ValueError):
        _sm_limit = 500
    sm_state = {'left': _sm_limit if _sm_limit > 0 else None, 'dropped': 0}

    # 1. robots.txt —— 目标自己公开的路径清单
    robots_url = urljoin(base, '/robots.txt')
    r = REQ(ctx, 'GET', robots_url)
    if r is not None and r.status_code == 200 and r.text:
        paths = set()
        for m in re.finditer(r'(?im)^\s*(?:Disallow|Allow)\s*:\s*(\S+)', r.text):
            p = m.group(1).strip()
            if not p or p in ('/', '*'):
                continue
            p = p.rstrip('*').rstrip('$')          # /admin/* → /admin
            if not p.startswith('/'):
                p = '/' + p
            if len(p) > 1:
                paths.add(p)
        for m in re.finditer(r'(?im)^\s*Sitemap\s*:\s*(\S+)', r.text):
            _sm_url = m.group(1).strip()
            # 同源校验: 恶意 robots.txt 可指向任意第三方 sitemap(审计 F, 与 sitemapindex 同口径)
            if _host_of(_sm_url) != _host_of(robots_url):
                continue
            _fetch_sitemap(ctx, _sm_url, discovered,
                           _seen=sm_seen, _state=sm_state)
        if paths:
            discovered |= paths
            ctx.add_finding('INFO', 'robots.txt 披露路径', robots_url,
                            f'{len(paths)} 条: ' + ','.join(sorted(paths)[:8]))

    # 2. sitemap.xml (默认位置)
    _fetch_sitemap(ctx, urljoin(base, '/sitemap.xml'), discovered,
                   _seen=sm_seen, _state=sm_state)

    # 3. security.txt (RFC 9116) —— 标准位置优先
    for u in WELLKNOWN_SECURITY_PATHS:              # 数据层(dicts.WELLKNOWN_SECURITY_PATHS)
        rr = REQ(ctx, 'GET', urljoin(base, u))
        if rr is not None and rr.status_code == 200 and rr.text and 'contact' in rr.text.lower():
            # catch-all 站点会为任意路径返回 SPA 首页(其中可能含 contact 字样) → 伪命中。
            #   与"不存在的随机路径"响应一致则不是真实 security.txt, 跳过(避免误报"存在")。
            hit, _why = _is_catchall(ctx, rr)
            if hit:
                continue
            ctx.add_finding('INFO', 'security.txt 存在', urljoin(base, u),
                            rr.text.strip().replace('\n', ' ')[:100])
            break

    # 4. favicon 哈希 —— 可用于反查同源资产 / 识别已知产品
    fav_url = urljoin(base, '/favicon.ico')
    fav = REQ(ctx, 'GET', fav_url)
    if fav is not None and fav.status_code == 200 and fav.content:
        ctx.add_finding('INFO', 'favicon 指纹', fav_url,
                        f'md5={hashlib.md5(fav.content).hexdigest()} '
                        f'size={len(fav.content)}B (可反查同源资产)')

    # 5. 安全响应头审计(零额外请求)
    if home_resp is not None:
        _audit_security_headers(ctx, base, home_resp)

    if discovered:
        log(f'[*] 被动打点发现 {len(discovered)} 条路径 '
            f'(robots/sitemap), 已并入探活集合')
    # sitemap 截断总量统一登记(跨所有入口/子 sitemap 汇总)
    if sm_state.get('dropped'):
        ctx.note_truncated('sitemap', sm_state['dropped'])
    return discovered


def extract_page_links(html, page_url):
    """从 HTML 提取**同源**候选链接（页面 / 接口）：<a|area href> + <form action>

    返回绝对 URL 集合（去 fragment、去重）。剔除：
      · 非同源 / 非 http(s)（跨域链接不跟，与合规定位一致）；
      · 伪协议（# / javascript: / mailto: / tel: / data: / blob:）；
      · 静态资源后缀（.js/.css/.png... —— 这些不是"页面"，由 JS 递归通道负责）。
    """
    out = set()
    if not html:
        return out
    b = urlsplit(page_url)
    raw = []
    for pat in (r'''<(?:a|area)\b[^>]*?\bhref\s*=\s*["']([^"']+)["']''',
                r'''<form\b[^>]*?\baction\s*=\s*["']([^"']+)["']'''):
        raw += re.findall(pat, html, re.IGNORECASE)
    for u in raw:
        u = (u or '').strip()
        if not u or u.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:', 'blob:')):
            continue
        au = urljoin(page_url, u)
        sp = urlsplit(au)
        if sp.scheme not in ('http', 'https') or sp.netloc != b.netloc:
            continue
        p = sp.path or '/'
        if p.lower().endswith(static_asset_exts()):
            continue
        out.add(au.split('#', 1)[0])
    return out


def _looks_non_english(html):
    """首页是否像"非英文站点": <html lang> 非 en, 或正文含 CJK/西里尔/韩文等非拉丁字符。"""
    if not html:
        return False
    m = re.search(r'<html\b[^>]*\blang\s*=\s*["\']?([A-Za-z][A-Za-z0-9-]*)', html)
    if m and not m.group(1).lower().startswith('en'):
        return True
    return bool(_NON_LATIN_RE.search(html))


def crawl_site(ctx, base, max_depth=1, max_pages=30):
    """同源多页 BFS（可选，默认关）—— 解决"接口藏在二级页面/表单里"的漏抓

    从 base 起逐层跟随同源 <a>/<form action> 链接，最多 max_depth 层、max_pages 页。
    每页经 REQ 抓取（**受全局限速与熔断约束**，不绕过配额）。

    Returns: {'pages': [(url, html), ...], 'paths': set(发现的同源路径)}
    注意：非 HTML 响应（如直接返回 JSON 的接口）只记录其路径、不递归。
    """
    from .http import REQ
    from .js_extract import _is_api_path
    pages, paths = [], set()
    seen, frontier = set(), [(base, 0)]
    while frontier and len(pages) < max_pages:
        url, d = frontier.pop(0)
        key = url.split('#', 1)[0]
        if key in seen:
            continue
        seen.add(key)
        r = REQ(ctx, 'GET', url)
        if r is None or getattr(r, 'status_code', 0) >= 400:
            continue
        html = getattr(r, 'text', '') or ''
        ctype = ''
        try:
            ctype = (r.headers.get('Content-Type') or '')
        except Exception:
            pass
        if 'html' not in ctype.lower() and not html.lstrip().startswith('<'):
            paths.add(urlsplit(url).path or '/')
            continue
        pages.append((url, html))
        paths.add(urlsplit(url).path or '/')
        # **发现的同源链接(含 form action)本身也是候选端点** —— 不能只在
        #   "GET 抓取成功"时才记录。否则"仅响应 POST 的表单 action"(GET 404)会被漏掉,
        #   而"接口藏在表单里"正是要解决的核心场景。链接在**任意深度**都记录, 仅在
        #   未达深度上限时才继续跟进。
        _links = extract_page_links(html, url)
        for lu in _links:
            _lp = urlsplit(lu).path or '/'
            if _lp:
                paths.add(_lp)
            # **接口形态的链接不进 frontier** —— 它们已作为路径登记(paths.add), 且非页面、
            #   抓了也不会递归(非 HTML 直接 continue) → 抓取纯属浪费流量。
            #   实测: 一个含 50 条 `/api/itemN` 链接的页面, max_pages=2 时旧实现发 **51** 次 REQ
            #   (`max_pages` 只约束 HTML 页数, 不约束请求数); 跳过接口链接后降为 1 次。
            if (d < max_depth and not _is_api_path(_lp)
                    and lu.split('#', 1)[0] not in seen):
                frontier.append((lu, d + 1))
    return {'pages': pages, 'paths': paths}
