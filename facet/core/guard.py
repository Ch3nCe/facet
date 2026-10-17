# -*- coding: utf-8 -*-
"""反脆弱判定 / 软404 / 页面分类 / 响应指纹 —— 从 `core/engine.py` 拆出（便于维护）。"""
import hashlib
import re
from urllib.parse import urlsplit

from .const import (
    _API_REGIME_SEGMENTS,
    _SPA_FP_HINTS,
    _UNAUTH_MARKER_MAXLEN,
    _UNAUTH_MARKERS,
    SIMHASH_MIN_LEN,
    SIMHASH_NEAR_HAMMING,
)


def _looks_json(s):
    """极简 JSON 判定: 以 { 或 [ 开头且以配对闭合符结尾"""
    s = s.strip()
    return (s[:1] in '[{' and s[-1:] in ']}') if s else False


def classify_page_type(html, content_type=None):
    """对单个页面按启发式信号分类 

    返回下列页面类型之一（本模块即该词汇的**单一真源**）。信号优先级:
    API_JSON > SPA > BACKEND_TEMPLATE > MPA > HTML_UNKNOWN(无标签非空文本 → STATIC)。
    纯函数、无副作用、可单测。不强依赖外部库 —— 仅基于文本信号。

    设计取舍: 这是"轻量分类"(用"响应指纹聚类 + canary
    基线"属轻量, 与 katana 的 simhash/tfidf/ML 不同)。本函数只做**确定性信号分类**,
    不引入 ML/外部依赖, 因此结果可解释、可回归; 跨页聚类的软 404 判定见
    `detect_soft404_signature`。
    """
    if not html:
        return 'UNKNOWN'
    ct = (content_type or '').lower()
    stripped = html.lstrip()
    # 1) JSON API: content-type 或首字符即 JSON 结构
    if ct.startswith('application/json') or (stripped[:1] in '[{' and _looks_json(stripped)):
        return 'API_JSON'
    if '<' not in html:
        # 无标签: 纯文本/数据; 非空且有结构感视为 STATIC, 否则 UNKNOWN
        return 'STATIC' if html.strip() else 'UNKNOWN'
    low = html.lower()
    # 2) SPA 信号(强): 挂载点 / 框架运行时标记 / noscript 提示
    _spa_strong = ('id="root"', "id='root'", 'id="app"', "id='app'", 'id="__next"',
                   'data-reactroot', 'window.__initial_state__', 'window.__next_data__',
                   'window.__nuxt', '<noscript>请启用 javascript', 'you need to enable javascript',
                   # Next.js: Pages Router 用 `__NEXT_DATA__`; **App Router 改用 RSC 载荷**
                   #   `self.__next_f.push(...)`, 且静态资源在 `_next/static`。
                   #   实测 nextjs.org(App Router) 无 `__NEXT_DATA__`, 因页面里有搜索 `<form>`
                   #   被判成 BACKEND_TEMPLATE(误判)。
                   '__next_f', '_next/static',
                   # Nuxt 的挂载点(实测 nuxt.com 用 `<div id="__nuxt">`)。
                   'id="__nuxt"', "id='__nuxt'")
    if any(s in low for s in _spa_strong):
        return 'SPA'
    # **未加引号**的挂载点(`<div id=app>`) —— 压缩 HTML 常见(实测官方 Vue RealWorld)。
    if re.search(r'\bid\s*=\s*(?:root|app|__next)\b', low):
        return 'SPA'
    # 大量 script + 构建产物 **.js** 名(`main.` / `app.` / `chunk.` / `bundle.` /
    #   `index-<hash>.js` 等) → SPA。实测官方 TodoMVC(Vue/Svelte) 用 `assets/index-<hash>.js`
    #   + `class="todoapp"` 挂载(无 `id="app"`) → 旧规则判成 HTML_UNKNOWN(误判)。
    #   两点必须注意:
    #     · **限定 `.js`** —— 实测 jQuery TodoMVC 的 `<link href="app.css">` 曾因旧 `'app.'` 裸子串被误判 SPA;
    #     · hash 里**可能含 `-`** —— 实测 Svelte 的 `index-BxPr2-fK.js` 因旧字符类 `[A-Za-z0-9_]` 不含 `-` 而漏判。
    #   注: **不用**"空挂载容器"作信号 —— 静态站 books.toscrape.com 有 `<div id="promotions_left"></div>`
    #   这类空位 div, 会把它误判成 SPA。
    _build_js = re.search(r'(?:index|main|app|chunk|bundle|vendor|runtime|polyfills)'
                          r'(?:[-.][A-Za-z0-9_.-]+)?\.(?:js|mjs)', low)
    if low.count('<script') >= 1 and _build_js:
        return 'SPA'
    # 2b) 扩展页面类型(规则版, 不引 ML) —— CAPTCHA / PARKED / LOGIN / ERROR。
    #   放在 SPA 之后、后端模板之前: 这些信号更具体, 且避免登录页/错误页被笼统归为
    #   BACKEND_TEMPLATE。全部用**强特征**匹配, 不做模糊判定(可解释、可回归)。
    if any(s in low for s in ('recaptcha', 'hcaptcha', 'g-recaptcha', 'cf-turnstile',
                              'geetest', 'captcha', '验证码', '请输入验证码')):
        return 'CAPTCHA'
    if any(s in low for s in ('this domain is for sale', 'domain for sale', 'buy this domain',
                              'this domain is parked', 'domain is parked', 'sedoparking',
                              '域名出售', '域名停放', '该域名')):
        return 'PARKED'
    # LOGIN: 必须出现**密码输入**(强特征) —— 仅凭 "login" 字样会把普通表单误判
    if ('type="password"' in low or "type='password'" in low
            or 'name="password"' in low or "name='password'" in low):
        return 'LOGIN'
    # ERROR: 标题命中错误码/错误短语, 或短正文 + 明确错误短语
    _tm = re.search(r'<title[^>]*>([^<]{0,200})</title>', low)
    _title = _tm.group(1) if _tm else ''
    if _title and re.search(r'(404|500|502|503|error|not found|forbidden|'
                            r'访问出错|页面不存在|出错了|无法访问)', _title):
        return 'ERROR'
    if len(html) < 3000 and any(s in low for s in (
            '404 not found', 'page not found', 'internal server error',
            'the page you requested', '页面不存在', '找不到页面', '访问出错')):
        return 'ERROR'
    # 3) 后端模板信号(强): 框架指纹 / CSRF token / 服务端模板语法
    #   注: Thymeleaf 的 `th:` **不能**用裸子串匹配 —— 实测 `width:60vw` / `height:` 等
    #   普通 CSS 都含 `th:`, 会把大量静态页误判为 BACKEND_TEMPLATE(example.com 即中招)。
    #   改为要求"属性形态"(前面是空白/引号, 后面紧跟字母)。
    #   注意: token 必须**框架特异** —— 实测裸子串 `express`/`spring`/`jsp` 会在压缩 JS
    #   或普通文案里命中, 把页面(甚至 JS)误判为后端模板。故改为特异性写法。
    _backend_strong = ('csrfmiddlewaretoken', 'name="__requestverificationtoken"',
                       '<%', '<?php', 'x-powered-by', 'server-parsed',
                       'werkzeug', 'springframework', 'whitelabel error',
                       'laravel_session', 'django', 'aspnet')
    if any(s in low for s in _backend_strong) or re.search(r'[\s"\']th:[a-z]', low):
        return 'BACKEND_TEMPLATE'
    # 含表单(服务端渲染的 input)且无 SPA 挂载点 → 后端模板
    if '<form' in low and ('method=' in low or 'action=' in low):
        return 'BACKEND_TEMPLATE'
    # 4) 多页(MPA): 多个内部超链接
    if low.count('<a ') >= 3 or low.count('<a href') >= 3:
        return 'MPA'
    return 'HTML_UNKNOWN'


def should_run_runtime(ctx, out):
    """解析 runtime **三态**配置 → (是否运行, 原因)。

    false : 从不运行（保持最小动作）。
    true  : 总是运行。
    auto  : 仅当目标被判定为 **SPA(客户端渲染)** 时运行 —— 此时静态 JS 分析覆盖最弱、
            运行时通道收益最大；非 SPA 目标保持关闭，避免无谓的浏览器流量。

    SPA 判定用多个信号(任一命中): 页面类型=SPA / 前端框架指纹 / 前端路由密集。
    纯函数(只读 config/out/ctx)，可单测。
    """
    cfg = getattr(ctx, 'config', None) or {}
    val = cfg.get('runtime')
    if val is True:
        return True, 'runtime=true 显式启用'
    if val is False or val is None:
        return False, ''
    # 'auto'（或任何非布尔真值字符串）
    if 'SPA' in set((out.get('page_types') or {}).values()):
        return True, 'runtime=auto: 页面类型=SPA'
    _hits = ' '.join((getattr(ctx, 'fingerprints', None) or {}).get('hits', [])).lower()
    if any(h in _hits for h in _SPA_FP_HINTS):
        return True, 'runtime=auto: 命中前端框架'
    if len(out.get('routes') or []) >= 5:
        return True, 'runtime=auto: 前端路由密集'
    # 未触发也要给原因(空串会让报告只能说"未运行", 无法区分"没请求"与"请求了没跑成")。
    return False, 'runtime=auto: 目标非 SPA(页面类型/框架指纹/前端路由密集均未命中), 未触发运行时通道'


def simhash64(text, shingle=3):
    """64-bit simhash(纯 Python, 无外部依赖)

    对 token 的 3-gram 特征做加权投票。用于判定"长度不同但内容高度相似"的回退页
    (如网关在 404 页里回显请求路径/时间戳 → 精确指纹各不相同, 但内容近乎一致)。
    """
    if not text:
        return 0
    toks = re.findall(r'\w+', text.lower())
    if not toks:
        toks = [text[:64]]
    if len(toks) <= shingle:
        feats = [' '.join(toks)]
    else:
        feats = [' '.join(toks[i:i + shingle]) for i in range(len(toks) - shingle + 1)]
    v = [0] * 64
    for f in feats:
        h = int(hashlib.md5(f.encode('utf-8', 'ignore')).hexdigest()[:16], 16)
        for i in range(64):
            v[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(64):
        if v[i] > 0:
            out |= (1 << i)
    return out


def hamming64(a, b):
    """两个 64-bit simhash 的汉明距离"""
    return bin(((a ^ b) & 0xFFFFFFFFFFFFFFFF)).count('1')


def detect_soft404_signature(responses):
    """基于多路径响应聚合判定 catch-all / 软 404 (响应指纹聚类 + simhash)

    `responses`: 可迭代的 dict, 每项为
        {'path': str, 'status': int|None, 'body_fp': hashable, 'title': str,
         'body': str(可选, 正文; 提供后启用 simhash 近重复判定)}
      `body_fp` 为响应正文指纹(如 hashlib 摘要 / 规范化后的前 N 字节 hash)。
      `path` 应为"随机/不存在"路径(由调用方负责提供 canary 集), 本函数不做随机化。

    判定(两级):
      ① **精确**: 存在 (status, body_fp) 被 >=3 个互不相同路径共享 → catch-all;
      ② **近重复**: 各响应正文 simhash 汉明距离 <= SIMHASH_NEAR_HAMMING 且同 status
         的簇含 >=3 个不同路径 → catch-all（兜住"长度不同但内容高度相似"的回退页）。

    与 `_is_catchall`(单点 canary 基线比对)互补: 后者在探测时逐响应判定, 本函数在
    扫描结束后**跨路径聚合**, 能兜住"canary 基线恰好 404、但大量随机路径返回同款 200 页面"
    这类单点基线漏判的场景。
    """
    from collections import defaultdict
    groups = defaultdict(list)
    for r in responses:
        key = (r.get('status'), r.get('body_fp'))
        groups[key].append(r.get('path'))
    for (status, fp), paths in groups.items():
        uniq = {p for p in paths if p}
        if status is not None and len(uniq) >= 3:
            return {'is_catchall': True, 'status': status, 'signature': fp,
                    'suspicious_paths': sorted(uniq)[:10], 'count': len(uniq),
                    'near_dup': False, 'simhash': None}
    # ② simhash 近重复(仅当响应提供了足够长的正文)
    sigs = []
    for r in responses:
        body = r.get('body')
        if isinstance(body, str) and len(body) >= SIMHASH_MIN_LEN:
            sigs.append((r.get('status'), simhash64(body), r.get('path')))
    clusters = []
    for status, h, path in sigs:
        for cl in clusters:
            if cl['status'] == status and any(
                    hamming64(h, m[0]) <= SIMHASH_NEAR_HAMMING for m in cl['members']):
                cl['members'].append((h, path))
                break
        else:
            clusters.append({'status': status, 'members': [(h, path)]})
    for cl in clusters:
        uniq = {p for _, p in cl['members'] if p}
        if cl['status'] is not None and len(uniq) >= 3:
            return {'is_catchall': True, 'status': cl['status'],
                    'signature': 'simhash-near-dup',
                    'suspicious_paths': sorted(uniq)[:10], 'count': len(uniq),
                    'near_dup': True, 'simhash': cl['members'][0][0]}
    return {'is_catchall': False, 'status': None, 'signature': None,
            'suspicious_paths': [], 'count': 0, 'near_dup': False, 'simhash': None}


# ---------- 探活与响应分析 ----------


def _looks_unauth(text):
    """判断"HTTP 200 但业务码表示未授权"。仅用于**分类**判定, 不改动响应内容。"""
    t = (text or '')
    if not t:
        return False
    tl = t.lower()
    if re.search(r'"code"\s*:\s*"?40[13]"?', tl):     # {"code":401} / {"code":403}
        return True
    # 裸标记：仅当响应是**短消息体**时才判 —— 否则长页面散文里出现该词会误判。
    if len(t) > _UNAUTH_MARKER_MAXLEN:
        return False
    return any(m.lower() in tl for m in _UNAUTH_MARKERS)


def _looks_mgmt_list(text):
    """判断响应体是否**确实**含管理列表数据(用户 / 角色 / 菜单 / 字典)。

    用于避免"只要 200 就报管理接口可达"的**过度断言**(同类缺陷: 凭路径 + 状态码下结论,
    不看响应体证据)。实测国内低代码框架未登录时**常回 HTTP 200 + 业务码未授权**
    (如 `{"code":401,"msg":"请先登录"}` / `token无效`), 此时响应体**不含**任何列表数据 ——
    若仍报 HIGH"管理接口可达 · 用户/角色/字典列表可读", 即**虚构证据**。

    判据: 需**同时**具备 ①列表容器字段 ②管理对象字段(证明是"用户/角色/菜单/字典"数据,
    而非空壳 / 错误体 / 通用回退页)。仅用于**分类**判定, 不改动响应内容。
    """
    t = (text or '')
    if not t:
        return False
    tl = t.lower()
    has_container = any(k in tl for k in ('"records"', '"rows"', '"total"',
                                          '"data"', '"list"'))
    has_entity = any(k in tl for k in (
        'username', 'user_name', 'rolename', 'role_name', 'menuname', 'menu_name',
        'dictname', 'dict_name', 'userid', 'user_id', 'roleid', 'role_id', 'nickname',
    ))
    return has_container and has_entity




def _fingerprint_resp(r):
    """响应指纹: 用于聚类去重与 catch-all 判定

    增强区分度: 前 200 字符 + 前 12 个标签 + 10 字节级长度桶。
    用"前100字符 + 前5标签 + 千位长度桶", 区分度不足会导致两个不同
    页面指纹碰撞 → 真实路径被误判为伪命中(假阴性)。
    """
    if r is None:
        return ''
    t = r.text or ''
    sig = t[:200]
    tags = re.findall(r'<(\w+)[>\s]', t)
    sig += '|' + ','.join(sorted(set(tags))[:12])
    sig += f'|len{len(t) // 10}0'
    return hashlib.md5(sig.encode('utf-8', 'ignore')).hexdigest()[:12]


def _regime_of(url):
    """取 URL 的"形态族"键: 已知 API 前缀(或 v1/v2…)→ '/'+前缀; 其余 → '/'。"""
    try:
        path = urlsplit(url or '').path or '/'
    except Exception:
        return '/'
    seg = path.strip('/').split('/', 1)[0].lower()
    if seg in _API_REGIME_SEGMENTS or re.fullmatch(r'v\d+', seg):
        return '/' + seg
    return '/'


def _ct_cat(ct):
    """响应 Content-Type → 短类别(html/json/xml/text/bin; 未知返回 '')。

    供探活备注携带, 让报告区分"页面型(HTML) vs 数据型(JSON)"候选 —— 文档站的
    `/api/xxx.html` 这类 HTML 页面不再与真实数据接口混为一谈(降噪)。纯函数, 可单测。
    """
    c = (ct or '').lower()
    if not c:
        return ''
    if 'json' in c:
        return 'json'
    if 'html' in c:
        return 'html'
    if 'xml' in c:
        return 'xml'
    if c.startswith('text/'):
        return 'text'
    return 'bin'
