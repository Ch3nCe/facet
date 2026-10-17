# -*- coding: utf-8 -*-
"""facet — Playwright 运行时通道（对抗 JS 混淆/加密/动态加载）

原理：在真实浏览器环境中执行目标页面，通过以下方式提取静态分析无法获取的信息：
1. 网络拦截：监听 page.on('request')，捕获动态加载的 API 端点
2. 路由触发：点击页面内已有的站内链接，触发懒加载路由和代码分割 chunk
3. JS 注入：在页面上下文中执行自定义脚本，提取 window 对象、React/Vue 内部状态
4. 事件驱动：监听 console / websocket 事件，捕获调试信息中的路径线索

合规约束：
- 仅访问用户指定的目标域名 —— 通过 page.route 主动 abort 所有第三方资源请求，
  避免把分析师的出口 IP 暴露给 CDN / 统计服务，也避免不可控的外部流量。
  · 但跨域请求的 **URL 仍会被登记**(只登记不请求, 见 `external_requests`) —— 对齐 DevTools
    的"看得到"。实测真实 SPA 的业务 API 常在跨域主机(`api.*` / `conduit.*`), 不登记则什么都看不到。
- 不自动填充表单、不提交数据（纯侦察）。
- 浏览器通道产生的每一个站内请求都会计入 ctx.total_sent —— 它同样是"发给目标的
  流量"，此前完全不计数会让报告的"总发包"严重偏低。
- **速率（统一限速，铁律·分流面#19）**：route 层对每个站内请求调用 `ctx.rm.reserve()`，
  与 HTTP 主链路**共享同一 RateManager**（同一 `last`/`rpm_window` 配额 + max_rpm 硬顶 +
  429/5xx 自适应调速 + 熔断感知），不再是"只复制 rate 数值、却各自独立状态"的伪统一。
  并设同域请求总数上限（`runtime_max_requests`）；浏览器发包计入 `ctx.total_sent`。
  · `ensure_rate_manager()` 已在进入 `async_playwright()` 前调用；若 rm 极端未就绪，
    退化按 local `rate` 节流（document/xhr/fetch 按 `rate`，静态子资源按轻量间隔），保底不跑飞。

捕获能力（对齐 DevTools Network 面板）：
- request : method / query / 请求体参数(JSON·form·multipart, **只取名不存值**) / 自定义头
- 取值形态: query/请求体参数的**形态**(int/uuid/hex/email/bool/str, **只记形态不存原值**)
            —— 用于判断 IDOR 可利用性(顺序 int 好打, uuid/hex 难枚举)
- response: 状态码
- websocket / console / window.__NEXT_DATA__ 等（原有）
"""

import asyncio
import os
import re
import threading
from urllib.parse import parse_qsl, urlparse

from ..core.dicts import (
    JS_EXTS,
    READONLY_METHODS,
    ROUTE_ENTRY_GUESSES,
    ROUTE_ENTRY_GUESSES_I18N,
    STATIC_ASSET_EXT,
    is_readonly_method,
)
from ..core.log import log
from ..core.util import _extract_paths_from_obj


def available():
    """Playwright 是否**真正可用**(已安装)。

    供 `guard.should_run_runtime` / 报告**如实披露**运行时通道状态 —— 避免"请求了 runtime
    但依赖缺失"时被报告误称为"已启用"(能力宣称必须等于真实执行; 与 `strong_available()` 同口径)。
    """
    try:
        from playwright.async_api import async_playwright  # noqa: F401
        return True
    except Exception:
        return False


def _empty_result(ran=False, reason=''):
    """运行时通道的**统一空结果**(未运行/异常时) —— 保证调用方 `.get()` 恒安全, 且带
    `ran`/`reason` 供上层**如实**判定"是否真的跑过"。"""
    return {
        'ran': bool(ran), 'reason': reason or '',
        'apis': set(), 'urls': set(), 'js_urls': set(), 'websockets': set(),
        'console': [], 'params': {}, 'param_shapes': {}, 'responses': set(),
        'external_requests': set(),
        # R5: 浏览器观测到但被只读护栏拦截的写请求(method, url) —— 观测≠发送的实证
        'write_blocked': [],
    }


def _assemble_runtime_result(dynamic_apis, intercepted_urls, runtime_js, ws_endpoints,
                             console_lines, runtime_params, runtime_param_shapes,
                             runtime_responses, external_requests, ran, reason,
                             write_blocked=None):
    """运行时通道的**统一结果装配**(正常结束与异常/半途均走此, 保证:
      · 调用方 `.get()` 恒安全(键恒齐全);
      · goto 失败等半途场景**保留已采集的部分数据**(不返回空 dict 丢失证据);
      · 'ran'/'reason' 如实反映"是否真的跑完"(能力宣称 = 真实执行)。
    """
    return {
        'ran': bool(ran), 'reason': reason or '',
        'apis': dynamic_apis,
        'urls': intercepted_urls,
        'js_urls': runtime_js,
        'websockets': ws_endpoints,
        'console': console_lines,
        'params': runtime_params,
        'param_shapes': runtime_param_shapes,
        'responses': runtime_responses,
        'external_requests': external_requests,
        'write_blocked': list(write_blocked or []),
    }


def _is_same_domain(url, base):
    """判定 URL 是否与目标同域（防止拦截到第三方 CDN）"""
    try:
        return urlparse(url).netloc == urlparse(base).netloc
    except Exception:
        return False


# 浏览器通道**只放行只读方法** —— 页面 JS 若发起写请求(POST/PUT/PATCH/DELETE)一律 abort。
#   (合规红线: 工具不做写操作; 该请求仍会被 request 事件登记为"观测到的端点", 观测≠发送。)
#   集合取自**数据层单一真源** `dicts.READONLY_METHODS`(与 HTTP 同步/异步通道同源)。


def _browser_should_abort(method, url, base, scope=None):
    """浏览器 route 层的**只读护栏 + 范围护栏**: 返回 (是否 abort, 原因)。纯函数, 可单测。

    - data:/blob:/about: 内部协议 → 放行(不产生网络请求);
    - scope 给定且 url 在声明范围内 → 放行(可能宽于同域, 如含子域), 但仍受只读方法约束;
    - 第三方 URL → abort(不请求第三方);
    - 同域但**非只读方法** → abort(不发写请求)。

    scope 为 None(默认, 未显式 --scope)时行为完全等价于旧版(仅同域 + 只读约束)。
    """
    if url.startswith(('data:', 'blob:', 'about:')):
        return False, ''
    if scope is not None and scope.in_scope(url):
        # 显式声明范围内(可能宽于同域) → 放行, 但写请求仍不发。
        if not is_readonly_method(method):
            return True, 'non-readonly-method'
        return False, ''
    if not _is_same_domain(url, base):
        return True, 'third-party'
    if not is_readonly_method(method):
        return True, 'non-readonly-method'
    return False, ''


def _nav_href_allowed(href):
    """点击页内链接前的**离站判定**（纯函数, 可单测）。

    只允许站内相对链接(纯相对 `foo` 或根相对 `/foo`); 排除:
      · 锚点 `#` / `javascript:` / `mailto:`(无意义);
      · 绝对外链 `http(s)://...`;
      · **协议相对 `//evil.com`**(会解析为外域) —— 此前跳过清单漏掉此项,
        目标页面含 `<a href="//attacker.com">` 时分析仪会尝试离站导航(虽被 route
        层 abort, 但违背"仅访问目标域名"承诺, 且是无效导航尝试)。
    作为 route 只读护栏之外的**第二道兜底**, 让点击路径从源头就不碰外域。
    """
    if not href:
        return False
    if href.startswith(('#', 'javascript:', 'mailto:', 'http', '//')):
        return False
    return True

def _extract_api_from_url(url):
    """从拦截到的请求 URL 中提取 API 路径"""
    try:
        parsed = urlparse(url)
        path = parsed.path
        # 过滤静态资源
        if any(path.endswith(ext) for ext in ('.js', '.mjs', '.css', '.png', '.jpg', '.woff', '.svg', '.ico', '.gif')):
            return None
        if '/api/' in path or '/v1/' in path or '/v2/' in path or '/graphql' in path:
            return path
        # 启发式：包含 REST 特征的路径
        if re.search(r'/[a-z]+/[0-9a-z_-]+(/|$)', path) and not path.startswith('/static/'):
            return path
    except Exception:
        pass
    return None

def _extract_from_text(text, out):
    """从 console 文本中提取疑似 API 路径"""
    if not text:
        return
    for m in re.findall(r'["\'`](/[A-Za-z0-9_\-./]{2,80})["\'`]', text):
        if any(m.startswith(p) for p in ('/api', '/v1', '/v2', '/graphql', '/rest', '/rpc')):
            out.add(m)


def _join_url(base, rel):
    """拼接 base 与相对路径(保留 base 已有路径段; 纯函数, 可单测)。

    旧实现用 `base.rstrip('/') + '/' + rel`, 当 base 含路径(如 https://x.com/app)时会错误
    丢弃 base 路径段。此处从 base 解析出目录段再拼接, 与 URL 规范一致。
    """
    try:
        ub = urlparse(base)
        base_dir = ub.path.rstrip('/')
        rel = rel.lstrip('/')
        new_path = (base_dir + '/' + rel) if base_dir else ('/' + rel)
        return f'{ub.scheme}://{ub.netloc}{new_path}'
    except Exception:
        return (base.rstrip('/') + '/' + rel)


def _external_request_key(url):
    """跨域端点登记键(纯函数): 保留 query, 避免把 `?a=1` 与 `?a=2` 合并成一条。

    仅用于 `external_requests`(只登记不请求); 同域端点仍走 `_endpoint_path` 形态。
    """
    try:
        u = urlparse(url)
        q = ('?' + u.query) if u.query else ''
        return f'{u.scheme}://{u.netloc}{u.path}{q}'
    except Exception:
        return url


def _resolve_response_method(resp_method):
    """响应方法解析(绝不虚构): 观测到方法则原样返回; 否则返回 '?'(不编造 'GET')。

    合规红线: 方法不得推断 —— 浏览器响应未携带/无法读取方法时, 标 '?' 而非 'GET',
    由报告层展示为 '—'(未声明), 绝不用猜的 GET 充数。
    """
    if resp_method:
        return str(resp_method).upper()
    return '?'


# ---------- DevTools 等价捕获: 常量与纯函数 ----------

# 逐请求节流: document/xhr/fetch 按统一 rate 节流; 页面静态子资源按轻量间隔放行。
_THROTTLE_TYPES = ('document', 'xhr', 'fetch')
_ASSET_INTERVAL = 0.05
# 浏览器通道同域请求总数上限(防跑飞; 超限即 abort 后续同域请求)。可经 config 覆盖。
_RUNTIME_MAX_REQS = 300


def _browser_throttle_wait(ctx, rtype):
    """返回浏览器通道单请求应等待的秒数, 并(若 rm 就绪)**消耗统一配额**。

    统一限速(铁律·分流面#19): 优先 `ctx.rm.reserve()` —— 与 HTTP 主链路共享同一
    RateManager 状态(同一 last/rpm_window 配额 + max_rpm 硬顶 + 429/5xx 自适应 + 熔断感知),
    不再用各自独立的 `rate` 数值(那是"数字相同≠状态共享"的反例)。
    rm 未就绪(ensure_rate_manager 极端失败)时退化按 local rate(document/xhr/fetch 按 rate,
    其余按轻量间隔), 保底不跑飞。
    """
    rm = getattr(ctx, 'rm', None)
    if rm is not None:
        return rm.reserve()
    _cfg = getattr(ctx, 'config', {}) or {}
    rate = float(_cfg.get('rate', 0.5) or 0.5)
    if rtype in _THROTTLE_TYPES:
        return rate
    return min(rate, _ASSET_INTERVAL)

# 静态资源后缀(非端点) —— **单一真源** = 数据层 `dicts.STATIC_ASSET_EXT`(窄口径);
#   此前此处与 `report/report.py` 各写一份**同值元组**("同值常量第二处"反模式), 现统一从数据层导入。

# 不视作"自定义头参数"的通用头(浏览器/代理自带, 无侦察价值)。
_HEADER_DENY = {'x-requested-with', 'x-forwarded-for', 'x-forwarded-proto',
                'x-forwarded-host', 'x-real-ip'}

# 跨域端点登记时的**遥测/统计**主机黑名单(与业务无关, 避免噪声淹没真实 API)。
_EXTERNAL_DENY_HOSTS = ('google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
                        'backtrace.io', 'sentry.io', 'cloudflareinsights.com', 'segment.io',
                        'mixpanel.com', 'hotjar.com', 'newrelic.com', 'datadoghq.com',
                        'bugsnag.com', 'amplitude.com', 'clarity.ms')

# 取值形态判定(只记形态, 不存原值)。
_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                      r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_HEX_RE = re.compile(r'^[0-9a-fA-F]{16,}$')
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _endpoint_path(url):
    """xhr/fetch/document 请求的端点路径(过滤静态资源与根路径); 非端点返回 None。"""
    try:
        p = urlparse(url).path
    except Exception:
        return None
    if not p or p == '/':
        return None
    if any(p.lower().endswith(e) for e in STATIC_ASSET_EXT):
        return None
    return p


def _value_shape(v):
    """参数值的**形态**(只记形态, 不存原值): int/uuid/hex/email/bool/str/empty。

    用途: 帮助判断 IDOR 可利用性 —— 顺序整数(`int`)比不可枚举的 `uuid`/`hex` 好打得多。
    刻意**不保留原值**(合规: 不留存数据, 也不落盘)。
    """
    if v is None or v == '':
        return 'empty'
    s = str(v)
    if s.lower() in ('true', 'false'):
        return 'bool'
    if s.isdigit():
        return 'int'
    if _UUID_RE.match(s):
        return 'uuid'
    if _HEX_RE.match(s):
        return 'hex'
    if _EMAIL_RE.match(s):
        return 'email'
    return 'str'


def _collect_shapes(obj, out, depth=0):
    """递归收集 JSON 里的 {键名: 取值形态}; 容器键记 'obj'。只记形态、不存值。"""
    if depth > 4:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            k = str(k)
            if isinstance(v, (dict, list)):
                out.setdefault(k, 'obj')
                _collect_shapes(v, out, depth + 1)
            else:
                out[k] = _value_shape(v)
    elif isinstance(obj, list):
        for v in obj[:20]:
            _collect_shapes(v, out, depth + 1)


def _body_param_shapes(body, content_type):
    """从请求体抽取 {参数名: 取值形态}(JSON/form/multipart); 只记形态、不存值。"""
    out = {}
    if not body:
        return out
    ct = (content_type or '').lower()
    try:
        if 'json' in ct:
            import json
            _collect_shapes(json.loads(body), out)
        elif 'multipart/form-data' in ct:
            for n in re.findall(r'name="([^"]+)"', body):
                out.setdefault(n, 'str')
        elif '=' in body:
            # 默认按 form-urlencoded 解析('a=1&b=2'); 无 '=' 视为原文本, 忽略。
            for k, v in parse_qsl(body, keep_blank_values=True):
                out[k] = _value_shape(v)
    except Exception:
        pass
    return out



# ---------- 浏览器复盘导入（人工触发 vs 自动扫描） ----------

def _session_headers(ctx):
    """构造浏览器运行时通道的会话头 —— 与 HTTP 主链路 `_global_headers` **同口径**。

    覆盖:
      · `--cookie` 注入的 Cookie;
      · `login` 会话预热建立的会话 Cookie(HTTP 通道经 requests.Session jar 自动继承,
        浏览器通道此前不继承 → 以 login 预热建会话的站点, 运行时通道实际是匿名, 登录后
        页面/接口漏抓);
      · `--token` 注入的 Bearer Authorization;
      · `--header` 注入的**全部**自定义头(含 X-Access-Token / X-Api-Key 等鉴权头, 也含
        普通自定义头) —— 此前浏览器通道只注入 cookie+token, 漏掉全部自定义头, 自定义头
        鉴权的目标运行时通道实为匿名。

    旧实现只读了 cfg['cookie']/cfg['token'], 与 HTTP 通道的认证态口径分叉(认证态分流缺陷)。
    """
    cfg = getattr(ctx, 'config', {}) or {}
    h = {}
    # Cookie: 配置注入 + 会话预热 cookie(合并, 互不覆盖)
    ck = str(cfg.get('cookie') or '').strip()
    sess = getattr(ctx, 'session', None)
    if sess is not None:
        try:
            _sc = '; '.join(f'{n}={v}' for n, v in sess.cookies.items())
        except Exception:
            _sc = ''
        if _sc:
            ck = (_sc if not ck else ck + '; ' + _sc).strip('; ')
    if ck:
        h['Cookie'] = ck
    # Bearer token
    tk = str(cfg.get('token') or '').strip()
    if tk:
        h['Authorization'] = f'Bearer {tk}'
    # 自定义头(全部注入, 与 _global_headers 一致)
    raw = cfg.get('header')
    if raw:
        items = raw if isinstance(raw, (list, tuple)) else [raw]
        for item in items:
            if not item or ':' not in str(item):
                continue
            k, _, v = str(item).partition(':')
            k, v = k.strip(), v.strip()
            if k:
                h[k] = v
    return h


# ---------- R4 登录态采集(演进建议 · 借鉴 JsOwl --login, 但只借"登录"环节) ----------
#   差异: JsOwl 登录后仍以 browser 模式扫全站; 本工具采集到 storage_state 后**关闭浏览器**,
#   整轮扫描切回轻量 HTTP 通道(同步/异步)复用会话 —— 成本远低于全程开浏览器。
def apply_captured_state(ctx, state):
    """把采集到的 storage_state 回灌: HTTP 长驻 Session cookie + 运行时上下文档。

    凭据**只进内存**(Session jar / ctx 属性), 不落盘、不进报告/审计(审计仅记"已采集")。
    """
    cookies = {}
    for c in ((state or {}).get('cookies') or []):
        try:
            name, value = c.get('name'), c.get('value')
        except Exception:
            continue
        if not name:
            continue
        cookies[name] = value
        try:
            s = ctx.ensure_session()
            s.cookies.set(name, value,
                          domain=c.get('domain') or '', path=c.get('path') or '/')
        except Exception:
            pass
    ctx.captured_cookies = cookies
    ctx.captured_storage_state = state or {}
    ctx.login_captured = bool(cookies or (state or {}).get('origins'))
    return cookies


def _interactive_input(prompt):
    """阻塞式读一行。EOF/异常 → None。"""
    try:
        return input(prompt)
    except Exception:
        return None


async def _wait_operator_enter(timeout):
    """等待操作者确认; 输入线程为 daemon, 超时后不会阻塞 asyncio.run 收尾。

    ThreadPoolExecutor 的 worker 是非 daemon: wait_for 超时并不能取消正在 input() 的线程,
    asyncio.run 退出时 join default executor 会继续卡到人工输入, 使 login_capture_timeout 形同虚设。
    这里用 daemon 线程 + Future; 超时后浏览器能立即关闭, 扫描继续。
    """
    loop = asyncio.get_running_loop()
    done = loop.create_future()

    def _resolve(value):
        if not done.done():
            done.set_result(value)

    def _reader():
        value = _interactive_input('  登录完成后按 Enter 结束采集 > ')
        try:
            loop.call_soon_threadsafe(_resolve, value)
        except Exception:
            pass

    threading.Thread(target=_reader, daemon=True, name='facet-login-input').start()
    return await asyncio.wait_for(done, timeout=float(timeout))


async def _runtime_capture_login_async(ctx, base):
    """R4: 可见浏览器登录采集 —— 操作员手动登录, 工具只旁观并导出 storage_state。

    合规边界:
      · **手动浏览阶段不装只读/范围护栏** —— SSO 第三方重定向是登录流的一部分, 拦截会直接
        断掉登录; 这一阶段等同于操作员使用自己的浏览器(工具不主动发包)。
      · 登录完成后**立即关闭浏览器**, 采集结果只含 cookie/localStorage, 不含任何请求流量;
      · 凭据仅内存态; 超时未登录 → 按未采集处理并如实披露, 扫描以原(匿名)态继续。
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {'ran': False, 'reason': 'Playwright 未安装', 'state': None}

    _cfg = ctx.config or {}
    try:
        _timeout = float(_cfg.get('login_capture_timeout', 300) or 300)
    except (TypeError, ValueError):
        _timeout = 300.0
    async with async_playwright() as p:
        _launch = {'headless': False}      # 必须可见: 操作员要亲手登录
        _rb = os.environ.get('FACET_RUNTIME_BROWSER') or _cfg.get('runtime_browser')
        if _rb:
            _rb = os.path.expanduser(str(_rb))
            if os.path.isfile(str(_rb)):
                _launch['executable_path'] = str(_rb)
            else:
                _launch['channel'] = str(_rb)
        try:
            browser = await p.chromium.launch(**_launch)
        except Exception as e:
            # 二进制缺失/启动失败(未 playwright install / 沙箱限制) → 优雅降级, 不炸扫描
            return {'ran': False, 'reason': f'浏览器启动失败: {str(e)[:120]}', 'state': None}
        try:
            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                           '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            page = await context.new_page()
            try:
                await page.goto(base, wait_until='domcontentloaded', timeout=30000)
            except Exception as e:
                return {'ran': False, 'reason': f'打开目标失败: {e}', 'state': None}
            log('[*] [login-capture] 已打开目标页面, 请在浏览器窗口中完成登录; '
                '回到本终端按 Enter 结束采集(或等待超时取消)…')
            try:
                await _wait_operator_enter(_timeout)
            except asyncio.TimeoutError:
                log(f'[-] [login-capture] {int(_timeout)}s 内未确认, 取消采集(以原认证态继续)')
                return {'ran': False, 'reason': f'登录采集超时({int(_timeout)}s)', 'state': None}
            state = await context.storage_state()
            n_ck = len(state.get('cookies') or [])
            log(f'[*] [login-capture] 采集完成: {n_ck} 个 cookie; '
                f'浏览器即将关闭, 后续扫描走 HTTP 通道复用该会话')
            return {'ran': bool(n_ck), 'reason': '' if n_ck else '未采集到 cookie',
                    'state': state}
        finally:
            try:
                await browser.close()
            except Exception:
                pass


def runtime_capture_login(ctx, base):
    """R4 同步包装: 登录态采集。返回 {'ran', 'reason', 'state'}。"""
    import asyncio as _asyncio
    try:
        _asyncio.get_running_loop()
        has_loop = True
    except RuntimeError:
        has_loop = False
    if has_loop:
        import concurrent.futures
        executor = concurrent.futures.ThreadPoolExecutor(1)
        try:
            return executor.submit(_asyncio.run,
                                   _runtime_capture_login_async(ctx, base)).result(
                timeout=(float((ctx.config or {}).get('login_capture_timeout', 300) or 300) + 60))
        finally:
            executor.shutdown(wait=False)
    return _asyncio.run(_runtime_capture_login_async(ctx, base))


async def _goto_best_effort(page, url, timeout=30000, settle_ms=8000):
    """**三级阶梯**导航：`commit`(必达) → `domcontentloaded`(尽力) → `networkidle`(尽力)。

    演进过程（每一级都是被真实目标逼出来的）：
      1. 最初 `wait_until='networkidle'` —— 繁忙 SPA(埋点/心跳/轮询)网络永不空闲 → 超时 →
         **整条运行时通道被放弃**；
      2. 改成 `domcontentloaded`(必达) + networkidle(尽力) —— 又实测到**有的 SPA 永不触发
         DOMContentLoaded**：手工验证 `goto(wait_until='commit')` **0.6s 成功、捕获 103 个请求
         (75 个 JS)**，而 `domcontentloaded` 30s 超时 → 通道再次被放弃
         （报告里表现为 `completeness.runtime.ran=false`）；
      3. 现改为**必达用最宽松的 `commit`**（只等导航提交，必然返回），后两级**尽力**且各自
         限时。这样"页面能加载"就一定拿得到请求流水（XHR/fetch 是运行时接口最可靠的来源），
         而"加载慢/不触发事件"只影响能拿到多少，不再让整条通道归零。
    """
    await page.goto(url, wait_until='commit', timeout=timeout)
    try:
        await page.wait_for_load_state('domcontentloaded', timeout=min(15000, timeout))
    except Exception:
        pass          # 不触发 DCL 的 SPA: 忽略, 继续
    try:
        await page.wait_for_load_state('networkidle', timeout=settle_ms)
    except Exception:
        pass          # 繁忙页面未空闲: 忽略, 继续用已加载的 DOM + 已捕获的请求


async def _runtime_recon_async(ctx, base):
    """异步运行时侦察核心（Playwright）"""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log('[-] Playwright 未安装，跳过运行时通道（pip install playwright && playwright install chromium）')
        # 返回带 ran=False 的统一结构 —— 上层据此**如实**披露"未运行", 而非按配置谎称"已启用"。
        return _empty_result(False, 'Playwright 未安装')

    intercepted_urls = set()
    ws_endpoints = set()
    dynamic_apis = set()
    runtime_params = {}          # path -> set(参数名: query/body/自定义头)
    runtime_param_shapes = {}    # path -> {参数名: set(取值形态)}  (只记形态, 不存原值)
    runtime_responses = set()    # (path, method, status)
    external_requests = set()    # 跨域端点(只登记不请求; 对齐 DevTools 的"看得到")
    runtime_js = set()           # 同域 .js(含 SPA 路由懒加载 chunk), 供 engine 追打分析(步骤3.5.2)
    console_lines = []
    browser_reqs = 0
    # R5: 浏览器观测到但被只读护栏**拦截**的写请求(method, url) —— "观测≠发送"的实证;
    #   交互模式(interactive)下由填表/点击触发, 常态也记录页面 JS 自发尝试的写请求。
    write_blocked = []
    _wb_seen = set()

    _cfg = ctx.config or {}
    max_reqs = int(_cfg.get('runtime_max_requests', _RUNTIME_MAX_REQS) or _RUNTIME_MAX_REQS)
    # 浏览器通道与 HTTP 主链路**共享同一 RateManager**(统一配额/熔断/自适应):
    #   route handler 的节流改调 `ctx.rm.reserve()`(见下), 故 rm 必须在 route 触发前就绪。
    try:
        ctx.ensure_rate_manager()
    except Exception:
        pass

    async with async_playwright() as p:
        # 浏览器启动参数：默认用 Playwright 自带的 Chromium。若环境无法下载自带 Chromium
        #   (离线/代理受限/CI 沙箱)，可用环境变量 `FACET_RUNTIME_BROWSER` 或配置键
        #   `runtime_browser` 指向系统已装的浏览器：
        #     · 填**可执行文件路径** → executable_path(如 /Applications/Google Chrome.app/.../Google Chrome)；
        #     · 填 'chrome' / 'chromium' → channel(用系统同名浏览器)。
        #   默认不传 → 行为不变(自带 Chromium)。仅在 root 下追加 --no-sandbox(Chrome 硬性要求)。
        _launch = {'headless': True}
        _rb = os.environ.get('FACET_RUNTIME_BROWSER') or _cfg.get('runtime_browser')
        if _rb:
            _rb = os.path.expanduser(str(_rb))   # `~/...` 波浪线此前不被识别, 误判为 channel 名(审计 L)
            if os.path.isfile(str(_rb)):
                _launch['executable_path'] = str(_rb)
            else:
                _launch['channel'] = str(_rb)
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            _launch.setdefault('args', []).append('--no-sandbox')
        try:
            browser = await p.chromium.launch(**_launch)
        except Exception as e:
            # 二进制缺失/启动失败(未 playwright install / 沙箱限制) → 优雅降级, 不炸扫描
            return _empty_result(False, f'浏览器启动失败: {str(e)[:120]}')
        try:
            # 注入会话: 浏览器上下文与 HTTP 通道**同认证态**(cookie+token+自定义头+login预热会话),
            #   否则自定义头鉴权 / 依赖 login 预热的站点, 运行时通道实为匿名, 登录后页面/接口漏抓。
            _sess = _session_headers(ctx)
            _ctx_kw = {
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                              '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'viewport': {'width': 1280, 'height': 720},
                'extra_http_headers': _sess,
            }
            # R4: 登录态采集结果(captured storage_state)注入浏览器上下文 ——
            #   浏览器通道与 HTTP 通道共用同一登录态。
            _st_state = getattr(ctx, 'captured_storage_state', None)
            if _st_state:
                _ctx_kw['storage_state'] = _st_state
            context = await browser.new_context(**_ctx_kw)
            page = await context.new_page()

            # 0. 只放行目标域名 + 逐请求节流 + 总数上限
            #    —— 兑现"仅访问目标域名"的承诺, 并把浏览器流量纳入统一限速。
            async def _route_handler(route):
                nonlocal browser_reqs
                req = route.request
                url = req.url
                _abort, _why = _browser_should_abort(req.method, url, base,
                                                     getattr(ctx, 'scope', None))
                if _abort:
                    # 第三方 → 一律不发; **非只读方法(POST/PUT/PATCH/DELETE) → 也不发**
                    #   (合规红线: 浏览器通道只发只读请求; 页面 JS 的写请求在此拦截 ——
                    #    它仍会被 handle_request 登记为"观测到的端点", 观测 ≠ 发送)。
                    # R5: 被拦的写方法请求**留证登记**(方法+URL+原因), 供报告如实披露
                    #   "观测到但未发送"; 交互模式的填表点击即由此拦截兜底(界面照点、包不发)。
                    if _why == 'non-readonly-method' and _is_same_domain(url, base):
                        _k = (str(req.method).upper(), str(url).split('?')[0])
                        if _k not in _wb_seen:
                            _wb_seen.add(_k)
                            write_blocked.append(
                                {'method': _k[0], 'url': _k[1], 'reason': '只读护栏拦截(未发送)'})
                    await route.abort()
                    return
                if browser_reqs >= max_reqs:
                    await route.abort()          # 超上限: 防跑飞
                    return
                browser_reqs += 1
                # 统一限速(铁律·分流面#19): 见 `_browser_throttle_wait` —— 优先 ctx.rm.reserve()
                #   (与 HTTP 主链路共享同一配额/熔断/自适应), rm 未就绪时退化为 local rate 节流。
                wait = _browser_throttle_wait(ctx, getattr(req, 'resource_type', ''))
                if wait > 0:
                    await asyncio.sleep(wait)
                await route.continue_()

            await page.route('**/*', _route_handler)

            # 1. 网络请求捕获（同步 handler）: 端点 + 参数(query/body/自定义头)
            #    —— 对齐 DevTools Network: 不只看到 URL, 还看到真实请求体与请求头。
            def handle_request(req):
                path = _endpoint_path(req.url)
                rtype = getattr(req, 'resource_type', '')
                if not _is_same_domain(req.url, base):
                    # 跨域请求: route 层已 abort(**不请求第三方**), 但 URL 在 request 事件里可见
                    #   → **登记**为外部端点(只登记不请求), 对齐 DevTools 的"看得到"。
                    #   实测真实 SPA 的业务 API 常在跨域主机(api.realworld.io / conduit.* 等),
                    #   不登记就会"什么都看不到"。
                    if rtype in ('xhr', 'fetch', 'document') and path:
                        _u = urlparse(req.url)
                        _host = _u.netloc.lower()
                        if not any(_host.endswith(d) for d in _EXTERNAL_DENY_HOSTS):
                            external_requests.add(_external_request_key(req.url))
                    return
                # 不再脱敏: 观测 URL 原样登记(本工具已移除全部脱敏)。
                intercepted_urls.add(req.url)
                # 同域 JS(含 SPA 路由懒加载 chunk; .js/.mjs)单独登记, 供 engine 追打分析(步骤3.5.2)。
                if urlparse(req.url).path.endswith(JS_EXTS):
                    runtime_js.add(req.url)
                if not path:
                    return
                if rtype in ('xhr', 'fetch'):
                    dynamic_apis.add(path)       # XHR/fetch 一律视为端点(DevTools 等价)
                else:
                    _ap = _extract_api_from_url(req.url)
                    if _ap:
                        dynamic_apis.add(_ap)
                # 参数: query + 请求体(只取名) + 取值形态(只记形态, 不存原值)
                params = set()
                shapes = {}                  # 参数名 -> set(取值形态)
                for k, v in parse_qsl(urlparse(req.url).query, keep_blank_values=True):
                    params.add(k)
                    shapes.setdefault(k, set()).add(_value_shape(v))
                try:
                    body = req.post_data
                except Exception:
                    body = None
                if body:
                    for k, sh in _body_param_shapes(
                            body, (req.headers or {}).get('content-type', '')).items():
                        params.add(k)
                        shapes.setdefault(k, set()).add(sh)
                # 自定义头(排除通用头) —— 只记名, 不记形态(头值多为凭据, 不推测)
                for h in (req.headers or {}):
                    hl = h.lower()
                    if hl in _HEADER_DENY:
                        continue
                    if hl.startswith('x-') or hl == 'authorization':
                        params.add(h)
                if params:
                    runtime_params.setdefault(path, set()).update(params)
                if shapes:
                    _dst = runtime_param_shapes.setdefault(path, {})
                    for _k, _ss in shapes.items():
                        _dst.setdefault(_k, set()).update(_ss)

            # 1b. 响应捕获: 状态码(供"端点是否可达/需鉴权"判断)
            def handle_response(resp):
                try:
                    if not _is_same_domain(resp.url, base):
                        return
                    path = _endpoint_path(resp.url)
                    if not path:
                        return
                    method = None
                    try:
                        method = resp.request.method
                    except Exception:
                        pass
                    runtime_responses.add((path, _resolve_response_method(method), int(resp.status)))
                except Exception:
                    pass

            def handle_websocket(ws):
                ws_endpoints.add(ws.url)

            def handle_console(msg):
                try:
                    txt = msg.text
                except Exception:
                    return
                if len(console_lines) < 200:
                    console_lines.append(txt)
                _extract_from_text(txt, dynamic_apis)

            page.on('request', handle_request)
            page.on('response', handle_response)
            page.on('websocket', handle_websocket)
            page.on('console', handle_console)

            # 2. 访问首页 —— **两段式导航**(见 `_goto_best_effort`): 必达 + 尽力, 繁忙 SPA 不再全丢
            try:
                await _goto_best_effort(page, base, timeout=30000, settle_ms=8000)
            except Exception as e:
                log(f'[-] Playwright goto 失败: {e}')
                # 半途失败: **保留已采集的部分数据**(请求/响应/跨域/参数/控制台等),
                #   不返回空 dict 丢失证据; 'ran'=False 如实告知上层"未跑完"。
                return _assemble_runtime_result(
                    dynamic_apis, intercepted_urls, runtime_js, ws_endpoints,
                    console_lines, runtime_params, runtime_param_shapes,
                    runtime_responses, external_requests, ran=False,
                    reason=f'goto 失败: {e}', write_blocked=write_blocked)

            # 3. 等待初始网络空闲
            await asyncio.sleep(1.5)

            # 4. 提取 window 全局对象中的 API 线索
            try:
                window_apis = await page.evaluate('''() => {
                    const apis = [];
                    if (window.__NEXT_DATA__) {
                        apis.push({src: '__NEXT_DATA__', data: JSON.stringify(window.__NEXT_DATA__).slice(0,2000)});
                    }
                    if (window.__NUXT__) {
                        apis.push({src: '__NUXT__', data: JSON.stringify(window.__NUXT__).slice(0,2000)});
                    }
                    if (window.__INITIAL_STATE__) {
                        apis.push({src: '__INITIAL_STATE__', data: JSON.stringify(window.__INITIAL_STATE__).slice(0,2000)});
                    }
                    const strs = [];
                    for (const k of Object.keys(window)) {
                        try {
                            const v = window[k];
                            if (typeof v === 'string' && (v.startsWith('/api/') || v.startsWith('/v1/'))) {
                                strs.push(v);
                            }
                        } catch(e) {}
                    }
                    return {apis, strs};
                }''')
                for item in window_apis.get('apis', []):
                    try:
                        import json
                        d = json.loads(item['data'])
                        # 复用 core 的同名实现(此前 runtime.py 里是一份行为不同的副本,
                        #   它收 '/' 开头的任意字符串, 会把 /home /about 等前端路由当 API)
                        _extract_paths_from_obj(d, dynamic_apis)
                    except Exception:
                        pass
                for s in window_apis.get('strs', []):
                    dynamic_apis.add(s)
            except Exception as e:
                log(f'[-] Playwright window 提取失败: {e}')

            # 5. 导航高价值入口路由(login / dashboard / admin / account …), 触发其**懒加载 chunk**。
            #    放在"点击页内链接"**之前**: 这些入口路由是**高价值目标**(接口常藏于此), 而浏览器
            #    通道有同域请求总数上限(默认 300)—— 若先做机会性点击, 高价值路由可能因预算耗尽被
            #    饿死。纯 client-routed SPA 的路由专属 .js 只在浏览器**导航**该路由时才被 import()
            #    动态加载(静态 GET /dashboard 仅返回 SPA shell); 这里显式 goto 让 route handler 把
            #    懒加载 .js 捕获进 runtime_js, 由 engine 步骤3.5.2 追打 deep_analyze。
            #    受 route_harvest / max_pages 约束; route handler 已做同源 abort + 逐请求限速 + 总数上限。
            #    纯只读 GET 导航, 不提交表单、不登录(除非 --cookie/--token 注入)。
            try:
                _rh = _cfg.get('route_harvest', True)
                _mp = int(_cfg.get('max_pages', 15) or 15)
                if _rh and _mp > 0:
                    # 非英文站点 → 用本地化入口猜测(与静态通道一致); 否则用英文清单。
                    _non_en = False
                    try:
                        _lang = (await page.evaluate('document.documentElement.lang || ""')) or ''
                        _non_en = bool(_lang) and not str(_lang).lower().startswith('en')
                    except Exception:
                        _non_en = False
                    _pool = ROUTE_ENTRY_GUESSES_I18N if _non_en else ROUTE_ENTRY_GUESSES
                    _nav = sorted(set(_pool))[:_mp]
                    _n_ok = 0
                    for _g in _nav:
                        try:
                            _ru = _join_url(base, _g)
                            # 同样两段式(短 settle): 必达 + 尽力, 单条路由卡住不再拖垮整轮
                            await _goto_best_effort(page, _ru, timeout=20000, settle_ms=3000)
                            await asyncio.sleep(1.0)
                            _n_ok += 1
                        except Exception:
                            continue
                    if _n_ok:
                        log(f'[*] 运行时入口路由导航: {_n_ok}/{len(_nav)} 个(捕获其懒加载 chunk)')
            except Exception:
                pass

            # 5b. 点击页面内**已存在**的站内链接, 机会性触发更多懒加载路由(在入口路由之后)。
            try:
                hrefs = await page.evaluate(
                    '() => Array.from(document.querySelectorAll("a[href]"))'
                    '.map(a => a.getAttribute("href")).slice(0, 40)')
                for href in hrefs:
                    if not _nav_href_allowed(href):
                        continue
                    try:
                        sel = f'a[href="{href}"]'
                        if await page.locator(sel).count() > 0:
                            await page.locator(sel).first.click(timeout=3000)
                            await asyncio.sleep(0.6)
                    except Exception:
                        continue
            except Exception:
                pass

            # 5c. R5 交互模式(opt-in, config interactive=true; 借鉴 JsOwl --aff 但**反转**:
            #     JsOwl 真实提交表单, 本工具只"填+点", 写请求由只读护栏 abort —— 界面照点、包不发)。
            #     目的: 发现"交互后才注册/懒加载"的动态端点与写接口(观测≠发送, 零写流量)。
            #     启动时 cli.py 已显著告警; 默认关闭。
            if _cfg.get('interactive'):
                try:
                    _max_i = int(_cfg.get('browser_max_interactions', 10) or 10)
                    log(f'[*] [interactive] 交互模式(opt-in): 填充表单+点击控件(≤{_max_i} 次); '
                        f'非只读请求一律被只读护栏拦截(只观测不发送)')
                    _n_fill = await page.evaluate(r'''() => {
                        let n = 0;
                        document.querySelectorAll('form').forEach(form => {
                            form.querySelectorAll('input, textarea, select').forEach(inp => {
                                const t = (inp.type || '').toLowerCase();
                                if (inp.disabled || inp.readOnly) return;
                                if (t === 'checkbox' || t === 'radio') { try { inp.click(); } catch(e){} return; }
                                if (t === 'submit' || t === 'button' || t === 'file' || t === 'image' || t === 'hidden') return;
                                let v = '1';
                                if (t === 'email') v = 'a@example.com';
                                else if (t === 'password') v = 'sighting-noop';   /* 绝不填真实口令; 且提交也会被只读护栏拦下 */
                                else if (/phone|tel|mobile/i.test(inp.name || '')) v = '13800000000';
                                else if (/url/i.test(inp.name || '')) v = 'http://example.com';
                                try {
                                    inp.value = v;
                                    inp.dispatchEvent(new Event('input', {bubbles: true}));
                                    inp.dispatchEvent(new Event('change', {bubbles: true}));
                                } catch(e) {}
                            });
                            n++;
                        });
                        return n;
                    }''')
                    if _n_fill:
                        log(f'[*] [interactive] 已填充 {_n_fill} 个表单(无害占位值, 非真实数据)')
                    _clicked = 0
                    _sel = ('form input[type=submit], form button[type=submit], '
                            'form button:not([type])')
                    try:
                        _locs = page.locator(_sel)
                        _n_btn = await _locs.count()
                        for _i in range(min(_n_btn, max(1, _max_i))):
                            try:
                                await _locs.nth(_i).click(timeout=3000)
                                _clicked += 1
                                await asyncio.sleep(0.8)
                            except Exception:
                                continue
                    except Exception:
                        pass
                    if _clicked:
                        log(f'[*] [interactive] 点击提交控件 {_clicked} 次'
                            f'(写请求已被只读护栏拦截, 观测≠发送; 见报告"运行时观测")')
                except Exception as e:
                    log(f'[-] [interactive] 交互模式异常(已跳过): {e}')

            # 6. 滚动页面触发懒加载（无限滚动场景）
            try:
                for _ in range(3):
                    await page.evaluate('window.scrollBy(0, 800)')
                    await asyncio.sleep(0.4)
            except Exception:
                pass

        finally:
            # **任何**退出路径都必须收尾(正常 / 异常 / 全局超时中断):
            #   旧实现只在「正常路径」与「goto 失败路径」关闭浏览器 —— 其余异常(含
            #   `ScanGlobalTimeout`)会让 Playwright 驱动子进程**泄漏**; 且 goto 失败路径
            #   提前 `return` 会跳过下面的发包结算, 使浏览器通道流量**少计**。
            try:
                await browser.close()
            except Exception:
                pass
            # 结算浏览器通道的发包数 —— 它同样是发给目标的流量, 必须计入总量
            try:
                ctx.ensure_rate_manager().count_only(ctx, n=browser_reqs)
            except Exception:
                pass

    out = _assemble_runtime_result(
        dynamic_apis, intercepted_urls, runtime_js, ws_endpoints,
        console_lines, runtime_params, runtime_param_shapes,
        runtime_responses, external_requests, ran=True, reason='',
        write_blocked=write_blocked)
    log(f'[*] Runtime 通道完成: 站内请求 {browser_reqs} 个(逐请求限速, 已计入总发包), '
        f'提取 {len(dynamic_apis)} API, {len(runtime_params)} 端点参数'
        f'({len(runtime_param_shapes)} 含取值形态), '
        f'{len(runtime_responses)} 响应状态, {len(external_requests)} 跨域端点(只登记), '
        f'{len(ws_endpoints)} WebSocket, {len(write_blocked)} 写请求被只读护栏拦截(观测≠发送)')
    return out

def runtime_recon(ctx, base):
    """同步包装：在事件循环中运行 Playwright 异步侦察

    Returns:
        dict: {'apis': set(), 'urls': set(), 'websockets': set(), 'console': list(),
               'params': {path: set(参数名)},
               'param_shapes': {path: {参数名: set(取值形态)}},
               'responses': {(path, method, status)}}
    """
    try:
        try:
            asyncio.get_running_loop()
            has_loop = True
        except RuntimeError:
            has_loop = False
        if has_loop:
            import concurrent.futures
            executor = concurrent.futures.ThreadPoolExecutor(1)
            try:
                future = executor.submit(asyncio.run, _runtime_recon_async(ctx, base))
                return future.result(timeout=180)
            except concurrent.futures.TimeoutError:
                # 180s 到点: with-block 退出时的 `shutdown(wait=True)` 会**阻塞到浏览器
                #   协程自然跑完** → 超时形同虚设(全库审计 M10)。改为不等待收尾:
                #   协程自身的 finally 仍会关浏览器并结算发包, 线程池随解释器退出回收;
                #   本次运行时数据如实披露为"不可用"。
                log('[i] Runtime 通道 180s 上限到点: 不再等待浏览器协程收尾'
                    '(浏览器由协程自身 finally 关闭), 本次运行时数据不可用')
                executor.shutdown(wait=False)
                return _empty_result(False, 'Runtime 通道 180s 超时(已放弃等待)')
            finally:
                # 正常完成路径关闭线程池(超时路径已在 except 里 wait=False 关过, 幂等)
                executor.shutdown(wait=False)
        return asyncio.run(_runtime_recon_async(ctx, base))
    except Exception as e:
        log(f'[-] Runtime 通道异常: {e}')
        return _empty_result(False, f'Runtime 通道异常: {e}')
