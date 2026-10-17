# -*- coding: utf-8 -*-
"""HTTP 请求 / 会话 / 限速 / SSRF 护栏 / 异步通道 —— 从 `core/engine.py` 拆出（便于维护）。"""
import asyncio
import hashlib
import ipaddress
import json
import socket
import time
import traceback
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlparse, urlsplit

import requests

from facet.core.log import log

from .const import _DIRECT_PROXIES, AIOHTTP, DEFAULT_UA
from .dicts import AUTH_HEADER_NAMES, READONLY_METHODS, get_js_priority, is_readonly_method, is_third_party
from .log import Color, clog

# 注: `RateManager` 已下沉到 core/rate.py(供 context/cli 直接引用, 打破循环依赖)。

# ---------- 只读方法护栏（合规红线: 观测≠发送） ----------
#   出站**默认只允许只读方法**; 非只读方法必须由调用点**显式**声明(语义只读的 POST, 如
#   GraphQL 内省 / gRPC reflection / 第三方密钥校验), 否则**拒发**。三通道(同步 `REQ` /
#   异步 `_aio_req` / 浏览器 `runtime._browser_should_abort`)统一此口径 —— 结构性硬保证。
#   集合本身定义在**数据层** `dicts.READONLY_METHODS`(单一真源), 浏览器通道同源引用,
#   不再各写一份同值元组。
_READONLY_METHODS = READONLY_METHODS

# ---------- 统一请求层 （限速 + 缓存 + 审计 + 熔断 + 双向敏感） ----------
def req_cache_key(method, url, headers=None, **kw):
    """请求缓存键: 纳入方法/URL/请求头/查询参数/请求体

    """
    body_parts = []
    for k in ('params', 'data', 'json'):
        v = kw.get(k)
        if v:
            try:
                body_parts.append(f'{k}={json.dumps(v, sort_keys=True, default=str)}')
            except Exception:
                body_parts.append(f'{k}={v!r}')
    raw = f"{method}:{url}:{json.dumps(headers or {}, sort_keys=True)}:{'&'.join(body_parts)}"
    return hashlib.md5(raw.encode('utf-8', 'ignore')).hexdigest()[:16]


def _proxies_dict(p):
    """把单个代理 URL 转成 requests 的 proxies 字典

    在 cli.py 里写 `C.S.proxies`, 但 core 从未定义模块级 S,
    导致 proxy 配置缺失直接 AttributeError 崩溃。现在代理统一从 config 读取。
    """
    if not p:
        return None
    return {'http': p, 'https': p}


def resolve_proxies(ctx, force_direct=False):
    """统一代理解析 

    旧行为: 未指定 proxy 配置时把 `proxies=None` 交给 requests。实测(requests 2.34.2)
    `requests.get(url, proxies=None)` 在环境存在 HTTP_PROXY 时会**静默走环境代理**:
    `Session.send` 会调用 `requests.utils.resolve_proxies(request, self.proxies,
    self.trust_env)`, 其中 `trust_env` 默认为 True, 于是环境代理被 `setdefault`
    注入最终代理表。

    后果: 运行环境里任何一条代理变量都会劫持全部扫描流量。实测沙箱内
    `HTTP_PROXY=http://127.0.0.1:58960` 时, 对 `127.0.0.1:18080` 的本地自建目标请求
    被代理转发并统一返回 502, facet 表现为"熔断、只发 5 个包、报告空白" ——
    使用者完全看不出是代理在作祟。

    更糟的是 `no_proxy=True`(语义是"本次请求绕过代理")原本也传的 None,
    等于**绕过代理反而启用了环境代理**, 语义完全反了。

    ⚠️ 关键实现细节(实测得出, 不要"优化"掉):
      `proxies={}` **不能**禁用环境代理 —— resolve_proxies 里是
      `new_proxies.setdefault(scheme, proxy)`, 空字典同样会被 setdefault 填上。
      唯一可靠的 sentinel 是**空字符串值**: `{'http': '', 'https': ''}` ——
      键已存在, setdefault 不再覆盖, 而 `select_proxy` 拿到空串后判定为假值,
      最终直连。已在本地自建目标上实测验证(proxies=None → ProxyError;
      proxies={'http':'','https':''} → 200)。

    新语义 —— 默认直连, 环境代理必须显式开启:
      · force_direct=True (请求级 no_proxy 开关) → 空串 sentinel, 强制绕过一切代理
      · 已配置 proxy                          → {http, https}
      · 未配置 + use_env_proxy=False (默认)     → 空串 sentinel, 显式禁用环境代理
      · 未配置 + use_env_proxy=True             → None, 交回 requests 读取环境变量
    """
    if force_direct:
        return dict(_DIRECT_PROXIES)
    p = ctx.config.get('proxy')
    if p:
        return _proxies_dict(p)
    if ctx.config.get('use_env_proxy'):
        return None
    return dict(_DIRECT_PROXIES)


def _host_of_url(u):
    """从 URL 提取主机名(小写), 用于 SSRF 重定向判定。"""
    try:
        return (urlparse(u or '').hostname or '').lower()
    except Exception:
        return ''


def _is_private_host(host):
    """SSRF 防护: host 是否落在内网/回环/链路本地/元数据地址段。

    IP 字面量直接判定; 域名解析后判定(解析失败视为不可判定, 不拦截, 交由连接失败处理)。
    判定覆盖 is_private / is_loopback / is_link_local / is_unspecified / is_reserved
    (is_private 在 Python 中已含 127/8、169.254/16、10/8、172.16/12、192.168/16 等)。
    """
    if not host:
        return False
    # 已知云元数据主机名(可能解析失败或直接落内网, 直接拦截)。
    if host in ('169.254.169.254', 'metadata.google.internal', 'metadata',
                'metadata.azure.com', 'metadata.goog'):
        return True
    try:
        _ip = ipaddress.ip_address(host)
    except ValueError:
        # 域名: 解析后逐个 IP 判定
        try:
            for _info in socket.getaddrinfo(host, None):
                _addr = _info[4][0]
                try:
                    _ip = ipaddress.ip_address(_addr)
                except ValueError:
                    continue
                if (_ip.is_private or _ip.is_loopback or _ip.is_link_local
                        or _ip.is_unspecified or _ip.is_reserved):
                    return True
        except Exception:
            return False
        return False
    return (_ip.is_private or _ip.is_loopback or _ip.is_link_local
            or _ip.is_unspecified or _ip.is_reserved)


def _redirect_pivots_private(orig_url, final_url):
    """重定向是否把请求**撬动**到内网/元数据地址(SSRF 防护)。

    仅在「发生重定向 且 终点主机 ≠ 原始主机 且 终点为内网/元数据」时判定为 pivot：
      · 公网目标被重定向到内网/元数据 → 拦截(云凭据/内网响应不得进入报告);
      · 内网目标同主机内路径跳转 → 放行(操作员本就在扫内网, 属预期);
      · 无重定向(终点==原始主机) → 放行。
    """
    if not final_url or not orig_url:
        return False
    _oh, _fh = _host_of_url(orig_url), _host_of_url(final_url)
    if not _oh or not _fh or _fh == _oh:
        return False
    return _is_private_host(_fh)


_RTT_MAX = 200          # 延迟样本保留条数（够算 P95，且内存有界）


def _eff_timeout(ctx, default=10.0):
    """本次请求的**生效超时**：优先取自适应值，否则取配置值。

    修一处真缺陷：`REQ` 原签名是 `timeout=10`（**字面量默认**），全项目只有
    `warm_up_session` 传了 `ctx.config['timeout']` —— 也就是说 `timeout` 配置**基本不生效**。
    现在默认 `None` → 落到这里解析（配置 → 再被自适应覆盖）。
    """
    v = getattr(ctx, '_eff_timeout', None)
    if v:
        return float(v)
    try:
        return float((getattr(ctx, 'config', None) or {}).get('timeout', default) or default)
    except (TypeError, ValueError):
        return default


def _record_rtt(ctx, dt):
    """记录一次成功响应耗时；样本足够时按**实测 P95** 刷新生效超时（自适应）。"""
    try:
        s = getattr(ctx, 'rtt_samples', None)
        if s is None:
            s = []
            ctx.rtt_samples = s
        s.append(round(float(dt), 4))
        if len(s) > _RTT_MAX:
            del s[:len(s) - _RTT_MAX]
        if len(s) < 12 or len(s) % 16:
            return
        from .adapt import effective_timeout, note, percentile
        cfg = getattr(ctx, 'config', None) or {}
        eff = effective_timeout(cfg, s)
        if not eff:
            return
        if abs(float(eff) - float(getattr(ctx, '_eff_timeout', 0) or 0)) > 1e-9:
            ctx._eff_timeout = eff
            note(ctx, 'timeout', cfg.get('timeout', 10), eff,
                 f'实测响应延迟 P95={percentile(s, 0.95):.2f}s（样本 {len(s)}）')
    except Exception:
        pass


def REQ(ctx, method, url, headers=None, timeout=None, no_session=False, **kw):
    """统一请求出口

    顺序(重要, 修正): 缓存去重 → 熔断 → 敏感URL告警 → 限速+计数 → 执行 → 审计 → 自适应调速

    旧实现顺序是"限速 → 缓存 → 熔断", 造成两个问题:
      · 缓存命中也要白等一个 rate 间隔 —— 缓存完全失去省时意义;
      · 缓存命中与熔断跳过都被 guard() 计入 total_sent —— 报告"总发包"虚高,
        审计日志与合规声明不符(声称的发包数并非实际发包数)。

    kw 支持两个控制参数(不参与缓存键):
      · stream=True  → 流式请求, 不读响应体、不缓存(用于 heapdump 等大体积端点)
      · no_proxy=True→ 本次请求不走代理(用于本机云元数据探测)

    变更(真实目标适用性):
      · **默认 User-Agent** — 此前完全不发 UA, requests 默认的 `python-requests/x.y.z`
        会被 Cloudflare / 阿里云WAF / 腾讯云WAF 按默认规则直接拦(实测 403, 零产出)。
      · **长驻 Session** — 此前用模块级 requests.request(), 每次新建 Session, 服务端
        下发的 Set-Cookie 立即丢弃 → 会话类站点只能看到第一页。
      · **全局时间预算** — 超预算即停止发起新请求, 避免 429 退避把扫描拖成"卡死"。
      · **关键请求重试** — 首页/JS 偶发超时不再导致整轮空报告。
      · **base 归一化** — 重定向后把最终 URL 的 scheme+host 作为规范 base, 省掉
        每个请求一次多余的 302 往返; 并按实际网络请求数计数。
    """
    # **只读方法护栏**(合规红线: 观测≠发送) —— 默认只允许 GET/HEAD/OPTIONS; 非只读方法须由
    #   调用点**显式**声明 `readonly_post=True`(语义只读的 POST: GraphQL 内省 / gRPC reflection /
    #   第三方密钥校验), 否则**拒发**(返回 None 并记审计)。与运行时通道同口径。
    _m = (method or 'GET').upper()
    if not is_readonly_method(_m) and not kw.pop('readonly_post', False):
        ctx.audit(_m, url, 'BLOCKED_WRITE', 0, 'readonly guard: 非只读方法未声明 readonly_post')
        log(f'[-] 只读护栏拦截: {_m} {url} (未声明 readonly_post)')
        return None
    # **声明范围护栏**(SRC 合规边界: 只在授权范围内活动)。越界请求硬拒并记审计
    #   BLOCKED_SCOPE。默认 scope = 目标同源(由 _scan_one_target 用 build_scope 装配),
    #   工具本就只生成同源 URL, 故越界基本不会发生; 显式 --scope 时严格按声明范围拦截(fail-closed)。
    if ctx is not None and getattr(ctx, 'scope', None) is not None and not ctx.scope.in_scope(url):
        ctx.scope_blocked = int(getattr(ctx, 'scope_blocked', 0) or 0) + 1
        ctx.audit(_m, url, 'BLOCKED_SCOPE', 0, 'scope guard: 目标不在声明范围内')
        log(f'[-] 范围拦截: {url} (不在声明范围内)')
        return None
    headers = _merge_headers(ctx, headers, no_session=no_session)
    if ctx.rm is None:                 # 防御性 —— 保证限速器一定存在
        ctx.ensure_rate_manager()
    stream = bool(kw.pop('stream', False))
    no_proxy = bool(kw.pop('no_proxy', False))
    retries = 0 if stream else int(ctx.config.get('retries', 1) or 0)
    h = req_cache_key(method, url, headers, **kw)

    # 0. 全局时间预算 —— 早于一切: 预算耗尽后不再发起任何新请求
    if ctx.budget_exhausted():
        return None

    # 1. 缓存去重  — 必须早于限速: 命中缓存不应付出 rate 间隔
    if not stream:
        cached = ctx.cache_get(h)
        if cached is not None:
            return cached

    # 2. 熔断检查 — 早于限速: 熔断期间不占用限速名额、不计入发包数
    #    新实现支持半开自动恢复: 冷却后放行有限探活, 探活成功即自愈, 不再永久跳过。
    _cskip, _cevt = ctx.circuit_gate()
    if _cskip:
        if _cevt == 'tripped':
            clog('[CIRCUIT]', '熔断触发(OPEN): 连续失败达阈值 → 进入冷却; 冷却后自动半开探活恢复', Color.BG_RED)
        else:  # cooling: 冷却期节流提示, 避免每条跳过都刷屏
            _now = time.monotonic()
            if _now - ctx._circuit_cool_log_t >= 5.0:
                ctx._circuit_cool_log_t = _now
                log('[CIRCUIT] 熔断冷却中, 请求暂缓(半开探活恢复后将自动恢复)')
        return None
    if _cevt == 'recovering':
        # 半开探活放行(本请求即探活); 成功则自动关闭熔断
        if not ctx._circuit_halfopen_announced:
            ctx._circuit_halfopen_announced = True
            log('[CIRCUIT] 进入半开探活: 放行有限探活请求以确认目标恢复')

    # 3. 双向敏感检测 —— 已**移出本函数**。
    #   正确做法是只在**目标来源的路径**上查一次 —— 见 js_deep_recon 里对 all_apis 的检查。

    # 4/5. 限速 + 计数 + 执行(含重试)
    r = None
    if timeout is None:
        timeout = _eff_timeout(ctx)      # 配置值 → 已被实测延迟自适应覆盖
    proxies = resolve_proxies(ctx, force_direct=no_proxy)
    session = ctx.ensure_session(_global_headers(ctx)) if not stream else None
    _t0 = time.monotonic()
    attempt = 0
    while True:
        if ctx.budget_exhausted():
            break
        # 4. 限速 + 计数(申请到名额即计数, 与实际发包一致)
        ctx.rm.guard(ctx)
        try:
            # TLS 校验默认关闭(侦察目标多为自签/内网证书), 但可经 `tls_verify: true`
            #   或 FACET_TLS_VERIFY=1 打开 —— 旧实现硬编码 False 且无任何披露。
            _verify = bool((ctx.config or {}).get('tls_verify', False))
            if stream:
                r = requests.request(method, url, headers=headers, timeout=timeout,
                                     verify=_verify, allow_redirects=True,
                                     proxies=proxies, stream=True, **kw)
            else:
                r = session.request(method, url, headers=headers, timeout=timeout,
                                    verify=_verify, allow_redirects=True,
                                    proxies=proxies, **kw)
            # 实际网络请求数 = 1 + 重定向跳数(工具自报的"总发包"此前漏算重定向)
            ctx.count_net(1 + len(getattr(r, 'history', None) or []))
            _record_rtt(ctx, time.monotonic() - _t0)      # 实测延迟样本 → 超时自适应
            break
        except requests.exceptions.Timeout:
            ctx.count_net(1)
            if attempt < retries:
                attempt += 1
                # 超时重试必须**放大超时预算**。真实站点偶发慢响应有两种:
                #   · 抖动型(偶尔慢) —— 原样重试即可;
                #   · 持续型(首页就是 13s, 而 timeout 是 10s) —— 原样重试只会再超时一次,
                #   这里按 ×2 递增并封顶 60s, 两种情况都能覆盖。
                timeout = min(max(timeout * 2, timeout + 5), 60)
                log(f'[!] 请求超时, 放大超时至 {timeout}s 后重试: {url}')
                continue
            ctx.rm.adapt(0, is_timeout=True)
            ctx.record_fail()
            ctx.audit(method, url, 'TIMEOUT', 0, 'timeout')
            return None
        except requests.exceptions.ConnectionError as _e:
            ctx.count_net(1)
            if attempt < retries:
                attempt += 1
                continue
            ctx.rm.adapt(0, is_timeout=True)
            ctx.record_fail()
            ctx.audit(method, url, 'CONNERR', 0, f'connection error: {_e}')
            return None
        except Exception as e:
            ctx.record_fail()
            ctx.audit(method, url, 'ERROR', 0, str(e)[:120])
            if ctx.config.get('debug'):
                traceback.print_exc()
            return None

    if r is None:
        return None

    # 6.5 SSRF 防护: 公网目标被重定向到内网/元数据地址时, 拒绝摄入响应
    #    (云元数据/内网管理面的凭据或响应不得进入报告)。仅拦截跨主机的私网 pivot,
    #    内网目标同主机内路径跳转仍放行(操作员本就在扫内网)。
    #    注: requests/aiohttp 默认跟随重定向, 此处为响应摄入前的最后一道闸 —— 请求可能已
    #    发出, 但响应体绝不被采集/缓存/写入报告, 故无凭据/内网数据外泄。
    _final = str(getattr(r, 'url', '') or '')
    if _redirect_pivots_private(url, _final):
        clog('[SSRF]', f'拒绝摄入重定向到内网/元数据地址的响应: {_final}', Color.BG_RED)
        ctx.audit(method, url, 'SSRF_BLOCK', 0, f'redirect pivots to private: {_final}')
        return None

    # 6. 熔断与自适应调速 —— 统一走 _settle_response(), 与异步通道共用同一语义
    if r is not None:
        cacheable = _settle_response(ctx, r)
        # 7. 审计日志(stream 模式绝不触碰响应体, 否则会触发全量下载)
        size = 0
        if not stream:
            try:
                size = len(r.content) if r.content else 0
            except Exception:
                size = 0
        ctx.audit(method, url, r.status_code, size)
        # 8. 缓存(stream 模式不缓存: 响应体未读取, 缓存无意义且会误导后续命中)
        # **不缓存瞬态错误响应**(429 / 5xx)。
        #   缓存的本意是"同一 URL 不重复抓" —— 对稳定的 2xx/3xx/404 成立, 但对
        #   429 恰恰相反: 429 的语义就是"稍后再来", 缓存它 300 秒等于把"稍后"变成
        #   "5 分钟内别来"。更糟的是**缓存命中不会计入 fail_count**, 于是
        #   "反复 429 → 熔断"这条链路对**同一个 URL** 会被静默短路 ——
        #   行为测试(第 33 组)正是这样发现它的: 连发 6 次同一 URL 的 429,
        #   fail_count 始终停在 1, 熔断永远不触发。
        #   现在瞬态错误一律不缓存, 保证熔断计数如实反映"目标在拒绝服务"。
        # 该判定收敛进 _settle_response() 的返回值, 异步通道同样适用。
        if not stream and cacheable:
            ctx.cache_set(h, r)
    return r


def _retry_after_of(r):
    """解析 429/503 的 Retry-After 响应头(秒); 无或非法返回 None"""
    try:
        v = (getattr(r, 'headers', None) or {}).get('Retry-After')
        if not v:
            return None
        v = str(v).strip()
        if v.isdigit():
            return int(v)
        return None
    except Exception:
        return None


def _is_transient_status(status):
    """瞬态错误(429 / 5xx): 语义是"稍后再来", 不应缓存"""
    try:
        st = int(status or 0)
    except (TypeError, ValueError):
        return False
    return st == 429 or 500 <= st < 600


def _settle_response(ctx, r):
    """响应结算 —— **同步与异步两条通道共用的唯一实现**

    。此前"429 计入熔断 + 瞬态错误不缓存 + 收到 429/5xx 降速"
    这三条语义只写在同步 `REQ()` 里; 而 `_fetch_js()` 在 **JS 文件数 > 4** 时会走
    异步 `_aio_fetch_batch()` —— 那是同一语义的**兄弟路径**, 却没有同步修改:
      · 429 不计入 fail_count(仅 >=500 计), 且对 429 调 `reset_fail()` **主动清零**
        → "连续 429 → 熔断"在异步路径上永不触发;
      · 429/5xx 被无条件 `cache_set` → 缓存命中短路失败计数;
      · 从不调用 `rm.adapt()` → 目标说"慢点"工具却继续按原速打。
    受控小样例每个仅 ~2 个 JS 文件, 全部走同步路径, 因此结构性地测不到。

    现在两条通道都调用本函数, 语义不可能再分叉。

    旧实现(同步 REQ 内联):
        if r.status_code >= 500 or r.status_code == 0: ctx.record_fail()
        elif r.status_code == 429:                     ctx.record_fail()
        else:                                          ctx.reset_fail()
        ctx.rm.adapt(r.status_code, retry_after=...)
        _transient = (r.status_code == 429 or 500 <= r.status_code < 600)
    旧实现(异步 _aio_fetch_batch 内联):
        if r.status_code >= 500: ctx.record_fail()
        else:                    ctx.reset_fail()      # ← 429 走这里, 主动清零
        ctx.cache_set(key, r)                          # ← 无条件缓存

    Returns:
        bool: 该响应是否**可缓存**(瞬态错误返回 False)
    """
    st = getattr(r, 'status_code', 0) or 0
    if st == 501:
        # 501 Not Implemented = 服务器不支持该方法 —— 是**成功的否定回答**
        # (目标健康, 只是没实现该方法), 不是目标侧故障。计入熔断会让扫描器
        # **自己**的 OPTIONS/POST 探测把健康目标打进冷却: 实测连续 5 个 OPTIONS
        # 501 → 熔断 OPEN → 60 个后续请求被跳过, 隐藏字典整段丢失 —— 覆盖损失
        # 由探测设计自身造成, 与目标健康无关。(对比: 429 必须计入 —— 那是目标
        # 在限流, "明确放弃"远好于静默爬行; 其余 5xx 是目标侧故障。)
        ctx.reset_fail()
    elif st >= 500 or st == 0:
        ctx.record_fail()
    elif st == 429:
        # 429 必须计入熔断计数 —— 否则目标持续限流时扫描会以
        #   RATE_MAX=60s/请求 的速度无限爬下去, 使用者只看到"卡死"。
        #   "明确放弃"远好于"静默爬行"。
        ctx.record_fail()
    else:
        ctx.reset_fail()
    ctx.rm.adapt(st, retry_after=(
        _retry_after_of(r) if ctx.config.get('respect_retry_after', True) else None))
    return not _is_transient_status(st)


def _global_headers(ctx):
    """构造全局请求头(UA / Cookie / 自定义头 / Bearer Token), 结果缓存在 ctx 上

    这些头注入到**所有**请求 —— 此前只有 probe/hidden/idor/sqli 带 token,
    recon 阶段的首页与 JS 抓取不带, 于是需要认证的目标在 recon 阶段就看不到内容。
    """
    cached = getattr(ctx, '_global_headers', None)
    if cached is not None:
        return cached
    cfg = ctx.config
    h = {'User-Agent': cfg.get('ua') or DEFAULT_UA}
    cookie = cfg.get('cookie')
    if cookie:
        h['Cookie'] = str(cookie).strip()
    token = cfg.get('token')
    if token:
        h['Authorization'] = f'Bearer {token}'
    # 自定义头: 支持 "K: V" 字符串或列表(header 配置可重复)
    raw = cfg.get('header')
    if raw:
        items = raw if isinstance(raw, (list, tuple)) else [raw]
        for item in items:
            if not item:
                continue
            if ':' in str(item):
                k, _, v = str(item).partition(':')
                k, v = k.strip(), v.strip()
                if k:
                    h[k] = v
    ctx._global_headers = h
    return h


def _merge_headers(ctx, headers, no_session=False):
    """全局头 + 调用点专属头(后者优先)

    调用点显式传入的同名头必须能覆盖全局值 —— 例如 WAF 探测需要用它自己的
    自我标识 UA, 不能被默认浏览器 UA 盖掉。
    no_session=True 时剔除 Cookie / Authorization, 用于"匿名视图"对比(访问矩阵)。
    """
    g = dict(_global_headers(ctx))
    if no_session:
        # 剔除**所有**承载会话的头(单一事实来源 dicts.AUTH_HEADER_NAMES), 而非仅
        #   Cookie/Authorization —— 否则用自定义鉴权头(如 `X-Access-Token`)时, "匿名半边"
        #   仍带 token → 匿名 vs 认证差分**失真**(实测目标即用 X-Access-Token 鉴权)。
        for _k in [k for k in g if str(k).lower() in AUTH_HEADER_NAMES]:
            g.pop(_k, None)
    if headers:
        g.update(headers)
    return g


def _session_cookie_header(ctx):
    """把长驻 requests.Session 的 cookie 拼成 Cookie 头, 供**异步通道**使用

    。此前只修了同步路径的 cookie 持久化, 漏了异步路径:
    `_aio_fetch_batch()` 每次调用都新建一个 `aiohttp.ClientSession`, 它**不共享**
    requests.Session 的 cookie jar。于是 `login` 配置预热拿到的会话在 JS 抓取阶段丢失 ——

    注意: 只有 JS 文件数 > 4 时才走异步通道(`_fetch_js` 的分支条件),
    所以小站点上这个缺陷不会显现 —— 这也是它容易被漏掉的原因。
    """
    s = getattr(ctx, 'session', None)
    if s is None:
        return None
    try:
        items = [f'{c.name}={c.value}' for c in s.cookies]
    except Exception:
        return None
    return '; '.join(items) if items else None


def _absorb_cookies(ctx, raw_set_cookie):
    """把异步响应里的 Set-Cookie 回灌进长驻 Session

    与 `_session_cookie_header()` 配对, 让两条通道的会话**双向收敛**:
    异步通道拿到的会话 cookie 也能被后续同步请求使用。
    """
    s = getattr(ctx, 'session', None)
    if s is None or not raw_set_cookie:
        return
    for raw in raw_set_cookie:
        try:
            jar = SimpleCookie()
            jar.load(raw)
            for name, morsel in jar.items():
                s.cookies.set(name, morsel.value)
        except Exception:
            continue


def warm_up_session(ctx, base, timeout=None):
    """会话预热: 先访问 login 配置指定的 URL 以建立会话(cookie)

    真实场景里很多系统要"先访问一次入口页"才会下发会话 cookie。
    只发 GET, 不做任何登录提交 —— 保持只读定位。
    """
    login_url = ctx.config.get('login')
    if not login_url:
        return None
    url = login_url if str(login_url).startswith('http') else urljoin(base, str(login_url))
    log(f'[*] 会话预热: GET {url}')
    return REQ(ctx, 'GET', url, timeout=timeout or _eff_timeout(ctx))


def normalize_base(ctx, base, resp):
    """重定向后归一化 base

    真实站点常把 裸域 → www、http → https 做 301/302。若始终用原始 base,
    后续每个请求都要先吃一次 302, 流量翻倍(实测服务端 148 次 vs 自报 74 次)。
    这里取最终响应的 scheme+host, 并**保留原 base 的路径前缀** —— 目标部署在
    子路径下(如 `/app/`)时, 丢掉路径会让所有后续 URL 全部指错位置。
    """
    try:
        final = getattr(resp, 'url', None)
        if not final:
            return base
        fu, bu = urlsplit(final), urlsplit(base)
        if (fu.scheme, fu.netloc) and (fu.scheme, fu.netloc) != (bu.scheme, bu.netloc):
            prefix = bu.path.rstrip('/')
            nb = f'{fu.scheme}://{fu.netloc}{prefix}/'
            log(f'[*] base 归一化: {base} → {nb} (跟随重定向)')
            return nb
    except Exception:
        pass
    return base


# ---------- 异步请求层 （aiohttp 并发 + 限速护栏接入） ----------
class _AioResp:
    """轻量响应对象, 模拟 requests.Response 的最小接口"""
    # 增加 set_cookie —— 异步通道需要把 Set-Cookie 回灌长驻 Session。
    #   注意 __slots__ 必须同步声明, 否则赋值直接 AttributeError(会被外层
    #   `except Exception: return None` 吞掉, 表现为"异步通道整体不可用")。
    __slots__ = ('status_code', 'text', 'content', 'headers', 'set_cookie', 'url')

    def __init__(self):
        self.status_code = 0
        self.text = ''
        self.content = b''
        self.headers = {}
        self.set_cookie = []
        self.url = ''       # 最终 URL(跟随重定向后) —— 供"重定向后同源校验"使用


class _AsyncRateGate:
    """异步限速闸门

    的异步批量抓取直接调用 session.request(),
    完全绕过 REQ 的限速/缓存/审计/熔断/计数。

    闸门不再自持 _last/_window, 改为委托 RateManager.reserve(),
    与同步路径共享同一限速状态。旧实现两套状态并存, 且闸门在每次
    _aio_fetch_batch 调用时新建 → 跨调用零限速、RPM 硬顶被绕过。
    """

    def __init__(self, rm):
        self.rm = rm

    async def acquire(self):
        wait = self.rm.reserve()
        if wait > 0:
            await asyncio.sleep(wait)


async def _aio_req(ctx, session, method, url, headers=None, timeout=10, proxy=None, readonly_post=False):
    """aiohttp 异步请求(用于批量并发) —— 与同步 `REQ` **共用同一只读护栏口径**

    `ssl=False` 显式关闭证书校验 —— 渗透测试目标大量使用自签
    证书/内部 CA, 校验失败会把可达目标误判为不可达。同步路径的 requests 早已
    `verify=False`, 此处补齐一致性(并抑制 InsecureRequestWarning 噪声)。

    只读护栏(合规红线"观测≠发送"): 非只读方法须调用点**显式**声明 `readonly_post=True`
    (语义只读的 POST), 否则**拒发**并记审计 `BLOCKED_WRITE` —— 与 `REQ` 同口径,
    弥补此前"异步通道裸丢弃非只读、无例外/无审计"的口径分叉(铁律 #9 三通道统一)。
    本通道仅用于 JS GET 抓取, 非只读分支生产不可达, 但护栏语义必须与 REQ 一致。
    """
    _m = (method or 'GET').upper()
    if not is_readonly_method(_m) and not readonly_post:
        if ctx is not None:
            ctx.audit(_m, url, 'BLOCKED_WRITE', 0,
                      'readonly guard: 异步通道非只读方法未声明 readonly_post')
        return None
    # 声明范围护栏(SRC 合规边界): 越界请求硬拒并记审计 BLOCKED_SCOPE(与 REQ 同口径)。
    if ctx is not None and getattr(ctx, 'scope', None) is not None and not ctx.scope.in_scope(url):
        if hasattr(ctx, 'scope_blocked'):
            ctx.scope_blocked = int(getattr(ctx, 'scope_blocked', 0) or 0) + 1
        if ctx.audit is not None:
            ctx.audit(_m, url, 'BLOCKED_SCOPE', 0,
                      'scope guard: 目标不在声明范围内(异步通道)')
        return None
    try:
        # AIOHTTP 为可选依赖(async extra), 未装时生产路径不会到达此处(调用方
        #   `_aio_fetch_batch` 已 `if not AIOHTTP: return {}` 降级同步); 此处对
        #   ClientTimeout 做空安全构造, 既避免可选依赖缺失时崩溃, 也让只读护栏的
        #   异步回归测试(用 mock session)在无 aiohttp 环境下仍可运行。
        _aio_timeout = AIOHTTP.ClientTimeout(total=timeout) if AIOHTTP else None
        async with session.request(_m, url, headers=headers, ssl=False,
                                    proxy=proxy,
                                    timeout=_aio_timeout) as resp:
            text = await resp.text()
            r = _AioResp()
            r.status_code = resp.status
            r.text = text
            r.content = text.encode('utf-8', 'ignore')
            r.headers = dict(resp.headers)
            r.url = str(getattr(resp, 'url', '') or '')
            # 保留全部 Set-Cookie。`dict(resp.headers)` 会把
            #   同名头折叠成一个, 服务端一次下发多个 cookie 时会丢。
            try:
                r.set_cookie = resp.headers.getall('Set-Cookie', [])
            except Exception:
                r.set_cookie = []
            return r
    except Exception:
        return None


async def _aio_fetch_batch(ctx, urls, headers=None, max_concurrent=8, timeout=10):
    """异步批量抓取: 限速闸门 + 并发上限 + 缓存/计数/审计/熔断 全接入

    Args:
        ctx: ScanContext(提供 rm / cache / audit / 熔断计数)
    """
    if not AIOHTTP:
        return {}
    if ctx.rm is None:
        ctx.ensure_rate_manager()
    # 闸门现在是无状态的(限速状态在 ctx.rm 内), 因此每次调用新建也安全。
    gate = _AsyncRateGate(ctx.rm)
    sem = asyncio.Semaphore(max(1, max_concurrent))
    results = {}
    # 异步路径的代理解析与同步路径对齐 ——
    #   显式 proxy 配置优先; 否则默认直连; 仅 use_env_proxy=True 时才读环境变量。
    proxy = ctx.config.get('proxy') or None
    trust_env = bool(ctx.config.get('use_env_proxy')) and not proxy
    # 全局请求头(UA/Cookie/自定义头/Token)同样注入异步路径 ——
    #   否则 JS 批量抓取会以 python-requests UA 发出, 与同步路径行为不一致。
    headers = _merge_headers(ctx, headers)
    # 异步通道的 aiohttp.ClientSession 是**每次新建**的,
    #   它不共享 requests.Session 的 cookie jar。若只注入全局头, `login` 配置预热
    #   得到的会话在 JS 抓取阶段就丢了(实测 6 个 JS 全 401 → 接口 0)。
    #   这里把长驻 Session 的 cookie 快照注入, 让两条通道的会话一致。
    if 'Cookie' not in headers:
        _sc = _session_cookie_header(ctx)
        if _sc:
            headers['Cookie'] = _sc

    async def one(session, u):
        # 全局时间预算
        if ctx.budget_exhausted():
            return None
        # 熔断检查
        if ctx.check_circuit(5):
            return None
        # 缓存去重
        key = req_cache_key('GET', u, headers)
        cached = ctx.cache_get(key)
        if cached is not None:
            return cached
        async with sem:
            await gate.acquire()
            r = await _aio_req(ctx, session, 'GET', u, headers=headers, timeout=timeout, proxy=proxy)
        # SSRF 防护: 跨主机重定向到内网/元数据时拒绝摄入(主动拦截)。
        #   注意: 此处 r=None 是"请求已发出但响应被拒摄入", 属**设计性拦截**而非
        #   目标侧失败 —— 与同步 REQ() 同口径, **不计入熔断器失败计数**(否则一次
        #   内网 pivot 拦截即误触发熔断), 仅记审计、照常累计发包数(审计 D4 修复)。
        _ssrf_blocked = False
        if r is not None and _redirect_pivots_private(u, getattr(r, 'url', '') or ''):
            ctx.audit('GET', u, 'SSRF_BLOCK', 0,
                      f'redirect pivots to private: {getattr(r, "url", "")}')
            r = None
            _ssrf_blocked = True
        # 计数 + 审计 + 熔断反馈
        ctx.rm.count_only(ctx)
        ctx.count_net(1)
        if r is None:
            # 仅对**真实发包失败**(超时/连接错误等)计入熔断; 设计性拦截(SSRF/预算/
            # 取消)不计入, 避免误熔断 —— 与同步路径的失败计数语义对齐。
            if not _ssrf_blocked:
                ctx.record_fail()
                ctx.audit('GET', u, 'ERROR', 0, 'async request failed')
        else:
            # 熔断计数 / 自适应调速 / 瞬态错误判定统一走
            #   _settle_response() —— 与同步 REQ() 共用同一实现。
            cacheable = _settle_response(ctx, r)
            # 异步响应里的 Set-Cookie 回灌长驻 Session,
            #   使两条通道的会话双向收敛(而非只有 Session → aiohttp 单向)。
            _absorb_cookies(ctx, getattr(r, 'set_cookie', None))
            ctx.audit('GET', u, r.status_code, len(r.content) if r.content else 0)
            # 瞬态错误(429/5xx)不缓存 —— 否则缓存命中会短路失败计数
            if cacheable:
                ctx.cache_set(key, r)
        return r

    # 连接器同样关闭 SSL 校验, 与 _aio_req 的 ssl=False 保持一致。
    connector = AIOHTTP.TCPConnector(limit=max_concurrent, ssl=False)
    async with AIOHTTP.ClientSession(connector=connector, headers=headers or {},
                                     trust_env=trust_env) as session:
        tasks = {u: asyncio.create_task(one(session, u)) for u in urls}
        for u, t in tasks.items():
            try:
                results[u] = await t
            except Exception:
                results[u] = None
    return results


def aio_fetch_sync(ctx, urls, headers=None, max_concurrent=8, timeout=10):
    """同步包装器: 在已有事件循环中运行, 无事件循环则新建"""
    if not AIOHTTP:
        return {}
    try:
        asyncio.get_running_loop()
        # 已有事件循环时, 用线程池包装
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(1) as ex:
            return ex.submit(asyncio.run, _aio_fetch_batch(ctx, urls, headers, max_concurrent, timeout)).result()
    except RuntimeError:
        return asyncio.run(_aio_fetch_batch(ctx, urls, headers, max_concurrent, timeout))


# ---------- JS 抓取 （异步并发 + 统一限速） ----------
def _fetch_js(ctx, urls, headers=None):
    """异步批量JS抓取, 统一限速 + 分级排序"""
    from .js_extract import _same_origin
    if not urls:
        return []
    # 分级排序: entry(0) > chunk(1) > vendor(2), 第三方产物压到最低
    urls = sorted(set(urls), key=lambda u: (get_js_priority(u), is_third_party(u), len(u)))
    from .config import effective_max_js
    max_js = effective_max_js(ctx.config, len(urls))   # 自适应(硬顶 max_js_hard_cap)
    if max_js > 0 and len(urls) > max_js:
        # 截断前先剔除第三方产物, 把预算留给业务代码
        business = [u for u in urls if not is_third_party(u)]
        third = [u for u in urls if is_third_party(u)]
        merged = business + third
        if len(merged) > max_js:
            log(f'[!] JS 队列按优先级截断: 保留 {max_js}/{len(merged)} '
                f'(业务 {min(len(business), max_js)}, 第三方 {max(0, max_js - len(business))})')
            # **必须登记进 ctx.truncated** —— 否则报告里看不到"JS 被截断",
            #   使用者会把"只扫了 80 个 JS"误当成"目标就这些 JS"。
            #   修复 chunk 枚举后这点尤其重要: 一个 runtime 就能枚举出上百个 chunk,
            #   默认上限 80 会静默吃掉一半接口面。
            ctx.note_truncated('js', len(merged) - max_js)
        urls = merged[:max_js]

    # 重定向后同源校验: 请求前已按同源过滤候选 URL, 但目标可能把自己的 JS **302 跳到第三方**
    #   (requests/aiohttp 默认跟随重定向) —— 若照单全收会**抓取并分析第三方内容**, 与
    #   "跨域 JS 只登记不抓取"的合规定位相悖。此处丢弃跨域重定向结果。
    _base = getattr(ctx, 'base', '') or ''
    results = []
    if AIOHTTP and len(urls) > 4:
        # 异步批量: 吞吐↑3~5倍
        # 限速/缓存/审计/熔断/计数 已通过 _AsyncRateGate 接入, 不再裸发
        max_c = min(ctx.config.get('threads', 8), 16)
        aio_results = aio_fetch_sync(ctx, urls, headers=headers, max_concurrent=max_c,
                                     timeout=_eff_timeout(ctx))   # 与同步路径同一超时口径
        # 不再对每个失败 URL 逐个同步重发 —— 后果:
        #     · 熔断触发时 _aio_fetch_batch 对所有 URL 返回 None →
        #       整个批次被同步重发一遍, 熔断形同虚设且流量翻倍;
        #     · 404 的 JS 也会被无意义地再请求一次。
        # 原 `if not aio_results:` 分支**不可达** ——
        #   `_aio_fetch_batch` 对每个 URL 都写入结果(失败写 None), 返回值恒非空,
        #   因此"异步通道不可用 → 降级同步"永远不会执行, 是一个误导性的死分支。
        #   真正的"异步不可用"(AIOHTTP 缺失)已由上面的 `if AIOHTTP and ...` 直接排除。
        #   现在改为: 本批全部失败时**只告警、不重发**(重发会绕过熔断并让流量翻倍),
        #   并如实说明"是目标在拒绝服务", 而不是伪装成"降级成功"。
        if aio_results and all(v is None for v in aio_results.values()):
            log('[!] 异步通道本批全部失败(熔断/网络/限流): 不重发, 避免绕过熔断与流量翻倍')
        for u, resp in (aio_results or {}).items():
            if resp is not None and resp.status_code == 200:
                _final = getattr(resp, 'url', '') or u
                if _base and not _same_origin(_final, _base):
                    log(f'[!] JS 跨域重定向, 丢弃(不抓第三方): {u} -> {_final}')
                    continue
                results.append((u, resp.text))
    else:
        # 少量或缺少aiohttp时走同步(经REQ统一限速)
        for u in urls:
            r = REQ(ctx, 'GET', u, headers=headers)
            if r is not None and r.status_code == 200:
                _final = getattr(r, 'url', '') or u
                if _base and not _same_origin(_final, _base):
                    log(f'[!] JS 跨域重定向, 丢弃(不抓第三方): {u} -> {_final}')
                    continue
                results.append((u, r.text))
    return results
