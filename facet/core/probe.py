# -*- coding: utf-8 -*-
"""探活 / 指纹门控探测 / catch-all 判定 / 隐藏路径 —— 从 `core/engine.py` 拆出（便于维护）。"""
import hashlib
import json
import os
import re
import sys
import time
import traceback
from urllib.parse import urljoin, urlparse, urlsplit

from ..recon.baseline import get_baseline_profile, get_confirm_overrides
from ..recon.fingerprint import (
    FP_RULES,
    ROUTE_RULES,
    fingerprint_from_js,
    fingerprint_target,
    get_enabled_rules,
    load_external_fingerprint_db,
    merge_fingerprints,
    merge_route,
)
from ..recon.stack import extract_backend_stack
from .const import (
    _ALLOW_METHODS,
    _LOGIN_PATH_RE,
    _RE_MINE_ABS,
    _RE_MINE_PATH,
    _REGIME_MAX,
    DEFAULT_UA,
    plugins,
)
from .dicts import (
    AUTH_PUBLIC_KW,
    CANARY_SEEDS,
    HIDDEN_PATHS_COMMON,
    MGMT_HIGH_RISK_KW,
    TRAILING_SLASH_PATHS,
    extract_query_params,
    get_hidden_paths,
    get_probe_specs,
    is_api_doc_path,
    is_content_diff_path,
    load_external_hidden_paths,
    normalize_extracted_path,
    normalize_path,
    score_api_priority,
    surface_segments,
    with_default_query,
)
from .log import Color, clog, dbg, log


def _canary_paths(base, mode, n=3):
    """生成 catch-all 基线用的 canary 路径(可测试单元)。

    不同 catchall_mode 采用不同采样策略:
      · WAF_BLOCK —— 多发(>=6)且专门挑"易被拦"的路径(带常见攻击/敏感特征: 注入点、
        /admin、/.env、/wp-login.php、<script> 等)。目的: 让基线真正抓到"拦截页"
        长什么样 —— 否则单 canary 可能恰好返回正常 404(很多 WAF 只拦带特征路径),
        真实拦截端点反而被当成暴露接口。
      · 其它模式 —— 沿用旧实现的纯随机路径(多路径聚合已能识别 SPA index / CMS 404 /
        API JSON 404, 无需特殊路径)。

    Returns:
        list[str]: 绝对路径列表(不含 base)
    """
    if mode == 'WAF_BLOCK':
        # 易被 WAF / 防护拦截的特征路径(仅用于"确认不存在路径的响应形态", 不探测真实资产)。
        # 注意: **绝不混入干净路径**(如空串) —— 否则首个 canary 是干净路径, 基线参考响应
        #   (r0) 会抓到 404 而非拦截页, 真实被拦端点(403 拦截页)反而因状态码不匹配被判成
        #   "隐藏接口暴露"。WAF 只拦带特征路径的场景下, 这条干净 canary 直接让 WAF_BLOCK
        #   失效。故种子全部为攻击特征路径。
        # 仅用**敏感路径特征**(不含攻击 payload 串) —— 与"只读、不打 payload"的对外表述一致。
        #   旧实现含 `?id=1%27`(SQLi 特征)、`/<script>`(XSS 特征)、`/etc/passwd`(LFI 特征)、
        #   `/api/../admin`(穿越特征), 虽只发往**随机不存在路径**, 仍属"发送攻击特征串" → 移除。
        seeds = list(CANARY_SEEDS)                  # 数据层(dicts.CANARY_SEEDS)
        n = max(n, len(seeds))            # 覆盖全部特征种子, 基线采样更稳
        paths = []
        for i in range(n):
            seg = seeds[i % len(seeds)]
            rand = hashlib.md5(
                f'facet-wafcanary-{base}-{time.time()}-{i}'.encode('utf-8', 'ignore')
            ).hexdigest()[:16]
            paths.append(f'/{rand}{seg}')
        return paths
    # 默认: 纯随机路径(保证不存在)
    return ['/' + hashlib.md5(
        f'facet-canary-{base}-{time.time()}-{i}'.encode('utf-8', 'ignore')
    ).hexdigest()[:24] for i in range(n)]


def _establish_catchall_baseline(ctx, base, profile=None, regime='/'):
    """发送若干保证不存在的随机路径, 建立 catch-all / soft-404 基线

    相比 用"主页响应指纹"作基线, 本方式能正确识别:
      · 网关 / CDN 对任意路径返回 200 + 自定义 404 页
      · SPA 对任意路径返回同一份 index.html
      · WAF 对任意路径返回统一拦截页
    这些场景下"主页指纹"都不匹配, 会被 误报为"隐藏接口暴露"。

    改为探测 **多个** 随机路径并做跨路径聚合(`detect_soft404_signature`)——
    单点 canary 只能给出"一个不存在路径的响应"用于逐响应比对(`_is_catchall`), 而
    多路径聚合能兜住"canary 恰好 404、但大量随机路径返回同款 200 页面"的漏判。

    **第十九轮后新增**: 接受 `profile.catchall_mode`, 据此调整 canary 采样策略
    (见 `_canary_paths`)。当前仅 WAF_BLOCK 改变采样(多发+易被拦路径), 其余模式
    沿用旧逻辑; 模式同时记入返回的基线 dict, 供报告/下游使用。

    Returns:
        dict | None: {'status', 'fp', 'len', 'head', 'signature', 'multi_path_catchall',
                      'n_canaries', 'catchall_mode'}
    """
    from .guard import _fingerprint_resp, detect_soft404_signature
    from .http import REQ
    # profile 可能是 BaselineProfile 对象(生产)或 dict(测试) —— 兼容两者
    if profile is None:
        mode = None
    elif isinstance(profile, dict):
        mode = profile.get('catchall_mode')
    else:
        mode = getattr(profile, 'catchall_mode', None)
    canary_n = 6 if mode == 'WAF_BLOCK' else 3
    responses = []
    r0 = None
    for canary in _canary_paths(base, mode, canary_n):
        # 形态族: regime != '/' 时, canary 发在该前缀下(如 /api/<rand>) —— 真实站点常
        #   按路径前缀分形态(/api/* 走 JSON、其余走 HTML), 必须分族建基线才能正确判 catch-all。
        _p = canary if regime == '/' else (regime.rstrip('/') + canary)
        r = REQ(ctx, 'GET', urljoin(base, _p), timeout=8)
        if r is None:
            continue
        if r0 is None:
            r0 = r
        responses.append({'path': canary, 'status': r.status_code,
                          'body_fp': _fingerprint_resp(r), 'title': '',
                          'body': (r.text or ''),   # 供 simhash 近重复判定
                          # 重定向形态(跟随重定向后 history 非空): 用于自动归类 REDIRECT_LOGIN
                          'redirected': bool(getattr(r, 'history', None)),
                          'final_url': getattr(r, 'url', '') or '',
                          'redirect_status': (r.history[-1].status_code
                                             if getattr(r, 'history', None) else None)})
    if r0 is None:
        return None
    sig = detect_soft404_signature(responses)
    # 自动分类 catch-all 形态: 仅当指纹未给出门控模式(mode=None)时补全语义,
    # 不覆盖 WAF_BLOCK/SPA_INDEX 等指纹门控模式。
    # 判定: catch-all 成立 且 所有 canary 都经 3xx 重定向 且 落到同一最终 URL
    #   → 典型的"任意路径跳登录页"形态, 归为 REDIRECT_LOGIN。
    effective_mode = mode
    if effective_mode is None and sig['is_catchall']:
        _redirected = [x for x in responses if x.get('redirected')]
        if _redirected and len(_redirected) == len(responses):
            _finals = {x['final_url'] for x in _redirected}
            if len(_finals) == 1:
                effective_mode = 'REDIRECT_LOGIN'
    txt = r0.text or ''
    _rtag = '' if regime == '/' else f' [形态族 {regime}]'
    log(f'[*] catch-all 基线(mode={effective_mode}){_rtag}: {responses[0]["path"]} → HTTP {r0.status_code}, {len(txt)}B'
        f' (多路径聚合 catch-all={sig["is_catchall"]}, n={len(responses)})')
    return {'status': r0.status_code, 'fp': _fingerprint_resp(r0),
            'len': len(txt), 'head': txt[:200],
            'signature': sig.get('signature'),
            'multi_path_catchall': sig['is_catchall'],
            'near_dup': sig.get('near_dup', False),
            'n_canaries': len(responses),
            'catchall_mode': effective_mode}


def _is_reportable_endpoint(path, status):
    """一个响应是否算"探活确认"里的**可报告端点**（口径见 docs/report-policy.md）。

    不该当端点报的:
      · 404/410            —— 路径**不存在**;
      · 403 且**文件型**路径(.env/.htaccess/composer.json…) —— 服务器常对整类文件统一拒绝,
        是**安全加固**而非暴露(只聚合报一条 INFO), 不该进端点清单。
    """
    if status in (404, 410):
        return False
    if status == 403 and is_content_diff_path(path):
        return False
    return True


def _looks_login_redirect(r):
    """响应是否为"重定向到登录页"。

    是 → 该路径**存在但受保护**, 不能报成"隐藏接口暴露"。实测 demo.testfire.net 的 /admin
    302 跳 /login.jsp(登录页), 旧实现跟随后见 200 即报 HIGH"隐藏接口暴露" → 过度断言。
    """
    if r is None:
        return False
    hist = getattr(r, 'history', None) or []
    if not hist:
        return False
    try:
        fin = urlsplit(getattr(r, 'url', '') or '').path or ''
    except Exception:
        return False
    return bool(_LOGIN_PATH_RE.search(fin))


def _looks_login_page(r):
    """响应体是否像**登录页**（服务端**直接返回**、无重定向）。

    实测真实站点 wptest.io：`/admin`、`/admin/`、`/wp-admin/` 均**直接返回**
    WordPress 登录页（200，同一 7136B 页面），无重定向 → 旧实现只认"重定向到登录页"
    (`_looks_login_redirect`)，于是把它们误报成 **HIGH「隐藏接口暴露」**（过度断言）。
    这里补**内容判据**：命中登录表单标记即视为"存在但受保护"。
    """
    if r is None:
        return False
    t = (getattr(r, 'text', '') or '')[:20000].lower()
    if not t:
        return False
    if any(k in t for k in ('id="loginform"', "id='loginform'", 'user_login',
                            'name="log"', "name='log'", 'name="pwd"', 'wp-login')):
        return True
    # 通用：含密码输入框 + 登录字样
    if 'type="password"' in t and ('sign in' in t or 'log in' in t or 'login' in t):
        return True
    return False


def _match_catchall_baseline(r, bl, fpfn):
    """响应是否与**某条** canary 基线一致(伪命中)。返回 `(bool, 依据)`。纯判定, 便于单测。"""
    if not bl or r is None or r.status_code != bl['status']:
        return False, ''
    txt = r.text or ''
    # 判定 1: 指纹与 canary 响应完全一致
    if fpfn(r) == bl['fp']:
        return True, f'与不存在路径响应一致(canary HTTP {bl["status"]})'
    # 判定 2: 长度差 <5% 且首部一致 → soft-404
    bl_len = max(bl['len'], 1)
    len_ratio = abs(len(txt) - bl['len']) / bl_len
    if len_ratio < 0.05 and txt[:120] == bl['head'][:120]:
        return True, f'与不存在路径响应高度相似(长度差 {len_ratio * 100:.1f}%)'
    return False, ''


def _is_catchall(ctx, r):
    """判定响应是否为 catch-all 伪命中(与 canary 基线比对)

    比对**两条**基线: ① 同**形态族**基线(`/api/*` 等按前缀分族); ② **根**基线。
    根基线兜底是必要的 —— 实测 SPA/catch-all 站对任意路径回**首页**(200 HTML),
    而 `/api/*` 形态族 canary 可能回**另一响应**(如 405), 只比族基线会漏判, 导致
    通用猜测路径(如 `/api/admin/config`)被误标 `EXISTS_PROTECTED`。

    Returns:
        (bool, str): (是否伪命中, 判定依据说明)
    """
    from .guard import _fingerprint_resp, _regime_of
    if r is None:
        return False, ''
    _reg = _regime_of(getattr(r, 'url', '') or '')
    # 非根形态族: 先比族基线, 再兜底比根基线; 根形态族: 只比根基线(去重)。
    _regimes = [_reg] if _reg == '/' else [_reg, '/']
    for _rg in _regimes:
        # 确保基线存在(被动打点阶段尚未探活时也能判定; 幂等, 已建则直接返回)。
        bl = _ensure_catchall_baseline(ctx, getattr(ctx, 'base', None), _rg)
        _hit, _why = _match_catchall_baseline(r, bl, _fingerprint_resp)
        if _hit:
            return True, _why
    return False, ''


def _ensure_catchall_baseline(ctx, base=None, regime='/'):
    """惰性建立 catch-all 基线

    · regime == '/'  → 根基线(整扫描一次, 存 ctx._catchall_baseline)
    · regime != '/'  → 该**形态族**基线(惰性、按族缓存、总数有上限, 存 ctx._catchall_baselines)
    """
    if not ctx.config.get('catchall_baseline', True):
        return None
    base = base or getattr(ctx, 'base', None)
    if not base:
        return None
    if getattr(ctx, '_catchall_base', None) != base:
        # 目标切换 → 旧基线作废
        ctx._catchall_base = base
        ctx._catchall_baseline = None
        ctx._catchall_tried = False
        ctx._catchall_baselines = {}
    if regime == '/':
        if ctx._catchall_baseline is not None:
            return ctx._catchall_baseline
        if ctx._catchall_tried:
            return None          # 已尝试且失败(canary 请求不可达), 不再重试
        ctx._catchall_tried = True
        ctx._catchall_baseline = _establish_catchall_baseline(
            ctx, base, getattr(ctx, 'baseline_profile', None))
        return ctx._catchall_baseline
    # 非根形态族: 先确保根基线(根都建不成 → 不额外发请求), 再按族惰性建
    if _ensure_catchall_baseline(ctx, base, '/') is None:
        return None
    store = getattr(ctx, '_catchall_baselines', None)
    if store is None:
        store = {}
        ctx._catchall_baselines = store
    if regime in store:
        return store[regime]
    if len(store) >= _REGIME_MAX:
        return None              # 超过上限: 该族退回"无基线"(不误判)
    store[regime] = _establish_catchall_baseline(ctx, base, None, regime=regime)
    return store[regime]


def _probe_req(ctx, url, method='GET', headers=None, no_session=False, **kw):
    """探测专用请求封装: 命中 catch-all 伪命中时返回 None

    被排除的路径记入 excluded(附录 A), 不计入严重度统计, 但保留判定依据供人工复核。
    """
    from .http import REQ
    r = REQ(ctx, method, url, headers=headers, no_session=no_session, **kw)
    if r is None:
        return None
    _ensure_catchall_baseline(ctx)      # 直接调用探测函数时也能拿到基线
    hit, why = _is_catchall(ctx, r)
    if hit:
        # 只有 200 类响应才值得记入附录 A。
        #   `_is_catchall` 返回 True 的语义是「响应与一个**保证不存在**的随机路径一致」——
        #   即该路径不存在, 属于"判定 0: 静默跳过", 而不是"疑似命中被抑制"。
        if 200 <= r.status_code < 300:
            ctx.add_excluded(urlparse(url).path or url, r.status_code,
                             f'伪命中(catch-all): {why}')
        return None
    return r


def _mine_urls_from_resp(r, base):
    """从响应**正文与响应头**挖掘**同源**候选路径(方案 2-B)。

    响应头: `Location` / `Link` / `Content-Security-Policy`(report-uri/connect-src/form-action)。
    正文: 仅当 Content-Type 为 json/html/text/xml/js 时挖"路径样"字面量与绝对 URL。
    **只挖不发请求**; 是否回灌由调用方决定(闭环见 `probe` 内的追加逻辑)。
    """
    from urllib.parse import urlsplit
    try:
        host = urlsplit(base).netloc
    except Exception:
        return set()
    found = set()

    def _add(u):
        if not u:
            return
        try:
            sp = urlsplit(urljoin(base, u))
        except Exception:
            return
        if sp.netloc and sp.netloc != host:
            return                                  # 只挖同源
        _p = normalize_extracted_path(sp.path + (('?' + sp.query) if sp.query else ''))
        if _p:
            found.add(_p)

    try:
        for _h in ('Location', 'Link', 'Content-Security-Policy'):
            _v = r.headers.get(_h)
            if _v:
                for _m in re.findall(r'https?://[^\s;,>"\']+', _v):
                    _add(_m)
                for _m in re.findall(r'/[A-Za-z0-9_\-./]{2,120}', _v):
                    _add(_m)
    except Exception:
        pass
    try:
        _ct = (r.headers.get('Content-Type') or '').lower()
        if any(_k in _ct for _k in ('json', 'html', 'text', 'xml', 'javascript')):
            _body = (r.text or '')[:200000]
            for _m in _RE_MINE_ABS.findall(_body):
                _add(_m)
            for _m in _RE_MINE_PATH.findall(_body):
                _add(_m)
    except Exception:
        pass
    return found


def _stage_cap(ctx, key, share, default):
    """阶段条目上限 —— 由**剩余时间预算 ÷ 实测单请求耗时 × share** 派生（`adapt` 统一口径）。

    取代"各阶段各自写死一个数字"（`max_probe=400` / `options_probe_max=60` /
    `resp_mine_max=100`）：那些数字在小站是空转、在大站又不够，且彼此无配比关系。
    配置值作**下限**（显式调大即尊重；`0`=不限，自适应不得覆盖）；信号不足 → 用配置值。
    """
    cfg = getattr(ctx, 'config', None) or {}
    try:
        from .adapt import effective_stage_cap, note, percentile
        _rtts = getattr(ctx, 'rtt_samples', None) or []
        _cost = percentile(_rtts, 0.5)          # 用中位耗时：均值会被尾部拖偏
        try:
            _rem = ctx.budget_left()
        except Exception:
            _rem = None
        _v = effective_stage_cap(cfg, key, _rem, _cost, share, hard_default=default)
        note(ctx, key, cfg.get(key, default), _v,
             f'剩余预算 {int(_rem) if _rem else "?"}s ÷ 实测中位耗时 '
             f'{round(_cost, 2) if _cost else "?"}s × {share}')
        return _v
    except Exception:
        try:
            return int(cfg.get(key, default) or 0)
        except (TypeError, ValueError):
            return default


def options_probe(ctx, base, apis, token=None):
    """**OPTIONS / `Allow` 方法发现**(方案 2-B): 只读 OPTIONS, 拿**目标自己声明**支持的方法。

    与"JS 声明方法"**互补且分区**: JS 给"前端怎么调", OPTIONS 给"服务端允许什么"。
    只发 OPTIONS(只读), **绝不发写方法**; 结果写 `ctx.options_methods`(path → 方法列表)。
    失败/无 Allow 头一律跳过(不做任何推断)。
    """
    from .http import REQ
    if not plugins.enabled('prober', 'options', ctx.config):
        return {}
    H = {'Authorization': f'Bearer {token}'} if token else {}
    # 上限由**剩余时间预算 × 实测单请求耗时**派生（配置值为下限）—— 小站不再空转、大站不再不够。
    cap = _stage_cap(ctx, 'options_probe_max', 0.05, 60)
    out = {}
    _n = 0
    for p in apis:
        if cap and _n >= cap:
            break
        if not p or ctx.is_invalid(p):
            continue
        try:
            r = REQ(ctx, 'OPTIONS', urljoin(base, p), headers=H)
        except Exception:
            continue
        _n += 1
        if r is None:
            continue
        _allow = ''
        try:
            _allow = r.headers.get('Allow') or r.headers.get('allow') or ''
        except Exception:
            _allow = ''
        _meths = sorted({m.strip().upper() for m in _allow.split(',')
                         if m.strip().upper() in _ALLOW_METHODS})
        if _meths:
            out[p.split('?')[0]] = _meths
    ctx.options_methods = out
    if out:
        log(f'[+] 方法发现(OPTIONS): {len(out)} 条路由返回 Allow 头(目标自述支持的方法)')
    return out


def probe(ctx, base, apis, token=None, no_cap=False, hard_cap=0):
    """批量探活: 统一限速 + TTL缓存 + 响应聚类去重

    变更:
      · 调用方传入的 apis 现在**包含 JS 声明的写操作路径** —— 它们只以
        GET/HEAD 验证可达性, 绝不发出写请求(合规红线不变)。旧实现把 `write_apis`
        排除在探活集合之外, 导致 `axios.get('/user/profile')` 这类接口提取到了
        却从不验证, 且"是否探活"取决于路径是否恰好以 `/api/` 开头。
      · 接入 `score_api_priority` / `expand_restful_v45` /
        `with_default_query` / `normalize_path` —— 这四个函数此前定义了但
        全项目从未调用, 现分别用于探活排序、占位符展开、语义 query 补全、URL 去重。
    """
    from .guard import _ct_cat, _fingerprint_resp, _looks_unauth
    from .js_extract import classify, expand_restful_v45
    from .secret import has_sensitive_v45, scan_response_secrets
    H = {'Authorization': f'Bearer {token}'} if token else {}
    checked = set()

    # --- RESTful 占位符展开 + 语义 query 补全 + URL 规范化去重 ---
    expanded = []
    seen_norm = set()
    for raw in apis:
        # 1) 展开 `:id` / `*id` / `{id}` 占位符(语义值优先)
        for v in expand_restful_v45(raw):
            # 2) 若该路径已关联参数且自身无 query, 补一组语义默认值
            params = ctx.pmap.get(v.split('?')[0]) or set()
            params = {p for p in params if p}
            cands = with_default_query(v, params) if params else [v]
            for c in cands:
                # 3) URL 规范化(去尾斜杠 / query 排序)后去重
                nk = normalize_path(c)
                if nk in seen_norm:
                    continue
                seen_norm.add(nk)
                expanded.append(c)

    # 优先管理面 + 高安全面评分（此前 score_api_priority 从未被调用）
    #   + 证据/来源分层: 复用 orchestrator 已算好的 `out['evidence']`(经 `ctx.evidence` 传入数值档),
    #     使 运行时观测/AST 还原 等高证据端点排在 启发式候选(route-rebase=0 / 字典)之前 ——
    #     预算或 max_probe 截断时, 先保已验证端点。同分同档内再按管理面/无效路径排。
    _evid = getattr(ctx, 'evidence', None) or {}
    score_api = sorted(expanded,
                       key=lambda p: (score_api_priority(p),
                                      _evid.get(p, 1),
                                      classify(p) == '管理运维面',
                                      ctx.is_invalid(p)),
                       reverse=True)

    # 探活条数上限。sitemap/字典/JS 提取三者叠加时, apis 规模可能
    #   远超预期; 无上限则流量与耗时都不可控。按优先级排序后再截断, 保证被砍掉的
    #   是低价值路径。截断事实写入报告, 不静默丢弃。
    limit = _stage_cap(ctx, 'max_probe', 0.35, 400)
    # no_cap=True: **提取到的接口**默认不按 max_probe 截断(用户: 所有提取接口必探活一次);
    #   但仍受 `hard_cap` 硬顶保护 —— 巨型 JS / 超大 sitemap 可能提取出上千条路径, 无上限
    #   会突破流量/时间控制(仅靠 max_duration 预算兜底, 中途不提前收尾)。hard_cap>0 时作为
    #   硬顶, 超出按 `probe_extracted` 登记截断; 默认 max_probe_extracted=2000, 常规目标远低于
    #   此值、不会被误截断; hard_cap=0 = 显式不限(审计 D1 修复)。
    _cap = limit
    _reason = 'probe'
    if no_cap:
        try:
            _hc = int(hard_cap or 0)
        except (TypeError, ValueError):
            _hc = 0
        _cap = _hc                     # no_cap 路径: 上限=hard_cap(0 表示不限)
        _reason = 'probe_extracted'
    if _cap > 0 and len(score_api) > _cap:
        dropped = len(score_api) - _cap
        ctx.note_truncated(_reason, dropped)
        log(f'[!] 探活截断({_reason}): 丢弃 {dropped} 条低优先级路径 (上限 {_cap})')
        score_api = score_api[:_cap]

    # 响应挖掘(方案 2-B) + 闭环回灌(方案 4.9): 从响应体/响应头挖出的**同源**新路径,
    #   去重后**追加到待办** —— Python 列表迭代会取到新追加项, 天然形成 BFS;
    #   受 `resp_mine_max` 上限 + 统一限速/预算约束(不会跑飞)。
    _mined = set()
    _mine_cap = _stage_cap(ctx, 'resp_mine_max', 0.05, 100)
    # probe() 在一次扫描中会被调用**多次**(提取面 no_cap + 补充面) —— 挖掘结果必须**跨调用累积**,
    #   否则后一次调用会覆盖前一次(`ctx.mined_paths = set(_mined)`)造成数据丢失;
    #   上限按**全局总数**(已累计 + 本次新增)判定, 与 `resp_mine_max`("每目标采纳上限")语义一致。
    _prev_mined = set(getattr(ctx, 'mined_paths', None) or ())

    for p in score_api:
        if p in checked or ctx.is_invalid(p):
            continue
        checked.add(p)
        url = urljoin(base, p)
        # 旧代码用裸 URL 查缓存, 而 REQ 以 md5(method:url:headers[:body]) 为键,
        #            键空间不匹配 → 此处恒 miss(死代码)。REQ 内部已做 TTL 缓存, 直接调用即可。
        # 改用 _probe_req —— catch-all 站点上不再把全部提取路径误记为"接口存在"。
        r = _probe_req(ctx, url, headers=H)
        if r is None:
            continue
        st = r.status_code
        # 路径**确认不存在**(404/410) → 记入 ctx.invalid, 供后续相位(options_probe / hidden_probe /
        #   再次 probe)跳过, 避免对同一不存在路径重复探测(此前 ctx.invalid 无生产者, 守卫恒空转)。
        if st in (404, 410):
            ctx.mark_invalid(p)
        # 响应体/响应头 URL 挖掘 → 回灌待办(闭环)
        if plugins.enabled('collector', 'mine', ctx.config) and (
                not _mine_cap or (len(_prev_mined) + len(_mined)) < _mine_cap):
            try:
                for _np in _mine_urls_from_resp(r, base):
                    if _np in checked or _np in _mined:
                        continue
                    _nk2 = normalize_path(_np)
                    if _nk2 in seen_norm:
                        continue
                    seen_norm.add(_nk2)
                    _mined.add(_np)
                    score_api.append(_np)
                    if _mine_cap and (len(_prev_mined) + len(_mined)) >= _mine_cap:
                        break
            except Exception:
                pass
        # "登录页 / 重定向到登录" 的 200 = **受保护(需登录)**, 不是"匿名可达"。
        #   **一处判定, 两处复用**(端点登记 + finding), 避免口径分叉 —— 旧实现只在端点登记处判,
        #   finding 仍对登录页报"管理接口可达"(与业务码未授权同理: 它其实要求登录)。
        _loginish = bool(st == 200 and (_looks_login_redirect(r) or _looks_login_page(r)))
        # 业务码未授权(需登录) 与登录页同属"受保护" —— 都必须**不带 len=**(见下方端点登记分支),
        # 否则 build_recon_matrix 的 broken_access_hint(疑似未授权访问启发式, 3.5) 会把"需登录"
        #   误判为"匿名可达返回实质内容"(HIGH「疑似未授权访问」), 与下方 MED「鉴权接口存在」自相矛盾。
        _unauth = bool(st == 200 and _looks_unauth(r.text))
        # 404/410(不存在) 与 文件型 403(安全加固) **不计入"探活确认"** —— 否则不存在的路径 /
        #   服务器拒绝的敏感文件会进端点清单, 再被风险矩阵/假设段当 P0 线索 → 误报。
        if _is_reportable_endpoint(p, st):
            # 需登录的路径（登录页）只记为"受保护(需登录)"，**不带 len=** —— 否则会被
            #   未授权访问启发式当成"匿名 200 有实质内容"而误报「疑似未授权访问」
            #   （语义：需登录 = 信息，**无需登录可达才是未授权**）。
            if _loginish:
                ctx.add_all_found(p, 'GET', st, '受保护(需登录)')
            elif _unauth:
                ctx.add_all_found(p, 'GET', st, '受保护(业务码未授权·需登录)')
            else:
                # 附响应类型短类别(ct=html/json/…) —— 供报告区分"页面型 vs 数据型"候选(降噪),
                #   如文档站的 `/api/xxx.html`(HTML 页面)不再与真实数据接口混为一谈。
                _ctc = ''
                try:
                    _ctc = _ct_cat(r.headers.get('Content-Type'))
                except Exception as e:
                    dbg(f'探活 Content-Type 读取 {p}: {e}')
                ctx.add_all_found(p, 'GET', st,
                                  f'len={len(r.text)}' + (f' ct={_ctc}' if _ctc else ''))
        # 改为只登记**真实存在**的参数名(来自 URL query),
        #         没有 query 就不登记 —— 空参数名对 idor/sqli 无任何意义。
        path_only = p.split('?')[0]
        if path_only:
            for pn in extract_query_params(p):
                if pn:
                    ctx.link_param(path_only, pn)
        if st == 200:
            fp = _fingerprint_resp(r)
            # 聚类去重: 若已有同指纹响应, 减少重复记录
            fps = getattr(ctx, '_resp_fingerprints', None)
            if fps is None:
                fps = ctx._resp_fingerprints = set()
            if fp not in fps:
                fps.add(fp)
                # 业务码未授权已在上方(端点登记处)统一判定并标记"受保护"; 此处复用 _unauth:
                #   这类响应体**不是目标的真实内容**, 不该拿去做内容/密钥扫描(避免对"请先登录"
                #   体扫描出误报机密); 仅作 MED「鉴权接口存在」分类(fp 去重保证只报一次)。
                if _unauth:
                    ctx.add_finding('MED', '鉴权接口存在', url, 'HTTP 200 + 业务码未授权')
                else:
                    # API 描述文档(OpenAPI/Swagger/JSON-Schema): 跳过 PII 字段扫描 ——
                    #   文档里的 email/password 多为联系人/字段示例, 属结构性误报
                    #   (实测 Petstore /v2/swagger.json 被误判)。结构化机密仍照扫。
                    if not is_api_doc_path(p):
                        res = has_sensitive_v45(r.text)
                        if res:
                            cats = '|'.join(sorted({d['category'] for d in res}))
                            snips = '; '.join(d['snippet'] for d in res[:6])
                            ctx.add_finding('HIGH', f'敏感信息响应({p})', url,
                                            f'[{cats}] 脱敏片段: {snips}')
                    # 再用完整密钥正则库扫一遍响应体 —— 关键词匹配只能发现
                    #   字段名, 发现不了 `mysql://user:pw@host/db`、云 AK、JWT 这类
                    #   结构化机密。两侧共用同一套规则与过滤器, 判定口径一致。
                    scan_response_secrets(ctx, url, r.text)
                    if '/admin' in p or 'manage' in p:
                        # 登录页 200 **其实要求登录** → 不报"可达"(与业务码未授权同理),
                        #   改报"存在(需登录·受保护)", 避免把受保护管理面误述为匿名可达。
                        if _loginish:
                            ctx.add_finding('MED', '管理接口存在(需登录·受保护)', url,
                                            '200 OK(登录页)')
                        else:
                            ctx.add_finding('MED', '管理接口可达', url, '200 OK')
                    # 认证/登录类端点可达。**公开认证入口(login/logout/signup/reset/token/
                    #   oauth/sso…含 /login.aspx 等带扩展名形态)返回 200 属正常**(登录页本就该
                    #   匿名可达), **不报** —— 只报"非公开入口"的 auth 路径, 避免正常登录/注销页
                    #   刷屏(用户反馈的误报); 需认证账户面匿名可达由「访问矩阵/疑似越权」按更高
                    #   严重度表达。
                    if ('login' in p or 'auth' in p) and not (surface_segments(p) & AUTH_PUBLIC_KW):
                        ctx.add_finding('INFO', '认证端点', url, '200 OK')
        elif st in (401, 403):
            ctx.add_finding('MED', '鉴权接口存在', url, f'HTTP {st}')
        elif st == 500:
            ctx.add_finding('INFO', '服务端异常', url, 'HTTP 500')

        # 写操作接口: 只提取信息, 零发包
        write_method = ctx.write_apis.get(p)
        if write_method and write_method != 'GET':
            ctx.add_finding('INFO', f'写操作接口({write_method})', url, 'JS声明提取,零发包')

    # 响应挖掘结果(方案 2-B) —— 记录供报告按来源单列。
    #   跨调用**累积**(不覆盖前一次); 日志只报**本次真正新增**的条数, 避免多次调用重复刷屏。
    _new = _mined - _prev_mined
    ctx.mined_paths = _prev_mined | _mined
    if _new:
        log(f'[+] 响应挖掘: 从响应体/响应头回灌 {len(_new)} 条同源新路径(闭环)')


# ---------- 指纹库加载 (支持外部化) ----------
def _load_fingerprints(config):
    """加载指纹库: 内置 + 外部JSON合并"""
    rules = list(FP_RULES)
    ext_path = config.get('fingerprint_db')
    if ext_path and os.path.exists(ext_path):
        try:
            ext = load_external_fingerprint_db(ext_path)
            rules = merge_fingerprints(rules, ext)
            log(f'[+] 已加载外部指纹库: {ext_path} ({len(ext)} 条)')
        except Exception as e:
            log(f'[-] 外部指纹库加载失败: {e}')
    return rules


# 注: 原 `_stack_known_paths_probe`(基于 `FP_BASELINES.probe_targets` 的硬编码栈路径探测)
#   已**移除** —— 它与**数据驱动**的 `hidden_probe`(指纹门控 + `HIDDEN_PATHS_BY_STACK`)
#   功能重叠、且路径来源是重复的硬编码列表。栈专属路径统一由 `hidden_probe` 处理。


# ---------- 框架条件化探测 (核心Bug修复) ----------
def _build_probe_map(ctx, hits):
    """按指纹命中列表构建条件化探测表

    重构: 从 detect_and_probe 中拆出, 使 JS 分析阶段补判出的指纹
    也能走同一套门控逻辑(见 probe_new_fingerprints)。

    原则: 指纹是「门禁」而非「加分项」—— 未命中对应技术栈的探测一律 pass。
    """
    cfg = ctx.config
    probe_map = {}

    # **数据驱动装配**: "哪个环境该探什么、由哪个指纹触发" 声明在 `dicts.PROBE_SPECS`,
    #   此处只做装配 —— 不再在代码里逐个 `if 'X' in hits:`(新增栈只需加一条数据)。
    #   原则: 指纹是「门禁」而非「加分项」—— 未命中对应技术栈的探测一律 pass。
    for _name, _spec in get_probe_specs(cfg).items():
        _trig = _spec.get('triggers')
        if _trig is None:
            # 无条件探测(common): 受 config 开关约束
            if _name == 'common' and not cfg.get('common_probe', True):
                continue
        else:
            if not any(h in hits for h in _trig):
                continue
            if _name == 'waf' and not cfg.get('waf_probe', True):
                continue
        # 有专用函数用它; 无函数 → **通用探测**(纯数据环境, 加数据即生效)。
        _fname = _spec.get('func')
        # 字符串间接派发改为**同模块显式解析 + 拼错即报错**: 旧写法 `globals().get(_fname)`
        #   对拼错的函数名**静默退化为通用探测**(声明与实现断裂, 与 RE_CHUNK 死通道同族)。
        #   声明了 func 却解析不到 → 立刻炸, 让拼写错误/函数增删暴露在门禁期, 不是运行期。
        _fn = getattr(sys.modules[__name__], _fname, None) if _fname else None
        if _fn is None:
            if _fname:
                raise KeyError(
                    f'PROBE_SPECS[{_name!r}] 声明的 func 不存在: {_fname!r} '
                    f'(拼写错误, 或该函数已被删除/改名)')
            if not _spec.get('paths'):
                continue
            def _bound(c, b, k=_name):
                return _generic_probe(c, b, k)
            _fn = _bound
        probe_map[_name] = _fn

    # 兜底探测: 默认关闭
    #   旧逻辑在"未命中 API 框架指纹"时反而追加探测, 与门控方向相反。
    #   防漏报应通过扩充指纹库解决, 而非对未命中目标补打。
    if cfg.get('fallback_probe', False):
        probe_map['fallback'] = _fallback_probe

    # 注: 原 `probe_targets_enabled`(栈专属已知路径探测)已移除 —— 与数据驱动的
    #   `hidden_probe` 重叠; 栈专属路径统一由 `hidden_probe` 处理。

    return probe_map


def detect_and_probe(ctx, base):
    """指纹驱动的条件化探测: 非Spring目标不探测Swagger/Actuator/Druid"""
    from .http import REQ
    clog('[*]', f'指纹驱动探测: {base}', Color.CYAN)
    # 记录目标根, 供 _probe_req / _ensure_catchall_baseline 惰性建立 canary 基线
    ctx.base = base
    # 加载指纹库(支持外部化)
    fp_rules = _load_fingerprints(ctx.config)

    # 1. 首发指纹
    r = REQ(ctx, 'GET', base)
    if r is None:
        return
    html = r.text
    hits, confidence, route = fingerprint_target(
        base, html, dict(r.headers), fp_rules,
        confirm_overrides=get_confirm_overrides(getattr(ctx, 'baseline_profile', None)))
    # 版本级后端栈（从响应头抽产品+版本；指纹只给"是什么", 这里补"哪个版本"）
    ctx.fingerprints = {'hits': hits, 'confidence': confidence,
                        'stack': extract_backend_stack(dict(r.headers))}
    ctx.baseline_profile = get_baseline_profile(hits)
    ctx.route = route
    log(f'指纹命中: {hits} (置信度: {confidence})')
    enabled = get_enabled_rules(route)

    # 2. 按指纹条件化探测
    probe_map = _build_probe_map(ctx, hits)

    # 执行探测
    _run_probe_map(ctx, base, probe_map)
    clog('[*]', f'门控后启用探测: {sorted(probe_map.keys())}', Color.GREY)
    return enabled


def _run_probe_map(ctx, base, probe_map):
    """执行探测表; 单个探测异常不影响其余探测"""
    for name, func in probe_map.items():
        try:
            func(ctx, base)
        except Exception as e:
            if ctx.config.get('debug'):
                traceback.print_exc()
            log(f'[-] 探测 {name} 异常: {e}')


def probe_new_fingerprints(ctx, base, js_texts):
    """JS 分析阶段补判指纹, 并对**新增**的指纹追加其专属探测

    解决的问题:
      · 有一类指纹的特征只出现在 JS 源码里(tRPC / Rollup / esbuild / Parcel /
        SolidJS 的 body 规则为空), HTML 阶段结构性不可能命中;
      · 首轮 `detect_and_probe` 发生在 JS 下载之前, 因此这些指纹的专属探测
        (如 `_trpc_probe`) 永远不会执行 —— 属死代码。

    现在 JS 下载完成后补判一次, 只对**新命中**的指纹执行其门控探测, 避免重复发包。

    Returns:
        list: 新命中的指纹名
    """
    if not js_texts:
        return []
    fp_rules = _load_fingerprints(ctx.config)
    known = list((getattr(ctx, 'fingerprints', None) or {}).get('hits', []))
    new_hits, new_conf = fingerprint_from_js(
        js_texts, fp_rules=fp_rules, known_hits=known,
        confirm_overrides=get_confirm_overrides(getattr(ctx, 'baseline_profile', None)))
    if not new_hits:
        return []
    log(f'[*] JS 阶段补判指纹: {new_hits} (置信度: {new_conf})')
    fp = dict(getattr(ctx, 'fingerprints', None) or {})
    hits = list(fp.get('hits', [])) + new_hits
    conf = dict(fp.get('confidence', {}))
    conf.update(new_conf)
    fp['hits'] = hits
    fp['confidence'] = conf
    ctx.fingerprints = fp
    ctx.baseline_profile = get_baseline_profile(hits)
    # 路由权重同步抬升(专属提取正则随之生效)
    route = dict(getattr(ctx, 'route', None) or ROUTE_RULES['_DEFAULT'])
    for name in new_hits:
        merge_route(route, name)
    ctx.route = route
    # 只执行"新指纹"对应的探测, 避免重复发包
    probe_map = _build_probe_map(ctx, new_hits)
    if probe_map:
        _run_probe_map(ctx, base, probe_map)
        clog('[*]', f'JS 阶段补判后追加探测: {sorted(probe_map.keys())}', Color.GREY)
    return new_hits


# ---------- 各探测函数 ----------
def _spec_paths(ctx, key):
    """取某探测环境的路径(含外部 `probe_specs_db` 覆盖) —— 探测函数只读数据层。"""
    return (get_probe_specs(getattr(ctx, 'config', None)).get(key) or {}).get('paths') or ()


def _generic_probe(ctx, base, key):
    """**通用数据驱动探测** —— 按 `PROBE_SPECS[key]` 的 paths + 声明式规则探测, **无需专用函数**。

    规则字段(数据层声明): `marker`(响应须含该子串, 可选) / `severity`(默认 MED) / `finding`(标题)。
    使"新增环境"= **纯数据**(加一条 `PROBE_SPECS` 或 `probe_specs_db` 条目), 不改代码。
    """
    spec = get_probe_specs(getattr(ctx, 'config', None)).get(key) or {}
    marker = (spec.get('marker') or '').lower()
    sev = spec.get('severity') or 'MED'
    ftype = spec.get('finding') or f'{key} 特征端点可达'
    for p in (spec.get('paths') or ()):
        r = _probe_req(ctx, urljoin(base, p))
        if r is None or r.status_code != 200:
            continue
        if marker and marker not in (r.text or '').lower():
            continue
        # 200 不必然"匿名可达": 若该路径返回登录页(或 200 + 业务码未授权), 它**要求登录**
        #   而非"暴露"。须核验响应证据, 与 probe()/hidden_probe()/actuator_probe 口径一致,
        #   避免把登录页误报成"特征端点可达"(过度断言)。缺 marker 的外部规格尤其易踩。
        if _looks_login_redirect(r) or _looks_login_page(r):
            ctx.add_finding('MED', f'{ftype}(需登录·受保护)', urljoin(base, p),
                            'HTTP 200, 登录页')
        else:
            ctx.add_finding(sev, ftype, urljoin(base, p), 'HTTP 200')


def _graphql_probe(ctx, base):
    log('[*] graphql: 内省端点')
    for ep in _spec_paths(ctx, 'graphql'):      # 路径来自数据层(dicts.PROBE_SPECS)
        url = urljoin(base, ep)
        r = _probe_req(ctx, url, method='POST', readonly_post=True,   # 语义只读的内省查询
                       headers={'Content-Type': 'application/json'},
                       json={'query': '{__schema{queryType{name}}}'}, timeout=10)
        if r is None:
            continue
        if r.status_code == 200:
            try:
                d = r.json()
                if d.get('data', {}).get('__schema'):
                    ctx.add_finding('HIGH', 'GraphQL内省开放', url, 'schema元查询可访问')
            except Exception as e:
                dbg(f'GraphQL 内省响应解析 {url}: {e}')
        elif r.status_code in (400, 401, 403):
            ctx.add_finding('INFO', 'GraphQL端点存在(内省受限)', url, f'HTTP {r.status_code}')


def _grpc_probe(ctx, base):
    log('[*] grpc: reflection/proto发现')
    _paths = _spec_paths(ctx, 'grpc')            # 路径来自数据层(dicts.PROBE_SPECS)
    for gp in [p for p in _paths if 'ServerReflection' in p]:
        r = _probe_req(ctx, urljoin(base, gp), method='POST', readonly_post=True)  # gRPC reflection(只读)
        if r is not None and r.status_code == 200:
            ctx.add_finding('INFO', 'gRPC端点存在', urljoin(base, gp), f'HTTP {r.status_code}')
    for pp in [p for p in _paths if 'ServerReflection' not in p]:
        r = _probe_req(ctx, urljoin(base, pp))
        if r is not None and r.status_code == 200 and len(r.text) > 20:
            low = r.text.lower()
            if ('syntax' in low and 'proto' in low) or 'message ' in low:
                ctx.add_finding('HIGH', '.proto文件泄露', urljoin(base, pp), '含接口定义')


def _swagger_probe(ctx, base):
    log('[*] swagger/openapi: 文档端点')
    # 路径**单一事实来源** = dicts.SWAGGER_SPEC_PATHS + SWAGGER_UI_PATHS(与门控字典、
    #   schema 通道同源) —— 旧实现此处硬编码 9 条, 与 dicts 各写一份 → 漂移风险。
    for sp in _spec_paths(ctx, 'swagger'):      # 路径来自数据层(dicts.PROBE_SPECS)
        r = _probe_req(ctx, urljoin(base, sp))
        if r is None:
            continue
        if r.status_code == 200:
            low = r.text.lower()
            if 'swagger' in low or '"openapi"' in low or 'paths' in low:
                # 公开 API 文档**常为有意发布**(开发者文档站) → MED(信息性披露), 不再 HIGH。
                ctx.add_finding('MED', 'Swagger/OpenAPI文档暴露', urljoin(base, sp), 'API定义可直接读取')
                # 注: **不在此处解析文档提取端点** —— 端点/参数抽取由 `recon/schema.py`
                #   (schema 通道, 受 `schema_probe` 开关控制) 统一负责。旧实现两处都解析,
                #   导致 `schema_probe: false` 无法真正关闭 schema 派生数据(重复通道)。
        elif r.status_code in (401, 403):
            # 已鉴权保护 → 未公开暴露, 属防御纵深观察(信息性), **非风险**; 不得按 MED 上报。
            # 仅 200(文档公开可读)才代表真实暴露(上方 MED 分支)。
            ctx.add_finding('INFO', 'Swagger端点存在(已鉴权保护·未暴露)',
                            urljoin(base, sp), f'HTTP {r.status_code} · 端点存在但需认证, 未公开可读')


def _actuator_probe(ctx, base):
    log('[*] actuator: Spring Boot 监控端点')
    from .guard import _looks_unauth
    from .http import REQ, _AioResp
    # heapdump / threaddump 是"大体积下载型"端点。
    #   现在: Range 限制前 4KB + stream=True(不读全量), 仅用于确认端点可达。
    BULK = ('/actuator/heapdump', '/actuator/threaddump')
    # 常态公开的 actuator 端点(健康检查/信息, 负载均衡探活用) —— 暴露它们**不是**发现。
    _PUBLIC = ('/actuator', '/actuator/health', '/actuator/info')
    # 路径来自数据层(dicts.PROBE_SPECS, 与门控字典同源)。
    for ep in _spec_paths(ctx, 'actuator'):
        url = urljoin(base, ep)
        if ep in BULK:
            # Range 已限制 4096 字节: 去掉 stream=True, 改用 r.content —— 受 urllib3 逐块
            # 超时保护, 避免 stream=True 下 r.raw.read 在连接半关(CLOSE_WAIT)时永久阻塞。
            r = REQ(ctx, 'GET', url, headers={'Range': 'bytes=0-4095'}, timeout=15)
            if r is None:
                continue
            st = r.status_code
            head = (r.content or b'')[:4096]
            try:
                r.close()
            except Exception:
                pass
            # 用只读到的那一小段做 catch-all 判定(绝不触碰 r.text / r.content)
            _ensure_catchall_baseline(ctx)
            probe = _AioResp()
            probe.status_code = st
            probe.content = head
            probe.text = head.decode('utf-8', 'ignore')
            hit, why = _is_catchall(ctx, probe)
            if hit:
                if st in (200, 206, 401, 403):
                    ctx.add_excluded(ep, st, f'伪命中(catch-all): {why}')
                continue
            if st in (200, 206):
                # 200/206 不必然"匿名可达": 大体积端点藏在登录墙后时, 网关/应用可能把
                #   请求重定向或直出登录页(此处只读到前 4KB 头, 用登录页标记判据核验)。
                #   登录页 = **受保护, 需登录**, 非"暴露" → 降级 MED(与 probe()/hidden_probe() 一致)。
                if _looks_login_page(probe):
                    ctx.add_finding('MED', f'Actuator端点存在(需登录·受保护) ({ep})', url,
                                    f'HTTP {st}, 登录页(仅探测头 4KB)')
                else:
                    ctx.add_finding('CRITICAL' if 'heapdump' in ep else 'HIGH',
                                    f'Spring Actuator暴露({ep})', url,
                                    f'HTTP {st} (仅探测, 未下载响应体)')
            elif st in (401, 403):
                ctx.add_finding('MED', f'Actuator端点存在({ep})', url, f'HTTP {st}')
            continue
        r = _probe_req(ctx, url)
        if r is None:
            continue
        if r.status_code == 200:
            if ep in _PUBLIC:
                # 健康检查/信息端点**常态公开**(LB 探活) → 非"暴露", 记 INFO。
                ctx.add_finding('INFO', f'Actuator端点可达(常态公开) {ep}', url,
                                f'HTTP 200, 长度 {len(r.text)}')
            else:
                # 200 不必然"匿名可达": Spring Security 常把 /actuator/* 重定向/直出登录页,
                #   或经网关/应用统一包装回 200 + 业务码未授权(`{"code":401,"msg":"未授权"}`)。
                #   这两种都**要求登录**, 不是"暴露" —— 须核验响应证据, 否则会像
                #   demo.testfire.net /admin 那样把登录页误报成 HIGH「暴露」(过度断言)。
                #   与 probe()/hidden_probe()/jeecgboot_probe/ruoyi_probe 口径一致。
                if _looks_login_redirect(r) or _looks_login_page(r):
                    ctx.add_finding('MED', f'Actuator端点存在(需登录·受保护) ({ep})', url,
                                    f'HTTP 200, 登录页(长度 {len(r.text)})')
                elif _looks_unauth(r.text):
                    ctx.add_finding('MED', f'Actuator端点存在(业务码未授权·需登录) ({ep})', url,
                                    'HTTP 200 + 业务码未授权')
                else:
                    ctx.add_finding('HIGH', f'Spring Actuator暴露({ep})', url,
                                    f'HTTP 200, 长度 {len(r.text)}')
        elif r.status_code in (401, 403):
            ctx.add_finding('MED', f'Actuator端点存在({ep})', url, f'HTTP {r.status_code}')


def _druid_probe(ctx, base):
    log('[*] druid: 监控面板')
    # 路径来自数据层(dicts.PROBE_SPECS, 与门控字典同源)。
    for dp in _spec_paths(ctx, 'druid'):
        r = _probe_req(ctx, urljoin(base, dp))
        if r is not None and r.status_code == 200 and 'Druid' in r.text:
            # 措辞: **不宣称"未授权"**(未做鉴权判定) —— 面板可达 + 需人工确认鉴权。
            ctx.add_finding('HIGH', 'Druid监控面板可达(需确认鉴权)', urljoin(base, dp),
                            'HTTP 200 · 含 SQL/会话监控')


def _wp_probe(ctx, base):
    log('[*] wordpress: REST API')
    # WP REST 默认公开：`posts`/`pages`/`media` 属**公开内容**(非泄露) → INFO；
    #   `users` 暴露用户名(用户枚举) → MED(已知默认行为, 是否可接受需人工判断)。
    #   旧实现一律 HIGH —— 实测真实站点 wptest.io 因此产生 4 条 HIGH 噪声。
    # 路径**单一事实来源** = dicts.HIDDEN_PATHS_BY_STACK['WordPress'](与门控字典同源)。
    #   `users` 暴露用户名(用户枚举) → MED; 其余集合(帖子/页面/媒体)属**公开内容**,
    #   由门控字典的隐藏路径通道处理, 此处不再另写一份(旧实现重复定义 → 漂移)。
    for wp in _spec_paths(ctx, 'wp'):           # 路径来自数据层(dicts.PROBE_SPECS)
        r = _probe_req(ctx, urljoin(base, wp))
        if r is not None and r.status_code == 200:
            try:
                d = r.json()
                if isinstance(d, list) and len(d) > 0:
                    ctx.add_finding('MED', 'WordPress REST API可达(用户枚举)',
                                    urljoin(base, wp), f'{len(d)}条记录')
            except Exception as e:
                dbg(f'WP REST 响应解析 {urljoin(base, wp)}: {e}')


def _django_probe(ctx, base):
    log('[*] django: 调试端点')
    for dp in _spec_paths(ctx, 'django'):       # 路径来自数据层(dicts.PROBE_SPECS)
        r = _probe_req(ctx, urljoin(base, dp))
        if r is not None:
            if r.status_code == 200 and 'django' in r.text.lower():
                ctx.add_finding('INFO', 'Django管理端点', urljoin(base, dp), '200 OK')


def _trpc_probe(ctx, base):
    """tRPC 专属探测: 查询 tRPC introspection 端点"""
    log('[*] trpc: introspection端点')
    for ep in _spec_paths(ctx, 'trpc'):         # 路径来自数据层(dicts.PROBE_SPECS)
        url = urljoin(base, ep)
        r = _probe_req(ctx, url, headers={'Accept': 'application/json'})
        if r is not None and r.status_code == 200:
            try:
                d = r.json()
                # 收紧判据: 旧实现"含 query/mutation/router 任一即命中"过宽 ——
                #   任何提到这些词的 JSON 都会误报。改为要求 tRPC 特征:
                #   superjson 转换器标记, 或 `result` 内嵌过程名(query/mutation)。
                _s = str(d).lower()
                if isinstance(d, dict) and ('superjson' in _s
                                            or ('result' in d and ('query' in _s or 'mutation' in _s))):
                    ctx.add_finding('HIGH', 'tRPC introspection开放', url, '路由器定义可读取')
            except Exception as e:
                dbg(f'tRPC introspection 响应解析 {url}: {e}')


def _fallback_probe(ctx, base):
    """指纹无关兜底探测 

    问题: 该探测在"未命中 API 框架指纹"时反而追加执行, 与门控方向相反 ——
              未命中本该 pass, 却变成"多打 4 发"。防漏报应通过扩充指纹库解决。
    处置:
      · 默认关闭(由 config.fallback_probe 控制), 仅显式开启时执行
      · 收窄到 2 发: /openapi.json + GraphQL GET 探测
    """
    log('[*] 兜底探测(显式开启): OpenAPI / GraphQL 通用端点')
    # OpenAPI: 跨框架标准路径(1 发)
    url = urljoin(base, '/openapi.json')
    r = _probe_req(ctx, url)
    if r is not None:
        if r.status_code == 200:
            low = r.text.lower()
            if 'openapi' in low or 'swagger' in low or '"paths"' in low:
                # 与主探测(_swagger_probe)统一为 MED(信息性披露); 公开文档常为有意发布。
                ctx.add_finding('MED', 'Swagger/OpenAPI文档暴露', url, 'API定义可直接读取(兜底命中)')
                try:
                    d = json.loads(r.text)
                    for p in list(d.get('paths', {}).keys())[:20]:
                        ctx.add_all_found(p, 'GET', 200, '来自Swagger兜底')
                except Exception as e:
                    dbg(f'兜底 Swagger 解析 {url}: {e}')
        elif r.status_code in (401, 403):
            # 已鉴权保护 → 未公开暴露, 信息性观察, 非风险(同 _swagger_probe)。
            ctx.add_finding('INFO', 'Swagger端点存在(已鉴权保护·未暴露)',
                            url, f'HTTP {r.status_code} · 端点存在但需认证, 未公开可读')
    # GraphQL: GET 探测 `/_graphql?query={__typename}` (1 发)
    gq_url = urljoin(base, '/_graphql') + '?query=%7B__typename%7D'
    r = _probe_req(ctx, gq_url)
    if r is not None and r.status_code == 200:
        head = r.text[:800]
        if ('"data"' in head or '__typename' in head or '"errors"' in head) and '{' in r.text:
            ctx.add_finding('HIGH', 'GraphQL端点存在(兜底命中)', gq_url, 'GET 探测返回 GraphQL 数据')


def _laravel_probe(ctx, base):
    """Laravel 专属探测: .env / debug / telescope / horizon"""
    log('[*] laravel: PHP框架特征端点')
    for ep in _spec_paths(ctx, 'laravel'):      # 路径来自数据层(dicts.PROBE_SPECS)
        r = _probe_req(ctx, urljoin(base, ep))
        if r is not None and r.status_code == 200:
            low = r.text.lower()
            if 'app_key' in low or 'db_password' in low or 'laravel' in low:
                ctx.add_finding('CRITICAL', 'Laravel敏感文件泄露', urljoin(base, ep), '含配置/密钥')


def _thinkphp_probe(ctx, base):
    """ThinkPHP 专属探测: 调试/Runtime/日志"""
    log('[*] thinkphp: 国内PHP框架特征端点')
    for ep in _spec_paths(ctx, 'thinkphp'):     # 路径来自数据层(dicts.PROBE_SPECS)
        r = _probe_req(ctx, urljoin(base, ep))
        if r is not None and r.status_code == 200:
            low = r.text.lower()
            if 'thinkphp' in low or 'runtime' in low or 'database' in low:
                ctx.add_finding('HIGH', 'ThinkPHP敏感信息泄露', urljoin(base, ep), '框架文件/日志暴露')


def _jeecgboot_probe(ctx, base):
    """JeecgBoot 专属探测: 国内低代码平台管理接口"""
    from .guard import _looks_mgmt_list, _looks_unauth
    log('[*] jeecgboot: 低代码平台特征端点')
    for ep in _spec_paths(ctx, 'jeecgboot'):    # 路径来自数据层(dicts.PROBE_SPECS)
        r = _probe_req(ctx, urljoin(base, ep))
        if r is not None:
            if r.status_code == 200:
                # 200 不必然"可达": 国内框架未登录常回 200 + 业务码未授权(如 `{"code":401,
                #   "msg":"请先登录"}` / `token无效`), 或返回空壳/错误体。必须**核验响应体确实含
                #   列表数据**才报"可达", 否则降级为"存在(需确认)" —— 禁止虚构"列表可读"证据。
                if _looks_unauth(r.text):
                    ctx.add_finding('MED', 'JeecgBoot管理接口存在(业务码未授权·需登录)',
                                    urljoin(base, ep), 'HTTP 200 + 业务码未授权')
                elif _looks_mgmt_list(r.text):
                    ctx.add_finding('HIGH', 'JeecgBoot管理接口可达(需确认鉴权)',
                                    urljoin(base, ep), '用户/角色/字典列表可读')
                else:
                    ctx.add_finding('MED', 'JeecgBoot管理接口存在(未确认内容)',
                                    urljoin(base, ep), f'HTTP 200, 长度 {len(r.text)}')
            elif r.status_code in (401, 403):
                ctx.add_finding('MED', 'JeecgBoot管理接口存在', urljoin(base, ep), f'HTTP {r.status_code}')


def _ruoyi_probe(ctx, base):
    """若依/RuoYi 专属探测: 国内后台管理框架接口"""
    from .guard import _looks_mgmt_list, _looks_unauth
    log('[*] ruoyi: 后台管理框架特征端点')
    for ep in _spec_paths(ctx, 'ruoyi'):        # 路径来自数据层(dicts.PROBE_SPECS)
        r = _probe_req(ctx, urljoin(base, ep))
        if r is not None:
            if r.status_code == 200:
                # 同 JeecgBoot: 200 需**核验响应体含列表数据**才算"可达", 否则降级"存在(需确认)"。
                if _looks_unauth(r.text):
                    ctx.add_finding('MED', 'RuoYi管理接口存在(业务码未授权·需登录)',
                                    urljoin(base, ep), 'HTTP 200 + 业务码未授权')
                elif _looks_mgmt_list(r.text):
                    ctx.add_finding('HIGH', 'RuoYi管理接口可达(需确认鉴权)',
                                    urljoin(base, ep), '用户/角色/菜单列表可读')
                else:
                    ctx.add_finding('MED', 'RuoYi管理接口存在(未确认内容)',
                                    urljoin(base, ep), f'HTTP 200, 长度 {len(r.text)}')
            elif r.status_code in (401, 403):
                ctx.add_finding('MED', 'RuoYi管理接口存在', urljoin(base, ep), f'HTTP {r.status_code}')


def _auth_probe(ctx, base):
    """认证方案专属探测: Keycloak/CAS/SAML 管理端点"""
    log('[*] auth: 认证方案管理端点')
    for ep in _spec_paths(ctx, 'auth'):         # 路径来自数据层(dicts.PROBE_SPECS)
        r = _probe_req(ctx, urljoin(base, ep))
        if r is not None and r.status_code == 200:
            low = r.text.lower()
            if any(k in low for k in ('keycloak', 'cas', 'saml', 'realm', 'sso')):
                # 登录页 / SAML 元数据属**正常 UI / 公开元数据**, 不是"暴露" → INFO;
                #   仅**管理面**(admin / realms 配置)才 HIGH, 且**不宣称"未授权"**。
                _loginish = (_looks_login_page(r) or ep.endswith('/login')
                             or ep.endswith('/metadata'))
                ctx.add_finding(
                    'INFO' if _loginish else 'HIGH',
                    '认证端点可达(登录/公开元数据)' if _loginish
                    else '认证管理端点暴露(需确认鉴权)',
                    urljoin(base, ep), 'HTTP 200')


def _waf_probe(ctx, base):
    """WAF 探测: 以指定 UA 访问主页, 观察是否触发 WAF 拦截特征

    UA 默认走**浏览器 UA**(`const.DEFAULT_UA`, 与扫描请求默认同口径)——
    全工具流量 UA 一致, 不再自带"扫描器"特征头。
      · 历史沿革: `sqlmap/1.0`(旧默认) → `facet-Scanner/<版本>`(自我标识) →
        浏览器 UA(当前默认, 用户要求: "默认 UA 用浏览器的, 不用工具的")。
      · 需要自我标识(授权测试流量可追溯)或复现特定工具 UA 时, 用 `waf_probe_ua`
        配置显式指定, 例如 `facet-Scanner/4.6.3(+联系方式)`。
    """
    from .http import REQ
    ua = ctx.config.get('waf_probe_ua') or DEFAULT_UA
    log(f'[*] waf: WAF防护检测 (UA: {ua})')
    # 注意: 此处不能用 _probe_req —— WAF 探测的对象就是主页本身,
    #       而 catch-all 站点的主页必然与 canary 基线一致, 会被误判为伪命中而跳过。
    r = REQ(ctx, 'GET', base, headers={'User-Agent': ua})
    if r is not None:
        if r.status_code in (403, 406, 503):
            ctx.add_finding('INFO', 'WAF拦截响应', base, f'HTTP {r.status_code}(疑似WAF阻断)')
        cf_ray = r.headers.get('CF-RAY')
        if cf_ray:
            ctx.add_finding('INFO', 'Cloudflare WAF已启用', base, f'CF-RAY: {cf_ray[:20]}')


# 注: 原 `_cloud_probe`(探测 169.254.169.254 / 100.100.100.200 / metadata.tencentyun.com)
#   已**移除** —— 它请求的是 **运行者本机** 的云元数据, 与目标站点无关(语义越界):
#   · 会把**扫描者自身**的云凭据暴露风险引入(命中即 CRITICAL, 易被误读为"目标问题");
#   · 在受管控云环境会触发安全告警。
#   目标侧的 SSRF/元数据风险应由"外部地址型参数(SSRF 候选)"维度标注, 而非由工具自查本机。


def _common_probe(ctx, base):
    """通用探测: 跨栈通用端点 

    仅保留命中率最高且信息量明确的 3 条。的 /api/v1 /api/v2 /api/health
    与 /health /status 高度冗余, 命中后信息量极低却计入"接口清单"。
    """
    log('[*] 通用探测: 标准API端点')
    common = _spec_paths(ctx, 'common')         # 路径来自数据层(dicts.PROBE_SPECS)
    for p in common:
        r = _probe_req(ctx, urljoin(base, p))
        if r is not None and r.status_code == 200:
            ctx.add_all_found(p, 'GET', 200, '通用探测命中')


# ---------- 隐藏接口探测 ----------
def _is_js_asset_path(p):
    """路径是否为 **JS 资源**(.js/.mjs) —— 这类路径属"隐藏 JS 发现管线", 不是"隐藏接口"。

    用于 `hidden_probe` 剔除指纹专属 JS 资源(如 Angular `/main.js`): 它们改由
    orchestrator `js_dir_fuzz`(步骤2.56, 早于 JS 管线)并入 js_urls 做源码分析。
    """
    return str(p).lower().split('?')[0].endswith(('.js', '.mjs'))


def hidden_probe(ctx, base, token=None):
    """敏感路径字典探测 

    字典分层:
      · 通用层 HIDDEN_PATHS_COMMON — 任何技术栈都探测
      · 栈专属层 — 仅当指纹命中对应技术栈时加载(如 /actuator/* 仅 Spring 系目标)

    判定依据(按优先级):
      0. 与 canary(保证不存在的随机路径)基线一致 → 路径根本不存在, 静默跳过
      1. catch-all 伪命中 → 200 时记入"已排除项", 不计入严重度统计
      2. 空回退        → 200 但内容极少, 记入"已排除项"
      3. 200 有实质差异 → HIGH(路径含 admin/manage/actuator/env/config/.git/.env 等) / MED
      4. 401/403       → MED(鉴权墙存在, 路径真实)
      5. 500           → INFO(触发服务端异常, 路由解析到了模块)

    关于"已排除项"的语义修正:
      excluded 只应记录**本来会被报成发现、但被判定为不可信**的路径。
    """
    from .guard import _fingerprint_resp
    from .http import REQ
    from .secret import _is_benign_wellknown
    ctx.base = base
    fp_hits = list((getattr(ctx, 'fingerprints', None) or {}).get('hits', []))
    # 字典可扩展(与 secret_db/fingerprint_db 同构): config 内联列表 + 外部字典文件；
    # 扩展层为 opt-in(默认关), 守"默认最小发包"定位。
    _cfg = ctx.config or {}
    _extra = list(_cfg.get('hidden_paths_extra') or [])
    _db = _cfg.get('hidden_paths_db')
    if _db:
        _extra += load_external_hidden_paths(_db)
    _ext = _cfg.get('hidden_paths_extended')
    if _ext == 'auto':
        _ext = bool(fp_hits)          # auto: 命中指纹(已知栈)才追加扩展字典层, 否则守最小发包
    _extended = bool(_ext)
    paths = get_hidden_paths(fp_hits, extra=_extra, extended=_extended)
    # 指纹专属 **JS 资源**(.js/.mjs)不属"隐藏接口" —— 它们由"隐藏 JS 发现"(orchestrator
    #   `js_dir_fuzz`, 步骤2.56, **早于 JS 管线**)并入 js_urls 做**源码分析**。此处**剔除**, 避免:
    #   ① 与 js_dir_fuzz 重复探测; ② 把 JS 资源误报成"隐藏接口暴露"(实测缺口)。
    # 仅在"隐藏 JS 发现"(`js_dir_fuzz`)开启时才剔除 —— 否则这些 JS 资源将**无人探测**
    #   (js_dir_fuzz 关 + hidden_probe 剔除 = 覆盖损失, 违反"提取只增不减")。
    if plugins.enabled('collector', 'jsdir', _cfg):
        _js_assets = {p for p in paths if _is_js_asset_path(p)}
        if _js_assets:
            paths = [p for p in paths if p not in _js_assets]
            dbg(f'hidden: 剔除 {len(_js_assets)} 条 JS 资源路径(改由"隐藏 JS 发现"管线处理)')
    # 尾斜杠变体(无重定向型服务器: 裸路径 404 但 /path/ 200)。仅补**高价值目录型**,
    #   控制发包增量 —— 其余路径靠 REQ 跟随 301 重定向已覆盖。
    _slash = [p + '/' for p in TRAILING_SLASH_PATHS
              if p in paths and (p + '/') not in paths]
    if _slash:
        paths = paths + _slash
    log(f'[*] hidden: 敏感路径字典 {len(paths)} 条 '
        f'(通用层 {len(HIDDEN_PATHS_COMMON)}'
        + (' + 扩展层' if _extended else '')
        + f' + 按指纹命中 {len(fp_hits)} 项加载'
        + (f' + 自定义 {len(_extra)}' if _extra else '')
        + (f' + 尾斜杠变体 {len(_slash)}' if _slash else '') + ')')

    H = {'Authorization': f'Bearer {token}'} if token else {}
    homepage_fp = getattr(ctx, '_homepage_fingerprint', '')
    bl = _ensure_catchall_baseline(ctx, base)
    if bl is None:
        log('[!] hidden: 无 catch-all 基线(canary 请求失败), 伪命中判定降级为"主页指纹比对"')

    # 字典"何时用": 目标若是 catch-all(随机 canary 也回 200), "页面型"条目
    #   (admin/console/health…)与"不存在"的响应一致 → 必然判定 0, 无信号且白费请求;
    #   故收窄到"内容型"条目(源码/备份/配置——若真存在必返回不同内容, 仍可判别)。
    #   判据只用 **canary 状态码 == 200**(不存在却回 200 = catch-all/soft-404);
    #   注意**不能**用 multi_path_catchall —— 普通 404 站点上多个 canary 的 404 页
    #   本就近乎相同, 该标志会误报为 True 而错误收窄。
    _catchall_regime = bool(bl and bl.get('status') == 200)
    if _catchall_regime:
        _narrowed = [p for p in paths if is_content_diff_path(p)]
        if _narrowed and len(_narrowed) < len(paths):
            log(f'[*] hidden: 目标疑似 catch-all(canary 回 {bl.get("status")}) → 字典收窄 '
                f'{len(paths)} → {len(_narrowed)} 条"内容型"条目(页面型在此目标上无法判别, 跳过)')
            paths = _narrowed

    # 统计三类去向, 供末尾汇总(旧实现"判定 0"完全静默, 无法分辨
    #   "没找到"与"根本判不了")
    n_silent = n_excl = n_found = 0
    _denied = []          # 403 路径聚合 —— 避免同一目标同类 403 刷屏(实测一次报 7 条)
    for p in paths:
        if ctx.is_invalid(p):
            continue
        url = urljoin(base, p)
        r = REQ(ctx, 'GET', url, headers=H)
        if r is None:
            continue
        fp = _fingerprint_resp(r)
        st = r.status_code
        txt = r.text or ''
        txt_len = len(txt)

        # 判定 0: 与 canary 基线完全一致 → 该路径不存在, 静默跳过(不产生任何记录)
        if bl and st == bl['status'] and fp == bl['fp']:
            ctx.mark_invalid(p)      # 记入"不存在", 供任何后续相位/重跑跳过
            n_silent += 1
            continue

        # 判定 1: catch-all 伪命中(canary 高度相似, 或与主页一致)
        hit_ca, why = _is_catchall(ctx, r)
        if not hit_ca and st == 200 and homepage_fp and fp == homepage_fp:
            hit_ca, why = True, '响应与主页指纹一致(疑似通用回退路由)'
        if hit_ca:
            # 只有 200 的伪命中"本来会成为发现", 才值得记入附录 A 供复核;
            # 非 200 的伪命中本来就不会被报成发现, 静默跳过即可。
            if st == 200:
                ctx.add_excluded(p, st, f'伪命中: {why} ({txt_len}B)')
                n_excl += 1
            continue

        # 非 (200/401/403/500) 的状态码从来不会成为发现, 直接跳过
        if st not in (200, 401, 403, 500):
            continue

        # 判定 2: 空回退 → 200 但内容极少
        if st == 200 and txt_len < 100 and not txt.strip():
            ctx.add_excluded(p, st, f'空响应: 200 OK 但仅 {txt_len}B')
            n_excl += 1
            continue

        # 正常判定
        n_found += 1
        if st == 200:
            if _looks_login_redirect(r) or _looks_login_page(r):
                # 需登录（重定向到登录页 / **直接返回登录页**）→ 只是"信息"（路径存在、受保护），
                #   **不是"暴露"，更不是"未授权"**；如实标注 MED（值得试绕过）。
                ctx.add_finding('MED', '路径存在但需登录(受保护)', url,
                                f'200 OK(登录页), 长度 {txt_len}')
                ctx.add_all_found(p, 'GET', 200, '受保护(需登录)')
            elif _is_benign_wellknown(p):
                # 常见公开文件(robots/sitemap/manifest/favicon…) 存在属正常 → INFO, 不报"暴露"。
                ctx.add_finding('INFO', '常见公开文件(非暴露)', url, f'200 OK, 长度 {txt_len}')
                ctx.add_all_found(p, 'GET', 200, '常见公开文件')
            else:
                # 定级: 路径**段**命中"高危管理/配置面"(单一事实来源 MGMT_HIGH_RISK_KW) → HIGH。
                #   用段匹配而非子串 —— 旧 `k in p` 会把 `/api/environment` 误当 `env`。
                _segs = {x for x in p.lower().split('?')[0].split('/') if x}
                severity = 'HIGH' if (_segs & MGMT_HIGH_RISK_KW) else 'MED'
                ctx.add_finding(severity, '隐藏接口暴露', url, f'200 OK, 长度 {txt_len}')
                ctx.add_all_found(p, 'GET', 200, '隐藏路径命中')
        elif st == 401:
            # 401 = 服务端明确要求认证 → 端点很可能存在
            ctx.add_finding('MED', '路径需认证(401)', url, f'HTTP {st}')
            ctx.add_all_found(p, 'GET', st, '需认证')
        elif st == 403:
            # 403 = 拒绝访问, 成因不确定(受保护资源 / 访问控制 / WAF 拦截规则)
            #   —— 旧措辞"隐藏接口存在(需鉴权)"属**过度断言**, 改为如实描述。
            #   逐条 403 会在同一目标刷屏(实测一次 7 条), 故**聚合**到循环后统一报一条。
            _denied.append(p)
            # 文件型 403(安全加固)不进端点清单; 页面/接口型 403(受保护资源)才登记为端点。
            if _is_reportable_endpoint(p, st):
                ctx.add_all_found(p, 'GET', st, '拒绝访问')
        elif st == 500:
            ctx.add_finding('INFO', '隐藏路径触发服务端异常', url, f'HTTP {st}')
            ctx.add_all_found(p, 'GET', st, '服务端异常')

    # 403 聚合: 同一目标同类 403 合并为**一条**(避免刷屏), 列出被拒路径供人工复核。
    #   并**按性质分档**: 文件型(.env/.htaccess/composer.json…, 实测服务器常对整类文件统一 403)
    #   = 多为**安全加固**(非暴露) → INFO; 页面/接口型 = 路径很可能存在(受保护) → MED。
    if _denied:
        _files = [p for p in _denied if is_content_diff_path(p)]
        _pages = [p for p in _denied if not is_content_diff_path(p)]

        def _prev(lst):
            return ', '.join(lst[:8]) + (f' …(共 {len(lst)})' if len(lst) > 8 else '')
        if _files:
            ctx.add_finding('INFO', '敏感文件被服务器拒绝(403 · 多为安全加固)', base,
                            f'{len(_files)} 条: {_prev(_files)}')
        if _pages:
            ctx.add_finding('MED', '页面/接口路径被拒绝(403 · 可能为受保护资源或访问控制)', base,
                            f'{len(_pages)} 条: {_prev(_pages)}')

    # 汇总日志 —— 旧实现"判定 0"完全静默(不产生任何记录),
    #   于是在 **catch-all 目标**(任意路径都回同一页面)上, 整个字典探测**全部**落进判定 0,
    #   使用者只看到"字典 36 条"然后什么都没有 —— **无法分辨"没找到"还是"根本判不了"**。
    #   这里明确交代: 测了几条 / 静默几条 / 排除几条 / 命中几条, 并点明 catch-all 的局限。
    _silent_note = ''
    if n_silent and bl is not None and bl.get('status') == 200:
        _silent_note = ('；随机 canary 路径也返回 200 → 该目标疑似 catch-all, '
                        '**无法用字典判定路径是否存在**')
    log(f'[*] hidden: 字典 {len(paths)} 条 → 命中 {n_found}, 已排除 {n_excl}, '
        f'与基线一致(无法判定) {n_silent}{_silent_note}')
