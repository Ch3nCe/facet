# -*- coding: utf-8 -*-
"""敏感信息扫描 / URL 泄露 / 可选密钥验证 / JWT 解析 —— 从 `core/engine.py` 拆出（便于维护）。"""
import base64
import json
import os
import re
from urllib.parse import parse_qsl, urlparse

from facet.core.log import log

from .const import _RULE_TO_PROVIDER, _SECRET_PROVIDERS, _SECRET_RULES_CACHE
from .dicts import (
    BENIGN_WELLKNOWN,
    SENSITIVE_FIELDS,
    SENSITIVE_FILTERS,
    SENSITIVE_PATTERNS,
    SOURCE_ONLY_SECRET_RULES,
    URL_SECRET_PARAM_KW,
    load_external_secret_db,
)

# ---------- 颜色引擎 ----------
# 注: `Color` / `clog` / `log` / `dbg` 已**下沉**到 `core/log.py`(供 report/recon 等下层
#   直接引用, 避免向上依赖)。engine 仅 import 自身用到的符号; 外部请从 core.log 导入,
#   不要经 engine 中转。

# ---------- JWT 三段校验 （减少误报） ----------
def _b64url_decode(seg):
    """base64url 段解码(自动补足 padding)

    """
    s = seg + '=' * (-len(seg) % 4)
    return base64.urlsafe_b64decode(s)


def _jwt_is_valid(token):
    """验证JWT三段结构: header 解码后应为合法JSON. 允许第三段为空(alg=none场景)"""
    parts = token.split('.')
    # 至少要有 header + payload 两段, 第三段(signature)可以为空
    if len(parts) < 2:
        return False
    try:
        hdr = _b64url_decode(parts[0])
        d = json.loads(hdr)
        return isinstance(d, dict) and ('alg' in d or 'typ' in d)
    except Exception:
        return False   # 畸形 JWT 静默跳过(少报方向); 排障需要时开 FACET_DEBUG


def _jwt_is_none_alg(token):
    """检测 JWT alg=none 漏洞: header 中 alg 为 'none' 或 'None'"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        hdr = _b64url_decode(parts[0]).decode('utf-8', 'ignore')
        d = json.loads(hdr)
        alg = d.get('alg', '').lower()
        return alg == 'none'
    except Exception:
        return False   # 同上: 畸形 JWT 视为"非 none"(少报方向)


def _looks_like_placeholder(v):
    """判断值是否为 JS/模板**占位符**(不是真实凭据), 如 `:r` / `${x}` / `{{x}}` / `<TOKEN>`。"""
    v = (v or '').strip()
    if not v:
        return True
    if v.startswith((':', '${', '{{', '<', '%')) or v.endswith(('}', '>', '%')):
        return True
    return bool(re.fullmatch(r'[:<>{}%$*_\-\s]+', v))


def _check_url_leak(ctx, url):
    """URL query 参数中是否泄露 token/key 等**真实**凭据。

    实测(真实站点): JS 里派生的模板 URL(`.../submit?universe=:n&token=:r`)会被抽成候选,
    其中 `token` 的值是**占位符** `:r`(长度 2)。旧实现只要键名命中就报 HIGH, 属**误报**。
    这里要求值"看起来像真实凭据": 非占位符, 且长度 ≥ 8。

    敏感参数名判据**单一事实来源**: 直接复用 `dicts.URL_SECRET_PARAM_KW` —— 旧实现在此
    **另写一份**硬编码集合、与 `dicts` 各写各的; 现统一为单一来源, 避免漂移。
    """
    try:
        for k, v in parse_qsl(urlparse(url).query):
            if k.lower() not in URL_SECRET_PARAM_KW or not v:
                continue
            if _looks_like_placeholder(v) or len(v) < 8:
                continue
            ctx.add_finding('HIGH', f'URL参数泄露敏感信息({k})', url, f'参数值长度 {len(v)}')
    except Exception:
        pass


# 常见"公开且正常"的 well-known 文件 —— 它们存在属正常, **不等于**"隐藏接口暴露"。
#   实测(真实站点): 字典里的 `/manifest.json`(PWA 清单)探活 200 → 旧实现报 MED"隐藏接口暴露",
#   属**误报**。命中这些路径时降级为 INFO。
def _is_benign_wellknown(path):
    # 数据层单一事实来源: dicts.BENIGN_WELLKNOWN(不在本文件硬编码)。
    p = (path or '').lower().split('?')[0].rstrip('/')
    return any(p == x or p.endswith(x) for x in BENIGN_WELLKNOWN)


def _scan_sensitive_block(ctx, text, src, allow_source_only=True):
    """对一段文本跑敏感规则, 命中则记 finding(HTML 隐藏域 / 注释复用, 与 deep_analyze 同源规则)。

    allow_source_only: 是否允许"源码专用规则"(如 `硬编码用户名`)。
        False 用于**响应体派生文本**(HTML 隐藏域 / 注释 / 内联脚本 / 页面 HTML) ——
        数据接口里 `username`/`account` 是每条记录的普通字段, 非硬编码凭证(见
        dicts.SOURCE_ONLY_SECRET_RULES 的设计意图); True 用于 JS / 源码文件扫描。
    """
    _hits = getattr(ctx, 'secret_hits', None)
    # 同一命中值只报**一次**(全库审计 M17): `ya29.` / `sk_live_` / Google vs Firebase
    #   等形态被多条规则覆盖 —— 同一密钥曾产出 2-3 条重复 HIGH。以**最先命中**的规则
    #   命名(表序即优先级), 后续规则对同一串不再重复上报。
    _seen_vals = set()
    for name, pat, sev in _load_secret_rules(getattr(ctx, 'config', None)):
        # 源码专用规则(如 `硬编码用户名`)不用于**响应体派生文本** —— 响应里 username
        #   是普通数据字段, 误报为"凭据泄露"会严重高估严重度(见 dicts.SOURCE_ONLY_SECRET_RULES)。
        if (not allow_source_only) and name in SOURCE_ONLY_SECRET_RULES:
            continue
        for m in pat.finditer(text):
            ev = m.group(0)
            if name.startswith('JWT'):
                if not _jwt_is_valid(ev):
                    continue
                if _jwt_is_none_alg(ev):
                    # 措辞: 只陈述"令牌 alg=none 这一**事实**", 不判定"漏洞成立" ——
                    #   是否可利用取决于服务端是否接受 alg=none, 本工具不验证。
                    # 证据打码: 与下方常规密钥发现同一口径(此前的 ev[:60] 是令牌 base64
                    #   明文前缀, 可解码出 header/payload —— 全库审计 H4)。
                    _jwt_ev = ev[:60].replace('\n', ' ')
                    ctx.add_finding('CRITICAL', '信息泄露-JWT(alg=none·疑似, 需人工确认)',
                                    src, _jwt_ev)
                    from .js_lex import note_finding_loc as _nfl
                    _nfl(ctx, ('CRITICAL', '信息泄露-JWT(alg=none·疑似, 需人工确认)', src, _jwt_ev),
                         text, [ev])
                    _seen_vals.add(ev)
                    continue
            if len(set(ev)) < 3:
                continue
            if ev in _seen_vals:
                continue
            _seen_vals.add(ev)
            filt_fn = SENSITIVE_FILTERS.get(name)
            eff_sev = sev
            if filt_fn:
                check_val = m.group(m.lastindex) if m.lastindex else ev
                fr = filt_fn(check_val)
                if fr is False:
                    continue
                elif fr == 'critical':
                    eff_sev = 'CRITICAL'
                elif fr == 'med':
                    eff_sev = 'MED'
            _sev_ev = ev[:60].replace('\n', ' ')
            ctx.add_finding(eff_sev, f'敏感信息-{name}', src, _sev_ev)
            from .js_lex import note_finding_loc as _nfl
            _nfl(ctx, (eff_sev, f'敏感信息-{name}', src, _sev_ev), text, [ev])
            # 保留完整值供 verify_secrets 实时验证(仅内存, 不落报告)
            #   封顶(审计 OBS): 无上限列表在超大响应多命中时内存无界。
            if _hits is not None and len(_hits) < 5000:
                _hits.append((name, ev, src))


def _provider_for_rule(name):
    return _RULE_TO_PROVIDER.get(name)


def _render_header_tmpl(hdr_tmpl, value):
    """安全渲染含 `{v}` 的 header 模板。

    旧实现用 `tmpl.format(v=value)` —— 若密钥值本身含 `{`/`}`(罕见但真实存在),
    会抛 `ValueError` 被外层吞掉, 导致**真实密钥被误判 `unknown`**(既不报有效也不报无效)。
    改用 `replace('{v}', value)` 规避 format 解析, 值里的花括号不再触发异常。
    """
    out = {}
    for k, tmpl in hdr_tmpl.items():
        try:
            out[k] = tmpl.replace('{v}', value) if '{v}' in tmpl else tmpl
        except Exception:
            out[k] = tmpl
    return out


def _verify_one_secret(provider, value, ctx):
    """对单条密钥做只读验证, 返回 'valid' / 'invalid' / 'unknown'。"""
    from .http import REQ
    spec = _SECRET_PROVIDERS.get(provider)
    if not spec:
        return 'unknown'
    method, url, hdr_tmpl, status_map = spec
    headers = _render_header_tmpl(hdr_tmpl, value)
    try:
        # 语义只读的第三方校验(端点表见 const._SECRET_PROVIDERS; slack 条目为 POST,
        #   故显式声明 readonly_post 供只读护栏放行 —— 不修改任何远端资源)。
        r = REQ(ctx, method, url, headers=headers, readonly_post=True)
    except Exception as e:
        from .log import dbg
        dbg(f'密钥实时验证({provider})网络异常: {e}')
        return 'unknown'
    if r is None:
        return 'unknown'
    code = getattr(r, 'status_code', 0)
    if provider == 'slack' and code == 200:
        try:
            return 'valid' if r.json().get('ok') else 'invalid'
        except Exception:
            return 'unknown'
    return status_map.get(code, 'unknown')


def _verify_secrets_pass(ctx, base):
    """遍历已发现的密钥, 按 provider 做只读验证, 升级/降级结论。返回 (有效, 无效, 未知)。"""
    hits = getattr(ctx, 'secret_hits', None) or []
    if not hits:
        return 0, 0, 0
    done = set()
    n_valid = n_invalid = n_unknown = 0
    for name, value, src in hits:
        prov = _provider_for_rule(name)
        if not prov:
            continue
        key = (name, value)          # 同一密钥只验证一次(避免重复发包/限速)
        if key in done:
            continue
        done.add(key)
        res = _verify_one_secret(prov, value, ctx)
        if res == 'valid':
            n_valid += 1
            ctx.add_finding('CRITICAL', f'密钥实时验证-有效({prov})', src,
                            f'{name} [{value[:4]}…] 经验证真实有效(已向 {prov} 发起只读验证)')
        elif res == 'invalid':
            n_invalid += 1
            ctx.add_finding('INFO', f'密钥实时验证-无效({prov})', src,
                            f'{name} [{value[:4]}…] 验证失败(401/ok:false), 疑似示例/已吊销/误报')
        else:
            n_unknown += 1
    if n_valid or n_invalid:
        log(f'[*] 密钥实时验证: 有效 {n_valid} / 无效 {n_invalid} / 未知 {n_unknown}')
    return n_valid, n_invalid, n_unknown


# ---------- 敏感信息响应扫描 (增强) ----------
def has_sensitive_v45(text):
    """扫描响应体中的敏感字段**键值对**(JSON / XML / HTML data-*)。

    ⚠️ 判定收紧(真实站点误报修正): 仅当"**字段名 + 非空值**成对出现"才计命中
    (见旧版说明)。本版**增强输出**: 不再只回类别名, 而是返回带"脱敏特征片段"的
    结构化命中 [{field, category, snippet}], 其中 snippet = `字段名:"脱敏值"`
    (如 `phone:"138****5678"`)。这样既暴露"泄露出现在哪个字段、什么形状", 又绝不
    在 findings / 报告 / diff 交付物里回显明文 —— 与 --redact 同口径。

    返回: list[dict], 去重(同字段同类别只记一次)。
    """
    if not text:
        return []
    hits = []
    seen = set()

    def _add(field, category, value):
        key = (field, category)
        if key in seen:
            return
        seen.add(key)
        snip = '{}:"{}"'.format(field, value)
        hits.append({'field': field, 'category': category, 'snippet': snip})

    _ph = {'', 'null', 'undefined', 'none', 'true', 'false', '***', '...', 'password', 'example'}

    def _val_ok(v):
        v = (v or '').strip()
        return len(v) >= 3 and v.lower() not in _ph

    def _scan(name, value):
        if not _val_ok(value):
            return
        nl = name.lower()
        for f in SENSITIVE_FIELDS:
            if f in nl:
                _add(name, f, value)
                break  # 一个字段只归一个最匹配类别, 避免重复计数

    # JSON: "field": "value"
    for m in re.finditer(r'"([A-Za-z_][\w\-]{1,40})"\s*:\s*"([^"]{1,300})"', text):
        _scan(m.group(1), m.group(2))
    # XML: <field>value</field>
    for m in re.finditer(r'<([A-Za-z_][\w\-]{1,40})>([^<>]{1,300})</\1>', text):
        _scan(m.group(1), m.group(2))
    # HTML data-*
    for m in re.finditer(r'data-([a-z\-]{2,40})="([^"]{1,300})"', text):
        _scan(m.group(1), m.group(2))
    return hits


def scan_response_secrets(ctx, url, text):
    """用完整密钥正则库扫描**响应体** 

    `has_sensitive_v45()` 只做 SENSITIVE_FIELDS 关键词匹配(id_card/phone/password…),
    因此响应体里的**结构化机密**全部漏报 —— 数据库连接串(`mysql://root:pw@10.0.0.1/db`)、
    云平台 AK、JWT、Bearer 令牌、内网地址… 这些恰恰是接口响应泄露里最严重的一类,
    而且一条 `mysql://` 就等于整个数据层失守。

    这里复用 JS 分析阶段**同一条** SENSITIVE_PATTERNS 规则链(含误报过滤器与 JWT
    三段校验), 保证两侧判定口径完全一致 —— 否则同一个字符串在 JS 里算发现、
    在响应里不算, 会让报告自相矛盾。

    仅扫描 ≤200KB 的响应, 避免对超大响应跑 40 条正则造成明显开销。
    """
    if not text or len(text) > 200000:
        return 0
    n = 0
    for name, pat, sev in _load_secret_rules(getattr(ctx, 'config', None)):
        # 源码专用规则(如 `硬编码用户名`)不用于**响应体数据** —— 数据接口里 username 是
        #   每条记录的普通字段, 非硬编码凭证(实测 jsonplaceholder /users 被误报 10 条)。
        if name in SOURCE_ONLY_SECRET_RULES:
            continue
        for m in pat.finditer(text):
            ev = m.group(0)
            if name.startswith('JWT') and not _jwt_is_valid(ev):
                continue
            if len(set(ev)) < 3:
                continue
            eff = sev
            filt = SENSITIVE_FILTERS.get(name)
            if filt:
                val = m.group(m.lastindex) if m.lastindex else ev
                fr = filt(val)
                if fr is False:
                    continue
                if fr == 'critical':
                    eff = 'CRITICAL'
                elif fr == 'med':
                    eff = 'MED'
            # 不再脱敏: 命中值**原样**写入 findings/报告/导出(本工具已移除全部脱敏)。
            _resp_ev = f'{name}: {ev}'
            ctx.add_finding(eff, f'响应体泄露-{name}', url, _resp_ev)
            from .js_lex import note_finding_loc as _nfl
            _nfl(ctx, (eff, f'响应体泄露-{name}', url, _resp_ev), text, [ev])
            n += 1
    return n


def _load_secret_rules(config):
    """内置敏感规则 + 外部规则库(--secret-db) 合并(按路径缓存)。

    与 `_load_fingerprints` 同构 —— **内置保留、外部追加**(不覆盖), 便于按业务补充私有密钥格式。
    """
    path = (config or {}).get('secret_db')
    if not path:
        return SENSITIVE_PATTERNS
    if path in _SECRET_RULES_CACHE:
        return _SECRET_RULES_CACHE[path]
    merged = list(SENSITIVE_PATTERNS)
    if os.path.exists(path):
        try:
            # R6: 自动识别内置 JSON 与 HaE 原生 YAML(同为外部追加, 不覆盖内置规则)
            from .dicts import load_secret_db_any
            ext, _fmt = load_secret_db_any(path)
            merged = merged + ext
            log(f'已加载外部敏感规则库: {path} ({len(ext)} 条'
                + (f' · HaE 原生格式' if _fmt == 'HaE' else '') + ')')
        except Exception as e:
            log(f'[-] 外部敏感规则库加载失败: {e}')
    _SECRET_RULES_CACHE[path] = merged
    return merged
