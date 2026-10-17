# -*- coding: utf-8 -*-
"""标准格式导出：SARIF 2.1.0 / Burp Site Map XML / OWASP ZAP JSON。

三者与 HTML/JSON 报告**同源**（都消费 `ctx.findings` + `ctx.all_found` + out/meta），
区别只在**交付形态**，便于把 facet 的发现接进既有工作流：

- **SARIF 2.1.0** → CI / 代码扫描平台（GitHub Code Scanning、DefectDojo、SonarQube 等）
  可直接消费的通用发现格式。
- **Burp Site Map XML** → 导入 Burp Suite 的 Target ▸ Site map（端点清单）。
- **OWASP ZAP JSON** → ZAP 报告视图的 alert 结构（按发现类型分组）。

**同源契约**（由 `verify/verify_e2e_offline.py` 门禁守护，勿破）：
  ① finding 集合 = `ctx.findings` 全量（与 JSON `findings.all` **逐条同数**；HTML 是**降噪展示子集**，
     只列高风险项 —— 两者定位不同，不是不一致）；
  ② 端点集合 ⊇ JSON `extracted_endpoints`（含**未探活候选**，`<status>` 留空以区分）；
  ③ **方法取 JS 声明**（与报告「方法」列同源），无声明留空 —— **不推断、不编造**。

合规：本工具**已移除全部脱敏** —— 导出内容（finding URL / 端点路径 / 证据）一律**原样**输出。
"""
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from .. import __version__
from ..output.paths import ensure_parent  # D5: 写入前确保父目录存在

# 严重度 → 各格式的等级映射
_SARIF_LEVEL = {'CRITICAL': 'error', 'HIGH': 'error', 'MED': 'warning',
                'LOW': 'note', 'INFO': 'note'}
_ZAP_RISK = {'CRITICAL': ('4', 'Critical'), 'HIGH': ('3', 'High'),
             'MED': ('2', 'Medium'), 'LOW': ('1', 'Low'), 'INFO': ('0', 'Informational')}
from ..core.dicts import SEV_ORDER as _SEV_ORDER  # 单一真源(审计 S11)


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


_BURP_DOW = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')
_BURP_MON = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
             'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')


def _now_burp():
    """Burp Site Map 时间戳(格式 `EEE MMM dd HH:mm:ss zzz yyyy`, **英文缩写**)。

    ⚠️ **不可用 `strftime('%a %b')`** —— `%a`/`%b` 依赖进程 `LC_TIME`, 非英文 locale 下
    会输出本地化缩写(实测 zh_CN→"一 10月" / de_DE→"Mo. Okt." / fr_FR→"lun. oct."),
    Burp 无法解析该时间。故用**固定英文缩写表**拼装(locale 无关); 另 `%Z` 在部分环境
    为空, 回退 `'UTC'` 以免出现双空格。
    """
    n = datetime.now()
    tz = n.astimezone().tzname() or 'UTC'
    return '%s %s %02d %02d:%02d:%02d %s %d' % (
        _BURP_DOW[n.weekday()], _BURP_MON[n.month - 1], n.day,
        n.hour, n.minute, n.second, tz, n.year)


def _sorted_findings(ctx):
    return sorted(getattr(ctx, 'findings', None) or [],
                  key=lambda x: _SEV_ORDER.get(x[0], 9))


def _rule_id(typ):
    """把（含中文/符号的）发现类型名规整为稳定 ruleId。"""
    s = re.sub(r'[^0-9A-Za-z]+', '-', (typ or 'finding')).strip('-').lower()
    return 'facet/' + (s or 'finding')


def _xml_cdata(s):
    """安全嵌入 CDATA（处理字符串内含 `]]>` 的边界情况）。"""
    return '<![CDATA[' + str(s or '').replace(']]>', ']]]]><![CDATA[>') + ']]>'


def _declared_methods(meta):
    """{归一化路径: 方法} —— **JS 声明**的方法(读+写), 与报告「方法」列**同源**。

    来源与 `_endpoint_master._js_method` 一致: `meta['api_methods']`(含 GET) 打底,
    `meta['write_apis']`(写方法) 覆盖同名。**无声明 → 不在表中** —— 调用方须输出
    "未知"而非编造(铁律: 方法零推断, 不拿探活充数)。
    """
    from ..core.dicts import normalize_endpoint
    out = {}
    for p, meth in ((meta or {}).get('api_methods') or {}).items():
        if p:
            out[normalize_endpoint(str(p).split('?')[0])] = str(meth or 'GET').upper()
    for p, meth in ((meta or {}).get('write_apis') or {}).items():
        if p:
            out[normalize_endpoint(str(p).split('?')[0])] = str(meth or 'POST').upper()
    return out


def _method_of(url, decl):
    """URL → JS 声明的方法; **无声明返回 `''`**(不推断)。"""
    from ..core.dicts import normalize_endpoint
    p = urlparse(str(url or '')).path or '/'
    return (decl or {}).get(normalize_endpoint(p), '')


def _split_ep(p):
    """端点 → `(path, query)` —— **剥 host**。

    提取结果(`meta['apis']`)可能是**完整 URL**, 而 `ctx.all_found` 是路径。旧实现直接
    `base + '/' + p` 拼接 → 遇到完整 URL 会得到**畸形 URL**
    (`https://x/https://x/api/x`), 导入 Burp 后是无效条目。统一先剥成路径再拼。
    """
    s = str(p or '').strip()
    if '://' in s:
        u = urlparse(s)
        return (u.path or '/'), (u.query or '')
    path, _, q = s.partition('?')
    if not path.startswith('/'):
        path = '/' + path
    return (path or '/'), q


def _endpoints(ctx, meta):
    """端点清单 `(路径[含 query], 方法, 状态码)` —— **与 JSON `extracted_endpoints` 同口径**。

    = 探活确认项(`ctx.all_found`, 优先, 带观测到的状态码) ∪ 提取到的候选
    (`apis` / `recomb` / JS 声明写操作)。未探活项的 status 为 `None` → Burp 中 `<status>`
    留空(不编造状态码), 分析员据此区分"已访问 / 待访问"。

    🔴 **修复**: 旧实现只在 `all_found` **完全为空**时才回落到 `apis` —— 一旦有任何探活结果,
    全部**未探活候选被静默丢弃**(JSON `extracted_endpoints` 有 N 条、Burp 只有 M 条),
    与「提取只增不减 / 报告须披露未探活候选」铁律相悖。方法取 **JS 声明**(同源报告"方法"列),
    无声明留空(不拿 GET 充数)。
    """
    eps, covered = [], set()
    decl = _declared_methods(meta)

    def _add(p, st):
        path, q = _split_ep(p)
        if not path:
            return
        disp = path + (('?' + q) if q else '')
        if disp in covered:                 # 同一路径只出一条(探活项先入, 候选不重复)
            return
        covered.add(disp)
        # 方法 = **JS 声明**(与报告「方法」列 / ZAP 同源); 无声明留空(不推断、不拿探活方法充数)。
        eps.append((disp, _method_of(path, decl) or '', st))

    for row in (getattr(ctx, 'all_found', None) or []):
        _add(row[0], (row[2] if len(row) > 2 else None))
    for p in sorted((meta or {}).get('apis', set()) or []):
        _add(p, None)
    for p in sorted((meta or {}).get('recomb', set()) or []):
        _add(p, None)
    for p in sorted(((meta or {}).get('write_apis') or {}).keys()):
        _add(p, None)
    return eps


# ------------------------------------------------------------------ SARIF
def write_sarif(ctx, base, path, meta=None):
    """SARIF 2.1.0 —— 通用静态分析结果格式。返回写入路径。"""
    fs = _sorted_findings(ctx)
    rules, seen, results = [], set(), []
    for sev, typ, url, ev in fs:
        rid = _rule_id(typ)
        if rid not in seen:
            seen.add(rid)
            rules.append({
                'id': rid,
                'name': typ,
                'shortDescription': {'text': typ},
                'defaultConfiguration': {'level': _SARIF_LEVEL.get(sev, 'warning')},
                'properties': {'severity': sev},
            })
        msg = f'[{sev}] {typ}'
        if ev:
            msg += f' — {ev}'
        results.append({
            'ruleId': rid,
            'level': _SARIF_LEVEL.get(sev, 'warning'),
            'message': {'text': msg},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': url or base},
                },
            }],
            'properties': {'severity': sev, 'target': base},
        })
    doc = {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {
                'name': 'facet',
                'version': __version__,
                'informationUri': 'https://facet.local',
                # 定位声明: 导出的是**只读侦察的发现级线索**, 非漏洞判定(SARIF 常被当"漏洞报告"读)。
                'properties': {'disclaimer': '只读侦察的发现级线索, 非漏洞判定; '
                                             '需人工在授权范围内复核。'},
                'rules': rules,
            }},
            'invocations': [{'executionSuccessful': True,
                             'endTimeUtc': _now_iso()}],
            'results': results,
        }],
    }
    ensure_parent(path)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return path


# ------------------------------------------------------------------ Burp
def write_burp(ctx, base, path, meta=None):
    """Burp Suite Site Map XML —— 导入 Target ▸ Site map 的端点清单。返回写入路径。"""
    u = urlparse(base)
    host = u.hostname or ''
    ssl = u.scheme == 'https'
    port = u.port or (443 if ssl else 80)
    protocol = 'https' if ssl else 'http'
    items = []
    for p, m, st in _endpoints(ctx, meta):
        # p 已由 `_endpoints` 归一化为**路径**(含 query), 故拼接一定得到合法 URL
        full = base.rstrip('/') + (p if str(p).startswith('/') else '/' + str(p))
        items.append(
            '  <item>\n'
            f'    <time>{_xml_cdata(_now_burp())}</time>\n'
            f'    <url>{_xml_cdata(full)}</url>\n'
            f'    <host ip="">{_xml_cdata(host)}</host>\n'
            f'    <port>{port}</port>\n'
            f'    <protocol>{protocol}</protocol>\n'
            f'    <method>{_xml_cdata(m)}</method>\n'
            f'    <path>{_xml_cdata(p)}</path>\n'
            f'    <status>{st if st is not None else ""}</status>\n'
            '    <responseLength>0</responseLength>\n'
            '    <mimetype></mimetype>\n'
            '  </item>'
        )
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           f'<items burpVersion="2024.1" exportTime="{_now_burp()}">\n'
           + '\n'.join(items) + '\n</items>\n')
    ensure_parent(path)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(xml)
    return path


# ------------------------------------------------------------------ ZAP
def write_zap(ctx, base, path, meta=None):
    """OWASP ZAP JSON 报告 —— 按发现类型分组为 alerts。返回写入路径。"""
    u = urlparse(base)
    host = u.hostname or ''
    ssl = u.scheme == 'https'
    port = u.port or (443 if ssl else 80)

    alerts = {}
    decl = _declared_methods(meta)
    for sev, typ, url, ev in _sorted_findings(ctx):
        riskcode, riskname = _ZAP_RISK.get(sev, ('0', 'Informational'))
        a = alerts.setdefault(typ, {
            'pluginid': _rule_id(typ),
            'alertRef': _rule_id(typ),
            'alert': typ,
            'name': typ,
            'riskcode': riskcode,
            'confidence': '2',
            'riskdesc': f'{riskname} (Medium)',
            'desc': typ,
            'instances': [],
        })
        a['instances'].append({
            'uri': url or base,
            # 🔴 修复: 旧实现**硬编码 'GET'** —— JS 声明为 PUT/DELETE 的端点被导出成 GET,
            #   与报告「方法」列(JS 声明为准)相悖, 且是**编造的信息**(比"未知"更糟)。
            #   现取 JS 声明方法; 无声明 → 空串(JSON 里 `""` 即"未知", 不编造)。
            'method': _method_of(url, decl),
            'evidence': ev or '',
        })
    doc = {
        '@version': __version__,
        '@generated': _now_iso(),
        'site': [{
            '@name': base,
            '@host': host,
            '@port': str(port),
            '@ssl': 'true' if ssl else 'false',
            'alerts': list(alerts.values()),
        }],
    }
    ensure_parent(path)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return path


# ------------------------------------------------------------------ 统一入口
_SUFFIX = {'sarif': '.sarif', 'burp': '.burp.xml', 'zap': '.zap.json'}
_WRITERS = {'sarif': write_sarif, 'burp': write_burp, 'zap': write_zap}


def write_exports(ctx, base, out_path, meta=None, formats=None):
    """按 formats 列表生成标准导出；返回实际写入的路径列表。

    out_path 为主报告路径（用于派生文件名）。

    🔴 未知格式**显式报错**(不静默跳过): `--export sraf` 这类笔误此前被 `continue` 吞掉
    —— 调用方以为导出了 N 种格式, 实际只有 N-1 种("声明了却不生效"家族, 审计复审新增)。

    本工具**已移除全部脱敏** —— 导出内容一律原样输出。
    """
    written = []
    stem = os.path.splitext(out_path)[0]
    for fmt in (formats or []):
        fmt = str(fmt).strip().lower()
        w = _WRITERS.get(fmt)
        if not w:
            raise ValueError(
                f'不支持的导出格式: {fmt!r}（仅支持 {sorted(_SUFFIX)}）')
        p = stem + _SUFFIX[fmt]
        try:
            w(ctx, base, p, meta)
            written.append(p)
        except Exception as e:
            # 单个导出失败不应影响主报告; 但**必须留痕** —— 此前 SARIF/Burp/ZAP
            # 静默少一种, 下游 CI/人工完全无感(审计 M)。
            from ..core.log import dbg
            dbg(f'导出 {fmt} 失败({p}): {e}')
            continue
    return written
