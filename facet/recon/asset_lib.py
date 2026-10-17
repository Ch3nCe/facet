# -*- coding: utf-8 -*-
"""跨目标资产库：把多次扫描的历史（`ScanHistory` SQLite）聚合成**统一视图**。

面向"我扫过哪些目标 / 每个目标暴露了什么 / 哪个问题在多个目标上重复出现"这类
**跨目标检索**，而非单次扫描报告。

设计：
- **只读历史库**，不发起任何网络请求（合规：纯本地检索）。
- 复用 `ScanHistory` 的 scans / apis / discovery / findings 四张表。
- 供 `facet/tools/asset_cli.py` 与自动化脚本调用。

诚实边界：资产库只反映**历史扫描当时的**结果；历史缺失 = 未覆盖，不等于目标无该资产。
"""
from ..core.dicts import SEV_TOKENS, norm_sev
from ..core.history import ScanHistory


def _history(path=None):
    return ScanHistory(path)


def list_targets(path=None):
    """所有扫描过的目标摘要。

    返回 [{base, scans, last_scan, latest_scan_id, findings, endpoints}]，按 base 排序。
    `findings` / `endpoints` 取自该目标**最近一次**扫描。
    """
    h = _history(path)
    rows = h.list_scans()          # 按时间倒序: [(scan_id, base, time, total_sent, version)]
    agg = {}
    for scan_id, base, t, _sent, _ver in rows:
        a = agg.get(base)
        if a is None:
            # 首见即最新（rows 倒序）
            agg[base] = {'base': base, 'scans': 1, 'last_scan': t,
                         'latest_scan_id': scan_id, 'findings': 0, 'endpoints': 0}
        else:
            a['scans'] += 1
    for a in agg.values():
        sid = a['latest_scan_id']
        a['findings'] = len(h.get_findings(sid))
        a['endpoints'] = len(h.get_discovery(sid))
    return sorted(agg.values(), key=lambda x: x['base'] or '')


def search_endpoints(path=None, base=None, grep=None, limit=500):
    """跨目标检索端点（全量发现集 discovery）。

    返回 [{base, path}]；base 精确过滤，grep 为路径子串（大小写不敏感）。
    """
    h = _history(path)
    rows = h.list_scans(base=base)
    g = (grep or '').lower()
    out = []
    for scan_id, b, _t, _s, _v in rows:
        for p in h.get_discovery(scan_id):
            if g and g not in (p or '').lower():
                continue
            out.append({'base': b, 'path': p})
            if len(out) >= limit:
                return out
    return out


def search_findings(path=None, base=None, sev=None, grep=None, limit=500):
    """跨目标检索发现。

    返回 [{base, scan_id, severity, type, url, evidence}]；sev 精确过滤，grep 匹配
    type/url/evidence 任一子串（大小写不敏感）。
    """
    h = _history(path)
    rows = h.list_scans(base=base)
    g = (grep or '').lower()
    # 严重度过滤接受**外部同义词**(MEDIUM/MODERATE→MED): 已知 token 经 `norm_sev` 归一;
    #   未知值**保持原样**(→ 诚实 0 命中), 不静默回落成 'MED'(否则 `--sev HIG` 会返回 MED, 更误导)。
    _sv = (sev or '').strip().upper() or None
    sev = norm_sev(_sv) if (_sv and _sv in SEV_TOKENS) else _sv
    out = []
    for scan_id, b, _t, _s, _v in rows:
        for s, typ, url, ev in h.get_findings(scan_id):
            if sev and (s or '').upper() != sev:
                continue
            if g and g not in f'{typ} {url} {ev}'.lower():
                continue
            out.append({'base': b, 'scan_id': scan_id, 'severity': s,
                        'type': typ, 'url': url, 'evidence': ev})
            if len(out) >= limit:
                return out
    return out


def shared_findings(path=None, min_targets=2, limit=100):
    """跨目标重复出现的问题类型 —— 同一 finding 类型出现在 ≥min_targets 个不同目标上。

    用于识别"共性问题"（如某中间件默认暴露、某类信息泄露普遍存在）。
    返回 [{type, targets: [base...], count}]，按目标数倒序。
    """
    h = _history(path)
    rows = h.list_scans()
    seen = {}   # type -> set(base)
    for scan_id, b, _t, _s, _v in rows:
        for _s, typ, _u, _e in h.get_findings(scan_id):
            seen.setdefault(typ, set()).add(b)
    out = [{'type': t, 'targets': sorted(bs), 'count': len(bs)}
           for t, bs in seen.items() if len(bs) >= min_targets]
    return sorted(out, key=lambda x: (-x['count'], x['type']))[:limit]
