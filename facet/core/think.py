# -*- coding: utf-8 -*-
"""思考层(规划器) —— CLI 优先 · 能力/上下文/模型全动态 · 建议式(不驱动主流程)。

三条设计约束(用户明确):
  1. 只做 CLI 端(不碰 MCP)。
  2. 任何内容都不写死: 能力清单从**插件注册表**动态派生(新增插件自动出现);
     上下文从**本次扫描的实测信号**动态采集; 推理后端**可插拔**(默认纯本地,
     配置了 LLM 端点才切换)。
  3. 只出"计划"(建议式) —— 不改主流程、不改判定、不发起任何目标请求。

合规:
  · 默认纯本地: 零外部依赖、离线可用、零发包。
  · LLM 后端为**显式 opt-in**(需同时配置 llm_base_url + llm_api_key); 只发送**本次扫描
    已观测到的聚合信号**(端点计数/指纹/JS 统计等)与**目标标识(target)** —— 后者用于让
    模型结合目标形态给建议; **不含原始响应体、不含凭据**(审计: 外发内容含 target 须明示)。
    启用时在计划里打印合规告警。走 urllib 直连 —— 它不是目标请求, 不经目标 REQ/限速/scope 护栏。
  · 产出恒标"发现级 · 建议 · 非漏洞判定"。
"""
from __future__ import annotations

import json
import urllib.request

_DISCLOSURE = '发现级 · 建议 · 非漏洞判定 · 不驱动主流程'


def capabilities(cfg=None):
    """动态能力清单 —— 从插件注册表派生(不写死任何模块名; 新增插件自动出现)。"""
    try:
        from . import plugins
        return plugins.list_plugins(cfg or {})
    except Exception as e:
        # 注册表读取失败静默返回 [] → 计划渲染成"启用 0 · 未启用 0", 误导为空注册表(审计 L)。
        from .log import dbg
        dbg(f'think.capabilities 读取插件注册表失败: {e}')
        return []


def collect_signals(report):
    """从扫描 JSON 报告**动态**提取聚合信号(纯读, 零发包)。"""
    r = report if isinstance(report, dict) else {}
    s = r.get('summary') or {}
    comp = r.get('completeness') or {}
    rt = comp.get('runtime') or {}
    trunc = comp.get('truncated') or {}
    silent = comp.get('silent_js') or {}
    cov = r.get('coverage') or {}
    # findings 在 JSON 报告里是 **dict**(by_category/other/all) —— 按 list 迭代只会得到
    #   字符串键, sev_dist 恒空(历史缺陷: findings 结构变更后此处漏改)。两种形态都兼容。
    _fnd_raw = r.get('findings')
    findings = (_fnd_raw.get('all', []) if isinstance(_fnd_raw, dict)
                else (_fnd_raw or []))
    eps = r.get('endpoints') or []

    def _i(v):
        try:
            return int(v)
        except Exception:
            return 0

    # 带参端点数: 直接从逐端点 params(path/query/body)现算 —— param_dimension 字段
    #   已随模块移除(用户要求), 不再依赖它(空报告时同样得 0)。
    _n_eps_with_params = sum(
        1 for e in eps if isinstance(e, dict)
        and any((e.get('params') or {}).get(k) for k in ('path', 'query', 'body')))

    src_dist = {}
    for e in eps:
        if isinstance(e, dict):
            for src in (e.get('sources') or []):
                src_dist[src] = src_dist.get(src, 0) + 1
    sev_dist = {}
    for f in findings:
        if isinstance(f, dict):
            k = str(f.get('severity') or '')
            sev_dist[k] = sev_dist.get(k, 0) + 1
    by_reason = silent.get('by_reason') or {}

    return {
        'target': r.get('target') or '',
        'endpoints': _i(s.get('api_candidates')) or len(eps),
        'live_endpoints': _i(s.get('live_endpoints')),
        'js_files': _i(s.get('js_files')),
        'frontend_routes': _i(s.get('frontend_routes')),
        'write_apis': _i(s.get('write_apis')),
        'subdomains': _i(s.get('subdomains')),
        'dict_candidates': _i(s.get('dict_candidates')),
        'runtime_requested': bool(rt.get('requested')),
        'runtime_ran': bool(rt.get('ran')),
        'js_queue_unscanned': _i(trunc.get('js_queue_unscanned')),
        'silent_js_n': _i(silent.get('n')),
        'silent_js_obf': _i(sum(v for k, v in by_reason.items()
                                if '解包' in str(k) or 'obf' in str(k).lower())),
        'circuit_tripped': bool(comp.get('circuit_tripped')),
        'param_rows': len(r.get('param_table') or []),
        'endpoints_with_params': _n_eps_with_params,
        'disabled_features': [d.get('name') for d in (cov.get('disabled_features') or [])
                              if isinstance(d, dict)],
        'endpoint_sources': src_dist,
        'findings_severity': sev_dist,
    }


def _reason_local(sig, caps):
    """本地动态推理: 从目标**实测信号**派生建议(无站点/模块硬编码; 能力清单来自注册表)。"""
    items = []

    def add(kind, action, why):
        items.append({'kind': kind, 'action': action, 'why': why})

    if sig['js_queue_unscanned'] > 0:
        add('js_coverage', 'deepen',
            f"JS 队列仍有 {sig['js_queue_unscanned']} 个未扫 —— 建议提高 max_js 或 --resume 续扫")
    if sig['silent_js_obf'] > 0:
        add('deobf', 'consider',
            f"{sig['silent_js_obf']} 个 JS 命中混淆/解包链 —— 可评估强反混淆/动态解包(opt-in)")
    if sig['runtime_requested'] and not sig['runtime_ran']:
        add('runtime', 'fix', '运行时通道已请求但未运行 —— 检查 Playwright/浏览器可用性')
    elif not sig['runtime_requested'] and sig['js_files'] >= 8 and sig['endpoints'] <= 2:
        add('runtime', 'consider', 'JS 多而端点少(疑似客户端渲染) —— 建议启用运行时通道')
    if sig['write_apis'] > 0:
        add('write_guard', 'keep', f"{sig['write_apis']} 个写接口 —— 保持只读提取, 不发送验证包")
    if sig['endpoints'] > 0 and sig['endpoints_with_params'] == 0:
        add('param_link', 'consider', '有端点但参数关联为 0 —— 建议复核 schema/调用点证据是否充分')
    if sig['circuit_tripped']:
        add('stability', 'review', '本轮触发熔断 —— 建议降低速率或避开高峰重扫')
    if not sig['runtime_requested'] and sig['js_files'] == 0:
        add('coverage', 'review', '未发现任何 JS —— 目标可能是静态站或首页抓取失败, 建议复核入口')

    disabled = sorted(c['name'] for c in caps if not c.get('enabled'))
    if disabled:
        add('registry', 'review', '注册但当前未启用的能力: ' + ', '.join(disabled))
    return items


_SYSTEM_PROMPT = (
    '你是 Web 攻击面侦察工具的"规划器"。基于给定的目标实测信号与能力清单, 产出一份'
    '**只读、合规、发现级**的下一步扫描计划。硬约束: 绝不建议发送写请求/攻击载荷/漏洞验证; '
    '只建议"在只读范围内如何提高覆盖与证据质量"。输出 JSON 数组, 每项 '
    '{"kind": 短标签, "action": 建议动作, "why": 理由}。不要输出多余文字。'
)


def _build_prompt(sig, caps):
    payload = {
        'signals': sig,
        'capabilities': [{'stage': c['stage'], 'name': c['name'],
                          'desc': c['desc'], 'enabled': c.get('enabled')} for c in caps],
    }
    return ('目标实测信号与能力清单(JSON):\n'
            + json.dumps(payload, ensure_ascii=False)
            + '\n\n请据此产出下一步只读扫描计划(JSON 数组)。')


def _llm_ready(cfg):
    cfg = cfg or {}
    return bool(str(cfg.get('llm_base_url') or '').strip()
                and str(cfg.get('llm_api_key') or '').strip())


def _parse_plan(content):
    txt = str(content or '').strip()
    if txt.startswith('```'):
        txt = txt.strip('`').strip()
        if '\n' in txt:
            txt = txt.split('\n', 1)[1]
    try:
        data = json.loads(txt)
    except Exception:
        return [{'kind': 'llm', 'action': 'note', 'why': txt[:500]}] if txt else None
    if isinstance(data, dict):
        data = data.get('plan') or data.get('items') or [data]
    # 条数封顶(审计 OBS): LLM 异常输出(上万条)不可撑爆本地渲染 —— 截断并披露。
    _MAX_PLAN = 50
    _n_items = len(data) if isinstance(data, list) else 0
    out = []
    for it in ((data[:_MAX_PLAN]) if isinstance(data, list) else []):
        if isinstance(it, dict):
            out.append({'kind': str(it.get('kind') or ''),
                        'action': str(it.get('action') or ''),
                        'why': str(it.get('why') or '')})
        elif isinstance(it, str):
            out.append({'kind': 'llm', 'action': 'suggest', 'why': it})
    if _n_items > _MAX_PLAN:
        out.append({'kind': 'llm', 'action': 'note',
                    'why': f'计划条目过多({_n_items} 条), 已截断至前 {_MAX_PLAN} 条'})
    return out or None


def _reason_llm(sig, caps, cfg):
    """可选 LLM 后端: 把聚合信号 + 能力清单交 LLM 产出计划。失败返回 None(降级本地)。"""
    base = str(cfg.get('llm_base_url') or '').strip().rstrip('/')
    key = str(cfg.get('llm_api_key') or '').strip()
    model = str(cfg.get('llm_model') or '').strip()
    if not base or not key:
        return None
    try:
        timeout = float(cfg.get('llm_timeout') or 30)
    except Exception:
        timeout = 30
    body = json.dumps({
        'model': model or 'default',
        'temperature': 0,
        'messages': [
            {'role': 'system', 'content': _SYSTEM_PROMPT},
            {'role': 'user', 'content': _build_prompt(sig, caps)},
        ],
    }).encode('utf-8')
    req = urllib.request.Request(
        base + '/chat/completions', data=body, method='POST',
        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8', 'replace'))
        content = ((data.get('choices') or [{}])[0].get('message') or {}).get('content') or ''
        return _parse_plan(content)
    except Exception:
        return None


def plan(report, cfg=None):
    """产出"思考计划"(建议式)。默认本地推理; 配置了 LLM 端点则切换, 失败自动降级。"""
    cfg = cfg or {}
    caps = capabilities(cfg)
    sig = collect_signals(report)
    backend = 'local'
    notice = ''
    items = None
    if _llm_ready(cfg):
        items = _reason_llm(sig, caps, cfg)
        if items:
            backend = 'llm'
            notice = ('LLM 推理: 已把本次扫描的**聚合信号**(不含原始响应体/凭据)'
                      '发送至配置的 LLM 端点')
        else:
            notice = 'LLM 推理不可用, 已降级为本地推理'
    if not items:
        items = _reason_local(sig, caps)
    return {
        'backend': backend,
        'notice': notice,
        'signals': sig,
        'capabilities': [{'stage': c['stage'], 'name': c['name'], 'enabled': c.get('enabled')}
                         for c in caps],
        'plan': items,
        'disclosure': _DISCLOSURE,
    }


def render_plan_text(plan_obj):
    """把计划渲染为控制台文本。"""
    p = plan_obj or {}
    lines = ['', '── 思考计划 (建议式 · 发现级 · 非漏洞判定) ──',
             f'  推理后端: {p.get("backend")}']
    if p.get('notice'):
        lines.append(f'  [!] {p.get("notice")}')
    sig = p.get('signals') or {}
    lines.append(
        f'  实测信号: 端点 {sig.get("endpoints")} · 存活 {sig.get("live_endpoints")} · '
        f'JS {sig.get("js_files")} · 写接口 {sig.get("write_apis")} · '
        f'运行时 {"已运行" if sig.get("runtime_ran") else "未运行"}')
    caps = p.get('capabilities') or []
    off = [c['name'] for c in caps if not c.get('enabled')]
    lines.append(f'  能力(注册表动态): 启用 {len(caps) - len(off)} · 未启用 {len(off)}'
                 + (f' → 未启用: {", ".join(off)}' if off else ''))
    lines.append('  下一步建议:')
    plan_items = p.get('plan') or []
    for it in plan_items:
        lines.append(f'    · [{it.get("kind")}/{it.get("action")}] {it.get("why")}')
    if not plan_items:
        lines.append('    (无)')
    return '\n'.join(lines)
