# -*- coding: utf-8 -*-
"""参数总表（弱项② 深化）：把散落在多处的**参数信息汇聚成一张表**。

数据来源（全部只读、零发包）：
- `meta['schema_params']`：OpenAPI/GraphQL 解析出的**类型 / 位置(in) / 必填**（最准）。
- `ctx.pmap`：JS/HTML/URL 提取到的参数名。
- `ctx.param_shapes`：运行时(浏览器)捕获的**取值形态**（只记形态、不含原值）。
- `matrix['param_intent_index']`：IDOR / SQLi / SSRF 命名意图（跨端点聚合）。
- `meta['params']`：全局提取的参数名（无归属证据 → 显式标注「未归属接口」，不臆造关联）。

目的：把"该测哪个参数、是什么类型、必不必填、出现在哪些接口、观测到什么形态"
收敛到一行，**省去人工从接口逐个捞参数**。仍是发现级线索，不验证、不打 payload。
"""
import html as _html

_INTENT_LABEL = {'idor': '越权/IDOR', 'sqli': '注入/SQLi', 'ssrf': 'SSRF'}
_SRC_LABEL = {'schema': 'schema', 'js': 'js', 'runtime': 'runtime',
               'global': '全局·未归属'}
_MAX_ROWS = 80


class _CappedRows(list):
    """携带 `total`(截断前总数)的行列表 —— 供渲染层如实披露截断。"""
    total = None


def build_param_table(ctx, meta, matrix=None):
    """汇聚全量参数 → 行列表（按 意图命中 → 端点数 → 名称 排序）。

    返回: [{'name','types':[...],'locations':[...],'required':bool,'intents':[...],
            'shapes':[...],'endpoints':[...],'endpoint_count':int,'sources':[...]}]
    """
    meta = meta or {}
    matrix = matrix or {}
    pmap = getattr(ctx, 'pmap', None) or {}
    shapes_map = getattr(ctx, 'param_shapes', None) or {}
    schema_params = meta.get('schema_params') or {}
    idx = matrix.get('param_intent_index') or {}

    rows = {}

    def _row(name):
        r = rows.get(name)
        if r is None:
            r = rows[name] = {'name': name, 'types': set(), 'locations': set(),
                              'required': False, 'intents': set(), 'shapes': set(),
                              'endpoints': set(), 'sources': set(), 'taints': set()}
        return r

    # 1) schema：类型 / 位置 / 必填（最准，先入）
    for path, sm in schema_params.items():
        if not isinstance(sm, dict):
            continue
        for p in (sm.get('params') or []):
            if not isinstance(p, dict) or not p.get('name'):
                continue
            r = _row(str(p['name']))
            if p.get('type'):
                r['types'].add(str(p['type']))
            if p.get('in'):
                r['locations'].add(str(p['in']))
            if p.get('required'):
                r['required'] = True
            r['endpoints'].add(path.split('?')[0])
            r['sources'].add('schema')

    # 2) pmap：参数名
    for path, names in pmap.items():
        for n in (names or set()):
            if not n:
                continue
            r = _row(str(n))
            r['endpoints'].add(path.split('?')[0])
            r['sources'].add('js')

    # 3) 运行时取值形态（只记形态）
    for path, pd in shapes_map.items():
        for n, sh in (pd or {}).items():
            if not n:
                continue
            r = _row(str(n))
            r['shapes'] |= set(sh or set())
            r['endpoints'].add(path.split('?')[0])
            r['sources'].add('runtime')

    # 4) 意图索引
    for dim, bucket in idx.items():
        for n, info in (bucket or {}).items():
            r = _row(str(n))
            r['intents'].add(dim)
            r['shapes'] |= set((info or {}).get('shapes') or [])
            for ep in ((info or {}).get('endpoints') or []):
                r['endpoints'].add(str(ep).split('?')[0])

    # 5) 全局提取参数(meta['params'] = 原始 out['params'] 集合): 那些**静态提取到、
    #    但无调用点 / schema 证据归属到具体接口**的参数。零推断 —— 不臆造它们属于哪个端点,
    #    仅显式标注「未归属接口」, 让"已提取但未关联"的参数也可见、可审计。
    #    此前这批参数整批消失: 不进 ctx.pmap、不进本表、也不序列化进 JSON(只用于"参数维度"计数)。
    #    已在 pmap/schema/shapes/intent 中拥有归属的参数不重复建行(保持其端点关联)。
    for n in (meta.get('params') or set()):
        if not n or n in rows:
            continue
        r = _row(str(n))
        r['sources'].add('global')

    # 6) R3 参数值来源(轻量污点): meta['param_taint'] = {path: {param: {kind,symbol,hops}}}
    for path, pm in (meta.get('param_taint') or {}).items():
        if not isinstance(pm, dict):
            continue
        for pn, tt in pm.items():
            if not pn or not isinstance(tt, dict):
                continue
            r = _row(str(pn))
            if tt.get('label'):
                r['taints'].add(str(tt['label']))
            r['taint_symbol'] = str(tt.get('symbol') or '')[:80]
            r['endpoints'].add(path.split('?')[0])

    out = []
    for r in rows.values():
        eps = sorted(r['endpoints'])
        out.append({
            'name': r['name'],
            'types': sorted(r['types']),
            'locations': sorted(r['locations']),
            'required': r['required'],
            'intents': sorted(r['intents']),
            'shapes': sorted(r['shapes']),
            'endpoints': eps,
            'endpoint_count': len(eps),
            'unlinked': not eps,
            'sources': sorted(r['sources']),
            # R3: 值来源(轻量污点标签)与代表符号(如 `res.data.user_id`); 无则空
            'value_sources': sorted(r['taints']),
            'value_symbol': r.get('taint_symbol', ''),
        })
    # 排序: 有意图的 → 端点数 → 名称
    out.sort(key=lambda x: (0 if x['intents'] else 1, -x['endpoint_count'],
                            x['name'].lower()))
    # 截断**如实披露**(审计): 行数超上限时返回带 `total` 的列表, 渲染层据此注明
    # "仅显示前 N 行"。此前第 81 行起的参数无声消失。
    rows = _CappedRows(out[:_MAX_ROWS])
    rows.total = len(out)
    return rows






def param_table_html(rows):
    """参数总表的 HTML **内容片段**（不含卡片/标题 —— 由调用方 report_html 统一包裹编号）。"""
    if not rows:
        return ''
    body = ''
    _total = getattr(rows, 'total', None)
    if _total is not None and _total > len(rows):
        body += (f'<p class="note">⚠️ 参数共 <b>{_total}</b> 行, 仅显示前 <b>{len(rows)}</b> 行'
                 f'(按意图/端点数排序取优)。</p>')
    body += ('<table><tr><th>参数</th><th>类型</th><th>位置</th><th>必填</th>'
            '<th>意图</th><th>观测形态</th><th>值来源</th><th>端点数</th><th>来源</th></tr>')
    for r in rows:
        t = '/'.join(r['types']) or '—'
        loc = '/'.join(r['locations']) or '—'
        req = '是' if r['required'] else '—'
        it = ' '.join(_INTENT_LABEL.get(d, d) for d in r['intents']) or '—'
        sh = '/'.join(r['shapes']) or '—'
        src = '/'.join(_SRC_LABEL.get(s, s) for s in r['sources'])
        # R3 值来源(轻量污点): 标签 + 悬停显示代表符号(如 res.data.user_id / localStorage.userToken)
        _vs = r.get('value_sources') or []
        if _vs:
            vsc = ('<span title="{}">{}</span>'.format(
                _html.escape(r.get('value_symbol') or '—'), _html.escape('/'.join(_vs))))
        else:
            vsc = '—'
        if r.get('unlinked'):
            # 已提取但无归属证据: 显式标注, 不臆造关联(零推断)
            ep_cell = '<span style="color:#888">未归属</span>'
        else:
            eps = r['endpoints']
            ep_cell = (f'<span title="{_html.escape(", ".join(eps))}">'
                       f'{r["endpoint_count"]}</span>')
        body += (f'<tr><td><code>{_html.escape(r["name"])}</code></td>'
                 f'<td>{_html.escape(t)}</td><td>{_html.escape(loc)}</td>'
                 f'<td>{req}</td><td>{_html.escape(it)}</td>'
                 f'<td>{_html.escape(sh)}</td><td>{vsc}</td><td>{ep_cell}</td>'
                 f'<td>{_html.escape(src)}</td></tr>')
    body += '</table>'
    return ('<p class="note">把 <b>schema 类型/必填</b> + <b>运行时取值形态</b> + <b>测试意图</b> '
            '汇聚到一行，省去人工从接口逐个捞参数。参数名/类型为静态或 schema 推断；'
            '取值形态只记形态、<b>不含原值</b>；意图为命名推断 —— '
            '均不发起写请求、不构成漏洞判定。'
            '「值来源」为轻量污点标注(一步回溯)：<b>上游接口响应</b>/<b>浏览器存储</b>/'
            '<b>路由参数</b>/<b>未知(函数入参)</b>，悬停看代表符号。'
            '「端点数」列悬停可看具体接口；标 <b>未归属</b> 者为静态提取到、'
            '但无调用点 / schema 证据归属到具体接口的参数（零推断，不臆造关联）。</p>' + body)
