# -*- coding: utf-8 -*-
"""facet — 报告生成模块（从 core.py 拆分）

职责：
- classify_findings(): 发现项按敏感类型分类
- classify_apis(): 接口按来源分类（JS提取 / 探测命中）
- report_html(): HTML Dashboard 报告生成（**本工具唯一报告输出**）
- report_json(): 机器可读 JSON 报告导出（finding 级结构化，供流水线消费）

报告按**功能节点**编排（分析师每个节点回答一个问题）：
  摘要 → 攻击面 → 风险线索 → 资产与技术栈 → 认证与访问 → 覆盖与边界 → 附录
"""

import html as _html
import json as _json
import os
import re
from contextlib import closing
from datetime import datetime, timezone

from .. import __version__
from ..core.dicts import (
    AUTH_PRIVATE_KW,
    AUTH_PUBLIC_KW,
    MGMT_HIGH_RISK_KW,
    MGMT_PUBLIC_KW,
    STATIC_ASSET_EXT,
    UNAUTH_SURFACE_KW,
    access_control_surface,
    has_auth_session,
    normalize_endpoint,
    path_segments,
    surface_segments,
)
from ..core.history import ScanHistory

# 依赖方向: 领域层(report)只向**下**引用 —— log/history/util 来自 core 基础设施,
#   指纹分组数据(categorize_fingerprints)来自 recon(同层, 纯数据变换), 不再经由 core.engine 中转。
#   展示渲染**在当前报告层(report.py)内**完成, 避免领域层(recon)反向耦合报告展示。
from ..core.log import dbg, log
from ..core.const import DEFAULT_UA
from ..core.util import _host_of
from ..output.paths import ensure_parent  # D5: 写入前确保父目录存在(报告/导出/侧车)
from ..recon.stack import format_stack


# 指纹章节: 分组数据来自 recon(同层数据变换), 报告专属渲染(置信度条/文本)在当前报告层(report.py)内。
from .params import build_param_table, param_table_html


def _group_endpoints(items, families):
    """按归一化端点聚合。

    返回 [(rep_path, method, status, note, n_variants, sample_variants)]。
    rep_path 取家族中**实际被探测**的代表(首个真实变体路径, 非占位符),
    保证与归一化占位符的通配匹配(如 `:id → [^/]+`), 且人类可读。
    n_variants 来自 meta['api_families'](含全部被提取的同族变体, 可能 >1)。
    """
    groups = {}
    for p, m, st, note in items:
        groups.setdefault(normalize_endpoint(p) + '|' + m, []).append((p, m, st, note))
    out = []
    for key, g in groups.items():
        g.sort(key=lambda x: x[0])
        nk = key.split('|', 1)[0]
        fam = families.get(nk, [x[0] for x in g])
        rep = fam[0] if fam else g[0][0]
        variants = sorted(set(fam))
        # 同组可能由**多个发现通道**贡献(如"静态提取 + 运行时捕获"): 保留**全部 distinct 来源**
        #   合并为一条备注, 而非只取首条 —— 否则运行时的交叉确认在报告里不可见(既失真, 又弱化
        #   "运行时通道贡献"的可审计性)。分类(`classify_api`)仍可基于合并备注的关键词正确判定。
        _notes = sorted({x[3] for x in g if x[3]})
        _note = ' · '.join(_notes) if _notes else (g[0][3] or '')
        out.append((rep, g[0][1], g[0][2], _note, len(variants), variants))
    out.sort(key=lambda x: x[0])
    return out


def _disp_path(p):
    """路径展示形态: `:id` → `{id}`(去查询串)。"""
    import re as _re
    return _re.sub(r':([A-Za-z_]\w*)', r'{\1}', (p or '').split('?')[0])


def _unauth_surface(api_items):
    """**未授权面**: 无凭据下返回了**实质内容**的端点(发现级线索, 非漏洞判定)。

    判据: 探活状态 ∈ {200,201,204,405}(路由解析成功) 且 备注**不含**"受保护/需登录/
    catch-all/无法判定" 且 路径**非设计公开**(登录/验证码/静态资源)。
    命中即"无凭据可达" —— 黑盒无凭据场景下, 这是最该先看的结论。
    """
    import re as _re
    _pub = _re.compile(
        r'(?i)/(?:login|logout|signin|sign_in|signup|sign_up|register|registration|'
        r'captcha|verifycode|validatecode|passport|sso|oauth|favicon|robots\.txt|'
        r'static|assets|css|js|images?|fonts?|media)(?:/|\.|$)')
    # **裸命名空间根**(如 `/api` `/rest` `/v1`)不是端点, 只是前缀 —— 通用探测常命中它们,
    #   若不剔除会把"catch-all 的 200"误报成未授权面。(`/health`/`/status` 等**保留**:
    #   健康检查接口常常确实匿名可达, 属真实发现。)
    _bare = frozenset(('api', 'rest', 'graphql', 'gql', 'rpc', 'gateway',
                       'service', 'services'))
    out = []
    for _x in (api_items or []):
        _p = _x[0] if len(_x) > 0 else ''
        _st = _x[2] if len(_x) > 2 else None
        _nt = str(_x[3] if len(_x) > 3 else '')
        if not _p or _st is None:
            continue
        try:
            _sti = int(_st)
        except (TypeError, ValueError):
            continue
        if _sti not in (200, 201, 204, 405):
            continue
        if any(_k in _nt for _k in ('受保护', '需登录', 'catch-all', '无法判定', '未授权')):
            continue
        if _pub.search(str(_p)):
            continue
        _segs = [s for s in str(_p).split('?')[0].split('/') if s]
        if len(_segs) == 1 and (_segs[0].lower() in _bare
                                or _re.fullmatch(r'v\d+', _segs[0].lower())):
            continue                       # 裸命名空间根(`/api`、`/v1`) → 非端点
        out.append(str(_p))
    return sorted(set(out))


def _load_biz_rules(spec):
    """加载自定义业务标注规则。

    `spec` 支持三种形态:
      · None                → 返回 None(调用方回退空规则 —— 业务域已改结构判定, 无需词表)
      · list[([关键词...], 标签)] 或 list[{'keywords': [...], 'label': ...}] → 直接使用
      · str(JSON 文件路径)  → 读取 `{"rules": [...]}` 或裸数组
    解析失败一律返回 None(绝不因自定义规则出错而中断报告)。
    """
    if not spec:
        return None
    if isinstance(spec, str):
        try:
            import json as _json
            with open(spec, encoding='utf-8') as f:
                data = _json.load(f)
            spec = data.get('rules') if isinstance(data, dict) else data
        except Exception:
            return None
    out = []
    try:
        for item in spec:
            if isinstance(item, dict):
                kws = item.get('keywords') or item.get('kw')
                label = item.get('label')
            else:
                kws, label = item[0], item[1]
            if kws and label:
                out.append((tuple(kws), str(label)))
    except Exception:
        return None
    return out or None


# 接口来源分类(classify_api)的默认启发式 —— 此前硬编码在 classify_api 内; 现抽出为常量,
#   以便通过 config['source_rules'] / meta['source_rules'] 外部化(动态获取)。
_SOURCE_JS_SUFFIX = '.js'
_SOURCE_PROBE_NOTE_KW = ('隐藏路径', '探测命中', '兜底探测', '通用探测', '伪命中',
                         '空响应', '空回退', '鉴权墙', '服务端异常')
_SOURCE_WRITE_NOTE_KW = ('写操作', 'write')


def _load_source_rules(spec):
    """加载接口来源分类的自定义启发式。

    `spec` 支持: None → 返回 None(回退默认); str(JSON 文件路径) → 读取
    `{"js_suffix", "probe_note_keywords", "write_note_keywords"}`; 或直接给 dict。
    解析失败一律返回 None(绝不因自定义规则出错而中断报告)。
    """
    if not spec:
        return None
    if isinstance(spec, str):
        try:
            import json as _json
            with open(spec, encoding='utf-8') as f:
                data = _json.load(f)
        except Exception:
            return None
    else:
        data = spec
    try:
        return {
            'js_suffix': str(data.get('js_suffix', _SOURCE_JS_SUFFIX)),
            'probe_note_keywords': tuple(data.get('probe_note_keywords')
                                        or _SOURCE_PROBE_NOTE_KW),
            'write_note_keywords': tuple(data.get('write_note_keywords')
                                        or _SOURCE_WRITE_NOTE_KW),
        }
    except Exception:
        return None


def _load_param_rules(spec):
    """加载参数语义标注的自定义规则。

    `spec` 支持: None → 返回 None(回退默认); str(JSON 文件路径) → 读取
    `{"id_keywords":[...], "time_keywords":[...], "param_kinds":[{keywords,label}]}`;
    或直接给 dict/list。解析失败一律返回 None(绝不因自定义规则出错而中断报告)。
    返回 `{'id': set, 'time': set, 'param_kinds': [(label, (kw,...)), ...]}` 或 None。
    """
    if not spec:
        return None
    if isinstance(spec, str):
        try:
            import json as _json
            with open(spec, encoding='utf-8') as f:
                data = _json.load(f)
        except Exception:
            return None
    else:
        data = spec
    try:
        kinds = []
        for item in (data.get('param_kinds') or []):
            if isinstance(item, dict):
                kws = item.get('keywords') or item.get('kw')
                label = item.get('label')
            else:
                label, kws = item[0], item[1]
            if kws and label:
                kinds.append((str(label), tuple(kws)))
        id_kw = set(data.get('id_keywords') or [])
        time_kw = set(data.get('time_keywords') or [])
    except Exception:
        return None
    if not (kinds or id_kw or time_kw):
        return None
    return {'id': id_kw, 'time': time_kw, 'param_kinds': kinds}


def _load_report_rules(ctx, meta):
    """统一加载报告三套分类规则, 返回 (biz_rules, param_rules, source_rules)。

    biz_rules: 未配置时为**空元组**（业务域已改**结构判定**, 不再有内置词表）;
    param/source 为 None 时调用方回退内置默认。任何解析异常均被各 loader 内部吞掉, 此处不会抛。
    """
    cfg = (getattr(ctx, 'config', None) or {})
    biz = _load_biz_rules(meta.get('biz_rules') or cfg.get('biz_rules')) or ()
    param = _load_param_rules(meta.get('param_rules') or cfg.get('param_rules'))
    src = _load_source_rules(meta.get('source_rules') or cfg.get('source_rules'))
    return biz, param, src


# ---- 参数语义分类(纯静态命名推断, **不发起任何请求**) —— 侦察阶段给攻击面打标签 ----
_ID_KW = {'id', 'uid', 'uuid', 'guid', 'no', 'num', 'recordcode', 'contractnum',
          'objectid', 'object_id', 'commentid', 'relatedid', 'sharecode', 'vipcardname',
          'order_no'}
_PARAM_KINDS = (
    ('跳转', ('url', 'uri', 'link', 'href', 'redirect', 'redirect_uri', 'redirecturl',
              'returnurl', 'return_url', 'callback', 'next', 'target', 'jump', 'goto',
              'authurl', 'auth_url', 'referer', 'referrer')),
    ('路径文件', ('file', 'filename', 'file_name', 'path', 'filepath', 'file_path',
                  'dir', 'folder', 'template')),
    ('搜索', ('q', 'query', 'keyword', 'keywords', 'search', 'kw', 'term', 'wd')),
    ('分页', ('page', 'pagesize', 'page_size', 'pageindex', 'page_index', 'size',
              'limit', 'offset', 'start', 'count', 'rows', 'pageno', 'page_no')),
    ('凭据', ('token', 'access_token', 'auth', 'authorization', 'apikey', 'api_key',
              'secret', 'sign', 'signature', 'ticket', 'session', 'sid', 'jwt')),
)
_TIME_KW = {'date', 'time', 'timestamp', 'ts', 'from', 'to', 'start_time', 'end_time'}


def _param_kind(name, rules=None):
    """参数语义类别(静态命名推断): 对象 ID / 跳转 / 路径文件 / 搜索 / 分页 / 凭据 / 时间 / 其他。

    `rules`(来自 `_load_param_rules`) 可覆盖内置关键词表(`_ID_KW`/`_PARAM_KINDS`/`_TIME_KW`),
    使"参数语义"可动态配置; `rules` 为 None 时行为与旧版完全一致(零配置不变)。
    """
    n = (name or '').lower()
    if not n:
        return '其他'
    _id = (rules or {}).get('id') if rules else _ID_KW
    _kinds = (rules or {}).get('param_kinds') if rules else _PARAM_KINDS
    _time = (rules or {}).get('time') if rules else _TIME_KW
    if n in _id or n.endswith('id') or n.endswith('_id'):
        return 'ID'
    for label, kws in _kinds:
        if n in kws:
            return label
    if 'token' in n or n.endswith('secret') or n.endswith('_sign'):
        return '凭据'
    if n in _time or n.endswith('time') or n.endswith('_time'):
        return '时间'
    return '其他'


_INTENT_LABEL_SHORT = {'idor': 'IDOR', 'sqli': 'SQLi', 'ssrf': 'SSRF'}

def _annotate_params(names, rules=None, intents=None):
    """参数名 → 带语义标签(如 `order_id·ID`); 若提供 `intents`(参数名→意图集合), 追加意图标签
    (如 `order_id·ID·IDOR`), 使端点主表里每个参数即见其安全含义。`rules` 见 `_param_kind`。
    `intents` 缺省 None 时行为不变(MD/JSON 调用方不传, 保持旧输出)。"""
    out = []
    for nm in names:
        k = _param_kind(nm, rules)
        s = f'{nm}·{k}' if k != '其他' else nm
        if intents:
            _it = intents.get(nm) or intents.get(nm.lower())
            if _it:
                s += '·' + '/'.join(_INTENT_LABEL_SHORT.get(d, d) for d in sorted(_it))
        out.append(s)
    return out


def _endpoint_master(ctx, api_items, write_apis, meta, source_rules=None):
    """**端点主表**: 把 业务接口 / 探测端点 / 写操作JS / 参数登记 四类来源合并为单一行集,
    每行同时携带 来源 · 状态/备注 · 路由 · 业务 · 路径参数 · 查询·请求体参数。

    消除旧版「接口(探活确认)」与「接口归档(路由/业务)」对同一批端点
    (api_items + write_apis) 的重复列举 —— 旧实现让同一条业务/探测/写操作接口在报告里
    出现两次(一次带状态/判定, 一次带路由/业务/参数), 既占版面又易让人以为是两个不同端点。

    返回 [(disp, method, source, status_note, path_params, other_params, probe_method)]
    其中 path_params / other_params 为已排序 list[str]; probe_method 为**实际探活使用的方法**
    (来自 ctx.add_all_found 的 m 字段, 非推断; 写声明端点恒为只读 GET/HEAD 降级; 未探活行为 None);
    按「来源优先级 → 路径」排序。
    """
    import re as _re
    pmap = getattr(ctx, 'pmap', None) or {}
    # 路径推断候选(方案 4.6) / 响应挖掘(方案 2-B): 来源列单列, 与"提取到的真实接口"分区
    _inf_set = getattr(ctx, 'inferred_paths', None) or set()
    _mine_set = getattr(ctx, 'mined_paths', None) or set()
    families = meta.get('api_families', {}) or {}
    groups = _group_endpoints(api_items or [], families)
    # **JS 声明的请求方法 = 权威来源**(读+写): 路径 → (原始键, 方法)。报告「方法」列以它为准;
    #   **无 JS 声明 → `—`**(不做推断、不拿探活方法充数)。`meta['api_methods']` 来自
    #   `_extract_api_calls` 的 {path: method}(含 GET); `write_apis`(写方法)优先级更高, 覆盖同名。
    _js_method = {}
    for _ap, _am in (meta.get('api_methods') or {}).items():
        _k = _disp_path(_ap).split('?')[0]
        if _k:
            _js_method[_k] = (_ap, str(_am or 'GET').upper())
    for _wp, _wm in (write_apis or {}).items():
        _k = _disp_path(_wp).split('?')[0]
        if _k:
            _js_method[_k] = (_wp, (_wm or 'POST').upper())
    rows = []
    covered = set()
    # 字典候选**命中**集(归一化)与 JS 提取集 —— 用于 ①字典命中端点来源单列(不与 JS 提取混同,
    #   与 JSON dict_candidates 同口径); ②JS 提取存在的路径不降级为字典来源。
    _dict_hit = {normalize_endpoint(p) for p in _confirmed_dict_candidates(ctx, meta)}
    _extracted = {normalize_endpoint(p) for p in
                  (meta.get('apis') or set()) | (meta.get('recomb') or set())}
    # JS 声明的写方法路径(展示形态) —— 探活合并后被"业务接口"吞掉写标记, 需追加 ·写声明
    #   (与 summary.write_apis 口径对齐; 实测 OA 目标 22 个写接口仅 1 个保住来源标注)。
    _write_disp = {_disp_path(w).split('?')[0] for w in (write_apis or {})}
    # 1) 已探活端点(api_items): 归一化聚合后逐组一行
    for rep, m, st, note, nv, variants in groups:
        cls = classify_api(rep, note, source_rules)
        if cls == '业务接口':
            source = '业务接口'
        elif cls == '探测端点':
            source = '探测端点'
        elif cls == '写操作接口':
            source = '写操作JS'
        elif cls == '运行时捕获':
            source = '运行时捕获'
        else:
            source = 'JS资源'
        # 运行时交叉确认: 合并备注含 `runtime捕获` 且非纯运行时端点 → 来源标注 `+运行时`,
        #   让"静态发现 + 运行时确认"在来源列即可见(无需展开状态备注), 通道贡献可审计。
        if 'runtime捕获' in (note or '') and cls != '运行时捕获':
            source = source + '+运行时'
        # 404 = **未找到** → 不是"已确认接口"。降级来源标注, 避免与真实接口混同
        #   (404 仍值得提及: 可能是方法/参数不符、或存在性隐藏; 但不应被当成已确认端点)。
        if st == 404:
            source = '未确认(404)'
        # 【强制约束·降噪】规则派生(路径推断)且**未命中** → 一律不进主表。
        #   路径推断 = 由已提取端点按规则(动词族/单复数/扩展名)派生的同族候选;
        #   其中**未命中(404/不可达)**的与目标无关, 展示只增噪声 → 隐去(用户要求)。
        #   若推断路径**命中(非 404)**则它是真实可达端点, 属"命中", 仍保留展示。
        if _inf_set and rep.split('?')[0] in _inf_set and st == 404:
            continue
        # 路径推断候选(命中项): 来源单列 —— 不把"推断出来的"当成"提取到的"
        if _inf_set and rep.split('?')[0] in _inf_set:
            source = '路径推断'
        # 响应挖掘(方案 2-B): 从响应体/响应头挖出并回灌的路径, 来源单列(真实命中, 保留)
        elif _mine_set and rep.split('?')[0] in _mine_set:
            source = '响应挖掘'
        disp = _disp_path(rep)
        covered.add(disp.split('?')[0])
        base = disp.split('?')[0]
        alt = _re.sub(r':([A-Za-z_]\w*)', r'{\1}', base)
        linked = set(pmap.get(base, set()) or set()) | set(pmap.get(alt, set()) or set())
        path_params = sorted(set(_re.findall(r'\{([A-Za-z_]\w*)\}', disp)))
        other = sorted(linked - set(path_params))
        variant = f' (同族 {nv} 变体)' if nv and nv > 1 else ''
        # st 为 HTTP 状态码(int, 来自 ctx.add_all_found 的 st 参数),
        #   必须显式转 str —— 否则 `(st or '') + ' · ...'` 在 st 为非零 int 时触发
        #   `int + str` 崩溃(旧版合成测试误用字符串状态码, 漏掉该回归)。
        _st_s = str(st) if st is not None else ''
        if cls == '业务接口':
            extra = _pretty_note(note) if note else ''
            status_note = _st_s + (f' · {extra}' if extra else '') + variant
        elif cls == '探测端点':
            verdict = _hidden_verdict(note)
            extra = _pretty_note(note) if note else ''
            status_note = f'{_st_s} · {verdict}' + (f' · {extra}' if extra else '') + variant
        else:   # 写操作JS / JS资源 —— 来自 api_items(已探活)
            extra = _pretty_note(note) if note else ''
            status_note = _st_s + (f' · {extra}' if extra else '') + variant
        # 方法: **只取 JS 声明**(用户要求: 不做任何推断) —— JS 未声明就留 `—`, **不拿探活方法充数**。
        _jm = _js_method.get(disp.split('?')[0])
        _method_disp = _jm[1] if _jm else '—'
        # —— 探活方法透明度(P-T): 目标无关(通用) ——
        # 不绑定任何特定目标: 披露逻辑只比较"**JS 声明的真实方法**"与"**实测探活方法**"两个
        #   结构事实(二者皆动态提取, 非硬编码), 凡二者不一致即标注, 对所有目标统一适用。
        #   常态是写声明端点(POST/PUT/PATCH/DELETE)仅以只读 GET/HEAD 探活(合规红线: 绝不发写请求),
        #   其状态(如 "403 · 响应 137B")若不说明会被误读为 "POST 被拦截"; 该情形给诚实的"只读降级"说明。
        #   probe_method 来自 ctx.add_all_found 的 m(实测记录, 非推断), 随 7 元组回传供 JSON/HTML 透出。
        probe_method = m if m else None
        if probe_method and _method_disp not in ('—', '') and probe_method != _method_disp:
            if _method_disp in ('POST', 'PUT', 'PATCH', 'DELETE') and probe_method in ('GET', 'HEAD'):
                status_note = (status_note or '') + f' · {probe_method} 探测(只读降级)'
            else:
                status_note = (status_note or '') + f' · 探测方法 {probe_method} ≠ 声明 {_method_disp}'
        # ① 字典候选命中(纯猜测字典里探活的)且 JS 未提取过 → 来源单列, 不与"源码里看到的"混同
        if (source in ('业务接口', '探测端点', 'JS资源')
                and normalize_endpoint(rep.split('?')[0]) in _dict_hit
                and normalize_endpoint(rep.split('?')[0]) not in _extracted):
            source = '字典候选(命中)'
        # ② JS 声明了写方法(POST/PUT/...) → 来源追加 `·写声明`(写操作JS 行自身已带, 不重复)
        if source != '写操作JS' and disp.split('?')[0] in _write_disp:
            source = source + '·写声明'
        rows.append((disp, _method_disp, source, status_note, path_params, other, probe_method))
    # 2) 写操作接口(JS 声明, 零发包): 跳过已被 api_items 覆盖的路径, 避免双重列举
    for p in sorted(write_apis or {}):
        disp = _disp_path(p)
        if disp.split('?')[0] in covered:
            continue
        covered.add(disp.split('?')[0])
        base = disp.split('?')[0]
        alt = _re.sub(r':([A-Za-z_]\w*)', r'{\1}', base)
        linked = set(pmap.get(base, set()) or set()) | set(pmap.get(alt, set()) or set())
        path_params = sorted(set(_re.findall(r'\{([A-Za-z_]\w*)\}', disp)))
        other = sorted(linked - set(path_params))
        rows.append((disp, (write_apis[p] or 'POST').upper(), '写操作JS', 'JS声明·零发包', path_params, other, None))
    # 3) 参数登记表(pmap 中有参数登记、但未出现在 api_items / write_apis 的路径)
    for base in pmap:
        k = (base or '').split('?')[0]
        if not k:
            continue
        # GraphQL schema 字段(`graphql:Type.field`)不是 URL 路径 —— 单列为"Schema字段",
        #   方法标 POST(GraphQL 查询)。**不得套用 `:id`→`{id}` 变换**: 否则 `graphql:Query.pet`
        #   会被误改成 `graphql{Query}.pet`, 并派生出**假路径参数 Query** 与假路由
        #   `/graphql{Query}.pet`(正是本应避免的"误读为 URL 端点")。
        _is_schema = k.startswith('graphql:')
        disp = k if _is_schema else _re.sub(r':([A-Za-z_]\w*)', r'{\1}', k)
        if disp in covered or k in covered:
            continue
        path_params = ([] if _is_schema
                       else sorted(set(_re.findall(r'\{([A-Za-z_]\w*)\}', disp))))
        other = sorted(set(pmap.get(base, set()) or set()) - set(path_params))
        if not (path_params or other):
            continue
        if _is_schema:
            # 非 URL: 只保留"来源=Schema字段"与参数; 方法 `—`(不臆造 POST)
            rows.append((disp, '—', 'Schema字段', 'GraphQL schema 字段(非 URL)·未探活',
                         path_params, other, None))
        else:
            # 方法 `—`(pmap 只登记了参数名, 没有方法信息 —— 不臆造 GET)
            rows.append((disp, '—', '参数登记', '参数登记·未探活', path_params, other, None))
    # 排序: 来源优先级 → 路径(单一真源 `_SRC_ORDER_BASE`; `·写声明` 后缀不参与分档)
    rows.sort(key=lambda r: (_src_rank(r[2]), r[0]))
    return rows


def _is_baseurl_sibling(cand_path, base_paths):
    """cand 是否是 base_paths 中某条的**baseURL 原形**(后缀同胞) —— 补回环节去重用。

    JS 常写 `axios.get("/auth/me")`(实例 baseURL="/api") → 字面量 `/auth/me` 与重建后的
    `/api/auth/me` 是**同一端点的两种形态**; 双落库后若不判重, 报告里同端点出两行
    (实测 OA 目标 100 端点中 30 对重复)。
    判据: cand(≥2 段)是某 base 的**段边界后缀**(`base.endswith(cand)`)或完全相等;
    仅对相对路径生效(绝对 URL 本就是独立端点); 单段路径(如 `/admin`)只判全等,
    避免 `/x/admin` 误伤真候选 `/admin`。
    """
    c = (cand_path or '').split('?')[0]
    if not c or c.startswith(('http://', 'https://')):
        return False
    if c.count('/') < 2:                     # 少于 2 段(如 /admin): 只认全等
        return c in (base_paths or ())
    return any(b == c or b.endswith(c) for b in (base_paths or ()))


def _endpoint_master_risk(ctx, api_items, write_apis, meta,
                          source_rules=None, matrix=None):
    """**端点主表 + 风险矩阵合一**: 在 `_endpoint_master` 七元组基础上,
    按 `(归一化端点, 方法)` 关联 `build_recon_matrix` 的 优先级 / 命中维度 / 风险假设 / 只读验证,
    并把矩阵中"不在主表"的源码候选(1c 行)补回(避免漏覆盖)。

    返回扩展元组 list(13 字段):
      (disp, method, source, status_note, path_params, other, probe_method,
       priority, dims, reason, probed, hyp, is_unprobed)
    其中 `probe_method` 为实际探活方法(写声明端点恒为只读 GET/HEAD 降级; 未探活行为 None),
    `dims` 为 dict(dim→bool), `hyp` 为假设键 list, `is_unprobed` 标记未探活。
    `verify` 不在元组内, 由渲染层用目标 base 现算(命令需拼目标 URL)。
    """
    import re as _re
    base_rows = _endpoint_master(ctx, api_items, write_apis, meta, source_rules)
    _no_dims = {d: False for d in DIM_ORDER}
    if not matrix:
        return [r + ('P2', dict(_no_dims), '', True, [], False) for r in base_rows]
    mx = {(normalize_endpoint(r['path']), str(r['method']).upper()): r
          for r in matrix['rows']}
    out = []
    used = set()
    for r in base_rows:
        disp, mth, src, sn, pp, op, pm = r
        key = (normalize_endpoint(disp), str(mth).upper())
        used.add(key)
        mr = mx.get(key)
        if mr:
            pri = mr['priority']
            dims = mr['dims']
            reason = mr.get('reason', '') or ''
            probed = mr.get('probed', True)
            hyp = _hypotheses_of(mr)
            is_unprobed = (not probed)
        else:
            pri = 'P2'; dims = dict(_no_dims); reason = ''
            probed = True; hyp = []; is_unprobed = (src in ('参数登记', 'Schema字段'))
        out.append((disp, mth, src, sn, pp, op, pm,
                    pri, dims, reason, probed, hyp, is_unprobed))
    # 补回矩阵中"不在主表"的源码候选(1c 行) —— 否则这些待复核线索会随矩阵卡片删除而丢失。
    # ⚠️ 去重按**路径**判(不只 (路径,方法)) —— 否则同一路径的 `(path, POST)` 矩阵行会被
    #   再次补回, 与主表里已合并了 JS 方法的 `(path, …)` 行**重复展示**
    #   (实测 `/api/booster/order-action` 出现两行: GET 探活行 + POST 源码声明行)。
    _base_paths = {normalize_endpoint(r[0].split('?')[0]) for r in base_rows}
    _base_paths_raw = {r[0].split('?')[0] for r in base_rows}
    pmap = getattr(ctx, 'pmap', None) or {}
    for mr in matrix['rows']:
        # 判重 = 精确(归一化路径) ∪ **后缀同胞**(baseURL 原形 vs 重建形, 如 /auth/me ↔ /api/auth/me)
        _mraw = _disp_path(mr['path']).split('?')[0]
        if (normalize_endpoint(_mraw) in _base_paths
                or _is_baseurl_sibling(_mraw, _base_paths_raw)):
            continue
        key = (normalize_endpoint(mr['path']), str(mr['method']).upper())
        if key in used:
            continue
        used.add(key)
        disp = _disp_path(mr['path'])
        base_k = disp.split('?')[0]
        alt = _re.sub(r':([A-Za-z_]\w*)', r'{\1}', base_k)
        linked = set(pmap.get(base_k, set()) or set()) | set(pmap.get(alt, set()) or set())
        path_params = sorted(set(_re.findall(r'\{([A-Za-z_]\w*)\}', disp)))
        other = sorted(linked - set(path_params))
        pri = mr['priority']; dims = mr['dims']; reason = mr.get('reason', '') or ''
        probed = mr.get('probed', False); hyp = _hypotheses_of(mr)
        is_unprobed = (not probed)
        src = '写操作JS' if mr.get('is_write') else '源码候选'
        out.append((disp, (mr['method'] or 'GET').upper(), src, '源码声明·未探活',
                    path_params, other, None,
                    pri, dims, reason, probed, hyp, is_unprobed))
    out.sort(key=lambda r: (_src_rank(r[2]), r[0]))
    return out


# ---------- 输出转义 ----------
# 报告里的路径/URL/证据/子域名等字段**全部来自目标站点的响应内容**
# (JS 提取的路径、Swagger 文档的 paths、响应体里的敏感字段、页面里的子域名)。
def _esc(v):
    """HTML 文本转义"""
    return _html.escape(str(v if v is not None else ''), quote=True)


def _esc_text(v):
    """HTML **元素内容**转义(仅 `& < >`) —— 用于 `<pre>` 等文本节点。

    引号在元素内容里**无需转义**; 用 `_esc`(quote=True) 会把每个 `"` 膨胀成 6 字符
    `&quot;`, 对压缩 JS 片段(引号密集)实测占报告体积的可观比例。属性值仍必须用 `_esc`。
    """
    return _html.escape(str(v if v is not None else ''), quote=False)


# ---------- 原子写入 ----------
# 报告/侧车此前直接 `open(path,'w')` 写: 全局超时(SIGALRM)、Ctrl-C、磁盘满会留下
# **语法不完整但文件名正常**的 .html/.json —— 比"没有文件"更难排查(JSON 解析失败、
# HTML 半截渲染)。统一改为 "写 <path>.tmp → os.replace", 失败时旧文件保持不变。
def _atomic_write_text(path, text):
    """原子写文本文件(先写临时文件再替换)。失败时清理临时文件并保留旧文件。"""
    from ..output.paths import ensure_parent
    ensure_parent(path)
    _tmp = path + '.tmp'
    try:
        with open(_tmp, 'w', encoding='utf-8') as f:
            f.write(text)
        os.replace(_tmp, path)
    except Exception:
        try:
            os.unlink(_tmp)
        except OSError:
            pass
        raise


def _atomic_dump_json(path, payload):
    """原子写 JSON(缩进 2, 不转义非 ASCII)。"""
    _atomic_write_text(path, _json.dumps(payload, ensure_ascii=False, indent=2))


# ---------- 端点折叠详情: 命中代码端 / 数据包构造（Burp 格式） ----------

def _fuzz_ph(name):
    """按参数名语义生成 `{{fuzz:...}}` 占位标签（借鉴 JsOwl 口径, 便于 Burp 里人工构造）:

      · 含 token/uuid/captcha → `name|token`（需会话/令牌）;
      · 以 id/_no/no 结尾 → `name|id-or`（对象引用）;
      · 含 page → `name|num`（分页序号）; 其余 → `name`。
    纯字符串变换, 零发包。
    """
    low = str(name).lower()
    if any(k in low for k in ('token', 'uuid', 'captcha')):
        return f'{name}|token'
    if low.endswith(('id', '_no', 'no')):
        return f'{name}|id-or'
    if 'page' in low:
        return f'{name}|num'
    return name


_BODY_METHODS = ('POST', 'PUT', 'PATCH')


def _build_burp_packet(base, disp, method, path_params, other_params, status_note='',
                       auth_required=False):
    """把一条端点**构造成可直接粘贴进 Burp Repeater 的原始请求包**（文本, 本工具自身零发包）。

    约定（与 JsOwl 报告口径一致）:
      · 方法行 `{METHOD} {path} HTTP/1.1`; 完整 URL 端点用绝对格式（自带 Host, 不重复 Host 头）;
      · `{{fuzz:名}}` = 需人工构造的测试值（语义标签见 `_fuzz_ph`）;
      · `{{cookie:session}}` = 需会话 Cookie 时的占位（仅该端点疑似需鉴权时作为真实头出现,
        否则以注释提示）;
      · `#` 开头为注意事项（状态/来源/合规提醒）, Burp 粘贴时删除即可。
    """
    from urllib.parse import urlparse
    import re as _re
    mth = str(method or '').strip().upper()
    if mth in ('', '—', '-'):
        mth = 'GET'
    path = disp or '/'
    # 路径参数 → 占位符（`{id}` 与 `:id` 两种模板形态, **单次正则**替换 ——
    #   先 replace('{id}') 再 replace(':id') 会二段命中(替换结果里含 ':id'), 故必须一次成)
    for p in path_params or ():
        ph = '{{fuzz:' + _fuzz_ph(p) + '}}'
        path = _re.sub(r'\{' + _re.escape(p) + r'\}|:' + _re.escape(p) + r'\b',
                       lambda _m, _ph=ph: _ph, path)
    # 其它参数: 提取阶段未区分 query/body 归属 → 按方法形态放置, 并在注释中如实说明
    others = [p for p in (other_params or ()) if p and p not in (path_params or ())]
    qs = ''
    body = ''
    is_full = '://' in path
    netloc = urlparse(base or '').netloc
    if mth in _BODY_METHODS and others:
        body = '{' + ', '.join(f'"{p}": "{{{{fuzz:{_fuzz_ph(p)}}}}}"' for p in others) + '}'
    elif others and '?' not in path:
        qs = '?' + '&'.join(f'{p}={{{{fuzz:{_fuzz_ph(p)}}}}}' for p in others)
    target = path + qs
    lines = [f'{mth} {target} HTTP/1.1']
    if not is_full and netloc:
        lines.append(f'Host: {netloc}')
    lines.append(f'User-Agent: {DEFAULT_UA}（浏览器 UA 占位 · 粘贴 Burp 前请按实际复核会话替换）')
    lines.append('Accept: application/json, text/plain, */*')
    if auth_required:
        lines.append('Cookie: {{cookie:session}}')
    if body:
        lines.append('Content-Type: application/json')
        lines.append('')
        lines.append(body)
    notes = ['---- 以下为注意事项（粘贴到 Burp Repeater 前删除）----']
    if status_note:
        notes.append(f'状态: {status_note}')
    if others:
        notes.append('参数名来自 JS 提取（未区分 query/body 归属）, 以实际报文为准')
    if not auth_required:
        notes.append('如需登录态, 手动加 Cookie: {{cookie:session}}')
    notes.append('只读复核: 本工具零发包; 请仅对授权目标在 Burp Repeater 人工复核')
    for n in notes:
        lines.append('')
        lines.append('# ' + n)
    return '\n'.join(lines) + '\n'


def _render_packet_html(packet, label='数据包构造（Burp 格式 · 可粘贴 Repeater）'):
    """把 Burp 格式数据包渲染为 HTML 块（方法行/占位符/注释高亮）+ 复制按钮。

    复制按钮携带**纯文本**（data-copy）, 点击写剪贴板（含无 clipboard API 时的降级路径）。
    """
    if not packet:
        return ''
    import re as _re
    out_lines = []
    for ln in packet.rstrip('\n').split('\n'):
        e = _esc_text(ln)
        if ln.startswith('#'):
            out_lines.append(f'<span class="pkt-note">{e}</span>')
        elif ' HTTP/1.1' in ln:
            out_lines.append(f'<span class="pkt-method">{e}</span>')
        else:
            # {{...}} 占位符高亮（转义后内容不含 <>&, 可安全替换）
            e = _re.sub(r'\{\{[^}]+\}\}',
                        lambda m: f'<span class="ph">{m.group(0)}</span>', e)
            out_lines.append(e)
    pkt_html = '\n'.join(out_lines)
    return ('<div class="epd-sec"><div class="epd-k">' + _esc(label) + '</div>'
            '<pre class="pkt">' + pkt_html + '</pre>'
            '<button class="copy-btn" type="button" data-copy="' + _esc(packet) + '">复制请求包</button>'
            '<span class="note">粘贴到 Burp Repeater; <code>{{fuzz:…}}</code>=需构造测试值, '
            '<code>{{cookie:session}}</code>=需会话 Cookie, <code>#</code>=注意事项</span></div>')







# ---------- 发现项敏感分类 ----------
SENSITIVE_CATEGORIES = {
    '云凭证 (AK/SK)':     {'AK', 'SK', 'AccessKey', 'SecretKey', 'LTAI', 'AKID', 'AKIA'},
    'JWT/令牌':            {'JWT', 'jwt', 'Bearer', 'Token', 'token', 'Authorization'},
    '密钥/ClientID':       {'PrivateKey', 'SECRET', 'API_KEY', 'ClientID', 'client_secret', 'api_key', 'secret_key'},
    '硬编码用户名':         {'username', 'user_name', '用户名', '硬编码用户名'},
    '硬编码密码':           {'password', 'passwd', '硬编码密码', 'password: '},
    'URL内嵌凭据':          {'URL内嵌密码', 'URL参数泄露'},
    '响应体敏感字段':       {'敏感信息响应', 'balance', 'id_card', 'phone', 'real_name'},
}

def classify_finding(evidence):
    """根据 evidence 文本将发现项归入敏感子类"""
    ev = str(evidence)
    for cat, kws in SENSITIVE_CATEGORIES.items():
        if any(kw in ev for kw in kws):
            return cat
    return '其他发现'

def classify_api(path, note, source_rules=None):
    """接口来源分类。

    `source_rules`(来自 `_load_source_rules`) 可覆盖 note 关键词启发式与 `.js` 后缀判定,
    使"接口来源分类"可动态配置; 为 None 时行为与旧版完全一致(零配置不变)。
    类别名(业务接口/探测端点/写操作接口/JS资源)保持结构性不变, 仅匹配词可配。
    """
    r = source_rules or {}
    js_suffix = r.get('js_suffix', _SOURCE_JS_SUFFIX)
    probe_kw = r.get('probe_note_keywords', _SOURCE_PROBE_NOTE_KW)
    write_kw = r.get('write_note_keywords', _SOURCE_WRITE_NOTE_KW)
    note_l = (note or '').lower()
    if path.endswith(js_suffix):
        return 'JS资源'
    if any(k in note_l for k in probe_kw):
        return '探测端点'
    if any(k in note_l for k in write_kw):
        return '写操作接口'
    # 仅当**纯运行时端点**(合并备注即 'runtime捕获', 无其它来源)才归为「运行时捕获」;
    #   若备注是 "业务接口 · runtime捕获" 这类**合并来源**, 应保留主分类(业务接口),
    #   运行时的交叉确认由 `+运行时` 标记体现(见 `_endpoint_master`)。
    if note_l == 'runtime捕获':
        return '运行时捕获'
    return '业务接口'

def _hidden_verdict(note):
    """隐藏路径判定标注"""
    if '伪命中' in note:
        return '⚠️ 伪命中 (Catch-all)'
    if '空响应' in note:
        return '⚠️ 空回退'
    if '鉴权墙' in note:
        return '🔒 需鉴权'
    if '服务端异常' in note:
        return '💥 触发异常'
    return '✅ 真实路径'


def _pretty_note(note):
    """把探活备注里的内部简写(`len=5645`)美化为可读文本(`响应 5645 B`) —— 报告面向人, 不暴露内部格式。"""
    import re as _re
    n = str(note or '')
    n = _re.sub(r'\blen=(\d+)\b', lambda m: f'响应 {m.group(1)} B', n)
    # 响应类型(降噪): HTML 页面 → 显式标注, 提示"疑似页面, 非数据接口"。
    n = _re.sub(r'\bct=html\b', '页面(HTML)', n)
    n = _re.sub(r'\bct=json\b', '数据(JSON)', n)
    n = _re.sub(r'\bct=xml\b', '数据(XML)', n)
    n = _re.sub(r'\bct=text\b', '文本', n)
    n = _re.sub(r'\bct=bin\b', '二进制', n)
    return n.strip()

# ---------- 端点风险特征标注（侦察） ----------
#   把"发现到的端点"按**测试维度**摊平成一张某, 并对每个端点标 P0/P1/P2 优先级,
#   让分析师一眼看到"优先复核哪里"。维度与优先级都不依赖模块是否跑过 verify ——
#   只要端点/参数被被动发现, 就能给出"值得测"的提示(实际能否测取决于已启用的模块)。
DIM_ORDER = ["auth", "idor", "sqli", "sensitive", "config", "unauth", "ssrf"]
DIM_LABELS = {
    "auth": "认证相关",
    "idor": "对象引用参数",
    "sqli": "查询参数",
    "sensitive": "敏感数据",
    "config": "配置/管理面",
    "unauth": "未授权可访问",
    "ssrf": "跳转/URL 参数",
}
# 维度命中关键词（路径小写段匹配）。覆盖面刻意保守, 只标"明显属于该维度的端点",
# 不臆测未发现的接口。
# 高危管理面关键词（**只取高危**：admin/manage/console/actuator/druid/metrics/monitor/debug/
#   internal/config/env/.git/.env/phpmyadmin/jenkins/grafana/kibana）—— 单一事实来源见 dicts。
#   注: 不含 health/status/swagger/graphql（可能本就公开, 单列 MGMT_PUBLIC_KW, **不升 P0**）。
_CONFIG_KW = set(MGMT_HIGH_RISK_KW)
# 可能本就公开的"配置/文档/探活面" —— 仅给低优先级信息性标注, 不算风险维度。
_CONFIG_PUBLIC_KW = set(MGMT_PUBLIC_KW)
_SENSITIVE_KW = {"secret", "apikey", "api_key", "privatekey", "private", "credential",
                 "user", "users", "order", "orders", "profile", "payment", "customer",
                 "member", "staff", "employee", "invoice", "wallet", "balance"}
# 疑似对象引用参数（IDOR/BOLA 候选）—— 出现即代表"接口以某个对象 ID 为输入"
_ID_PARAM_KW = {"id", "ids", "uid", "userid", "user_id", "uuid", "no", "num", "orderid",
                "order_id", "itemid", "item_id", "docid", "fileid", "file_id", "pid", "tid"}
# 疑似注入点参数（SQLi 候选）—— 出现即代表"接口以该参数参与查询/拼接"
_SQLI_PARAM_KW = {"id", "no", "num", "keyword", "q", "query", "search", "type", "name",
                  "title", "sort", "filter", "page", "category", "uid", "userid", "orderid",
                  "field", "col", "value", "term"}
# 未授权访问面（内部/调试/运维后门，暴露即风险）—— 与 config(功能配置/监控面) 区分：
# 这里只标"明显不该公开的内部/调试端点"，不重复 admin/actuator/metrics/dashboard 等
# 单一事实来源见 dicts.UNAUTH_SURFACE_KW。
_UNAUTH_KW = set(UNAUTH_SURFACE_KW)
# 认证面细分（单一事实来源见 dicts）：
#   · 私有 = 需认证的账户/会话面 → 匿名可达才是风险(P0)
#   · 公开 = 按设计即匿名可达的认证入口(login/logout/signup/reset/token/oauth…)
#     → **不构成风险**（登录页本就该匿名可达），仅作"认证入口"信息性标注(P2)
_AUTH_PUBLIC_KW = set(AUTH_PUBLIC_KW)
_AUTH_PRIVATE_KW = set(AUTH_PRIVATE_KW)
# SSRF 候选参数—— 接口以"外部地址型"参数接收远程资源/回调/抓取
_SSRF_PARAM_KW = {"url", "uri", "link", "image", "img", "src", "picture", "photo",
                  "avatar", "callback", "webhook", "redirect", "return", "next", "continue",
                  "feed", "fetch", "proxy", "remote", "import", "target", "site", "thumbnail"}

# 疑似未授权访问启发式(越权线索)的内容长度阈值(字节): 匿名扫描下, 需认证账户面/内部运维面/
# 高危管理面端点返回的响应体达到该长度才视为"实质内容"(排除空/极小响应, 降低噪声)。
_UNAUTH_CONTENT_MIN = 200

# 路径拆段 —— **单一事实来源** dicts.path_segments(与访问控制面判据同源, 避免两处实现漂移)。
_path_segments = path_segments

def _looks_like_id_segment(path):
    """路径里含对象引用段：:id / <id> / {id} / 纯数字段 / detail 段"""
    import re as _re
    p = path.split("?")[0].rstrip("/")
    for seg in p.split("/"):
        if not seg:
            continue
        if seg in (":id", "<id>", "{id}", "{no}", "<no>"):
            return True
        if _re.fullmatch(r"\d{1,}", seg):
            return True
        if seg.lower() in ("detail", "info", "view", "item"):
            return True
    return False

def _endpoint_dims(path, method, params, is_write):
    """返回该端点命中的测试维度集合 + 优先级 + 原因"""
    segs = _path_segments(path)
    param_l = {str(p).lower() for p in (params or set())}
    # "不该公开面"(认证/内部运维/高危管理)匹配用 surface_segments —— 兼容带服务端扩展名的路径
    #   (/login.aspx · /phpinfo.php · /admin.aspx · /config.php · /dump.jsp), 否则整类漏判。
    surf = surface_segments(path)
    # 认证面细分: 公开认证入口(login/logout/signup/reset/token/oauth…)按设计即匿名可达,
    #   不是风险 → 仅作信息性标注(P2); 需认证的账户/会话面匿名可达才是风险(P0)。
    #   同一路径同时含公开与私有段时以**公开**为准(如 /account/login 是登录页, 不是账户面)。
    has_auth_pub = bool(surf & _AUTH_PUBLIC_KW)
    has_auth_priv = bool(surf & _AUTH_PRIVATE_KW) and not has_auth_pub
    # 配置面细分: **只**把"高危管理面"计入风险维度; health/status/swagger/graphql 可能本就公开,
    #   单列低优先级信息(旧实现把 health/swagger 也标 P0 → 误报)。
    has_config = bool(surf & _CONFIG_KW)
    has_config_pub = bool(surf & _CONFIG_PUBLIC_KW)
    has_sensitive = bool(segs & _SENSITIVE_KW)
    has_id = bool(param_l & _ID_PARAM_KW) or _looks_like_id_segment(path)
    has_unauth = bool(surf & _UNAUTH_KW)
    has_ssrf = bool(param_l & _SSRF_PARAM_KW)
    has_sqli = bool(param_l & _SQLI_PARAM_KW)
    dims = {
        # auth 维度**只**计入"需认证账户面"(匿名可达才是风险); 公开认证入口(login/logout/
        #   signup/reset/token/oauth…)不计入 —— 否则会给正常登录页配上"认证/会话缺陷"假设(误报)。
        "auth": has_auth_priv,
        "idor": has_id,
        "sqli": has_sqli,
        "sensitive": has_sensitive,
        # config 维度**只**计"高危管理面"; 可能公开的 health/swagger 不计入(避免误报)。
        "config": has_config,
        "unauth": has_unauth,
        "ssrf": has_ssrf,
    }
    # **公开认证入口**(login/logout/signup/reset/token/oauth/sso…)按设计即匿名可达 → 其 POST 属
    #   正常(登录/注销本就该匿名调用), **不当作"写操作风险"**: 不加"写操作"理由、不因它升 P0、
    #   不给"越权写"假设。否则会出现 "P0 + reason 写'非风险'" 的**自相矛盾**(实测 /api/account/login:
    #   被标 P0, 而 reason 写"认证入口(公开可达属正常, 非风险)")。
    _write_risk = bool(is_write) and not has_auth_pub
    reasons = []
    if _write_risk:
        reasons.append("写操作(状态变更)")
    if has_auth_priv:
        reasons.append("认证/账户面")
    elif has_auth_pub:
        reasons.append("认证入口(公开可达属正常, 非风险)")
    if has_config:
        reasons.append("管理/配置/监控面")
    if has_unauth:
        reasons.append("内部/调试/运维面(未授权访问风险)")
    if has_id:
        reasons.append("含对象引用参数(IDOR候选)")
    if has_ssrf:
        reasons.append("含外部地址型参数(SSRF候选)")
    if has_sqli:
        reasons.append("含查询型参数(SQLi候选)")
    if has_sensitive:
        reasons.append("敏感数据面")
    if has_config_pub and not (_write_risk or has_auth_priv or has_config or has_unauth
                               or has_id or has_sensitive or has_ssrf):
        reasons.append("配置/文档/探活面(可能本就公开, 非风险)")
    # 优先级：P0=高价值/高风险(写/高危管理面/内部运维面/需认证账户面), P1=常见严重类, P2=其余
    #   注: 公开认证入口(login/logout…)与可能公开的 health/swagger **不**升 P0 —— 不是风险。
    if _write_risk or has_auth_priv or has_config or has_unauth:
        priority = "P0"
    elif has_id or has_sensitive or has_ssrf:
        priority = "P1"
    else:
        priority = "P2"
    return dims, priority, "；".join(reasons) or "普通只读/列表接口"


def _endpoint_param_intent(path, params, rules=None):
    """该端点"值得人工复核的参数"及其意图，按假设维度分组（只读静态聚合，不发包）。

    `rules`(来自 `_load_param_rules`) 与端点主表的 `_param_kind` **同源** —— 外置
    `param_rules` 时两处 kind 口径一致（此前此处固定用内置规则, 与外置不同源）。

    复用 ``_endpoint_dims`` 的同款关键词集（``_ID_PARAM_KW`` / ``_SSRF_PARAM_KW`` /
    ``_SQLI_PARAM_KW``），把"命中维度"细化到"**哪个参数**触发了它"——
    直接补上弱项：idor/sqrf/sqli 标了维度却没说清是哪一个参数，人工还得从接口再捞一遍。

    返回 ``{"idor": [(name, kind), ...], "ssrf": [...], "sqli": [...]}``，
    仅列入命中攻击假设的参数；普通参数不进表。路径级对象引用
    （``:id`` / ``{id}`` / 纯数字段 / detail 段）以 ``{id} 路径对象引用`` 计入 idor。
    纯静态命名推断，不含任何取值样例、不发起任何请求。
    """
    param_l = {str(p).lower(): str(p) for p in (params or set())}
    result = {}
    idor = [param_l[k] for k in param_l if k in _ID_PARAM_KW]
    if _looks_like_id_segment(path):
        idor.append("{id} 路径对象引用")
    if idor:
        result["idor"] = [(n, _param_kind(n, rules)) for n in idor]
    ssrf = [param_l[k] for k in param_l if k in _SSRF_PARAM_KW]
    if ssrf:
        result["ssrf"] = [(n, _param_kind(n, rules)) for n in ssrf]
    sqli = [param_l[k] for k in param_l if k in _SQLI_PARAM_KW]
    if sqli:
        result["sqli"] = [(n, _param_kind(n, rules)) for n in sqli]
    return result


# 参数意图标注里重点关注的假设维度（按价值排序：IDOR 最高）
_PARAM_INTENT_DIMS = ("idor", "ssrf", "sqli")

# 静态资源后缀：不是"可测端点", 不进端点标注（.json 保留，可能是数据泄露点）。
#   **单一真源** = 数据层 `dicts.STATIC_ASSET_EXT`（窄口径）—— 此前此处与 `recon/runtime.py`
#   各写一份**同值元组**（"同值常量第二处"反模式），现统一从数据层导入。

def _is_static_asset(path):
    p = (path or "").split("?")[0].split("#")[0].lower()
    return p.endswith(STATIC_ASSET_EXT)

def _candidate_path(p):
    """把 JS 声明的接口候选归一为可读路径。

    - 去掉 `${...}` 模板前缀（如 `${L$.hostServer}/rest/2fa/disable` → `/rest/2fa/disable`）；
    - 段内模板（如 `${this.host}/${e}/reviews`）归一为 `:id`；
    - 返回 None 表示无法归一（非路径候选）。
    """
    import re as _re
    p = (p or "").strip()
    while p.startswith("${"):
        idx = p.find("}")
        if idx < 0:
            return None
        p = p[idx + 1:]
    if not p.startswith("/"):
        return None
    p = _re.sub(r"\$\{[^}]+\}", ":id", p)
    return p

# 端点类别判定用的 API 前缀形态(发现级启发式, 非判定)。
#   含常规 API 前缀 + **运维/监控面**(actuator/druid/swagger… 是服务端 HTTP 端点, 属后端接口;
#   实测 macrozheng.com 的 /actuator/* 若不含此组会被误判 unknown)。
_API_KIND_RE = re.compile(
    r'^/(?:api|rest|v[0-9]+|graphql|gql|rpc|ajax|service|internal'
    r'|actuator|druid|swagger|api-docs|openapi|jolokia|prometheus|grafana)(?:/|$)', re.I)
# 通用 REST **动作段**(形态启发式, 非站点白名单): 路径含 `list/add/update/save/delete/…` 段
#   → 后端接口。用于识别**无 /api 前缀**的真实接口(实测 mall: /cart/add·/member/*/list·/order/*)。
_API_ACTION_SEG_RE = re.compile(
    r'/(?:(?:list|add|create|update|save|delete|remove|detail|info|query|search|clear|'
    r'edit|submit|cancel|confirm|generate|pay|apply|approve|reject|enable|disable|'
    r'reset|bind|unbind|follow|unfollow|sign|upload|download|export|import|refresh|'
    r'verify|validate|count|tree|receive|collect|publish|audit|assign|distribute)[A-Za-z]*'
    r'|[A-Za-z]{0,24}(?:List|Detail))(?:/|$)', re.I)
# 注: **不**含 login/logout/register/signin/get/set/auth —— 这些词会把**页面**(登录页/设置页/
#   文档 `getting-started`)误判为接口(`/login` 单段多为页面而非 API); 登录类接口多带方法声明,
#   由 write_apis 通道覆盖。
# 静态页扩展名(文档/页面, 非接口) → 前端路由/页面
_STATIC_PAGE_RE = re.compile(r'\.(?:html?|php|jsp|aspx?|do|action)\b', re.I)


def _endpoint_kind(p, meta, method=None):
    """端点类别: `backend_api` / `frontend_route` / `unknown`（**发现级启发式, 非判定**）。

    目的: 让"端点清单梳理"能直接筛出**真实后端接口**, 把**前端 SPA 路由 / i18n 登录页猜测**
    等非接口项区分开(实测 recon_matrix 中约 2/3 为非 `/api` 前缀项)。

    判据(高→低):
      1. 写方法声明 / 在 `write_apis` / `relative_apis` → `backend_api`
      2. 命中**前端路由集合** `meta['routes']` → `frontend_route`
      3. 路径命中 API 前缀形态(`/api`·`/rest`·`/v1`·`/graphql`·`/actuator`…) → `backend_api`
      4. 静态页扩展名(`.html`/`.php`…) → `frontend_route`(文档/页面, 非接口)
      5. 含**通用 REST 动作段**(`list`·`add`·`update`·`save`·`delete`·`detail`…) → `backend_api`
         (识别**无 `/api` 前缀**的真实接口; 形态驱动, 非站点白名单)
      6. 其余 → `unknown`(需人工/探活判定; 如 i18n 登录页猜测 `/accedi`)
    """
    path = (p or '').split('?', 1)[0]
    if str(method or '').upper() in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return 'backend_api'
    _w = meta.get('write_apis') or {}
    _rel = meta.get('relative_apis') or set()
    if p in _w or path in _w or p in _rel or path in _rel:
        return 'backend_api'
    _routes = meta.get('routes') or set()
    if p in _routes or path in _routes:
        return 'frontend_route'
    if _API_KIND_RE.match(path):
        return 'backend_api'
    # 静态页扩展名(文档/页面) → 前端路由/页面(实测 /swagger-ui/index.html·/tool/*.html)
    if _STATIC_PAGE_RE.search(path):
        return 'frontend_route'
    # 通用 REST 动作段(无 /api 前缀的真实接口) → 后端接口
    if _API_ACTION_SEG_RE.search(path):
        return 'backend_api'
    return 'unknown'


def build_recon_matrix(ctx, meta):
    """从扫描上下文计算端点标注（**风险提示与测试优先级排序，非漏洞判定**）。

    注意：本函数只做"基于端点特征的**风险标注**"，不检测、不确认任何漏洞。
    命中的维度仅代表"该端点**值得在授权范围内人工复核**"，是否构成风险由人工验证决定。

    数据源：① JS 声明的写操作；② 已探活的端点；③ **JS 源码声明但未探活的接口候选**
    （标 `probed=False`，仍是待复核线索，纳入以免漏掉客户端动态构造/懒加载的接口）。

    返回:
        {
          "rows": [{"path","method","is_write","kind","probed","confidence","dims","priority","reason"}],
          "summary": {"P0":n,"P1":n,"P2":n,"by_dim":{"auth":n,...}},
          "legend": {"dimensions":{...},"priority":{...},"disclaimer":...},
          "param_intent_index": {"idor"/"ssrf"/"sqli": {参数名: {"kind","endpoints"}}},
          "unauth_access_hints": [{"path","method","dims":[...],"content_len"}],  # 仅匿名扫描, 命中 auth/sensitive/unauth/高危config
        }
    """
    # 参数语义规则(外置 `param_rules` 与端点主表 `_param_kind` 同源) —— 供 param_intent_index 的 kind 标注。
    _, _param_r, _ = _load_report_rules(ctx, meta)
    # JS 声明的**方法**(读+写) —— 报告「方法」列的**权威来源**; 无声明 → `—`(不拿探活方法充数)。
    #   与端点主表(`_endpoint_master._js_method`)同源, 消除"同一端点两处方法不一致"。
    _decl = {normalize_endpoint(k): str(v or 'GET').upper()
             for k, v in (meta.get('api_methods') or {}).items()}
    for _wp, _wm in (meta.get('write_apis') or {}).items():
        _decl[normalize_endpoint(_wp)] = str(_wm or 'POST').upper()
    # 1) 收集端点（去重：归一化路径 + 方法）
    seen = set()
    rows = []
    # 实际探活过的端点(归一化路径) —— 写操作是否探活要**如实判定**, 不能一律 True。
    #   写操作来自 JS 声明(零发包提取), 探活时以 GET 验证可达性; 但若 `probe` 模块未开
    #   (`-m passive`) 或被 `max_probe` 截断, 它**并未被探活** —— 标 True 即过度声称。
    _probed_norm = {normalize_endpoint(p) for p, _m, _st, _n in (ctx.all_found or [])}
    # 1a) 写操作（来自 JS 声明, 零发包）
    write_apis = meta.get("write_apis", {}) or {}
    for p, meth in write_apis.items():
        key = (normalize_endpoint(p), str(meth))
        if key in seen:
            continue
        seen.add(key)
        params = (getattr(ctx, 'pmap', None) or {}).get(p.split("?")[0], set())
        dims, prio, reason = _endpoint_dims(p, meth, params, True)
        rows.append({"path": p, "method": meth, "is_write": True,
                     "kind": _endpoint_kind(p, meta, meth),
                     "probed": normalize_endpoint(p) in _probed_norm,
                     "dims": dims, "priority": prio, "reason": reason})
    # 1b) 被动/探测发现的所有端点（已探活）；跳过静态资源（非可测端点）
    for p, m, st, note in (ctx.all_found or []):
        if _is_static_asset(p):
            continue
        key = (normalize_endpoint(p), str(m))
        if key in seen:
            continue
        seen.add(key)
        params = (getattr(ctx, 'pmap', None) or {}).get(p.split("?")[0], set())
        is_write = "写操作" in (note or "") or str(m).upper() in ("POST", "PUT", "DELETE", "PATCH")
        dims, prio, reason = _endpoint_dims(p, m, params, is_write)
        rows.append({"path": p, "method": _decl.get(normalize_endpoint(p), '—'),
                     "is_write": is_write, "kind": _endpoint_kind(p, meta, m),
                     "probed": True,
                     "dims": dims, "priority": prio, "reason": reason})
    # 1c) JS 源码声明但未探活的接口候选 —— 仍是"待复核线索", 纳入矩阵避免漏覆盖。
    #     已探活/写操作的条目优先（1a/1b 先入 seen）, 此处只补差集。
    _srcline = meta.get("api_srcline") or {}
    _conf = meta.get("api_conf") or {}
    for p in _srcline:
        cp = _candidate_path(p)
        if not cp:
            continue
        # 去重键必须用**展示方法**(JS 声明)而非写死 "GET" —— 否则"既是写声明(POST, 1a 已入)
        #   又在源码候选(1c)"的路径会因键不同而**重复成两行**(实测 macrozheng: /admin/login 等 8 条)。
        _m_decl = _decl.get(normalize_endpoint(cp), 'GET')
        key = (normalize_endpoint(cp), _m_decl)
        if key in seen:
            continue
        seen.add(key)
        params = (getattr(ctx, 'pmap', None) or {}).get(cp.split("?")[0], set())
        dims, prio, reason = _endpoint_dims(cp, "GET", params, False)
        reason = (reason + "；仅源码声明(未探活)").strip("；")
        rows.append({"path": cp, "method": _decl.get(normalize_endpoint(cp), '—'),
                     "is_write": False, "probed": False,
                     "kind": _endpoint_kind(cp, meta, "GET"),
                     "confidence": _conf.get(p, "-"),
                     "dims": dims, "priority": prio, "reason": reason})
    # 2) 严重度提升：有 CRITICAL/HIGH 发现直接指向该端的, 升到 P0
    sev_paths = set()
    for sev, typ, url, ev in (ctx.findings or []):
        if sev in ("CRITICAL", "HIGH") and url:
            sev_paths.add(normalize_endpoint(url.split("?")[0]))
    for r in rows:
        if normalize_endpoint(r["path"].split("?")[0]) in sev_paths and r["priority"] != "P0":
            r["priority"] = "P0"
            r["reason"] = (r["reason"] + "；关联高危发现").strip("；")
    # 3) 排序：P0 → P1 → P2, 同档按路径
    _pri = {"P0": 0, "P1": 1, "P2": 2}
    rows.sort(key=lambda r: (_pri[r["priority"]], r["path"]))
    # 3.5) 疑似未授权访问启发式(越权线索)：仅当本次扫描**未带会话(匿名)**时触发。
    #      **定义（用户明确）**：未授权访问 = **无身份信息访问了"本应需要认证"的资源**；
    #      信息泄露只是**结果**。故判据取**访问控制面**(`dicts.access_control_surface` —— 单一事实来源):
    #        · auth   —— **需认证**的账户/会话面(account/session/credential/apikey…)
    #        · unauth —— 内部/运维/调试面(internal/debug/console/env/manage/backup/actuator…)
    #        · config 且高危管理段(admin/actuator/metrics/monitor/dashboard)
    #      ⚠️ **公开认证入口(login/logout/signup/reset/token/oauth…)按设计即匿名可达, 不计入** ——
    #      否则会把正常登录页/注销接口误报为"疑似未授权访问"(用户反馈的误报)。
    #      **"敏感数据面"(user/order/profile/payment/balance…)** 是**内容**, 属"信息泄露"结果,
    #      由「敏感信息响应」finding 单独表达, **不计入未授权访问**（判据是"无凭据访问受保护资源"，
    #      不是"内容敏感"）。纯对已采集事实的相关性分析——匿名扫描下探针拿到的 2xx 响应长度,
    #      不发包、不验证、不构成漏洞判定；带认证扫描无法判断匿名可达性, 故不触发。
    #      注: config 维度只取高危管理面, 避免把 health/status/swagger 等本就可能公开的面误标。
    _anon = not _auth_state(ctx)
    _probe_len = {}
    import re as _re
    for _p, _m, _st, _note in (ctx.all_found or []):
        if isinstance(_st, int) and 200 <= _st < 300:
            _ml = _re.search(r'len=(\d+)', str(_note or ''))
            if _ml:
                # 关联键**只按路径**(method 无关): 未被 JS 声明、method 被规约为 `—` 的
                #   探活端点(字典/hidden/sitemap 探出的管理面)也能正确关联其实质内容长度,
                #   否则这些匿名可达的真实内容会因 (path,'GET')≠(path,'—') 漏标 broken_access_hint。
                _probe_len[normalize_endpoint(_p)] = int(_ml.group(1))
    unauth_hits = []
    if _anon:
        for r in rows:
            if not r.get("probed"):
                continue
            _cl = _probe_len.get(normalize_endpoint(r["path"]))
            if _cl is None or _cl < _UNAUTH_CONTENT_MIN:
                continue
            # 判据 = 访问控制面(仅需认证面/内部运维面/高危管理面)。
            if access_control_surface(r["path"]):
                r["broken_access_hint"] = True
                r["content_len"] = _cl
                r["reason"] = (r["reason"] + "；无认证即返回内容(疑似未授权访问)").strip("；")
                if r["priority"] != "P0":
                    r["priority"] = "P0"
                unauth_hits.append(r)
    # 3.9) 404 = **未找到** → 不给 P0/P1: 给一个不存在的路径排高优先级是误导。
    #      降为 P2 并显式标注"未确认" —— 优先级只对**已确认**端点有意义。
    _p404 = {normalize_endpoint((p or '').split('?')[0])
             for p, _m, _st, _n in (getattr(ctx, 'all_found', None) or []) if _st == 404}
    for r in rows:
        if normalize_endpoint(r["path"].split("?")[0]) in _p404:
            r["priority"] = "P2"
            # 显式"未找到"标记: 供候选层排除(不存在的路径不该出"管理面存在性线索")。
            r["not_found"] = True
            r["reason"] = (r.get("reason", "") + "；探活 404 · 未确认, 优先级仅供参考").strip("；")
    # 3.91) **受保护(需认证) → 不标"暴露", 不升 P0**。两种形态**同判**(口径统一, 避免分叉):
    #         · HTTP 401/403 —— 访问控制生效(无凭据被拒);
    #         · HTTP 200 但响应是**登录页** —— 探活层已标注 note='受保护(需登录)'(engine 判定),
    #           同样"其实要求登录"(与业务码未授权同理)。**旧实现只覆盖 401/403**, 于是
    #           返回登录页的管理面(200)仍被标 P0/"暴露" —— 与用户反馈的 403 误标同源。
    #       管理/配置面 / 需认证账户面 属此列时, 并非"匿名可达的高危/暴露面"; 原样标 P0
    #       会误导为"匿名可达优先测"。与 3.9(404 未找到) 同理: 优先级只对**已确认暴露**的端点有意义。
    _protected_norm = {
        normalize_endpoint((p or '').split('?')[0])
        for p, _m, _st, _n in (ctx.all_found or [])
        if _st in (401, 403) or '受保护' in str(_n or '')
    }
    for r in rows:
        # **证据优先级**: 若该端点已被**确认为匿名可达**(broken_access_hint, 即 200+实质内容),
        #   不因另一路探测的 401/403/登录页 而降级 —— "已证实暴露"强于"受保护"。仅在无暴露证据时降级。
        if normalize_endpoint(r["path"].split("?")[0]) in _protected_norm \
                and not r.get("broken_access_hint"):
            r["priority"] = "P2"
            # 显式"受保护(需认证)"标记: 供候选层识别"管理面存在但未暴露"(存在性线索)。
            r["protected"] = True
            _old = r.get("reason", "")
            # 明确"受保护·需认证", 去掉"暴露"语义
            _new = _old.replace("管理/配置/监控面", "管理/配置/监控面(受保护·需认证)")
            if "受保护" not in _new:
                _new = (_new + "；受保护·需认证(401/403 或 登录页)").strip("；")
            r["reason"] = _new.strip("；")
    # 4) 汇总
    summary = {"P0": 0, "P1": 0, "P2": 0, "by_dim": {d: 0 for d in DIM_ORDER}}
    for r in rows:
        summary[r["priority"]] += 1
        for d in DIM_ORDER:
            if r["dims"][d]:
                summary["by_dim"][d] += 1
    # 4.5) 参数级意图标注：把"命中维度"细化到触发它的具体参数，并跨端点聚合。
    #      纯静态聚合(复用 _endpoint_dims 同款关键词集)，不发包、不留存取值样例。
    param_index = {d: {} for d in _PARAM_INTENT_DIMS}
    _pm_shapes = getattr(ctx, 'param_shapes', None) or {}
    for r in rows:
        _rp = r["path"].split("?")[0]
        _pi = _endpoint_param_intent(r["path"], (getattr(ctx, 'pmap', None) or {}).get(_rp, set()), _param_r)
        if _pi:
            r["param_intent"] = _pi
            for _dim, _items in _pi.items():
                _bk = param_index[_dim]
                for _n, _k in _items:
                    _e = _bk.setdefault(_n, {"kind": _k, "endpoints": [], "shapes": set()})
                    _e["endpoints"].append(r["path"])
                    # 取值形态(来自运行时捕获; 静态扫描时为空集)
                    _e["shapes"] |= set((_pm_shapes.get(_rp, {}) or {}).get(_n, set()))
    # 集合 → 排序列表: 保证 JSON 可序列化(侧车 / JSON 报告)。
    for _bk in param_index.values():
        for _e in _bk.values():
            _e["shapes"] = sorted(_e.get("shapes") or [])
    legend = {
        "dimensions": DIM_LABELS,
        "priority": {
            "P0": "先测：写操作 / 认证账户面 / 管理配置监控面 / 内部调试面 / 关联高危发现",
            "P1": "重点：含对象引用参数(IDOR候选) / 敏感数据面 / 外部地址型参数(SSRF候选)",
            "P2": "常规：只读或列表类接口，低先验风险",
        },
        "disclaimer": "本矩阵是基于端点特征的【风险提示与测试优先级排序】，不是漏洞判定；"
                      "所有条目均为待人工复核的线索，是否构成风险取决于授权范围内的实际验证。",
    }
    return {"rows": rows, "summary": summary, "legend": legend,
            "param_intent_index": param_index,
            "unauth_access_hints": [
                {"path": r["path"], "method": r["method"],
                 # 命中维度 = **访问控制面**（触发依据）：需认证账户面 auth / 内部运维面 unauth /
                 #   高危管理面 config；公开认证入口(login/logout…)与敏感数据面均不作依据, 故不列。
                 "dims": [d for d in ("auth", "unauth", "config")
                          if d in access_control_surface(r["path"])],
                 "content_len": r.get("content_len")}
                for r in unauth_hits
            ]}



def _unauth_access_html(m):
    """疑似越权访问线索 HTML 段（与 Markdown 同源）。"""
    hits = m.get("unauth_access_hints") or []
    if not hits:
        return ''
    body = ('<table><tr><th>端点</th><th>方法</th><th>命中维度</th>'
            '<th>匿名响应长度</th><th>说明</th></tr>')
    for h in hits:
        dims = '/'.join(_esc(DIM_LABELS.get(d, d)) for d in h["dims"])
        body += (f'<tr><td><code>{_esc(h["path"])}</code></td><td>{_esc(h["method"])}</td>'
                 f'<td>{dims}</td><td>{h["content_len"]} B</td>'
                 f'<td class="note">无认证即返回内容</td></tr>')
    body += '</table>'
    # 仅返回**内容**(卡片与标题由调用方 report_html 统一包裹/编号, 保证章节号与目录一致)
    return ('<p class="note">仅当本次扫描<b>未带会话（匿名）</b>时触发。'
            '<b>未授权访问 = 无身份信息访问了"本应需要认证"的资源</b>'
            '（认证 / 账户面 · 内部运维调试面 · 高危管理面）；<b>信息泄露只是结果</b>'
            '（敏感数据面匿名可达由「敏感信息响应」单独表达）。纯对已采集事实的相关性分析，'
            '<b>不发包、不验证、不构成漏洞判定</b>；是否越权由人工确认。</p>' + body)

# ---------- 认证机制图谱（已整体移除） ----------
#   原「猎人模式 T1」遗留项 —— 认证机制图谱(E) 及其渲染器 `_auth_mechanisms_html` 已随
#   「猎人模式」一并删除（连同 recon/auth.py、plugins 'auth' enricher、config `auth_map`）。


# ---------- 待验证风险假设（测试建议 · 非利用） ----------
#   把"端点风险维度"展开成**可测的风险假设 + 安全验证方式**, 供人工在**授权范围内**复核。
#   通用映射(维度 → bug 类), 不涉站点特化; 命令一律**只读 GET + 本人会话**, 不给利用载荷。
_HYPOTHESIS_ORDER = ('idor', 'unauth', 'auth', 'ssrf', 'sensitive', 'sqli', 'config', 'write')


def _hypotheses_of(row):
    """由端点维度得出"待验证的风险假设"键列表(通用映射)。

    写操作端点把 `write` 放**首位** —— 让它的安全验证取"勿发写请求"的指引。
    """
    dims = row.get('dims') or {}
    out = []
    # 公开认证入口(login/logout/signup/reset/token/oauth/sso…)按设计即匿名可达 → **不是**
    #   "越权写"候选, 不给 write 假设(与 _endpoint_dims 的 _write_risk 同口径)。
    _pub_auth = bool(surface_segments(row.get('path') or '') & _AUTH_PUBLIC_KW)
    if row.get('is_write') and not _pub_auth:
        out.append('write')
    for k in _HYPOTHESIS_ORDER:
        if k == 'write':
            continue
        if dims.get(k):
            out.append(k)
    return out


def _safe_verify(base, path, method, dim):
    """生成**安全、只读**的验证命令 / 思路(不含任何利用载荷)。"""
    import re as _re
    b = (base or '').rstrip('/')
    p = str(path or '')
    if not p.startswith('/'):
        p = '/' + p
    p = _re.sub(r'\{[^}]+\}', '1', p)          # {id} → 1
    p = _re.sub(r':[A-Za-z_]\w*', '1', p)      # :id → 1
    url = b + p
    # 防 copy-paste 命令注入: 路径/URL 可能含单引号 → 在单引号 shell 串中必须转义为 '\''
    # (POSIX 单引号内 $,`,; 等均不展开, 只需处理单引号本身)。否则恶意目标路径如
    # `/x';id;'` 会被粘贴为 `curl -sS '/x';id;'` 触发二次命令执行。
    url = url.replace("'", "'\\''")
    if dim == 'idor':
        return (f"`curl -sS -b '<你的会话>' '{url}'`(id=1)，再把 id 改成 `2`，"
                f"比对是否越权互读**你的两个测试对象**(水平越权 · 仅限自有测试账号, 勿碰真实他人数据)"
                "（curl 默认 UA 易被 WAF 拦, 按需加 `-A` 浏览器 UA）")
    if dim == 'unauth':
        return f"`curl -sS '{url}'`(**不带**会话)观察是否直接返回数据（curl 默认 UA 易被 WAF 拦, 按需加 `-A` 浏览器 UA）"
    if dim == 'config':
        return f"`curl -sS '{url}'` 检查是否暴露配置/调试/监控信息（curl 默认 UA 易被 WAF 拦, 按需加 `-A` 浏览器 UA）"
    if dim == 'sensitive':
        return f"`curl -sS -b '<你的会话>' '{url}'` 检查响应是否含 PII/凭据等敏感数据（curl 默认 UA 易被 WAF 拦, 按需加 `-A` 浏览器 UA）"
    if dim == 'ssrf':
        return "仅思路: 把外部地址型参数指向**你自己的**回连地址, 观察是否发起请求(勿指向第三方)"
    if dim == 'sqli':
        return "仅思路: 用**你自己的**测试参数观察报错/时延差异(勿用破坏性 payload)"
    if dim == 'auth':
        return "仅思路: 用**两个不同权限账号**访问同一端点, 比对可见范围(越权/弱鉴权)"
    if dim == 'write':
        return "仅思路: **不要**发写请求; 用只读 GET 或接口文档核对越权写/逻辑缺陷风险"
    return "仅思路: 人工复核该端点的访问控制与返回数据范围"


# 注: 原「待验证漏洞假设」独立渲染器(_hyp_rows / _hypotheses_markdown / _hypotheses_html)已移除
#   —— 已合并进 `_recon_matrix_markdown/_html`(端点风险表新增"漏洞假设"+"只读验证"两列),
#   避免同一批端点被两节重复列举。`_hypotheses_of` / `_safe_verify` 仍被合并后的渲染器复用。


def _plugins_list(cfg):
    """插件清单(方案 9.1) —— 列出本次实际启用的 Collector/Parser/Prober/Enricher; 失败不影响报告。"""
    try:
        from ..core import plugins as _p
        return _p.list_plugins(cfg)
    except Exception:
        return []


def _sh_sq(s):
    """POSIX 单引号安全包裹 —— 供 replay.sh 使用。

    单引号内 `$`/反引号/`;` 等**均不展开**, 只需处理单引号本身(`'\''`)。
    目标可控的路径字面量(如 `/x';id;'`)若用双引号包裹, `$()` / 反引号会被
    分析员 copy-paste 执行时展开 —— 与 `_safe_verify` 同一威胁, 同一防法。
    """
    return "'" + str(s).replace("'", "'\\''") + "'"


def _sh_comment(s):
    """replay.sh 注释行字段净化: 换行会终止 `#` 注释 → 其后内容被当作命令执行。"""
    return str(s).replace('\r', ' ').replace('\n', ' ')


def write_replay_sh(ctx, base, meta, path):
    """导出**只读复现脚本** `replay.sh`(方案 §8 输出三件套之一)。

    · 每条端点一行 `curl`, **只读方法**(GET/HEAD/OPTIONS; 写方法一律降级为 GET —— 只读护栏);
    · 鉴权用**占位符** `$AUTH_HEADER`, **不回填任何真实凭据**(由使用者自行填);
    · 与 HTML/JSON **同源**(同一 `_endpoint_master_risk`), 保证三者一致。
    返回写入的端点数。
    """
    import os as _os
    import re as _re2
    from urllib.parse import urlsplit as _urlsplit
    _am = build_recon_matrix(ctx, meta)
    _, _, _sr = _load_report_rules(ctx, meta)        # 只用 source 规则
    _rows = _endpoint_master_risk(ctx, list(getattr(ctx, 'all_found', []) or []),
                                  meta.get('write_apis') or {}, meta, _sr, _am)
    # 复现脚本的 URL 基址取**目标 origin(scheme://host)** —— 旧实现直接对 `base` 做
    #   rstrip('/'): 当 `base` 是含路径的扫描入口(如 `http://h/login`)时, 会拼出
    #   `http://h/login/api/...`(实测 405)。端点路径本身已是绝对路径(`/api/...`),
    #   故只应前缀 origin。
    _sp = _urlsplit(base or '')
    _b = (f'{_sp.scheme}://{_sp.netloc}' if (_sp.scheme and _sp.netloc)
          else (base or '').rstrip('/'))
    lines = [
        '#!/usr/bin/env bash',
        '# facet 只读复现脚本（方案 §8 三件套）—— 全部为**只读**请求, 不含任何利用载荷。',
        '# 用法: 按需填写 AUTH_HEADER 后执行; 请仅在**已授权**范围内运行。',
        f'# 目标: {base}',
        'set -u',
        'AUTH_HEADER="${AUTH_HEADER:-}"   # 例: AUTH_HEADER=\'-H "Authorization: Bearer <token>"\'',
        '',
    ]
    for _r in _rows:
        _disp, _mth, _src, _sn = _r[0], _r[1], _r[2], _r[3]
        # `—` 是报告"方法"列对**无 JS 声明**的占位符, 不是真实方法 → 不能当作"原方法"披露
        _decl_raw = str(_mth or '').strip()
        _decl_m = '' if _decl_raw in ('—', '-', '') else _decl_raw.rstrip('*').upper()
        _method = _decl_m if _decl_m in ('GET', 'HEAD', 'OPTIONS') else 'GET'
        # 只读护栏: 复现脚本绝不发写方法。但**必须披露**原方法 —— 否则分析员只看到
        #   `-X GET /api/v1/profile`, 会误以为该端点真是 GET(而 JS 声明的是 PUT)。
        _note = _sn if _decl_m in ('', _method) \
            else f'{_sn} · 原方法 {_decl_m}(只读降级为 {_method})'
        _url = _b + '/' + str(_disp).lstrip('/')
        _url = _re2.sub(r'\{[^}]+\}', '1', _url)
        _url = _re2.sub(r':[A-Za-z_]\w*', '1', _url)
        lines.append(f'# [{_sh_comment(_src)}] {_sh_comment(_note)}')
        lines.append(f'curl -sS -X {_method} $AUTH_HEADER {_sh_sq(_url)}')
        lines.append('')
    ensure_parent(path)
    _atomic_write_text(path, '\n'.join(lines) + '\n')
    try:
        _os.chmod(path, 0o755)
    except Exception:
        pass
    return len(_rows)


def write_recon_matrix(ctx, meta, path):
    """把端点标注（风险提示与测试优先级，非漏洞判定）落盘为 JSON 侧车文件。

    与 MD/HTML/JSON 报告**同源**（都来自 build_recon_matrix），因此侧车同样携带
    `param_intent_index`（参数级意图标注）与 `unauth_access_hints`（疑似越权访问线索），
    避免这两项新增强只活在人读报告里、机器可读侧车却缺失。
    """
    m = build_recon_matrix(ctx, meta)
    payload = {
        "version": __version__,
        "summary": m["summary"],
        "legend": m["legend"],
        "rows": m["rows"],
        "param_intent_index": m.get("param_intent_index", {}),
        "unauth_access_hints": m.get("unauth_access_hints", []),
    }
    _atomic_dump_json(path, payload)
    log(f'端点标注(风险提示): {path} | P0={m["summary"]["P0"]} P1={m["summary"]["P1"]} P2={m["summary"]["P2"]}')

# ---------- Markdown 报告 ----------
# 覆盖能力开关 —— 默认关时, 报告须显式披露"没扫什么"(否则"没扫到"会被误读成"目标没有")。
_COVERAGE_FEATURES = (
    ('运行时渲染(SPA 客户端渲染)', 'runtime', 'runtime: true'),
    ('多页爬取', 'crawl_depth', 'crawl_depth: 2'),
    ('OPTIONS/Allow 方法发现', 'options_probe', 'options_probe: auto'),
    ('构建产物拆包', 'unbundle', 'unbundle: true (默认 auto)'),
    ('强反混淆(webcrack / VM 可读化)', 'strong_deobf', 'strong_deobf: true (默认 auto)'),
    ('动态解包(L3-L5 密封沙箱)', 'dynamic_deobf', 'dynamic_deobf: true (或 auto)'),
    # 以下同为"默认关的覆盖扩展" —— 一并披露, 避免"没扫到"被误读成"目标没有"。
    ('OSV 在线漏洞库查询(SCA 增强)', 'sca_osv', 'sca_osv: true'),
    ('密钥实时验证(第三方只读)', 'verify_secrets', 'verify_secrets: true'),
    ('兜底探测(未命中指纹时的通用端点)', 'fallback_probe', 'fallback_probe: true'),
    ('扩展隐藏路径字典层', 'hidden_paths_extended', 'hidden_paths_extended: true'),
)

# 截断原因 → 人类可读标签(报告"扫描完整性"用)。未知键原样回退, 保证向后兼容。
_TRUNC_LABELS = {
    'js': 'JS 队列(按优先级)',
    'js_queue_unscanned': 'JS 未扫完(可 --resume 续扫)',
    'probe': '端点探活',
    'sitemap': 'sitemap 条目',
    'sitemap_index_depth': 'sitemap 索引深度',
    'global_timeout': '全局时间预算(已中止并导出部分结果)',
    'js_time': 'JS 阶段时间预算',
    'route_harvest_pages': '入口页收割(max_pages)',
    'unbundle_oversize': '超大文件跳过拆包(体积阈值)',
    'strong_deobf_oversize': '超大文件跳过强反混淆(体积阈值)',
    'spa_route_harvest_pages': 'SPA 路由收割(页数上限)',
    'spa_route_barren': 'SPA 路由无新增(提前停止)',
}


def _trunc_label(k):
    return _TRUNC_LABELS.get(k, k)


# 静默 JS 的**归类 → 可操作建议**：只说"没产出"没用, 要给出下一步该开哪个开关。
#   键为 `_silence_reason` 的返回; `'疑似打包产物'` 按**前缀**匹配(带打包器名, 如 `(webpack)`)。
_SILENT_HINTS = {
    '疑似打包产物': '属**打包产物**(代码在, 只是模块化封装) → 可开 <code>unbundle: true</code>'
                    '(默认 auto, 需 webcrack) 逐模块深析',
    '疑似混淆': '可试 <code>strong_deobf: true</code>(静态, 安全)',
    '含解包链': '可试 <code>dynamic_deobf: true</code>(密封沙箱内执行目标代码, 默认关)',
}


def _silent_hint(reason):
    """静默 JS 归类 → 可操作建议(HTML 片段); 无建议返回 ''。"""
    r = str(reason or '')
    if r in _SILENT_HINTS:
        return _SILENT_HINTS[r]
    for k, v in _SILENT_HINTS.items():          # 打包产物带打包器名 → 前缀匹配
        if r.startswith(k):
            return v
    return ''


def _coverage_state(ctx):
    """返回 (disabled: [(名称, 开关)], is_static_single: bool)。

    读取 ctx.config 判断哪些覆盖能力处于关闭态; 缺 config 时按"全关"处理(保守)。
    runtime 特殊: 三态(false/true/auto)。'auto' 只有在**实际运行过**(ctx.runtime_ran)时
    才算"已启用" —— 否则(auto 但目标非 SPA)应如实披露为"未启用", 避免把"没跑"说成"跑了"。
    """
    cfg = getattr(ctx, 'config', None) or {}

    def _on(key):
        if key == 'runtime':
            # 能力宣称=真实执行: 只有**确实跑过**才算"已启用"。显式 `runtime: true` 但依赖缺失
            #   (Playwright 未装)或异常导致未跑时, 必须**如实披露为"未启用"** —— 旧实现用
            #   `(cfg.runtime is True) or runtime_ran`, 会把"没跑"说成"跑了"(实测缺陷)。
            return bool(getattr(ctx, 'runtime_ran', False))
        if key == 'strong_deobf' and cfg.get(key) == 'auto':
            # auto = 依赖(node+webcrack)可用才启用 → 披露按**真实可用性**(缺依赖时不谎报"已启用")
            try:
                from ..core.deobf import strong_available
                return strong_available()
            except Exception:
                return False
        if key == 'unbundle' and cfg.get(key) == 'auto':
            try:
                from ..recon.unbundle import webcrack_available
                return webcrack_available()
            except Exception:
                return False
        return bool(cfg.get(key))

    disabled = [(n, f) for n, k, f in _COVERAGE_FEATURES if not _on(k)]
    is_static = all(not _on(k) for k in
                    ('runtime', 'crawl_depth',
                     'verify_secrets', 'dynamic_deobf'))
    return disabled, is_static


def _auth_state(ctx):
    """本次扫描是否**带会话**（来自 --cookie / --token）。

    认证态是覆盖边界的关键一条: 未带会话 → 登录后接口/页面不可见, 报告必须讲明,
    否则使用者会把"没扫到登录后的面"误当成"目标没有"。
    """
    cfg = getattr(ctx, 'config', None) or {}
    # **单一事实来源**(dicts.has_auth_session): 覆盖 --cookie / --token / **自定义鉴权头**
    #   (如 `header: "X-Access-Token: …"`) —— 否则自定义头鉴权时报告会误称"未认证"。
    return has_auth_session(cfg)


# ---------- 与上次扫描的差异（持续侦察） ----------
#   用已存的扫描历史(ScanHistory, sqlite)对比"同一目标上一次扫描", 产出新增/消失。
#   "新增端点/新增发现"正是持续侦察最高价值的信号。无历史 → 不出现该段。
def _scan_diff(ctx, base):
    # 持续侦察差异**仅在保留历史时**才有意义(否则无"上次扫描"可比) —— 默认(save_history 关闭)
    #   直接跳过: 既避免报告凭空出现该段, 也避免 ScanHistory() 在输出目录创建空的 history.db。
    if not (getattr(ctx, 'config', None) or {}).get('save_history'):
        return None
    try:
        import sqlite3
        h = ScanHistory()
        b = (base or '').rstrip('/')
        # closing(): sqlite3 的 with 只管事务不关连接 —— 此前靠 GC 回收(全库审计 L)。
        with closing(sqlite3.connect(h.path)) as conn:
            rows = conn.execute('SELECT scan_id, time FROM scans WHERE base=? '
                                'ORDER BY time DESC LIMIT 1', (b,)).fetchall()
            if not rows:
                # LIKE 通配符**必须转义**: base 若含 `%`/`_`/`\`(如 URL 编码 `%20`), 会被当通配符
                #   → 误匹配到别的目标的历史扫描(差分张冠李戴)。用 ESCAPE 只让末尾的 % 生效。
                _b_like = b.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
                rows = conn.execute("SELECT scan_id, time FROM scans WHERE base LIKE ? ESCAPE '\\' "
                                    'ORDER BY time DESC LIMIT 1', (_b_like,)).fetchall()
            if not rows:
                return None
            prev_id, prev_time = rows[0]
            prev_apis = {(p, str(m)) for p, m in
                         conn.execute('SELECT path, method FROM apis WHERE scan_id=?', (prev_id,))}
            prev_find = {(t, u) for t, u in
                         conn.execute('SELECT type, url FROM findings WHERE scan_id=?', (prev_id,))}
        cur_apis = {(p, str(m)) for p, m, st, note in (ctx.all_found or [])}
        # 「新增发现」同样**只计高风险项**(与「完整发现清单」同口径) —— 响应头/写操作/路径收割等
        #   信息性条目不算"值得关注的差异"(它们的变化无处置价值); 端点级变化仍由「新增端点」完整覆盖。
        #   传 sev 走**严重度兜底**, 与 report_html 的清单口径**完全一致**(否则两处会再次不同源)。
        cur_find = {(t, u) for sev, t, u, ev in (ctx.findings or [])
                    if _is_high_risk_finding(t, sev)}
        return {'prev_id': prev_id, 'prev_time': prev_time,
                'new_apis': sorted(cur_apis - prev_apis),
                'gone_apis': sorted(prev_apis - cur_apis),
                'new_findings': sorted(cur_find - prev_find)}
    except Exception as e:
        # 差异段失败静默 = "与上次扫描对比"无声消失(持续侦察能力假存在), 留痕。
        dbg(f'_scan_diff 历史差分失败: {e}')
        return None




def _diff_html(d):
    na, nf, ga = d['new_apis'], d['new_findings'], d['gone_apis']
    h = (f'<p class="note">对比<b>同一目标上次扫描</b>（{_esc(d["prev_time"])}，'
         f'<code>{_esc(d["prev_id"])}</code>）—— 持续侦察。</p>')
    if not (na or nf or ga):
        return h + '<p class="note">与上次扫描<b>无差异</b>。</p>'
    if na:
        h += f'<p class="note"><b>新增端点 ({len(na)})</b></p><ul class="note">'
        h += ''.join(f'<li><code>{_esc(m)} {_esc(p)}</code></li>' for p, m in na[:40])
        h += '</ul>'
    if nf:
        h += f'<p class="note"><b>新增发现 ({len(nf)})</b></p><ul class="note">'
        h += ''.join(f'<li>{_esc(t)} — {_esc(u)}</li>' for t, u in nf[:40])
        h += '</ul>'
    if ga:
        h += f'<p class="note"><b>消失端点 ({len(ga)})</b>（上次有、本次无）</p><ul class="note">'
        h += ''.join(f'<li><code>{_esc(m)} {_esc(p)}</code></li>' for p, m in ga[:40])
        h += '</ul>'
    return h


# ---------- 脱敏（已整体移除） ----------
#   本工具**不再对任何内容做脱敏/打码** —— 报告/JSON/侧车/历史库/审计日志里的
#   端点 URL、finding URL、硬编码证据一律**原样**输出。
#   原 `_redact_url` / `_redact_ctx` / `_redact_paths_in_ctx` 已删除。


# 泛化「隐藏路径」类发现 —— 同一 URL 若已有更具体发现, 应丢弃这些泛化条目。
#   (单一真源: 此前该元组在本文件**硬编码三份**(这里 + 普通主表 + 风险主表),
#   新增类别漏改其一即去重口径静默分叉 —— 全库审计 S17。)
_GENERIC_HIDDEN_TYPES = ('隐藏接口暴露', '隐藏路径伪命中', '隐藏路径空响应', '隐藏接口存在')

# 来源列排序(单一真源): 普通主表与风险主表各排一次 —— 此前两处各自维护字典,
#   风险版多一项「源码候选」; 新增来源漏改其一即静默落到优先级 9(全库审计 S16)。
_SRC_ORDER_BASE = {'业务接口': 0, '探测端点': 1, '字典候选(命中)': 2, '写操作JS': 3,
                   '参数登记': 4, 'Schema字段': 5, 'JS资源': 6, '响应挖掘': 7, '路径推断': 8}
_SRC_ORDER_RISK = {**_SRC_ORDER_BASE, '源码候选': 9}


def _src_rank(src):
    """来源排序键: 取 `·写声明` 后缀前的基名查表 —— 后缀只作标注, 不参与排序分档。"""
    return _SRC_ORDER_RISK.get(str(src).split('·')[0], 9)


def _dedupe_generic_hidden_list(fs):
    """去重: 同一 URL 若已有**更具体**的发现, 丢弃其泛化的「隐藏接口暴露」类条目。

    原因: 栈专属探测(`_swagger_probe`/`_wp_probe`/`_actuator_probe`…)与隐藏路径字典探测
    (`hidden_probe`)会命中**同一路径** → 报告同 URL 出现两条(如 `/v2/swagger.json` 既有
    「Swagger/OpenAPI文档暴露」又有「隐藏接口暴露」)。幂等。
    """
    fs = list(fs or [])
    _specific = {u for _, t, u, _ in fs
                 if not any(k in t for k in _GENERIC_HIDDEN_TYPES)}
    if not _specific:
        return fs
    return [(s, t, u, e) for s, t, u, e in fs
            if not (u in _specific and any(k in t for k in _GENERIC_HIDDEN_TYPES))]


def _confirmed_dict_candidates(ctx, meta):
    """**已探活命中**的字典候选(泛化猜测中确实可达的那些)。

    背景: `dict_candidates` 是"内置泛 API 猜测字典"里**未被 JS/HTML 提取到**的路径(纯猜测)。
    其中**未命中**的项(探活 404/不可达)与目标毫无关系 —— 展示它们只增篇幅、干扰基本判断,
    故报告**只列命中项**; 未命中项一律不展示(它们出现在清单里只代表"值得一试", 不代表存在)。
    """
    cands = meta.get('dict_candidates') or set()
    if not cands:
        return []
    # "命中" = 探活得到**非 404** 响应(端点确实存在); 404=未找到, 不算命中。
    hit = {normalize_endpoint(p) for p, _m, _st, _n in (getattr(ctx, 'all_found', None) or [])
           if _st != 404}
    return sorted(p for p in cands if normalize_endpoint(p) in hit)


# 「高风险发现」白名单 —— 报告「完整发现清单」的**纳入关键词**。
#   降噪目标: 响应头缺失/版本泄露/写操作声明/路径收割/指纹/端口/TLS 等**信息性或加固类**
#   条目不展示(用户要求: 只留硬编码信息、加密相关)。
#   🔴 **严重度兜底(本轮修复)**: 旧实现**只**按关键词子串判定 → 多类 HIGH/CRITICAL 发现
#   (如 `GraphQL内省开放` / `Spring Actuator暴露` / `Druid监控面板可达` / `tRPC introspection开放`
#   / `JeecgBoot管理接口可达` / `ThinkPHP敏感信息泄露` / 用户自定义规则)因**类型名不含关键词**
#   而被**静默吞掉** —— 高危项在 HTML 里完全不可见, 而 JSON/SARIF/ZAP 却有 → 跨端不一致 +
#   分析师看不到最高危的东西(实测 13 类 HIGH/CRITICAL 中 11 类被隐藏)。
#   现改为**严重度兜底 + 关键词扩展**: HIGH/CRITICAL **一律纳入**(关键词只决定 MED/LOW/INFO
#   的信息类条目是否额外纳入) → 降噪仍生效, 但**高危项永不静默消失**。
_HIGH_RISK_FINDING_KW = (
    '硬编码', '敏感信息-', '敏感文件', '密钥', '凭据', 'JWT',
    '加密', '签名', '混淆',
    '响应体泄露', '敏感信息响应', 'URL参数泄露',
    '源码映射', 'SourceMap', '.proto',
)
_HIGH_RISK_SEV = ('HIGH', 'CRITICAL')


def _is_high_risk_finding(typ, sev=None):
    """该发现是否属**高风险**类(决定它是否进入「完整发现清单」)。

    判定 = **严重度兜底** ∪ 关键词扩展:
      · `sev` 为 HIGH/CRITICAL → 一律 True(高危项不得因"类型名没命中关键词"而消失);
      · 否则按类型名匹配 `_HIGH_RISK_FINDING_KW`(硬编码信息/凭据密钥/加密签名/敏感数据泄露/源码泄露)。

    调用方**应尽量传 sev**(只传 typ 时退化为纯关键词判定, 会漏高危项)。
    """
    if str(sev or '').upper() in _HIGH_RISK_SEV:
        return True
    t = typ or ''
    return any(k in t for k in _HIGH_RISK_FINDING_KW)


def _dedupe_generic_hidden(ctx):
    fs = getattr(ctx, 'findings', None)
    if fs:
        ctx.findings = _dedupe_generic_hidden_list(fs)


# ---------- HTML 报告 ----------
class _ReportBuilder:
    """HTML 报告构建器。

    把原 report_html 的嵌套闭包（共享可变状态 _toc/_cur_group/_hs/_hsub/_appx
    与分段渲染）抽为实例方法；所有跨段共享数据挂在 self 上，使每个
    _emit_* 段都能独立测试、互不耦合。渲染逻辑与旧实现逐字节等价。
    """

    def __init__(self, ctx, base, out_html, meta, fs):
        self.ctx = ctx
        self.base = base
        self.out_html = out_html
        self.meta = meta
        self.fs = fs
        self._toc = []
        self._cur_group = ['']
        self._hs = [0]
        self._hsub = [0]
        self._appx = [False]
        self.html = ''
        self.build()

    def build(self):
        self._precompute()
        self._emit_summary()
        self._emit_unauth_surface()
        self._precompute_params()
        self._emit_core_surface()
        self._emit_risk_findings()
        self._emit_assets()
        self._emit_auth_access()
        self._emit_coverage()
        self._emit_appendix()
        self._finalize()

    def _group(self, title):
        """输出一个**分组带**（摘要 / 攻击面 / 风险线索 / 资产与技术栈 / 认证与访问 /
        覆盖与边界 / 附录）, 后续 `_h2` 归属该组, 用于侧栏目录分组。"""
        self._cur_group[0] = title
        return f'<div class="group">{_esc(title)}</div>'

    def _h2(self, title):
        """开启一个顶层卡片并写入动态章节号(同时登记目录锚点与所属分组)。

        转义: 标题**在输出处统一 `_esc`**(与 `_group` 一致); TOC 存原文, 渲染时再 `_esc`。
        当前所有标题均为内部常量, 但统一转义可防"将来把目标可控串传进来"时变成 HTML 注入。
        """
        self._hs[0] += 1
        _aid = f'sec{self._hs[0]}'
        self._toc.append((_aid, f'{self._hs[0]}. {title}', self._cur_group[0]))   # TOC 渲染处已 _esc
        return f'<div class="card" id="{_aid}"><h2>{self._hs[0]}. {_esc(title)}</h2>'

    def _h3(self, title):
        """卡片内的小节号 (x.1 / x.2 ...), 每张卡片开始处重置(标题统一 `_esc`)"""
        self._hsub[0] += 1
        return f'<h3>{self._hs[0]}.{self._hsub[0]} {_esc(title)}</h3>'

    def _appendix(self):
        if self._appx[0]:
            return ''
        self._appx[0] = True
        return (self._group('附录')
                + '<p class="sec-lead">工具内部素材：JS 资源清单、构建产物模块、已排除项，'
                  '供溯源与调试（不影响上方结论）。</p>')

    def _precompute(self):
        self.sev_colors = {'CRITICAL': '#ef4444', 'HIGH': '#f97316', 'MED': '#eab308',
                      'LOW': '#22c55e', 'INFO': '#3b82f6'}
        # jsowl 风格 severity 软色 pill 类名映射(CRITICAL/HIGH/MED/LOW/INFO -> s-*)
        self.sev_cls = {'CRITICAL': 's-critical', 'HIGH': 's-high', 'MED': 's-medium',
                    'LOW': 's-low', 'INFO': 's-info'}
        self.fs = _dedupe_generic_hidden_list(self.fs)     # 去重: 泛化「隐藏接口暴露」被同 URL 具体发现覆盖
        self.sens_groups = {}
        self.other_findings = []
        for sev, typ, url, ev in self.fs:
            if not _is_high_risk_finding(typ, sev):
                continue        # 展示层只留高风险项(响应头/写操作/路径收割等信息性发现不列, 降噪)
            if any(k in typ for k in _GENERIC_HIDDEN_TYPES):
                self.other_findings.append((sev, typ, url, ev))
                continue
            cat = classify_finding(ev)
            if cat != '其他发现':
                self.sens_groups.setdefault(cat, []).append((sev, typ, url, ev))
            else:
                self.other_findings.append((sev, typ, url, ev))

        self.js_files = list(self.meta.get('js_files', []))
        self.api_items = list(self.ctx.all_found)
        # 分类规则外部化(与 MD/HTML 同源): JSON 侧只需 source_rules 保证来源分类口径一致
        _, _, self._src_r = _load_report_rules(self.ctx, self.meta)        # 本段只需 source 规则(业务/参数规则见下方 1930 处)
        self.biz = [x for x in self.api_items if classify_api(x[0], x[3], self._src_r) == '业务接口']
        self.probe_items = [x for x in self.api_items if classify_api(x[0], x[3], self._src_r) == '探测端点']
        self.write_apis = self.meta.get('write_apis', {})
        self.subdomains = sorted(self.meta.get('subdomains', set()))
        self.excluded = getattr(self.ctx, 'excluded', None) or []
        self.overflow = getattr(self.ctx, 'excluded_overflow', 0)
        self.bl = getattr(self.ctx, '_catchall_baseline', None)

        # 顶部关键指标(仪表盘) —— 让分析师一眼看到资产规模
        self._n_cand = (len(self.meta.get('apis', set())) + len(self.meta.get('recomb', set()))
                   + len(self.meta.get('write_apis', {})))
        # 口径: 「接口确认」只计**非 404**(404=未找到, 不是"已确认"); 单列「未确认(404)」—— 与 MD 同口径。
        self._conf_items = [_x for _x in (list(self.biz) + list(self.probe_items)) if (_x[2] if len(_x) > 2 else None) != 404]
        self._n_conf = len(self._conf_items) + len(self.write_apis)
        self._n_404 = (len(self.biz) + len(self.probe_items)) - len(self._conf_items)
        self._n_params = len(self.meta.get('params', set()) or set())

        self.html = f'''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>facet v{__version__} 报告 — {_esc(self.base)}</title>
<style>
:root{{--accent:#2f6fed;--accent-d:#1d4ed8;--ink:#1f2329;--ink2:#475569;--mut:#8a919c;
  --line:#e4e7ec;--line2:#f0f1f3;--card:#fff;--soft:#f5f6f8;--bg:#f5f6f8;
  --crit:#d64545;--high:#d64545;--med:#b7791f;--low:#2f9e6e;--info:#8a919c;
  --accent-soft:#eaf1fe;--danger:#d64545;--danger-soft:#fdecec;
  --warn:#b7791f;--warn-soft:#fdf3e3;--success:#2f9e6e;--success-soft:#e6f6ef;
  --info-soft:#f0f1f3;
  --panel:#fff;--fg:#1f2329;
  --r:12px;--sh:0 1px 2px rgba(31,35,41,.04),0 1px 3px rgba(31,35,41,.06)}}
*{{box-sizing:border-box}}
body{{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
  background:var(--bg);margin:0;color:var(--ink);line-height:1.6;font-size:13.5px;
  -webkit-font-smoothing:antialiased}}
.layout{{max-width:1180px;margin:0 auto;padding:20px;display:grid;
  grid-template-columns:236px minmax(0,1fr);gap:20px;align-items:start}}
.sidebar{{position:sticky;top:20px;max-height:calc(100vh - 40px);overflow:auto;
  background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:10px 8px;box-shadow:var(--sh)}}
.brand{{font-weight:700;font-size:14.5px;padding:8px 12px 10px;color:var(--ink);border-bottom:1px solid var(--line2);margin-bottom:6px}}
.brand .v{{color:var(--mut);font-weight:500;font-size:11.5px}}
.toc{{list-style:none;margin:0;padding:0}}
.toc .grp{{font-size:10.5px;font-weight:700;color:var(--mut);text-transform:uppercase;
  letter-spacing:.06em;margin:12px 0 3px;padding:0 12px}}
.toc a{{display:block;padding:5px 12px;color:var(--ink2);text-decoration:none;font-size:12.5px;
  border-left:2px solid transparent;border-radius:0 6px 6px 0}}
.toc a:hover{{background:var(--line2);color:var(--accent);border-left-color:var(--accent)}}
.main{{min-width:0}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:var(--r);
  padding:16px 18px;margin:14px 0;box-shadow:var(--sh)}}
.banner{{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
  padding:16px 20px;box-shadow:var(--sh);color:var(--ink)}}
.banner h1{{font-size:18px;margin:0 0 6px;color:var(--ink);letter-spacing:.01em;
  display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.banner .meta{{color:var(--ink2);font-size:12.5px}}
.banner .chips{{margin-top:11px;display:flex;flex-wrap:wrap;gap:6px}}
.banner .chip{{background:var(--soft);border:1px solid var(--line);color:var(--ink2);
  border-radius:999px;padding:2px 10px;font-size:11.5px}}
.warning{{display:inline-block;font-size:12px;padding:6px 10px;border:1px solid #f0d9a8;
  background:var(--warn-soft);color:var(--warn);border-radius:8px}}
.group{{display:flex;align-items:center;gap:10px;margin:26px 0 2px;font-size:11.5px;
  font-weight:700;color:var(--mut);text-transform:uppercase;letter-spacing:.07em}}
.group::after{{content:"";flex:1;height:1px;background:var(--line)}}
h2{{font-size:15.5px;margin:0 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line);
  font-weight:650;letter-spacing:.01em}}
h3{{font-size:13.5px;color:var(--ink2);margin:16px 0 7px;font-weight:650}}
h4{{font-size:12.5px;color:var(--mut);margin:12px 0 5px;font-weight:600}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;margin:7px 0}}
th,td{{padding:7px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}
th{{background:var(--soft);color:var(--mut);font-weight:600;font-size:11.5px;
  text-transform:uppercase;letter-spacing:.03em;position:sticky;top:0}}
tbody tr:nth-child(even){{background:#fafbfd}}
tr:hover{{background:#f1f5f9}}
code{{background:var(--line2);border-radius:4px;padding:1px 5px;
  font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;color:#0b3a6f}}
table.ep-risk td{{word-break:break-word}}
table.ep-risk code{{word-break:break-all}}
pre{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;line-height:1.5;
  background:var(--soft);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;color:var(--ink2)}}
.sev{{display:inline-block;padding:2px 8px;border-radius:999px;font-size:10.5px;font-weight:700;
  letter-spacing:.02em;background:var(--info-soft);color:var(--mut)}}
.sev.s-critical{{background:#fdecec;color:#d64545}}
.sev.s-high{{background:#fff1e6;color:#c2410c}}
.sev.s-medium{{background:#fef6e0;color:#b7791f}}
.sev.s-low{{background:#e6f6ef;color:#2f9e6e}}
.sev.s-info{{background:#f0f1f3;color:#8a919c}}
.mth{{display:inline-block;padding:1px 7px;border-radius:6px;font-size:10.5px;font-weight:700;
  font-family:ui-monospace,Menlo,monospace}}
.m-get{{background:#e6f1fb;color:#0c447c}}.m-post{{background:#faeeda;color:#633806}}
.m-put,.m-patch{{background:#eaf3de;color:#27500a}}.m-delete{{background:#fcebeb;color:#791f1f}}
details.grp{{border:1px solid var(--line);border-radius:10px;margin:8px 0;overflow:hidden}}
details.grp>summary{{cursor:pointer;padding:7px 12px;background:var(--soft);font-weight:600;font-size:12.5px;list-style:none}}
details.grp>summary::-webkit-details-marker{{display:none}}
details.grp>summary::before{{content:"▸";display:inline-block;margin-right:6px;color:var(--mut);transition:transform .15s}}
details.grp[open]>summary::before{{transform:rotate(90deg)}}
details.grp .cnt{{color:var(--mut);font-weight:400;font-size:11.5px}}
details.grp table{{margin:0}}
.recon{{margin-top:12px;padding:12px 14px;background:var(--soft);border:1px solid var(--line);border-radius:10px;font-size:12.5px}}
.recon .note{{margin-left:8px}}
.recon ul{{margin:8px 0 0;padding-left:18px}}
.recon li{{margin:4px 0}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));gap:9px;margin:12px 0 4px}}
.stat{{text-align:center;padding:11px 8px;background:var(--soft);border:1px solid var(--line);border-radius:10px}}
.n{{font-size:21px;font-weight:750;color:var(--accent);line-height:1.2}}
.l{{font-size:10.5px;color:var(--mut);margin-top:3px;text-transform:uppercase;letter-spacing:.03em}}
.sevbar{{display:flex;height:9px;border-radius:999px;overflow:hidden;margin:6px 0 10px;background:var(--line2)}}
.sevbar span{{display:block}}
.legend{{display:flex;flex-wrap:wrap;gap:12px;font-size:11.5px;color:var(--mut)}}
.legend b{{color:var(--ink2)}}
.dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle}}
.tag{{display:inline-block;padding:2px 7px;border-radius:6px;font-size:11px;background:var(--line2);color:#475569;margin:2px}}
.note{{font-size:11.5px;color:var(--mut)}}
.sec-lead{{font-size:12px;color:var(--mut);margin:-4px 0 10px}}
.quickviews{{display:flex;align-items:center;flex-wrap:wrap;gap:6px;margin:12px 0}}
.quickviews .qv-label{{font-size:11px;color:var(--mut);margin-right:2px}}
.quickviews a{{display:inline-block;padding:4px 10px;border:1px solid var(--line);border-radius:999px;
  background:var(--card);color:var(--ink2);font-size:11.5px;text-decoration:none}}
.quickviews a:hover{{border-color:var(--accent);color:var(--accent)}}
.vendor-badge{{display:inline-block;margin-left:6px;padding:1px 6px;border-radius:999px;
  background:#eef2ff;color:#4338ca;font-size:10px;font-weight:700}}
.vendor-controls{{display:flex;justify-content:flex-end;align-items:center;gap:6px;margin:8px 0;color:var(--mut);font-size:11.5px}}
.vendor-controls label{{cursor:pointer}}
.warn-banner{{display:block;margin:10px 0;padding:12px 14px;border-radius:10px;
  background:#fef2f2;border:1px solid #fecaca;color:#991b1b;font-size:12.5px;line-height:1.55}}
.warn-banner b{{color:#7f1d1d}}
tr.ep-row{{cursor:pointer}}
tr.ep-row .ep-caret{{display:inline-block;color:var(--mut);font-size:10px;margin-left:4px;transition:transform .15s}}
tr.ep-row.open .ep-caret{{transform:rotate(90deg);color:var(--accent)}}
tr.ep-row.open td{{background:var(--accent-soft)}}
tr.ep-detail{{display:none}}
tr.ep-detail.open{{display:table-row}}
tr.ep-detail>td{{background:var(--soft);padding:10px 14px;border-bottom:1px solid var(--line)}}
tr.src-row{{cursor:pointer}}
tr.src-row .ep-caret{{display:inline-block;color:var(--mut);font-size:10px;margin-left:4px;transition:transform .15s}}
tr.src-row.open .ep-caret{{transform:rotate(90deg);color:var(--accent)}}
tr.src-row.open td{{background:var(--accent-soft)}}
tr.src-detail{{display:none}}
tr.src-detail.open{{display:table-row}}
tr.src-detail>td{{background:var(--soft);padding:10px 14px;border-bottom:1px solid var(--line)}}
tr.fnd-row{{cursor:pointer}}
tr.fnd-row .ep-caret{{display:inline-block;color:var(--mut);font-size:10px;margin-left:4px;transition:transform .15s}}
tr.fnd-row.open .ep-caret{{transform:rotate(90deg);color:var(--accent)}}
tr.fnd-row.open td{{background:var(--accent-soft)}}
tr.fnd-detail{{display:none}}
tr.fnd-detail.open{{display:table-row}}
tr.fnd-detail>td{{background:var(--soft);padding:10px 14px;border-bottom:1px solid var(--line)}}
.epd .epd-sec{{margin:0 0 10px}}
.epd .epd-sec:last-child{{margin-bottom:0}}
.epd-k{{font-size:10.5px;font-weight:700;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}}
.code-hit,.pkt{{white-space:pre-wrap;word-break:break-all;max-height:240px;overflow:auto;margin:4px 0 0}}
.code-hit mark{{background:#fde68a;color:#78350f;border-radius:2px;padding:0 1px}}
.pkt .pkt-method{{color:var(--accent-d);font-weight:700}}
.pkt .pkt-note{{color:var(--mut)}}
.pkt .ph{{background:#fef3c7;color:#92400e;border-radius:3px;padding:0 2px}}
.copy-btn{{background:var(--card);border:1px solid var(--line);color:var(--ink2);border-radius:6px;
  padding:2px 10px;font-size:11px;cursor:pointer;margin:5px 6px 0 0}}
.copy-btn:hover{{color:var(--accent);border-color:var(--accent)}}
.recon-list{{margin:8px 0 0;padding-left:18px;font-size:12.5px}}
.recon-list code{{font-family:ui-monospace,Menlo,monospace;font-size:12px}}
.brev{{display:inline-block;font-family:ui-monospace,Menlo,monospace;font-size:10.5px;
       padding:0 5px;margin:0 3px 2px 0;border:1px solid var(--line);border-radius:6px;color:var(--mut)}}
a.anchor{{color:inherit;text-decoration:none}}
@media(max-width:1000px){{.layout{{grid-template-columns:1fr}}.sidebar{{position:static;max-height:none}}}}
@media(max-width:760px){{body{{font-size:13px}}.layout{{padding:12px}}.card{{padding:16px}}.stats{{grid-template-columns:repeat(3,1fr)}}}}
@media print{{body{{background:#fff}}.sidebar{{display:none}}.layout{{display:block;max-width:none;padding:0}}.card{{break-inside:avoid;box-shadow:none}}}}
</style></head><body>
<div class="layout">
<aside class="sidebar"><div class="brand">facet <span class="v">v{__version__}</span></div><!--TOC--></aside>
<main class="main">
<div class="banner"><h1>facet 侦察报告 <span class="warning">敏感数据，请妥善保管</span></h1>
  <div class="meta">目标 <b>{_esc(self.base)}</b></div>
  <div class="meta" style="color:var(--mut)">定位: <b>只读侦察 / 攻击面测绘 —— 不做漏洞验证</b>；全部产出为<b>发现级线索（非漏洞判定）</b>，需人工复核</div>
  <div class="chips"><span class="chip">总发包 {self.ctx.total_sent}</span>'''
        if self.bl:
            _bl_mode = self.bl.get('catchall_mode')
            self.html += (f'<span class="chip">catch-all 基线 HTTP {_esc(self.bl["status"])} · '
                     f'{_esc(self.bl["len"])}B' + (f' · {_esc(_bl_mode)}' if _bl_mode else '') + '</span>')
        self.html += ('<span class="chip">认证态: '
                 + ('已认证（已提供会话）' if _auth_state(self.ctx) else '匿名（未提供 --cookie/--token）')
                 + '</span></div></div><!--QUICKVIEWS-->')
        # 概览卡片: 严重度分布(堆叠条+图例) + 资产规模 KPI
        self._sev_counts = {s: sum(1 for x in self.fs if x[0] == s)
                       for s in ('CRITICAL', 'HIGH', 'MED', 'LOW', 'INFO')}
        self._sev_total = sum(self._sev_counts.values()) or 1
        #   章节号与侧栏目录由同一处登记 —— 保证"卡片编号"与"目录条目"永不漂移。
        #   （_group / _h2 / _h3 定义见下方；此处先置状态，使「摘要」分组带可在概览卡前输出）
        self._hs = [0]
        self._toc = []           # [(anchor, label, group)]
        self._cur_group = ['']



    def _emit_summary(self):
        # ================= 摘要（先看这里） =================
        #   每个功能节点 = 分析师的一个问题。本节点回答"这份报告能给我什么"。
        self.html += self._group('摘要')
        self.html += ('<p class="sec-lead">先回答：这份报告能给我什么？资产规模、严重度概览、'
                 '覆盖是否完整 —— 先看这里，再决定要不要深挖后面的节点。</p>')
        self.html += '<div class="card" id="sec-overview"><h2>概览</h2>'
        self.html += '<div class="sevbar">'
        for sev in ('CRITICAL', 'HIGH', 'MED', 'LOW', 'INFO'):
            _n = self._sev_counts[sev]
            if _n:
                self.html += (f'<span style="width:{_n / self._sev_total * 100:.2f}%;'
                         f'background:{self.sev_colors[sev]}" title="{sev} {_n}"></span>')
        self.html += '</div><div class="legend">'
        for sev in ('CRITICAL', 'HIGH', 'MED', 'LOW', 'INFO'):
            self.html += (f'<span><span class="dot" style="background:{self.sev_colors[sev]}"></span>'
                     f'{sev} <b>{self._sev_counts[sev]}</b></span>')
        self.html += '</div>'
        self.html += '<div class="stats">'
        for _v, _l in [(len(self.js_files), 'JS 文件'), (self._n_cand, '接口候选'),
                       (self._n_conf, '接口确认'), (self._n_404, '未确认(404)'),
                       (self._n_params, '参数名'), (len(self.subdomains), '子域名'),
                       (len(self.fs), '发现项')]:
            self.html += f'<div class="stat"><div class="n">{_v}</div><div class="l">{_l}</div></div>'
        self.html += '</div>'
        if self.excluded:
            self.html += (f'<p class="note">已排除项（不计入严重度）: {len(self.excluded)} 条 · 见附录「已排除项」</p>')
        self.html += '</div>'
        # 概览卡归入「摘要」节点并登记到侧栏目录(否则 TOC 里「摘要」为空头分组)
        self._toc.append(('sec-overview', '概览', '摘要'))

        # 授权声明(合规证据链): 目标 / 声明范围 / 授权确认 / 时间 —— SRC 提交与审计复核留痕
        self._scope_decl = (_esc(', '.join(str(x) for x in (getattr(self.ctx, 'scope_rules', None) or [])))
                       if getattr(self.ctx, 'scope_rules', None)
                       else '目标同源（默认保守边界，未显式声明）')
        self._auth_method = getattr(self.ctx, 'auth_method', '') or ''
        self._auth_decl = ('未确认（未经过授权确认）' if not getattr(self.ctx, 'authorized', False)
                      else ('已确认（--yes 跳过交互确认，责任自负）' if self._auth_method == 'cli-skip (--yes)'
                            else '已确认（交互式授权确认）'))
        self._scan_time = (self.meta or {}).get('scan_time') or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.html += '<div class="card" id="sec-authz"><h2>授权声明</h2>'
        self.html += ('<p class="note">本工具为<strong>合规优先的发现级只读侦察</strong>，仅在声明范围内活动；'
                 '以下为本次扫描的授权与范围留痕，供 SRC 提交与审计复核。</p>')
        self.html += '<div class="stats">'
        self.html += f'<div class="stat"><div class="n" style="font-size:13px">{_esc(self.base)}</div><div class="l">目标</div></div>'
        self.html += f'<div class="stat"><div class="n" style="font-size:13px">{self._scope_decl}</div><div class="l">声明范围</div></div>'
        self.html += f'<div class="stat"><div class="n" style="font-size:13px">{_esc(self._auth_decl)}</div><div class="l">授权确认</div></div>'
        self.html += f'<div class="stat"><div class="n" style="font-size:13px">{_esc(self._scan_time)}</div><div class="l">扫描时间</div></div>'
        self.html += '</div>'
        self._sb = int(getattr(self.ctx, 'scope_blocked', 0) or 0)
        if self._sb:
            self.html += (f'<p class="note">范围护栏拦截：本次有 <b>{self._sb}</b> 个越界请求被硬拒（未发出），'
                     f'已计入「扫描完整性」披露。</p>')
        self.html += '</div>'
        self._toc.append(('sec-authz', '授权声明', '摘要'))



    def _emit_unauth_surface(self):
        # ================= 未授权面（无凭据可达 · 优先复核） =================
        #   黑盒(无凭据)下分析师最先要问: 有没有未授权面? 测试面多大?
        #   独立「结论」卡已按用户要求取消(方案 A): 原 3 个统计里, 未授权面数=本节列表长度,
        #   测试面≈概览「接口候选」, 已确认≈概览「接口确认」—— 去重后只保留两种**不重复**形态:
        #   ① 标题行带未授权面计数; ② 本节首行输出 测试面/已确认/源码声明(概览未直接给出的口径)。
        self._extracted_all = (set(self.meta.get('apis') or set()) | set(self.meta.get('recomb') or set())
                          | set(self.write_apis))
        # 注: 「路由」与「业务分类」已整体移除（用户要求）—— 不再计算 read_business / 命名空间段。
        self._unauth = _unauth_surface(self.api_items)
        self._n_extracted = len(self._extracted_all)
        self._n_conf_extracted = len({(_x[0] if len(_x) > 0 else None) for _x in self.api_items}
                                & self._extracted_all)

        self.html += f'<div class="card" id="sec-unauth"><h2>未授权面（{len(self._unauth)}）</h2>'
        self.html += ('<p class="sec-lead">测试面 <b>'
                 f'{self._n_extracted}</b>（已确认 <b>{self._n_conf_extracted}</b> / '
                 f'源码声明 <b>{self._n_extracted - self._n_conf_extracted}</b>）。'
                 '以下为<strong>无凭据可达</strong>的端点 —— 已剔除登录页 / 验证码 / 静态资源等'
                 '设计公开项；命中即优先复核。全部产出为<strong>发现级线索（非漏洞判定）</strong>。</p>')
        if self._unauth:
            self.html += '<ul class="recon-list">'
            for _p in self._unauth[:60]:
                self.html += f'<li><code>{_esc(_p)}</code></li>'
            self.html += '</ul>'
            if len(self._unauth) > 60:
                self.html += f'<p class="note">… 其余 {len(self._unauth) - 60} 条见 JSON 端点清单</p>'
        else:
            self.html += ('<p class="sec-lead">未发现未授权面 —— 无凭据可达的端点均为设计公开项'
                     '（登录页 / 验证码 / 静态资源），或响应与 catch-all 基线一致（无法判定）。</p>')
        self.html += '</div>'
        self._toc.append(('sec-unauth', '未授权面', '摘要'))

        # 注: 「路由」与「业务分类」已整体移除（用户要求）—— 无「业务地图」卡、无按路由/按业务分组、
        #   无前端路由与目标自述业务名清单。



    def _precompute_params(self):
        # 注: 「参数维度」卡**已移除**（用户要求）。本方法现仅做**预计算**，供「基础提取」等章节共用：
        #   `_am`(端点矩阵) / `_ua`(未授权线索) / 报告规则 / 参数总表 / `_core_has` 等。

        self._hsub = [0]

        # --- 预计算派生数据(供各章节共享, 与 Markdown 报告同源) ---
        #   注: 「候选」章节已取消(用户要求) → HTML 与 JSON 报告均不再计算/输出
        #   build_candidates(candidates.py 已随本次清理删除)。
        self._am = build_recon_matrix(self.ctx, self.meta)
        self._ua = _unauth_access_html(self._am)
        # 分类规则外部化: 与 MD/JSON 同源加载一次, 供端点主表共用
        _, self._param_r, self._src_r = _load_report_rules(self.ctx, self.meta)
        self._pt_rows = build_param_table(self.ctx, self.meta, self._am)
        self.params = sorted(self.meta.get('params', set()))
        self.external_apis = sorted(self.meta.get('external_apis', set()))
        # 字典候选: 只取**已探活命中**项 —— 未命中的泛化猜测不展示(降噪; 见 _confirmed_dict_candidates)。
        self._dict_cands_h = _confirmed_dict_candidates(self.ctx, self.meta)
        self._core_has = (self.js_files or self.biz or self.probe_items or self.write_apis or self.params
                     or self.external_apis or self.meta.get('api_srcline') or self.meta.get('schema_apis')
                     or self.meta.get('relative_apis') or self._dict_cands_h)


    def _endpoint_detail_html(self, disp, mth, sn, pp, op):
        """端点主表行点击展开的详情面板: **数据包构造（Burp 格式）**。

        注: 「来源定位 / 命中代码端」已按用户要求移至下方「接口清单（按来源）」的
        **源码定位**行展开面板(同源交互, 见 `_srcline_detail_html`) —— 端点主表只保留
        数据包构造; 两块各司其职: 主表=探活后端点事实+发包构造, 接口清单=提取线索+源码证据。
        数据全部来自扫描期留存, 报告渲染阶段**零发包**。
        """
        _cls = _endpoint_class(sn)
        _pkt = _build_burp_packet(self.base, disp, mth, pp, op, sn,
                                  _cls == 'EXISTS_PROTECTED')
        return '<div class="epd">' + _render_packet_html(_pkt) + '</div>'

    def _srcline_detail_html(self, path):
        """「接口清单（按来源） 源码定位」行点击展开: 来源定位 + 命中代码端。

        与端点主表的展开面板同源同交互; 命中路径在代码窗口里 `<mark>` 高亮。
        派生来源(无精确 srcline 行/列)时如实标注, 不编造位置。
        """
        _t = (self.meta.get('api_srcline') or {}).get(path)
        _snip = (self.meta.get('api_snippet') or {}).get(path)
        _ex = (self.meta.get('api_extractor') or {}).get(path)
        _cf = (self.meta.get('api_conf') or {}).get(path)
        parts = []
        # 1. 来源定位（回溯 JS 位置）
        if _t:
            loc = _esc(_t[0])
            if len(_t) > 1 and _t[1]:
                loc += f':{_esc(_t[1])}'
            if len(_t) > 2 and _t[2]:
                loc += f':{_esc(_t[2])}'
            parts.append('<div class="epd-sec"><div class="epd-k">来源定位（回溯 JS 位置）</div>'
                         f'<code>{loc}</code>'
                         + (f' <span class="tag">extractor:{_esc(_ex)}</span>' if _ex else '')
                         + (f' <span class="tag">置信:{_esc(_cf)}</span>' if _cf else '')
                         + '</div>')
        # 2. 命中代码端（JS 调用现场, 路径高亮）
        if _snip:
            e = _esc_text(_snip)
            needle = _esc_text(path.split('?')[0])
            if needle and needle in e:
                e = e.replace(needle, f'<mark>{needle}</mark>', 1)
            parts.append('<div class="epd-sec"><div class="epd-k">命中代码端'
                         '（JS 调用现场 · 路径已高亮）</div>'
                         f'<pre class="code-hit">{e}</pre></div>')
        else:
            parts.append('<div class="epd-sec"><div class="epd-k">命中代码端</div>'
                         '<span class="note">无精确源码位置（派生来源或 JS 未保留正文）</span></div>')
        return '<div class="epd">' + ''.join(parts) + '</div>'

    def _finding_detail_html(self, loc):
        """「完整发现清单」行点击展开: 来源定位 + 命中代码端(与接口清单源码定位行同款)。

        loc = ctx.finding_loc[key](扫描期写入, 含 src/line/col/probe/snippet)。
        """
        if not loc:
            return ''
        parts = []
        loc_s = _esc(loc.get('src') or '')
        if loc.get('line'):
            loc_s += f':{_esc(loc["line"])}'
        if loc.get('col'):
            loc_s += f':{_esc(loc["col"])}'
        # 定位来源分流: JS/静态资源 → "回溯 JS 位置 + 调用现场"; 响应体/接口 URL →
        #   "命中位置(响应体) + 命中内容" —— 不把响应体位置诡称"JS 位置"。
        _src_s = str(loc.get('src') or '')
        _is_js = _src_s.split('?')[0].lower().endswith(('.js', '.mjs'))
        parts.append('<div class="epd-sec"><div class="epd-k">'
                     + ('来源定位（回溯 JS 位置）' if _is_js else '来源定位（命中位置 · 响应体/接口 URL）')
                     + '</div>'
                     f'<code>{loc_s}</code></div>')
        snip = loc.get('snippet')
        if snip:
            e = _esc_text(snip)
            needle = _esc_text(loc.get('probe') or '')
            if needle and needle in e:
                e = e.replace(needle, f'<mark>{needle}</mark>', 1)
            parts.append('<div class="epd-sec"><div class="epd-k">'
                         + ('命中代码端（JS 调用现场 · 命中处已高亮）' if _is_js
                            else '命中内容（响应体片段 · 命中处已高亮）')
                         + f'</div><pre class="code-hit">{e}</pre></div>')
        else:
            parts.append('<div class="epd-sec"><div class="epd-k">'
                         + ('命中代码端' if _is_js else '命中内容')
                         + '</div><span class="note">无精确源码位置</span></div>')
        return '<div class="epd">' + ''.join(parts) + '</div>'

    def _emit_core_surface(self):
        # ================= 核心提取成果（JS 分析与静态提取） =================
        #   本工具**核心主功能** = 对目标 JS 文件做静态分析, 提取 API 接口 / 参数 / 硬编码信息。
        #   故把"从 JS/HTML 提取到的接口 / 参数 / 路由 / 外部依赖 / 硬编码证据"**置顶**,
        #   分析师第一眼看到核心产出; 指纹 / SCA / 认证态等仅为辅助上下文, 后移。
        if self._core_has:
            # 基础提取 : 接口 / 参数名 / 外部依赖 合并为一章(与模块面 passive 对应)。
            #   注: **敏感信息发现不在此章渲染**(统一在「发现项」章节按类别呈现, 见下方 `_emit_risk_findings`)
            #   —— 故守卫**不含** `sens_groups`；否则"仅有敏感发现、无端点/路由/参数"时会渲染出一张
            #   **空**的「基础提取」卡（实测缺陷）。分组带 + 导语也随守卫内移，避免**孤儿分组带**。
            self.params = sorted(self.meta.get('params', set()))
            self.external_apis = sorted(self.meta.get('external_apis', set()))
            if (self.biz or self.probe_items or self.write_apis or self.params
                    or self.external_apis or self.meta.get('api_srcline') or self._dict_cands_h):
                self.html += self._group('攻击面')
                self.html += ('<p class="sec-lead">目标暴露了哪些接口、参数与外部依赖？'
                         '这是本工具的核心产出（JS 静态分析 + 被动探测），也是后续风险研判的对象。</p>')
                self._hsub[0] = 0
                self.html += self._h2('基础提取')
                # 端点主表: 业务接口 / 探测端点 / 写操作JS / 参数登记 四类来源合并为单一表,
                #   消除旧版「接口(探活确认)」与「接口归档(路由/业务)」对同一批端点的重复列举。
                _master_h = _endpoint_master_risk(self.ctx, self.api_items, self.write_apis, self.meta, self._src_r, self._am)
                if _master_h:
                    # 参数意图索引(反向映射: 参数名 → 意图集合), 供下方端点主表参数单元补安全意图标签
                    _param_intents = {}
                    for _dim, _bucket in (self._am.get('param_intent_index') or {}).items():
                        for _n in (_bucket or {}):
                            _param_intents.setdefault(str(_n), set()).add(_dim)
                    _n_cand_h = (len(self.meta.get('apis', set())) + len(self.meta.get('recomb', set()))
                                 + len(self.meta.get('write_apis', {})))
                    self.html += self._h3(f'端点主表（探活确认） ({len(_master_h)} 接口)')
                    self.html += (f'<p style="font-size:12px;color:#888">提取候选 <b>{_n_cand_h}</b> 条'
                             f'(JS/HTML 提取, 未探活) → 本表为探活后端点 <b>{len(_master_h)}</b> 条'
                             f'(含参数登记表)。「来源」区分 业务接口 / 探测端点 / 写操作JS / 字典候选(命中) / 参数登记 / Schema字段 / '
                             f'**响应挖掘**(从响应体·头挖出并回灌); '
                             f'（**规则派生(路径推断)等未命中项已按降噪约束隐去**, 不入表）; '
                             f'「状态/备注」给出探活结果与判定(如 Catch-all 伪命中 / 需鉴权)。</p>')
                    self.html += ('<p style="font-size:12px;color:#888">参数单元含<b>语义/意图标签</b>'
                             '(如 <code>order_id·ID·IDOR</code>): <code>·ID</code>=对象引用参数, '
                             '<code>·IDOR/SQLi/SSRF</code>=命名意图命中(提示该参数值得优先复核)；'
                             '完整类型/必填/观测形态见下方「参数总表」。</p>')
                    _n_html_h = sum(1 for _r in _master_h if '页面(HTML)' in _r[3])
                    if _n_html_h:
                        self.html += (f'<p style="font-size:12px;color:#888">其中 <b>疑似页面型 {_n_html_h} 条</b>'
                                 f'(响应为 HTML, 多为文档/静态页, 非数据接口 —— 建议优先复核其余端点)。</p>')
                    _n_unprobed_h = max(0, _n_cand_h - len(_master_h))
                    if _n_unprobed_h:
                        self.html += (f'<p style="font-size:12px;color:#888">其余 <b>{_n_unprobed_h} 条为未探活候选</b>'
                                 f'(提取到但未确认, 非"不存在") —— 完整清单见同目录 JSON 的 '
                                 f'<code>extracted_endpoints</code>。</p>')
                    # 注: 「优先级 / 命中维度 / 风险假设 / 只读验证」四列**已按用户要求取消**
                    #   (发现级排序对端点主表无意义) —— 主表只保留端点事实(接口/方法/来源/状态/参数)。
                    self.html += ('<p class="note"><b>方法</b>只显示 <b>从 JS 中提取到的声明</b>; '
                             '未提取到则留 <b>—</b>（<b>不做推断</b>）。'
                             '同一路径只列一次（探活结果与 JS 声明方法已合并）。'
                             '⚠️ <b>写声明端点(如 POST)实际仅以只读 GET/HEAD 探活</b>'
                             '（合规红线: 绝不发写请求）, 其状态备注末尾标注'
                             '「<b>· GET 探测(只读降级)</b>」、方法格带 '
                             '<span style="color:#c0392b;border:1px solid #c0392b;'
                             'border-radius:3px;padding:0 3px">↓GET</span> 角标, '
                             '请勿将 "GET 403" 误读为 "POST 被拦截"。</p>')
                    # 端点主表：**平铺单表**（「按路由 / 按业务」分组切换已移除）。
                    #   行可点击展开: 数据包构造（Burp 格式）。
                    #   注: 「来源定位 / 命中代码端」已移至「接口清单（按来源）→ 源码定位」行
                    #   （用户要求, 与该表同属"提取线索+源码证据"范畴）。
                    self.html += ('<p class="note">点击任意端点行展开: <b>数据包构造</b>'
                             '（Burp Repeater 格式, 一键复制）。'
                             '来源定位与命中代码端见下方「接口清单（按来源）→ 源码定位」行。</p>')
                    # 一键复制接口清单(一行一个完整 URL) —— 复用既有 `.copy-btn` + `data-copy`
                    #   剪贴板逻辑(clipboard API + 无 API 时 execCommand 降级, 见本文件底部脚本)。
                    #   另给"仅后端接口"一键复制(复用 `_endpoint_kind` 分类), 便于清单梳理直取真实接口。
                    from urllib.parse import urlsplit as _us
                    _osp = _us(self.base or '')
                    _origin = (f'{_osp.scheme}://{_osp.netloc}'
                               if (_osp.scheme and _osp.netloc) else '')
                    _nl = '\n'
                    _all_u, _api_u, _seen_u = [], [], set()
                    for _r in _master_h:
                        _d, _mth = _r[0], _r[1]
                        _u = (_origin + _d) if _origin else _d
                        if _u in _seen_u:
                            continue
                        _seen_u.add(_u)
                        _all_u.append(_u)
                        if _endpoint_kind(_d, self.meta, _mth) == 'backend_api':
                            _api_u.append(_u)
                    self.html += (
                        '<p class="note">'
                        f'<button class="copy-btn" type="button" data-copy="{_esc(_nl.join(_all_u))}">'
                        f'复制全部接口 ({len(_all_u)})</button> '
                        f'<button class="copy-btn" type="button" data-copy="{_esc(_nl.join(_api_u))}">'
                        f'仅复制后端接口 ({len(_api_u)})</button> '
                        '<span>一行一个完整 URL, 可直接粘贴到其它工具。</span></p>')
                    self.html += ('<table id="ep-master-table"><tr><th>接口</th><th>方法</th>'
                             '<th>类别</th><th>来源</th>'
                             '<th>状态 / 备注</th><th>路径参数</th>'
                             '<th>查询 / 请求体参数</th></tr>')
                    for _i, _r in enumerate(_master_h):
                        _disp, _mth, _src, _sn = _r[0], _r[1], _r[2], _r[3]
                        _pp, _op, _pm = _r[4], _r[5], _r[6]
                        # 方法为 `—`(JS 未提取到)时不套方法样式类, 避免无效 CSS 类名
                        _mth_cls = (f' m-{_esc(_mth.lower())}' if _mth and _mth != '—' else '')
                        # 写声明端点以只读 GET/HEAD 探活(降级) → 方法单元格追加红色角标,
                        #   明确"声明方法 vs 实际探测方法"的差异, 避免误读状态备注。
                        _pm_badge = ''
                        if _pm in ('GET', 'HEAD') and _mth in ('POST', 'PUT', 'PATCH', 'DELETE'):
                            _pm_badge = (f'<span style="font-size:10px;color:#c0392b;'
                                         f'border:1px solid #c0392b;border-radius:3px;'
                                         f'padding:0 3px;margin-left:4px" '
                                         f'title="以只读 {_esc(_pm)} 探活(降级, 非声明方法 {_esc(_mth)})">'
                                         f'↓{_esc(_pm)}</span>')
                        # 类别列(backend_api/frontend_route/unknown → 中文短标签) —— 与端点侧车/矩阵同源
                        _kdisp = {'backend_api': '后端接口', 'frontend_route': '前端路由'}.get(
                            _endpoint_kind(_disp, self.meta, _mth), '待定')
                        self.html += (f'<tr class="ep-row" data-epd="epd-{_i}" '
                                 f'title="点击展开: 数据包构造（Burp 格式）">'
                                 f'<td><code>{_esc(_disp)}</code> <span class="ep-caret">▸</span></td>'
                                 f'<td><span class="mth{_mth_cls}">{_esc(_mth)}</span>{_pm_badge}</td>'
                                 f'<td>{_esc(_kdisp)}</td>'
                                 f'<td>{_esc(_src)}</td>'
                                 f'<td>{_esc(_sn)}</td>'
                                 f'<td>{_esc(", ".join(_annotate_params(_pp, self._param_r, _param_intents))) or "—"}</td>'
                                 f'<td>{_esc(", ".join(_annotate_params(_op, self._param_r, _param_intents))) or "—"}</td></tr>')
                        self.html += (f'<tr class="ep-detail" id="epd-{_i}"><td colspan="7">'
                                 + self._endpoint_detail_html(_disp, _mth, _sn, _pp, _op)
                                 + '</td></tr>')
                    self.html += '</table>'
                    # 未明确归属到具体接口的参数(全局 query/body 形参, 不绑定路径)
                    _covered_h = set()
                    for (_disp, _mth, _src, _sn, _pp, _op, _pm,
                         _pri, _dims, _reason, _probed, _hyp, _is_unprobed) in _master_h:
                        _covered_h |= set(_pp) | set(_op)
                    _orphans_h = [p for p in self.params if p not in _covered_h and len(p) >= 2]
                    if _orphans_h:
                        self.html += ('<p class="note">另有 '
                                 + str(len(_orphans_h))
                                 + ' 个参数名未明确归属到具体接口(多为全局 query/body 形参): '
                                 + ' '.join(f'<span class="tag">{_esc(p)}</span>' for p in _orphans_h[:40])
                                 + '</p>')
                # 方法发现(OPTIONS · Allow · 方案 2-B): 目标**自述**支持的方法
                #   —— 与「方法」列(JS 声明)互补, 二者来源不同, 不混为一谈。
                _om_h = getattr(self.ctx, 'options_methods', None) or {}
                if _om_h:
                    self.html += (f'<p class="note"><b>方法发现（OPTIONS · Allow · {len(_om_h)} 条）</b>'
                             f'：由<b>只读 OPTIONS</b> 取到的 <code>Allow</code> 头 —— '
                             f'<b>目标自述</b>该路由支持的方法；与「方法」列（来自 JS 声明）互补、来源不同。</p>')
                    self.html += ('<p class="note">' + ' '.join(
                        f'<span class="tag">{_esc(_p2)} → {_esc(",".join(_ms))}</span>'
                        for _p2, _ms in sorted(_om_h.items())) + '</p>')
                # R1/R2 披露(与 JSON 侧车同源): 端点证据分级分布 + 库 bundle 跳过数。
                _ev_h = self.meta.get('evidence') or {}
                if _ev_h:
                    # 只统计**最终提取路径**(与 by_endpoint 同口径, 排除归一化前的陈旧键)
                    _ev_paths = (set(self.meta.get('apis') or set())
                                 | set(self.meta.get('recomb') or set())
                                 | set((self.meta.get('write_apis') or {}).keys()))
                    _evc = {}
                    for _p in _ev_paths:
                        _t = _ev_h.get(_p, 'static')
                        _evc[_t] = _evc.get(_t, 0) + 1
                    self.html += (
                        '<p class="note"><b>端点证据分级</b>：'
                        + ' · '.join(f'{_esc(_t)} {_evc.get(_t, 0)}'
                                     for _t in ('runtime', 'full-url', 'static', 'dict'))
                        + '（<code>runtime</code>=浏览器真实观测 · <code>full-url</code>=baseURL/'
                          '规格重建 · <code>static</code>=源码字面量 · <code>dict</code>=字典/推断; '
                          '逐端点标注见 <code>.recon_matrix.json</code> 的 evidence 字段）</p>')
                _vjs_h = self.meta.get('vendor_js') or []
                if _vjs_h:
                    self.html += (
                        f'<p class="note"><b>库 bundle 跳过深度分析</b>：{len(_vjs_h)} 个 JS '
                        f'经版权注释/路径形态判定为第三方库, 已跳过 AST/正则/拆包深度分析'
                        f'(仍计入 JS 资源清单与框架指纹补判; '
                        f'<code>vendor_bundle_skip=false</code> 可恢复全量分析)</p>')
                # 接口清单（按来源）: 把 源码定位 / 外部接口 / 相对端点 / Schema源 / 字典候选
                #   合并为**一张表**(来源类别列区分), 避免同一批线索被拆成多个子节重复占版面。
                #   (端点主表已含"目标真实接口 + 风险", 此处只补"非主表来源的接口线索"。)
                _srcline = self.meta.get('api_srcline') or {}
                _conf = self.meta.get('api_conf') or {}
                _extractor = self.meta.get('api_extractor') or {}
                _rows_src = [(p, _srcline[p]) for p in sorted(_srcline)
                             if (_srcline[p][1] if len(_srcline[p]) > 1 else None)
                             or (_conf.get(p) or '-') != '-'
                             or _extractor.get(p)]
                _rel_apis_h = sorted(self.meta.get('relative_apis', set()))
                _schema_apis_h = sorted(self.meta.get('schema_apis', set()))
                # _dict_cands_h 已在函数上方按"**只取探活命中项**"计算(未命中的泛化猜测不展示)。
                #   第 4 列 detail_html: **源码定位**行可点击展开「来源定位 + 命中代码端」
                #   (已按用户要求从端点主表迁来); 其余来源行为空(不可展开)。
                _src_rows = []
                for _p, _t in _rows_src:
                    _bits = f'<code>{_esc(_p)}</code> ← {_esc(_t[0])}'
                    if len(_t) > 1 and _t[1]:
                        _bits += f':{_esc(_t[1])}'
                    if len(_t) > 2 and _t[2]:
                        _bits += f':{_esc(_t[2])}'
                    if _extractor.get(_p):
                        _bits += f' [{_esc(_extractor.get(_p))}]'
                    if _conf.get(_p) not in (None, '-'):
                        _bits += f' [{_esc(_conf.get(_p))}]'
                    _bits += ' <span class="ep-caret">▸</span>'
                    _src_rows.append(('源码定位', _bits,
                                      'HIGH=源码字面量直接命中 · 标注=extractor层; '
                                      '点击展开: 来源定位 / 命中代码端',
                                      self._srcline_detail_html(_p)))
                for u in self.external_apis:
                    _src_rows.append(('外部接口(第三方)', f'<code>{_esc(u)}</code>',
                                      f'主机 {_esc(_host_of(u))} · 跨域未探活', ''))
                for p in _rel_apis_h:
                    _src_rows.append(('相对端点(未探活)', f'<code>{_esc(p)}</code>',
                                      '基址未知 · 需人工补全前缀/主机', ''))
                for s in _schema_apis_h:
                    _src_rows.append(('Schema 源(规范定义)', f'<code>{_esc(s)}</code>',
                                      '精度最高 · 参数类型/必填见参数总表', ''))
                for d in self._dict_cands_h:
                    _src_rows.append(('字典候选(命中)', f'<span class="tag">{_esc(d)}</span>',
                                      '泛化字典**命中** · 已探活确认可达', ''))
                if _src_rows:
                    self.html += self._h3('接口清单（按来源）')
                    self.html += ('<p style="font-size:12px;color:#888">以下为<b>非端点主表来源</b>的接口线索'
                             '(源码字面量 / 第三方 / 相对片段 / 规范定义 / 字典命中), '
                             '统一按「来源类别」归集; 端点主表已含探活确认的目标真实接口与风险标注。'
                             '<b>字典候选只列命中项</b> —— 未命中的泛化猜测与目标无关, 已隐去不列。'
                             '<b>「源码定位」行可点击展开</b>: 来源定位（JS 文件:行:列）+ '
                             '命中代码端（JS 调用现场, 路径高亮）。</p>')
                    self.html += '<table><tr><th>来源类别</th><th>接口 / 路径 / 条目</th><th>备注</th></tr>'
                    for _i2, (_cat, _item, _note, _detail) in enumerate(_src_rows):
                        if _detail:
                            self.html += (f'<tr class="src-row" data-epd="isd-{_i2}" '
                                     f'title="点击展开: 来源定位 / 命中代码端">'
                                     f'<td>{_esc(_cat)}</td><td>{_item}</td>'
                                     f'<td class="note">{_note}</td></tr>')
                            self.html += (f'<tr class="src-detail" id="isd-{_i2}"><td colspan="3">'
                                     + _detail + '</td></tr>')
                        else:
                            self.html += (f'<tr><td>{_esc(_cat)}</td><td>{_item}</td>'
                                     f'<td class="note">{_note}</td></tr>')
                    self.html += '</table>'
                # 注: 「接口归档(路由/业务)」已合并进上方「端点主表」(含参数登记 / 未归属参数),
                #   不再单列, 避免同一批端点被列举两次。
                # 注: 敏感信息发现**不再**在「基础提取」重复列出 —— 统一在「发现项」章节按类别呈现
                #   (去重: 此前同一 finding 同时出现在「基础提取→敏感信息」与「其他发现项」两处)。
                self.html += '</div>'


            # 业务分布: 与「端点主表」的「路由 / 业务」列**同类**(明细已在主表), 不再单列
            #   —— 删除此冗余摘要(避免与主表业务/路由列重复占版面)。

            if self._pt_rows:
                self._hsub[0] = 0
                self.html += self._h2('参数总表（类型 / 必填 / 意图 / 形态）') + param_table_html(self._pt_rows) + '</div>'






    def _emit_risk_findings(self):
        # ================= 结论与优先级 =================
        # 风险线索（发现级 · 非漏洞判定）—— 与 Markdown 报告 report() 同源。
        #   「候选(去重排序)」章节**已取消**(用户要求) —— 它与「完整发现清单」是同一批发现的两个
        #   粒度视图, 保留其一即可; 现只保留**逐条原始证据**的「完整发现清单(溯源)」独立成节。
        #   _am 在此提前计算, 下方「端点风险特征标注」段复用(避免重复计算)。
        if self.sens_groups or self.other_findings:
            self.html += self._group('风险线索')
            self.html += ('<p class="sec-lead">发现级风险线索（非漏洞判定）—— 逐条原始证据，'
                     '供人工在授权范围内复核；不构成已确认漏洞。</p>')
        # 端点风险与只读验证已**并入「端点主表」**(端点只列一次, 详其风险列); 此处不再单列卡片。
        # 完整发现清单(溯源): **独立成节**(不再折叠), **只列高风险项**
        #   (硬编码/凭据/加密/敏感数据/源码泄露); 响应头、写操作、路径收割等信息性发现不展示(降噪)。
        if self.sens_groups or self.other_findings:
            self._hsub[0] = 0
            self.html += self._h2('完整发现清单（溯源）')
            self.html += ('<p class="note"><b>逐条原始证据</b>（独立于任何归并视图, 便于回到单次发现核对）。'
                     '<b>只列高风险项</b>：硬编码信息 / 凭据密钥 / 加密签名 / 敏感数据泄露 / 源码泄露; '
                     '响应头、写操作声明、路径收割等信息性条目<b>已隐去</b>。'
                     '严重度为<b>启发式标注（非漏洞定级）</b>, 是否构成问题需人工在授权范围内复核。'
                     '候选类别标注的 CWE 为<b>启发式分类映射(参考性, 非漏洞定级)</b>。'
                     '带<b>源码定位</b>的发现(硬编码/密钥/JS 内容项)行可点击展开: '
                     '来源定位（JS 文件:行:列）+ 命中代码端。</p>')
            # 带**来源代码定位**的 finding(硬编码/密钥/标记等 JS 内容项)行可点击展开
            #   「来源定位 + 命中代码端」—— 与「接口清单(按来源)→源码定位」同款交互。
            self.html += '<table id="fnd-master-table"><tr><th>严重度</th><th>类型</th><th>URL</th><th>证据</th></tr>'
            _floc = getattr(self.ctx, 'finding_loc', None) or {}
            _fnd_rows = [(sev, typ, url, ev) for cat in sorted(self.sens_groups)
                         for sev, typ, url, ev in self.sens_groups[cat]]
            _fnd_rows += list(self.other_findings)
            _fi = 0
            for sev, typ, url, ev in _fnd_rows:
                _sev_td = (f'<td><span class="sev {self.sev_cls.get(sev, "s-info")}">'
                           f'{_esc(sev)}</span></td>')
                _loc = _floc.get((sev, typ, url, ev))
                _u_html = _esc(url) + (' <span class="ep-caret">▸</span>' if _loc else '')
                if _loc:
                    self.html += (f'<tr class="fnd-row" data-epd="fnd-{_fi}" '
                             f'title="点击展开: 来源定位 / 命中代码端">'
                             + _sev_td + f'<td>{_esc(typ)}</td><td>{_u_html}</td>'
                             f'<td>{_esc(ev[:60])}</td></tr>')
                    self.html += (f'<tr class="fnd-detail" id="fnd-{_fi}"><td colspan="4">'
                             + self._finding_detail_html(_loc) + '</td></tr>')
                    _fi += 1
                else:
                    self.html += (f'<tr>' + _sev_td + f'<td>{_esc(typ)}</td><td>{_u_html}</td>'
                             f'<td>{_esc(ev[:60])}</td></tr>')
            self.html += '</table></div>'



    def _emit_assets(self):
        # ================= 资产与技术栈 =================
        # 补齐「指纹识别」章节(与 Markdown 报告对齐)。
        #   指纹是本工具的**门控依据** —— 它决定后续走哪些探测分支、加载哪些隐藏路径字典、
        #   注入哪些专属提取正则。HTML 报告不写它, 分析师就无从解释"为什么这个目标没探 XX"。
        _fp = self.meta.get('fingerprints') or getattr(self.ctx, 'fingerprints', None) or {}
        _fp_hits = _fp.get('hits') or []
        # 仅当本节点**确有内容**时才显示分组带(空组隐藏, 与报告约定一致)。
        #   注意: 接口/参数/外部依赖/字典候选/发现项 归属「攻击面 / 风险线索」节点,
        #   不得在此计入, 否则目标无指纹/SCA 时也会挂一个空「资产与技术栈」带。
        self._bmods = self.meta.get('bundle_modules') or {}
        _page_types = self.meta.get('page_types') or {}
        _ca = getattr(self.ctx, '_catchall_baseline', None)
        _has_assets = bool(
            _fp_hits or self.meta.get('sca_libs') or self.meta.get('sca_vulns')
            or self._bmods or _page_types or _ca or self.subdomains)
        # 动态解包还原（opt-in · L3–L5 密封沙箱）—— 仅当有还原产物时渲染（与 MD **同标题**）
        #   注: 本节点是**章节**(`_h2`), **不是分组带** —— MD 侧同为一 `sec()`, 不设 `grp()`。
        #   此前 HTML 额外发一个同名 `_group`, 使两端的**分组带集合**漂移(MD 无此带);
        #   移除该冗余分组带后, recovered 归入当前分组(风险线索), 与 MD 的分组归属一致。
        _rec = self.meta.get('recovered') or {}
        if _rec:
            self.html += self._h2('动态解包还原（L3–L5 密封沙箱）')
            self.html += ('<p class="sec-lead">动态解包（opt-in）在<b>本地密封离线沙箱</b>内运行目标代码, '
                     '还原 <code>module.exports</code> / 沙箱全局；沙箱<b>零网络</b>, 未向目标发包。'
                     '以下为还原产物（发现级线索）。</p>')
            for _src, _item in _rec.items():
                self.html += f'<h3>来源 <code>{_esc(_src)}</code></h3>'
                _cf = _item.get('config') or {}
                if _cf:
                    self.html += '<table><thead><tr><th>配置键</th><th>值</th></tr></thead><tbody>'
                    for _k, _v in _cf.items():
                        self.html += f'<tr><td>{_esc(_k)}</td><td>{_esc(_v)}</td></tr>'
                    self.html += '</tbody></table>'
                _ep = _item.get('endpoints') or {}
                if _ep:
                    self.html += '<p>' + ' '.join(f'<span class="tag">{_esc(x)}</span>'
                                             for x in list(_ep)[:40]) + '</p>'
        if _has_assets:
            self.html += self._group('资产与技术栈')
            self.html += ('<p class="sec-lead">目标是什么？指纹、前端组件与已知漏洞、构建产物、'
                     '页面类型与子域 —— 用以解释"为什么探到 / 没探到某些面"。</p>')
            self._hsub[0] = 0
            # 资产三合一: 指纹 / SCA / 拆包 / 页面类型 / 子域 合并为**一张「资产与技术栈」卡片**
            #   (原各自独立卡片 → 同类资产上下文归并, 减少卡片 sprawl; 明细(h3)仍完整保留)。
            self.html += self._h2('资产与技术栈')
        # 技术栈指纹(门控依据: 决定后续探测分支 / 隐藏路径字典 / 专属提取正则)
        if _fp_hits:
            self.html += self._h3('技术栈指纹（门控依据）')
            # HTML 原生渲染(按大类分组 + 置信度条), 取代旧版 ASCII 条文本块 —— 更易读、可打印。
            from ..recon.fingerprint import categorize_fingerprints as _categorize_fp
            try:
                _fp_cat = _categorize_fp(_fp_hits, _fp.get('confidence') or {})
            except Exception:
                _fp_cat = {'命中': [(_h, 0.5) for _h in _fp_hits]}
            self.html += '<table><tr><th>技术 / 组件</th><th>置信度</th></tr>'
            for _cat, _items in _fp_cat.items():
                self.html += (f'<tr><td colspan="2" style="background:var(--line2);font-weight:600;'
                         f'color:var(--ink2)">{_esc(_cat)} '
                         f'<span class="note">({len(_items)})</span></td></tr>')
                for _name, _conf in _items:
                    _pct = int(round((_conf or 0) * 100))
                    self.html += (f'<tr><td>{_esc(_name)}</td><td>'
                             f'<span style="display:inline-block;width:90px;height:6px;'
                             f'background:var(--line2);border-radius:999px;vertical-align:middle;'
                             f'overflow:hidden"><span style="display:block;width:{_pct}%;height:6px;'
                             f'background:var(--accent)"></span></span> '
                             f'<span class="note">{_pct}%</span></td></tr>')
            self.html += '</table>'
            # 版本级后端栈(与 Markdown 报告同源)
            self._stack_txt = format_stack(_fp.get('stack'))
            if self._stack_txt:
                self.html += f'<p class="note"><b>后端栈(版本级)</b>: {_esc(self._stack_txt)}</p>'
            _sw = sorted(self.meta.get('route_switches') or set())
            if _sw:
                self.html += (f'<p class="note">由指纹门控启用的专属提取开关 ({len(_sw)}): '
                         + ' '.join(f'<span class="tag">{_esc(s)}</span>' for s in _sw) + '</p>')
            # B5 侦察要点: 与 Markdown 报告同源(命中指纹的基线注解)。
            _bp = getattr(self.ctx, 'baseline_profile', None)
            _ann = list(getattr(_bp, 'annotations', None) or [])
            if _ann:
                self.html += ('<p class="note"><b>侦察要点</b>: '
                         + ' · '.join(f'<span class="tag">{_esc(a)}</span>' for a in _ann)
                         + '</p>')

        # 前端组件与已知漏洞 (SCA)
        _sca_libs = self.meta.get('sca_libs') or {}
        _sca_vulns = self.meta.get('sca_vulns') or []
        if _sca_libs or _sca_vulns:
            if _sca_libs:
                self.html += self._h3(f'前端组件（含版本） ({len(_sca_libs)})')
                self.html += '<table><tr><th>组件</th><th>版本</th><th>来源</th></tr>'
                for _n in sorted(_sca_libs):
                    _i = _sca_libs[_n] or {}
                    self.html += (f'<tr><td>{_esc(_n)}</td>'
                             f'<td>{_esc(_i.get("version") or "未知")}</td>'
                             f'<td>{_esc(_i.get("src") or "-")}</td></tr>')
                self.html += '</table>'
            if _sca_vulns:
                self.html += self._h3(f'已知漏洞组件 ({len(_sca_vulns)})')
                self.html += '<table><tr><th>组件</th><th>版本</th><th>严重度</th><th>漏洞编号</th><th>说明</th></tr>'
                for _v in _sca_vulns:
                    # `sca_vulns[].severity` 已在 sca.py 经 norm_sev 归一成内部词汇(MED, 非 MEDIUM),
                    # 故此处直接用 sev_cls 取软色 pill 类名, 文本与全局严重度词汇完全一致。
                    self.html += (f'<tr><td>{_esc(_v.get("name"))}</td>'
                             f'<td>{_esc(_v.get("version"))}</td>'
                             f'<td><span class="sev {self.sev_cls.get(_v.get("severity"), "s-info")}">{_esc(_v.get("severity"))}</span></td>'
                             f'<td>{_esc(_v.get("id"))}</td>'
                             f'<td>{_esc(_v.get("summary"))}</td></tr>')
                self.html += '</table>'
            self.html += ('<p class="note">SCA 基于内置库特征指纹与已知漏洞版本区间表（retire.js 式）；'
                     '仅对识别到明确版本的组件判定漏洞。所列<b>严重度为启发式标注（非漏洞定级）</b>, '
                     'CVE 编号仅作已知漏洞版本匹配参考, 是否适用需人工复核。</p>')

        # 构建产物拆包
        if self._bmods:
            self.html += self._h3('构建产物拆包 (webpack/browserify)')
            _bu_bits = ' · '.join(f'<code>{_esc(_bu)}</code> {len(self._bmods[_bu] or [])} 模块'
                                  for _bu in sorted(self._bmods))
            self.html += f'<p class="note">{_bu_bits}</p>'
            self.html += ('<p class="note">由 webcrack 还原模块边界（结构），结构化通道负责模块内表达式/拼接（语义）。'
                     '原始模块清单(纯内部素材)见附录「构建产物模块明细」。</p>')

        # 页面类型与软 404
        if _page_types or _ca:
            self.html += self._h3('页面类型与软 404')
            if _page_types:
                from collections import Counter as _Counter
                _pc = _Counter(_page_types.values())
                self.html += '<table><tr><th>页面类型</th><th>页面数</th><th>示例</th></tr>'
                for _t, _n in _pc.most_common():
                    _ex = next((s for s, t in _page_types.items() if t == _t), '-')
                    self.html += f'<tr><td>{_esc(_t)}</td><td>{_esc(str(_n))}</td><td>{_esc(_ex)}</td></tr>'
                self.html += '</table>'
            if _ca:
                _bits = []
                if _ca.get('multi_path_catchall'):
                    _bits.append('多路径聚合确认')
                if _ca.get('near_dup'):
                    _bits.append('simhash 近重复确认')
                if _ca.get('catchall_mode'):
                    _bits.append(f'模式 {_ca.get("catchall_mode")}')
                _extra = ('（' + ' · '.join(_bits) + '）') if _bits else ''
                # 去重: 基线值(状态/长度)已在页面顶部横幅披露, 此处只补充判定方式。
                self.html += f'<p class="note">软 404 判定: 探测阶段按上述基线剔除伪命中{_esc(_extra)}。</p>'
            else:
                self.html += '<p class="note">未建立软 404 基线(`--no-catchall-baseline` 或探测未触发)。</p>'

        # 子域名
        if self.subdomains:
            self.html += self._h3('子域名资产') + '<p>' + ' '.join(f'<span class="tag">{_esc(d)}</span>' for d in self.subdomains) + '</p>'

        if _has_assets:
            self.html += '</div>'



    def _emit_auth_access(self):
        # ================= 攻击面侦察（认证与访问） =================
        if self._ua or self._pt_rows:
            self.html += self._group('认证与访问')
            self.html += ('<p class="sec-lead">哪些入口需要认证、匿名能否触达受限面？'
                     '纯侦察分析，不验证、不利用；命中仅作"需人工复核"候选。</p>')
        if self._ua:
            self._hsub[0] = 0
            self.html += self._h2('疑似越权访问线索（侦察启发式 · 非利用）') + self._ua + '</div>'


    def _emit_coverage(self):
        # ================= 覆盖与边界（压缩项：默认折叠） =================
        #   设为**压缩项**: 默认折叠, 不占主视觉; 内容完整保留, 点击摘要行展开。
        #   仅设置 _cur_group 用于侧栏 TOC 分组标签(下方卡片归属此组); 视觉头改为 <details> 摘要。
        self._cur_group[0] = '覆盖与边界'
        self.html += ('<details class="grp" id="sec-coverage">'
                 '<summary>覆盖与边界'
                 '<span class="cnt">预算 / 熔断 / 截断 / 未启用能力</span></summary>')
        self.html += ('<p class="sec-lead">本次扫得有多全？预算 / 熔断 / 截断披露，'
                 '以及未启用的覆盖能力（子域、历史资产、运行时通道等）。</p>')
        # 补齐「扫描完整性」披露 —— 与 Markdown 报告 report() 对齐。
        _trunc = getattr(self.ctx, 'truncated', None) or {}
        _net = getattr(self.ctx, 'net_sent', 0) or 0
        _tls = getattr(self.ctx, 'tls_cert', None)
        _budget_hit = getattr(self.ctx, 'budget_exhausted', None)
        _exhausted = bool(_budget_hit()) if callable(_budget_hit) else False
        # fail_count 已随熔断状态机重构移除 → 不可再读它(旧写法恒得 0, 会把"连续失败 N 次"错报为 0 次)。
        #   连续失败次数用配置阈值表达("达阈值 N 次触发"); 另量化"实际被跳过的请求数"。
        _tripped = bool(getattr(self.ctx, 'circuit_tripped', False))
        _fails = int((getattr(self.ctx, 'config', None) or {}).get('circuit_max_fail', 5) or 5)
        _circ_skipped = int(getattr(self.ctx, 'circuit_skipped', 0) or 0)
        # "体量够大却零产出"的 JS —— 必须与"截断/熔断"同处披露（否则会被误读成"那里没有接口"）
        _silent_n = int(self.meta.get('silent_js_n', 0) or 0)
        _silent_rows = self.meta.get('silent_js') or []
        # 自适应派生记录（改了什么、依据是什么）—— 不披露的话自适应就成黑箱, 与"可审计"冲突
        _adapt = getattr(self.ctx, '_adapt_notes', None) or {}
        if (_trunc or _exhausted or _tripped or _net > self.ctx.total_sent or _tls or _silent_n
                or _adapt):
            self._hsub[0] = 0
            self.html += self._h2('扫描完整性')
            self.html += (f'<p class="note">逻辑请求: {self.ctx.total_sent} | '
                     f'实际网络请求(含重定向跳数与重试): {_net}</p>')
            if _exhausted:
                self.html += ('<p class="note">⚠️ <b>全局时间预算已耗尽</b>, 后续环节未执行; '
                         '在 <code>~/.facet/config.yaml</code> 设 <code>max_duration: 0</code> 取消预算限制</p>')
            if _tripped:
                _skip_txt = (f', 实际被跳过 <b>{_esc(_circ_skipped)}</b> 个请求' if _circ_skipped else '')
                self.html += (f'<p class="note">⚠️ <b>熔断已触发</b> (连续失败达 {_esc(_fails)} 次阈值, '
                         f'多为 429/5xx/超时){_skip_txt}: 目标可能在限流, '
                         '结果<b>不代表</b>已完整覆盖; 建议降低 <code>rate</code> / '
                         '<code>max_rpm</code>（配置文件或 FACET_RATE 等环境变量）后重扫</p>')
            if _trunc:
                self.html += ('<p class="note">⚠️ 以下环节被上限<b>截断</b>, 覆盖范围不完整:</p>'
                         '<ul class="note">')
                for _k, _v in sorted(_trunc.items()):
                    self.html += f'<li>{_esc(_trunc_label(_k))}: 丢弃 {_esc(_v)} 条</li>'
                self.html += '</ul>'
            if _silent_n:
                self._sb = int(self.meta.get('silent_js_bytes', 0) or 0)
                _su = int(self.meta.get('silent_js_unreadable_n', 0) or 0)
                self.html += (f'<p class="note">⚠️ <b>{_silent_n}</b> 个 JS 文件（{self._sb // 1024} KB）'
                         f'<b>未能从中提取任何内容</b>（接口 / 路由 / 参数 / 业务名全为空）'
                         f'—— 其中 <b>{_su}</b> 个<b>疑似不可读</b>（混淆 / 解包链）。'
                         '这些文件的接口与参数<b>可能未被发现</b>，不等同于"那里没有接口"。</p>')
                if _silent_rows:
                    # 分组用**真实计数**（`silent_js_by_reason`），样本单独列 —— 样本列表有上限，
                    #   拿样本数当计数会把"59 个样本"误读成"只有 59 个文件"（实测踩过）。
                    _cnt = self.meta.get('silent_js_by_reason') or {}
                    _by_reason = {}
                    for _r in _silent_rows:
                        _by_reason.setdefault(_r.get('reason') or '?', []).append(_r)
                    self.html += '<ul class="note">'
                    for _why, _items in sorted(_by_reason.items(),
                                               key=lambda kv: -int(_cnt.get(kv[0], len(kv[1])))):
                        _ex = ', '.join(_esc((_i.get('url') or '').rsplit('/', 1)[-1])
                                        for _i in _items[:6])
                        _hint = _silent_hint(_why)          # 每类给**可操作**建议, 而非只说"没产出"
                        _hint_html = f' <span class="brev">→ {_hint}</span>' if _hint else ''
                        self.html += (f'<li>{_esc(_why)}: <b>{_esc(_cnt.get(_why, len(_items)))}</b> 个'
                                 f'（样本 <code>{_ex}</code> …）{_hint_html}</li>')
                    self.html += '</ul>'
                if _su:
                    self.html += ('<p class="note">"疑似不可读"= 命中混淆/解包链特征但静态层未取得任何产出。'
                             '可尝试 <code>strong_deobf: true</code>（静态，安全）或 '
                             '<code>dynamic_deobf: true</code>（密封沙箱内执行目标代码，默认关）。</p>')
            if _adapt:
                self.html += ('<p class="note"><b>自适应参数</b>（依据取自<strong>目标自身的实测状态</strong>，'
                         '非固定默认值）：</p><ul class="note">')
                for _k, _v in sorted(_adapt.items()):
                    self.html += (f'<li><code>{_esc(_k)}</code>: {_esc(_v.get("base"))} → '
                             f'<b>{_esc(_v.get("value"))}</b> '
                             f'<span class="brev">{_esc(_v.get("basis") or "")}</span></li>')
                self.html += '</ul>'
            if _tls:
                _iss = (_tls.get('issuer') or {})
                _san = _tls.get('san') or []
                self.html += (f'<p class="note">TLS 证书: 颁发者 '
                         f'{_esc(_iss.get("organizationName") or _iss.get("commonName") or "?")}'
                         f' | 有效期至 {_esc(_tls.get("not_after") or "?")} '
                         f'| SAN {len(_san)} 条</p>')
            self.html += '</div>'

        # 覆盖模式披露(与 Markdown 报告对齐): "默认静态单目标"必须显式告知。
        # 与上次扫描的差异（持续侦察）—— 与 report() 同源
        _d = _scan_diff(self.ctx, self.base)
        if _d:
            self._hsub[0] = 0
            self.html += self._h2('与上次扫描的差异（持续侦察）') + _diff_html(_d) + '</div>'

        _dis, _static = _coverage_state(self.ctx)
        _auth = _auth_state(self.ctx)
        self._hsub[0] = 0
        self.html += self._h2('覆盖模式')
        self.html += (f'<p class="note">认证态: <b>'
                 f'{"已认证(已提供会话)" if _auth else "未认证(未提供 --cookie/--token)"}</b>'
                 + ('' if _auth else ' —— <b>登录后接口/页面不可见</b>') + '</p>')
        if _static:
            self.html += ('<p class="note">本次为 <b>静态单目标</b> 模式: '
                     '仅覆盖 <b>首页 + 同源 JS + 单主机</b>。</p>')
        if _dis:
            self.html += ('<p class="note">未启用(默认关)的覆盖能力: '
                     + ' · '.join(f'{_esc(_n)}(<code>{_esc(_f)}</code>)' for _n, _f in _dis)
                     + '</p>')
            self.html += ('<p class="note">含义: 客户端渲染后才出现的页面/接口、二级页面、'
                     '同组织其他主机、历史下线接口 <b>未纳入</b> 本次结果。</p>')
        # 运行时通道状态**如实披露**(两种情形分流, 不混淆):
        #   ① 已请求但未实际运行(依赖缺失/异常/超时) → ⚠️ 能力缺口, 静态结果为主;
        #   ② 已配置但未触发(auto 非 SPA / false) → 设计如此, 说明原因即可。
        #   旧实现两种都渲染"⚠️ 已请求但未实际运行" —— 把 auto 未触发(设计不跑)说成能力缺口, 误导。
        _rt_cfg = (getattr(self.ctx, 'config', None) or {}).get('runtime')
        if _rt_cfg and not getattr(self.ctx, 'runtime_ran', False):
            _rt_reason = getattr(self.ctx, 'runtime_reason', '') or '未运行'
            if getattr(self.ctx, 'runtime_requested', False):
                self.html += (f'<p class="note">⚠️ 运行时通道<b>已请求但未实际运行</b>'
                         f'(runtime: {_esc(_rt_cfg)}; 原因: {_esc(_rt_reason)}) —— '
                         '客户端渲染后才出现的页面/接口<b>未纳入</b>本次结果。</p>')
            else:
                self.html += (f'<p class="note">运行时通道<b>已配置但未触发</b>'
                         f'(runtime: {_esc(_rt_cfg)}; 原因: {_esc(_rt_reason)}) —— '
                         '本次以静态分析为主; 如目标实为 SPA, 可显式 --runtime true 重扫。</p>')
        self.html += '</div>'      # 关闭「覆盖模式」卡片 —— 此前**漏关**, 导致其后所有卡片嵌套错位、整份 HTML 少一个 </div>

        self.html += '</details>'      # 关闭「覆盖与边界」压缩项(<details> 默认折叠)



    def _emit_appendix(self):
        # ================= 附录 =================
        #   JS 清单 / 已排除项 = 工具内部素材, 后置到附录(与 MD 同序)。
        self._appx = [False]

        if self.js_files:
            self.html += self._appendix()
            self._hsub[0] = 0
            self.html += self._h2('JS 资源清单')
            # 与 MD 同口径: 扫描被截断时, JS 清单可能不完整 → 显式提示
            _trunc_js = getattr(self.ctx, 'truncated', None) or {}
            # 与 :2769/:3083 同一调用口径 —— 此前此处把**方法对象**当真值(getattr 恒真),
            #   导致"JS 清单可能不完整"警告只要 js_files 非空就无条件显示(假阳性披露)。
            _budget_hit = getattr(self.ctx, 'budget_exhausted', None)
            if (bool(_budget_hit()) if callable(_budget_hit) else False) or any(
                    'js' in str(k).lower() for k in _trunc_js):
                self.html += ('<p class="note">⚠️ 本次扫描<b>被截断</b>（时间预算耗尽 / 上限）, '
                         'JS 抓取或分析<b>可能未跑完</b>, 本清单<b>可能不完整</b>（详见「扫描完整性」）。</p>')
            _vendor_urls = {str(_x.get('url') or '') for _x in (self.meta.get('vendor_js') or [])}
            if _vendor_urls:
                self.html += ('<div class="vendor-controls"><label><input type="checkbox" '
                              'onchange="document.querySelectorAll(\'#js-asset-table tr[data-vendor=true]\')'
                              '.forEach(r=>r.hidden=this.checked)"> 一键隐藏 vendor 库文件 '
                              f'（{len(_vendor_urls)} 个，保留分析记录）</label></div>')
            self.html += '<table id="js-asset-table"><tr><th>路径</th><th>大小</th></tr>'
            for u, size, path in sorted(self.js_files)[:60]:
                _is_vendor = str(u) in _vendor_urls
                _badge = '<span class="vendor-badge">VENDOR · 已跳过分析</span>' if _is_vendor else ''
                self.html += (f'<tr data-vendor="{str(_is_vendor).lower()}">'
                              f'<td>{_esc(u)}{_badge}</td><td>{_esc(size)}B</td></tr>')
            self.html += '</table>'
            _tgt = _host_of(self.base)
            _ext_hosts = sorted({_host_of(u) for u, _, _ in self.js_files
                                 if _host_of(u) and _host_of(u) != _tgt})
            if _ext_hosts:
                self.html += (f'<p class="note">第三方 JS 资源主机 ({len(_ext_hosts)}): '
                         + ' '.join(f'<span class="tag">{_esc(h)}</span>' for h in _ext_hosts) + '</p>')
            _ext_js_h = sorted(self.meta.get('external_js', set()))
            if _ext_js_h:
                self.html += (f'<p class="note">跨域 JS chunk 已登记但<b>未抓取</b> '
                         f'({len(_ext_js_h)} 个, 仅揭示前端依赖面): '
                         + ' '.join(f'<span class="tag">{_esc(u)}</span>' for u in _ext_js_h[:12])
                         + (f' …另有 {len(_ext_js_h) - 12} 个' if len(_ext_js_h) > 12 else '') + '</p>')
            self.html += '</div>'

        # 构建产物模块明细(纯内部素材, 从「资产与技术栈」主卡移出, 避免主视觉被长 dump 占满)
        if self._bmods:
            self.html += self._appendix()
            self._hsub[0] = 0
            self.html += self._h2('构建产物模块明细')
            self.html += ('<p class="note">构建产物拆包还原的<b>原始模块清单</b>（纯内部素材, 不影响上方结论）；'
                     '结构复用说明见「资产与技术栈 → 构建产物拆包」。</p>')
            for _bu in sorted(self._bmods):
                _ms = self._bmods[_bu] or []
                if not _ms:
                    continue
                self.html += self._h3(f'{_bu} — {len(_ms)} 个模块')
                self.html += '<pre>' + _esc_text('\n'.join(_ms[:200])) + '</pre>'
            self.html += '</div>'

        if self.excluded:
            self.html += self._appendix()
            self._toc.append(('secA', '附录 · 已排除项', '附录'))
            self.html += ('<div class="card" id="secA"><h2>附录 · 已排除项 '
                     f'({len(self.excluded)})</h2>'
                     '<p class="note">'
                     '以下路径经 catch-all / 空回退判定被排除，<b>不计入上方严重度统计</b>。'
                     '列出以公开判定依据供人工复核。</p>'
                     '<table><tr><th>路径</th><th>状态</th><th>排除原因</th></tr>')
            for path, st, reason in self.excluded[:200]:
                self.html += f'<tr><td>{_esc(path)}</td><td>{_esc(st)}</td><td>{_esc(reason)}</td></tr>'
            if len(self.excluded) > 200:
                self.html += f'<tr><td colspan="3">... 另有 {len(self.excluded) - 200} 条已省略</td></tr>'
            if self.overflow:
                self.html += f'<tr><td colspan="3">... 另有 {self.overflow} 条超出记录上限未列出</td></tr>'
            self.html += '</table></div>'



    def _finalize(self):
        # 目录(骨架里预留了 <!--TOC--> 占位, 此处统一注入 —— 章节号/分组此时才全部就绪)
        if self._toc:
            _nav = []
            _last_g = None
            for _a, _t, _g in self._toc:
                if _g and _g != _last_g:
                    _nav.append(f'<li class="grp">{_esc(_g)}</li>')
                    _last_g = _g
                _nav.append(f'<li><a href="#{_a}">{_esc(_t)}</a></li>')
            self.html = self.html.replace('<!--TOC-->', '<ul class="toc">' + ''.join(_nav) + '</ul>')
        # 单文件总览内的页内跳转：各内容都合并在本 HTML，不生成独立分项文件。
        _quick_specs = [('端点', '基础提取'), ('参数', '参数总表'),
                        ('敏感信息', '完整发现清单'), ('资源', 'JS 资源清单')]
        _quick = []
        for _label, _needle in _quick_specs:
            _match = next((_a for _a, _t, _g in self._toc if _needle in _t), None)
            if _match:
                _quick.append(f'<a href="#{_match}">{_esc(_label)}</a>')
        self.html = self.html.replace('<!--QUICKVIEWS-->',
                    ('<nav class="quickviews" aria-label="报告内容导航">'
                     '<span class="qv-label">快速跳转：</span>' + ''.join(_quick) + '</nav>')
                    if _quick else '')
        self.html += ('<script>'
                 '(function(){'
                 'function _fk_open(){var id=location.hash.replace(/^#/,\'\');'
                 'if(!id)return;var el=document.getElementById(id);'
                 'if(!el)return;var d=el.closest("details");if(d&&!d.open)d.open=true;}'
                 'window.addEventListener("hashchange",_fk_open);'
                 'window.addEventListener("DOMContentLoaded",_fk_open);'
                 # 折叠行(仿 JsOwl): 端点主表(ep-row)与接口清单源码定位行(src-row)共用
                 #   data-epd → 详情行 id 的约定, 一处 handler 全覆盖
                 'document.addEventListener("click",function(ev){'
                 'var tr=ev.target.closest?ev.target.closest("tr[data-epd]"):null;'
                 'if(tr){var d=document.getElementById(tr.getAttribute("data-epd"));'
                 'if(d){d.classList.toggle("open");tr.classList.toggle("open");}return;}'
                 # 复制按钮: data-copy 携带纯文本(数据包/路径), clipboard API + execCommand 双路径
                 'var b=ev.target.closest?ev.target.closest(".copy-btn"):null;'
                 'if(!b)return;var t=b.getAttribute("data-copy")||"";'
                 'function _cp(){var o=b.textContent;b.textContent="已复制";'
                 'setTimeout(function(){b.textContent=o;},1200);}'
                 'function _fb(){var ta=document.createElement("textarea");ta.value=t;'
                 'ta.style.position="fixed";ta.style.opacity="0";document.body.appendChild(ta);'
                 'ta.select();try{document.execCommand("copy")}catch(e){}'
                 'document.body.removeChild(ta);_cp();}'
                 'if(navigator.clipboard&&navigator.clipboard.writeText){'
                 'navigator.clipboard.writeText(t).then(_cp,_fb);}else{_fb();}'
                 '});'
                 '})();'
                 '</script>')
        self.html += '</main></div></body></html>'
        _atomic_write_text(self.out_html, self.html)
        log(f'HTML报告: {self.out_html}')


    # ---------- JSON 报告（机器可读, 与 MD/HTML 同源） ----------


def report_html(ctx, base, out_html, meta, fs):
    """生成单文件 HTML Dashboard 报告（分类版）。见 _ReportBuilder。"""
    _ReportBuilder(ctx, base, out_html, meta, fs)


def _recovered_json(meta):
    """动态解包还原产物 → 结构化 dict（JSON 报告内嵌 + <out>.recovered.json 侧车同源）。

    返回 {源JS: {config, endpoints, keys, globals}}；无还原产物时返回 {}（不产生空结构）。
    （旧版 `--redact` 时对敏感键打码的逻辑已随开关移除; 还原产物本身即发现级线索, 不向目标发包。）
    """
    rec = (meta or {}).get('recovered') or {}
    return {src: {
        'config': item.get('config') or {},
        'endpoints': item.get('endpoints') or {},
        'keys': item.get('keys') or [],
        'globals': item.get('globals') or {},
    } for src, item in rec.items()}


def _endpoint_class(_sn):
    """端点存在性分类: 由探活状态说明串映射到报告 JSON 的 `class` 字段。

    提到模块级(原为 `report_json` 内嵌套函数)以便单测。
    """
    _s = str(_sn or '')
    if _s.startswith('405'):
        return 'EXISTS_METHOD_MISMATCH'
    if _s.startswith(('401', '403')) or '需登录' in _s:
        return 'EXISTS_PROTECTED'
    if _s.startswith('410'):
        return 'RETIRED'
    if _s.startswith('404') or '未确认(404)' in _s:
        return 'NOT_FOUND'
    if _s.startswith(('200', '201', '204')):
        return 'EXISTS'
    if _s.startswith('500'):
        return 'EXISTS_ERROR'
    return 'UNKNOWN'


def report_json(ctx, base, out, meta):
    """生成机器可读 JSON 报告（与 MD/HTML 同源, 供流水线/自动化消费）。

    镜像 MD 报告的核心结构: 目标/版本/认证态/覆盖模式/严重度分布/完整性/diff/发现列表。
    与 MD 一样, 对 finding URL 与端点路径里的敏感 query 值**无条件打码**(合规基线同源口径)。
    这是 finding 级别的**结构化导出**——区别于 write_recon_matrix(只导端点风险标注, 非漏洞判定)。
    """
    _dedupe_generic_hidden(ctx)      # 与 MD/HTML 同源: 去重泛化「隐藏接口暴露」
    from datetime import datetime, timezone
    order = {'CRITICAL': 0, 'HIGH': 1, 'MED': 2, 'LOW': 3}
    fs = sorted(ctx.findings, key=lambda x: order.get(x[0], 9))

    # --- 预分类(与 report() 完全一致) ---
    js_files = list(meta.get('js_files', []))
    routes = sorted(meta.get('routes', set()))
    api_items = list(ctx.all_found)
    write_apis = meta.get('write_apis', {})
    subdomains = sorted(meta.get('subdomains', set()))
    sens_groups, other_findings = {}, []
    for sev, typ, url, ev in fs:
        if any(k in typ for k in _GENERIC_HIDDEN_TYPES):
            other_findings.append((sev, typ, url, ev))
            continue
        cat = classify_finding(ev)
        if cat != '其他发现':
            sens_groups.setdefault(cat, []).append((sev, typ, url, ev))
        else:
            other_findings.append((sev, typ, url, ev))

    c = {}
    for sev, _, _, _ in fs:
        c[sev] = c.get(sev, 0) + 1
    excluded = getattr(ctx, 'excluded', None) or []
    _n_cand = (len(meta.get('apis', set())) + len(meta.get('recomb', set()))
               + len(meta.get('write_apis', {})))
    # dict_candidates: summary 必须与**展示数组**同口径(只计**命中**项) —— 否则 summary=7 而
    #   数组=[](7 条猜测全部 404 未命中) 会对不上账。另单列 _n_dict_probed 披露"试了多少条猜测"。
    _n_dict = len(_confirmed_dict_candidates(ctx, meta))
    _n_dict_probed = len(meta.get('dict_candidates', set()))

    # --- 覆盖模式 / 认证态 / diff / 完整性(与 report() 同源字段) ---
    _dis, _static = _coverage_state(ctx)
    _auth = _auth_state(ctx)
    _auth_disc = ('已认证(已提供会话)' if _auth
                  else '未认证(未提供 --cookie/--token) —— 登录后接口/页面不可见')
    _d = _scan_diff(ctx, base)
    _trunc = getattr(ctx, 'truncated', None) or {}
    _net = getattr(ctx, 'net_sent', 0) or 0
    _budget_hit = getattr(ctx, 'budget_exhausted', None)
    _exhausted = bool(_budget_hit()) if callable(_budget_hit) else False
    # fail_count 已随熔断状态机重构移除 → 不可再读它(旧写法恒得 0, 会把"连续失败 N 次"错报为 0 次)。
    #   连续失败次数用配置阈值表达("达阈值 N 次触发"); 另量化"实际被跳过的请求数"。
    _tripped = bool(getattr(ctx, 'circuit_tripped', False))
    _fails = int((getattr(ctx, 'config', None) or {}).get('circuit_max_fail', 5) or 5)
    _circ_skipped = int(getattr(ctx, 'circuit_skipped', 0) or 0)
    _tls = getattr(ctx, 'tls_cert', None)

    _floc = getattr(ctx, 'finding_loc', None) or {}

    def _flist(items):
        # 合规基线(无条件): finding URL 敏感 query 值遮掩; evidence 不再做通用打码(已移除 --redact)。
        # source_location/snippet = 扫描期定位(HTML 完整发现清单同款展开数据; 无定位为 None)。
        return [{'severity': s, 'type': t, 'url': u, 'evidence': e,
                 'source_location': ({'src': _l['src'], 'line': _l['line'], 'col': _l['col']}
                                     if (_l := _floc.get((s, t, u, e))) else None),
                 'snippet': (_l['snippet'] if _l else None)}
                for s, t, u, e in items]

    # 注: 「候选(去重排序)」章节已按用户要求取消(HTML/JSON 均不再产出) ——
    #   build_candidates 调用已移除, 只保留端点风险矩阵(_am)供端点对象复用。
    _am = build_recon_matrix(ctx, meta)

    # ---- 逐端点数据模型(方案七) ----
    #   endpoint/template/methods/params{path,query,body}/sources/status/class/auth/
    #   crypto_fields/risk/evidence/replay/snippet/packet —— 供流水线**按端点**消费(而非按报告分区)。
    #   snippet=命中代码端(JS 调用现场窗口); packet=Burp Repeater 格式原始请求(占位符, 零发包)。
    # JSON 端点参数为**原始名**(机器可读, 不标注 kind) → 只需 biz/source 规则。
    _, _, _src_rj = _load_report_rules(ctx, meta)
    _master_j = _endpoint_master_risk(ctx, api_items, write_apis, meta, _src_rj, _am)
    # `_auth_rows` 原是"认证态 → 端点"的查表, 但**生产者从未存在**(只读不写) →
    #   JSON `status.roles` 恒为 {}。按"无该信息如实输出空"的约定, 显式留空并注明(全库审计 D2)。
    _crypto_kw = ('加密', '签名', '混淆')
    _crypto_eps = {normalize_endpoint(_u.split('?')[0]) for _s, _t, _u, _e in fs
                   if any(_k in _t for _k in _crypto_kw)}
    _hi_risk_kw = ('admin', 'internal', 'upload', 'pay', 'export', 'manage', 'debug', 'config')
    _auth_hdrs = []   # 认证机制图谱已移除 → 无 headers 来源, 恒空
    # 端点级来源坐标(方案 §9): 来源文件:行:列 + extractor 层(ast/regex/wasm)
    _srcline_map = meta.get('api_srcline') or {}
    _extractor_map = meta.get('api_extractor') or {}

    _ep_class = _endpoint_class     # 分类逻辑提到模块级(可单测), 此处仅别名

    endpoints = []
    for _r in _master_j:
        _disp, _mth, _src, _sn = _r[0], _r[1], _r[2], _r[3]
        _pp, _op = list(_r[4]), list(_r[5])
        _pm, _pri, _dims, _reason, _probed = _r[6], _r[7], _r[8], _r[9], _r[10]
        _hyp = list(_r[11])
        _is_unprobed = _r[12]
        _key = normalize_endpoint(_disp)
        _cls = _ep_class(_sn)
        _low = _disp.lower()
        # 风险打分 —— **方案 §8 的通用加减分公式**(启发式, 非漏洞定级)
        _score = 0
        if _dims.get('unauth'):
            _score += 40                       # 受保护但可未授权触及
        if _pp:
            _score += 20                       # 路径含 ID(越权面)
        if any(_k in _low for _k in _hi_risk_kw):
            _score += 15                       # 含敏感关键词
        if _key in _crypto_eps:
            _score += 10                       # 含高熵/加密字段
        if '{' in _disp or ':' in _disp:
            _score += 5                        # 动态模板路由
        if _cls in ('NOT_FOUND', 'RETIRED'):
            _score -= 20                       # 废弃/诱饵
        _ar = {}                               # 认证态查表未接线(见上) —— 如实输出空
        _sl = _srcline_map.get(_disp)
        _ext = _extractor_map.get(_disp)
        endpoints.append({
            'endpoint': _disp,
            'template': bool('{' in _disp or ':' in _disp),
            'methods': ([] if not _mth or _mth == '—' else [_mth]),
            # 实际探活使用的方法(只读降级: 写声明端点恒为 GET/HEAD); 与 `methods`(JS 声明)分离,
            #   使"状态备注里的 403 是 GET 打出来的"永远可对照(透明度修复 P-T)。
            'probe_method': (_pm or None),
            'params': {'path': _pp, 'query': [], 'body': _op},
            'sources': [_src],
            # 端点级来源坐标(方案 §8 / §9): 来源文件:行:列 + extractor 层
            'source_location': ({'src': _sl[0], 'line': _sl[1], 'col': _sl[2]}
                                if _sl else None),
            'source_extractor': _ext,
            'status': {'note': _sn, 'roles': dict(_ar.get('status') or {})},
            'auth': {'required': _cls == 'EXISTS_PROTECTED', 'headers': _auth_hdrs},
            'crypto_fields': ([{'field': '', 'guess': 'JS 含加密/签名逻辑'}]
                              if _key in _crypto_eps else []),
            'class': _cls,
            'risk': {'score': _score,
                     'tags': [d for d in ('auth', 'idor', 'sqli', 'sensitive',
                                          'config', 'unauth', 'ssrf') if _dims.get(d)],
                     'priority': _pri},
            'evidence': {'response_snippet': _sn, 'reason': _reason,
                         'hypotheses': _hyp, 'probed': bool(_probed)},
            # 命中代码端: JS 调用现场上下文窗口(与 api_srcline 同一次查找; 派生来源无精确位置=null)
            'snippet': (meta.get('api_snippet') or {}).get(_disp),
            # 数据包构造: Burp Repeater 格式原始请求(占位符 {{fuzz:…}}/{{cookie:…}}; 本工具零发包)
            'packet': _build_burp_packet(base, _disp, _mth, _pp, _op, _sn,
                                         _cls == 'EXISTS_PROTECTED'),
            'replay': _safe_verify(base, _disp, _mth, (_hyp[0] if _hyp else None)),
        })
    # 参数总表（与 MD/HTML 同源）
    _pt = build_param_table(ctx, meta, _am)

    # 合规基线(无条件): 导出的 URL 清单敏感 query 值也遮掩, 与审计/历史库同源。
    def _urls(_it):
        _l = sorted(_it or ())
        return list(_l)

    def _hits_only(paths):
        """【强制约束·降噪】只保留**探活命中(非 404)**的路径 —— 未命中项一律隐去。

        用于字典候选 / 路径推断等"猜测/派生"字段; **不**用于 `extracted_endpoints`
        (那是真实提取, 属合规铁律必留)。判定口径与 `_confirmed_dict_candidates` 一致。
        """
        hit = {normalize_endpoint(p) for p, _m, _st, _n
               in (getattr(ctx, 'all_found', None) or []) if _st != 404}
        return {p for p in (paths or ()) if normalize_endpoint(p) in hit}

    # ---- 结论先行(未授权面) —— 与 HTML 报告**同源** ----
    #   注: 「业务地图 / 业务解读 / 命名空间段」已随模块整体移除(用户要求) ——
    #   read_business / segment_kinds / induce_lexicon / namespace_segments 等计算与
    #   business_map / business_reading / param_dimension 等 JSON 字段一并删除。
    _extracted_j = (set(meta.get('apis') or set()) | set(meta.get('recomb') or set())
                    | set((write_apis or {}).keys()))
    _unauth_j = _unauth_surface(api_items)
    _verdict = {
        'unauthorized_surface': _urls(set(_unauth_j)),
        'unauthorized_surface_n': len(_unauth_j),
        'test_surface_n': len(_extracted_j),
        'confirmed_n': len({(_x[0] if len(_x) > 0 else None) for _x in api_items}
                           & _extracted_j),
        'disclosure': '未授权面=无凭据可达(已剔除设计公开项); 发现级线索, 非漏洞判定',
    }
    payload = {
        'schema': 'facet-report/v1',
        'tool_version': __version__,
        'target': base,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'total_sent': ctx.total_sent,
        'auth_state': {'authenticated': _auth, 'disclosure': _auth_disc},
        # 结论先行: 未授权面（与 HTML 报告同源）
        'verdict': _verdict,
        # 注: 「业务地图 / 业务解读 / 参数维度(RPC 表 / 字段字典)/ 漏洞候选」已随模块
        #   整体移除(用户要求) —— 相应 JSON 字段(business_map / business_reading /
        #   param_dimension / rpc_endpoints / field_dict / candidates /
        #   candidates_summary)一并删除, 不再输出。
        # 版本级后端栈（响应头抽取; 供已知漏洞区间映射）
        'backend_stack': (getattr(ctx, 'fingerprints', None) or {}).get('stack'),
        # ===== 核心提取成果（JS 静态分析产出 · 一等字段, 置顶）=====
        #   **完整提取清单**(机器可读, 保证"提取结果一条不少"): 提取到的全部端点 ——
        #     含**未探活**的候选(报告表格只列探活确认的, 未探活候选仅计数会丢信息)。
        #     dict_candidates(字典猜测) 单列, 与"目标真实提取"分区, 不混为一谈。
        'extracted_endpoints': _urls(set(meta.get('apis') or set())
                                     | set(meta.get('recomb') or set())
                                     | set((write_apis or {}).keys())),
        # R1 端点证据分级(演进建议 · 借鉴 JsOwl evidence): 逐端点 tier + 分布计数。
        #   runtime=浏览器真实观测 > full-url=baseURL/规格重建 > static=源码字面量
        #   > dict=字典/路径推断猜测。同源口径见 orchestrator._ev_bump。
        #   计数只覆盖**最终提取路径**(排除 baseURL 归一化前的陈旧键), 与 by_endpoint 一致。
        'evidence_tiers': (lambda _ev, _paths: {
            'by_endpoint': {p: _ev.get(p, 'static') for p in _paths},
            'counts': {t: sum(1 for p in _paths if _ev.get(p, 'static') == t)
                       for t in ('runtime', 'full-url', 'static', 'dict')},
        })(meta.get('evidence') or {},
           (set(meta.get('apis') or set()) | set(meta.get('recomb') or set())
            | set((write_apis or {}).keys()))),
        # R2 库 bundle 跳过披露(演进建议): 嗅探判定为第三方库、未做深度分析的 JS ——
        #   资源仍在盘(JS 清单可查), 跳过的只是 AST/正则/拆包这类纯开销解析。
        'vendor_js_skipped': {
            'count': len(meta.get('vendor_js') or []),
            'files': [{'url': _vj.get('url'), 'bytes': _vj.get('bytes'),
                       'reason': _vj.get('reason')}
                      for _vj in (meta.get('vendor_js') or [])[:100]],
            'disclosure': ('版权注释/路径形态判定为第三方库 bundle, 已跳过深度分析(仍计入 JS '
                           '资源清单与框架指纹补判); vendor_bundle_skip=false 可恢复全量分析'),
        },
        # 文档站代码块 chunk(VitePress)跳过披露: `*.html-<hash>.js` 内容为文档代码示例,
        #   不入队/不分析/不抓取(避免把示例路径当真实接口 → 噪声; 同时省抓取提速)。
        'doc_code_js_skipped': {
            'count': len(meta.get('doc_code_js') or []),
            'files': [{'url': _dj.get('url'), 'bytes': _dj.get('bytes'),
                       'reason': _dj.get('reason')}
                      for _dj in (meta.get('doc_code_js') or [])[:100]],
            'disclosure': ('文件名形态为 <page>.html-<hash>.js(VitePress 文档代码块 chunk), '
                           '内容为文档代码示例而非目标自身代码, 已不入队分析(避免示例路径误当真实接口)'),
        },
        # 字典候选: 只列**命中**项(未命中的泛化猜测隐去, 降噪强制约束)
        'dict_candidates': _urls(_hits_only(meta.get('dict_candidates') or set())),
        # 逐端点数据模型(方案七): 按端点消费的完整对象(含 class/risk/replay)
        'endpoints': endpoints,
        # 插件清单(方案 9.1): 本次实际启用的 Collector/Parser/Prober/Enricher
        'plugins': _plugins_list(getattr(ctx, 'config', None) or {}),
        # 路径推断候选(方案 4.6): 由已知路径派生的同族兄弟 —— **只列命中(非404)项**,
        #   未命中的派生候选隐去(降噪强制约束; 命中项仍与提取结果分区存放)。
        'inferred_paths': _urls(_hits_only(meta.get('inferred_paths') or set())),
        # OPTIONS/Allow 方法发现(方案 2-B): 目标自述支持的方法 {path: [方法…]}
        'options_methods': dict(getattr(ctx, 'options_methods', None) or {}),
        # 响应体/响应头 URL 挖掘(方案 2-B): 从响应挖出并回灌的同源新路径
        'mined_paths': _urls(getattr(ctx, 'mined_paths', None) or set()),
        'relative_apis': _urls(meta.get('relative_apis', set())),
        # 参数总表（schema 类型/必填 + 运行时形态 + 意图; 全量参数）
        'param_table': _pt,
        # 注: 漏洞候选(candidates/candidates_summary)已随「候选」章节取消(用户要求)移除。
        # 动态解包(opt-in)还原产物: module.exports 的 config/endpoints(发现级线索, 不向目标发包)。
        'recovered': _recovered_json(meta),
        'coverage': {
            'is_static_single': _static,
            'disabled_features': [{'name': n, 'flag': f} for n, f in _dis],
        },
        'summary': {
            'severity': c,
            'js_files': len(js_files), 'frontend_routes': len(routes),
            'api_candidates': _n_cand, 'live_endpoints': len(api_items),
            # dict_candidates = **命中项**数(与 `dict_candidates` 数组同口径);
            #   dict_candidates_probed = 探测过的字典猜测总数(含未命中), 供了解尝试面。
            'dict_candidates': _n_dict, 'dict_candidates_probed': _n_dict_probed,
            'write_apis': len(write_apis),
            'subdomains': len(subdomains), 'excluded': len(excluded),
        },
        'completeness': {
            'logical_requests': ctx.total_sent, 'network_requests': _net,
            'budget_exhausted': _exhausted, 'circuit_tripped': _tripped,
            'circuit_recovered': bool(getattr(ctx, 'circuit_recovered', False)),
            # 熔断**实际跳过**的请求数(量化"熔断导致的漏扫量"; 旧版只有布尔, 无法量化)。
            'circuit_skipped': int(getattr(ctx, 'circuit_skipped', 0) or 0),
            # 运行时通道真实状态(能力宣称=真实执行): ran 只在浏览器会话确实启动后为 True;
            #   显式 runtime=true 但依赖缺失/异常时 ran=false + reason, 不再谎称"已启用"。
            #   triggered = 本次是否**实际请求**运行(auto 未触发=false) —— 区分
            #   "配置了但没请求"与"请求了但没跑成"两种未运行情形(与 HTML 披露同源)。
            'runtime': {
                'requested': (getattr(ctx, 'config', None) or {}).get('runtime'),
                'triggered': bool(getattr(ctx, 'runtime_requested', False)),
                'ran': bool(getattr(ctx, 'runtime_ran', False)),
                'reason': str(getattr(ctx, 'runtime_reason', '') or ''),
            },
            'truncated': dict(_trunc),
            # 断点续扫恢复量(纯统计, 零发包): 本次从 --resume 状态恢复、因而未重复发包的已探活路径数。
            #   避免"发包极少却有一堆端点"被误读为"工具没干活" —— 这些端点其实是上一轮已探、本轮继承的。
            'resumed_probed': int(getattr(ctx, 'resumed_probed', 0) or 0),
            # 自适应参数（值 + 依据）—— 与 HTML 同源
            'adapted': {str(_k): {'base': _v.get('base'), 'value': _v.get('value'),
                                  'basis': _v.get('basis')}
                        for _k, _v in (getattr(ctx, '_adapt_notes', None) or {}).items()},
            # "体量够大却零产出"的 JS —— **零产出 ≠ 无接口**, 必须如实披露(纯本地统计, 零发包)
            'silent_js': {
                'n': int(meta.get('silent_js_n', 0) or 0),
                'bytes': int(meta.get('silent_js_bytes', 0) or 0),
                'unreadable_n': int(meta.get('silent_js_unreadable_n', 0) or 0),
                'by_reason': dict(meta.get('silent_js_by_reason') or {}),
                'samples': list(meta.get('silent_js') or []),
                'disclosure': ('这些 JS 未能提取到任何内容(接口/路由/参数/业务名全空) —— '
                               '其接口与参数可能未被发现, 不等同于"那里没有接口"; '
                               '"疑似不可读"= 命中混淆/解包链特征; '
                               '"疑似打包产物(<打包器>)"= 命中打包器签名(代码在但模块化封装, 非混淆)'
                               ' → 建议 unbundle; 各归类的可操作建议见报告"扫描完整性"节'),
            },
            'tls': ({'issuer': ((_tls.get('issuer') or {}).get('organizationName')
                                 or (_tls.get('issuer') or {}).get('commonName')),
                      'not_after': _tls.get('not_after'),
                      'san_count': len(_tls.get('san') or [])} if _tls else None),
            # 声明范围(in-scope)护栏 + 授权确认留痕(合规证据链)
            'scope_rules': list(getattr(ctx, 'scope_rules', None) or []),
            'scope_blocked': int(getattr(ctx, 'scope_blocked', 0) or 0),
            'authorized': bool(getattr(ctx, 'authorized', False)),
            'auth_method': str(getattr(ctx, 'auth_method', '') or ''),
        },
        'diff': ({'prev_id': _d['prev_id'], 'prev_time': _d['prev_time'],
                  'new_apis': [{'path': p, 'method': m}
                               for p, m in _d['new_apis']],
                  'gone_apis': [{'path': p, 'method': m}
                                for p, m in _d['gone_apis']],
                  'new_findings': [{'type': t, 'url': u}
                                   for t, u in _d['new_findings']]}
                 if _d else None),
        'findings': {
            'by_category': {cat: _flist(items) for cat, items in sens_groups.items()},
            'other': _flist(other_findings),
            'all': _flist(fs),
        },
        'param_intent': (lambda _m: {
            dim: {name: {'kind': info['kind'], 'endpoints': info['endpoints'],
                         'shapes': info.get('shapes', [])}
                  for name, info in (_m.get('param_intent_index', {}).get(dim, {}).items())}
            for dim in ('idor', 'ssrf', 'sqli')
        })(_am),
        'unauth_access_hints': _am['unauth_access_hints'],
    }
    ensure_parent(out)
    _atomic_dump_json(out, payload)
    log(f'JSON报告: {out}')


# ---------- §2.6 / §10 独立侧车 JSON ----------
def write_endpoints_json(ctx, target, meta, path):
    """独立端点侧车(方案 §10): 与 report.json 同源, 但**单独成文件**便于 CI / 流水线消费。

    含: extracted_endpoints(完整提取清单) + 逐端点 source_location(file:line:col) +
    source_extractor(ast/regex/wasm) + confidence + wasm/external/relative 分区。
    端点 URL 清单的敏感 query 值按合规基线无条件遮掩(与审计/历史库同源)。
    """
    _raw = (set(meta.get('apis') or set())
            | set(meta.get('recomb') or set())
            | set((meta.get('write_apis') or {}).keys()))
    _eps_sorted = sorted(_raw)
    _srcline = meta.get('api_srcline') or {}
    _extractor = meta.get('api_extractor') or {}
    _conf = meta.get('api_conf') or {}
    _evidence = meta.get('evidence') or {}   # R1: path → tier(runtime/full-url/static/dict)

    def _red(u):
        return u

    _endpoints = []
    _kind_counts = {}
    _writes_map = meta.get('write_apis') or {}
    for p in _eps_sorted:
        _sl = _srcline.get(p)
        # 端点类别(发现级启发式): backend_api / frontend_route / unknown —— 供清单梳理直接筛真实接口。
        _k = _endpoint_kind(p, meta, _writes_map.get(p))
        _kind_counts[_k] = _kind_counts.get(_k, 0) + 1
        _endpoints.append({
            'endpoint': _red(p),
            'source_location': ({'src': _sl[0], 'line': _sl[1], 'col': _sl[2]}
                                if _sl and len(_sl) >= 3 else None),
            'source_extractor': _extractor.get(p),
            'confidence': _conf.get(p, 'MEDIUM'),
            'evidence': _evidence.get(p, 'static'),
            'kind': _k,
        })
    payload = {
        'schema': 'facet-endpoints/v1',
        'target': target,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'tool_version': __version__,
        'extracted_endpoints': [_red(p) for p in _eps_sorted],
        'wasm_apis': sorted(_red(u) for u in (meta.get('wasm_apis') or set())),
        'external_apis': sorted(_red(u) for u in (meta.get('external_apis') or set())),
        'relative_apis': sorted(_red(u) for u in (meta.get('relative_apis') or set())),
        # 端点类别汇总(backend_api / frontend_route / unknown 计数) —— 一眼看清"真接口"占比。
        'kind_summary': _kind_counts,
        'endpoints': _endpoints,
    }
    ensure_parent(path)
    _atomic_dump_json(path, payload)
    log(f'端点侧车 JSON: {path}')


def write_recovered_json(ctx, target, meta, path):
    """动态解包(opt-in)还原产物侧车 —— 还原出的 `module.exports`(config / endpoints)。

    仅当本次确有动态解包还原产物时写文件(否则返回 0, 不产生空文件)。
    与端点侧车同源同目录, 便于 CI / 流水线消费"还原即产出"。
    """
    rec = (meta or {}).get('recovered') or {}
    if not rec:
        return 0
    payload = {
        'schema': 'facet-recovered/v1',
        'target': target,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'tool_version': __version__,
        'source': 'dynamic_deobf (L3–L5 密封离线沙箱)',
        'note': '发现级线索(启发式·非定级); 沙箱内零网络, 未向目标发包',
        'recovered': _recovered_json(meta),
    }
    ensure_parent(path)
    _atomic_dump_json(path, payload)
    log(f'动态解包还原侧车: {path}')
    return len(rec)


def write_diff_json(ctx, target, meta, out_path, use_history=False):
    """与上次扫描基线做增量 diff(方案 §2.6): 新增 / 消失 / 未变端点, 供 CI 门禁。

    基线的**首选来源是 history.db**(`--save-history`), 其次才是本地文件
    `<stem>.endpoints.baseline.json` —— 旧实现只认文件, 导致"历史库"与"增量 diff"
    两套开关、两套数据、两套结果(用户必须记着开哪个)。两者口径已统一为 **path 级**。

    use_history=True 且库里有该 base 的上一次扫描 → 用库; 否则回退文件(兼容老用户)。
    无论用哪个来源, 都会**继续更新文件基线**, 保证回退路径始终可用。
    """
    import hashlib
    _stem = os.path.splitext(out_path)[0]
    _baseline_path = _stem + '.endpoints.baseline.json'
    _raw = (set(meta.get('apis') or set())
            | set(meta.get('recomb') or set())
            | set((meta.get('write_apis') or {}).keys()))
    _current = _raw  # 集合, 用于集合差分(切勿先 sorted 成 list, 否则 list - set 抛 TypeError)
    _current_sorted = sorted(_raw)
    _cur_sha = hashlib.sha256('\n'.join(_current_sorted).encode('utf-8', 'ignore')).hexdigest()

    # ① 优先: 历史库(与 --save-history 同一份数据)
    _hist = None
    if use_history:
        try:
            from ..core.history import ScanHistory
            _hist = ScanHistory().diff_paths(target, _current)
        except Exception as e:
            dbg(f'历史库 diff 失败, 回退文件基线: {e}')
            _hist = None

    if _hist:
        _added, _removed, _unchanged = _hist['added'], _hist['removed'], _hist['unchanged']
        _source, _baseline_at, _prev_sha = 'history', _hist.get('baseline_scan'), None
        _baseline_scan = _hist.get('baseline_scan')
    else:
        # ② 回退: 文件基线
        _prev, _baseline_at, _prev_sha = set(), None, None
        if os.path.exists(_baseline_path):
            try:
                with open(_baseline_path, encoding='utf-8') as f:
                    _b = _json.load(f)
                _prev = set(_b.get('endpoints', []))
                _baseline_at = _b.get('generated_at')
                _prev_sha = _b.get('sha256')
            except Exception:
                _prev = set()
        _added = sorted(_current - _prev)
        _removed = sorted(_prev - _current)
        _unchanged = sorted(_current & _prev)
        _source, _baseline_scan = 'file', None

    diff = {
        'schema': 'facet-diff/v1',
        'target': target,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'baseline_source': _source,
        'baseline_scan': _baseline_scan,
        'baseline_at': _baseline_at,
        'added': _added,
        'removed': _removed,
        'unchanged': _unchanged,
        'counts': {'added': len(_added), 'removed': len(_removed), 'unchanged': len(_unchanged)},
        'current_sha256': _cur_sha,
        'baseline_sha256': _prev_sha,
    }
    ensure_parent(_stem + '.diff.json')
    _atomic_dump_json(_stem + '.diff.json', diff)
    # 更新基线(供下次 diff / 回退路径)
    _bl = {'schema': 'facet-baseline/v1', 'target': target,
           'generated_at': diff['generated_at'], 'sha256': _cur_sha, 'endpoints': _current_sorted}
    ensure_parent(_baseline_path)
    _atomic_dump_json(_baseline_path, _bl)
    log(f'增量 diff({_source}): {_stem}.diff.json '
        f'(新增 {len(_added)} / 消失 {len(_removed)} / 未变 {len(_unchanged)})')
