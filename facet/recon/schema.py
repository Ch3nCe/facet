# -*- coding: utf-8 -*-
"""Schema 源 ingestion（Phase A：缺口 ① Swagger/OpenAPI/GraphQL）。

动机：Swagger/OpenAPI/GraphQL 是**最准确、信息量最大**的接口 + 参数 + 类型来源。
此前 facet 只把 swagger/graphql 当"良性配置不误报"，没有主动探测并解析 schema，
等于放着最准的情报源没吃。本模块补齐：

- 探测并解析 **OpenAPI / Swagger** JSON 规范 → 端点(路径+方法) + 参数(名称/位置/类型/必填)
  + 请求体字段 + 认证机制(securitySchemes)。
- 探测并内省 **GraphQL** 端点 → 每个对象类型的字段 + 参数(args) 作为端点候选。
- 端点并入 out['apis']（复用确认 / 报告 / recon_matrix 全链路）；参数并入 ctx.pmap
  且以更丰富形态存入 out['schema_params']（直接补缺口 ②：嵌套结构 + 类型 + 必填）；
  来源写入 out['api_srcline']；认证机制写入 out['schema_auth']。

合规：全部走 REQ（只读 GET / 受限 POST 内省），受统一限速 + 全局预算 + 熔断约束，
不请求跨域、不写、不爆破。探测路径为常见 schema 端点候选（同源）。
"""
import re
import urllib.parse

from facet.core.dicts import SWAGGER_SPEC_PATHS, normalize_extracted_path

# 同源 schema 端点候选（只读 GET；非 JSON 响应的候选会被跳过，不误报）。
#   规范 JSON 路径**复用 `dicts.SWAGGER_SPEC_PATHS`**(单一事实来源) —— 避免与
#   隐藏路径字典各写一份导致漂移; GraphQL 端点单独列出(内省探测, 非 GET spec)。
_GRAPHQL_CANDIDATES = (
    '/graphql',
    '/api/graphql',
    '/graphql/',
)
_SCHEMA_CANDIDATES = tuple(SWAGGER_SPEC_PATHS) + _GRAPHQL_CANDIDATES

# GraphQL 内省查询（只取对象类型 + 字段 + 参数，足够支撑"端点 + 参数"测绘）。
_GRAPHQL_INTROSPECT = (
    'query{__schema{types{kind name fields{name args{name type{kind name '
    'ofType{kind name}}}}}}}'
)

_HTTP_METHODS = ('get', 'post', 'put', 'delete', 'patch', 'options', 'head')


def _looks_like_yaml(text):
    """启发式: 目标正文是否像 YAML OpenAPI/Swagger 规范。

    仅用于"非 JSON 且非 HTML"的场景兜底 —— 很多规范以 .yaml 交付(正文以
    `openapi:` / `swagger:` / `info:` / `paths:` 起始)。返回 True 才尝试 yaml.safe_load。
    """
    t = (text or '').lstrip()
    if not t or t[:1] in ('{', '[', '<'):
        return False
    return t.startswith(('openapi:', 'swagger:', 'info:', 'paths:'))


def _parse_spec_body(r):
    """从 schema 探测响应解析规范(dict); 支持 JSON 与 YAML, 均安全解析。

    - JSON: 优先(r.json()) —— Content-Type 含 json 或正文以 { / [ 起始。
    - YAML: Content-Type 含 yaml/yml, 或正文像 YAML(_looks_like_yaml) → yaml.safe_load
      (SafeLoader 子类, 无任意代码执行; 与全仓 yaml 解析口径一致)。
    - 任一失败/非规范 → 返回 None(调用方跳过, 不误报)。

    修复覆盖缺陷: 此前只调 r.json(), 目标以 YAML 交付的 OpenAPI/Swagger 规范
    (application/yaml / text/yaml / `openapi:` 起始正文)被**静默跳过**, 导致大量
    端点漏覆盖(工具宣称支持 OpenAPI/Swagger, 实则漏 YAML 形态)。
    """
    if r is None:
        return None
    ct = ((getattr(r, 'headers', None) or {}).get('Content-Type') or '').lower()
    body = getattr(r, 'text', '') or ''
    if 'json' in ct or body.lstrip()[:1] in ('{', '['):
        try:
            return r.json()
        except Exception:
            return None
    if 'yaml' in ct or 'yml' in ct or _looks_like_yaml(body):
        try:
            import yaml
            return yaml.safe_load(body)
        except Exception:
            return None
    return None


def _type_name(schema):
    """从 OpenAPI/GraphQL 类型片段提取最简类型名。

    兼容两种形态:
    - OpenAPI 3.0: {type|format|$ref|enum}
    - Swagger 2.0: 参数级 type 直接挂在 param 上(无 schema 包裹)
    - GraphQL 内省: {kind, name, ofType}（NON_NULL/LIST 包裹，叶子为 SCALAR/ENUM/...）
    """
    if not isinstance(schema, dict):
        return None
    if schema.get('type'):
        return schema['type']
    if schema.get('format'):
        return schema['format']
    ref = schema.get('$ref')
    if ref:
        return ref.rsplit('/', 1)[-1]
    if schema.get('enum'):
        return 'enum'
    # GraphQL 内省类型: NON_NULL/LIST 包裹 → 递归 ofType
    if schema.get('kind') in ('NON_NULL', 'LIST') and schema.get('ofType'):
        return _type_name(schema['ofType'])
    # GraphQL 叶子类型: SCALAR/ENUM/OBJECT/INPUT_OBJECT 的 name
    if schema.get('kind') in ('SCALAR', 'ENUM', 'OBJECT', 'INPUT_OBJECT') and schema.get('name'):
        return schema['name']
    return None


def _schema_base_prefix(spec):
    """从 OpenAPI/Swagger 规范抽取**路径前缀**(basePath / servers url 路径段)。

    两种形态通用, 不做任何硬编码:
      · Swagger 2.0: 顶层 `basePath`(如 "/v2")
      · OpenAPI 3.x: `servers[].url` 的路径部分(相对 "/v2" / 绝对 "https://x/v2"
        / 带模板变量 "{baseUrl}/v2" 皆兼容)
    规范里的 paths 均**相对于此前缀**; 漏加会导致端点路径缺前缀(如 petstore
    的 /v2/pet 被错记成 /pet —— 探活目标错误、召回归零)。无前缀则留空。
    """
    if not isinstance(spec, dict):
        return ''
    bp = spec.get('basePath')
    if isinstance(bp, str) and bp.strip():
        return bp.strip().rstrip('/') or ''
    for s in (spec.get('servers') or []):
        if not isinstance(s, dict):
            continue
        url = s.get('url')
        if not isinstance(url, str) or not url.strip():
            continue
        # 去掉模板变量(如 {baseUrl})以免产生非法路径段
        cleaned = re.sub(r'\{[^}]+\}', '', url).strip()
        if not cleaned:
            continue
        # 抽出**路径部分**, 兼容四种形态(不写死具体值):
        #   相对 "/v2" · 绝对 "https://x/v2" · 协议相对 "//x/v2" · 模板残留 ":///v2"
        if '://' in cleaned:
            cleaned = cleaned.split('://', 1)[1]
        elif cleaned.startswith('//'):
            cleaned = cleaned[2:]
        if not cleaned.startswith('/'):
            _i = cleaned.find('/')
            if _i < 0:
                continue          # 纯 host、无路径前缀
            cleaned = cleaned[_i:]
        p = '/' + cleaned.lstrip('/')
        if p != '/':
            return p.rstrip('/') or ''
    return ''


def _join_path_prefix(prefix, path):
    """把规范路径前缀拼到相对路径前, 避免重复前缀。"""
    if not prefix:
        return path
    if path.startswith(prefix):
        return path
    return prefix.rstrip('/') + '/' + path.lstrip('/')


def _json_pointer_get(doc, pointer):
    """按 RFC6901 JSON Pointer 从文档取值; 非 `#/` 指针或路径不存在 → None。"""
    if not isinstance(pointer, str) or not pointer.startswith('#/'):
        return None
    node = doc
    for raw in pointer[2:].split('/'):
        key = raw.replace('~1', '/').replace('~0', '~')
        if isinstance(node, dict):
            if key not in node:
                return None
            node = node[key]
        elif isinstance(node, list):
            try:
                node = node[int(key)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return node


def _deref(spec, obj, _depth=0):
    """若 obj 是 `{"$ref": "#/..."}` 则解析为真实对象(带深度上限, 防自引用/循环)。

    非 $ref / 解析失败 → 原样返回(不误伤、不崩溃)。
    """
    if _depth > 8 or not isinstance(obj, dict):
        return obj
    ref = obj.get('$ref')
    if not isinstance(ref, str):
        return obj
    target = _json_pointer_get(spec, ref)
    if not isinstance(target, dict):
        return obj
    return _deref(spec, target, _depth + 1)


def _schema_fields(spec, schema, _depth=0):
    """收集对象 schema 的 (properties, required) —— 兼容 `$ref` 与 `allOf` 组合(递归合并)。

    返回 (props:dict, required:set)。非对象 / 解析失败 → ({}, set())。
    """
    if _depth > 8:
        return {}, set()
    schema = _deref(spec, schema)
    if not isinstance(schema, dict):
        return {}, set()
    props = {}
    required = set()
    for sub in (schema.get('allOf') or []):        # allOf: 合并各子 schema 的字段
        _p, _r = _schema_fields(spec, sub, _depth + 1)
        for k, v in _p.items():
            props.setdefault(k, v)
        required |= _r
    for k, v in (schema.get('properties') or {}).items():
        props.setdefault(k, v)
    for r in (schema.get('required') or []):
        required.add(r)
    return props, required


def parse_openapi(spec):
    """解析 OpenAPI/Swagger 规范 → 端点列表。

    每个端点: {path, method, params:[{name, in, type, required}], source}。
    参数来源: 路径级 parameters(对所有操作生效) + 操作级 parameters + requestBody(JSON)的 properties。
    """
    endpoints = []
    if not isinstance(spec, dict):
        return endpoints
    paths = spec.get('paths') or {}
    _prefix = _schema_base_prefix(spec)
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        item = _deref(spec, item)          # 路径项本身可能是 $ref
        _path = _join_path_prefix(_prefix, path)
        # 路径级参数(OpenAPI 规范: 作用于该路径下**所有**操作; 操作级同 (name,in) 覆盖之)
        _path_params = item.get('parameters') if isinstance(item.get('parameters'), list) else []
        for method in _HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            # 合并 路径级 + 操作级 参数, 以 (name, in) 为键 —— 操作级覆盖路径级
            _merged = {}
            for _src in (_path_params, op.get('parameters') or []):
                if not isinstance(_src, list):
                    continue
                for p in _src:
                    if not isinstance(p, dict):
                        continue
                    p = _deref(spec, p)        # 参数可能是 $ref(#/components/parameters/…)
                    if not isinstance(p, dict):
                        continue
                    _merged[(p.get('name'), p.get('in'))] = p
            params = []
            for p in _merged.values():
                # Swagger 2.0 `in: body` 参数: 其 schema 的字段才是真实请求体字段
                #   (容器参数名通常是 "body", 单列无意义) —— 展开为 body 字段。
                if p.get('in') == 'body':
                    _props, _req = _schema_fields(spec, p.get('schema') or {})
                    if _props:
                        for fname, fsch in _props.items():
                            params.append({
                                'name': fname, 'in': 'body',
                                'type': _type_name(fsch),
                                'required': fname in _req,
                            })
                        continue
                # OpenAPI 3.0: 类型在 schema 内; Swagger 2.0: 类型直接挂在 param 上。
                #   `p.get('schema') or p` 同时覆盖两种形态(Swagger 2.0 的 body 参数仍走 schema)。
                _type_src = p.get('schema') or p
                params.append({
                    'name': p.get('name'),
                    'in': p.get('in'),
                    'type': _type_name(_type_src),
                    'required': bool(p.get('required', False)),
                })
            # requestBody → **各媒体类型**的 properties 视作字段参数
            #   (JSON / x-www-form-urlencoded / multipart-form-data … 通用, 不只 JSON)
            rb = (op.get('requestBody') or {}).get('content') or {}
            _rb_fields = {}
            for _mt, _mtval in (rb.items() if isinstance(rb, dict) else ()):
                if not isinstance(_mtval, dict):
                    continue
                # 表单类媒体类型标 formData(与 Swagger 2.0 语义一致), 其余标 body
                _loc = ('formData'
                        if ('form' in str(_mt).lower() or 'multipart' in str(_mt).lower())
                        else 'body')
                _props, _req = _schema_fields(spec, _mtval.get('schema') or {})
                for fname, fsch in _props.items():
                    if fname in _rb_fields:      # 同名字段跨媒体类型去重(首个为准)
                        continue
                    _rb_fields[fname] = {
                        'name': fname, 'in': _loc,
                        'type': _type_name(fsch),
                        'required': fname in _req,
                    }
            params.extend(_rb_fields.values())
            endpoints.append({
                'path': _path,
                'method': method.upper(),
                'params': [p for p in params if p['name']],
                'source': 'openapi',
            })
    return endpoints


def parse_graphql(introspection):
    """解析 GraphQL 内省结果 → 端点列表。

    每个对象类型(非 __ 内省类型)的字段作为端点: graphql:{Type}.{field}，
    字段 args 作为参数。
    """
    endpoints = []
    if not isinstance(introspection, dict):
        return endpoints
    sch = (introspection.get('data') or {}).get('__schema') or {}
    for t in (sch.get('types') or []):
        if not isinstance(t, dict):
            continue
        if t.get('kind') != 'OBJECT':
            continue
        tname = t.get('name') or ''
        if tname.startswith('__'):
            continue
        for fld in (t.get('fields') or []):
            if not isinstance(fld, dict):
                continue
            fname = fld.get('name') or ''
            if fname.startswith('__'):
                continue
            params = []
            for a in (fld.get('args') or []):
                if not isinstance(a, dict):
                    continue
                params.append({
                    'name': a.get('name'),
                    'in': 'arg',
                    'type': _type_name(a.get('type', {})),
                    'required': False,
                })
            endpoints.append({
                'path': 'graphql:%s.%s' % (tname, fname),
                'method': 'POST',
                'params': [p for p in params if p['name']],
                'source': 'graphql',
            })
    return endpoints


def _merge_endpoint(ctx, out, ep):
    """把一个 schema 端点并入 out / ctx.pmap。(base 参数从未被读取, 审计 D7 删除)"""
    raw = ep['path']
    norm = ep['path'] if raw.startswith('graphql:') else (normalize_extracted_path(raw) or raw)
    if not norm:
        return
    out['apis'].add(norm)
    out.setdefault('schema_apis', set()).add(norm)
    out.setdefault('api_srcline', {})[norm] = (ep['source'], None, None)
    # 参数：写入更丰富形态 + 并入 pmap(参数名集合)
    sp = out.setdefault('schema_params', {})
    sp[norm] = {'method': ep['method'], 'source': ep['source'],
                'params': ep['params']}
    for p in ep['params']:
        if p.get('name'):
            ctx.pmap.setdefault(norm, set()).add(p['name'])


def discover_schema(ctx, base, out, req):
    """探测并解析目标同源的 OpenAPI/Swagger/GraphQL schema，并入 out / ctx.pmap。

    `req` —— **HTTP 客户端由上层注入**(依赖倒置): 领域层(recon)不 import 编排层(core.engine),
    否则会形成向上依赖 + 循环依赖。调用方(engine)传入其 `REQ`。

    返回 (openapi_n, graphql_n, auth_schemes)，供调用方日志。失败静默返回 (0,0,[])。
    """
    if not getattr(ctx, 'config', {}).get('schema_probe', True):
        return 0, 0, []

    openapi_n = 0
    graphql_n = 0
    auth_schemes = []

    # 分两类候选：OpenAPI/Swagger（GET 拿规范 JSON）与 GraphQL（POST 内省）。
    #   关键：GraphQL 端点对**无 query 的 GET** 通常返回 400/错误页（非 200），
    #   若与 OpenAPI 共用 "GET==200 且 JSON" 门槛会漏掉 GraphQL，因此单独处理：
    #   对 graphql 候选直接 POST 内省查询，以响应是否含 __schema 判定。
    _graphql_cands = [c for c in _SCHEMA_CANDIDATES if c.rstrip('/').endswith('graphql')]
    _openapi_cands = [c for c in _SCHEMA_CANDIDATES if c not in _graphql_cands]

    # ---- OpenAPI / Swagger：GET 探测规范 ----
    for cand in _openapi_cands:
        if ctx.budget_exhausted():
            break
        url = urllib.parse.urljoin(base, cand)
        try:
            r = req(ctx, 'GET', url)
        except Exception as e:
            # 逐候选失败此前零日志: 系统性原因(代理/超时)全军覆没时, 报告无法区分
            # "目标无 schema"与"探测从未成功"(审计 M)。
            from ..core.log import dbg
            dbg(f'schema 候选探测失败({url}): {e}')
            continue
        if r is None or getattr(r, 'status_code', 0) != 200:
            continue
        spec = _parse_spec_body(r)
        if not isinstance(spec, dict):
            continue

        # OpenAPI / Swagger
        if isinstance(spec, dict) and 'paths' in spec and (
                'swagger' in spec or 'openapi' in spec):
            # 认证机制（securitySchemes）→ 顺手记录（补缺口 ③ 的认证指纹）
            #   · OpenAPI 3.x: `components.securitySchemes`
            #   · Swagger 2.0 : `securityDefinitions`（**顶层**）—— 真实站点 petstore 即此形态,
            #     只读 components 会漏掉 api_key/petstore_auth(实测 E 图谱为空)。
            schemes = dict((spec.get('components') or {}).get('securitySchemes') or {})
            for sname, sval in (spec.get('securityDefinitions') or {}).items():
                schemes.setdefault(sname, sval)
            for sname, sval in schemes.items():
                if isinstance(sval, dict):
                    auth_schemes.append({
                        'name': sname,
                        'type': sval.get('type'),
                        'scheme': sval.get('scheme'),
                        # Swagger 2.0 用 `in`(apiKey 位置) 与 `flow`(oauth2); OpenAPI 3.x 用 `flows`。
                        'in': sval.get('in'),
                        'flow': (sval.get('flow') or (sval.get('flows') or {}) or {}),
                    })
            for ep in parse_openapi(spec):
                _merge_endpoint(ctx, out, ep)
                openapi_n += 1

    # ---- GraphQL：POST 内省（不依赖 GET 200）----
    for cand in _graphql_cands:
        if ctx.budget_exhausted():
            break
        url = urllib.parse.urljoin(base, cand)
        try:
            ri = req(ctx, 'POST', url,
                     headers={'Content-Type': 'application/json'},
                     json={'query': _GRAPHQL_INTROSPECT},
                     readonly_post=True)   # 语义只读的 introspection —— 显式声明供只读护栏放行
        except Exception:
            continue
        if ri is None or getattr(ri, 'status_code', 0) != 200:
            continue
        try:
            intro = ri.json()
        except Exception:
            continue
        if isinstance(intro, dict) and (intro.get('data') or {}).get('__schema'):
            for ep in parse_graphql(intro):
                _merge_endpoint(ctx, out, ep)
                graphql_n += 1

    if openapi_n:
        log = getattr(ctx, 'log', None)
        if callable(log):
            log(f'[*] Schema(OpenAPI/Swagger): 解析 {openapi_n} 个端点/方法')
    if graphql_n:
        log = getattr(ctx, 'log', None)
        if callable(log):
            log(f'[*] Schema(GraphQL): 解析 {graphql_n} 个字段端点')
    if auth_schemes:
        out.setdefault('schema_auth', []).extend(auth_schemes)
    return openapi_n, graphql_n, auth_schemes
