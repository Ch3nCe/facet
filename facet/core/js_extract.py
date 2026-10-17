# -*- coding: utf-8 -*-
"""JS 静态提取（调用点 / 拼接 / 变量传播 / 参数 / 结构式） —— 从 `core/engine.py` 拆出（便于维护）。"""
import re
import re as _re
from bisect import bisect_left as _bisect_left
from bisect import bisect_right as _bisect_right
from urllib.parse import parse_qsl, urljoin, urlparse, urlsplit

from ..recon.fingerprint import (
    ROUTE_EXTRA_ROUTE_NAMES,
    get_extra_route_patterns,
)
from .const import (
    _API_MAP_CAMEL_RE,
    _API_MAP_CLUSTER,
    _API_MAP_KEY_RE,
    _API_MAP_RESERVED,
    _API_MAP_SRV_EXT,
    _API_MAP_VAR_DECL_RE,
    _API_MAP_VAR_ITEM_RE,
    _API_PREFIX_ANY,
    _API_PREFIX_RE,
    _BODY_KEY_STOP,
    _CHUNK_STATIC_EXTS,
    _CONCAT_ARG_RE,
    _FRAG_STATIC_EXTS,
    _HTTP_CALL_RE,
    _HTTP_CLIENT_NAMES,
    _IDENT,
    _LIT,
    _NAV_CALL_RE,
    _NON_API_PREFIX,
    _OPERAND_RE,
    _PRECEDING_READ_CHAIN,
    _QP_VAL_OK,
    _RE_BODY_CALL,
    _RE_DATA_OBJ,
    _RE_JSON_STR,
    _RE_OBJ_KEY,
    _RE_QUERY_LIT,
    _RE_SHORTHAND_KEY,
    _RE_STRVAR,
    _RE_TEMPLATE_PATH,
    _REQ_CALL_RE,
    _STATIC_EXT,
    _TRACKING_PARAMS,
    PARAM_SEMANTICS_V45,
    ast_sidecar,
    plugins,
)
from .deobf import _decode_js_escapes, decode_layer, has_charcode_apply, unpack_string_array
from .dicts import (
    OBF_KEYS,
    RE_API,
    RE_BASEURL,
    RE_CHUNK,
    RE_CONCAT,
    RE_CONCAT2,
    RE_GRPC_METHOD,
    RE_LAZY,
    RE_PLACEHOLDER,
    RE_REST_PARAM,
    RE_ROUTE,
    RE_SSE,
    RE_TEMPLATE_URL,
    RE_URL_SEARCH_QS,
    RE_WS,
    RE_WS_SEND,
    SECMAP,
    SKELETON,
    WRITE_METHODS,
    _is_base_prefix,
    _is_route_template,
    apply_custom_rules,
    crypto_score,
    extract_query_params,
    get_custom_rules,
    is_obfuscated,
    is_static_or_malformed_path,
    iter_api_call_patterns,
    norm_sev,
    normalize_extracted_path,
    obfuscation_score,
    param_names_from_text,
    scan_js_markers,
    srv_ep_exts,
)
from .log import dbg, log
from .util import _host_of


# ---------- 分类与聚类 ----------
# 注: 这两个函数被 core 内部使用(probe 排序 / recon_deep 汇总), 非废弃。
#     报告层的分类逻辑在 report.py(classify_finding / classify_api), 两者职责不同。
def classify(p):
    low = p.lower()
    for name, kws in SECMAP:
        if any(k in low for k in kws):
            return name
    return '业务接口'


def modules_of(apis):
    from collections import Counter
    c = Counter()
    for p in apis:
        segs = [s for s in p.lower().split('/') if s and s not in SKELETON and not s.isdigit() and '.' not in s]
        if segs:
            c[segs[0]] += 1
    return dict(c.most_common(12))


# 注: 解码层(decode_layer / _decode_js_escapes)已拆至 `core/deobf.py`(便于维护)。

# ---------- 拼接重组 ----------
def concat_recomb(text, base):
    """把"被压缩器拆散的 URL 碎片"两两拼回 (如 `/api/v1` + `/users`)。

    ① 丢弃"自身已完整"的片段(含 `?` 查询串 / 含模板插值 `${`), 它们不是被拆散的碎片;
          ② 禁止两个 `/api/` 完整路径互相拼接;
          ③ 尾片必须是"单段"(`/users` `/v1`), 不能是另一条完整路径;
          ④ 结果里 `/api/` 至多出现一次、且不含 `//`。
    """
    raw = [f for f in RE_CONCAT.findall(text) + RE_CONCAT2.findall(text)
           if f.startswith('/') and not f.endswith(_FRAG_STATIC_EXTS)]
    frags = [f for f in set(raw) if '?' not in f and '${' not in f]
    frags = sorted(frags, key=len, reverse=True)[:30]
    cands = set()
    for i, a in enumerate(frags):
        for b in frags[i + 1:]:
            if _is_api_path(a) and _is_api_path(b):
                continue                       # 两个完整接口路径不拼接
            if b.count('/') > 1:
                continue                       # 尾片必须是单段, 不是另一条路径
            if len(a) + len(b) < 60 and not a.endswith('/') and not b.startswith('/'):
                cands.add(a + '/' + b)
            elif len(a) + len(b) < 60:
                cands.add(a + b)
    return {c for c in cands if c.count('/') >= 1 and len(c) > 6
            and len(_API_PREFIX_ANY.findall(c)) <= 1 and '//' not in c[1:]}


def _req_ctx_ok(text, pos, back=400):
    """`pos` 之前 back 字符内(且不跨越 `;`/`}` 语句边界)是否存在请求调用记号。

    back 取 400(而非更小): **未压缩**站点(多行缩进)里 `$.ajax({` 与 `data:{` 之间
    可相距 200+ 字符(几乎全是空白/缩进)。窗口跨语句由 `;`/`}` 截断兜底, 故放大不引入
    跨语句误判。
    """
    lo = max(0, pos - back)
    seg = text[lo:pos]
    for sep in (';', '}'):
        i = seg.rfind(sep)
        if i >= 0:
            seg = seg[i + 1:]
    return bool(_REQ_CALL_RE.search(seg))




def _is_api_path(p):
    """判断是否为"像接口"的绝对路径（放宽自旧版仅 `/api/` 的硬编码）。

    采纳 ① `/api` `/rest` `/graphql` `/gateway` `/rpc` `/service(s)` `/v1` 等前缀；
    ② 传统服务端脚本端点（`.jsp`/`.php`/`.asp`/`.do`/`.cgi` 等）。
    排除静态资源与明显非接口前缀，避免放宽后引入噪声。仅作**路径形态**判断，不保证可达。
    """
    if not p or not p.startswith('/'):
        return False
    path = p.split('?')[0].split('#')[0]
    low = path.lower()
    if low.endswith(_STATIC_EXT):
        return False
    if low.startswith(_NON_API_PREFIX):
        return False
    return bool(_API_PREFIX_RE.match(low)) or low.endswith(srv_ep_exts())


def _is_dynamic_base_candidate(p, root_base=False):
    """动态基址解析产出的候选端点 —— **形态 / 用法判定，不依赖任何变量名或站点白名单**。

    接受「某变量被赋值为根相对路径形态、又作为 `VAR + "字面量"` 左操作数」解析出的结果,
    只要结果形如真实端点即可: 根相对 / 多段 / 非静态资源 / 非资源目录前缀。
    不再要求 `/api` 等硬编码前缀 —— 否则 RuoYi 类 `ctx + "/login"`(ctx="/xinzuo")会被整条漏掉。

    这是「动态获取而非硬编码」原则的核心落地: 我们不预设接口必须带 `/api`, 而是看
    「这个拼接结果是否长得像一个端点」。

    `root_base=True` 用于「基址为站点根 `/`」的场景(如 RuoYi `var ctx="/"` + `ctx+"login"`
    → `/login`): 此时拼接产物本身就是**单段真实端点**, 不应因"段数不足"被丢弃。
    """
    if not p or not isinstance(p, str):
        return False
    path = p.split('?')[0].split('#')[0]
    if not path.startswith('/'):
        return False
    low = path.lower()
    if low.endswith(_STATIC_EXT):
        return False
    if any(low.startswith(pre) for pre in _NON_API_PREFIX):
        return False
    # 静态资源 / 畸形形态(中段静态目录、中段扩展名、残缺结尾) → 非端点。
    #   覆盖 `_NON_API_PREFIX`(仅前缀) / `_STATIC_EXT`(仅结尾) 漏掉的**中段**形态
    #   (实测 `/wls_prs_sps/images/sps/-` 会漏过前缀/结尾判, 被误当端点)。
    if is_static_or_malformed_path(path):
        return False
    # 根相对路径形态: 仅含 URL 路径安全字符 + 占位符({x} / :id / ${x}), 不允许空白 / 尖括号 / 注释。
    if not _DYN_BASE_PATH.match(path):
        return False
    # 去噪声: 默认至少 2 段(基址 + 子资源); 单段(如 `/xinzuo`)通常只是基址本身, 不算端点。
    #   **例外(root_base=True)**: 基址为站点根 `/` 时, 单段产物(如 `/login`)是真实端点。
    #   但仍要求段内含字母 —— `/3` 这类纯数字段几乎不可能是端点(形态去噪, 不依赖名字白名单)。
    if path.count('/') < 2:
        if not root_base:
            return False
        if not re.search(r'[A-Za-z]', path[1:]):
            return False
    return _is_plausible_api_path(path)


_DYN_BASE_PATH = re.compile(r'^/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-{}:$]+)*$')


def _is_base_value(v):
    """变量值是否为「基址形态」(供跨文件符号表 `ctx.js_symbols` 登记)。

    接受根相对路径 —— **含站点根 `/` 本身**。纯形态判定, 不依赖变量名或站点白名单。
    站点根 `/` 是合法基址: 其拼接产物(如 RuoYi `ctx + "login"` → `/login`)是真实端点;
    若把 `/` 排除在外, 根部署变体(`var ctx="/"`)会因基址无法登记而整条漏抓。
    """
    if not v or not isinstance(v, str) or not v.startswith('/'):
        return False
    core = v.rstrip('/')
    return core == '' or bool(_DYN_BASE_PATH.match(core))


def _is_web_endpoint(p):
    """HTML 属性（action/href/formaction/data-*）用的**更宽**判定。

    在 `_is_api_path` 基础上，额外接受"带查询参数的绝对路径"（如 `/catalog/product?productId=1`、
    `/search?q=x`）——这是动态端点的强信号，服务端渲染站点（Django/Rails/Flask/ASP.NET/PHP）
    的接口常以无前缀的 RESTful 路径出现。仍排除静态资源与非接口前缀。
    """
    if _is_api_path(p):
        return True
    if not p or not p.startswith('/'):
        return False
    path = p.split('?')[0].split('#')[0]
    low = path.lower()
    if low.endswith(_STATIC_EXT) or low.startswith(_NON_API_PREFIX):
        return False
    if '?' in p and '=' in p.split('?', 1)[1]:
        # 但**全是跟踪/营销参数**的链接是导航跳转, 不是接口 —— 实测 nextjs.org 的
        #   `/contact/sales?utm_source=…&utm_medium=footer` 曾被当成"接口"。
        # HTML 里 query 常以实体形式出现(`&amp;`) → 先反转义, 否则键会变成 `amp;utm_medium`。
        _q = p.split('?', 1)[1].replace('&amp;', '&').replace('&#38;', '&')
        _keys = [k.lower() for k, _ in parse_qsl(_q, keep_blank_values=True)]
        if _keys and all(k in _TRACKING_PARAMS for k in _keys):
            return False
        return True
    return False


def _resolve_base_var_concat(text, syms=None):
    """解析 `const API='/api'; fetch(API+'/user/profile')` 这类"基址变量 + 路径"拼接。

    返回补出的完整路径集合(动态形态门禁, 不再硬编码 `/api` 前缀)。常量传播此前只服务写方法提取,
    接口路径提取完全不解析 —— 实测真实打包产物里 `API+'/x'` 写法极常见, 整条漏报。
    """
    if not text or '+' not in text:
        return set()
    consts = dict(_RE_STRVAR.findall(text))
    if syms:
        consts = {**consts, **syms}
    if not consts:
        return set()
    out = set()
    for m in re.finditer(r'\b([A-Za-z_$][\w$]*)\s*\+\s*["\']([^"\']+)["\']', text):
        var, lit = m.group(1), m.group(2)
        if var in consts and consts[var]:
            base = str(consts[var])
            cand = base.rstrip('/') + '/' + lit.lstrip('/')
            if _is_dynamic_base_candidate(cand, root_base=(base.strip('/') == '')):
                out.add(cand)
    # 反向: `"字面量" + VAR`(较少见, 但真实存在; 语义是"字面量挂到基址**后面**")
    #   🔴 组合顺序修正(审计实证): 旧写法 `lit + '/' + base` 拼出的候选**缺少前导斜杠**
    #   (如 'login/xinzuo'), 被路径形态门禁一律拒收 → 该分支对所有基址恒空转(死分支)。
    #   语义正确的是 `base + '/' + lit`(与正向同口径)。
    for m in re.finditer(r'["\']([^"\']+)["\']\s*\+\s*([A-Za-z_$][\w$]*)', text):
        lit, var = m.group(1), m.group(2)
        if var in consts and consts[var]:
            base = str(consts[var])
            cand = base.rstrip('/') + '/' + lit.lstrip('/')
            if _is_dynamic_base_candidate(cand, root_base=(base.strip('/') == '')):
                out.add(cand)
    return out


def _compose_base_with_callsites(text):
    """识别 `fetch("<base>"+VAR)` 形态, 并把**同文件内调用点传入的相对路径字面量**与基址拼接。

    例: `async function r(t){ … fetch("/api/v1"+t, …) }`  +  `(0,i.FH)("/auth/login", …)`
        →  `/api/v1/auth/login`
    这里只在"检测到 `基址 + 变量` 的 fetch 形态"时才启用(避免对普通文件过度生成)。

    **动态基址形态(非硬编码)**: 基址只要是「根相对路径形态」(`_DYN_BASE_PATH`)即可,
    不再写死 `/api|rest|gateway|graphql|vN` 前缀集合 —— 否则 `/app` `/xinzuo` 这类
    自定义上下文基址会被整条漏掉。结果仍走 `_is_dynamic_base_candidate` 形态门禁。

    **边界(有意为之)**: 只做**同文件**基址 × 调用点拼接。跨文件只做"基址变量传播"
    (`_resolve_base_var_concat` 的 `syms`), 不跨文件拼调用点 —— 否则 A 文件的基址会与
    B 文件里毫不相干的路径字面量拼出**假端点**。此前本函数带一个从不使用的 `syms`
    形参, 会让读者以为跨文件拼接已生效(实测参数被静默忽略), 已移除。
    """
    out = set()
    if not text or '+' not in text:
        return out
    # 基址必须是**根相对路径形态**(动态), 不能是**路径段**或任意串。
    bases = {b for b in re.findall(
        r'["\'`](/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)*)["\'`]\s*\+\s*[A-Za-z_$]', text)
        if _DYN_BASE_PATH.match(b)}
    if not bases:
        return out
    # 调用点传入的路径字面量: 兼容 `foo("/x")` 与 webpack 的 `(0,mod.fn)("/x")` 形态
    #   —— 后者 callee 是**括号表达式**, 标识符与 `(` 之间隔着 `)`, 故只要求 "`(` 后紧跟路径字面量"。
    calls = set(re.findall(
        r'\(\s*["\'`](/[A-Za-z][A-Za-z0-9_\-/{}.:$]*)["\'`]', text))
    for b in bases:
        for c in calls:
            if c.startswith(b) or c.endswith(_CHUNK_STATIC_EXTS):
                continue
            cand = b.rstrip('/') + '/' + c.lstrip('/')
            if _is_dynamic_base_candidate(cand):
                out.add(cand)
    return out


def _extract_concat_paths(text):
    """还原"字符串拼接"形式的接口路径。

    `"/api/user/"+id` → `/api/user/{id}`;  `"/api/comment/"+cid+"/replies"` → `/api/comment/{cid}/replies`。
    """
    paths, truncated = set(), set()
    if not text or '+' not in text:
        return paths, truncated
    for m in re.finditer(r'(["\'])(/[^"\']+)\1', text):
        base = m.group(2)
        if not _is_api_path(base):
            continue
        pos, path, extended = m.end(), base, False
        while True:
            # ① `+ IDENT + "字面量"`
            mm = re.match(r'\s*\+\s*([A-Za-z_$][\w$]*)\s*\+\s*(["\'])([^"\']*)\2', text[pos:])
            if mm:
                path += '{%s}' % mm.group(1) + mm.group(3)
                pos += mm.end(); extended = True; continue
            # ② `+ "字面量"` —— **纯字符串续接**(无标识符)。
            #   旧实现漏了这一支: `"…"+id+"/b/"+"c"` 会在 `+"c"` 处直接 break,
            #   产出 `/api/v1/a/{id}/b/` —— **尾段 `/c` 被静默截断**。
            #   截断后的路径看着完全合理, 探活却必然落空, 是最难发现的一类错。
            mm = re.match(r'\s*\+\s*(["\'])([^"\']*)\1', text[pos:])
            if mm:
                path += mm.group(2); pos += mm.end(); extended = True; continue
            # ③ `+ IDENT`(其后可能还有 `+ "字面量"`, 由下一轮 ② 接手)
            mm = re.match(r'\s*\+\s*([A-Za-z_$][\w$]*)', text[pos:])
            if mm:
                path += '{%s}' % mm.group(1); pos += mm.end(); extended = True; continue
            break
        if extended:
            clean = path.split('?')[0]
            # `"/api/v1"+t`(基址 + 完整路径变量)会产出畸形 `/api/v1{t}`(无 `/` 分隔) ——
            #   它不是真实端点, 而是"基址"; 交由 `_compose_base_with_callsites` 用调用点拼接。此处跳过。
            if re.search(r'[^/]\{[^}]+\}$', clean):
                continue
            paths.add(clean)
            truncated.add(base)
    return paths, truncated


def _normalize_template_paths(text):
    """模板字面量 `` `/api/user/${id}/x` `` 归一为 `/api/user/{id}/x`。

    """
    out = set()
    if not text or '${' not in text:
        return out
    for m in _RE_TEMPLATE_PATH.finditer(text):
        s = m.group(1)
        if not _API_PREFIX_ANY.search(s):
            continue
        def _ph(mm):
            expr = mm.group(1).strip()
            nm = re.search(r'([A-Za-z_$][\w$]*)\s*$', expr)
            return '{%s}' % (nm.group(1) if nm else 'x')
        norm = re.sub(r'\$\{([^}]*)\}', _ph, s).split('?')[0]
        # 去掉前导基址占位（`{hostServer}/rest/x` → `/rest/x`），否则 _is_api_path 会因非 '/' 开头而拒
        norm = re.sub(r'^(?:\{[^}]+\})+', '', norm)
        if _is_api_path(norm):
            out.add(norm)
    return out


def _is_relative_param_path(p):
    """**相对端点片段 + 变量** 形态 → 疑似"基址在配置里"的接口(非本站绝对路径)。

    覆盖常见开发写法: 配了 baseURL 的 axios 实例 / Angular HttpClient 服务 /
    `fetch(PREFIX + '/articles/' + id)` —— 端点写成**不含 `/api/` 前缀的相对片段**。
    判据: 含 `{变量}` 占位符(动态端点强信号), 且不是静态资源/已知非接口前缀/已有 API 前缀。
    """
    if not p or not p.startswith('/') or p.startswith('//'):
        return False
    low = p.lower()
    if low.endswith(_STATIC_EXT) or low.startswith(_NON_API_PREFIX):
        return False
    if _API_PREFIX_RE.match(low):
        return False            # 已有 API 前缀 → 走常规通道, 不重复
    # 排除 JS 代码残留(括号/方括号)与相对跳转(`/../`) —— 实测压缩 bundle 会产出 `/({i}`、`/../{n}`。
    if any(c in p for c in '()[]') or '..' in p:
        return False
    # 至少 2 段(`/a/{b}`): 单段(如 `/{x}_${sid}_${ts}`)多为非 URL 的字符串拼接残留。
    if p.count('/') < 2:
        return False
    return '{' in p             # 必须含变量占位符


def _extract_concat_method_paths(text):
    """还原 `"a/".concat(x, "/b")` 形式 —— **TS/Babel 把模板字面量编译成 `.concat()`**。

    实测(Vue RealWorld): `"profiles/".concat(n,"/follow")`、`"articles/".concat(t,"/comments")`、
    `"articles/".concat(t,"/comments/").concat(e)`(链式)。旧实现只认 `+` 拼接 → 这类端点**全部漏掉**。
    """
    out = set()
    if not text or '.concat(' not in text:
        return out
    for m in re.finditer(r'(["\'])([^"\']*)\1\s*\.concat\(', text):
        pos, parts, ok = m.end(), [m.group(2)], True
        while True:
            mm = _CONCAT_ARG_RE.match(text, pos)
            if not mm:
                ok = False
                break
            parts.append(mm.group(2) if mm.group(1) else ('{%s}' % mm.group(3)))
            pos = mm.end()
            if mm.group(4) == ')':
                cm = re.match(r'\s*\.concat\(', text[pos:])   # 链式 .concat(...)
                if not cm:
                    break
                pos += cm.end()
        if ok and len(parts) > 1:
            out.add(''.join(parts))
    return out


def _extract_http_client_paths(text):
    """提取"HTTP 客户端方法 + 路径字面量"写法(基址在配置里)。

    实测(Vue RealWorld): `axios.defaults.baseURL='https://api.realworld.show/api'` 之后
    用 `l.get("articles")` / `l.post("users/login")` / `l.get("tags")` 调用 —— 路径**不带前导 `/`**,
    旧实现(要求绝对路径)全部漏掉。
    **仅当文本里出现 `baseURL` 配置**(说明确有基址)才启用 —— 否则会把普通对象取值
    (`map.get("k")`、i18n `t("home")`)误当接口。
    """
    out = set()
    if not text or 'baseURL' not in text:
        return out
    for m in _HTTP_CALL_RE.finditer(text):
        recv, method, p = m.group(1), m.group(2).lower(), m.group(4)
        if p.startswith(('/', 'http', 'data:', '//', '#')) or ' ' in p:
            continue
        if p.lower().endswith(_STATIC_EXT):
            continue
        # 含大写/下划线 → 多为**属性名**而非接口(实测 Ember vendor 的 `obj.get('Content-Type')`)。
        if re.search(r'[A-Z_]', p):
            continue
        # 既无路径分隔、又非写方法、接收者也不像 HTTP 客户端 → 丢弃
        #   (实测 Ember vendor 的 `this.get('attrs')` / `.get('class')` 会被旧版误收)。
        if ('/' not in p and method not in ('post', 'put', 'patch', 'delete')
                and recv.lower() not in _HTTP_CLIENT_NAMES):
            continue
        out.add('/' + p.lstrip('/'))
    return out


def _extract_relative_param_paths(text):
    """提取"相对端点片段 + 变量"(见 `_is_relative_param_path`)。

    实测(Angular RealWorld bundle): 端点为 `"/articles/"+t+"/comments"`、`"/profiles/"+t`
    —— 旧实现因要求 API 前缀而**整条漏掉**(只捞到 `/api`、`/profiles/` 等碎片)。
    """
    found = set()
    if not text:
        return found
    # ① 模板字面量: `/profiles/${u}` → /profiles/{u}
    if '${' in text:
        for m in re.finditer(r'`([^`]*\$\{[^`]*)`', text):
            s = m.group(1)
            if not s.startswith('/'):
                continue
            def _ph(mm):
                nm = re.search(r'([A-Za-z_$][\w$]*)\s*$', mm.group(1).strip())
                return '{%s}' % (nm.group(1) if nm else 'x')
            norm = re.sub(r'\$\{([^}]*)\}', _ph, s).split('?')[0]
            norm = re.sub(r'^(?:\{[^}]+\})+', '', norm)
            if _is_relative_param_path(norm):
                found.add(norm)
    # ② 字符串拼接: "/articles/"+t+"/comments"
    for m in re.finditer(r'(["\'])(/[^"\']+)\1', text):
        base = m.group(2)
        pos, path, extended = m.end(), base, False
        while True:
            mm = re.match(r'\s*\+\s*([A-Za-z_$][\w$]*)\s*\+\s*(["\'])([^"\']*)\2', text[pos:])
            if mm:
                path += '{%s}' % mm.group(1) + mm.group(3); pos += mm.end(); extended = True; continue
            mm = re.match(r'\s*\+\s*(["\'])([^"\']*)\1', text[pos:])
            if mm:
                path += mm.group(2); pos += mm.end(); extended = True; continue
            mm = re.match(r'\s*\+\s*([A-Za-z_$][\w$]*)', text[pos:])
            if mm:
                path += '{%s}' % mm.group(1); pos += mm.end(); extended = True; continue
            break
        if extended:
            clean = path.split('?')[0]
            if _is_relative_param_path(clean):
                found.add(clean)
    return found


def _extract_body_params(text):
    """请求体参数名 —— axios.post/put/patch(url,{...}) / data:{...} / JSON.stringify({...}) 的对象键。"""
    found = set()
    if not text:
        return found
    for pat in (_RE_BODY_CALL, _RE_DATA_OBJ, _RE_JSON_STR):
        for m in pat.finditer(text):
            # `_RE_BODY_CALL` 自带 `.post(` 锚点; `data:`/`JSON.stringify` 需请求语境,
            #   否则会把 Vue 组件 `data(){…}`、图表/轮播库配置对象当请求体。
            if pat is not _RE_BODY_CALL and not _req_ctx_ok(text, m.start()):
                continue
            body = m.groups()[-1]
            for k in _RE_OBJ_KEY.findall(body):
                if k not in _BODY_KEY_STOP:
                    found.add(k)
            # 简写属性键 `{username, password}`(无 `:`) —— 现代 JS 常见, 旧实现整类漏掉
            for k in _RE_SHORTHAND_KEY.findall(body):
                if k not in _BODY_KEY_STOP:
                    found.add(k)
    return found


# ---------- 参数轻量污点(演进建议 R3 · 借鉴 JsOwl Taint) ----------
#   回答"这个参数的值从哪来": 上游接口响应 / 浏览器存储 / 路由参数 / 未知(函数入参)。
#   只做**一步**解析(内联表达式直接判; 标识符查一次 const/let/var 绑定), 控制开销;
#   纯静态、零发包。输出 out['param_taint'] = {endpoint: {param: {kind,symbol,hops,label}}},
#   由 report/params.py 汇入参数总表"值来源"列。
_TAINT_LABEL = {'upstream': '上游接口响应', 'storage': '浏览器存储',
                'route': '路由参数', 'unknown': '未知(函数入参)'}
_RE_TAINT_ASSIGN = _re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,240})')
# 响应成员形态: `res.data.x` / `response.data` / `.json()` 链…… (jowl 同款思路)
_RE_TAINT_RESP = _re.compile(
    r'\b(?:res|resp|response|result|ret|json|body|data)\.data\b|\.json\s*\(\s*\)')
_RE_TAINT_STORAGE = _re.compile(r'\b(?:localStorage|sessionStorage)\b')
# 路由参数形态: `$route.params.x` / `route.params` / `useParams()` / `.params`
_RE_TAINT_ROUTE = _re.compile(
    r'\$route\b|useParams|route\.params|\bparams\.[A-Za-z_$]')
# 调用点: 方法调用/取的**字符串路径字面量**(跟在请求词后, 宽度任取, 后窗再解析)
_RE_TAINT_CALLPATH = _re.compile(
    r"""['"`]([/A-Za-z0-9_\-./{}$:]{2,150})['"`]""")
# 参数容器键: params:{...} / data:{...} / body:{...}(允许嵌套花括号, 由配平提取处理)
_RE_TAINT_CONTAINER = _re.compile(r'\b(?:params|data|body)\s*:\s*\{')
# 参数对象的 键:值 对(值取到顶层逗号/右括号为止; 嵌套复杂值跳过 —— 轻量判定)
_RE_TAINT_KV = _re.compile(r'([A-Za-z_$][\w$]*)\s*:\s*([^,}]{1,120})')


def _taint_balanced_obj(s, open_pos):
    """从 s[open_pos]('{') 起取**配平**的对象文本(含首尾花括号); 失败返回 None。"""
    if open_pos < 0 or open_pos >= len(s) or s[open_pos] != '{':
        return None
    depth = 0
    for i in range(open_pos, min(len(s), open_pos + 600)):
        c = s[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return s[open_pos + 1:i]
    return None


def _taint_of_expr(expr, assigns, is_param_name=None, _depth=0):
    """对一个值表达式做一步污点分类。返回 (kind, symbol, hops) 或 None(常量/无法判定)。"""
    v = (expr or '').strip()
    if not v or _depth > 2:
        return None
    if _RE_TAINT_RESP.search(v):
        return ('upstream', v, 0)
    if _RE_TAINT_STORAGE.search(v):
        return ('storage', v, 0)
    if _RE_TAINT_ROUTE.search(v):
        return ('route', v, 0)
    # 成员表达式取**根标识符**做一跳解析: `uinfo.uid` → uinfo → sessionStorage.getItem(...)
    _mr = _re.match(r'([A-Za-z_$][\w$]*)\s*\.', v)
    if _mr:
        root = _mr.group(1)
        if is_param_name and is_param_name(root):
            return ('unknown', v, 0)      # 形参成员: 值由调用方决定
        bound = assigns.get(root)
        if bound:
            inner = _taint_of_expr(bound, assigns, None, _depth + 1)
            if inner:
                return (inner[0], v, inner[2] + 1)
    if _re.fullmatch(_IDENT, v):
        if is_param_name and is_param_name(v):
            return ('unknown', v, 0)          # 函数形参: 值由调用方决定
        bound = assigns.get(v)
        if bound:
            inner = _taint_of_expr(bound, assigns, None, _depth + 1)
            if inner:
                return (inner[0], inner[1], inner[2] + 1)
    return None


def _extract_param_taint(text, braces=None, max_sites=4000):
    """扫描 API 调用点参数对象, 标注参数值**来源**(upstream/storage/route/unknown)。

    覆盖形态: `params:{...}` / `data:{...}` / `body:{...}` 容器、写方法的第二实参对象
    (axios.post('/x',{a:1}))、ES6 简写属性({userId, page})。零发包、纯静态。
    """
    if not text:
        return {}
    from .js_lex import _strip_comments_safe
    t = _strip_comments_safe(text)
    # 标识符绑定表(同名取**首个**——保守: 多声明场景不臆造)
    assigns = {}
    for m in _RE_TAINT_ASSIGN.finditer(t):
        assigns.setdefault(m.group(1), m.group(2).strip())
    # 函数形参名集(复用既有作用域基建) —— 形参即动态值 → unknown
    param_names = set()
    try:
        param_names = set(_build_param_scopes(t, braces).keys())
    except Exception:
        param_names = set()

    def _scan_kv(container, per):
        # KEY: VALUE(含内联表达式)
        for km in _RE_TAINT_KV.finditer(container):
            k, v = km.group(1), km.group(2).strip()
            if k in _BODY_KEY_STOP or not v:
                continue
            tt = _taint_of_expr(v, assigns, lambda n: n in param_names)
            if tt:
                per.setdefault(k, {'kind': tt[0], 'symbol': tt[1][:80],
                                   'hops': tt[2], 'label': _TAINT_LABEL.get(tt[0], tt[0])})
        # 简写属性 {userId, page}: KEY 自身即值(标识符)
        for k in _RE_SHORTHAND_KEY.findall(container):
            if k in _BODY_KEY_STOP:
                continue
            if k in param_names:
                per.setdefault(k, {'kind': 'unknown', 'symbol': k, 'hops': 0,
                                   'label': _TAINT_LABEL['unknown']})
                continue
            bound = assigns.get(k)
            if bound:
                tt = _taint_of_expr(bound, assigns, None)
                if tt:
                    per.setdefault(k, {'kind': tt[0], 'symbol': tt[1][:80],
                                       'hops': tt[2] + 1,
                                       'label': _TAINT_LABEL.get(tt[0], tt[0])})

    out = {}
    n_sites = 0
    # 路径字面量匹配(仅用于窗口定界: 下一个 /路径 字面量即下一调用的边界)
    _next_path_lit = _re.compile(r"""['"`](/[A-Za-z0-9_\-./{}$:]{2,})['"`]""")
    for m in _RE_TAINT_CALLPATH.finditer(t):
        if n_sites >= max_sites:
            break
        raw = m.group(1)
        if not raw.startswith('/') and not (_is_api_path(raw) and '/' in raw):
            continue
        if not _is_plausible_api_path(raw):
            continue
        ep = normalize_extracted_path(raw) or raw.split('?')[0]
        # 窗口截止到**下一个 /路径字面量**之前 —— 防止把后续调用的参数对象算进来
        #   (实测: fetch('/api/me') 的 .then 之后紧跟 axios.get('/api/orders',{params:…}),
        #   不加边界会把 orders 的参数挂到 /api/me 上)。
        _nc = _next_path_lit.search(t, m.end())
        window = t[m.end():(_nc.start() if _nc else min(len(t), m.end() + 300))]
        n_sites += 1
        per = {}
        # ① params:/data:/body: 容器对象(嵌套)
        _has_container = False
        for pm in _RE_TAINT_CONTAINER.finditer(window):
            _has_container = True
            obj = _taint_balanced_obj(window, pm.end() - 1)
            if obj:
                _scan_kv(obj, per)
        # ② 写方法第二实参对象: `'/x', {a:1}` 直接形态(无 params/data/body 容器时)
        if not _has_container:
            sm = _re.match(r"\s*,\s*\{", window)
            if sm:
                obj = _taint_balanced_obj(window, window.index('{', sm.start()))
                if obj:
                    _scan_kv(obj, per)
        if per:
            out.setdefault(ep, {}).update(per)
    return out



def _extract_query_params_js(text):
    """从 JS 字符串字面量里提取 query 参数名(值可任意 —— 因为在字面量内)。

    与 `param_names_from_text` 互补: 后者要求"值为简单原语", 于是拼接式
    `"/api/wallet/transactions?page="+pg+"&size="+sz` 只能取到 `page`(`&size=` 落在**另一个**
    字面量里)。本函数: ① 含 `/api/` 的字面量取 `?` 之后全部 `name=`; ② **纯 query 续段**
    字面量(如 `"&size="`)按 `&name=` 取。②用 `_RE_QUERY_LIT` + `_QP_VAL_OK` 双重约束,
    避免把那类压缩代码(`&&t===null`、`?n=oe.ParamRegExp:…`)重新当参数名。
    """
    found = set()
    if not text:
        return found
    for m in re.finditer(r'["\'`]([^"\'`]*)["\'`]', text):
        s = m.group(1)
        if not s:
            continue
        if _is_api_path(s) and '?' in s:
            q = s.split('?', 1)[1]
            for k in re.findall(r'(?:^|&)([A-Za-z_][A-Za-z0-9_]*)=' , q):
                found.add(k)
        if _RE_QUERY_LIT.match(s):
            for mm in re.finditer(r'[?&]([A-Za-z_][A-Za-z0-9_]*)=([^&]*)', s):
                if all(c in _QP_VAL_OK for c in mm.group(2)):
                    found.add(mm.group(1))
    return found


def _path_param_names(paths):
    """从路径集合提取路径参数名(`{id}` / `:id` / `${id}` 归一后)。"""
    found = set()
    for p in paths:
        found |= set(re.findall(r'\{([A-Za-z_][\w]*)\}', p))
        found |= set(re.findall(r':([A-Za-z_][\w]*)', p))
    return found


def _link_params(text, path):
    """在调用点**所在语句**范围内提取关联参数名

    现在把窗口收敛到"当前语句"(以 ; } 换行为边界), 参数只归属于真正携带它的那个调用点。
    """
    from .js_lex import _stmt_span
    params = set()
    # 边界感知: `re.escape(path)` 直接 finditer 会把短路径匹配到更长路径**内部**
    #   (实测 `/Submit/Login` 命中 `/Submit/LoginWithCode` 的前缀 → 参数挂错接口/丢失)。
    #   要求匹配后不再紧跟路径字符(字母/数字/下划线/斜杠), 才算一次真正的"该路径出现"。
    _pat = re.compile(re.escape(path) + r'(?![A-Za-z0-9_/])')
    for m in _pat.finditer(text):
        seg_lo, seg_hi = _stmt_span(text, m.start(), m.end())
        ctx = text[seg_lo:seg_hi]
        # 走 param_names_from_text —— 与通道 2 同一判据, 否则压缩代码里的
        #   `&&x=` / 三元 `?x=` 会被当参数名(此处 ctx 是单条语句, 同样会中招)。
        params |= param_names_from_text(ctx)
        pm = re.search(r'params\s*:\s*\{([^}]{2,120})\}', ctx)
        if pm:
            params |= set(re.findall(r'(\w+)\s*:', pm.group(1)))
        # ③ POST 请求体参数: 同一调用点语句内的 data:{...} / .post(url,{...}) /
        #    JSON.stringify({...}) 对象键。此前仅全局提取(_extract_body_params),
        #    不挂到具体接口, 导致"按接口归类展示参数"时 POST 接口漏掉其请求体参数。
        #    这里收敛到调用点(仅归属真正携带它的那个调用点) —— 用户明确要求"参数按接口展示"。
        #    注意: _stmt_span 会在 `}` 处截断, 而请求体 `{...}` 的收尾 `}` 恰在窗口边缘之外,
        #    导致 _RE_BODY_CALL 因缺收尾 `}` 而无法匹配。故请求体类用"URL 之后 +N 字符"的
        #    扩展窗口(请求体必紧跟 URL 出现在同一 .post/.put/.patch 调用内), 既命中又不会越界到
        #    其它调用。
        _body_hi = m.end() + 400
        _semi = text.find(';', m.end())          # 语句边界: 不越过 `;`, 否则会把相邻调用的
        if _semi != -1 and _semi < _body_hi:     #   请求体(如紧随其后的另一个 $.ajax)误并进来
            _body_hi = _semi
        _body_ctx = text[max(0, m.start() - 40): _body_hi]
        for _bp in (_RE_BODY_CALL, _RE_DATA_OBJ, _RE_JSON_STR):
            for _bm in _bp.finditer(_body_ctx):
                _body = _bm.groups()[-1]
                for _k in _RE_OBJ_KEY.findall(_body):
                    if _k not in _BODY_KEY_STOP:
                        params.add(_k)
    return params


def _same_object_url(text, pos):
    """从 pos 起回溯其所在平衡 `{...}` 块, 返回块内出现的 API 路径(归一化、去 query)或 None。

    用途 = **请求对象同体关联**(level-3): 当 `params` / `query` / `URLSearchParams` 与
    `url` / `path` 同处一个 `{}`(即同一次调用)时, 把参数锚定到该接口 —— 纯证据驱动,
    不臆造归属。回溯逻辑: pos 为 `params:`/`query:`/`URLSearchParams(` 关键字起点,
    其左侧最近的 `{` 即所在请求对象的左边界(该关键字位于值对象之外、作为兄弟键),
    向右括号平衡匹配到右边界即整个请求对象, 块内找 url/path 键或其相对路径字面量。
    """
    lo = text.rfind('{', 0, max(0, pos))
    if lo == -1:
        return None
    depth = 0
    hi = -1
    _lim = min(len(text), lo + 4000)
    for i in range(lo, _lim):
        c = text[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                hi = i + 1
                break
    if hi == -1:
        hi = _lim
    block = text[lo:hi]
    # ① 优先 url:/path: 键(最明确的同体证据)
    for mm in re.finditer(r'(?:url|path)\s*:\s*["\']([^"\']+)["\']', block):
        _u = mm.group(1)
        if _u.startswith('/') and _is_api_path(_u):
            return (normalize_extracted_path(_u) or _u).split('?')[0]
    # ② 退一步: 块内相对路径字面量(以 / 开头且形态像 API 路径)
    for mm in re.finditer(r'["\'](/[^"\']{2,200})["\']', block):
        _u = mm.group(1)
        if _is_api_path(_u):
            return (normalize_extracted_path(_u) or _u).split('?')[0]
    return None


# 驼峰↔蛇形互转
def _camel_to_snake(name):
    """'userId' -> 'user_id'"""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def _snake_to_camel(name):
    """'user_id' -> 'userId'"""
    parts = name.split('_')
    return parts[0] + ''.join(p.capitalize() for p in parts[1:])


def infer_param_value_v45(name):
    """增强版参数值推断: 支持驼峰、蛇形互查"""
    # 直接命中
    if name in PARAM_SEMANTICS_V45:
        return PARAM_SEMANTICS_V45[name]
    # 蛇形→驼峰互查
    camel = _snake_to_camel(name)
    if camel in PARAM_SEMANTICS_V45:
        return PARAM_SEMANTICS_V45[camel]
    snake = _camel_to_snake(name)
    if snake in PARAM_SEMANTICS_V45:
        return PARAM_SEMANTICS_V45[snake]
    # 后缀推断
    low = name.lower()
    for suffix, val in (('id', '1'), ('time', '2024-01-01'), ('date', '2024-01-01'),
                        ('page', '1'), ('size', '20'), ('num', '1'), ('count', '1')):
        if low.endswith(suffix):
            return val
    return '1'


# ---------- RESTful展开优化  ----------
def expand_restful_v45(path, max_variants=2):
    """语义值选择: 根据参数名推断值, 每占位符≤2变体, 总变体≤3

    占位符识别改由 dicts 里的两条编译正则承担(RE_REST_PARAM / RE_PLACEHOLDER),
    不再内联 `re.findall(r'[:*]\\w+', path)` —— 那份内联写法与 RE_REST_PARAM 语义重叠,
    导致正则定义与使用各写一份、改一处漏一处。
    """
    # 主形态: `:id` / `*id`(归一化后的路径, 也是绝大多数来源)
    placeholders = RE_REST_PARAM.findall(path)
    if not placeholders:
        # 兼容未归一化的 `{id}` 形态(SpringBoot/FastAPI)
        placeholders = [f'{{{m}}}' for m in RE_PLACEHOLDER.findall(path)]
    if not placeholders:
        return [path]
    # 根据占位符名推断语义值
    def _placeholder_value(ph):
        name = ph.lstrip(':*')
        return infer_param_value_v45(name)
    # 第一变体: 语义值
    p1 = path
    for ph in placeholders:
        p1 = p1.replace(ph, _placeholder_value(ph), 1)
    variants = [p1]
    # 第二变体(仅第一个占位符): 通用测试值
    if len(placeholders) > 0 and max_variants >= 2:
        ph0 = placeholders[0]
        p2 = path.replace(ph0, 'test123', 1)
        # 其余占位符用语义值
        for ph in placeholders[1:]:
            p2 = p2.replace(ph, _placeholder_value(ph), 1)
        if p2 != p1:
            variants.append(p2)
    return variants[:3]  # 上限3个


# ---------- 通用调用点提取  ----------
# 注: `_host_of` 已下沉到 core/util.py。

def _same_origin(url, base):
    """url 与 base 是否同源(scheme + netloc 完全一致)。

    统一同源护栏 —— 此前"同源判定"在项目里被**内联重复**了三处, 且三处规则不一致:
      · _extract_js_refs 用 `startswith(('http://','https://','//','data:','blob:'))` 前缀判定
      · crawl_site / _extract_api_calls 用 `sp.netloc != b.netloc`
      · JS 入队处**根本没有判定** —— 于是前两处的过滤被这条分支整体绕过。
    抽成单一实现, 供所有"要不要发请求"的决策点共用。
    """
    try:
        sp, bp = urlsplit(url or ''), urlsplit(base or '')
    except Exception:
        return False
    return bool(sp.netloc) and sp.netloc == bp.netloc and sp.scheme == bp.scheme


def _is_plausible_api_path(p):
    """端点路径层面的合理性校验: 过滤开发库 JS 注释/标签片段等误抓噪声。

    真实端点路径(相对/绝对)不含: 空白(多行误抓)、HTML 标签(< >)、JS 注释开头(/* )。
    命中即丢弃, 避免污染 ``out['apis']`` / 报告 ``extracted_endpoints``。
    允许 query 串(``?a=1&b=2``)与常规路径字符; 模板占位符(``${...}``)由上游归一化处理。
    """
    if not p or not isinstance(p, str):
        return False
    if re.search(r'[\s<>]|/\*', p):
        return False
    return True


# P0-1 语义级字符串常量解析(模块作用域): 把 baseURL / 路由 path / 调用参数里的
#   "变量引用 + 字符串拼接/模板" 还原为真实字面量, 补"启发式 route-rebase"的盲区。
#   例如:
#     const API = '/api';
#     axios.create({ baseURL: API });             # 变量作 baseURL
#     function call(p){ return request(API + p); }  # 调用参数拼接变量
#     const ADMIN = API + '/admin';               # 变量 + 字面量拼接
#     fetch(`${API}/user/list`);                  # 模板串插值
#   仅做**模块作用域常量传播**(无函数参数/无运行时求值), 安全且高精度; 与既有
#   "上下文无关字面量扫描"互补: 后者只在字面量已带 /api 前缀时才采纳, 这里补
#   "前缀藏在变量里"的情形。所有解析结果仍需过 _is_api_path/_is_plausible_api_path 同口径门禁。

# const/let/var NAME = "lit" | 'lit'
_RE_CONST_LIT = re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[\x27\x22]([^\x27\x22]*)[\x27\x22]')
# const/let/var NAME = `tpl`  (可能含 ${VAR})
_RE_CONST_TPL = re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*`([^`]*)`')
# const/let/var NAME = A + B  (A/B 为字面量或已解析变量)
_RE_CONST_CONCAT = re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*'
    r'([A-Za-z_$][\w$]*|[\x27\x22][^\x27\x22]*[\x27\x22])\s*\+\s*'
    r'([A-Za-z_$][\w$]*|[\x27\x22][^\x27\x22]*[\x27\x22])')
# 调用/赋值处的拼接或模板表达式(供全局扫描):
#   VAR + 'lit'  |  'lit' + VAR  |  `...${VAR}...`
_RE_ENDPOINT_EXPR = re.compile(
    r'(?:[A-Za-z_$][\w$]*\s*\+\s*[\x27\x22]/[^\x27\x22]+[\x27\x22]'
    r'|[\x27\x22]/[^\x27\x22]+[\x27\x22]\s*\+\s*[A-Za-z_$][\w$]*'
    r'|`[^`]*\$\{[A-Za-z_$][\w$]*\}[^`]*`)')
# 模板/变量不可解析时的哨兵(字符串形态, 便于 substring 判定)
_UNRESOLVED = '\x00UNRESOLVED\x00'


def _unq(s):
    """去引号('a' -> a)。"""
    if len(s) >= 2 and s[0] in ('"', "'") and s[-1] == s[0]:
        return s[1:-1]
    return s


def _resolve_string_constants(text):
    """模块作用域字符串常量表: var -> 解析后的字面量。

    支持: 字面量 / 模板串(含 ${VAR}) / 二元 + 拼接(字面量或已解析变量)。
    定点迭代解析交叉引用(如 A='/api'; B=A+'/admin')。不含函数参数/运行时求值。
    无任何绑定命中时返回空 dict(调用方据此跳过额外扫描)。
    """
    if not text:
        return {}
    _SENT = object()
    raw = {}
    for m in _RE_CONST_LIT.finditer(text):
        raw[m.group(1)] = ('lit', m.group(2))
    for m in _RE_CONST_TPL.finditer(text):
        raw[m.group(1)] = ('tpl', m.group(2))
    for m in _RE_CONST_CONCAT.finditer(text):
        raw[m.group(1)] = ('bin', m.group(2), m.group(3))
    resolved = {}
    changed = True
    while changed:
        changed = False
        for name, b in list(raw.items()):
            if name in resolved:
                continue
            if b[0] == 'lit':
                resolved[name] = b[1]
                changed = True
            elif b[0] == 'tpl':
                out = re.sub(r'\$\{([A-Za-z_$][\w$]*)\}',
                             lambda mm: resolved.get(mm.group(1), _UNRESOLVED),
                             b[1])
                if _UNRESOLVED not in out:
                    resolved[name] = out
                    changed = True
            elif b[0] == 'bin':
                a, c = b[1], b[2]
                ra = a if a[0] in ('"', "'") else resolved.get(a, _SENT)
                rc = c if c[0] in ('"', "'") else resolved.get(c, _SENT)
                if ra is not _SENT and rc is not _SENT:
                    resolved[name] = _unq(ra) + _unq(rc)
                    changed = True
    return resolved


def _resolve_endpoint_arg(expr, consts):
    """把一个表达式解析为字符串字面量(可完全解析才返回), 否则 None。

    expr: 'lit' | `tpl` | VAR | A + B(单 +, 操作数为字面量/变量)。
    """
    expr = (expr or '').strip()
    if not expr:
        return None
    if expr[0] in ('"', "'") and expr[-1] == expr[0] and len(expr) >= 2:
        return expr[1:-1]
    if expr[0] == '`' and expr.endswith('`'):
        out = re.sub(r'\$\{([A-Za-z_$][\w$]*)\}',
                     lambda mm: consts.get(mm.group(1), _UNRESOLVED), expr[1:-1])
        return None if _UNRESOLVED in out else out
    if re.fullmatch(r'[A-Za-z_$][\w$]*', expr):
        return consts.get(expr)
    if '+' in expr:
        a, _, b = expr.partition('+')
        a, b = a.strip(), b.strip()
        if a and b:
            ra = a if a[0] in ('"', "'") else consts.get(a)
            rb = b if b[0] in ('"', "'") else consts.get(b)
            if ra is not None and rb is not None:
                return _unq(ra) + _unq(rb)
    return None


def _extract_api_calls(text, base=None):
    """按 API_CALL_PATTERNS 提取**全部**调用点 → {归一化路径: HTTP方法}

    旧实现只有两条读路径入口:
      · RE_API   —— 强制要求 `/api/` 前缀
      · RE_AXIOS —— 强制要求 `对象.方法('...')` 链式写法
    fetch / $.ajax / xhr.open 的 GET 分支则被困在写方法提取器里, 且 xhr.open 还额外
    要求方法属于 POST/PUT/DELETE/PATCH —— 于是 12 条真实接口丢 5 条, 全是普通 GET。

    本函数把方法判定与路径提取解耦:
      路径 → normalize_extracted_path() 统一成相对路径(绝对URL取path、模板占位符→:ph、
              静态资源/静态目录/单段无关键词路径剔除)
      方法 → 优先取调用点显式声明(xhr.open('POST')/$.post/axios({method})); 无声明则 GET

    冲突合并规则: 同一路径若既有 GET 又有写方法判定, 保留写方法(写方法信息量更大,
    且写路径会在 probe 阶段被排除出 GET 探活, 不会造成误探)。

    **跨域绝对 URL 不归入己方 apis**。此前 `normalize_extracted_path` 会把
      `https://api.stripe.com/v1/charges` 取 path 成 `/v1/charges` 并入己方接口, 与外部
      同路径的己方接口无法区分(且 host 信息永久丢失)。跨域调用改由 `_extract_external_api_calls`
      单独收集完整绝对 URL 到 `out['external_apis']`; 同源绝对 URL(`https://本站/api/x`)仍按
      原行为归一为相对路径入己方 apis。
    """
    target_host = _host_of(base) if base else ''
    calls = {}
    for _pname, pat, path_grp, method_grp in iter_api_call_patterns():
        for m in pat.finditer(text):
            try:
                raw = m.group(path_grp)
            except IndexError:  # pragma: no cover - 模式表与正则组数不匹配时的兜底
                continue
            # 跨域绝对 URL 跳过 —— 交给 external 收集器, 不污染己方 apis
            if target_host and raw.startswith(('http://', 'https://')):
                if _host_of(raw) and _host_of(raw) != target_host:
                    continue
            path = normalize_extracted_path(raw)
            if not path:
                continue
            # 噪声过滤: 与 `_is_plausible_api_path` **同一判定**(此前内联第二份,
            #   改一处漏一处 —— 审计 S8)。开发版库 JS 内的注释片段/`</script>` 残片
            #   会被 API_CALL 正则误抓, 此类候选一律丢弃。
            if not _is_plausible_api_path(path):
                continue
            if method_grp is None:
                method = 'GET'
            elif isinstance(method_grp, str):
                # 模式表里写死的常量方法(如"函数实参 + 数据对象"形态 → POST)
                method = method_grp
                # 护栏: 该启发式在**读式链式调用**下会误判 —— `axios.get('/x', {params:{…}})`
                #   的第二个对象是 config(非请求体), 却被判 POST → 端点归入 write_apis 而**不探活**。
                #   若紧邻匹配之前的调用链是读方法, 改判 GET(只读、可探活)。
                if method == 'POST' and _PRECEDING_READ_CHAIN.search(
                        text[max(0, m.start() - 40):m.start()]):
                    method = 'GET'
            else:
                try:
                    method = (m.group(method_grp) or '').upper()
                except Exception:  # pragma: no cover
                    method = 'GET'
                if method == 'GETJSON':
                    method = 'GET'
                if method not in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'):
                    method = 'GET'
            prev = calls.get(path)
            if prev is None or (prev == 'GET' and method != 'GET'):
                calls[path] = method
    # **上下文无关**的端点提取（通用，不写死、不依赖任何内部标记）：
    #   上面按"调用点模式"提取是**上下文耦合**的（只认 fetch/axios/xhr/对象值…），任何出现在
    #   **未预料上下文**里的路径字面量都会整条漏掉 —— 真实案例 `/api/rsa_gen` 由片段数组 +
    #   base64 片段拼接而成，是**裸字面量**，上述模式全不命中。
    #   这里改为：扫描**所有**字符串字面量，凡通过既有形态判定 `_is_api_path`（`/api`/`/rest`/
    #   `/v1`… 前缀或服务端脚本后缀）者一律采纳。于是无论混淆以**哪种形态**重建端点
    #   （碎片拼接 / 拼接折叠 / 赋值 / 数组元素 / 对象值 / 调用参数 …），都能提取。
    #   在**剥注释后**的文本上做 —— 注释里的示例路径(如 `// 例 "/api/v2/user"`)不算端点, 降噪。
    #   (实测: 剥注释不丢任何真实端点; 注释内容本就不该产出端点。)
    from .js_lex import _strip_comments_safe
    _clean = _strip_comments_safe(text)
    for _m in re.finditer(r'["\']([^"\'\n]{1,300})["\']', _clean):
        _lit = _m.group(1)
        if _is_api_path(_lit) and _is_plausible_api_path(_lit):
            _p = normalize_extracted_path(_lit)
            if _p:
                calls.setdefault(_p, 'GET')
    # P0-1 语义恢复: 全局扫描 "变量/模板 + 字面量" 拼接, 还原被变量前缀藏起来的端点。
    #   例: request(API + '/admin/user/list') / fetch(`${API}/user`) / const X = API + '/x'
    #   仅当解析结果通过 _is_api_path + _is_plausible_api_path 才采纳(与既有字面量扫描同口径),
    #   故不会引入超出原政策的候选。
    _consts = _resolve_string_constants(_clean)
    if _consts:
        for _m in _RE_ENDPOINT_EXPR.finditer(_clean):
            _resolved = _resolve_endpoint_arg(_m.group(0), _consts)
            if not _resolved:
                continue
            if _is_api_path(_resolved) and _is_plausible_api_path(_resolved):
                _p = normalize_extracted_path(_resolved)
                if _p:
                    calls.setdefault(_p, 'GET')
    return calls


def _extract_external_api_calls(text, base):
    """收集**跨域**绝对 API 调用(完整 URL, 保留 host) → set()

    与 `_extract_api_calls` 同源的 API_CALL_PATTERNS, 但**保留完整绝对 URL** 并过滤 host:
      仅收 host != 目标 host 的绝对 http(s) URL(排除协议相对 `//`、data:/blob:、同源)。
    这些不是本站的探活目标(跨域不发包, 与合规定位一致), 但作为"外部/第三方接口"发现项
    单独呈现, 能揭示前端把数据发往的第三方服务(支付/分析/云服务), 这正是同类工具
    (de-secretor / katana) 的共识能力, 此前 facet 完全缺失。
    """
    target_host = _host_of(base) if base else ''
    if not target_host:
        return set()
    ext = set()
    for _pname, pat, path_grp, _ in iter_api_call_patterns():
        for m in pat.finditer(text):
            try:
                raw = m.group(path_grp)
            except IndexError:  # pragma: no cover
                continue
            if not raw.startswith(('http://', 'https://')):
                continue
            host = _host_of(raw)
            if host and host != target_host:
                # 归一化: 保留完整绝对 URL(不去 host), 但剔除明显非接口的静态资源
                norm = normalize_extracted_path(raw)
                if norm is None:
                    continue
                ext.add(raw.rstrip('/') if '?' not in raw else raw)
    return ext


# 整合: 双字面量拼接还原(_extract_concat_apis) 已**整体
#   并入** `_extract_struct_apis`(其 tokenize-and-walk 对 >=2 操作数链全覆盖, 且额外
#   支持变量传播 / 数组 join / 单标识符调用参数, 并保留同样的双斜杠归一与 normalize 护栏)。
#   单一事实来源, 避免两条拼接通道漂移。下方不再保留独立实现。

# ---------- 写方法提取增强  ----------
# 重构: 原先这个函数同时承担"读路径提取"和"写路径提取"两份职责,
#   导致 fetch/xhr.open 的 GET 分支只能靠"写方法提取器"侥幸捞回来。
#   现在读路径全部改由 _extract_api_calls() 负责, 本函数**只**保留那些需要额外上下文
#   才能判定为写操作的语法形态(URLSearchParams 请求体 / xhr.send(JSON.stringify) /
#   模板串紧邻写动词 / 方法常量传播)。返回值仍为 {路径: 写方法}。
def _extract_write_text_v45(text, base):
    """写方法提取(仅写路径): 覆盖 URLSearchParams / send / 常量传播 / 模板串上下文"""
    apis = {}
    # 1. axios 对象式写法: axios({url, method:'post'}) / axios({method, url})
    #    (链式写法 axios.post('/x') 已由 API_CALL_PATTERNS 覆盖, 此处不再重复)
    for m in re.finditer(r'axios\s*\(\s*\{([^}]{2,300})\}\s*\)', text):
        body = m.group(1)
        mu = re.search(r'url\s*:\s*[`"\']([^`"\']+)[`"\']', body)
        mm = re.search(r'method\s*:\s*[`"\'](\w+)[`"\']', body)
        if not mu:
            continue
        u = normalize_extracted_path(mu.group(1))
        if not u:
            continue
        # 无 method → axios **默认 GET**(非写); 仅显式写方法才登记。
        #   (旧版无 method 时默认 POST —— 会把 axios({url}) 这类读端点误记为写操作)
        method = mm.group(1).upper() if mm else ''
        if method in WRITE_METHODS:
            apis[u] = method
    # 2. fetch(url, {method: 'POST', body: ...}) —— 仅收写方法, GET 交回调用点提取器。
    #    首个参数既可能是字面量 URL, 也可能是**拼接表达式**: fetch(API_BASE + '/api/orders', {method:'POST'})
    #    (baseURL 存于 const 再 fetch(BASE+path, {method}) 是极常见写法; 旧实现只认字面量 URL 会漏掉写方法)。
    #    做法: 取首个参数, 从中抽出"路径字面量"(形如 '/api/x' 或 'https://h/api/x', 含反引号模板串),
    #          拼接里的变量名本身不含路径, 抽不到则跳过 —— 不靠任何硬编码站点名, 纯形态驱动(通用)。
    for m in re.finditer(r'fetch\s*\(\s*([^,]{1,200})\s*,\s*\{', text):
        arg = m.group(1)
        um = re.search(r'[`"\']((?:/[^`"\']*|https?://[^`"\']+))[`"\']', arg)
        if not um:
            continue
        u = normalize_extracted_path(um.group(1))
        if not u:
            continue
        ctx = text[m.end():m.end() + 200]
        mm = re.search(r'method\s*:\s*["\'](\w+)["\']', ctx)
        method = mm.group(1).upper() if mm else ''
        if method in WRITE_METHODS:
            apis[u] = method
    # 3. xhr.open('POST', url) —— 仅收写方法
    for m in re.finditer(r'\.open\s*\(\s*["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']', text):
        method = m.group(1).upper()
        u = normalize_extracted_path(m.group(2))
        if method in WRITE_METHODS and u:
            apis[u] = method
    # 4. jQuery $.ajax({url, type:'POST'}) / $.post / $.put —— 两种键序都要覆盖
    for _ajax_pat, _url_first in (
        (r'\$\.ajax\s*\(\s*\{[^}]{0,400}?url\s*:\s*["\']([^"\']+)["\'][^}]{0,400}?(?:type|method)\s*:\s*["\'](\w+)["\']', True),
        (r'\$\.ajax\s*\(\s*\{[^}]{0,400}?(?:type|method)\s*:\s*["\'](\w+)["\'][^}]{0,400}?url\s*:\s*["\']([^"\']+)["\']', False),
    ):
        for m in re.finditer(_ajax_pat, text, re.S):
            if _url_first:
                u, method = normalize_extracted_path(m.group(1)), m.group(2).upper()
            else:
                method, u = m.group(1).upper(), normalize_extracted_path(m.group(2))
            if method in WRITE_METHODS and u:
                apis[u] = method
    for m in re.finditer(r'\$\.(?:post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', text):
        method = m.group(0).split('.')[1].split('(')[0].upper()
        u = normalize_extracted_path(m.group(1))
        if u:
            apis[u] = method
    # 5. URLSearchParams 请求体 —— 归属**同一语句**内最近的前置 URL, 默认按 POST 处理。
    #    必须限定语句边界(`;`/`}`/换行): 否则会把**相邻无关语句**里的 URL(如前一条 GET
    #    fetch)误当本请求的 URL → 读端点被标成写方法(方法编造 + 误升 P0)。
    #    (跨语句的 `xhr.open(...); xhr.send(...)` 形态由项3/项2 覆盖, 不依赖本项。)
    from .js_lex import _stmt_span
    for m in re.finditer(r'URLSearchParams\s*\(\s*\{([^}]{2,200})\}\s*\)', text):
        seg_lo, _seg_hi = _stmt_span(text, m.start(), m.end())
        ctx = text[seg_lo:m.start()]
        url_match = re.search(r'["\']([^"\']+/[^"\']*)["\']\s*[,)]', ctx)
        if url_match:
            u = normalize_extracted_path(url_match.group(1))
            if u:
                apis[u] = apis.get(u, 'POST')  # URLSearchParams 通常用于 POST
    # 5b. URLSearchParams('a=1&b=2') 字符串形态 —— RE_URL_SEARCH_QS 此前从未被调用
    for m in RE_URL_SEARCH_QS.finditer(text):
        seg_lo, _seg_hi = _stmt_span(text, m.start(), m.end())
        ctx = text[seg_lo:m.start()]
        url_match = re.search(r'["\']([^"\']+/[^"\']*)["\']\s*[,)]', ctx)
        if url_match:
            u = normalize_extracted_path(url_match.group(1))
            if u:
                apis.setdefault(u, 'POST')
    # 6. xhr.send(JSON.stringify({...})) —— 反查最近的 .open(method, url)
    for m in re.finditer(r'\.send\s*\(\s*JSON\.stringify\s*\(\s*\{([^}]{2,200})\}\s*\)\s*\)', text):
        ctx_start = max(0, m.start() - 300)
        ctx = text[ctx_start:m.start()]
        open_match = re.search(r'\.open\s*\(\s*["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']', ctx)
        if open_match:
            method, u = open_match.group(1).upper(), normalize_extracted_path(open_match.group(2))
            if u:
                apis[u] = method
    # 7. 模板字符串 URL —— 仅当前文出现写动词时才计入
    for m in RE_TEMPLATE_URL.finditer(text):
        raw = m.group(0).strip('\'"`')
        u = normalize_extracted_path(raw)
        if not u:
            continue
        ctx_start = max(0, m.start() - 100)
        low = text[ctx_start:m.start()].lower()
        # 写动词须**非字母夹持**匹配 —— 旧版用裸子串, `input`/`output`/`compute` 里的 "put"
        #   会被误当 PUT → 读端点被归入 write_apis 而**不探活**(漏探)。按优先级取首个命中。
        for _v in ('post', 'put', 'delete', 'patch'):
            if re.search(r'(?:^|[^a-z])' + _v + r'(?:[^a-z]|$)', low):
                apis[u] = _v.upper()
                break
    # 8. 常量传播: const m = 'POST'; fetch(url, {method: m})
    const_map = {}
    for cm in re.finditer(r'(?:const|let|var)\s+(\w+)\s*=\s*["\'](\w+)["\']', text):
        const_map[cm.group(1)] = cm.group(2)
    for m in re.finditer(r'fetch\s*\(\s*["\']([^"\']+)["\']\s*,\s*\{[^}]*method\s*:\s*(\w+)', text):
        u, var = normalize_extracted_path(m.group(1)), m.group(2)
        if u and var in const_map:
            method = const_map[var].upper()
            if method in WRITE_METHODS:
                apis[u] = method
    return apis


def _build_param_scopes(text, braces=None):
    """扫出"函数形参 → 函数体区间", 用于**形参遮蔽**判定。

    返回 {param_name: [(body_start, body_end), ...]}(按 body_start 升序)。

    为什么需要:
      压缩产物里形参名全是单字母(e/n/t/o/id), 与文件其它位置的 `var` 极易撞名。
      例:
          var id = "home";
          c = { a: function(t, id){ return "…".concat(id,"/detail/") } }
      形参 `id` 在函数体内是**动态值**(实参由调用方决定), 必须遮蔽外层的
      `var id="home"` —— 否则会产出 `/api/v5/items/home/detail/`:
      **形态完全合理、但语义错误**的路径。这类错误探活必然落空, 且无法从输出上察觉。

      注: 此前 `_is_path_fragment()` 只能拦"明显不像路径"的值(中文/句子);
      "撞名后恰好解析成另一个路径形态字符串"必须靠**作用域**才能拦住。

    实现(整体 O(n), 可安全用于 500KB 级压缩产物):
      ① 正则找函数头 —— `function` 声明/表达式、括号箭头、单标识符箭头;
      ② 单次扫描建"代码态括号表"(跳过字符串/模板串/注释/正则字面量);
      ③ 用**按深度索引的闭括号表 + 二分**为每个函数头定位配对的 `}`
         (避免逐函数向后扫描导致的 O(n²))。
    """
    from .js_lex import _scan_braces
    if not text or ('function' not in text and '=>' not in text):
        return {}
    headers = []
    for m in _re.finditer(
            r'\bfunction\b\s*[A-Za-z_$][\w$]*\s*\(([^()]*)\)'
            r'|\bfunction\b\s*\(([^()]*)\)'
            r'|\(([^()]*)\)\s*=>'
            r'|([A-Za-z_$][\w$]*)\s*=>', text):
        raw = next((g for g in m.groups() if g is not None), '')
        names = frozenset(x.strip() for x in raw.split(',')
                          if _re.fullmatch(_IDENT, x.strip()))
        if names:
            headers.append((m.end(), names))
    if not headers:
        return {}

    # ② 括号表 —— 优先**复用调用方顺手产出的那份**(注释剥离时一并建好),
    #    避免对同一份文本做第二次全文逐字符扫描(3.5MB 语料上实测差约 2s)。
    if braces is not None:
        opens = braces.get('opens') or []
        depth_at_open = braces.get('depth_at_open') or {}
        close_by_depth = braces.get('close_by_depth') or {}
    else:
        opens, depth_at_open, close_by_depth = _scan_braces(text)
    if not opens:
        return {}

    # ③ 二分定位配对闭括号
    scopes = {}
    for hpos, names in headers:
        oi = _bisect_left(opens, hpos)
        if oi >= len(opens):
            break
        open_pos = opens[oi]
        # 闭括号表语义(见 js_lex._strip_js_comments): `{` 时 depth 先增后记录、
        #   `}` 时先记录后减 → **配对 `}` 就在 close_by_depth[open 的 depth]**。
        #   旧实现取 `depth_at_open[open_pos] - 1`: 顶层函数体(深度1→查key 0)恒缺失
        #   → 直接 continue, 形参遮蔽**从不生效**; 嵌套函数则取到**外层**函数体的闭括号,
        #   区间过宽 → 过度遮蔽(区间内 base 常量解析全部作废)。审计 R3 实施期实证发现。
        closes = close_by_depth.get(depth_at_open[open_pos])
        if not closes:
            continue
        ci = _bisect_right(closes, open_pos)
        if ci >= len(closes):
            continue
        end_pos = closes[ci]
        for nm in names:
            scopes.setdefault(nm, []).append((open_pos, end_pos))
    return scopes


def _prepare_shadow(scopes):
    """把形参区间表预处理成"可二分 + 可早停"的形态。"""
    prepared = {}
    for nm, lst in scopes.items():
        lst.sort()
        starts = [s for s, _ in lst]
        ends = [e for _, e in lst]
        mx, cur = [], -1
        for e in ends:
            cur = max(cur, e)
            mx.append(cur)
        prepared[nm] = (starts, ends, mx)
    return prepared


def _is_param_shadowed(prepared, name, pos):
    """name 在位置 pos 处是否被某个**函数形参**遮蔽。

    从"最后一个 start <= pos"向前扫, 用前缀最大 end 早停 —— 实践中只看 1~2 个区间。
    """
    it = prepared.get(name)
    if not it:
        return False
    starts, ends, mx = it
    i = _bisect_right(starts, pos) - 1
    while i >= 0:
        if mx[i] <= pos:          # 更早的区间都不可能覆盖 pos
            return False
        if ends[i] > pos:
            return True
        i -= 1
    return False


class _VarScope:
    """位置感知的局部常量表 —— 按"最近的前置声明"解析, 而非全局后写覆盖。

    压缩产物里短标识符(o/r/c/e/n/...)会在**不同作用域被反复复用**。用单个全局
    字典会"后写覆盖": 文件后段任意一处 `r=<别的值>` 都会把先声明的 base 常量污染掉。
    实测目标里 `r="/api/v2"` 被后文 `r="store/ABC..."` 覆盖, 导致整个 /api/v2
    接口家族(15 条)静默丢失 —— 且没有任何报错。

    语义: 先 `at(pos)` 设定当前解析位置, 再 `get(name)` 返回**位置严格早于 pos、
    且离 pos 最近**的那次声明的值; 找不到返回 None(不臆造路径)。
    此外还要过一道**形参遮蔽** —— 见 `_build_param_scopes`。
    """

    __slots__ = ('_decls', '_pos', '_cache', '_shadow')

    def __init__(self, shadow=None):
        self._decls = []          # [(pos, name, value)] —— 按 pos 升序追加
        self._pos = 0
        self._cache = {}
        self._shadow = shadow or {}   # 形参作用域表(见 _prepare_shadow)

    def at(self, pos):
        """把解析位置移到 pos(每次解析前调用)"""
        self._pos = pos
        self._cache = {}
        return self

    def add(self, pos, name, value):
        self._decls.append((pos, name, value))

    def get(self, name, default=None):
        if name in self._cache:
            return self._cache[name]
        val = default
        # **形参遮蔽优先** —— 若该名字在当前位置的**某个外层函数**里是形参,
        #   它在函数体内就是动态值(实参由调用方决定), 不能用文件里同名的
        #   `var` 声明解析。否则会产出"形态合理、语义错误"的路径。
        if self._shadow and _is_param_shadowed(self._shadow, name, self._pos):
            self._cache[name] = default
            return default
        # _decls 按 pos 升序 → 逆序扫描首个命中即为"最近的前置声明"
        for p, n, v in reversed(self._decls):
            if p < self._pos and n == name:
                val = v
                break
        self._cache[name] = val
        return val

    def __contains__(self, name):
        return self.get(name) is not None

    def __getitem__(self, name):
        return self.get(name)

    def known_values(self):
        """已登记的**可解析**常量值集合 —— 用于识别"这条链其实就是某个 base 常量"。

        例: `o="/api/".concat("v1")` 会被 `.concat()` 扫描通道当成一条链,
        解析出 `/api/v1` —— 但它是**前缀**, 不是接口。调用方用本方法把这些值排除。
        不可解析的声明(value=None)只是用于遮蔽, 不参与本集合。
        """
        return {v for _p, _n, v in self._decls if v is not None}


def _resolve_expr(expr, vars, _depth=0):
    """尝试把表达式解析为字符串字面量; 无法完全解析(含未知变量/非字面量)返回 None

    支持: 字符串字面量 / 已知变量(映射到字面量) / 顶层 + 拼接链(各操作数均可解析)。
    不支持(返回 None, 调用方跳过): 含未知变量、函数调用、模板插值 ${...} 等。
    递归深度上限12 — 恶意/病态嵌套表达式(如 a+(a+(a+...)) 或超长拼接链)
    不再触发 RecursionError 崩掉整个扫描(真实目标已复现), 超限按不可解析处理。
    """
    from .js_lex import _split_top_level_plus, _unquote_lit
    if _depth > 12:            # 深度护栏: 病态嵌套直接放弃
        return None
    expr = expr.strip()
    if not expr:
        return None
    if _re.fullmatch(_LIT, expr):           # 单个完整字符串字面量
        return _unquote_lit(expr)
    if _re.fullmatch(_IDENT, expr):
        return vars.get(expr)          # 未知变量 → None(不臆造)
    if '+' in expr:
        vals = [_resolve_expr(p, vars, _depth + 1) for p in _split_top_level_plus(expr)]
        if vals and all(v is not None for v in vals):
            return ''.join(vals)
        return None
    return None


def _split_top_level_commas(expr):
    """在顶层逗号处切分实参列表(不切字符串/括号内部的逗号)"""
    parts, cur, in_str, q, depth, i = [], '', False, '', 0, 0
    while i < len(expr):
        c = expr[i]
        if in_str:
            cur += c
            if c == '\\' and i + 1 < len(expr):
                cur += expr[i + 1]
                i += 2
                continue
            if c == q:
                in_str = False
            i += 1
            continue
        if c in '"\'':
            in_str, q = True, c
            cur += c
            i += 1
            continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ',' and depth == 0:
            parts.append(cur.strip())
            cur = ''
            i += 1
            continue
        cur += c
        i += 1
    if cur.strip():
        parts.append(cur.strip())
    return parts


def _split_concat_chain(expr):
    """把 `BASE.concat(a,b).concat(c)` 切为 (base_expr, [[args1],[args2],...])

    仅在**顶层**(不在字符串/括号内)识别 `.concat(`; 实参用**括号配平**切分
    (而非 `[^()]*` 正则 —— 后者无法处理实参里再含括号/嵌套 concat 的情形)。
    非 `.concat()` 形态返回 (None, None)。
    """
    s = expr.strip()
    if not s or '.concat' not in s:
        return None, None
    # 定位第一个"顶层"的 `.concat(`
    first, depth, in_str, q, i = None, 0, False, '', 0
    while i < len(s):
        c = s[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == q:
                in_str = False
            i += 1
            continue
        if c in '"\'':
            in_str, q = True, c
            i += 1
            continue
        if c in '([{':
            depth += 1
            i += 1
            continue
        if c in ')]}':
            depth -= 1
            i += 1
            continue
        if depth == 0 and s.startswith('.concat', i):
            j = i + 7
            while j < len(s) and s[j] in ' \t':
                j += 1
            if j < len(s) and s[j] == '(':
                first = i
                break
        i += 1
    if first is None:
        return None, None
    base = s[:first].strip()
    # 依次吃掉后续 `.concat(...)` 调用
    arg_lists, pos = [], first
    while pos < len(s):
        if not s.startswith('.concat', pos):
            break
        j = pos + 7
        while j < len(s) and s[j] in ' \t':
            j += 1
        if j >= len(s) or s[j] != '(':
            break
        k, d, in_str2, q2 = j + 1, 1, False, ''
        while k < len(s):
            c = s[k]
            if in_str2:
                if c == '\\':
                    k += 2
                    continue
                if c == q2:
                    in_str2 = False
                k += 1
                continue
            if c in '"\'':
                in_str2, q2 = True, c
                k += 1
                continue
            if c == '(':
                d += 1
            elif c == ')':
                d -= 1
                if d == 0:
                    break
            k += 1
        if d != 0:            # 括号未配平 → 表达式被截断, 放弃(宁缺勿错)
            return None, None
        arg_lists.append(_split_top_level_commas(s[j + 1:k]))
        pos = k + 1
        while pos < len(s) and s[pos] in ' \t':
            pos += 1
    # 尾部还可能跟着 `+ "字面量"` / `+ 标识符` —— Terser 会产出**混合形态**:
    #     `"/study/".concat(d.id)+"/score"`
    #   旧实现到 `.concat(...)` 就收尾, 尾段 `/score` 被**静默截断**
    #   (产出 `/study/{id}`, 看着合理但少了最后一段)。这里继续吃下去。
    while pos < len(s):
        _tm = _re.match(r'\s*\+\s*(' + _LIT + r'|' + _IDENT + r')', s[pos:])
        if not _tm:
            break
        arg_lists.append([_tm.group(1)])
        pos += _tm.end()
    if not arg_lists:
        return None, None
    return base, arg_lists


def _is_navigation_target(t, start):
    """拼接链起点前是否紧邻**前端路由跳转**调用。

    只回看 48 字符 —— 足够覆盖 `this.$router.push(` / `location.href =` 这类前缀,
    又不会误伤"前面很远的地方碰巧出现过 router"的情况。
    """
    if start <= 0:
        return False
    return bool(_NAV_CALL_RE.search(t[max(0, start - 48):start]))


def _is_path_fragment(val):
    """值是否可用作路径片段 —— **黑名单式**判定。

    为什么需要它: 压缩产物里函数形参名全是单字母(e/n/t/o), 与文件里其它位置的
    `var` 极易撞名; 一旦撞上, 形参就会被错误解析成别处的字符串字面量, 产出
    **看起来像路径、实际是垃圾**的结果。实测产出过:

        /api/v2/practice/detail/确定刷新此页吗？/set_as_unsure/

    (真值应是 `/api/v2/practice/detail/:e/set_as_unsure/` —— `e` 是 `though(t,e)`
     的形参, 却被解析成了 `beforeUnloadHandler` 里的 `var e="确定刷新此页吗？"`。)

    为什么用黑名单而非白名单: 路径里可能出现的字符太多(`? & = # : { } % + @` 等),
    白名单极易误伤。只拦**明确不是路径**的形态:
      · 含空白 / 引号 / 反斜杠 / `<` `>`  → 句子、HTML 片段、转义残留
      · 含非 ASCII 字符                    → 中文文案、全角标点
    正常路径与占位符(`:param` / `{param}`)零误伤。空串放行(`"".concat(...)` 的惯用基)。

    > 说明: 本函数只拦"明显不像路径"的值(空白/引号/非 ASCII 等)。"撞名后恰好解析成
    >   另一个**路径形态**字符串"的情况由**形参遮蔽**兜住 —— 见 `_build_param_scopes`
    >   与 `_VarScope.get`: 函数形参在函数体内被识别为**动态值**, 不解析外层同名 `var`。
    >   (已实现; 覆盖 `function` 声明/表达式与括号/单标识符箭头三类函数头。)
    """
    if val == '':
        return True
    if any(c in val for c in ' \t\r\n"\''):
        return False
    if '\\' in val or '<' in val or '>' in val:
        return False
    return all(ord(c) < 128 for c in val)


def _join_path_fragments(parts):
    """路径片段拼接: 相邻片段缺斜杠时补 `/`, 并归一双斜杠。

    修复 `var ctx="/xinzuo"; ctx + "login"` 被拼成 `/xinzuologin`(漏斜杠)的 bug。
    所有片段已被 `_is_path_fragment` 过滤为路径形态, 补斜杠是安全的路径语义,
    不会污染非路径串(非路径串在入口处已被 `_is_path_fragment` 拒绝)。
    """
    s = parts[0] if parts else ''
    for p in parts[1:]:
        if s and p and not s.endswith('/') and not p.startswith('/'):
            s = s + '/' + p
        else:
            s = s + p
    return s.replace('//', '/')


def _dynamic_placeholder(expr):
    """把动态操作数转成 `{name}` 占位(仅接受属性访问/裸标识符); 否则 None

    只对"变量/属性引用"造占位 —— 函数调用、三元、下标等一律放弃,
    避免把 `foo()` 之类的非路径片段写进结果。
    """
    e = expr.strip()
    m = _re.fullmatch(r'(?:' + _IDENT + r'\.)*(' + _IDENT + r')', e)
    if m:
        return '{' + m.group(1) + '}'
    return None


def _resolve_concat_expr(expr, vars, _depth=0):
    """解析 `.concat()` 链为路径; 动态段以 `{param}` 占位。

    返回 (path_or_None, is_concat_form)。is_concat_form=False 表示该表达式
    根本不是 `.concat()` 形态, 调用方应回落到其他通道; 为 True 而 path 为 None
    表示"确是 concat 形态但无法完整还原"(如 base 本身是动态值)。
    """
    if _depth > 8:                     # 深度护栏, 与 _resolve_expr 同策略
        return None, True
    base, arg_lists = _split_concat_chain(expr)
    if base is None:
        return None, False
    base_val = _resolve_expr(base, vars)
    if base_val is None:
        base_val, _ = _resolve_concat_expr(base, vars, _depth + 1)
    if base_val is None or not _is_path_fragment(base_val):
        return None, True
    parts = [base_val]
    for args in arg_lists:
        for a in args:
            v = _resolve_expr(a, vars)
            if v is None:
                v, _ = _resolve_concat_expr(a, vars, _depth + 1)
            # 解析出来的值若**不像路径片段**(含空白/引号/非 ASCII 等), 说明这是
            #   "形参撞名外层变量"导致的错误解析 —— 不能把它拼进路径, 退化为动态段占位。
            #   见 `_is_path_fragment` 的说明与实测样例。
            if v is not None and not _is_path_fragment(v):
                v = None
            if v is None:
                v = _dynamic_placeholder(a)
            if v is None:              # 动态且无法占位 → 整条链放弃
                return None, True
            parts.append(v)
    return _join_path_fragments(parts), True


def _concat_chain_start(s, pos):
    """从 `.concat(` 的位置 pos 向前回退到 base 表达式起点; 失败返回 None

    支持 base 为 字面量 / 标识符路径 / 括号组(含函数调用) 三种形态。
    """
    i = pos
    while i > 0 and s[i - 1] in ' \t':
        i -= 1
    if i == 0:
        return None
    if s[i - 1] == ')':                # base 是括号组(如 getBase())
        d, k = 1, i - 1
        while k > 0 and d > 0:
            k -= 1
            if s[k] == ')':
                d += 1
            elif s[k] == '(':
                d -= 1
        if d != 0:
            return None
        i = k
        j = i                        # 连函数名一起吞掉
        while j > 0 and (s[j - 1].isalnum() or s[j - 1] in '_$.'):
            j -= 1
        if j < i:
            i = j
        return i
    if s[i - 1] in '"\'':
        q, k = s[i - 1], i - 1
        while k > 0:
            k -= 1
            if s[k] == '\\':
                k -= 1
                continue
            if s[k] == q:
                return k
        return None
    k = i
    while k > 0 and (s[k - 1].isalnum() or s[k - 1] in '_$.'):
        k -= 1
    return k if k < i else None


def _is_relative_literal_path(p):
    """**裸根相对路径字面量**的形态门禁(用于路由表/请求字面量提取) —— **不依赖 `/api` 前缀**。

    与 `_is_dynamic_base_candidate` 的分工: 后者要求"基址 + 拼接"派生; 本函数直接判**字面量本身**
    是否像一条路径(根相对 / 段字符合法 / 非静态 / 非资源目录 / 非路由模板)。
    这是"动态获取而非硬编码"的落地: 不看前缀名单, 只看"这个字面量是否长得像路径"。
    """
    if not p or not p.startswith('/') or p.startswith('//'):
        return False
    path = p.split('?')[0].split('#')[0]
    if not _DYN_BASE_PATH.match(path):
        return False
    if is_static_or_malformed_path(path):
        return False
    low = path.lower()
    if any(low.startswith(pre) for pre in _NON_API_PREFIX):
        return False
    if _is_route_template(path):
        return False
    return True


_LABEL_CJK_RE = re.compile(r'[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]')
# 「像**展示名**」的形态门禁（供非中文标签使用）：多词 + 不含代码字符。
#   实测（weikayun 单包）：85 条 `name:"…",path:"/x"` 里 84 条是中文，非中文仅 1 条
#   （`/dashboard/covestro/tank` → `Smart Tank Dashboard`）—— **零噪声**，故可安全放开。
_LABEL_CODEISH_RE = re.compile(r'[_/\\{}<>()\[\]$]')


def _looks_like_display_name(s):
    """非中文标签的形态门禁：**多词**且不含代码字符（`view` / `weikaConfigView` 一律拒）。"""
    s = (s or '').strip()
    if not s or len(s) > 60 or _LABEL_CODEISH_RE.search(s):
        return False
    return len(s.split()) >= 2
_URL_LIT_RE = re.compile(r'url\s*:\s*["\'](/[^"\']{1,200})["\']')
_PATH_LIT_RE = re.compile(r'path\s*:\s*["\'](/[^"\']{1,200})["\']')
_TITLE_LIT_RE = re.compile(r'title\s*:\s*["\']([^"\']{1,60})["\']')
_NAME_LIT_RE = re.compile(r'name\s*:\s*["\']([^"\']{1,60})["\']')


def _extract_adjacent_labels(text, window=160):
    """从**路径字面量旁的中文标签**提取「目标自述的业务名」—— 最强证据类。

    为什么重要：目标**自己写的名字**胜过任何从英文路径段猜出来的域标签。
    真实形态（weikayun 实测）：

        {name:"微卡回报信息查询", buildQuery:()=>({cfg:encodeConfig(
            {url:"/desktop/feedbackSupportingTool", title:"微卡回报信息查询"}), ...})}

    覆盖两种写法：① `url:"/x"` 之后紧跟 `title:"…"`；② `name:"…"` 之后紧跟 `path:"/x"`。
    收两类标签：**含中文**（业务名的强特征），或**多词展示名**（英文站点，见
    `_looks_like_display_name`）；`name:"view"` 这类单词标识符一律拒。
    """
    out = {}
    for m in _URL_LIT_RE.finditer(text):
        _t = _TITLE_LIT_RE.search(text[m.end():m.end() + window])
        if _t and _is_business_label(_t.group(1)):
            out.setdefault(m.group(1), _t.group(1).strip())
    for m in _PATH_LIT_RE.finditer(text):
        _cands = list(_NAME_LIT_RE.finditer(text[max(0, m.start() - window):m.start()]))
        if not _cands:
            continue
        _lab = _cands[-1].group(1)      # 取**最近**的一个（窗口内最后一个），避免张冠李戴
        if _is_business_label(_lab):
            out.setdefault(m.group(1), _lab.strip())
    return out


def _is_business_label(s):
    """标签是否**像业务名**：含中文，或形如多词展示名（不含代码字符）。"""
    s = s or ''
    return bool(_LABEL_CJK_RE.search(s)) or _looks_like_display_name(s)


# RPC / 远程调用约定（**形态驱动 · 无站点私有名**）
# 背景（实测 weikayun）：部分 SPA **不用 URL 路径调接口**，而用 RPC/remoting 约定：
#     const remotingApis = { AssociatedChargeItemsController: {
#         readAssociateChargeItemSimpleVos: create2ParamsRequest(["AssociatedChargeItemsController",
#                                                                 "readAssociateChargeItemSimpleVos"]), … } }
#     function create2ParamsRequest([e,r]){ return (a,t,o)=>invoke(e, r, [a,t], o) }
#   → 接口身份 = `Service.method`（不是 URL）；**参数是位置数组**，`createNParamsRequest` 的 N
#     就是参数个数；**参数名不在前端**（RPC 的固有性质）。
# 现有 5 条参数通道全部锚定 URL/axios 语义 → 对这类约定 0 命中（实测该 chunk 1428 个 RPC
#   接口一个都没提取到）。本段按**形态**识别，不写死 `remotingApis` / `createNParamsRequest`
#   这类站点私有命名。

def _top_split(s):
    """按**顶层**逗号切分（括号/方括号/花括号内不切）—— `[a,t],o` → `['[a,t]','o']`。"""
    out, buf, d = [], [], 0
    for ch in s:
        if ch in '([{':
            d += 1
        elif ch in ')]}':
            d -= 1
        if ch == ',' and d == 0:
            out.append(''.join(buf))
            buf = []
        else:
            buf.append(ch)
    out.append(''.join(buf))
    return [x.strip() for x in out if x.strip()]


def _fn_body(text, start, limit=800):
    """取 `function f(){…}` / `const f = …` 的**体**（花括号配对；无花括号则以 `;` 收尾）。"""
    i = text.find('{', start)
    if i == -1 or i - start > 200:
        j = text.find(';', start)
        return text[start: j if 0 < j - start < 400 else start + 400]
    d = 0
    for k in range(i, min(len(text), i + limit)):
        c = text[k]
        if c == '{':
            d += 1
        elif c == '}':
            d -= 1
            if d == 0:
                return text[start:k + 1]
    return text[start:i + limit]


def _factory_arity(body):
    """从工厂函数体推**参数个数**：`(…)=>invoke(e,r,[a,t],o)` → 2。

    形态判据（不依赖任何函数名）：取体内**最后一个调用**的实参，按**顶层**逗号切开后
      · 实参里有**数组字面量** `[...]` → 元素个数即参数个数；
      · 实参里有 `void 0`/`undefined` → 0 个（`undefined` 表示无数据）；
      · 末位出现**布尔字面量**（`!0`/`true`）且实参数 ≥5 → `'form'`（表单体，整对象提交）。
    返回 int / `'form'` / None（无法判定，如变参 `(...a)`）。
    """
    if not body:
        return None
    calls = re.findall(r'[A-Za-z_$][\w$]*\s*\(([^()]*)\)', body)
    if not calls:
        return None
    args = _top_split(calls[-1])
    arr = next((a for a in args if a.startswith('[') and a.endswith(']')), None)
    if arr is not None:
        return len(_top_split(arr[1:-1]))
    _bool = any(a in ('!0', '!1', 'true', 'false') for a in args[3:])
    if any(a in ('void 0', 'undefined') for a in args):
        return 'form' if (len(args) >= 5 and _bool) else 0
    return 'form' if _bool else None


def _extract_rpc_apis(text, min_group=2):
    """提取 RPC 接口表 → `{'Service.method': {'service','method','arity'}}`。

    形态（**不写死任何名字**）：某个**函数调用**的实参是 `["Ident","ident"]` 两段字符串数组。
    真伪判据（三条，实测调校）：
      ① 被调方是**裸函数名** —— 前面不能是 `.`（排除 `obj.addXxx(["a","b"],…)` 这类**属性注册器**：
         实测 ag-grid 的 `addManagedPropertyListeners(["domLayout","ensureDomOrder"],…)` 曾被误判成接口）；
      ② 该函数必须是**可解析的工厂**，且**体内 `return` 出一个函数**（闭包 = "造调用器"语义）；
      ③ 同一 `Ident`（首元素）在 ≥`min_group` 个条目里重复出现 → 它是"服务/控制器"，而非偶发数组。
    实测：真信号 chunk → **1425 个方法 / 102 个服务**；ag-grid 与入口包 → **0**（噪声清零）。
    """
    out = {}
    if not text or '[' not in text:
        return out
    pairs = []
    for m in re.finditer(
            r'([A-Za-z_$][\w$]*)\s*\(\s*\[\s*["\']([A-Za-z_][\w]*?)["\']\s*,\s*'
            r'["\']([A-Za-z_][\w]*?)["\']\s*\]', text):
        if m.start() > 0 and text[m.start() - 1] in '.$':   # ① 属性调用 → 不是工厂
            continue
        fac, svc, meth = m.group(1), m.group(2), m.group(3)
        if svc == meth:                      # 同名 → 多半不是 `服务.方法`
            continue
        pairs.append((fac, svc, meth))
    groups = {}
    for _f, svc, meth in pairs:
        groups.setdefault(svc, set()).add(meth)
    keep = {svc for svc, ms in groups.items() if len(ms) >= min_group}
    if not keep:
        return out
    _arities = {}
    _bodies = {}
    for _f, svc, meth in pairs:
        if svc not in keep:
            continue
        if _f not in _bodies:
            _m = re.search(r'(?:function\s+%s\s*\(|(?:const|let|var)\s+%s\s*=)'
                           % (re.escape(_f), re.escape(_f)), text)
            _bodies[_f] = _fn_body(text, _m.start()) if _m else None
            _arities[_f] = _factory_arity(_bodies[_f]) if _bodies[_f] else None
        _body = _bodies.get(_f)
        # ② 工厂体必须 `return` 一个函数（闭包）；否则是普通工具/注册函数
        if not _body or not re.search(
                r'return\s*(?:[\w$]+\s*)?(?:\([^)]*\)\s*=>|[\w$]*\s*=>|function\b)', _body):
            continue
        out[f'{svc}.{meth}'] = {'service': svc, 'method': meth, 'arity': _arities[_f]}
    return out


# 字段/字典对象的**通用元数据键**（不是站点私有名：`name`/`field`/`key`/`code` 是跨项目通用写法）
_FIELD_NAME_KEYS = ('name', 'field', 'fieldname', 'key', 'code')


# 字段名必须是**裸 ASCII 标识符**（无连字符/空格/中文/点）—— 这条同时挡掉三类噪声（实测）：
#   · 菜单/报表**显示名**（`AXA账单报表`）· i18n **键**（`AI-enabled-job-create-recognition`）
#   · 库/UI 枚举（`Backspace`/`Delete` 多为键位表，不满足"≥2 个字符串元数据"故另被挡）
_FIELD_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]{1,60}$')


def _extract_field_dict(text, min_rows=5, need_meta=2):
    """同构对象集合 → **字段字典** `{字段名: {其它键: 值}}`。

    形态（不写死键名组合）：**同一组键**的对象字面量重复 ≥`min_rows` 次、组内含一个
    **名称类键**（`_FIELD_NAME_KEYS`）、名称值是**裸 ASCII 标识符**、且对象有 ≥`need_meta`
    个字符串元数据 → 判定为"字段定义表"。
    实测：真信号 chunk → **317 条**；入口包（菜单/i18n）→ **0**；ag-grid → 1（收紧前 1223 条噪声）。
    这是**系统级字段词表**（"传什么"的候选），**不等于**某接口的参数 —— 报告须如此标注。
    """
    out = {}
    if not text or '{' not in text:
        return out
    groups = {}
    for m in re.finditer(r'\{([^{}]{8,300})\}', text):
        body = m.group(1)
        keys = tuple(sorted(set(re.findall(r'([A-Za-z_$][\w$]*)\s*:', body))))
        if not keys or not any(k.lower() in _FIELD_NAME_KEYS for k in keys):
            continue
        groups.setdefault(keys, []).append(
            dict(re.findall(r'([A-Za-z_$][\w$]*)\s*:\s*["\']([^"\']{1,60})["\']', body)))
    for keys, rows in groups.items():
        if len(rows) < min_rows:
            continue
        _nk = next((k for k in keys if k.lower() in _FIELD_NAME_KEYS), None)
        if not _nk:
            continue
        for r in rows:
            fname = (r.get(_nk) or '').strip()
            if not _FIELD_NAME_RE.match(fname):
                continue
            meta = {k: v for k, v in r.items() if k != _nk}
            if len(meta) < need_meta:
                continue
            out.setdefault(fname, meta)
    return out


def _extract_route_table_literals(text):
    """从**前端路由/菜单表**提取相对路径字面量(`path:"/x/y"`) → 归 `routes`(前端路由)。

    这类路径写在路由/菜单配置对象里(与调用点解耦), 现有调用点 / 拼接 / API map 通道**都漏**;
    实测某 Vite SPA 入口 bundle 有 100+ 条 `path:"/..."`, 仅 10 条被提取。
    **纯形态**判定(不依赖 `/api` 前缀), 经 `is_static_or_malformed_path` / `_is_route_template` 降噪。
    """
    out = set()
    if not text or 'path' not in text:
        return out
    for m in re.finditer(r'''\bpath\s*:\s*["'](/[^"'\s]{1,200})["']''', text):
        p = m.group(1)
        if _is_relative_literal_path(p):
            out.add(p)
    return out


def _extract_api_map_strings(text):
    """提取集中式 API map 的静态端点值(对象值形态 + 变量声明形态, 见上方模块说明)。

    覆盖的两种形态(都是"中心化接口声明表", 与调用点解耦, 故现有调用点/拼接通道都漏):
      · 对象值 `key:"/path"` —— Vue/Nuxt 的 `api/index.js` 导出对象(常见);
      · 变量声明 `const a="/x",b="/y",c="/z"` —— 多声明符语句里的路径常量(压缩产物常见)。

    判定: 键(变量名)非保留键, 值经 `normalize_extracted_path` 过滤(含 `_is_route_template`
    闸门, 自动排除 `/list/:a-:b-...` 等前端路由模板)。是否接纳:
      · 对象值形态: 同一文件内 ≥`_API_MAP_CLUSTER` 条即视为 API map 模块(生产构建键被
        uglify 成单字母, 不能靠 camelCase 判别, 用集群信号兜底); 仅 1-2 条时也接纳"键是
        camelCase 方法名"或"值是服务端脚本后缀"的条目(兼容未压缩构建)。
      · 变量声明形态: 单条 `const/var/let` 语句内 ≥2 条路径声明即视为 API map。
    """
    cands = []  # (key, np)
    # 1) 对象值形态
    obj_cands = []
    for m in _API_MAP_KEY_RE.finditer(text):
        key, val = m.group(1), m.group(2)
        if key.lower() in _API_MAP_RESERVED:
            continue
        np = normalize_extracted_path(val)
        if not np:
            continue
        obj_cands.append((key, np))
    is_obj_map = len(obj_cands) >= _API_MAP_CLUSTER
    for key, np in obj_cands:
        if is_obj_map or _API_MAP_CAMEL_RE.search(key) or _API_MAP_SRV_EXT.search(np):
            cands.append((key, np))
    # 2) 变量声明形态(单条语句内 ≥2 条路径声明即集群)
    for stmt in _API_MAP_VAR_DECL_RE.finditer(text):
        items = _API_MAP_VAR_ITEM_RE.findall(stmt.group(0))
        if len(items) < 2:
            continue
        for key, val in items:
            if key.lower() in _API_MAP_RESERVED:
                continue
            np = normalize_extracted_path(val)
            if np:
                cands.append((key, np))
    return {np for _, np in cands}


def _extract_struct_apis(text, base_consts=None, routes_out=None, external=None):
    """纯 Python 结构化(类 AST-lite)提取通道 —— 正则通道的补充

    覆盖正则(仅双字面量拼接)仍漏掉的结构性写法:
      · 多字面量拼接链      "a" + "b" + "c"
      · 局部变量字符串传播  const BASE="/api"; ... BASE + "/users"  → /api/users
      · 数组字面量 join     ['/api','v1','users'].join('/')          → /api/v1/users
      · 单标识符作调用参数  const BASE="/api"; fetch(BASE)            → /api
      · `.concat()` 链      "".concat(B,"/auth/").concat(t.w,"/login/") → /api/v1/auth/{w}/login/
                            (Terser 压缩把 `a + b` 改写成 `"".concat(a,b)`, 上述 `+` 通道
                             对它完全失效; 统一 service 模块里这是**主流形态**)
    仅当**整个表达式可完全解析为字面量**(或映射到字面量路径的变量)时才收, 否则跳过——
    不臆造路径、不把变量名当路径。结果经 `normalize_extracted_path` 过滤(剔除静态资源/非路径)。

    实现采用 tokenize-and-walk: 先 `_OPERAND_RE` 取出全部字面量/标识符 token, 再手动判定
    token 间是否仅以空白+加号+空白连接来成链; 数组 join 用 `].join(` 回溯 `[`。彻底规避
    "重复组内含交替"引发的回溯退化(见本文件 注释)。

    参数:
      base_consts —— 可选 set; 若传入, 会被填入本文件里识别到的**基址常量值**
        (如 `var o="/api/v3"` 的 `/api/v3`)。调用方用它把"恰好等于基址前缀"的路径
        从 apis 中剔除 —— 这类值也会被 RE_API 之类的**字面量通道**捞进 apis,
        而它们只是前缀, 不是可探活端点。
      routes_out —— 可选 set; 若传入, 会被填入识别到的**前端路由跳转目标**
        (`$router.push("/pay/confirm?...")` 之类)。这类路径与真实接口形态一致,
        只能靠**调用语境**区分, 故从 apis 中分离出去、交由调用方归入 routes。
    """
    from .js_lex import _strip_js_comments, has_http_method_element
    # 注释剥离与括号表**一次扫描产出**(见 `_strip_js_comments` 的 `_braces` 参数) ——
    #   二者都是全文逐字符扫描, 分开做要扫两遍。
    _braces = {}
    t = _strip_js_comments(text, _braces)
    out = set()
    # 1) 变量 -> 可解析字面量(只收 RHS 能完全解析为字面量的赋值)
    #    含 `.concat()` 形态(如 `var o="/api/".concat("v1")`) —— 否则这类 base 常量
    #    永远进不了 vars, 后续所有引用它的链都还原不出前缀。
    #    **多声明符语句**(`var a="x", b="y", c={...}`)必须逐个 declarator 解析 ——
    #    旧实现用 `[^;]+;` 抓 RHS, 会把整条语句(含后续 declarator 与对象字面量)当成
    #    一个 RHS, 导致除第一个以外的声明**全部丢失**(实测目标因此丢掉整个 /api/v2 家族)。
    #    且必须按**声明位置**解析(见 _VarScope), 否则后文同名变量会覆盖前文的 base 常量。
    #    还要叠加**形参遮蔽**(见 _build_param_scopes): 函数形参在函数体内是动态值,
    #    不能被文件里同名的 `var` 声明解析。
    vars = _VarScope(_prepare_shadow(_build_param_scopes(t, _braces)))
    # 跨文件符号注入: 把「内联脚本 / 同源 JS」聚合到的变量→值(external)以 pos=-1 登记,
    #   使其在本文件任意位置可见(实现 `ctx` 定义在 HTML、拼接在 JS 的跨文件解析)。
    #   保守: 只作「已知常量值」补充, 不覆盖本文件更近的声明(就近声明优先, 见 _VarScope.get)。
    if external:
        for _n, _v in external.items():
            if _v is not None:
                vars.add(-1, _n, _v)
    for dm in _re.finditer(r'\b(?:const|let|var)\s+', t):
        segs, seg_start, k, depth, in_str, q = [], dm.end(), dm.end(), 0, False, ''
        while k < len(t):
            c = t[k]
            if in_str:
                if c == '\\':
                    k += 2
                    continue
                if c == q:
                    in_str = False
                k += 1
                continue
            if c in '"\'':
                in_str, q = True, c
                k += 1
                continue
            if c in '([{':
                depth += 1
            elif c in ')]}':
                if depth == 0:
                    break                      # 语句终止(如 for(...) 的括号)
                depth -= 1
            elif depth == 0 and c in ',;':
                segs.append((seg_start, t[seg_start:k]))
                seg_start = k + 1
                if c == ';':
                    break
            k += 1
        if seg_start < k:
            segs.append((seg_start, t[seg_start:k]))
        for _spos, seg in segs:
            sm = _re.match(r'\s*(' + _IDENT + r')\s*=\s*(.+)$', seg, _re.S)
            if sm:
                name, expr = sm.group(1), sm.group(2).strip()
                vars.at(_spos)
                val = _resolve_expr(expr, vars)
                if val is None:
                    val, _is_concat = _resolve_concat_expr(expr, vars)
                if val is not None and '{' in val:
                    val = None           # 带占位的 base 不写入(避免污染传播)
            else:
                # 无 `=` 的声明(如 `var x;`)同样要登记 —— 见下方说明。
                nm2 = _re.match(r'\s*(' + _IDENT + r')\b', seg)
                if not nm2:
                    continue
                name, val = nm2.group(1), None
            # **无论能否解析都要登记**。只登记"可解析"的声明会让 `get()` 越过
            #   这条声明**向前回退**到更早的同名声明 —— 而那是**另一个作用域**的变量。
            #   实测: 文件后段有 `var o=n(141)`(模块 require, 不可解析), 于是
            #   `n.n(o)` 里的模块变量 `o` 被解析成了 service 模块的 base 常量
            #   `/api/v1`, 凭空多出一条"接口"。
            #   登记为 None 后, 该声明会正确遮蔽更早的同名声明。
            vars.add(_spos, name, val)
    # 2) tokenize-and-walk: 成链(>=2 个操作数, 仅以 + 连接)
    toks = list(_OPERAND_RE.finditer(t))
    n = len(toks)
    i = 0
    while i < n:
        chain = [toks[i]]
        j = i
        while j + 1 < n:
            between = t[toks[j].end():toks[j + 1].start()]
            if _re.fullmatch(r'\s*\+\s*', between):
                chain.append(toks[j + 1])
                j += 1
            else:
                break
        if len(chain) >= 2:
            vars.at(chain[0].start())        # 按链首位置解析(位置感知, 防同名污染)
            parts = [_resolve_expr(tok.group(1), vars) for tok in chain]
            # 任一段解析出"不像路径片段"的值 → 整条链放弃(宁缺勿错)。
            #   与 `.concat()` 通道同一守卫: 形参撞名外层变量时会解析出中文文案/
            #   英文句子, 拼进路径只会产出看似合理实则错误的接口。
            if all(p is not None and _is_path_fragment(p) for p in parts):
                val = _join_path_fragments(parts)  # 路径片段拼接(补缺斜杠 · 双斜杠归一)
                np = normalize_extracted_path(val)
                if np:
                    # 紧邻**前端路由跳转**调用的链 → 归入 routes, 不当接口
                    if routes_out is not None and _is_navigation_target(t, chain[0].start()):
                        routes_out.add(np)
                    else:
                        out.add(np)
        i = j + 1
    # 2b) 单标识符作调用参数(fetch(BASE))经变量传播还原
    for tok in toks:
        if not _re.fullmatch(_IDENT, tok.group(1)):
            continue
        vars.at(tok.start())
        if tok.group(1) not in vars:
            continue
        prev = t[tok.start() - 1] if tok.start() > 0 else ''
        if prev != '(':
            continue
        # **排除"路径构建函数"的实参** —— `concat(o,"/auth/")` 里的 `o` 是**基址前缀**,
        #   不是端点; 但 `prev == '('` 这一条判定分不清 `concat(o` 与 `fetch(o)`。
        #   实测后果: `var o="/api/".concat("v1")` 会把 `o` 单独登记成一条 `/api/v1`
        #   接口(看着像接口, 探活必然落空)。
        _pre = t[max(0, tok.start() - 16):tok.start()]
        if _re.search(r'(?:^|[^\w$])(?:concat|join)\s*\(\s*$', _pre):
            continue
        # 若该标识符紧接着又是 + 操作数(如 axios.get(B + "/me")), 其成链已由 2) 处理,
        # 不再单独还原裸变量, 避免冗余(且可能非端点的)前缀路径。
        nxt = t[tok.end():].lstrip()
        if nxt.startswith('+'):
            continue
        val = vars[tok.group(1)]
        # 跳过**绝对 URL**(`://`) —— 它们是跨域链接(如 `c="https://www.medsci.cn/message/list.do"`)
        #   或 XML 命名空间(`http://www.w3.org/1999/xlink`), 其路径段泄漏进同域 apis 纯属误报;
        #   绝对 URL 本应由 external/url 通道登记到 external_apis, 此处不掺和。
        if '://' in val:
            continue
        if (val.startswith('/') or '://' in val) and _is_path_fragment(val):
            np = normalize_extracted_path(val)
            if np:
                # 同 2)/2c): 紧邻前端路由跳转的 → routes
                if routes_out is not None and _is_navigation_target(t, tok.start()):
                    routes_out.add(np)
                else:
                    out.add(np)
    # 2c) `.concat()` 链还原 —— 收益最大的一条通道。
    #   Terser/uglify 压缩会把 `a + "/x/" + b` 改写成 `"".concat(a,"/x/").concat(b)`,
    #   使上面 2) 的 `+` 成链判定完全失效。真实 SPA 的统一 service 模块
    #   (api/index.js 导出的上百个函数) 几乎全是这个形态, 不单独还原则接口主链
    #   整体为 0。实参用括号配平切分; 动态段以 `{param}` 占位。
    _seen_concat = set()
    for cm in _re.finditer(r'\.concat\s*\(', t):
        start = _concat_chain_start(t, cm.start())
        if start is None or start in _seen_concat:
            continue
        _seen_concat.add(start)
        vars.at(start)
        val, is_concat = _resolve_concat_expr(t[start:start + 2000], vars)
        if not is_concat or not val:
            continue
        # 解析结果**恰好等于某个已登记的 base 常量**(如 `o="/api/".concat("v1")`
        #   解析出 `/api/v1`)→ 它是前缀, 不是接口, 不进 apis。
        #   实测这一条会多报出一个 `/api/v1`, 看着像接口但探活必然落空。
        if val in vars.known_values():
            continue
        np = normalize_extracted_path(val.replace('//', '/'))   # 双斜杠归一(护栏)
        if np:
            # 紧邻**前端路由跳转**调用的链 → 归入 routes, 不当接口。
            #   实测 `this.$router.push("/pay/confirm?good-ids=0-".concat(t.id))`
            #   在 12 个 chunk 里各产出一条假接口。
            if routes_out is not None and _is_navigation_target(t, start):
                routes_out.add(np)
            else:
                out.add(np)
    # 3) 数组字面量 join: 定位 ].join(...) 回溯匹配 [
    for jm in _re.finditer(r'\]\.join\(\s*(' + _LIT + r'|' + _IDENT + r')\s*\)', t):
        vars.at(jm.start())
        sep = _resolve_expr(jm.group(1), vars)
        if sep is None:
            sep = '/'
        depth, k, arr_start = 1, jm.start() - 1, None
        while k >= 0:
            ch = t[k]
            if ch == ']':
                depth += 1
            elif ch == '[':
                depth -= 1
                if depth == 0:
                    arr_start = k
                    break
            k -= 1
        if arr_start is None:
            continue
        arr_content = t[arr_start + 1: jm.start()]
        elems = [_resolve_expr(m.group(1), vars)
                 for m in _OPERAND_RE.finditer(arr_content)
                 if _re.fullmatch(_LIT, m.group(1))]
        elems = [e for e in elems if e is not None]
        # 元素含**裸 HTTP 方法** → join 会产出"路径 + 方法"垃圾(如 `['/api/orders','POST']`
        #   → `/api/ordersPOST`), 该垃圾会经上下文无关提取污染 extracted_endpoints。
        #   判据与 `deobf` 的碎片数组拼接**同源**(js_lex.has_http_method_element)。
        if elems and not has_http_method_element(elems):
            joined = sep.join(elems).replace('//', '/')  # 双斜杠归一(护栏)
            np = normalize_extracted_path(joined)
            if np:
                out.add(np)
    # 4) 导出本文件识别到的**基址常量值** —— 调用方据此把"恰好等于基址前缀"的路径
    #    从 apis 中剔除。必要性: 这类值还会被 RE_API 等**字面量通道**捞进 apis
    #    (实测 `var o="/api/v3"` 里的字面量会被 RE_API 命中), 只在本函数内过滤不够。
    if base_consts is not None:
        base_consts |= vars.known_values()
    return out


def _static_analysis_signals(ctx, text, src, base, out, enabled):
    """deep_analyze **静态信号段**(2026-10-12 结构拆分抽取):

    构建产物 chunk / Module Federation / RE_CHUNK·RE_LAZY 字面量引用 / 混淆检测 /
    加密签名逻辑。只写 `out` 与 `ctx.findings`, 与主流程无局部变量耦合。
    """
    from .html_extract import _extract_bundler_chunks, _extract_federation_remotes
    _b_chunks, _b_mode = _extract_bundler_chunks(text)
    if _b_chunks:
        # **跨域 chunk 与同源 chunk 必须分区**。旧实现一律塞进 js_refs, 报告里与
        #   同源 chunk 混在一起, 使用者看不出哪些会被抓、哪些只是登记。
        #   实测目标里 `https://g.alicdn.com/...` 这类绝对 URL 会经此通道进来,
        #   与 `/_nuxt/xxx.js` 同列 —— 而二者的处置方式(抓取 / 不抓取)完全不同。
        _ref_base = src if (isinstance(src, str)
                            and src.startswith(('http://', 'https://'))) else base
        _ext_chunks, _same_chunks = set(), set()
        for _c in _b_chunks:
            if _c.startswith(('http://', 'https://', '//')):
                (_same_chunks if _same_origin(urljoin(_ref_base, _c), base)
                 else _ext_chunks).add(_c)
            else:
                _same_chunks.add(_c)          # 相对路径 → 同源
        out['js_refs'] |= _same_chunks
        if _ext_chunks:
            out.setdefault('external_js', set()).update(_ext_chunks)
        _msg = f'{len(_b_chunks)} 个 chunk 候选'
        if _ext_chunks:
            _hosts = ', '.join(sorted({_host_of(c) for c in _ext_chunks if _host_of(c)}))[:80]
            _msg += (f' (同源 {len(_same_chunks)} 个将抓取 / 跨域 {len(_ext_chunks)} 个'
                     f'仅登记不抓取 · {_hosts})')
        _fnd_loc(ctx, 'INFO', f'构建产物 chunk({_b_mode or "runtime"})', src, _msg, text)
    # Module Federation 远程入口(可能跨域) —— 只登记, 不自动抓取
    _fed = _extract_federation_remotes(text)
    if _fed:
        _fnd_loc(ctx, 'MED', 'Module Federation 远程入口', src, ', '.join(sorted(_fed))[:140], text, sorted(_fed))

    if 'RE_CHUNK' in enabled or 'RE_LAZY' in enabled:
        # 直接引用模块级导入的两个正则 —— **不得**用 `globals().get(pat_name)` 字符串间接:
        #   旧写法下两个名字从未 import → 恒 None → 通道静默失效, 而 fingerprint 里
        #   100+ 个栈的 'RE_CHUNK': 1 开关全在给死机制发信号(全库审计 H2)。
        #   (顺带: 直接引用也让静态检查能看见真实使用, 不再误删 import。)
        for pat_name, pat in (('RE_CHUNK', RE_CHUNK), ('RE_LAZY', RE_LAZY)):
            if pat_name in enabled and pat:
                for m in pat.finditer(text):
                    # 归入 js_refs 而非 apis: 这是"要抓的 JS 文件", 不是接口
                    out['js_refs'].add(m.group(1))

    # 混淆检测
    # 改调 dicts.obfuscation_score() —— 此前这里内联了同一段统计逻辑,
    #   而 dicts 里的 is_obfuscated() 反而全项目无人调用(死代码)。现在共用一份实现。
    # **触发条件改为 is_obfuscated()** —— 裸计数 `>= 3` 会把
    #   "仅压缩"的产物(axios/vue 等库天然含 btoa/decodeURIComponent/\x 转义)误报成
    #   "疑似混淆"; 实测某 SPA 的 axios 压缩源码命中 5/8 却毫无混淆特征。
    obf_score = obfuscation_score(text)
    if is_obfuscated(text):
        ctx.add_finding('MED', 'JS疑似混淆', src,
                        f'命中 {obf_score}/{len(OBF_KEYS)} 特征, 建议 --runtime 或反混淆')

    # JS 加密/签名逻辑检测: 与混淆不同, 这是"代码真的在做密码学运算"
    #   (API 签名 / token 生成 / anti-bot), 需逆向它才能打有签名的接口。
    #   命中即报 MED 级线索; 证据列出具体命中的密码学 API, 方便人工定位。
    crypto_hits, crypto_report = crypto_score(text)
    if crypto_report:
        # 跨域(第三方)JS 的加密逻辑与"目标自身签名"无关 —— 实测 medsci 的 hls.js /
        #   aliplayer 等 CDN 库被误标为"目标 API 签名/token 生成"。故: 同源 → MED;
        #   跨域 → 降为 INFO 并明确标注"第三方/跨域"。
        _same = True
        if isinstance(src, str) and base:
            try:
                _same = _same_origin(src, base)
            except Exception:
                # fail-closed: 判不了就当**第三方**降 INFO(宁漏报不误标"目标自身签名")
                _same = False
        if _same:
            _fnd_loc(ctx, 'MED', 'JS含加密/签名逻辑', src,
                     '疑似 API 签名/token 生成: ' + ', '.join(crypto_hits)
                     + '; 建议人工逆向密钥与算法', text, crypto_hits)
        else:
            _fnd_loc(ctx, 'INFO', 'JS含加密/签名逻辑(第三方/跨域 JS)', src,
                     '第三方库的加密逻辑, 非目标自身签名: ' + ', '.join(crypto_hits), text, crypto_hits)


def _js_marker_findings(ctx, text, src, base):
    """deep_analyze **JS 内容线索四表**段(2026-10-12 结构拆分抽取):

    执行 sink / 密钥材料 / 演示账号 / 签名用法。同源(目标自身) → MED; 跨域 → INFO。
    """
    # JS 内容线索四表(执行 sink / 密钥材料 / 演示账号 / 签名用法) —— 与 crypto 同口径:
    #   同源(目标自身 JS) → MED; 跨域(第三方库) → INFO(避免把 CDN 库的 demo/test 当目标线索)。
    _markers = scan_js_markers(text)
    _same = True
    if isinstance(src, str) and base:
        try:
            _same = _same_origin(src, base)
        except Exception:
            # fail-closed: 与 crypto 段同口径(判不了当第三方 → INFO; 旧这里 fail-open
            #   会把跨域库的 demo/test 误标成目标自身线索)
            _same = False
    _marker_meta = (
        ('exec_sinks', 'JS执行/代码注入入口线索',
         '发现级线索(非漏洞判定): 命中执行/反序列化入口, 下游可追 RCE 链入口'),
        ('key_material', 'JS含前端密钥材料',
         '发现级线索(非漏洞判定): 前端含公钥/加密材料, 可能与 IDOR 自加密邻号相关'),
        ('demo_account', 'JS硬编码演示/测试账号',
         '发现级线索(非漏洞判定): 前端硬编码演示/测试账号, 可作"钥匙账号"尝试'),
        ('sign_hints', 'JS含签名/防重放逻辑',
         '发现级线索(非漏洞判定): 前端含签名/nonce/timestamp, 下游可尝试绕过鉴权只打签名'),
    )
    for _key, _title, _note in _marker_meta:
        _hits, _report = _markers.get(_key, ([], False))
        if not _report:
            continue
        if _same:
            _fnd_loc(ctx, 'MED', _title, src,
                     _note + ': ' + ', '.join(_hits), text, _hits)
        else:
            _fnd_loc(ctx, 'INFO', _title + '(第三方/跨域 JS)', src,
                     '第三方库行为, 非目标自身: ' + ', '.join(_hits), text, _hits)


def _apply_sca_and_custom_rules(ctx, text, src, out):
    """deep_analyze **SCA + 自定义规则**段(2026-10-12 结构拆分抽取):

    只消费编排层裁决(`ctx.sca_enabled`); 均为增强能力, 失败仅 dbg 不中断。
    """
    _cfg = getattr(ctx, 'config', None) or {}
    # R2(路由归编排): 只读编排层设定的 `ctx.sca_enabled`(orchestrator:913 统一裁决);
    #   属性缺失(直接调 deep_analyze 的测试/外部场景)时默认 True —— 工具层**不再**回读
    #   `config['sca']` 自决(旧实现属"轻微偏离", 见 CONTRIBUTING.md「设计约定」R2)。
    _sca_on = getattr(ctx, 'sca_enabled', True)
    if _sca_on:
        try:
            from ..recon import sca as _sca
            _extra = _sca.load_sca_db(_cfg.get('sca_db'))
            _sca_r = _sca.sca_scan(text, src, _extra, osv=bool(_cfg.get('sca_osv')))
            if _sca_r['libs']:
                out['sca_libs'] = _sca_r['libs']
            if _sca_r['vulns']:
                out['sca_vulns'] = _sca_r['vulns']
                for _v in _sca_r['vulns']:
                    ctx.add_finding(norm_sev(_v.get('severity')),
                                    f'已知漏洞组件 {_v["name"]}@{_v["version"]}',
                                    src, f'{_v["id"]}: {_v["summary"]}')
        except Exception as _e:
            dbg(f'SCA 跳过({src}): {type(_e).__name__}: {_e}')  # 增强能力, 不中断主分析

    # 自定义规则即时配置 —— 运行时加载外部 JSON 规则并应用(内置保留、外部追加)。
    #   不改代码即可追加 api/param/sensitive 提取规则; 失败静默跳过, 绝不影响主分析。
    #   加载/应用逻辑在**数据层**(`core.dicts`, 与 secret_db/extract_rules 同处) —— 原
    #   `recon/custom_rules.py` 已并入, 消除"外部规则"机制分散。
    if _cfg.get('custom_rules'):
        try:
            _rules = get_custom_rules(ctx)
            if _rules and (_rules.get('api') or _rules.get('param') or _rules.get('sensitive')):
                _nh = apply_custom_rules(_rules, text, src, out, ctx)
                if _nh:
                    log(f'[*] 自定义规则命中 {_nh} 处: {src}')
        except Exception as _e:
            dbg(f'自定义规则跳过({src}): {type(_e).__name__}: {_e}')


def _code_window(text, sub, before=100, after=120, cap=600):
    """命中代码端窗口 —— 委托 `js_lex.code_window`(单一实现, finding/接口同源)。"""
    from .js_lex import code_window as _cw
    return _cw(text, sub, before, after, cap)


def _fnd_loc(ctx, sev, typ, src, ev, text, probes=None):
    """记 finding 的同时留存**来源代码定位**(报告「完整发现清单」展开用)。

    probes 缺省时从 evidence 自动抽取候选(见 `js_lex.probes_from_evidence`);
    调用方能给出**精确命中字面量**时(密钥串/命中 token)应显式传, 定位更稳。
    """
    from .js_lex import note_finding_loc, probes_from_evidence as _pfe
    note_finding_loc(ctx, (sev, typ, src, ev), text,
                     probes if probes is not None else _pfe(ev))


def _record_api_trace(text, src, out):
    """deep_analyze **API 溯源记账**段(2026-10-12 结构拆分抽取):

    字面量命中 → 精确行列 + HIGH + 命中代码端窗口; 派生(拼接/归一化) → 标"派生" + MEDIUM。
    """
    from .js_lex import _line_of
    _api_conf = out.setdefault('api_conf', {})
    _api_srcline = out.setdefault('api_srcline', {})
    _api_snippet = out.setdefault('api_snippet', {})
    _api_extractor = out.setdefault('api_extractor', {})
    for _a in out['apis']:
        if _a in _api_srcline:
            continue
        _lc = _line_of(text, _a)
        if _lc:
            _api_srcline[_a] = (src, _lc[0], _lc[1])   # (来源, 行, 列)
            _api_conf.setdefault(_a, 'HIGH')
            _api_snippet.setdefault(_a, _code_window(text, _a))  # 命中代码端(与 srcline 同一次查找)
        else:
            _api_srcline[_a] = (src, None, None)        # 派生(无精确行/列)
            _api_conf.setdefault(_a, 'MEDIUM')
        # extractor 层标签(ast/regex/wasm): AST 已在上方单独标; 其余默认 regex
        _api_extractor.setdefault(_a, 'regex')


def deep_analyze(ctx, text, src, base, enabled, fingerprints=None, allow_source_only=True):
    """增强版深度分析: 支持常量传播、useParams反向推断

    """
    from . import plugins as _plugins
    from .guard import classify_page_type
    from .html_extract import (
        _extract_form_body_links,
        _extract_js_refs,
        _extract_subdomains,
        _extract_wasm_refs,
    )
    from .js_lex import _strip_comments_safe
    from .secret import _scan_sensitive_block
    # 字符串数组解包(方案 4.3): **先**还原 `_0x…` 字符串数组/索引/包装函数, 再走既有
    #   提取通道 —— 否则"索引形态"的 URL 在提取阶段根本看不出来。
    #   只做静态字面量替换, **不执行任何代码**(沙箱执行仍由运行时通道负责)。
    #   门控: 统一走插件注册表(`plugins.enabled('parser','deobf')`, 注册恒开) —— 消除"注册了却
    #   从不经 enabled() 读取"的死注册。
    #   门控从 `_0x` **放宽**到 sojson.v4/jsjiami 的 `fromCharCode.apply(null,"<数字链>")` 形态
    #   （`has_charcode_apply` 廉价预检）—— 否则扫描线与离线 `--deobf-file` 线**不一致**：
    #   后者无条件调用 `unpack_string_array`, 能还原 sojson 载荷, 而扫描线因缺 `_0x` 漏掉。
    if text and ('_0x' in text or has_charcode_apply(text)) \
            and _plugins.enabled('parser', 'deobf', getattr(ctx, 'config', None)):
        try:
            _unpacked, _n_unpack = unpack_string_array(text)
            if _n_unpack:
                text = _unpacked
                log(f'[*] 字符串数组解包: 还原 {_n_unpack} 处混淆字面量({src})')
        except Exception:
            pass
    # §4.2 转义解码回填: 把 \xNN / \uNNNN / \u{...} / \/ 还原为真实字符,
    #   让后续 URL/路径提取能命中"藏在转义里的端点"。decode_layer 的 unicode_escape
    #   对 UTF-8 JS 会崩(被吞), 故此处用定向正则做稳健解码(见 _decode_js_escapes)。
    text = _decode_js_escapes(text)
    out = {'apis': set(), 'params': set(), 'recomb': set(),
           'routes': set(), 'baseurls': set(),
           'fingerprints': {'hits': list(fingerprints or [])},
           'write_apis': {}, 'subdomains': set(), 'websockets': set(),
           'sse': set(), 'ws_messages': [], 'grpc': set(),
           'route_switches': set(),
           # JS 文件引用单独成集 —— 它们只用于"继续递归抓取", 不应
           #   混进 apis(那会变成探活目标, 对 .js 发探活请求既无意义又浪费流量)。
           'js_refs': set(),
           # .wasm 引用(同源只读 GET 后再做二进制字符串扫描, 见 _drain_wasm_ref)
           'wasm_refs': set(),
           # 从 wasm 二进制提取到的己方接口路径(供报告标注来源)
           'wasm_apis': set(),
           # 跨域绝对 API 调用(完整 URL, 含 host), 与己方 apis 分区。
           #   跨域不探活(与合规定位一致), 仅作为"外部/第三方接口"发现项呈现。
           'external_apis': set(),
           # **相对端点片段**(基址在配置里, 非本站绝对路径) —— 如 `/articles/{t}/comments`。
           #   覆盖"配了 baseURL 的 axios / Angular HttpClient / 前缀常量"这类写法; 不探活。
           'relative_apis': set(),
           # 页面类型分类(每个被分析的 HTML 页 → 类型)
           'page_types': {},
           # 每条接口的"来源文件:行号"与置信度(HIGH/MEDIUM)
           'api_conf': {}, 'api_srcline': {}, 'api_extractor': {},
           # 第三方库 SCA —— 识别到的库(含版本)与命中的已知漏洞
           'sca_libs': {}, 'sca_vulns': [],
           # R3 参数轻量污点(演进建议): {endpoint: {param: {kind,symbol,hops,label}}}
           #   kind ∈ upstream/storage/route/unknown
           'param_taint': {},
           # R7 AST 提取 sidecar(仅 --sidecars 时填充): 源文件 URL → AST 衍生路径/解析状态。
           'ast_results': {}}

    # JS 内部再引用的 chunk —— import / require / 动态 import / worker。
    #   真实 SPA 的接口大量分布在 webpack 懒加载 chunk 里, 此前完全没有这类提取器,
    #   只有 RE_CHUNK/RE_LAZY 两个针对字面量路径的模式。
    out['js_refs'] |= _extract_js_refs(text)
    # wasm 引用发现(§3.7-G2): Blazor/emscripten 类产物的 .wasm 端点盲区
    #   仅在 JS/HTML 文本里出现 .wasm 字面量引用时才收集, 不主动猜测。
    out['wasm_refs'] |= _extract_wasm_refs(text)
    # 构建产物 chunk 枚举 —— webpack(JSONP / import) + Vite + Worker。
    #   补"chunk 文件名由运行时拼接 / 映射, 从不以字面量出现"的漏抓。
    _static_analysis_signals(ctx, text, src, base, out, enabled)

    _js_marker_findings(ctx, text, src, base)

    # baseURL(含变量引用: baseURL: API)
    _consts = _resolve_string_constants(text)
    if 'RE_BASEURL' in enabled:
        for m in RE_BASEURL.finditer(text):
            out['baseurls'].add(m.group(1))
        # P0-1: baseURL 也可能是变量(const API='/api'; baseURL: API)
        for m in re.finditer(r'baseURL\s*:\s*([A-Za-z_$][\w$]*)', text):
            _v = _consts.get(m.group(1))
            if _v:
                out['baseurls'].add(_v)

    # 前端路由(含变量引用: path: ADMIN_ROUTE)
    if 'RE_ROUTE' in enabled:
        for m in RE_ROUTE.finditer(text):
            out['routes'].add(m.group(1))
        # P0-1: 路由 path 也可能是变量(const ADMIN='/admin/...'; path: ADMIN)
        for m in re.finditer(r'path\s*:\s*([A-Za-z_$][\w$]*)', text):
            _v = _consts.get(m.group(1))
            if _v and _v.startswith('/'):
                out['routes'].add(_v)

    # API路径（_is_api_path 兜底过滤静态资源，如 /rest/foo.js）
    if 'RE_API' in enabled:
        for m in RE_API.finditer(text):
            _p = m.group(1)
            if _is_api_path(_p):
                # 经 normalize_extracted_path 收口 —— 与结构化通道同源(`{id}`→`:id`),
                #   否则 RE_API 的 `{`/`}` 包容字符类会抓到 `/api/user/{id}` 这类字面路由,
                #   与 _extract_api_calls 归一出的 `/api/user/:id` 在 apis 内**自相重复**。
                _np = normalize_extracted_path(_p)
                if _np:
                    out['apis'].add(_np)

    # 调用点提取(fetch / $.ajax / xhr.open / axios({url}) / new URL() / gRPC-Web / 完整URL 等)
    #   形态统一在此收口, 按方法分流: GET/HEAD → apis(读探活), 写方法 → write_apis。
    #   跨域绝对 URL 被 _extract_api_calls 排除, 改由下方 _extract_external_api_calls 收集
    #     (完整绝对 URL 含 host, 进 external_apis, 不与己方 apis 混淆)。
    #   受 RE_API 门控(与"结构式"通道同源: 文档 B1 RE_API = "调用点 + 结构式")。
    if 'RE_API' in enabled:
        call_apis = _extract_api_calls(text, base)
        # R3 参数轻量污点(演进建议): 调用点参数值来源(upstream/storage/route/unknown)
        #   —— 一步解析, 零发包; 结果并入 out['param_taint'] 供报告参数总表展示。
        #   受 param_taint 配置门控(默认开; 设 false 跳过该静态标注, 不影响端点发现)。
        if getattr(ctx, 'config', {}).get('param_taint', True):
            try:
                _tt = _extract_param_taint(text)
                if _tt:
                    out.setdefault('param_taint', {}).update(_tt)
            except Exception:
                pass
        for path, method in call_apis.items():
            # JS 声明的**方法**(读+写)**全量**登记 —— 报告「方法」列以它为准。
            #   此前只留写方法(GET 随 `apis` 只存 path 而**丢失**), 导致 JS 明确 `.get('/x')`
            #   的端点在主表显示 `—` —— 现登记到 meta['api_methods'] 供报告消费。
            out.setdefault('api_methods', {})[path] = method
            if method in WRITE_METHODS:
                out['write_apis'][path] = method
            else:
                out['apis'].add(path)
            # 调用点自带 query 时同步登记参数名 （现在能拿到全部参数）
            qp = extract_query_params(path)
            if qp:
                out['params'] |= qp
            # 上下文关联参数: 在调用点附近找 ?a=1&b=2 / params:{...} 形态。
            # _link_params 此前定义了但返回值被丢弃, 属死代码 —— 现在
            #   把它的结果真正写入 ctx.pmap, 供后续 idor/sqli 阶段按路径取参。
            path_only = path.split('?')[0]
            if path_only:
                for pn in _link_params(text, path_only):
                    if pn:
                        ctx.link_param(path_only, pn)

    # 跨域绝对 API 调用 → external_apis(完整 URL 含 host, 不探活不进己方 apis)
    if 'RE_API' in enabled and base:
        out['external_apis'] |= _extract_external_api_calls(text, base)

    # 纯 Python 结构化(类 AST-lite)通道 —— 拼接路径还原(覆盖双字面量
    #   拼接, 并额外支持变量传播 / 多段链 / 数组 join / 单标识符调用参数)。仅 RE_API 开启时
    #   运行(与 API 提取同源); 结果经 normalize_extracted_path 过滤。单一事实来源。
    # ---- 跨文件符号聚合(动态提取层) ----
    # 把本文件里「根相对路径形态」的字符串常量值并入 ctx.js_symbols, 供后续文件解析本文件中
    #   定义的基址变量(如 RuoYi `var ctx="/xinzuo"` 定义在 HTML 内联脚本、拼接在 login.js)。
    #   同时合并 {本文件声明} ∪ {ctx.js_symbols} 作为本次解析符号表 `syms`(跨文件共享)。
    _file_consts = dict(_RE_STRVAR.findall(text))
    _js_syms = getattr(ctx, 'js_symbols', None)
    if _js_syms is None:
        _js_syms = {}
        try:
            ctx.js_symbols = _js_syms
        except Exception:
            pass
    for _n, _v in _file_consts.items():
        if _is_base_value(_v):
            _js_syms[_n] = _v
    syms = {**_file_consts, **_js_syms}

    if 'RE_API' in enabled:
        # 收集本文件识别到的**基址常量值**(如 `var o="/api/v3"` 的 `/api/v3`)。
        #   真正的剔除放在下方**所有通道都写完之后**做 —— 这类值不只来自结构化通道,
        #   RE_API 字面量匹配 / `_resolve_base_var_concat` / `_compose_base_with_callsites`
        #   都会产出它, 提前剔除会被后续通道重新写回(实测就踩过这个坑)。
        _base_consts = set()
        _nav_routes = set()
        out['apis'] |= _extract_struct_apis(text, _base_consts, _nav_routes, external=syms)
        # 集中式 API map 静态对象值(`key:"/path"`) —— 见 `_extract_api_map_strings`。
        #   补 RE_API/struct/调用点三条通道都漏的洞(实测 open.medsci.cn 漏 18 条)。
        out['apis'] |= _extract_api_map_strings(text)
        # 前端路由跳转目标(`$router.push("/pay/confirm?...")`)与真实接口形态一致,
        #   只能靠调用语境区分 —— 归入 routes, 不进 apis(实测混入 48 条, 占 apis 28%)。
        out['routes'] |= _nav_routes

    # 前端路由/菜单表字面量(`path:"/x/y"`) → routes —— 与调用点解耦, 现有通道都漏
    #   (实测 Vite SPA 入口 100+ 条 `path:"/..."` 仅 10 条被提取)。**无条件**运行(不依赖 RE_API)。
    out['routes'] |= _extract_route_table_literals(text)

    # 目标**自述的业务名**（路径字面量旁的中文 `name:` / `title:` 标签）—— 「读懂业务」的
    #   最强证据类：目标自己写的名字，胜过从英文段猜出来的域标签。实测 `/desktop/companyConfig`
    #   旁边就写着 `title:"配置微卡页面显示"`（本工具此前只取路径、把名字丢了）。
    out.setdefault('labels', {}).update(_extract_adjacent_labels(text))

    # RPC / 远程调用约定（`Service.method` + 参数个数）与字段字典 —— **参数维度**的两条来源。
    #   与 URL 端点**分区存放**(`rpc_apis` / `field_dict`), 不与 `apis` 混为一谈。
    _rpc = _extract_rpc_apis(text)
    if _rpc:
        out.setdefault('rpc_apis', {}).update(_rpc)
    _fd = _extract_field_dict(text)
    if _fd:
        out.setdefault('field_dict', {}).update(_fd)

    # 第三方库 SCA(retire.js 式, 离线优先) —— 识别 JS 库版本并对照已知漏洞表。
    #   纯本地文本分析, **零额外请求**, 被动能力。是否启用由调度层(recon_deep)裁决后写入
    #   ctx.sca_enabled(见 CONTRIBUTING.md「设计约定」R2: 能力在 recon/sca.py, 路由决策归编排层);
    #   此处只消费裁决。兜底回 config['sca'] 以兼容直接调用 deep_analyze 的测试/外部场景。
    #   关闭: config['sca']=False; 外部库表: config['sca_db']; OSV 联网富化: config['sca_osv'](默认关)。
    _apply_sca_and_custom_rules(ctx, text, src, out)

    # 写方法提取 (增强版) —— 只补那些需要额外上下文的写语法
    if 'RE_WRITE' in enabled:
        write_apis = _extract_write_text_v45(text, base)
        out['write_apis'].update(write_apis)
        for p, method in write_apis.items():
            _fnd_loc(ctx, 'INFO', f'JS声明写操作({method})', src, p, text, [p])

    # 参数提取 —— **默认无条件开启**(被动扫描 / 离线对账的最小 ENABLED 也生效)。
    #   参数名 / useParams 解构 / 模板参数等一律抽取, 不依赖任何开关 —— 用户明确要求
    #   "默认提取而非靠 options 开关"(早期曾因开关缺失导致参数整块丢失)。
    # 1. useParams 解构反向推断
    for m in re.finditer(r'useParams\s*\(\s*\)\s*;?\s*const\s*\{([^}]+)\}\s*=\s*useParams\s*\(\)', text):
        params_str = m.group(1)
        inferred = [p.strip() for p in params_str.split(',')]
        for param in inferred:
            # 向后查找关联的URL路径
            ctx_end = min(len(text), m.end() + 400)
            url_ctx = text[m.end():ctx_end]
            for _ in re.finditer(r'["\']([^"\']*[:*]\w+[^"\']*)["\']', url_ctx):
                out['params'].add(param)
    # 2. 通用参数名提取(param_names_from_text: 仅在 URL 形态字面量内、值为简单原语时匹配,
    #    已规避 `&&x=` / 三元 `?x=` 噪声 —— 见 dicts.py 同函数注释)
    out['params'] |= param_names_from_text(text)
    # 3. URLSearchParams 构造 —— 语义明确(query 参数构造器), 总是接受
    for m in re.finditer(r'URLSearchParams\s*\(\s*\{([^}]{2,400})\}', text):
        _names = set(re.findall(r'(\w+)\s*:', m.group(1)))
        if not _names:
            continue
        out['params'] |= _names
        # level-3 同体关联: 同一请求对象内若有 url/path, 锚定到该接口(零推断、不臆造)
        _u = _same_object_url(text, m.start())
        if _u:
            for _n in _names:
                ctx.link_param(_u, _n)
    # 4. params:{...} / query:{...} —— **仅请求语境**(见 `_req_ctx_ok`)。
    #    否则会命中库/框架配置对象: Swiper 内部 `this.params`(50+ 选项)、Vue 组件
    #    选项、`router.go({query:{…}})` 路由跳转参数等 —— 这些都不是 API 参数。
    #    上限放宽到 400: 未压缩(多行缩进)站点的对象体可远超 120。
    #    level-3 同体关联: 命中请求语境的对象, 若同 `{}` 内出现 url/path 则锚定到接口。
    for _key in ('params', 'query'):
        for m in re.finditer(r'%s\s*:\s*\{([^}]{2,400})\}' % _key, text):
            if not _req_ctx_ok(text, m.start()):
                continue
            _names = set(re.findall(r'(\w+)\s*:', m.group(1)))
            if not _names:
                continue
            out['params'] |= _names
            _u = _same_object_url(text, m.start())
            if _u:
                for _n in _names:
                    ctx.link_param(_u, _n)

    # 解码层 + 拼接重组
    decoded = decode_layer(text)
    t = text + '\n' + decoded
    # 第二轮在解码文本中查找
    if 'RE_API' in enabled:
        for m in RE_API.finditer(decoded):
            _p = m.group(1)
            if _is_api_path(_p):
                _np = normalize_extracted_path(_p)
                if _np:
                    out['apis'].add(_np)

    # 敏感信息检测 (增强JWT校验 + 误报过滤 + 注释过滤 -B)
    if 'SENSITIVE' in enabled:
        # -B: 先剔除注释，减少示例文字误报（保护字符串/正则/模板串）
        clean_t = _strip_comments_safe(t)
        # 用 getattr 取 config —— 保证最小 ctx 桩(单测)也能跑 deep_analyze
        # 抽成 _scan_sensitive_block, 与 HTML 隐藏域/注释提取共用同一套规则(单一事实来源)。
        _scan_sensitive_block(ctx, clean_t, src, allow_source_only=allow_source_only)

    # 子域名
    out['subdomains'] |= _extract_subdomains(text, base)

    # 按指纹注入栈专属正则 —— **单一机制**: 统一经 `get_extra_route_patterns(enabled)`
    #   (ROUTE_RULES → 开关 驱动; 正则表见 `fingerprint.ROUTE_EXTRA_PATTERNS`)。
    #   **必须按模式语义分流**(而非只看形态): 有的产出前端路由(如 `/course/:id`)、状态机
    #   动作名、库标记、数据表名等**非路径**值; 前端路由同样以 `/` 开头, 单靠形态无法与
    #   真实接口区分 → 必须按模式名判定(ROUTE_EXTRA_ROUTE_NAMES)。
    #   历史: 原为**两套并行注入机制**(EXTRA_JS_PATTERNS 按指纹名 + ROUTE_EXTRA_PATTERNS 按
    #   开关名), 21 个同名模式各存一份、分流口径还不一致 —— 已合并为下面这**一个**循环。
    for switch, pat in get_extra_route_patterns(enabled):
        _is_route_pat = switch in ROUTE_EXTRA_ROUTE_NAMES
        for m in pat.findall(t):
            val = m[0] if isinstance(m, tuple) else m
            if not val:
                continue
            if _is_route_pat:
                out['routes'].add(val)             # 前端路由/构建产物: 一律进 routes
            elif val.startswith('http'):
                out['external_apis'].add(val)      # 跨域绝对 URL: 只登记, 不探活
            elif val.startswith('/'):
                # 经 normalize_extracted_path 收口 —— 与 RE_API/结构化通道同源口径,
                #   指纹栈专属路由正则抓到的 `/api/.../{id}` 也统一成 `:id`, 避免 apis 内
                #   自相重复 / 与 recomb 合并时去重失效。
                _nv = normalize_extracted_path(val)
                if _nv:
                    out['apis'].add(_nv)
            # 非路径形态(如 PINIA store 名 / ALPINE x-data)不当作接口, 仅计入路由线索
            else:
                out['routes'].add(val)
        out['route_switches'].add(switch)

    # 拼接重组路径经 normalize_extracted_path 统一收口 —— 与 `apis` / `write_apis` 同一
    #   归一口径(模板占位 `{id}`→`:id`、去 fragment/静态资源/前端路由模板、剔除单段噪声)。
    #   否则 recomb 的 `{id}` 形态与 `apis` 的 `:id` 形态在 `apis | recomb | write_apis`
    #   合并时**无法去重**(且 normalize_endpoint 不统一 `:id`/`{id}`), 同一接口在
    #   `extracted_endpoints` / 端点侧车 / 报告主表出现两次、参数语法不一致(实证)。
    out['recomb'] |= {normalize_extracted_path(c) for c in concat_recomb(decoded, base)
                      if normalize_extracted_path(c)}

    # ---- 拼接路径还原 + 基址变量解析 + 参数通道补齐 ----
    # `"/api/user/"+id` → `/api/user/{id}`; `"/api/comment/"+cid+"/replies"` 保留 /replies;
    #      模板 `` `/api/user/${id}` `` → `/api/user/{id}`(修 `$1` 畸形)。
    # `const API='/api'; fetch(API+'/x')` → `/api/x`。
    # 补 query 名(字面量内, 不受值形态影响) / 请求体对象键 / 路径参数名。
    _srcs = (text, decoded)
    if 'RE_API' in enabled:
        _trunc_all = set()
        for _s in _srcs:
            _cp, _tr = _extract_concat_paths(_s)
            # **统一归一** —— `_extract_concat_paths` / `_normalize_template_paths` 产出
            #   `{id}` 形式, 而其余通道经 normalize_extracted_path 统一为 `:id`。
            #   不归一会让**同一个接口**以两种占位符形态并存, 去重失效、清单重复。
            out['apis'] |= {normalize_extracted_path(p) or p for p in _cp}
            _trunc_all |= {normalize_extracted_path(t) or t for t in _tr}
            out['apis'] |= {normalize_extracted_path(p) or p
                            for p in _normalize_template_paths(_s)}
            # 动态基址解析(去 /api 硬编码 + 跨文件符号): 经 _is_dynamic_base_candidate 形态门禁。
            #   结果标注 'dynamic-base'(派生, 文件中无该字面量 → 置信度 MEDIUM)。
            _dynbase = set()
            _dynbase |= {normalize_extracted_path(p) or p
                         for p in _resolve_base_var_concat(_s, syms)}
            _dynbase |= {normalize_extracted_path(p) or p
                         for p in _compose_base_with_callsites(_s)}
            out['apis'] |= _dynbase
            for _dp in _dynbase:
                out.setdefault('api_extractor', {})[_dp] = 'dynamic-base'
            # 相对端点片段(不含 API 前缀, 基址在配置里) —— 单列, 不并入本站 apis(避免误归属)。
            out['relative_apis'] |= {normalize_extracted_path(p) or p
                                     for p in _extract_relative_param_paths(_s)}
            # `.concat()` 拼接(TS/Babel 编译模板字面量的产物) + HTTP 客户端方法调用
            #   (`x.get("articles")` —— 基址由 baseURL 提供)。命中绝对/相对通道分别归位。
            for _p in _extract_concat_method_paths(_s):
                # `.concat()` 产出的路径**不带前导 `/`**(`articles/{t}`); 归一为绝对形态再分流。
                #   以 `{` 开头的(空串 base, 如 `"".concat(t,"/comments")`)是残片, 丢弃。
                if not _p.startswith('/'):
                    if _p.startswith('{'):
                        continue
                    _p = '/' + _p
                # 守卫必须在**归一前**判定 —— `normalize_extracted_path` 会把 `{t}` 变成 `:t`,
                #   而 `_is_relative_param_path` 判的是 `{` 形态(顺序反了会被误丢)。
                _n = normalize_extracted_path(_p) or _p
                if _is_api_path(_p):
                    out['apis'].add(_n)
                elif _is_relative_param_path(_p):
                    out['relative_apis'].add(_n)
            for _p in _extract_http_client_paths(_s):
                _n = normalize_extracted_path(_p) or _p
                if _is_api_path(_p):
                    out['apis'].add(_n)
                else:
                    out['relative_apis'].add(_n)
        out['apis'] -= _trunc_all          # 去掉被还原的截断前缀(如 /api/user/)
        # 含 `${...}` 的**原始模板形态**统一归一 —— RE_API 等字面量通道不做归一,
        #   于是同一接口会以两种形态并存:
        #       `/api/v1/orders/${orderId}/items`(原始) + `/api/v1/orders/:orderId/items`(归一)
        #   去重失效 → 清单里同一接口出现两次。只处理含 `${` 的条目, 不动其余
        #   (其余条目各自通道已归一, 再动会误伤)。
        for _tp in [p for p in out['apis'] if '${' in p]:
            _tn = normalize_extracted_path(_tp)
            if _tn:
                out['apis'].discard(_tp)
                out['apis'].add(_tn)
        # **最后**剔除"恰好等于某个基址常量"的路径 —— 它们是**前缀**, 不是可探活端点。
        #   放在这里而不是更早: 上面这些通道(尤其 `_resolve_base_var_concat` /
        #   `_compose_base_with_callsites`)同样会产出基址本身, 提前剔除会被写回。
        #   收窄: 只移除**真正的前缀型基址**(结尾 `/` 或 `/(api|rest|graphql|gateway…)`
        #   单段前缀)。`vars.known_values()` 会把所有赋值过的字符串(含 `/comment/list`
        #   这类完整资源端点)都收进来, 若整集合相减会把真实接口误删(实测 open.medsci.cn
        #   漏掉全部 API map 端点即此因)。完整资源路径(≥2 段、无尾斜杠、非 api 前缀)
        #   一律保留。
        if _base_consts:
            _base_prefixes = {v for v in _base_consts if _is_base_prefix(v)}
            out['apis'] -= _base_prefixes
            out['write_apis'] = {k: v for k, v in out['write_apis'].items()
                                 if k not in _base_prefixes}
    for _s in _srcs:
        out['params'] |= _extract_query_params_js(_s)
        out['params'] |= _extract_body_params(_s)
    out['params'] |= _path_param_names(out['apis'])

    # 外部链接参数剔除 —— 出现在**非本域绝对 URL** 字面量里的 query 参数(第三方登录 /
    #   OAuth 跳转 / 应用商店等, 如 `android.myapp.com/…?apkName=…`、
    #   `open.weixin.qq.com/connect/oauth2/authorize?appid=…&state=…`)不是目标自身 API 参数。
    #   仅当该参数**只**出现在外部链接(本域/相对 URL 及其它通道均未产出)时才剔除,
    #   避免误删同时用于本域接口的同名参数。
    if base:
        _host = urlparse(base).hostname or ''
        _root = '.'.join(_host.split('.')[-2:]) if '.' in _host else _host
        if _root:
            _ext, _own = set(), set()
            # ① 单字面量判定。注意 `_own` **只**收录"明确的同域依据"——相对路径(`/…`)或同域
            #   绝对 URL; 不含路径的 query **片段**(`"&redirect_uri="`)既不进 `_own` 也不在这里进
            #   `_ext`, 由 ② 语句级判定归属 —— 否则片段会被 `_own` 误当成同域依据而"保护"住。
            for _m in re.finditer(r'["\']([^"\']{0,400})["\']', text):
                _s = _m.group(1)
                _um = re.match(r'https?://([^/]+)', _s.lower())
                if _um:
                    if '.'.join(_um.group(1).split('.')[-2:]) == _root:
                        _own |= set(re.findall(r'[?&]([A-Za-z_][A-Za-z0-9_]*)=', _s))
                    else:
                        _ext |= set(re.findall(r'[?&]([A-Za-z_][A-Za-z0-9_]*)=', _s))
                elif _s.startswith('/'):
                    _own |= set(re.findall(r'[?&]([A-Za-z_][A-Za-z0-9_]*)=', _s))
            # ② 语句级判定: **拼接式**外部 URL 的后续片段不含 `://`(如微信 OAuth
            #   `"https://open.weixin.qq.com/…?appid=".concat(…,"&redirect_uri=")`),
            #   单字面量判定会漏掉 `redirect_uri`/`response_type`/`scope` 等。
            #   若同一语句内出现的**绝对 URL 全部为外域**, 则该语句内所有 query 参数视为外部。
            for _stmt in text.split(';'):
                _lits = re.findall(r'["\']([^"\']{0,400})["\']', _stmt)
                _shosts = []
                for _s in _lits:
                    _um = re.match(r'https?://([^/]+)', _s.lower())
                    if _um:
                        _shosts.append('.'.join(_um.group(1).split('.')[-2:]))
                if _shosts and all(_h != _root for _h in _shosts):
                    for _s in _lits:
                        _ext |= set(re.findall(r'[?&]([A-Za-z_][A-Za-z0-9_]*)=', _s))
            if _ext:
                _drop = _ext - _own - (out['params'] - _ext)
                if _drop:
                    out['params'] -= _drop

    # WebSocket / SSE / gRPC-Web
    if 'RE_WS' in enabled:
        for ws_url in RE_WS.findall(text):
            out.setdefault('websockets', set()).add(ws_url)
        for ws_msg in RE_WS_SEND.findall(text):
            out.setdefault('ws_messages', []).append(ws_msg[:200])
    if 'RE_SSE' in enabled:
        for sse_url in RE_SSE.findall(text):
            out.setdefault('sse', set()).add(sse_url)
    if 'RE_GRPC_METHOD' in enabled:
        for grpc_method in RE_GRPC_METHOD.findall(text):
            out['grpc'].add(grpc_method)

    # 页面类型分类 —— 仅对**真实 HTML 文档**判定。
    #   实测(真实 bundle): JS 里含 `<body`(模板字符串) 会被旧守卫放行, 再因裸子串
    #   `express` 命中被判 BACKEND_TEMPLATE → **JS 文件在报告里显示成"后端模板"**(误报)。
    #   收紧: ① JS/内联脚本/源码映射 来源直接跳过; ② 要求文本**以 `<!doctype`/`<html` 开头**
    #   或同时含 `<body` 与 `</html>`(真正的文档形态)。
    _src_l = (src or '').lower()
    try:
        _src_path_l = urlparse(_src_l).path.lower()
    except Exception:
        _src_path_l = _src_l.split('?', 1)[0].split('#', 1)[0]
    _is_js_src = (_src_path_l.endswith(('.js', '.mjs', '.cjs', '.map'))
                  or '#inline-' in _src_l or '#sourcemap' in _src_l)
    _txt_l = text.lower()
    _head = text.lstrip()[:200].lower()
    _is_html_doc = (_head.startswith(('<!doctype', '<html'))
                    or ('<body' in _txt_l and '</html>' in _txt_l))
    if not _is_js_src and _is_html_doc:
        out.setdefault('page_types', {})[src] = classify_page_type(text)

    # ---- JS AST 提取 sidecar（方案 4.1「AST 优先, 正则兜底」）----
    #   Python tree-sitter 优先、常驻 Node+Acorn JSON-lines 回退: 覆盖正则漏掉的"URL 存变量后再用"、
    #   复杂调用形态(`$.ajax({url,type})` 等)。均不可用 → 回退正则(行为与从前一致)。
    #   **只做静态解析, 绝不执行目标代码。** `_is_js_src` 使用 URL path 判定, 保证带 query 的 JS 也走 AST。
    if _is_js_src:
        _cfg_ast = getattr(ctx, 'config', None) or {}
        _capture_ast = bool(_cfg_ast.get('sidecars'))
        _ast_enabled = plugins.enabled('parser', 'ast', _cfg_ast)
        if _ast_enabled:
            _ast = ast_sidecar.extract(text, _cfg_ast)
            if _capture_ast:
                # R7 AST 提取结果持久化入口: 只保存 AST 解析出的路径集合(不保存源 JS),
                #   JSON 侧车按源文件分组; 限额避免大 bundle 把内存/产物撑爆。
                _ar = {'ran': bool(_ast), 'apis': [], 'literals': [], 'write_apis': {},
                       'reason': '' if _ast else 'Node/Acorn 解析失败或超时'}
                if _ast:
                    _ar['apis'] = sorted(_ast.get('apis') or [])[:1000]
                    _ar['literals'] = sorted(_ast.get('lits') or [])[:1000]
                    _ar['write_apis'] = dict(list((_ast.get('write_apis') or {}).items())[:1000])
                out.setdefault('ast_results', {})[src] = _ar
            if _ast:
                _n_ast = 0
                # AST 侧"接口路径/字面量"提取 —— 与正则通道同源, 受 RE_API 门控
                #   (文档 B1 RE_API = "调用点 + 结构式"; 否则禁用 RE_API 时 AST 仍漏抓调用点, 与门控契约不一致)。
                if 'RE_API' in enabled:
                    for _p in list(_ast['apis']) + list(_ast['lits']):
                        _np = normalize_extracted_path(_p)
                        if _np and _np not in out['apis']:
                            out['apis'].add(_np)
                            out.setdefault('api_extractor', {})[_np] = 'ast'
                            _n_ast += 1
                # AST 侧写方法 —— 与 RE_WRITE 通道同源, 受 RE_WRITE 门控。
                if 'RE_WRITE' in enabled:
                    for _p, _m in (_ast['write_apis'] or {}).items():
                        _np = normalize_extracted_path(_p)
                        if _np:
                            out['write_apis'].setdefault(_np, _m)
                            out.setdefault('api_extractor', {})[_np] = 'ast'
                            _n_ast += 1
                # P0-1 AST 级还原: baseURL / 路由 path 的"变量·拼接·模板"已在 Acorn 侧解析为字面量,
                #   与 RE_BASEURL / RE_ROUTE 同门控并入 —— 供后续 _apply_baseurls/route-rebase 重建后端端点。
                #   (tree-sitter 引擎不产出这两键 → .get 兜底; 缺失时由正则 P0-1 兜底。)
                if 'RE_BASEURL' in enabled:
                    for _b in (_ast.get('baseurls') or []):
                        if _b:
                            out['baseurls'].add(_b)
                if 'RE_ROUTE' in enabled:
                    for _r in (_ast.get('routes') or []):
                        if _r and str(_r).startswith('/'):
                            out['routes'].add(_r)
                if _n_ast:
                    out['ast_hits'] = int(out.get('ast_hits', 0)) + _n_ast
        elif _capture_ast:
            _mode = _cfg_ast.get('ast_sidecar', 'auto')
            try:
                _available = ast_sidecar.available(_cfg_ast)
            except Exception:
                _available = False
            _reason = ('AST 提取已配置关闭' if _mode is False or
                       (isinstance(_mode, str) and _mode.strip().lower() in ('false', 'off', '0'))
                       else ('Node/Acorn 不可用' if not _available else 'AST 插件未启用'))
            out.setdefault('ast_results', {})[src] = {
                'ran': False, 'apis': [], 'literals': [], 'write_apis': {}, 'reason': _reason}

    # 为每条接口记录"来源文件:行号:列"与置信度, 供报告标注(方案 §1 原则3 / §8 / §9)
    #   字面量命中 → 精确定位 + HIGH; 派生(拼接/归一化/基址拼接, 文本无字面量) → 标"派生" + MEDIUM
    _record_api_trace(text, src, out)

    # 表单 → 请求体 → 端点 的数据流关联: 此处**只登记**(form_id → 端点), 真正 `link_param`
    #   在 recon 收尾由 `_resolve_form_body_links` 统一做 —— 这样无论 HTML 与 JS 的解析先后,
    #   都能在收尾"求交", 且**歧义(一表单喂多端点)一律不关联**(零推断)。
    for _fid, _eps in (_extract_form_body_links(text) or {}).items():
        ctx.form_body_links.setdefault(_fid, set()).update(_eps)

    return out
