# -*- coding: utf-8 -*-
"""共享常量 / 正则 / 词表 —— 原从 `core/engine.py` 下沉（依赖单向向下）。

定位（如实）：本模块是**共享常量 hub**，只放**纯数据**（正则/元组/字典/缓存）与可选依赖探测，
不放业务逻辑。

🔴 **不再承担领域层再导出面**（P3a 收窄）：本文件曾以 10 条 `import *` 再导出整个领域层
（`recon.auth/fingerprint/runtime/sca/schema/unbundle`）+ `ast_sidecar/context/dicts/plugins`。
实证审计：全库 12 个文件共 15 处 `from .const import X`（90 个名字）**全部**是本文件自身定义的
—— 那些星导入**没有任何消费者**，却把领域层拽进"常量"层（循环耦合 + 导入期副作用）。
现只显式导入本文件自身需要的 `dicts` 符号；下方保留的**显式** re-export 均有真实消费者。

**新代码请从定义处导入**（如 `from .dicts import X`、`from ..recon.fingerprint import Y`）。
"""
import html as _html  # noqa: F401   (re-export 供 `from .const import _html` → html.unescape)
import re
import re as _re  # 内部正则别名(常量区使用)

import urllib3

urllib3.disable_warnings()

# 异步依赖: asyncio 是标准库, 必须无条件导入(_AsyncRateGate 依赖它);
# 仅 aiohttp 是可选依赖(未装则异步批量抓取降级为同步 REQ)

try:
    import aiohttp
    AIOHTTP = aiohttp
except ImportError:
    # 未装 aiohttp: 置 None, 由调用方(`_fetch_js` / `aio_fetch_sync`)降级为同步 REQ。
    #   注意 —— 兜底**只能**写在这里; 绝不能在模块后面再写一行无条件的
    #   `AIOHTTP = None`, 那会把已导入的 aiohttp 覆盖掉, 静默关闭整条异步通道。
    AIOHTTP = None

# 可选依赖
try:
    import jsbeautifier
except ImportError:
    jsbeautifier = None

# brotli 支持检测。
#   requests 只有在装了 brotli / brotlicffi 时才能解 `Content-Encoding: br`。
#   现代 CDN(Cloudflare / Fastly / ngx_brotli / 各云厂商 CDN)普遍启用 brotli,
#   缺失时响应体是**压缩后的二进制**, 不会抛异常, 只会"什么都提取不到" ——
#   使用者会误以为"这站点没东西"。实测: 未装 brotli 时 0 指纹 0 接口 0 JS。
try:
    import brotli as _brotli  # noqa: F401
    BROTLI = True
except ImportError:
    try:
        import brotlicffi as _brotlicffi  # noqa: F401
        BROTLI = True
    except ImportError:
        BROTLI = False

# ---- 🔴 只从**定义处**显式取本文件需要的符号（原为 `import *` 再导出整个领域层，已收窄）----
#   收窄依据（实证，非推理）：全库 12 个文件、15 处 `from .const import X` 共 90 个名字，
#   **全部**是 const 自身定义的；本文件内部只用到 `dicts` 的 3 个名字 + `_VAL_OK`。
#   即：原先那 10 条 `import *`（recon.auth/fingerprint/runtime/sca/schema/unbundle +
#   ast_sidecar/context/dicts/plugins）**没有任何消费者**，却把整个领域层拽进"常量"层
#   （循环耦合风险 + 导入期副作用），属纯死重量。需要领域层能力请**直接从定义处导入**。
from .dicts import (
    _VAL_OK,  # noqa: F401  (供 _QP_VAL_OK 派生; 显式导入才带下划线名)
    NON_API_PREFIX,
    PARAM_SEMANTICS,
    STATIC_EXT,
)

# 强制直连的 sentinel。空字符串值使 requests.utils.resolve_proxies
# 里的 `new_proxies.setdefault(scheme, proxy)` 不再注入环境代理, 而 select_proxy
# 拿到空串后判为假值 → 最终直连。`{}` 无效(实测), 必须带空串值。
_DIRECT_PROXIES = {'http': '', 'https': ''}


# ---- 显式 re-export（故意，勿删）—— 这 4 个名字**有真实消费者**（已实证，逐个核过）：
#   · `__version__` ← `core/probe.py`（版本号统一从这里取）；
#   · `ast_sidecar` ← `core/js_extract.py`（模块对象本身；星导入不会带模块名）；
#   · `plugins`     ← `core/js_extract.py` / `core/orchestrator.py` / `core/probe.py`；
#   · `_output_dir` ← `core/orchestrator.py`（在源模块 `__all__` 之外）。
from .. import __version__  # noqa: F401
from . import (
    ast_sidecar,  # noqa: F401
    plugins,  # noqa: F401   (re-export 模块对象本身, 供 `from .const import plugins`)
)
from .context import _output_dir  # noqa: F401

# ---------- 全局请求头 / Session / 预算 辅助 ----------

# 默认 User-Agent。取一个常规浏览器 UA —— 真实目标普遍部署 WAF, 而 WAF 的默认
# 规则集几乎都会拦 `python-requests/*`(实测: 被拦后 0 指纹 0 接口 0 JS)。
# 需要自我标识或复现特定工具 UA 时, 用 `--ua` 覆盖, 例如:
#   --ua 'Mozilla/5.0 (compatible; facet/4.6.3; +https://your-contact)'
DEFAULT_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36')


# ---------- 提取增强  ----------
_RE_STRVAR = re.compile(r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*["\']([^"\']+)["\']')


_RE_TEMPLATE_PATH = re.compile(r'`([^`]*\$\{[^}]+\}[^`]*)`')


_RE_BODY_CALL = re.compile(r'\.(?:post|put|patch)\s*\([^,]{0,200},\s*\{([^}]{0,600})\}', re.S)


_RE_DATA_OBJ = re.compile(r'\bdata\s*:\s*\{([^}]{0,600})\}', re.S)


_RE_JSON_STR = re.compile(r'JSON\.stringify\s*\(\s*\{([^}]{0,600})\}', re.S)


_RE_OBJ_KEY = re.compile(r'([A-Za-z_$][\w$]*)\s*:')


_BODY_KEY_STOP = {'function', 'if', 'else', 'return', 'true', 'false', 'null', 'new', 'typeof'}


# 简写属性键 `{username, password}` —— 无 `:` 的裸标识符(仅当其后紧跟 `,`/`}`/串尾)。
#   现代 JS 请求体大量用简写; `_RE_OBJ_KEY` 要求 `key:` 会整类漏掉这些参数。
_RE_SHORTHAND_KEY = re.compile(r'(?:^|[,{])\s*([A-Za-z_$][\w$]*)\s*(?=[,}]|$)')


# 请求语境判定 —— `params:` / `query:` / `data:` 对象只有在 **HTTP 请求调用附近** 才是
#   API 参数; 否则极可能是库/框架配置对象。典型误报: Swiper 把它的选项存在内部对象
#   `this.params` 里 (`params:{autoplay:…, coverflowEffect:…, navigation:…, …}`),
#   被旧版 `params:` 通道整包当参数抽出来(实测单站 53 个假参数)。Vue 组件 `data(){…}`
#   的对象同理。此闸门把这类"非请求对象"挡在参数集之外。
_REQ_CALL_RE = re.compile(
    r'\.(?:get|post|put|patch|delete|head|options)\s*\('
    r'|\.ajax\s*\(|\.(?:get|post)JSON\s*\('                      # jQuery / Zepto ajax
    r'|\$\.(?:get|post|put|patch|ajax|getJSON|postJSON)\s*\('
    r'|fetch\s*\(|axios|\$http|\$axios|http\.(?:get|post|put|patch)')


# 接口路径前缀（不止 /api/）：真实应用广泛使用 /rest、/graphql、/v1 等。
_API_PREFIX_RE = re.compile(r'^/(?:api|rest|graphql|gql|gateway|rpc|service|services|v\d+)(?:/|$)')


# 非锚定版：用于统计路径里出现几次接口前缀（拼接去重判断）
_API_PREFIX_ANY = re.compile(r'/(?:api|rest|graphql|gql|gateway|rpc|service|services|v\d+)/')


# 数据层单一事实来源(dicts.NON_API_PREFIX / dicts.STATIC_EXT); 此处仅别名, 不再本地硬编码。
_NON_API_PREFIX = NON_API_PREFIX


_STATIC_EXT = STATIC_EXT


# 纯跟踪/营销参数 —— 出现在 URL 里**不代表是接口**(实测导航链接常带 utm_*)。
_TRACKING_PARAMS = frozenset((
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'utm_id', 'utm_name', 'utm_reader', 'utm_brand', 'utm_social',
    'gclid', 'fbclid', 'msclkid', 'yclid', 'dclid', 'igshid', 'twclid',
    'mc_cid', 'mc_eid',
    # Matomo / Piwik
    'mtm_campaign', 'mtm_source', 'mtm_medium', 'mtm_keyword', 'mtm_content', 'mtm_cid',
))


_CONCAT_ARG_RE = re.compile(r'\s*(?:(["\'])([^"\']*)\1|([A-Za-z_$][\w$]*))\s*(,|\))')


# HTTP 客户端方法调用: `x.get("articles")` / `api.post("users/login")`
#   捕获组: 1=接收者名  2=方法  3=引号  4=路径
_HTTP_CALL_RE = re.compile(
    r'(?<![\w$])(?:[A-Za-z_$][\w$]*\s*\.\s*)*([A-Za-z_$][\w$]*)\s*\.\s*'
    r'(get|post|put|patch|delete)\s*\(\s*(["\'])([^"\'\s]{2,80})\3')


# 接收者名像"HTTP 客户端"的白名单(用于区分 `api.get(...)` 与 `obj.get(...)`)
_HTTP_CLIENT_NAMES = ('api', 'http', 'https', 'axios', 'request', 'client', 'service',
                      'backend', 'server', 'ajax', 'rest', 'gateway')


# 单一真源(审计 S3): 与 dicts._VAL_OK 同值 —— 从那里派生, 不再各写一份。
_QP_VAL_OK = set(_VAL_OK)


# 静态资源扩展名(单一真源, 审计 S7): 此前 js_extract 里 `_join_fragments` 用 3 项
#   小表、`_compose_base_with_callsites` 内联 11 项大表 —— 三处各写一份必然漂移。
_CHUNK_STATIC_EXTS = ('.js', '.css', '.png', '.jpg', '.jpeg', '.svg',
                      '.ico', '.map', '.woff', '.woff2', '.ttf')
_FRAG_STATIC_EXTS = ('.png', '.css', '.js')

# 纯 query 串形态: `?a=1&b=2` 或 `&a=1`(拼接写法的后半截)。`&&t=` / `?n=oe.X(` 不满足。
_RE_QUERY_LIT = re.compile(r'^(?:[?&][A-Za-z_][A-Za-z0-9_]*=[^&]*)+$')


# 注: 字符串数组解包(unpack_string_array 及其 `_RE_*` 正则)已拆至 `core/deobf.py`(便于维护)。


# unpack_string_array / _beautify_js 已拆至 `core/deobf.py`(见文件顶部导入)。

# ---------- 参数语义扩展  ----------
# 驼峰→蛇形映射 + useParams 反向推断
# 单一真源(全库审计 M18): 与 `dicts.PARAM_SEMANTICS` **同键**的值从其派生(取首个候选)。
#   此前两表同键不同值(`size`: '20' vs '10'、`search`: 'test' vs 'user') → 同一参数
#   在"探活补全"与"参数值推断 v45"两条通道产出**不同**值。dicts 表是参数语义推断的
#   源头; V45 只维护**单数形态/独有键**。(可调用候选 —— date/timestamp —— 不派生。)
PARAM_SEMANTICS_V45 = {
    **{k: v[0] for k, v in PARAM_SEMANTICS.items() if v and not callable(v[0])},
    # ---- V45 独有键(驼峰/单数形态 · 时间区间) ----
    'cursor': '0',
    'order_id': '1001', 'product_id': '1001', 'room_id': '1001', 'article_id': '1001',
    'userId': '1', 'orderId': '1001', 'productId': '1001',
    'articleId': '1001', 'roomId': '1001', 'categoryId': '1',
    'tagId': '1', 'roleId': '1', 'deptId': '1', 'postId': '1001',
    'createTime': '2024-01-01', 'updateTime': '2024-01-01',
    'startTime': '2024-01-01', 'endTime': '2024-12-31',
    'pageNum': '1', 'pageSize': '20', 'pageNo': '1',
    'currentPage': '1', 'pageIndex': '1',
}


# "URL + {对象} → POST" 启发式的前置**读式调用**护栏(见 _extract_api_calls):
#   · `.get/.getJSON/.head/.options(` —— 第二参是 config(非请求体);
#   · 裸 `fetch(` —— fetch 在 init 无 `method` 时**规范默认 GET**(显式 method 由 fetch_method 模式另判)。
#   二者都不该按 POST 处理: 判 POST 会把读端点归入 write_apis 而**不探活**(漏探)。
_PRECEDING_READ_CHAIN = re.compile(r'(?:\.(?:get|getJSON|head|options)|\bfetch)\s*$', re.I)


# ---------- JS 内部再引用的 JS 文件 ----------
# 兼容 `.mjs` —— webpack `output.module`(ESM)/Vite 会产出 `.mjs` chunk,
#   旧后缀只认 `.js`, 于是 ESM 产物**一个都抓不到**。
_JS_SUFFIX = r'\.(?:m)?js(?:\?[^"\']*)?'


_JS_REF_PATTERNS = (
    # import x from './a.js'  /  import './a.js'  /  import {a,b} from "./a.js"
    re.compile(r'''\bimport\s+(?:[\w${},*\s]+?\s+from\s+)?["']([^"']+''' + _JS_SUFFIX + r''')["']'''),
    # 动态 import('./a.js')  —— 引号串形态(双/单引号)
    re.compile(r'''\bimport\s*\(\s*["']([^"']+''' + _JS_SUFFIX + r''')["']'''),
    # 动态 import(`./a.js`) / import(`./${h}.js`) 模板串形态(引号串形态覆盖不到)。
    #   排除 `${...}` 插值(`./x.${h}.js` 非真实文件名, 抓取必 404); 仅收字面量 chunk 名。
    re.compile(r'''\bimport\s*\(\s*[`"']([^`"'$}{]+''' + _JS_SUFFIX + r''')[`"']'''),
    # require('./a.js')
    re.compile(r'''\brequire\s*\(\s*["']([^"']+''' + _JS_SUFFIX + r''')["']'''),
    # new Worker('./w.js') / new SharedWorker('./w.js')
    re.compile(r'''new\s+(?:Shared)?Worker\s*\(\s*["']([^"']+''' + _JS_SUFFIX + r''')["']'''),
    # webpack/vite chunk 映射表里的字面量: "1234.abcd.js" / "./chunk-x.js" / "/static/js/x.js"
    re.compile(r'''["']((?:\./|\.\./|/)?[\w./\-]+''' + _JS_SUFFIX + r''')["']'''),
)


# 单文件最多接受多少个 JS 引用, 防止极端产物(数千个 chunk 名)把队列撑爆
MAX_JS_REFS_PER_FILE = 120


# ---------- WebAssembly 二进制字符串提取(§3.7-G2) ----------
# 背景: Blazor / emscripten / wasm 前端里, 接口路径 / URL 常硬编码进 .wasm 二进制
#   (而非 JS 文本), 旧实现对 .wasm 完全无通道 → 这类靶场的端点盲区。
# 合规不变: 仅对 .wasm 做**只读 GET** + **字符串扫描**, 不执行任何 wasm 代码。
# 引用发现: 在 JS / HTML 文本里抓 `.wasm` 字面量引用(import / fetch / preload / URL)。
_WASM_REF_RE = re.compile(r'''['"]([^'"]*?\.wasm)['"]''')


_MAX_WASM_REFS = 16


# 二进制可打印串 + URL / 路径形态过滤
_WASM_PRINTABLE = re.compile(r'[\x20-\x7e]{6,}')


_WASM_URL_RE = re.compile(r'(?:https?|ws|wss)://[^\s"\'<>()\\]+', re.I)


_WASM_PATH_RE = re.compile(r'/[A-Za-z0-9._\-/~%]+(?:/[A-Za-z0-9._\-/~%]+)+')


_WASM_PATH_HINT = re.compile(
    r'^(?:/api|/rest|/graphql|/gateway|/rpc|/service|/services|/v\d|/data'
    r'|/backend|/server|/app|/auth|/admin|/user|/users|/internal|/public)/', re.I)


# ---------- webpack runtime chunk 枚举 (JSONP / import 两种加载模式) ----------
# 背景: 旧实现只能发现"chunk 名恰好是完整字面量"的情况(如 `n.u=t=>"admin.chunk.js"`)。
#   而主流 webpack 多 chunk 产物里, chunk 文件名是**运行时拼出来的**:
#     JSONP 模式: n.u = t => "static/js/" + t + "." + {1:"a1b2",2:"c3d4"}[t] + ".js"
#                 (由 __webpack_require__.p 拼 publicPath, <script src> 注入)
#     import 模式: 同上 .u, 但经 n.l=(url,done)=>{import(url)} 加载 (webpack5 chunkLoading:'import')
#   这类产物里 chunk 的完整文件名**从不以字面量出现** → 旧实现一个 chunk 都枚举不出。
# 本函数从 runtime 里还原: ① `.u` 命名模板 ② chunkId→hash 映射表 ③ chunkId 集合
#   (installedChunks 键 / `.e(N)` 调用) ④ publicPath `.p`; 并识别加载模式。
# chunkId 可为**数字**(deterministic id) 或**具名字符串**(`chunkIds:'named'`: `{app:"a1b2",admin:"c3d4"}`) ——
#   旧实现只认数字 → 具名 chunk **整类漏掉**。此处接受 `[\w$]+`(数字/标识符/引号包裹的名字)。
_RE_WP_IDMAP = re.compile(r'["\']?([\w$]+)["\']?\s*:\s*["\']([^"\']+)["\']')


# 形态 D: 内联映射表(压缩产物无 `.u` 命名函数时, chunk 表被内联进 <script src> 构造处)
#   匹配 `.p + <可选前缀字面量> + {id:"hash",...} + [<下标表达式>] + "<后缀字面量>"`
#   例: script.src=function(e){return d.p+""+{0:"f60144a",1:"4acc83d"}[e]+".js"}
#   具名组: pre=可选前缀字面量 / id=可选 chunkId 操作数 / mid=可选中间字面量(如 ".") / map=映射表体 / suf=后缀。
#   模板可为 `前缀 + {map}[id] + 后缀` 或 `前缀 + id + "." + {map}[id] + 后缀`(含 id)。
_RE_WP_INLINE_MAP = re.compile(
    r'\.p\s*\+\s*'
    r'(?:["\'](?P<pre>[^"\']*)["\']\s*\+\s*)?'
    r'(?:(?P<id>[A-Za-z_$][\w$]*)\s*\+\s*)?'
    r'(?:["\'](?P<mid>[^"\']*)["\']\s*\+\s*)?'
    r'\{(?P<map>[^{}]{2,8000})\}\s*\[[^\]]{0,40}\]\s*\+\s*'
    r'["\'](?P<suf>[^"\']*)["\']',
    re.S)


# 属性值引号可选(压缩 HTML 常去引号) —— 三个分支覆盖 双引号/单引号/无引号。
#   `hx-*` = **htmx** 的请求 URL 属性(`hx-get/post/put/patch/delete`)。htmx 站点把接口写在
#   这些属性里(常见于 `<button>`/`<div>`, 无 `href`/`action`) —— 不收则**整类端点漏提取**
#   (htmx 指纹本身能识别, 但其端点此前从不被提取 = "识别了栈却没提取其端点")。
#   `hx-*` 只出现在 htmx 站点, 故对非 htmx 站点零误报; 跨域值仍由 `_extract_html_apis` 的同源护栏拦截。
_HTML_ATTR_OPT = re.compile(
    r'''\b(action|href|formaction|data-url|data-href|data-api|hx-get|hx-post|hx-put|hx-patch|hx-delete)\s*=\s*'''
    r'''(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))''', re.I)


# ---- 表单字段 / 隐藏域 / HTML 注释提取 ----
# 服务端渲染栈(Django/Rails/Laravel/Spring MVC/ASP.NET/PHP)的接口参数写在
#   <form><input name=...> 里, 隐藏域(type=hidden)常带 CSRF token / API key / 签名,
#   HTML 注释常泄露端点 / 凭据 / 调试信息 / TODO。
# 旧实现只从 HTML 取 action/href 端点(见 _extract_html_apis), 完全漏掉:
#   · 表单字段名 → 不进入 out['params'], idor/sqli 阶段看不到这些参数;
#   · 隐藏域里的敏感值 → 不进敏感扫描;
#   · HTML 注释正文 → 不进敏感扫描(RE_API 虽能扫到注释里的端点, 但不扫敏感)。
# 这正是 phantom / FindSomething 的共识能力, 补上。
_FORM_OPEN_RE = re.compile(r'<form\b', re.I)


_FORM_BLOCK_RE = re.compile(r'<form\b.*?</form>', re.I | re.S)


_FORM_FIELD_RE = re.compile(r'<(input|textarea|select)\b[^>]*>', re.I)


_FORM_ACTION_RE = re.compile(
    r'\baction\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+))', re.I)


_NAME_ATTR_RE = re.compile(
    r'\bname\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+))', re.I)


_TYPE_ATTR_RE = re.compile(
    r'\btype\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+))', re.I)


_VALUE_ATTR_RE = re.compile(
    r'\bvalue\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+))', re.I)


_FORM_ID_RE = re.compile(
    r'\bid\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+))', re.I)


# --- JS 数据流关联: 表单字段 → `new FormData(form)` → `Object.fromEntries(...)` → 请求体 → 端点 ---
#   **只认"变量赋值链"这一代码依据**, 不做任何猜测; 歧义(一表单喂多端点)由调用方放弃关联。
_JS_FORM_VAR_RE = re.compile(
    r'(?:const|let|var)\s+(\w+)\s*=\s*document\.(?:getElementById|querySelector)\(\s*'
    r'(?:"#?([\w\-:.]+)"|\'#?([\w\-:.]+)\')\s*\)')


_JS_FORMDATA_VAR_RE = re.compile(
    r'(?:const|let|var)\s+(\w+)\s*=\s*new\s+FormData\(\s*(\w+)\s*\)')


_JS_FROMENTRIES_VAR_RE = re.compile(
    r'(?:const|let|var)\s+(\w+)\s*=\s*Object\.fromEntries\(\s*(\w+)\.entries\(\)\s*\)')


_JS_BODY_FETCH_RE = re.compile(
    r'\b(?:fetch|axios(?:\.\w+)?)\(\s*(?:"([^"]+)"|\'([^\']+)\'|`([^`]+)`)'
    r'[^;]{0,500}?\bbody\s*:\s*(?:JSON\.stringify\(\s*)?(\w+)', re.S)


_JS_AXIOS_BODY_RE = re.compile(
    r'\baxios\.(?:post|put|patch)\(\s*(?:"([^"]+)"|\'([^\']+)\')\s*,\s*(\w+)')


_HTML_COMMENT_RE = re.compile(r'<!--(.*?)-->', re.S)


# ---- 可选密钥实时验证(默认关, 对齐 trufflehog) ----
# 正则命中的密钥可能是示例/占位/已吊销。对部分云密钥做**只读**验证请求, 确认真实有效,
# 把"疑似泄露"升级为"已确证泄露"(CRITICAL), 把"无效"降级为 INFO(疑似误报)。
# 默认关闭: 开启会向第三方(api.github.com 等)发包, 需显式开启 verify_secrets + 合规告警。
# 合规红线: 只发 GET/POST 只读端点, 不修改任何远端资源; 完整密钥仅驻留内存, 不落报告/磁盘。
_SECRET_PROVIDERS = {
    # provider: (method, url, {header: 含 {v} 模板}, {status_code: 结论})
    'github':    ('GET',  'https://api.github.com/user',
                  {'Authorization': 'Bearer {v}'}, {200: 'valid', 401: 'invalid'}),
    'gitlab':    ('GET',  'https://gitlab.com/api/v4/user',
                  {'PRIVATE-TOKEN': '{v}'}, {200: 'valid', 401: 'invalid'}),
    'slack':     ('POST', 'https://slack.com/api/auth.test',
                  {'Authorization': 'Bearer {v}'}, {200: 'valid'}),
    'stripe':    ('GET',  'https://api.stripe.com/v1/charges?limit=1',
                  {'Authorization': 'Bearer {v}'}, {200: 'valid', 401: 'invalid'}),
    'openai':    ('GET',  'https://api.openai.com/v1/models',
                  {'Authorization': 'Bearer {v}'}, {200: 'valid', 401: 'invalid'}),
    'anthropic': ('GET',  'https://api.anthropic.com/v1/models',
                  {'x-api-key': '{v}', 'anthropic-version': '2023-06-01'},
                  {200: 'valid', 401: 'invalid'}),
    'npm':       ('GET',  'https://registry.npmjs.org/-/npm/v1/user',
                  {'Authorization': 'Bearer {v}'}, {200: 'valid', 401: 'invalid'}),
    'sendgrid':  ('GET',  'https://api.sendgrid.com/v3/user/profile',
                  {'Authorization': 'Bearer {v}'}, {200: 'valid', 401: 'invalid'}),
    'heroku':    ('GET',  'https://api.heroku.com/account',
                  {'Authorization': 'Bearer {v}',
                   'Accept': 'application/vnd.heroku+json; version=3'},
                  {200: 'valid', 401: 'invalid'}),
}


# 规则名 -> provider (None = 无法只读验证, 记 unknown)
_RULE_TO_PROVIDER = {
    'GitHub-PAT': 'github', 'GitLab-PAT': 'gitlab',
    'Slack-Token': 'slack', 'Slack-AppToken': 'slack',
    'Stripe-APIKey': 'stripe', 'Stripe-Restricted': 'stripe',
    'Stripe-WebhookSecret': None,   # 签名密钥无法只读验证
    'OpenAI-APIKey': 'openai', 'Anthropic-APIKey': 'anthropic',
    'npm-Token': 'npm', 'SendGrid-APIKey': 'sendgrid', 'Heroku-APIKey': 'heroku',
}


# ---- 构建清单下载与解析 ----
# 一份 asset-manifest.json / build-manifest.json 就能**直接枚举全部打包产物**,
# 比逐个猜 chunk 路径高效得多(且能发现"从未被引用"的 chunk)。
_BUILD_MANIFEST_PATHS = [
    '/asset-manifest.json',        # CRA / webpack
    '/build-manifest.json',        # Next.js (pages)
    '/app-build-manifest.json',    # Next.js (app router)
    '/_buildManifest.js',          # Next.js (pages, JS 形态; 此前内联于 html_extract, 审计 S9)
    '/_ssgManifest.js',            # Next.js (SSG, JS 形态)
    '/precache-manifest.js',       # Workbox precache
    '/manifest.json',              # PWA 清单(常含入口 JS)
    '/webpack.stats.json',         # webpack stats: 完整模块图
    '/stats.json',
    '/.vite/manifest.json',        # Vite 构建清单
    '/vite-manifest.json',
]


# JS 形态的清单(非 JSON): 只在正文含这些标记时才按正则提取, 避免把普通 JS 当清单。
_JS_MANIFEST_MARKERS = ('__BUILD_MANIFEST', '__SSG_MANIFEST', 'precacheManifest',
                        '__vite__mapDeps', 'webpackChunk', 'self.__next_f')


# ---------- 页面类型分类 + 软 404 / catch-all 增强 ----------
# 页面类型词汇由 `guard.classify_page()` 的返回值定义(该模块即单一真源)。


# 前端框架指纹关键词(命中即视为 SPA 信号)。
_SPA_FP_HINTS = ('react', 'vue', 'angular', 'svelte', 'next.js', 'nuxt',
                 'ember', 'backbone', 'preact', 'solid', 'alpine')


# 正文 simhash 近重复阈值(64-bit 汉明距离)。<=10 视为"高度相似"。
#   取 10 在两者间留足余量。注意: 本函数只用于**随机/不存在路径**的聚合, 这些路径本应无内容,
#   任何相似性都指向泛化回退页, 故阈值可放宽(低误报风险)。
SIMHASH_NEAR_HAMMING = 10


# 参与 simhash 比对的最小正文长度(过短正文 simhash 不可靠, 交给精确 body_fp)
SIMHASH_MIN_LEN = 64


_DQ = r'"[^"\\]*(?:\\.[^"\\]*)*"'  # 双引号字符串字面量(标准稳健转义处理)


_SQ = r"'[^'\\]*(?:\\.[^'\\]*)*'"  # 单引号字符串字面量


_LIT = _DQ + r'|' + _SQ             # 任意引号字符串字面量


_IDENT = r'[A-Za-z_$][\w$]*'


# 单个操作数(字面量 | 标识符) —— 非重复匹配, 由调用方手动串接 + 链, 规避正则引擎
# 在 "(LIT|IDENT)(?:\+\s*(LIT|IDENT))+" 这类"重复组内含交替"结构上的回溯退化(实战中
# 3 操作数链只匹配出 2 个, 数组 join 直接空匹配)。改用 tokenize-and-walk 彻底绕开。
_OPERAND_RE = _re.compile(r'(' + _LIT + r'|' + _IDENT + r')')


_REGEX_PREV_CHARS = set('(,=:[!&|?{};+-*%~^<>')


_REGEX_PREV_WORDS = frozenset((
    'return', 'typeof', 'case', 'in', 'of', 'new', 'delete', 'void',
    'instanceof', 'do', 'else', 'yield', 'await',
))


# 前端路由跳转的调用标记 —— 紧邻拼接链之前时, 该链是**导航目标**而非接口。
# 为什么需要: `this.$router.push("/pay/confirm?good-ids=0-".concat(t.id))` 里的路径
#   与真实接口在**形态上完全一样**(都是 `/x/y`), 用形态/字符集都区分不了 ——
#   唯一可用的信息是**调用语境**。
# 实测: 该写法在 12 个 chunk 里各产出一条假接口(`/pay/confirm?...`),
#   并让 apis 里混入 48 条非 `/api/` 前缀的前端路由(占 apis 总量的 28%)。
_NAV_CALL_RE = _re.compile(
    r'(?:\$?router|\$route)\s*\.\s*(?:push|replace|resolve)\s*\(\s*$'
    r'|\b(?:navigateTo|redirectTo|switchTab|reLaunch)\s*\(\s*\{\s*url\s*:\s*$'
    r'|(?:\bwindow\s*\.\s*)?\blocation\s*'
    r'(?:\.\s*(?:assign|replace)\s*\(\s*|\.\s*href\s*=\s*)$'
    r'|\bhistory\s*\.\s*(?:pushState|replaceState)\s*\([^)]{0,60}$'
    # 组件式导航: `<nuxt-link :to="/x">` / `<router-link :to="/x">` / `<a :href="/x">`
    #   渲染函数里长这样: `attrs:{to:"/actual-course/".concat(id),target:"_blank"}`
    #   —— 实测这是本站剩余路由产物的**主要来源**(其余 19 条几乎全来自此处)。
    r'|\b(?:to|href)\s*:\s*$'
)


# 集中式 API map 静态对象值通道 (`key:"/path"`)
# Vue/Nuxt 项目极常见的 `api/index.js` 导出对象, 形如:
#     export default { commentList:"/comment/list", payBuild:"/payment/pay/build", ... }
# 调用点用 `api.commentList` 属性访问(而非字面量), 故:
#   · `_extract_api_calls`(fetch/axios) 抓不到(参数是属性访问, 不是字符串字面量);
#   · `_extract_struct_apis` 只处理 `+`/`.concat()`/join/标识符调用, 不处理纯对象值;
#   · `RE_API` 要求 `/api|rest|...` 前缀或 `.do` 后缀, `/comment/list` 这类无前缀
#     REST 资源/动作路径会被 `_is_api_path` 拒。
# 三条通道全部漏掉 → 实测 open.medsci.cn 因此漏 18 条真实接口(占该站声明接口的 60%)。
# 本通道专门补这个洞: 提取 `KEY:"/path"` 静态对象值, 用"方法名键(camelCase) 或
# 服务端脚本后缀"作为 API-map 判别信号(与路由/配置对象用 `path:`/`component:` 等保留键区分)。
_API_MAP_RESERVED = frozenset({
    # 路由/配置对象保留键(这些键的值即使像路径也是路由/配置, 不是接口)
    'path', 'name', 'redirect', 'redirectto', 'component', 'components', 'alias',
    'meta', 'children', 'element', 'elements', 'to', 'href', 'src', 'icon', 'title',
    'id', 'class', 'view', 'default', 'props', 'beforeenter', 'exact', 'casesensitive',
    'link', 'active', 'tag', 'target', 'rel', 'style', 'role', 'key', 'ref', 'width',
    'height', 'type', 'value', 'placeholder', 'label', 'alt', 'for', 'slot', 'from',
    # 配置/基址类键(值通常是 baseURL 或调用配置, 不是端点)
    'url', 'action', 'method', 'baseurl', 'base', 'endpoint', 'axios', 'http', 'api',
})


# `KEY:"/path"` 对象值匹配(值须以 `/` 开头、不含空白/括号/尖括号)
_API_MAP_KEY_RE = re.compile(r'([A-Za-z_$][\w$]*)\s*:\s*["\'](/[^"\'\s{}()<>]+)["\']')


# 方法名 camelCase 信号: 至少一处 小写→大写 过渡(如 getUserDetail / createOrder / payBuild)
_API_MAP_CAMEL_RE = re.compile(r'[a-z][A-Z]')


# 服务端脚本端点后缀 —— 即使无 `/api` 前缀也是动态接口
_API_MAP_SRV_EXT = re.compile(r'\.(do|php|asp|aspx|jsp|cgi|action|ashx|jsonp?)$', re.I)


# 集群阈值: 同一文件内出现 ≥ 此数的非保留键 `key:"/path"` 即视为"集中式 API map 模块"。
#   生产构建里键被 uglify 成单字母, 不能靠 camelCase 判别, 故用集群信号兜底;
#   路由/配置对象用 `path:`/`component:`/`icon:` 等保留键, 不会出现 ≥3 条非保留键路径值。
_API_MAP_CLUSTER = 3


# 变量声明形态: `const c="/comment/list",d="/comment/send",h="/comment/like",f="/comment/reply-list"`
#   —— 同样是 API map, 只是用多声明符变量语句而非对象字面量。wepback 压缩产物里这种
#   形态不少见。单条 `const/var/let` 语句内出现 ≥2 条路径声明即视为 API map(单条语句
#   集群, 避免污染巨型 runtime 包的跨语句计数)。
_API_MAP_VAR_DECL_RE = re.compile(r'\b(?:const|var|let)\s+[^;{]+')


_API_MAP_VAR_ITEM_RE = re.compile(r'([A-Za-z_$][\w$]*)\s*=\s*["\'](/[^"\'\s{}()<>]+)["\']')


# "HTTP 200 + 业务码未授权" —— 国内 API 极常见的约定:
#   鉴权失败时**仍回 200**, 只用 body 里的 `{"code":401,"msg":"请先登录"}` 表达。
#   若只看 HTTP 状态码, 会把**受保护的接口**误判成"管理接口可达"(实测自建目标
#   /api/admin/logs 就是这样被报成 MED 可达, 而它实际要求登录)。
_UNAUTH_MARKERS = (
    '请先登录', '请登录', '请重新登录', '未登录', '未授权', '登录已过期', '登录失效',
    '登录状态失效', '无权限', '没有权限', 'unauthorized', 'not logged in',
    'please login', 'login required', 'invalid token', 'token 无效', 'token无效',
    '未提供凭证', '认证失败',
)


# 裸标记判定的**长度上限**：业务码未授权多为**短消息体**（`{"code":401,"msg":"请先登录"}`）；
#   长页面里"unauthorized"出现在**散文**中不算（实测 testaspnet.vulnweb.com 一篇 22KB 新闻页
#   因正文含 "Unauthorized access detection for Redis…" 被误判为"鉴权接口存在"）。
_UNAUTH_MARKER_MAXLEN = 800


# ---- 形态族: 真实站点常按路径前缀分响应形态(/api/* 走 JSON、其余走 HTML) ----
#   对这些前缀**分别建 catch-all 基线**, 否则"该前缀族的通用响应"会被误判为命中
#   (实测 open.medsci.cn: 根 canary→404 HTML, 但 /api/* → 200 通用 JSON, 单基线覆盖不到)。
_API_REGIME_SEGMENTS = frozenset({
    'api', 'rest', 'graphql', 'gql', 'rpc', 'gateway', 'service', 'services',
})


_REGIME_MAX = 6          # 最多为几个额外形态族建基线(防请求膨胀)


# 登录页路径特征(重定向目标) —— 用于识别"存在但需登录"的路径(不是"暴露")。
_LOGIN_PATH_RE = re.compile(
    r'(?i)/(?:login|sign[-_]?in|signon|sign[-_]?on|auth|sso|cas|account/login|'
    r'user/login|users/sign_in|session/new|passport)')


# ---------- 探活 （缓存去重 + 聚类） ----------
_ALLOW_METHODS = ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT')


# 响应挖掘(方案 2-B): 正文里的"路径样"字面量 / 绝对 URL —— 只挖, 由调用方决定是否回灌
_RE_MINE_PATH = re.compile(r'''["'`(=\s,](/[A-Za-z0-9_\-./{}:]{3,120})''')


_RE_MINE_ABS = re.compile(r'https?://[A-Za-z0-9._\-]+(?::\d+)?(/[A-Za-z0-9_\-./{}:]{1,120})')


_SECRET_RULES_CACHE = {}


# ---------- 深度侦察主入口 ----------
# ---------- 步骤0: 被动打点  ----------
# 对照真实渗透测试的"前期打点"流程, 有一批**零/低成本、高确定性**的标准动作此前完全缺失:
#   · robots.txt / sitemap.xml —— 目标**主动公开**的路径清单, 是最合规的资产发现手段,
#     而且是唯一"目标自己告诉你有哪些路径"的渠道。缺了它, 资产面只能靠猜。
#   · security.txt            —— 安全联系人, 影响报告投递与合规流程(GB/T 与 ISO 都要求)。
#   · favicon.ico 哈希        —— 配合 Shodan/Fofa 可反查同源资产与已知产品版本。
#   · 安全响应头审计          —— **零额外请求**(直接复用主页响应头), 但直接反映配置成熟度,
#     且 HSTS/CSP/X-Frame-Options 的缺失本身就是可报告的发现项。
# 这些步骤不依赖指纹, 因此在指纹探测(步骤1)之前执行, 发现的路径并入后续探活集合。

SECURITY_HEADERS = [
    ('Strict-Transport-Security', '存在 SSL 剥离 / 中间人降级风险', 'MED', True),
    ('Content-Security-Policy',   'XSS 缺乏纵深防御', 'MED', False),
    ('X-Frame-Options',           '存在点击劫持风险', 'MED', False),
    ('X-Content-Type-Options',    '存在 MIME 类型嗅探风险', 'LOW', False),
    ('Referrer-Policy',           '可能向第三方泄露完整 URL', 'LOW', False),
    ('Permissions-Policy',        '浏览器特性未收敛', 'INFO', False),
]


# 末位 True 表示"仅 HTTPS 目标才审计"(HTTP 站点上谈 HSTS 没有意义)

INFO_LEAK_HEADERS = [
    ('Server',              '暴露服务端软件与版本'),
    ('X-Powered-By',        '暴露后端技术栈'),
    ('X-AspNet-Version',    '暴露 .NET 版本'),
    ('X-AspNetMvc-Version', '暴露 ASP.NET MVC 版本'),
]


# ROUTE_ENTRY_GUESSES 已迁至 core/dicts.py(经 `from .dicts import *` 一并引入),
#   供 engine._harvest_route_entry_js(静态通道) 与 recon.runtime(运行时导航) 共用,
#   单一来源、避免重复定义。此处不再重复声明。

# 非英文正文/CJK 探测 —— 用于决定是否追加"本地化入口页猜测"(避免英文站白跑一堆 404)。
_NON_LATIN_RE = re.compile(r'[\u3040-\u30ff\u3400-\u9fff\u0400-\u04ff\uac00-\ud7af]')


# 开发服务器指纹(方案六): 命中则**强制低并发 + 加大请求间隔** ——
#   这类服务器(Flask dev/Werkzeug、python -m http.server、webpack-dev-server…)多为单线程,
#   正常速率就能把它打挂 → 数据不全甚至污染结论。仅**降速**、不减覆盖。
_DEV_SERVER_HINTS = ('werkzeug', 'simplehttp', 'webpack-dev-server', 'browsersync',
                     'uvicorn', 'hypercorn', 'waitress', 'cherrypy', 'tornado')
