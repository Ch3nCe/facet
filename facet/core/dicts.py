import re
from urllib.parse import urlsplit

"""facet 字典与配置常量(独立模块)"""

# 严重度词汇(单一事实来源)
#   内部统一用 {CRITICAL, HIGH, MED, LOW, INFO}; 外部源(OSV / GitHub Advisory /
#   内置漏洞表)常用 {CRITICAL, HIGH, MEDIUM, LOW} 或 {CRITICAL, HIGH, MODERATE, LOW}。
#   凡"外部严重度"进入本工具, 必须经 `norm_sev` 归一为内部词汇, 否则会在报告/导出间
#   出现 "MEDIUM" vs "MED" 的词汇分裂(实测: SCA 漏洞表显示 MEDIUM、严重度分布显示 MED)。
SEV_INTERNAL = ('CRITICAL', 'HIGH', 'MED', 'LOW', 'INFO')
SEV_SET = frozenset(SEV_INTERNAL)
# 外部严重度字符串 → 内部严重度(大小写不敏感、兼容 MEDIUM/MODERATE 等变体)。
_SEV_EXTERNAL = {
    'CRITICAL': 'CRITICAL', 'CRIT': 'CRITICAL', 'BLOCKER': 'CRITICAL',
    'HIGH': 'HIGH', 'MAJOR': 'HIGH',
    'MEDIUM': 'MED', 'MODERATE': 'MED', 'MED': 'MED', 'MINOR': 'MED',
    'LOW': 'LOW', 'MINOR_LOW': 'LOW', 'TRIVIAL': 'LOW',
    'INFO': 'INFO', 'INFORMATIONAL': 'INFO', 'NOTE': 'INFO',
}
# 所有被识别的严重度 token(内部 ∪ 外部同义词)。供 CLI/入口做**已知值校验**:
#   已知 → 经 norm_sev 归一; 未知 → **保持原样**(诚实 0 命中), 而非经 norm_sev 静默回落 'MED'
#   (后者会把 `--sev HIG`(拼错) 变成"返回 MED", 比"返回空"更误导)。
SEV_TOKENS = SEV_SET | frozenset(_SEV_EXTERNAL)


def norm_sev(s):
    """把任意(外部/大小写混杂)严重度字符串归一为内部词汇; 未知 → 回落 'MED'。

    单一归一入口: SCA / 自定义规则 / 任何外部严重度都走这里, 避免各消费点各写一套
    (旧实现里 `js_extract._sevmap` 与 `report.py` 的 `{'MEDIUM': 'MED'}` 一次性映射
    就是两套分散的归一逻辑, 导致 SCA 表的文本仍是原始 MEDIUM)。
    """
    return _SEV_EXTERNAL.get(str(s or '').strip().upper(), 'MED')


# 非首页"入口页"猜测清单 —— 这些页常加载与首页不同的 JS chunk(登录/后台/账户/仪表盘…),
# 纯 BFS 爬取(crawl_site 只跟随 <a>/<form>)抓不到(尤其 SPA / 网关后页面), 而它们常不在
# 首页静态 HTML 被链接。被动 GET(静态通道)或被浏览器导航(运行时通道)后, 提取其懒加载
# JS chunk 并入分析管线, 补齐"非首页才加载的 JS"缺口。
# 供 engine._harvest_route_entry_js(静态通道) 与 recon.runtime(运行时导航) 共用, 单一来源。
ROUTE_ENTRY_GUESSES = (
    'login', 'signin', 'signup', 'register', 'logout', 'password', 'reset',
    'dashboard', 'admin', 'manage', 'console', 'panel', 'control',
    'account', 'profile', 'settings', 'user', 'member', 'me', 'my',
    'app', 'search', 'cart', 'checkout', 'orders', 'messages',
    'notifications',
)

# 本地化"入口页"猜测 —— 非英文站点常用本地化命名(中文/日文/西/法/德/意/葡)。
#   仅当首页看起来非英文(见 engine._looks_non_english)时才加入, 避免英文站白跑一堆 404。
ROUTE_ENTRY_GUESSES_I18N = (
    '登录', '注册', '管理', '后台', '控制台', '账户', '个人中心', '设置', '仪表盘', '会员',
    'ログイン', 'アカウント', '設定',
    'ingresar', 'registro', 'cuenta', 'panel', 'administracion', 'ajustes',
    'connexion', 'compte', 'administration', 'parametres',
    'anmelden', 'konto', 'verwaltung', 'einstellungen',
    'accedi', 'conta', 'amministrazione', 'entrar', 'configuracoes',
)

# 全部入口猜测(供运行时导航复用) —— 英文 + 本地化。
ROUTE_ENTRY_GUESSES_ALL = ROUTE_ENTRY_GUESSES + ROUTE_ENTRY_GUESSES_I18N


def entry_like(path):
    """路径是否"形似入口页"(登录/后台/账户/仪表盘…, 含本地化命名)。

    供入口页收割**排序**: 真实首页链接里"像入口页"的优先抓(它们最可能藏接口/JS)。
    匹配按**路径段**进行, 避免短词误伤 —— 如 `me`/`my`/`app` 必须整段命中,
    否则 `/home`、`/comment`、`/time` 都会被 `me` 误判。
    """
    if not path:
        return False
    segs = [s for s in str(path).lower().split('/') if s]
    if not segs:
        return False
    for s in segs:
        for g in ROUTE_ENTRY_GUESSES_ALL:
            if len(g) >= 4:
                if g in s:                       # 长词: 子串即可(login.aspx / dashboard-v2)
                    return True
            elif s == g or s.startswith(g + '.') or s.startswith(g + '-'):
                return True                      # 短词: 需整段(或 . 后缀), 防误伤
    return False



# 接口路径前缀：不止 /api/。真实应用广泛使用 /rest、/graphql、/v1 等 ——
_API_PREFIX_ALT = r'(?:api|rest|graphql|gql|gateway|rpc|service|services|v\d+)'
RE_API = re.compile(r"['\"`](\/" + _API_PREFIX_ALT + r"\/[A-Za-z0-9_\-\/{}.:$\[\]]+)(?:\?[^\"'`]*)?['\"`]")

# JS 资源后缀(单一事实来源): 同时认 `.js` 与 `.mjs`(部分构建配置/现代打包产物用 .mjs)。
#   曾出现不一致: `_extract_bundler_chunks` 接受 .mjs, 但入队/入口正则只认 .js → .mjs chunk
#   枚举到却不被抓取分析。统一用本元组 + 正则里的 `\.(?:m)?js`。
JS_EXTS = ('.js', '.mjs')

# 属性值**引号可选**。旧实现要求 `src="..."`(带引号), 而压缩部署的
#   HTML shell(html-minifier 默认去引号)是 `<script src=/dist/main.js>`(合法 HTML5) →
#   RE_SRC 一个都不命中 → js_urls 为空 → **整条 JS 流水线(接口/路由/敏感/子域)全部空转**。
#   单捕获组: `["\']?` 吃掉可选引号, 未引号值按 HTML5 规则止于 空白/" ' ` = < >。
RE_SRC = re.compile(r'''src\s*=\s*["\']?([^"'\s=<>`]+\.(?:m)?js[^"'\s=<>`]*)''')

# <link rel="modulepreload" href> / <link rel="preload" as="script" href> 声明的 JS chunk。
#   SPA 常以此预加载路由懒加载包; 这些 .js 不在 <script src> 里, 单靠 RE_SRC 抓不到 ——
#   静态 GET 入口页即可拿到(无需浏览器导航), 故在 _harvest_route_entry_js 一并提取。
RE_LINK_JS = re.compile(r'<link\b[^>]*\bhref\s*=\s*["\']?([^"\'<>`\s]+\.(?:m)?js[^"\'<>`\s]*)', re.I)

RE_CHUNK = re.compile(r'["\'\(]([^"\')]{3,120}?\.(?:m)?js)["\'\)]')                # 任意JS引用(递归循环提取)
# 懒加载/动态脚本引用补充 (script.src=..., loadScript(...), import()中RE_CHUNK未覆盖的形态)
RE_LAZY = re.compile(r'''(?:script\.src\s*=\s*|\$?loadScript\s*\(\s*)["\']([^"\']+\.(?:m)?js[^"\']*)["\']''', re.S)

SECMAP = [('未鉴权敏感面', ['internal', 'debug', 'test', 'env', 'config', 'backup', 'install', 'actuator', 'swagger', 'api-docs', 'docs', 'druid', 'trace', 'health', 'status', 'dump', 'info']),
          ('管理运维面', ['admin', 'manage', 'console', 'ops', 'audit', 'deploy', 'monitor', 'job', 'task', 'cron', 'supervisor', 'reset']),
          ('认证会话面', ['auth', 'login', 'logout', 'register', 'token', 'captcha', 'sso', 'oauth', 'password', 'session', 'sms']),
          ('身份PII面', ['user', 'member', 'profile', 'person', 'customer', 'employee', 'account', 'staff', 'id']),
          ('资金交易面', ['pay', 'order', 'refund', 'wallet', 'trade', 'recharge', 'withdraw', 'balance', 'coupon', 'points', 'bill', 'settle', 'finance']),
          ('文件传输面', ['upload', 'download', 'file', 'export', 'import', 'attachment', 'oss', 'media', 'image']),
          ('开放接口面', ['open', 'webhook', 'callback', 'gateway', 'third', 'app', 'mini'])]

SKELETON = {'api', 'apis', 'rest', 'v1', 'v2', 'v3', 'service', 'services', 'controller', 'handler', 'index.php', 'api.php', 'index', 'common', 'public', 'static'}

RE_ROUTE = re.compile(r'path\s*:\s*[\'"`](\/[A-Za-z0-9_\-\/:]*)[\'"`]')          # Packer-Fuzzer: 前端路由

RE_BASEURL = re.compile(r'baseURL\s*:\s*[\'"`]([^\'"`]+)[\'"`]')                # baseURL智能识别

RE_PARAM = re.compile(r'[?&]([A-Za-z_][A-Za-z0-9_]*)=')                          # LinkFinder: 参数名

# 从 JS 文本提取"真实" query 参数名。
#   (真参数来自另外两条通道: `params:{…}` 与 `useParams` 解构 —— 它们不受影响。)
# 判据(三层, 都满足才算 query 参数):
#   1. 命中必须位于**字符串字面量**内;
#   2. 该字面量必须是 **URL 形态** —— 内容以 `/` 或 `?` 或 `http` 开头, 或含 `://`;
#   3. `=name=` 之后的**值**必须是"简单原语"(`a=1` / `?q=hello` / `?id=${id}`),
#      不得含 `( ) , : ; < > [ ] + *` 等代码符号 —— 否则这是 `?f=f.slice(0,-1)` 这类代码。
#      (第二版只靠"前缀全 URL 合法字符"过滤, 被 `oe.ParamRegExp` 骗过; 第三版只靠"以 `?` 开头"
#       过滤, 又被 `"?n=oe.ParamRegExp:…` 骗过。值形态判定是最后一道、也是最关键的一道。)
_STR_LIT = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|`(?:[^`\\]|\\.)*`', re.S)
_URL_SHAPED = re.compile(r'^(?:https?://|/|\?)|://')
# 值允许的字符(排除所有代码符号); `://` 折叠后判定, 故 http(s):// 的值不被 `:` 误伤。
_VAL_OK = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
              '0123456789_./-~%${}')

def param_names_from_text(text):
    """从 JS 文本提取 query 参数名(只在 URL 形态字面量内、且值为简单原语时匹配)。"""
    found = set()
    if not text:
        return found
    for lit in _STR_LIT.finditer(text):
        seg = lit.group(0)
        inner = seg[1:-1]
        if not _URL_SHAPED.search(inner):
            continue                                       # 非 URL 形态 → 代码, 跳过
        for m in RE_PARAM.finditer(seg):
            i = m.start()
            if seg[i] == '&' and i > 0 and seg[i - 1] == '&':
                continue                                   # `&&name=` 是逻辑与
            # 取值: 从 `=` 之后到下一个 `&` 或字面量结尾(闭引号前)
            end = seg.find('&', m.end())
            if end == -1:
                end = len(seg) - 1
            val = seg[m.end():end].replace('://', '')
            if all(c in _VAL_OK for c in val):
                found.add(m.group(1))
    return found
# 旧正则为 `\?([A-Za-z_]\w*)=`, 只匹配 `?` 之后的**第一个**参数 ——
#   `?status=1&page=2&size=10` 只能提取到 `status`, `page`/`size` 全部丢失,
#   直接压缩了后续 idor / sqli 的参数探测范围。改为 `[?&]` 后可提取全部参数。

RE_CONCAT = re.compile(r'[\'"`]([^\'"`]{2,60})[\'"`]\s*\+')                     # 转子女神: 拼接重组

RE_CONCAT2 = re.compile(r'\+\s*[\'"`]([^\'"`]{2,60})[\'"`]')

RE_GRPC = re.compile(r'[\'"`](\/[A-Za-z][A-Za-z0-9_.]*\.[A-Z][A-Za-z0-9]*\/[A-Za-z][A-Za-z0-9_]*)[\'"`]')  # gRPC-Web方法路径

SENSITIVE_FIELDS = ['id_card', 'idcard', 'phone', 'mobile', 'real_name', 'password', 'token', 'secret', 'email', 'balance']

# ---------- 脱敏（已整体移除） ----------
# 本工具**不再对提取到的任何内容做脱敏/打码**（硬编码证据、端点 URL query 一律原样输出）。
# 原 `mask_evidence` / `set_mask_disabled` / `mask_disabled` / R8 逃生门 均已删除。


# API 描述文档（OpenAPI/Swagger/JSON-Schema）后缀 —— 用于**抑制结构性误报**：
#   这类响应是"接口描述"而非业务数据，其中 email/password 多为文档联系人 / 字段示例；
#   对它们跑 PII 字段扫描是误报（实测 Petstore `/v2/swagger.json` 被误判为"敏感数据过度暴露"）。
#   注意：结构化机密（mysql://、云 AK 等）**不受此影响**，文档里出现即真泄露。
_API_DOC_SUFFIXES = ('swagger.json', 'openapi.json', 'swagger.yaml', 'swagger.yml',
                     'openapi.yaml', 'openapi.yml', 'api-docs', 'schema.json')


def is_api_doc_path(path):
    """路径是否为 API 描述文档（OpenAPI/Swagger/JSON-Schema）。见 `_API_DOC_SUFFIXES`。"""
    p = (path or '').split('?')[0].rstrip('/').lower()
    return bool(p) and any(p.endswith(s) for s in _API_DOC_SUFFIXES)



RE_API_FULL = re.compile(r'[\'"`](https?://[A-Za-z0-9.\-]+/(?:api|v\d+)[A-Za-z0-9_\-\/{}.:$\[\]]+)[\'"`]')  # 完整URL形态: https://api.xxx.com/v1/...
RE_API_V = re.compile(r'[\'"`](\/v\d+\/[A-Za-z0-9_\-\/{}.:$\[\]]+)[\'"`]')  # 相对路径变体: /v1/...

# ==================== 新增: 通用 API 路径提取 ====================
# 背景: 旧实现的「读取路径」提取只有两条路 ——
#   · RE_API     —— 强制要求路径以 `/api/` 开头
#   · RE_AXIOS   —— 强制要求 `对象.方法('...')` 链式写法
# 而 `fetch()` / `$.ajax` / `xhr.open` 的处理只存在于 `_extract_write_text_v45`
# (写方法提取), 且 `xhr.open` 分支还额外要求方法属于 POST/PUT/DELETE/PATCH。
# 结果实测 12 条真实 API 路径丢失 5 条, 全部是普通 GET 接口:
#   fetch('/rest/service/list') / fetch(`/gateway/user/${id}`) /
#   $.ajax({url:'/manage/dept/list'}) / fetch('/v2/inventory/items') /
#   fetch('/order/query?status=1&page=2&size=10')
# 下面这组正则按**调用点**提取路径, 不再要求 `/api/` 前缀, 并保留 HTTP 方法线索。

# 静态资源后缀: 命中即判定"不是接口"
STATIC_ASSET_EXTS = (
    '.js', '.mjs', '.cjs', '.css', '.scss', '.less', '.sass',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.avif',
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
    '.map', '.mp4', '.mp3', '.webm', '.ogg', '.wav', '.pdf', '.zip', '.gz',
    '.ts', '.tsx', '.jsx', '.vue', '.md', '.txt',
)

# 服务端脚本扩展名: 传统服务端渲染端点(/login.jsp、/user.php、/x.do、/y.cgi)。
#   这些是**动态端点**, 不是静态资源; 单段也应保留(如 /index.jsp)。
SRV_EP_EXTS = (
    '.jsp', '.jspx', '.jspa', '.jsf', '.php', '.php3', '.php4', '.php5', '.phtml',
    '.asp', '.aspx', '.ashx', '.asmx', '.do', '.action', '.cgi', '.pl', '.py', '.rb',
    '.cfm', '.cfc', '.shtml',
)

# 纯静态目录前缀: 单层命中且无 API 关键词时判为静态资源
STATIC_DIR_PREFIXES = (
    '/static/', '/assets/', '/public/', '/images/', '/img/', '/css/', '/js/',
    '/fonts/', '/media/', '/dist/', '/build/', '/favicon', '/_next/static/',
    '/_nuxt/', '/@vite/', '/node_modules/',
)

# 路径中出现这些词 → 大概率是接口而非前端路由
API_HINT_WORDS = (
    'api', 'rest', 'service', 'gateway', 'graphql', 'grpc', 'rpc',
    'v1', 'v2', 'v3', 'v4', 'v5', 'v6',
    'admin', 'manage', 'manager', 'system', 'monitor', 'console', 'internal',
    'user', 'member', 'account', 'profile', 'order', 'goods', 'product', 'item',
    'auth', 'login', 'logout', 'token', 'captcha', 'sso', 'oauth',
    'upload', 'download', 'file', 'files', 'export', 'import',
    'list', 'query', 'search', 'page', 'detail', 'info', 'data', 'save',
    'add', 'edit', 'update', 'delete', 'remove', 'create', 'submit',
    'actuator', 'swagger', 'druid', 'wp-json', 'jsonapi', 'sys', 'tool',
    'callback', 'webhook', 'notify', 'pay', 'wallet', 'trade',
)

# 调用点模式表: (编译后的正则, 路径所在组, 方法所在组 or None)
#   方法组为 None → 该调用点无法从语法上判断方法, 默认按 GET 处理;
#   方法组为整数 → 从该组取方法名 (xhr.open('GET','/x') / $.post('/x') / .put('/x'))。
#   注意: 顺序有意义 —— 越靠前的模式越"具体"(带 method/type 的写法排在裸写法之前),
#   同一路径后写的模式不会覆盖先写的方法判定(见 core._extract_api_calls)。
API_CALL_PATTERNS = [
    # ---- 1. fetch 系列 ----
    # fetch('/x') / fetch(`/x`)
    (re.compile(r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']'), 1, None),
    # fetch(`/gateway/user/${id}`) —— 反引号模板串(上面那条的 [^`] 已能覆盖, 此处补 ${} 形态)
    (re.compile(r'fetch\s*\(\s*`([^`]+)`'), 1, None),
    # fetch('/x', {method:'POST'}) —— 方法在第二个参数里
    (re.compile(r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']\s*,\s*\{[^}]{0,300}?method\s*:\s*[`"\'](\w+)[`"\']', re.S), 1, 2),
    # ---- 2. jQuery 系列 ----
    # $.ajax({url:'/x', type:'POST'}) —— 带 type 的写法必须先于裸 url 写法
    (re.compile(r'\$\.ajax\s*\(\s*\{[^}]{0,400}?url\s*:\s*[`"\']([^`"\']+)[`"\'][^}]{0,400}?type\s*:\s*[`"\'](\w+)[`"\']', re.S), 1, 2),
    # $.ajax({url:'/x', method:'POST'})
    (re.compile(r'\$\.ajax\s*\(\s*\{[^}]{0,400}?url\s*:\s*[`"\']([^`"\']+)[`"\'][^}]{0,400}?method\s*:\s*[`"\'](\w+)[`"\']', re.S), 1, 2),
    # $.ajax({type:'POST', url:'/x'}) —— 键序颠倒的写法(组1=方法, 组2=路径)
    (re.compile(r'\$\.ajax\s*\(\s*\{[^}]{0,400}?(?:type|method)\s*:\s*[`"\'](\w+)[`"\'][^}]{0,400}?url\s*:\s*[`"\']([^`"\']+)[`"\']', re.S), 2, 1),
    # $.ajax({url: '/x', ...}) —— 无方法线索
    (re.compile(r'\$\.ajax\s*\(\s*\{[^}]{0,400}?url\s*:\s*[`"\']([^`"\']+)[`"\']', re.S), 1, None),
    # $.get('/x') / $.post('/x') / $.getJSON('/x') —— 组1=方法, 组2=路径
    (re.compile(r'\$\.(get|post|getJSON|put|delete)\s*\(\s*[`"\']([^`"\']+)[`"\']'), 2, 1),
    # ---- 3. XHR ----
    # xhr.open('GET', '/x') —— 组1=方法, 组2=路径
    (re.compile(r'\.open\s*\(\s*[`"\'](\w+)[`"\']\s*,\s*[`"\']([^`"\']+)[`"\']'), 2, 1),
    # ---- 4. 链式调用 ----
    # axios.get('/x') / request.post('/x') / http.get('/x') —— 组1=方法, 组2=路径
    (re.compile(r'\.(get|post|put|delete|patch)\s*\(\s*[`"\']([^`"\']+)[`"\']'), 2, 1),
    # ---- 5. 对象式配置 ----
    # axios({url:'/x', method:'get'})
    (re.compile(r'axios\s*\(\s*\{[^}]{0,400}?url\s*:\s*[`"\']([^`"\']+)[`"\'][^}]{0,400}?method\s*:\s*[`"\'](\w+)[`"\']', re.S), 1, 2),
    (re.compile(r'axios\s*\(\s*\{[^}]{0,400}?url\s*:\s*[`"\']([^`"\']+)[`"\']', re.S), 1, None),
    # 自封装请求器: request({url:'/x'}) / http({url:'/x'}) / api({url:'/x'})
    (re.compile(r'(?:request|http|api|client|service|ajax|fetchData)\s*\(\s*\{[^}]{0,400}?url\s*:\s*[`"\']([^`"\']+)[`"\']', re.S), 1, None),
    # 对象字面量里的 url 字段(兜底; 排最后, 不覆盖前面更精确的方法判定)
    (re.compile(r'url\s*:\s*[`"\']([^`"\']+)[`"\']'), 1, None),
    # ---- 6. 构造器 ----
    # new URL('/x') / new Request('/x')
    (re.compile(r'new\s+(?:URL|Request)\s*\(\s*[`"\']([^`"\']+)[`"\']'), 1, None),
    # ---- 7. 此前定义了却从未被调用的三条正则 ----
    # gRPC-Web 方法路径: /pkg.Service/Method
    (RE_GRPC, 1, None),
    # 完整 URL 形态: https://api.x.com/v1/...
    (RE_API_FULL, 1, None),
    # 相对路径变体: /v1/...
    (RE_API_V, 1, None),
    # ---- 8. 函数实参 / 属性赋值形态的 URL ----
    # fn(el, "/path", {data...}) —— URL 作**函数实参**且后随数据对象。含请求体 → 按 POST 处理
    #   (常量方法 'POST' 由 _extract_api_calls 支持; 避免把"发短信/提交"类端点当 GET 去探活)。
    #   来源: mpassport.huazhu.com 的 SendSms.init($btnSms, "/Validate/SendLoginSMSForGeetest", {…})。
    (re.compile(r'[,\(]\s*[`"\'](/[A-Za-z][^`"\'\s]{2,}?)[`"\']\s*,\s*\{'), 1, 'POST'),
    # .attr('src'|'href'|'action', '/path') —— URL 作**属性赋值**实参(图片/跳转类接口)
    (re.compile(r'\.attr\s*\(\s*[`"\'](?:src|href|action)[`"\']\s*,\s*[`"\']'
                r'(/[A-Za-z][^`"\'\s]{2,}?)[`"\']'), 1, None),
]

# URLSearchParams('a=1&b=2') —— RE_URL_SEARCH 此前从未被调用
RE_URL_SEARCH_QS = re.compile(r'URLSearchParams\s*\(\s*[`"\']([^`"\']*=[^`"\']*)[`"\']\s*\)')

# 归一化的 HTTP 方法集合
WRITE_METHODS = ('POST', 'PUT', 'PATCH', 'DELETE')

# API_CALL_PATTERNS 每条的**稳定标识**(与上表一一对应) —— 供外部规则按名**禁用**某条内置模式
#   (config `extract_rules.disable_patterns`)。数量须与 API_CALL_PATTERNS 一致(verify 断言)。
API_CALL_PATTERN_NAMES = (
    'fetch_str', 'fetch_tmpl', 'fetch_method',
    'jq_ajax_type', 'jq_ajax_method', 'jq_ajax_rev', 'jq_ajax_url', 'jq_shorthand',
    'xhr_open', 'chain_method',
    'axios_obj_method', 'axios_obj_url', 'custom_requester', 'bare_url_field',
    'new_url_request', 'grpc_method', 'full_url', 'api_v_prefix',
    'fn_arg_post', 'attr_assign',
)


# ==================== 外部提取规则(动态获取) ====================
# 与 secret_db / fingerprint_db / hidden_paths_db / custom_rules 同构: 内置默认保留, 外部可**覆盖**。
#   覆盖对象(仅"纯数据、无顺序语义"的部分, 不动核心调用点正则):
#     ① 过滤词表 —— static_asset_exts / srv_ep_exts / static_dir_prefixes / api_hint_words;
#     ② 禁用某条内置调用点模式 —— disable_patterns(取 API_CALL_PATTERN_NAMES 的稳定名)。
# 缺省(未注入或 rules 为空) → 行为与内置完全一致(零配置不变)。
# 注: 本模块为数据层, 不 import 上层; 加载与注入由编排层(engine)在扫描开始调用。
_EXTRACT_RULES = {}
_DISABLED_PATTERNS = set()


def apply_extract_rules(rules):
    """用外部规则覆盖内置过滤词表 / 禁用内置调用点模式(先清空, 缺省即回退内置)。"""
    _EXTRACT_RULES.clear()
    _DISABLED_PATTERNS.clear()
    if not isinstance(rules, dict):
        return
    for _k in ('static_asset_exts', 'srv_ep_exts', 'static_dir_prefixes', 'api_hint_words'):
        _v = rules.get(_k)
        if _v:
            _EXTRACT_RULES[_k] = tuple(str(x) for x in _v)
    _dis = rules.get('disable_patterns')
    if _dis:
        _DISABLED_PATTERNS.update(str(x) for x in _dis)


def load_extract_rules(spec):
    """加载外部提取规则(spec: JSON 文件路径 / dict / None)。失败一律返回 None(不中断)。"""
    if not spec:
        return None
    if isinstance(spec, str):
        import json as _json
        import os as _os
        if not _os.path.exists(spec):
            return None
        try:
            with open(spec, encoding='utf-8') as f:
                data = _json.load(f)
        except Exception:
            return None
    else:
        data = spec
    return data if isinstance(data, dict) else None


def static_asset_exts():
    """静态资源后缀表(可被外部覆盖; 缺省内置)。"""
    return _EXTRACT_RULES.get('static_asset_exts', STATIC_ASSET_EXTS)


def srv_ep_exts():
    """服务端脚本扩展名表(可被外部覆盖; 缺省内置)。"""
    return _EXTRACT_RULES.get('srv_ep_exts', SRV_EP_EXTS)


def static_dir_prefixes():
    """静态目录前缀表(可被外部覆盖; 缺省内置)。"""
    return _EXTRACT_RULES.get('static_dir_prefixes', STATIC_DIR_PREFIXES)


def api_hint_words():
    """接口关键词表(可被外部覆盖; 缺省内置)。"""
    return _EXTRACT_RULES.get('api_hint_words', API_HINT_WORDS)


def iter_api_call_patterns():
    """产出**未被禁用**的调用点模式: (name, 正则, 路径组, 方法组)。"""
    for _i, _entry in enumerate(API_CALL_PATTERNS):
        _name = (API_CALL_PATTERN_NAMES[_i] if _i < len(API_CALL_PATTERN_NAMES)
                 else f'pat_{_i}')
        if _name in _DISABLED_PATTERNS:
            continue
        yield (_name,) + tuple(_entry)

def normalize_extracted_path(p):
    """把提取到的路径统一成可用于探活的相对路径; 不像接口则返回 None

    处理:
      · 去 fragment(`#...`) —— 与全项目其它路径处理 `split('#')[0]` 同口径, 否则
        `/api/x#f` 会与 `/api/x` 重复登记(去重键 normalize_endpoint 虽已丢弃 fragment,
        但 `meta['apis']`/JSON extracted_endpoints 仍会出现两条)
      · 绝对 URL → 取其 path+query
      · 模板占位符 `${...}` / `{...}` / `:name` / `*name` → 统一为 `:ph`(供 expand_restful_v45 展开)
      · 剔除静态资源(后缀 / 静态目录前缀)
      · 拒绝空路径、协议相对、data:/blob: 等
    """
    if not p:
        return None
    p = p.strip()
    if not p or p.startswith(('data:', 'blob:', 'about:', 'javascript:', '#', '//')):
        return None
    # 去 fragment(纯 `#...` 开头已在上一行拒绝; 此处处理 path 中段/末段的 `#`)
    if '#' in p:
        p = p.split('#', 1)[0]
        if not p:
            return None
    # 绝对 URL → 取 path
    if p.startswith('http://') or p.startswith('https://'):
        try:
            sp = urlsplit(p)
        except Exception:
            return None
        p = sp.path or '/'
        if sp.query:
            p = f'{p}?{sp.query}'
    if not p.startswith('/'):
        return None
    # 模板占位符统一化
    #   `${name}` **保留参数名** → `:name`。旧实现一律压成 `:ph`, 后果有二:
    #     ① 参数名丢失 —— 后续 idor/sqli 阶段无法按参数名取参, 报告里也看不出这条
    #        接口需要什么参数;
    #     ② 同一接口产生**多种表示**并存 —— 模板字面量通道产出 `/orders/${id}/items`、
    #        拼接通道产出 `/orders/{id}/items`, 归一后一个变 `:ph`、一个变 `:id`,
    #        **去重失效**, 同一接口在清单里出现多次(实测一个接口出现 3 次)。
    #   只有无名表达式(如 `${a+b}`)才退化为 `:ph`。
    p = re.sub(r'\$\{\s*([A-Za-z_$][\w$]*)\s*\}', r':\1', p)
    p = re.sub(r'\$\{[^}]*\}', ':ph', p)
    p = re.sub(r'\{(\w+)\}', r':\1', p)
    # 拼接残留: `'/api/list?' + params` 会留下尾随 '?'/'&' —— 清掉, 否则会被当成
    # 独立 URL 重复探活, 且 query 参数解析得到空集合。
    p = re.sub(r'[?&]+$', '', p)
    low = p.lower()
    base = low.split('?')[0]
    # 静态资源过滤
    if base.endswith(static_asset_exts()):
        return None
    if any(base.startswith(pre) for pre in static_dir_prefixes()):
        return None
    # 单段路径且无 API 关键词 → 大概率是前端路由, 丢弃
    #   例外①: 服务端脚本端点(/index.jsp、/x.do、/y.cgi)单段也保留 —— 动态端点。
    #   例外②: 带查询参数的单段路径(/mission?id=1、/view?doc=2)也保留 —— 动态端点强信号。
    segs = [s for s in base.split('/') if s]
    _has_qp = ('?' in p and '=' in p.split('?', 1)[1])
    if len(segs) < 2 and not any(w in base for w in api_hint_words()) \
            and not base.endswith(srv_ep_exts()) and not _has_qp:
        return None
    # 前端路由模板(动态路由, 非接口)拒绝 —— 见 `_is_route_template`。
    #   这类来自 Vue/Nuxt 路由定义或 `$router.push(base+"/list/0-0-1-...")` 拼接,
    #   与真实接口(资源/动作)形态不同且从不作为 fetch/axios 调用目标。
    #   实测 open.medsci.cn: /list/:classify-:categoryId-...-:type、/list/0-0-1-20641-0-0
    #   等被当作接口提取, 实为前端分类/列表路由(站点自身 REST 接口是 `/comment/list`
    #   这类资源/动作形态, 无此模板特征)。仅当 path 段(?)前 `:` 占位 ≥2 或含数字段范围
    #   时拒绝 —— 单 `:id` 仍保留(可能是真实接口, 由调用点上下文保证相关性)。
    if _is_route_template(base):
        return None
    # 明显的前端路由(带 :ph 且无 API 关键词)仍保留 —— 由调用点上下文保证相关性
    return p


def _is_route_template(base):
    """判断路径(去 query 后的小写)是否为前端路由模板而非接口。

    拒绝信号(任一即判为路由, 都不匹配真实接口形态):
      · 某路径段**以数字开头且含 ≥2 个连字符** —— 数字段范围路由, 如
        `0-0-1-:categoryId-0-0` / `0-0-1-21028-0-0` / `0-0-1-0-0-1`
        (Nuxt 分类/列表动态路由; 用"段首数字 + ≥2 连字符"而非泛数字正则,
        以免误伤日期型/普通含连字符的真实接口段, 如 `2024-q1`)。
      · 某路径段**含 `:param` 且含连字符** —— 动态路由参数嵌在连字符段, 如
        `:categoryId-0-0`(不是真实接口的资源/动作形态)。
    保留: 单 `:id` 占位(`/users/:id` 可能是真实接口) 与 普通资源/动作路径
        (`/comment/list`、`/wx-share/wx-share-config` 等), 由调用点上下文保证相关性。
    """
    path_part = base.split('?')[0]
    for seg in path_part.split('/'):
        if not seg:
            continue
        # 数字段范围路由: 段以数字开头且含 ≥2 个连字符
        if seg[0].isdigit() and seg.count('-') >= 2:
            return True
        # 动态参数嵌在连字符段(路由参数, 非接口)
        if ':' in seg and '-' in seg:
            return True
    return False


# 基址前缀判定: 仅"真正的前缀型基址"才应从 apis 中剔除(它们是前缀, 不是可探活端点)。
#   误判风险: `vars.known_values()` 会把所有赋值过的字符串(含 `/comment/list` 这类
#   完整资源端点)都收进 base_consts; 若整集合相减会把真实接口误删。故只在值明确是
#   "前缀"时才移除 —— 结尾 `/`, 或 `/(api|rest|graphql|gateway|service(s)?|bff|v\d)`
#   单段/单版本前缀。
_BASE_PREFIX_RE = re.compile(
    r'^/(?:api|apis|rest|restful|graphql|gateway|service|services|bff|v\d)'
    r'(?:/[A-Za-z0-9_.-]+)?$'
)


def _is_base_prefix(v):
    """判断某已知值是否应作为"基址前缀"从 apis 中剔除(而非真实端点)。"""
    if not v or not v.startswith('/'):
        return False
    if v.endswith('/'):
        return True
    return bool(_BASE_PREFIX_RE.match(v))


def extract_query_params(p):
    """从路径的 query 部分提取全部参数名"""
    if not p or '?' not in p:
        return set()
    qs = p.split('?', 1)[1]
    return set(re.findall(r'(?:^|&)([A-Za-z_][A-Za-z0-9_]*)', qs))

# 注: 删除了此处的 `parse_query_string(qs)` —— 它与上面的
#     `extract_query_params` 功能完全重叠(都解析 'a=1&b=2' 形态), 且全项目零引用。
#     两个语义相同的函数并存只会让调用方选错, 保留一个即可。

# ==================== 优化整合: 配置与工具函数 ====================

# ==================== 隐藏路径字典 按技术栈分层 ====================
# 设计原则(修复 的跨框架混合字典问题):
#   通用层 COMMON   → 任何技术栈都探测(管理面/监控面/通用配置泄露)
#   栈专属层 BY_STACK → 仅当指纹命中对应技术栈时才加载
# 效果: 纯 Vue/静态站目标发包量从 82 降到约 22, Spring 目标仍可打全量

# ---- 通用层: 与具体技术栈无关的管理面/配置面/监控面 ----
HIDDEN_PATHS_COMMON = [
    '/admin', '/manage', '/manager', '/console', '/dashboard',
    '/config', '/debug', '/test',
    '/backup', '/bak',
    '/db.sql', '/database.sql', '/dump.sql',
    '/.env', '/.git/config',
    '/health', '/status', '/ready',
    '/metrics',
    '/docs',
    '/internal', '/private',
    # ---- 源码/版本控制泄露(SRC 经典三件套: .git / .svn / .DS_Store) ----
    #   来源: 公开"源码泄露总结"(CN-SEC / FreeBuf / Hello CTF)。
    '/.git/HEAD', '/.svn/entries', '/.DS_Store', '/.idea/workspace.xml',
    # ---- 站点源码/数据库备份包(SRC 高发; 公开"备份文件泄露"专题) ----
    '/backup.zip', '/www.zip', '/web.zip', '/wwwroot.zip', '/backup.rar', '/wwwroot.rar',
    # ---- 配置/凭据泄露(.env 变体 / 配置备份 / Apache 配置) ----
    '/.env.local', '/.env.production', '/.env.bak', '/config.php.bak', '/.htaccess',
    # ---- 平台信息泄露(Java EE / PHP / Apache / Flash 跨域策略) ----
    '/WEB-INF/web.xml', '/phpinfo.php', '/server-status', '/crossdomain.xml',
    # ---- 依赖清单(版本 → CVE; SRC 常见报告项) ----
    '/composer.json', '/package.json',
    # ---- API 文档(OpenAPI v3; springdoc 官方默认) ----
    '/v3/api-docs',
    # ---- 侦察基建(通用、近零噪声; robots/sitemap 常直接泄露隐藏路径) ----
    '/robots.txt', '/sitemap.xml',
]

# ---- 尾斜杠变体(无重定向型服务器) ----
# 背景: 多数服务器对 `/admin` 会 301 → `/admin/`(REQ 已跟随重定向, 无需补);
#   但存在**无重定向型**: 裸路径 404、仅 `/path/` 200(实测复现)。此时裸路径会漏判。
#   仅对这批**高价值目录型**路径补一次带斜杠变体 —— 避免对所有路径翻倍发包(守最小发包)。
TRAILING_SLASH_PATHS = (
    '/admin', '/manage', '/manager', '/console', '/dashboard',
    '/actuator', '/druid', '/internal', '/docs',
)

# ---- 管理 / 敏感面关键词: 单一事实来源 ----
# 供三处共用, 避免"管理关键词"各写一份 → **同一路径定级不一致**
#   (审计发现: `report._CONFIG_KW` / `report._UA_CONFIG_RISKY` / `engine` hidden_probe
#    三套列表互不一致 —— `/console`·`/monitor`·`/debug`·`/internal` 在其中一处是管理面、
#    另一处不是)。
#   · MGMT_KEYWORDS     —— 管理/配置/监控面(含**可公开**的 health/status/swagger/graphql)
#   · MGMT_HIGH_RISK_KW —— 其中"**不应公开**"的高危子集(暴露即 HIGH / 未授权高危段)
MGMT_KEYWORDS = frozenset({
    'admin', 'manage', 'manager', 'console', 'dashboard', 'actuator', 'druid',
    'metrics', 'monitor', 'debug', 'internal', 'config', 'env', '.git', '.env',
    'phpmyadmin', 'jenkins', 'grafana', 'kibana', 'swagger', 'graphql',
    'health', 'status',
})
MGMT_HIGH_RISK_KW = frozenset({
    'admin', 'manage', 'manager', 'console', 'dashboard', 'actuator', 'druid',
    'metrics', 'monitor', 'debug', 'internal', 'config', 'env', '.git', '.env',
    'phpmyadmin', 'jenkins', 'grafana', 'kibana',
})

# ---- 泛 API 路径猜测层（与技术栈无关, 任何目标都探）----
# 用于 engine 的"字典候选"叠加 —— 一组通用 REST API 路径猜测(管理/调试/账户/资料)。
#   **不得包含栈专属路径**(/actuator*·/druid*·/swagger.json·/api-docs…) —— 那些由
#   **指纹门控**的 `HIDDEN_PATHS_BY_STACK` 按栈加载；混入此处会绕过门控(旧实现即如此,
#   导致 Express 站也出现 `/actuator`)。
GENERIC_API_GUESS_PATHS = [
    '/api/internal/config', '/api/internal/daily-report', '/api/admin/config',
    '/api/debug', '/api/auth/login', '/api/user/profile', '/api/admin/users',
]

# ---- 栈专属层: 键为技术栈标识, 与 FP_RULES 的指纹名对齐 ----
# ---- 规范文档路径: 单一事实来源 ----
# 供**两处共用**: ① 隐藏路径字典(_SWAGGER_PATHS) ② schema 源探测(recon/schema.py)。
# 旧实现两处各写一份 spec 路径 → 长期漂移(同一路径一处有、另一处无), 现统一到此处。
SWAGGER_SPEC_PATHS = [
    # 规范 JSON(可解析为端点)
    '/swagger.json', '/swagger/v1/swagger.json', '/v2/swagger.json',
    '/api/swagger.json', '/api/v2/swagger.json', '/swagger/v2/api-docs',
    '/api-docs', '/api-docs/v1', '/api/docs',
    '/openapi.json', '/api/openapi.json', '/openapi/v3.json',
    '/.well-known/openapi.json', '/schema.json',
    '/v2/api-docs', '/v3/api-docs',
]
# Swagger/OpenAPI **UI 页面**(HTML, 非规范 JSON) —— 仅供隐藏路径字典探测。
SWAGGER_UI_PATHS = [
    '/swagger-ui.html', '/api/swagger-ui.html', '/swagger', '/api/swagger', '/redoc',
]
_SWAGGER_PATHS = SWAGGER_SPEC_PATHS + SWAGGER_UI_PATHS
_SPRING_PATHS = [
    '/actuator', '/actuator/health', '/actuator/env', '/actuator/configprops',
    '/actuator/mappings', '/actuator/loggers', '/actuator/metrics',
    '/actuator/prometheus',
    # Actuator 高危(SRC 高价值): 内存转储/线程转储/请求轨迹 —— 泄密钥·会话·内部调用。
    #   官方端点名(Spring Boot Actuator 文档)。
    '/actuator/heapdump', '/actuator/threaddump', '/actuator/httptrace',
    # Actuator 其余常用端点(官方文档; beans/gateway 常泄露内部 Bean 与网关路由)。
    '/actuator/beans', '/actuator/gateway/routes', '/actuator/scheduledtasks',
    '/actuator/caches', '/actuator/sessions', '/actuator/conditions',
    # Jolokia(JMX over HTTP, 可致 RCE)—— 官方端点 /jolokia/list|exec|version。
    '/jolokia/list', '/jolokia/exec', '/jolokia/version',
    '/druid', '/druid/index.html', '/druid/wall.html',
    # Druid 监控页其余默认路径 / H2 控制台(默认无鉴权 → 可查改库)。
    '/druid/sql.html', '/druid/websession.html', '/druid/weburi.html', '/h2-console',
    # Springdoc OpenAPI v3 / Swagger UI 官方默认路径(此前只探 swagger.json 系)。
    '/swagger-ui/index.html', '/v3/api-docs/swagger-config', '/swagger-resources',
]
_PHP_PATHS = [
    '/phpmyadmin', '/pma', '/adminer',
    '/index.php', '/install.php', '/setup.php',
]

# ---- 前端构建产物 / 运行时配置层  ----
#   ② 运行时配置(config.js / env-config.js / app-config.js):
#      前端最常见的配置泄露点 —— 后端地址、AK、功能开关、灰度标记常年写在这里。
# 这些路径与具体框架无关, 因此所有前端指纹都挂同一组"构建产物层"。
_FRONTEND_MANIFEST_PATHS = [
    '/asset-manifest.json',        # CRA / webpack
    '/manifest.json',              # PWA 清单
    '/webpack.stats.json',         # webpack stats: 完整模块图
    '/stats.json',
    '/build-manifest.json',        # Next.js
    '/precache-manifest.js',       # workbox
    '/service-worker.js',
]
_FRONTEND_CONFIG_PATHS = [
    '/config.js', '/config.json',
    '/env.js', '/env-config.js', '/runtime-config.js',
    '/app-config.js',              # uni-app / Taro
    '/appsettings.json', '/settings.json',
    '/version.json', '/build-info.json', '/changelog.txt',
]
_FRONTEND_COMMON_PATHS = _FRONTEND_MANIFEST_PATHS + _FRONTEND_CONFIG_PATHS

# ---- JS 文件名"目录爆破"词表: 发现"未被页面引用但存在"的隐藏 JS ----
#   用途: 从已发现的 <script src>(如 /static/js/auth.js)派生其目录(/static/js/),
#     再以本词表逐个只读 GET, 命中(200 且像 JS)者并入 js_urls 走步骤3 分析。
#   来源: 常见 JS 命名约定 + gh0stkey/Web-Fuzzing-Box(Javascript_Filename) 精选。
JS_FILE_NAMES_COMMON = (
    'main', 'app', 'index', 'bundle', 'vendor', 'runtime', 'polyfills', 'chunk', 'chunks',
    'common', 'core', 'base', 'init', 'start', 'boot',
    'jquery', 'bootstrap', 'vue', 'react', 'angular', 'axios', 'lodash', 'moment', 'dayjs',
    'config', 'configs', 'settings', 'setting', 'env', 'app-config', 'runtime-config', 'options',
    'admin', 'dashboard', 'manage', 'manager', 'console', 'panel',
    'login', 'logout', 'register', 'signup', 'signin', 'auth', 'user', 'users', 'profile',
    'account', 'member', 'password', 'captcha', 'token',
    'order', 'orders', 'pay', 'payment', 'cart', 'product', 'goods', 'shop', 'store',
    'upload', 'uploader', 'download', 'file', 'files', 'filemanager', 'search', 'list', 'detail',
    'chat', 'message', 'messages', 'notify', 'comment', 'feedback',
    'utils', 'util', 'helper', 'helpers', 'api', 'request', 'ajax', 'http', 'service', 'services',
    'validator', 'validate', 'verify',
    'crypto', 'encrypt', 'decrypt', 'md5', 'sha', 'sha256', 'rsa', 'aes', 'base64', 'security',
    'editor', 'dialog', 'modal', 'table', 'form', 'chart', 'echarts', 'layer', 'element', 'antd',
    'template', 'theme', 'skin', 'style', 'script', 'scripts', 'functions',
)

# 框架专属补充路径
_NEXT_PATHS = ['/__nextjs_original-stack-frame', '/_next/data/', '/api/health']
_NUXT_PATHS = ['/_payload.json', '/__nuxt_error', '/api/_content/query']
_VITE_PATHS = ['/@vite/client', '/@vite/env']
_SVELTEKIT_PATHS = ['/_app/version.json', '/__data.json']
_ANGULAR_PATHS = ['/3rdpartylicenses.txt', '/main.js', '/polyfills.js', '/runtime.js']
_TARO_PATHS = ['/app-config.js', '/taro/']
_UNIAPP_PATHS = ['/app-config.js', '/manifest.json']

# ---- 补齐"现代框架"栈专属层 ----
# 背景: 实测 Express / Gin / Flask / Rails / ASP.NET 的**特征端点 0 发现** ——
#   它们要么被 HIDDEN_STACK_ALIASES 别名到通用 Swagger 路径, 要么直接指向 _SWAGGER_PATHS,
#   各自真正该看的调试/信息端点从不被探测。这里为每个栈补上专属路径(并保留 Swagger 层)。
_RAILS_PATHS = [
    '/rails/info/properties', '/rails/info/routes', '/rails/info',
    '/assets/application.js.map', '/.git/config',
]
_ASPNET_PATHS = [
    '/trace.axd', '/elmah.axd', '/swagger/v1/swagger.json', '/swagger/index.html',
    '/web.config', '/App_Data/', '/bin/',
]
_GIN_PATHS = [
    '/debug/pprof/', '/debug/pprof/goroutine', '/debug/vars', '/metrics', '/api/health',
]
_NODE_PATHS = [
    '/api', '/api-docs', '/graphql', '/socket.io/', '/api/health', '/healthz',
]
_FLASK_PATHS = ['/static/', '/console', '/api/health']
_FASTAPI_PATHS = ['/openapi.json', '/docs', '/redoc']

# ---- 中间件高危管理面(SRC 高价值: 默认口令 → 部署/RCE 的经典入口) ----
#   路径均为官方默认管理路径。
_TOMCAT_PATHS = [
    '/manager/html', '/host-manager/html', '/manager/status',
]
_JBOSS_PATHS = [
    '/jmx-console/', '/web-console/', '/admin-console/',
    '/invoker/JMXInvokerServlet', '/invoker/EJBInvokerServlet',
]
_WEBLOGIC_PATHS = [
    '/console/', '/console/login/LoginForm.jsp', '/uddiexplorer/',
    '/wls-wsat/CoordinatorPortType',
]

HIDDEN_PATHS_BY_STACK = {
    'Spring':               _SPRING_PATHS,
    'Spring-Boot':          _SPRING_PATHS,
    'Spring-Cloud-Alibaba': ['/nacos', '/nacos/v1/auth', '/eureka'],
    'Dubbo':                _SPRING_PATHS,
    'JFinal':               _SPRING_PATHS,
    'Swagger':              _SWAGGER_PATHS,
    'OpenAPI':              _SWAGGER_PATHS,
    # 补 /wp-admin/ 与 /wp-login.php —— 旧实现只探 /wp-json/*
    'WordPress':            ['/wp-json/wp/v2/users', '/wp-json', '/xmlrpc.php',
                             '/wp-admin/', '/wp-login.php'],
    'PHP':                  _PHP_PATHS,
    'Laravel':              _PHP_PATHS + ['/telescope', '/horizon', '/_ignition/health-check'],
    # Livewire(Laravel 全栈组件框架): 固定端点 `/livewire/message`(v2) / `/livewire/update`(v3)
    'Livewire':             ['/livewire/message', '/livewire/update', '/livewire/livewire.js'],
    'ThinkPHP':             ['/runtime/log', '/runtime/temp', '/application/database.php'],
    'Beego':                _PHP_PATHS,
    'Discuz!':              _PHP_PATHS,
    'Typecho':              _PHP_PATHS,
    'GraphQL':              ['/graphql', '/api/graphql', '/_graphql'],
    'tRPC':                 ['/api/trpc', '/trpc'],
    'JeecgBoot':            ['/jeecg-boot', '/jeecg', '/api/sys/user/list'],
    'RuoYi':                ['/ruoyi', '/api/system/user/list'],
    'Django':               ['/admin/', '/api/v1/users', '/api/v1/admin'],
    # 从"只复用 Swagger"改为"专属层 + Swagger"
    'Rails':                _RAILS_PATHS + _SWAGGER_PATHS,
    'ASP.NET':              _ASPNET_PATHS + _SWAGGER_PATHS,
    # ---- 前端栈: 构建产物 + 运行时配置 ----
    'React':                _FRONTEND_COMMON_PATHS,
    'Vue':                  _FRONTEND_COMMON_PATHS,
    'Vue3':                 _FRONTEND_COMMON_PATHS,
    'Angular':              _FRONTEND_COMMON_PATHS + _ANGULAR_PATHS,
    'Svelte':               _FRONTEND_COMMON_PATHS,
    'SolidJS':              _FRONTEND_COMMON_PATHS,
    'Preact':               _FRONTEND_COMMON_PATHS,
    'Astro':                _FRONTEND_COMMON_PATHS,
    'Webpack':              _FRONTEND_COMMON_PATHS,
    'Rollup':               _FRONTEND_COMMON_PATHS,
    'esbuild':              _FRONTEND_COMMON_PATHS,
    'Parcel':               _FRONTEND_COMMON_PATHS,
    'Next.js':              _FRONTEND_COMMON_PATHS + _NEXT_PATHS,
    'Nuxt':                 _FRONTEND_COMMON_PATHS + _NUXT_PATHS,
    'Remix':                _FRONTEND_COMMON_PATHS,
    'Vite':                 _FRONTEND_COMMON_PATHS + _VITE_PATHS,
    'SvelteKit':            _FRONTEND_COMMON_PATHS + _SVELTEKIT_PATHS,
    'Taro':                 _FRONTEND_COMMON_PATHS + _TARO_PATHS,
    'uni-app':              _FRONTEND_COMMON_PATHS + _UNIAPP_PATHS,
    # UI 组件库本身不代表构建工具, 但命中它们说明是前端项目 → 值得打构建产物层
    'Ant-Design-Pro':       _FRONTEND_COMMON_PATHS,
    'Element-Plus':         _FRONTEND_COMMON_PATHS,
    'Element-UI':           _FRONTEND_COMMON_PATHS,
    'Vant':                 _FRONTEND_COMMON_PATHS,
    'uView':                _FRONTEND_COMMON_PATHS,
    'Bootstrap':            _FRONTEND_COMMON_PATHS,
    'Layui':                _FRONTEND_COMMON_PATHS,
    'MUI':                  _FRONTEND_COMMON_PATHS,
    'Vuetify':              _FRONTEND_COMMON_PATHS,
    'Quasar':               _FRONTEND_COMMON_PATHS,
    'Naive-UI':             _FRONTEND_COMMON_PATHS,
    # ---- 现代后端框架: 专属层 + Swagger 层(此前被别名到 Swagger, 特征端点漏探) ----
    'Gin':                  _GIN_PATHS + _SWAGGER_PATHS,
    'Echo':                 _GIN_PATHS + _SWAGGER_PATHS,
    'Fiber':                _GIN_PATHS + _SWAGGER_PATHS,
    'Express':              _NODE_PATHS + _SWAGGER_PATHS,
    'Koa':                  _NODE_PATHS + _SWAGGER_PATHS,
    'NestJS':               _NODE_PATHS + _SWAGGER_PATHS,
    'Hono':                 _NODE_PATHS + _SWAGGER_PATHS,
    'Elysia':               _NODE_PATHS + _SWAGGER_PATHS,
    'Flask':                _FLASK_PATHS + _SWAGGER_PATHS,
    'FastAPI':              _FASTAPI_PATHS + _SWAGGER_PATHS,
    # ---- 中间件高危管理面(默认口令 → 部署/RCE 的经典入口) ----
    'Tomcat':               _TOMCAT_PATHS,
    'JBoss':                _JBOSS_PATHS,
    'WebLogic':             _WEBLOGIC_PATHS,
}

# ---- 扩展层(opt-in, 默认关闭) ----
# 通用层刻意保持精简(近零噪声 + 最小发包)。下列路径**价值高但体积/噪声略大**
#   (备份变体、容器/云凭据、监控中间件面、well-known、调试页), 归入 opt-in 扩展层 ——
#   由 config `hidden_paths_extended: true` 开启, 守"默认最小发包"的定位。
HIDDEN_PATHS_EXTENDED = [
    # 备份变体(公开"备份文件泄露"专题; 常见归档后缀)
    '/backup.sql', '/data.sql', '/db.zip', '/site.zip', '/web.rar',
    '/www.tar.gz', '/web.tar.gz', '/wwwroot.tar.gz', '/backup.tar.gz', '/www.7z',
    # 容器 / 云 / CI 凭据与配置(SRC 高发: 泄露即失守)
    '/docker-compose.yml', '/docker-compose.yaml', '/Dockerfile', '/.dockerenv',
    '/.aws/credentials', '/.ssh/id_rsa', '/.npmrc', '/.gitlab-ci.yml',
    '/.travis.yml', '/.circleci/config.yml', '/terraform.tfstate', '/k8s.yaml',
    '/secrets.json', '/credentials.json', '/service-account.json',
    # .env 变体
    '/.env.dev', '/.env.staging', '/.env.test', '/.env.example',
    # 监控 / 中间件管理面(默认口令 → 横向的经典入口)
    '/jenkins', '/grafana', '/kibana', '/prometheus', '/consul',
    '/zabbix', '/rabbitmq', '/solr', '/_cat/indices', '/nginx_status',
    '/hystrix.stream',
    # well-known / 跨域策略
    '/security.txt', '/.well-known/security.txt', '/.well-known/change-password',
    '/clientaccesspolicy.xml',
    # 常见调试 / 信息页
    '/info.php', '/test.php', '/error', '/trace',
]

# ---- 别名映射: 未单列字典的指纹名 → 复用已有栈字典 ----
# 注: 起 Next.js / Nuxt / Remix 已各自拥有专属层(构建产物 + 框架路径),
#     原先指向 Swagger 的别名已被覆盖, 故从本表中移除 —— 留着只会让人误以为
#     这几个前端框架仍然复用后端 API 文档字典。
HIDDEN_STACK_ALIASES = {
    # FastAPI/NestJS/Express/Gin/Echo/Fiber/Hono/Elysia/Flask/Koa 已各自
    #   拥有 HIDDEN_PATHS_BY_STACK 专属层(专属端点 + Swagger), 故从别名表移除 ——
    #   留着只会让人误以为这些栈仍只复用 Swagger 字典(那正是它们特征端点漏探的原因)。
    'Symfony': 'PHP', 'Yii': 'PHP', 'CodeIgniter': 'PHP',
    'CakePHP': 'PHP', 'Micronaut': 'Swagger', 'Quarkus': 'Swagger',
    'Solon': 'Swagger',
}

def load_external_hidden_paths(path):
    """加载外部隐藏路径字典(JSON: 顶层为 list, 或 {"paths": [...]})。

    与 `secret_db` / `fingerprint_db` / `sca_db` 同构 —— 便于按业务补充私有路径
    (如公司内部后台、专有中间件面)。失败静默返回 []。
    也接受**内置词表名**(见 `load_wordlist`) —— 这样 `pip install` 后无需知道包内路径。
    """
    return load_wordlist(path, kind='paths')


# ---- 内置词表（**随包发布**，经 `hidden_paths_db` / `js_dir_fuzz_names` 按**名字**引用）----
#   🔴 为什么必须放在包内: 此前这些词表在**仓库根** `wordlists/`, 而 `packages.find` 只收
#   `facet*` → 真建 wheel 核对时 `wordlists/*` **一个都不在**(实测 69 条目里 0 个),
#   于是文档记的 `hidden_paths_db: wordlists/js_paths_common.json` 在 `pip install` 后
#   **必然静默失效**。现移入 `facet/assets/wordlists/` 并声明 package-data。
#   同时支持**按名引用**（`highvalue` 等）—— 使用者不必知道包内路径。
BUILTIN_WORDLISTS = {
    # 路径字典（JSON，{"paths": [...]}）
    'common':       ('js_paths_common.json', 'paths'),
    'highvalue':    ('js_paths_highvalue.json', 'paths'),
    'static':       ('js_paths_static.json', 'paths'),
    # JS 文件名字典（纯文本，一行一名）
    'js_common':    ('js_filenames_common.txt', 'names'),
    'js_highvalue': ('js_filenames_highvalue.txt', 'names'),
    'js_full':      ('js_filenames.txt', 'names'),
}
# `all` 的展开（按 kind 分族）：路径族 / 文件名族
WORDLIST_ALL = {'paths': ('common', 'highvalue', 'static'),
                'names': ('js_common', 'js_highvalue', 'js_full')}
# 按 kind 允许的内置名（防"把文件名词表当路径词表用"这类张冠李戴）
_WORDLIST_KINDS = {'paths': ('common', 'highvalue', 'static'),
                   'names': ('js_common', 'js_highvalue', 'js_full')}


def wordlist_path(name):
    """内置词表名 → **包内**绝对路径；未知名返回 None。"""
    import os as _os
    ent = BUILTIN_WORDLISTS.get(str(name or '').strip().lower())
    if not ent:
        return None
    p = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                      '..', 'assets', 'wordlists', ent[0])
    p = _os.path.normpath(p)
    return p if _os.path.isfile(p) else None


def load_wordlist(ref, kind='paths'):
    """按 **内置名 / 文件路径** 加载词表 → list[str]；失败返回 []。

    接受的 `ref`（按序尝试，任一成功即返回）：
      ① 内置名（`common` / `highvalue` / `static` / `js_common` / `js_highvalue` / `js_full`）；
      ② `all` —— 该 kind 的全部内置词表**合并去重**；
      ③ 文件路径（`.json` 取 list 或 `{"paths": [...]}`；`.txt` 逐行取，忽略空行与 `#` 注释）；
      ④ **旧路径兼容**：形如 `wordlists/js_paths_common.json` 的历史写法（文件已移入包内）
         → 按**文件名**回退到内置词表（否则老配置会静默失效）。
    `kind` ∈ {'paths','names'}：路径词表要求条目以 `/` 开头（与旧口径一致）；文件名词表不做前缀过滤。
    """
    import json as _json
    import os as _os

    def _finish(items):
        out = []
        seen = set()
        for it in items:
            s = str(it).strip()
            if not s or s.startswith('#'):
                continue
            if kind == 'paths' and not s.startswith('/'):
                continue
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out

    if not ref:
        return []
    name = str(ref).strip()
    low = name.lower()
    if low == 'all':
        merged = []
        for n in WORDLIST_ALL.get(kind, ()):
            p = wordlist_path(n)
            if p:
                merged += _read_wordlist_file(p, kind, _json)
        return _finish(merged)
    if low in _WORDLIST_KINDS.get(kind, ()):
        p = wordlist_path(low)
        return _finish(_read_wordlist_file(p, kind, _json)) if p else []
    if _os.path.isfile(name):
        return _finish(_read_wordlist_file(name, kind, _json))
    # ④ 旧路径兼容: 只认**文件名**是否命中内置表（不跟随任意路径, 避免误读）
    base = _os.path.basename(name)
    for _n, (fn, _k) in BUILTIN_WORDLISTS.items():
        if fn == base:
            p = wordlist_path(_n)
            return _finish(_read_wordlist_file(p, kind, _json)) if p else []
    return []


def _read_wordlist_file(path, kind, _json):
    """读词表文件 → list（不做 kind 过滤/去重, 交给 `load_wordlist._finish`）。"""
    try:
        if str(path).lower().endswith('.json'):
            with open(path, encoding='utf-8') as f:
                data = _json.load(f)
            if isinstance(data, dict):
                data = data.get('paths') or data.get('names') or []
            return list(data) if isinstance(data, list) else []
        with open(path, encoding='utf-8') as f:
            return [ln.strip() for ln in f if ln.strip()]
    except Exception:
        return []


def get_hidden_paths(fingerprint_hits=None, extra=None, extended=False):
    """按指纹命中列表返回应探测的隐藏路径(通用层 + [扩展层] + 命中的栈专属层 + 自定义)。

    Args:
        fingerprint_hits: 命中的指纹名列表; 为空则只返回通用层
        extra: 调用方追加的自定义路径(config `hidden_paths_extra` / 外部字典文件)
        extended: 是否并入 **opt-in 扩展层**(config `hidden_paths_extended`, 默认关)

    Returns:
        list[str]: 去重后的路径列表(保持顺序)
    """
    paths, seen = [], set()

    def _add(seq):
        for p in seq:
            p = str(p).strip()
            if p and p not in seen:
                seen.add(p)
                paths.append(p)

    _add(HIDDEN_PATHS_COMMON)
    if extended:
        _add(HIDDEN_PATHS_EXTENDED)
    for name in (fingerprint_hits or []):
        key = name if name in HIDDEN_PATHS_BY_STACK else HIDDEN_STACK_ALIASES.get(name)
        _add(HIDDEN_PATHS_BY_STACK.get(key, []))
    _add([p for p in (extra or []) if str(p).strip().startswith('/')])
    return paths

# 注: 原 `HIDDEN_PATHS`(全量字典兼容变量)已删除 —— 实测**零引用**(死代码);
#     探测请用 `get_hidden_paths()`, 统计请按层直接取 `HIDDEN_PATHS_*`。

# ---- 字典"何时用"的判别: 内容型 vs 页面型 ----
# 背景: 字典探测只在**目标能判别路径存在性**时产生信号。若目标是 catch-all
#   (任意路径都回同一响应), "页面型"条目(如 /admin)与"不存在"的响应一致 →
#   必然落入基线一致(判定 0), 既无信号又白费请求; 而"内容型"条目(源码/备份/配置/
#   清单——若真存在必返回**文件内容**)即使在该目标上也能与 catch-all 页区分。
# 判据是**通用形态**(点目录 / 文件扩展名 / 已知内容端点), 不是站点特化列表。
_CONTENT_DIFF_EXT = (
    '.json', '.js', '.xml', '.zip', '.rar', '.sql', '.map', '.yml', '.yaml',
    '.txt', '.bak', '.old', '.swp', '.env', '.ini', '.csv', '.gz', '.tar',
    '.php', '.asp', '.jsp', '.do', '.action',
)
# 无扩展名、但"存在即返回文件/结构化内容"的已知端点(官方默认路径)。
_CONTENT_DIFF_ENDPOINTS = frozenset({
    '/server-status', '/server-info',
    '/v2/api-docs', '/v3/api-docs', '/api-docs', '/api-docs/v1',
    '/actuator/env', '/actuator/configprops', '/actuator/mappings',
    '/actuator/httptrace', '/actuator/threaddump', '/actuator/heapdump',
    '/jolokia/list', '/jolokia/version', '/jolokia/exec',
    '/debug/vars', '/debug/pprof/', '/manager/status',
})


def is_content_diff_path(p):
    """路径是否为"内容型"—— 若存在必返回文件/结构化内容(源码·备份·配置·清单)。

    这类条目在 catch-all 目标上**仍可判别**(内容与 catch-all 页不同);
    反之"页面型"条目(admin/console/health 等)在 catch-all 下与"不存在"无法区分。
    判据: 任一路径段以 `.` 开头(点目录/点文件, 如 `.git`/`.svn`/`.env`/`.DS_Store`)
         或末段是已知文件扩展名, 或命中已知内容端点。
    """
    s = str(p)
    segs = [x for x in s.split('/') if x]
    if not segs:
        return False
    if any(x.startswith('.') and x not in ('.', '..') for x in segs):
        return True
    if segs[-1].lower().endswith(_CONTENT_DIFF_EXT):
        return True
    return s in _CONTENT_DIFF_ENDPOINTS

# ---- JS分级: entry/chunk/vendor 优先级 + 第三方库排除 ----
JS_EXCLUSION_LIST = ['jquery', 'bootstrap', 'vue.min', 'vue.js', 'vue.runtime', 'react', 'react-dom',
                     'react.production', 'angular', 'underscore', 'lodash', 'moment', 'echarts', 'd3.',
                     'axios.min', 'element-ui', 'elementplus', 'antd', 'swiper', 'sockjs', 'chunk-vendors',
                     'webpack', 'polyfill', 'babel', 'crypto-js', 'sweetalert', 'nprogress', 'dayjs', 'qs.js',
                     'sockjs-client', 'stomp']
JS_PRIORITY = {'entry': 0, 'chunk': 1, 'vendor': 2}

def get_js_priority(name):
    """按JS文件名/路径特征判定优先级: 入口0 > 业务chunk1 > 第三方/压缩产物2"""
    n = (name or '').lower()
    if any(k in n for k in JS_EXCLUSION_LIST) or '.min.js' in n:
        return JS_PRIORITY['vendor']
    if any(k in n for k in ('index', 'main', 'app', 'entry', 'bundle', 'setup')):
        return JS_PRIORITY['entry']
    return JS_PRIORITY['chunk']

def is_third_party(url):
    """第三方JS快速判定(node_modules/CDN/已知库, 跳过省流量)

    修正: 旧实现把 `.min.js` 一律判为第三方 —— 但业务代码在
    生产环境同样会被压缩, 一刀切会把**业务入口**也剔出下载队列, 与
    `get_js_priority()` 的 entry 语义冲突。现改为: 先看路径特征(node_modules /
    CDN 域名), 再看文件名是否命中已知库名单(`JS_EXCLUSION_LIST`)。
    """
    u = url.lower()
    if any(k in u for k in ('node_modules', '/vendor/', 'cdn.', 'unpkg',
                            'jsdelivr', 'bootcdn', 'cdnjs')):
        return True
    name = u.rsplit('/', 1)[-1]
    # 构建器给第三方包起的**文件名形态**: `vendor-<hash>.js` / `chunk-vendors-<hash>.js` /
    #   `vendor.<hash>.js`。旧实现只匹配路径里的 `/vendor/`, 于是 Vite 把第三方包打成
    #   `assets/vendor-BAAikhJs.js` 时**判不出第三方**(实测: 2.0MB 的 vendor 包被当业务包,
    #   触发 webcrack 拆包 → 每文件最长 120s, 把 JS 阶段预算吃光)。
    if re.match(r'^(?:chunk[-._])?vendors?[-._]', name):
        return True
    return any(k in name for k in JS_EXCLUSION_LIST)

# ---- 混淆检测: 命中>=3个特征提示 --runtime ----
OBFUSCATION_HINTS = ['_0x', 'atob(', r'\x', r'\u00', 'eval(', 'String.fromCharCode', 'decodeURIComponent(', 'btoa(']
OBF_KEYS = OBFUSCATION_HINTS  # 历史别名(原名兼容已拆分的 core.py); 现消费点 = js_extract

def obfuscation_score(text):
    """统计混淆特征命中数 

    旧 `is_obfuscated(text) -> bool` 全项目零调用 —— js_extract.deep_analyze 内联实现了同一
    段逻辑 `sum(1 for k in OBF_KEYS if k in text)`, 因为它除了判断还要把命中数写进
    发现项的说明(`命中 N/6 特征`)。把函数改成返回计数, 两边就能共用一份实现,
    阈值判断留在调用方(deep_analyze 用 >= 3)。

    ⚠️ 本函数**只计数, 不能单独作为"是否混淆"的判据** —— 见 `is_obfuscated()`。
    """
    return sum(1 for h in OBFUSCATION_HINTS if h in text)

# 真正判定"是否混淆"。
# 为什么不能只看计数: `\\x` / `\\u00` / `btoa(` / `decodeURIComponent(` /
#   `String.fromCharCode` 在 **axios / vue 等正常库代码**里本来就有 ——
#   "压缩(minify)" ≠ "混淆(obfuscate)": 前者是打包常态, 后者才是分析障碍。
# 判据(任一成立才算混淆):
#   1. **强标记**: `_0x` 标识符(javascript-obfuscator 的招牌) 或 `eval(`;
#   2. **转义密度**: `\\xNN` / `\\uNNNN` 的**数量 >= 20** 且**占比 > 阈值** ——
#      正常代码里这类转义极少(实测 axios 压缩源码 51KB 仅 14 个, 占比 0.00027),
#      混淆器则大面积铺满; 加绝对下限是为了避免**短样本**被小数目拉高占比而误判。
_RE_HEX_ESC = re.compile(r'\\x[0-9a-fA-F]{2}')
_RE_UNI_ESC = re.compile(r'\\u[0-9a-fA-F]{4}')
OBF_ESC_MIN = 20                 # 转义序列绝对数量下限
OBF_ESC_DENSITY = 0.002          # 每 500 字符 >1 个转义序列

def is_obfuscated(text):
    """是否**真的**混淆(区别于"仅压缩")。用于替代裸的 `obfuscation_score(...) >= 3`。"""
    if not text:
        return False
    if '_0x' in text:
        return True
    # 只认**打包器特征**的 eval(如 Dean Edwards packer `eval(function(p,a,c,k,e,...)`)。
    #   不再"见 `eval(` 即判混淆" —— 正常库也用 eval( 做数值/表达式求值
    #   (实测 huazhu main.cherry.js 的 `eval(subDD)` 被误报为"疑似混淆")。
    if re.search(r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e', text):
        return True
    n = len(text)
    if n < 200:
        return False
    esc = len(_RE_HEX_ESC.findall(text)) + len(_RE_UNI_ESC.findall(text))
    return esc >= OBF_ESC_MIN and (esc / n) > OBF_ESC_DENSITY

# ---- JS 加密/签名逻辑检测 ----
# 真实授权侦察里, 前端的 API 签名、token 生成、anti-bot 常常藏在 JS 的加密逻辑中。
# 工具应当把它标记出来, 供人工逆向 —— 否则使用者只看到一堆接口, 不知道其中哪几个
# 需要逆向出签名算法才能打。
# 与混淆检测的区别: 混淆是"代码难以阅读"(packed/renamed), 加密是"代码真的在做
# 密码学运算"(签名/哈希/密钥派生)。两者都值得报, 但含义不同, 故分两条发现。
JS_CRYPTO_HINTS = [
    ('CryptoJS', re.compile(r'CryptoJS\.')),
    ('crypto-js库', re.compile(r'crypto-js')),
    ('WebCrypto-subtle', re.compile(r'crypto\.subtle|subtle\.(?:encrypt|decrypt|sign|verify|deriveKey|deriveBits|digest|importKey|generateKey)')),
    ('AES', re.compile(r'\bAES\b|aesEncrypt|aesDecrypt')),
    ('RSA/JSEncrypt', re.compile(r'\bRSA\b|JSEncrypt')),
    ('PBKDF2', re.compile(r'[Pp]bkdf2')),
    ('HMAC', re.compile(r'\bHMAC\b|createHmac')),
    ('哈希(SHA)', re.compile(r'SHA(?:1|256|512)|createHash')),
    ('密钥操作', re.compile(r'importKey|deriveKey|deriveBits|generateKey')),
    ('encrypt调用', re.compile(r'\.encrypt\(')),
    ('sign调用', re.compile(r'\.sign\(')),
]

def crypto_score(text):
    """返回 (命中标签列表, 是否应报告)。

    判定: 命中任意"强信号"(库/subtle/哈希/密钥派生/HMAC/PBKDF2/AES/RSA)即报;
    仅命中弱信号(.encrypt( / .sign() )时需 >=2 个才报, 避免普通方法名误报。
    """
    strong = [lbl for lbl, rx in JS_CRYPTO_HINTS
              if lbl not in ('encrypt调用', 'sign调用') and rx.search(text)]
    weak = [lbl for lbl, rx in JS_CRYPTO_HINTS
            if lbl in ('encrypt调用', 'sign调用') and rx.search(text)]
    hits = strong + weak
    report = bool(strong) or len(weak) >= 2
    return hits, report


# JS 内容线索四表（"JS 不只抽 path" —— 从 JS 正文再抽四类**发现级线索**）
#   纯静态匹配(不执行、不发包); 同源 → MED, 跨域(第三方库) → INFO(与 crypto 同口径)。
#   全部是"攻击面线索", 非漏洞判定。

# ① 执行 sink —— RCE 链的**入口线索**(有入口才值得下游跟)
#   注: **不**收 `.exec(`(RegExp.exec 太常见, 会淹没); 只收真正的命令/代码执行面。
JS_EXEC_SINKS = [
    ('eval', re.compile(r'\beval\s*\(')),
    ('Function构造', re.compile(r'\bnew\s+Function\s*\(|\bFunction\s*\(\s*[\'"]')),
    ('模板渲染', re.compile(r'(?i)\b(?:Handlebars|mustache|nunjucks|ejs|doT|pug|jade)\s*\.\s*(?:compile|render|renderString|template)')),
    ('命令执行', re.compile(r'\b(?:child_process|execSync|spawnSync|execFileSync)\b|\bspawn\s*\(')),
    ('反序列化', re.compile(r'\b(?:unserialize|deserialize|readObject)\b|pickle\.loads\s*\(|yaml\.load\s*\(')),
    ('字符串代码', re.compile(r'\bsetTimeout\s*\(\s*[\'"]|\bsetInterval\s*\(\s*[\'"]|document\.write\s*\(')),
]

# ② 前端密钥材料 —— IDOR"自己加密邻号再换"的**前置钥匙**
JS_KEY_MATERIAL = [
    ('PEM公钥', re.compile(r'-----BEGIN PUBLIC KEY-----')),
    ('JSEncrypt公钥', re.compile(r'setPublicKey\s*\(')),
    ('前端公钥字面量', re.compile(r'(?i)\b(?:publicKey|pubKey|PUBLIC_KEY|rsaKey)\s*[:=]\s*[\'"][A-Za-z0-9+/=]{64,}[\'"]')),
]

# ③ 演示号 / 测试租户 —— 硬编码的"钥匙账号"(下游明确: 当钥匙用, 不是弱口令)
JS_DEMO_ACCOUNT = [
    ('演示账号名', re.compile(r'(?i)\b(?:demo|test|guest|trial|sandbox)[_-]?(?:user|account|admin|login|pwd|pass)\b')),
    ('演示租户', re.compile(r'(?i)\b(?:tenant|corp|org|merchant|app)[_-]?(?:id|code|no)\s*[:=]\s*[\'"](?:demo|test|trial|dev)[-_0-9a-z]*[\'"]')),
    ('演示凭据对', re.compile(r'(?i)\b(?:username|account|login|user)\s*[:=]\s*[\'"](?:demo|test|guest|trial)[-_0-9a-z]{0,12}[\'"]')),
]

# ④ 签名/加密用法 —— 下游"自己算签名、打只要 sign 不要 Cookie 的口"的依据
JS_SIGN_HINTS = [
    ('签名参数', re.compile(r'(?i)[\'"](?:sign|signature|x[-_]?sign|app[-_]?sign)[\'"]')),
    ('签名三件套', re.compile(r'(?i)[\'"](?:nonce|timestamp)[\'"]')),
    ('签名函数', re.compile(r'\b(?:makeSign|getSign|createSign|genSign|calcSign|signParams)\s*\(')),
]

# 四表统一扫描入口(供 js_extract.deep_analyze 调用, 与 crypto_score 同口径)。
# 返回 {表名: (命中标签列表, 是否应报告)}; 四表均为强信号 —— 任一命中即报。
_JS_MARKER_TABLES = (
    ('exec_sinks', JS_EXEC_SINKS),
    ('key_material', JS_KEY_MATERIAL),
    ('demo_account', JS_DEMO_ACCOUNT),
    ('sign_hints', JS_SIGN_HINTS),
)


def scan_js_markers(text):
    """扫描 JS 正文四类"发现级线索"(执行 sink / 密钥材料 / 演示账号 / 签名用法)。

    返回 dict: {'exec_sinks': (hits, report), 'key_material': ..., 'demo_account': ...,
                'sign_hints': ...}。hits 为命中标签列表; report 为是否值得报告(任一命中即报)。
    纯静态匹配(不执行、不发包); 与 crypto_score 同源口径, 跨域降级由调用方依据同源性处理。
    """
    out = {}
    for key, table in _JS_MARKER_TABLES:
        hits = [lbl for lbl, rx in table if rx.search(text)]
        out[key] = (hits, bool(hits))
    return out


# ---- RESTful 路径占位符识别与展开(命中优化: /:id -> /1) ----
# 覆盖两种主流写法: Express/Koa/Next.js 的 `:id`, 以及 Vite/自研路由的 `*id`
RE_REST_PARAM = re.compile(r'[:*][A-Za-z_][A-Za-z0-9_]*')
RE_PLACEHOLDER = re.compile(r'\{(\w+)\}')               # SpringBoot/FastAPI 路径参数 {id}

# 注: 删除了此处的 `expand_restful(path)` —— 它被 core.expand_restful_v45()
#     完全取代(后者多了语义值推断: 参数名 id→1 / page→1 / size→20 / time→2024-01-01,
#     而旧版只会无脑塞 '1'/'123'/'abc'/'*')。两个展开器并存只会让调用方选错那个更差的。
#     上面两条编译正则保留下来, 改由 expand_restful_v45 复用, 不再各自内联写一遍。

# ---- 常见 query 参数补全(命中优化: 从参数名生成带 query 的探活路径) ----
# 语义驱动参数值推断 — 根据参数名语义推断合理默认值, 而非固定字典
PARAM_SEMANTICS = {
    'page': ('1', '2', '10'),
    'size': ('10', '20', '50'),
    'limit': ('10', '20', '100'),
    'offset': ('0', '10', '20'),
    'q': ('test', 'admin', 'query'),
    'search': ('user', 'admin', 'x'),
    'type': ('1', 'json', 'xml'),
    'status': ('1', 'active', 'pending'),
    'keyword': ('test', 'fuzz', 'x'),
    'category': ('1', 'all', 'default'),
    'tag': ('important', 'latest', 'x'),
    'date': (lambda: __import__('datetime').date.today().strftime('%Y-%m-%d'),),
    'timestamp': (lambda: str(int(__import__('time').time())),),
    'version': ('1', '2', 'latest'),
    'token': ('dummy_token_for_probe',),
    'sort': ('id', 'name', 'created_at'),
    'order': ('asc', 'desc'),
    'start': ('0', '1'),
    'end': ('100', '999'),
    'id': ('1', '123', 'abc'),
    'user_id': ('1', 'admin', 'root'),
    'order_id': ('1', '1001', 'ORD-001'),
}

def infer_param_value(name):
    """语义驱动参数值推断: 根据参数名关键词匹配语义类别, 返回合理默认值"""
    nlow = (name or '').lower()
    # 精确匹配
    if nlow in PARAM_SEMANTICS:
        v = PARAM_SEMANTICS[nlow][0]
        return v() if callable(v) else v
    # 模糊匹配(参数名包含关键词)
    for keyword, values in PARAM_SEMANTICS.items():
        if keyword in nlow:
            v = values[0]
            return v() if callable(v) else v
    return '1'  # 兜底默认值

def with_default_query(path, params):
    """对与路径关联的参数名集合(JS上下文实际出现), 语义驱动生成带默认 query 值的探活变体
    仅对已有关联参数的路径补query(不再全量填充), 已有query不重复拼接, 上限3个参数"""
    if not params or '?' in path:
        return [path]
    qs = '&'.join(f'{k}={infer_param_value(k)}' for k in sorted(params)[:3])
    return [f'{path}?{qs}', path]

# ---- 资源上限 / 状态文件 ----
# 注: 此处原有 `MAX_JS` / `MAX_RESP_SIZE` / `STATE_FILE` / `MAX_BASELINE_SIZE` 四个常量, 但
#   **全项目从未使用**(死代码)。其中 `MAX_RESP_SIZE`("单个JS/响应体上限100KB")尤其有害 ——
#   会**误导**读者以为响应体已被限长(实际未限; 一个历史 ReDoS 评估即据此得出错误前提)。
#   已移除, 权威来源如下:
#     · JS 递归上限        → config['max_js'](默认 200)
#     · 断点续扫状态文件    → config['state_path'](默认 .facet_state.json)
#     · 响应体大小上限      → **不设**(对 JS/HTML 截断会丢掉其后的接口/参数, 违背"提取只增不减")

# ---- 模板字符串/参数解构(P2优化): `/api/user/${id}/orders` -> 展开变体 ----
RE_TEMPLATE_URL = re.compile(r'[`\'"](\/[^`\'"]*)\$\{([^}]*)\}([^`\'"]*)[`\'"]')  # 含${}的API路径

# ---- 智能探活排序 / URL规范化(P0~P1优化) ----
# 注: 原先此处还有一个 `response_fingerprint(text) -> (len, hash)` 的响应聚类函数,
#     但全项目从未调用 —— core/guard.py 的 `_fingerprint_resp(r)` 才是真正在用的实现,
#     且区分度更高(前200字符 + 前12标签 + 10字节长度桶, 见该函数 docstring 的对比说明)。
#     为避免两套"响应指纹"并存造成误用, 已删除这个死函数。
def score_api_priority(p):
    """智能探活排序: 安全面评分(管理面100最高) + 文档类路径加分"""
    low = p.lower()
    score = 0
    for name, kws in SECMAP:
        if any(k in low for k in kws):
            score += {'管理运维面': 100, '未鉴权敏感面': 95, '认证会话面': 90,
                      '资金交易面': 85, '身份PII面': 80, '开放接口面': 70, '文件传输面': 65}.get(name, 50)
            break
    if any(k in low for k in ('swagger', 'api-docs', 'actuator', 'druid', 'openapi')):
        score += 15
    return score

def normalize_path(p):
    """URL规范化去重: 去尾斜杠/默认index, query参数排序 (防重复探测)"""
    from urllib.parse import parse_qsl, urlencode, urlsplit
    sp = urlsplit(p)
    path = sp.path.rstrip('/') or '/'
    if sp.query:
        qs = sorted(parse_qsl(sp.query, keep_blank_values=True))
        return sp._replace(path=path, query=urlencode(qs)).geturl()
    return sp._replace(path=path, query='').geturl()

# 端点动态段归一 —— 把"数字/UUID/哈希/日期/长随机串"路径段替换为占位符,
#   用于同族端点聚合(报告更短)与探测去重(省配额)。仅归一"纯动态"段, 保留语义词
#   (active/archived/admin/v2), 以区分真实不同端点(对齐 katana -fsu 的 ID 参数化语义)。
_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                      r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_HEX_RE = re.compile(r'^[0-9a-fA-F]{16,}$')
# base64 段: 标准 base64 字符集, 长度≥16, 且含 +/= 标记(避免与通用 {token} 混淆)
_B64_RE = re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')
# 带扩展名的文件段(只归并明显静态的资产扩展名, 排除 .json/.html/.js/.php 等接口型后缀)
_FILE_EXT = ('png', 'jpg', 'jpeg', 'gif', 'svg', 'pdf', 'zip', 'gz', 'tar', 'rar', '7z',
             'csv', 'xls', 'xlsx', 'doc', 'docx', 'txt', 'rtf', 'mp4', 'mp3', 'wav',
             'ogg', 'webm', 'woff', 'woff2', 'ttf', 'eot', 'otf', 'ico', 'webp',
             'bmp', 'tif', 'tiff')

def _norm_seg(seg):
    if _UUID_RE.match(seg):
        return '{uuid}'
    if re.fullmatch(r'\d{4}-\d{2}-\d{2}', seg) or re.fullmatch(r'\d{8}', seg):
        return '{date}'
    if _HEX_RE.match(seg):
        return '{hash}'
    if seg.isdigit():
        return '{id}'
    # base64 段(需含 +/= 标记才判定, 否则留给 {token}): 长随机 base64 串归一
    if '=' in seg or '/' in seg or '+' in seg:
        if _B64_RE.match(seg):
            return '{b64}'
    # 带扩展名文件段(图片/文档/媒体/字体等静态资产)
    if '.' in seg:
        _ext = seg.rsplit('.', 1)[1].lower()
        if _ext in _FILE_EXT:
            return '{file}'
    # 【已移除 slug 折叠】原规则把"连字符小写词"(如 my-demands / order-action / submit-demand /
    #   available-boosters)一律折成 `{slug}` → 把**互不相同的业务端点合并进同一族**:
    #   报告 `_group_endpoints` 只留一个代表, 其余被吞掉(退化成"零发包"补显示),
    #   与"提取到的接口一条不少 / 每个接口都要探活"冲突。业务端点名与"动态 slug"无法靠
    #   字符串可靠区分, 而本工具是**接口侦察**工具(连字符段多为静态业务名) →
    #   取消该折叠: 连字符段按**静态**保留。
    # 长短字母数字混合(疑似随机 token / 短 hash): 长度≥16 且含数字
    if len(seg) >= 16 and re.fullmatch(r'[A-Za-z0-9_\-]+', seg) and any(c.isdigit() for c in seg):
        return '{token}'
    return seg

def normalize_endpoint(path):
    """将路径中的动态段归一为占位符, 返回归一化端点键(用于同族聚合/去重)。

    >>> normalize_endpoint('/api/user/123')
    '/api/user/{id}'
    >>> normalize_endpoint('/api/user/admin')
    '/api/user/admin'
    >>> normalize_endpoint('http://x/api/comment/abc123de-1234-1234-1234-1234567890ab/replies')
    '/api/comment/{uuid}/replies'
    """
    from urllib.parse import urlsplit
    sp = urlsplit(path)
    base = (sp.path or path).rstrip('/')
    segs = [s for s in base.strip('/').split('/') if s]
    if not segs:
        return '/'
    return '/' + '/'.join(_norm_seg(s) for s in segs)


# 路径推断（方案 4.6）—— 由已知路径派生"同族兄弟"候选
#   性质: **纯字符串变换**, 不做任何语义猜测(不猜业务、不猜参数), 只做命名习惯上的等价变换。
#   用途: 补"静态提取不到的兄弟接口"(如只暴露了 /api/order/create, 推断 /api/order/detail)。
#   产出: 必须与"提取到的真实接口"**分区存放**(`out['inferred_paths']`), 报告单独标注来源。
_VERB_FAMILIES = (
    # 族内顺序 = 命中优先级(取用时按序截断), 对齐方案示例: create→edit/delete/detail
    ('create', ('edit', 'delete', 'detail', 'add', 'new', 'update', 'save', 'submit')),
    ('add', ('create', 'edit', 'delete', 'detail', 'new', 'update', 'save')),
    ('new', ('create', 'add', 'edit', 'detail', 'save')),
    ('edit', ('update', 'delete', 'detail', 'create', 'view', 'save', 'add')),
    ('update', ('edit', 'save', 'detail', 'create', 'add')),
    ('delete', ('remove', 'del', 'destroy', 'edit', 'detail')),
    ('remove', ('delete', 'del', 'destroy')),
    ('del', ('delete', 'remove', 'destroy')),
    ('detail', ('info', 'view', 'edit', 'delete', 'show', 'get', 'query')),
    ('info', ('detail', 'view', 'show', 'get', 'query')),
    ('view', ('detail', 'info', 'show', 'get', 'query')),
    ('list', ('query', 'search', 'page', 'index', 'all')),
    ('query', ('list', 'search', 'detail', 'info')),
    ('search', ('query', 'list', 'filter')),
    ('login', ('signin', 'sign_in', 'auth', 'token', 'logon')),
    ('signin', ('login', 'auth', 'token')),
    ('logout', ('signout', 'sign_out', 'logoff')),
    ('register', ('signup', 'sign_up', 'create')),
    ('signup', ('register', 'sign_up', 'create')),
    ('upload', ('download', 'import', 'file')),
    ('download', ('upload', 'export', 'file')),
    ('export', ('import', 'download', 'excel', 'csv')),
    ('import', ('export', 'upload')),
    ('enable', ('disable', 'toggle', 'active')),
    ('disable', ('enable', 'toggle', 'active')),
    ('open', ('close', 'toggle')),
    ('close', ('open', 'toggle')),
    ('start', ('stop', 'restart', 'pause')),
    ('stop', ('start', 'restart', 'pause')),
    ('lock', ('unlock', 'block')),
    ('unlock', ('lock', 'block')),
    ('pay', ('payment', 'refund', 'checkout', 'order')),
    ('refund', ('pay', 'payment', 'cancel')),
    ('send', ('submit', 'push', 'notify')),
    ('bind', ('unbind', 'link', 'connect')),
    ('unbind', ('bind', 'unlink', 'disconnect')),
)
_VERB_MAP = {k: v for k, v in _VERB_FAMILIES}
_BATCH_SUFFIX = ('-batch', '_batch', 'batch')

# 栈指纹 → 服务端扩展名词汇(用于**路径推断的扩展名变换门控**)。
#   纯**栈语义**(与 `recon/fingerprint.py` 的 FP_RULES 同源的签名事实), **不是**站点/变量名白名单。
#   键名与 FP_RULES 指纹名对齐(仅列真实存在的指纹, 避免"死键")。
STACK_EXT_VOCAB = {
    'PHP': ('.php',),
    'ASP.NET': ('.asp', '.aspx', '.ashx', '.asmx'),
    'Spring': ('.do', '.action'),
    'Tomcat': ('.jsp', '.do'),
    'WebLogic': ('.jsp',),
}


def derive_ext_vocab(paths, fp_hits=None):
    """由**目标自身信号**归纳「服务端扩展名词汇」—— 供 `infer_path_variants` 的扩展名变换门控。

    ① **已观测扩展名**(最动态): 给定路径里出现的 `srv_ep_exts()` 扩展名;
    ② **栈指纹**(数据层 `STACK_EXT_VOCAB`): 命中 PHP/ASP.NET/Spring/Tomcat/WebLogic 时补其专属扩展名。

    返回并集(小写)。**空集** → 调用方不加/不换扩展名(仅剥后缀) —— 消除"栈盲扩展名"噪声
    (实测 Vite/React 站被无脑加 `.php/.aspx` 派生出一堆垃圾)。**纯数据驱动, 无站点白名单**。
    """
    vocab = set()
    _exts = tuple(srv_ep_exts())
    for _p in (paths or ()):
        _low = str(_p).lower().split('?')[0].split('#')[0]
        for _e in _exts:
            if _low.endswith(_e):
                vocab.add(_e)
    for _h in (fp_hits or ()):
        for _e in STACK_EXT_VOCAB.get(_h, ()):
            vocab.add(_e)
    return vocab


def _plural_swap(seg):
    """单复数互换(user↔users / category↔categories / box↔boxes)。仅对**全字母**段生效。"""
    if not seg.isalpha():
        return None
    lo = seg.lower()
    if lo.endswith('ies') and len(seg) > 3:
        return seg[:-3] + 'y'
    if lo.endswith(('ses', 'xes', 'zes', 'ches', 'shes')) and len(seg) > 3:
        return seg[:-2]
    if lo.endswith('s') and not lo.endswith('ss') and len(seg) > 1:
        return seg[:-1]
    if lo.endswith('y') and len(seg) > 1 and seg[-2].lower() not in 'aeiou':
        return seg[:-1] + 'ies'
    return seg + 's'


def _split_ext(seg):
    """拆出 (主干, 扩展名)；无扩展名时扩展名为 ''。"""
    i = seg.rfind('.')
    if i <= 0:
        return seg, ''
    return seg[:i], seg[i:].lower()


def infer_path_variants(path, max_out=8, allowed_exts=None):
    """由已知路径派生**同族候选**(方案 4.6): 动词族 / 单复数 / 扩展名 / 批量↔单品。

    纯字符串变换, 不含任何语义猜测。返回**不含原路径**的有序变体列表。

    **按类别分桶取用**(动词族 ≤4 / 扩展名 ≤3 / 批量 ≤1 / 单复数 ≤1) —— 保证四类变换
    都有代表, 不会被某一类挤占; 总上限 `max_out`。

    `allowed_exts`: **本站扩展名词汇**(由 `derive_ext_vocab` 从目标指纹/已观测端点归纳)。
      扩展名的**加/换**只在该词汇内进行; **为空则不加、不换**(只保留"剥后缀") —— 消除
      "栈盲加 `.php/.aspx`"的噪声(对 SPA/Node 站毫无意义)。动词族/单复数/批量不受影响。
    """
    if not path or not path.startswith('/'):
        return []
    # 基址前置校验: 静态资源 / 畸形路径**不派生** —— 否则会对 `/x/images/sps/-`、
    #   `/x/authError.html/y` 这类畸形基址再派生出 `.aspx/.php/.json/-batch` 一堆垃圾。
    if is_static_or_malformed_path(path):
        return []
    from urllib.parse import urlsplit
    sp = urlsplit(path)
    segs = [s for s in (sp.path or '').strip('/').split('/') if s]
    if not segs:
        return []
    _seen = {path}
    verb, ext, batch, plural = [], [], [], []

    def _push(bucket, v):
        if v and v not in _seen:
            _seen.add(v)
            bucket.append(v)

    # ① 动词族: 只替换**最后一个**匹配动词的段(更靠近动作, 噪声最小)
    for _i in range(len(segs) - 1, -1, -1):
        _stem, _ext = _split_ext(segs[_i])
        _fam = _VERB_MAP.get(_stem.lower())
        if _fam:
            for _v in _fam:
                _n = list(segs)
                _n[_i] = _v + _ext
                _push(verb, '/' + '/'.join(_n))
            break
    # ② 扩展名变换(带后缀 ↔ 去后缀 ↔ 其它后缀) —— **仅在本站扩展名词汇内**(栈/观测门控)
    _stem, _ext = _split_ext(segs[-1])
    _exts = tuple(allowed_exts or ())
    if _ext:
        # 剥后缀: 始终有意义(`/x.php` 与 `/x` 常并存)
        _n = list(segs)
        _n[-1] = _stem
        _push(ext, '/' + '/'.join(_n))
        # 换后缀: 仅在**本站词汇**内换(无词汇 → 不换)
        for _e in _exts:
            if _e != _ext:
                _n = list(segs)
                _n[-1] = _stem + _e
                _push(ext, '/' + '/'.join(_n))
    elif _exts and len(_stem) >= 3 and not _stem.isdigit():
        # 加后缀: 仅在**本站词汇**内加(无词汇 → 不加)
        for _e in _exts[:3]:
            _n = list(segs)
            _n[-1] = _stem + _e
            _push(ext, '/' + '/'.join(_n))
    # ③ 批量↔单品(后缀加在**主干**上, 即扩展名之前; 最长后缀匹配, 避免 `submit-batch`→`submit-`)
    _low_stem = _stem.lower()
    _hit = False
    for _sfx in _BATCH_SUFFIX:
        if _low_stem.endswith(_sfx) and len(_stem) > len(_sfx):
            _n = list(segs)
            _n[-1] = _stem[:-len(_sfx)] + _ext
            _push(batch, '/' + '/'.join(_n))
            _hit = True
            break
    if not _hit and _stem.isalpha() and _stem.islower() and _stem not in _VERB_MAP:
        # 加 `-batch` 仅对**简单小写资源名词**(非动词 / 非驼峰 / 非复合) —— 否则
        #   `/login`→`/login-batch`、`/companyConfig`→`/companyConfig-batch` 之类纯噪声。
        _n = list(segs)
        _n[-1] = _stem + '-batch' + _ext
        _push(batch, '/' + '/'.join(_n))
    # ④ 单复数(最后一个**简单小写资源名词**段; 跳过动词段与复合/驼峰段)
    for _i in range(len(segs) - 1, -1, -1):
        _seg = segs[_i]
        if not (_seg.isalpha() and _seg.islower() and _seg.lower() not in _VERB_MAP):
            continue
        _p = _plural_swap(_seg)
        if _p and _p != _seg:
            _n = list(segs)
            _n[_i] = _p
            _push(plural, '/' + '/'.join(_n))
            break
    out = []
    for _bucket, _cap in ((verb, 4), (ext, 3), (batch, 1), (plural, 1)):
        out.extend(_bucket[:_cap])
    return out[:max_out]

# SENSITIVE_PATTERNS 40项密钥正则库(预编译)
# 修复项:
# 1. Facebook-ClientID: 增加上下文约束(facebook/fb/oauth/app)
# 2. 密钥键值对: 值长度下限8, 排除占位符
# 3. URL内嵌密码: 排除常见弱密码(password/admin/root/user/test/123456), 密码长度≥6
# 4. Bearer令牌: 排除token/null/undefined/test/demo占位符, 长度≥8(短令牌由过滤层降级为MED)
# 5. 内网地址: 正则不变, 通过后过滤排除内部服务(grafana/prometheus等)
# 6. 硬编码用户名: 长度下限4, 排除常见默认值
# 7. 硬编码密码: 长度下限6, 排除弱口令
# 8. 硬编码密钥: 拆分client_id为INFO级别, 其余要求长度≥8
# CTF 目标标记的**前缀形态**表(非站点白名单; 可经 `--secret-db` 追加自有平台)。
#   见 `SENSITIVE_PATTERNS` 里的 `CTF-flag` 规则。
CTF_FLAG_PREFIXES = ('flag', 'ctf', 'key', 'picoctf', 'htb', 'thm',
                     'nssctf', 'ctfshow', 'dasctf', 'buuctf')
CTF_FLAG_RE = re.compile(
    r'(?i)\b(?:' + '|'.join(CTF_FLAG_PREFIXES) + r')\{[^{}\s\x00-\x1f]{1,200}\}')

SENSITIVE_PATTERNS = [
    # ---- 私钥/证书 (CRITICAL) ----
    ('私钥-PEM', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 'CRITICAL'),
    # ---- 云平台AK (HIGH) ----
    ('云AK-阿里云', re.compile(r'\b(?:LTAI|AKID)[A-Za-z0-9]{10,}\b'), 'HIGH'),
    ('云AK-AWS', re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 'HIGH'),
    ('AWS-SecretKey', re.compile(r'\baws_secret_access_key\b[^\n]{0,40}[:=][\'" ]?([A-Za-z0-9/+=]{40})'), 'HIGH'),
    ('AWS-MWS-Token', re.compile(r'\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'), 'HIGH'),
    # ---- Google (HIGH) ----
    ('Google-APIKey', re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), 'HIGH'),
    ('Google-OAuthToken', re.compile(r'\bya29\.[0-9A-Za-z\-_]+\b'), 'HIGH'),
    ('Google-Captcha', re.compile(r'\b6L[0-9A-Za-z\-_]{38}\b'), 'HIGH'),
    ('Google-OAuthID', re.compile(r'\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b'), 'HIGH'),
    # ---- Facebook (HIGH) ----
    ('Facebook-Token', re.compile(r'\bEAACEdEose0cBA[0-9A-Za-z]+\b'), 'HIGH'),
    # 客户端 ID 本就随前端公开(非机密) → INFO; 并要求 `facebook` 语境, 避免"app + 长数字"误命中
    #   (实测 medsci 的 `app_id=".concat("2021002130689760` 被误报为 MED 敏感信息)。
    ('Facebook-ClientID', re.compile(r'(?i)facebook[^\n]{0,40}?\b[0-9]{13,17}\b'), 'INFO'),
    # ---- SaaS/第三方 (HIGH) ----
    # 旧规则是**裸 UUID** 正则 → 任意 `8-4-4-4-12` 十六进制串都判 HIGH。
    #   Heroku API Key 确实是 UUID 形态, 但**必须**伴随 heroku 语境才成立;
    #   裸 UUID 不构成任何机密泄露, 已从规则集中彻底移除。
    #   若 UUID 真的出现在 `api_key = "..."` 这类键值语境中, 会由下面的
    #   `硬编码AK/SK` / `密钥键值对` 规则(带上下文)正确捕获, 无需裸值兜底。
    ('Heroku-APIKey', re.compile(r'(?i)heroku[^\n]{0,60}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b'), 'HIGH'),
    ('MailChimp-APIKey', re.compile(r'\b[0-9a-f]{32}-us[0-9]{1,2}\b'), 'HIGH'),
    ('Mailgun-APIKey', re.compile(r'\bkey-[0-9a-zA-Z]{32}\b'), 'HIGH'),
    ('Braintree-Token', re.compile(r'\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b'), 'HIGH'),
    ('Picatic-APIKey', re.compile(r'\bsk_live_[0-9a-z]{32}\b'), 'HIGH'),
    ('Slack-Token', re.compile(r'\bxox[baprs]-[0-9a-zA-Z]{10,}\b'), 'HIGH'),
    ('Slack-Webhook', re.compile(r'https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,}/B[0-9A-Za-z_]{8,}/[0-9A-Za-z_]{24}'), 'HIGH'),
    ('Stripe-APIKey', re.compile(r'\b[rs]k_live_[0-9a-zA-Z]{24}\b'), 'HIGH'),
    ('Stripe-Restricted', re.compile(r'\brk_live_[0-9a-zA-Z]{24}\b'), 'HIGH'),
    ('Square-Token', re.compile(r'\bsq0atp-[0-9A-Za-z\-_]{22}\b'), 'HIGH'),
    ('Square-OAuthSecret', re.compile(r'\bsq0csp-[0-9A-Za-z\-_]{43}\b'), 'HIGH'),
    ('Twilio-APIKey', re.compile(r'\bSK[0-9a-fA-F]{32}\b'), 'HIGH'),
    ('Twilio-AccountSID', re.compile(r'\bAC[a-fA-F0-9]{32}\b'), 'HIGH'),
    # ---- 通用密钥 (HIGH/MED) ----
    ('URL内嵌密码', re.compile(r'\b([a-zA-Z]{3,10}://[^/\s:@]{3,20}:(?!password|admin|root|user|test|123456)[^/\s:@]{6,20}@[^/\s]*)'), 'HIGH'),
    ('密钥键值对', re.compile(r'[\'"`](\w*(?:secret|password|apikey|api_key|access_key|appsecret)\w*)[\'"`]\s*[:=]\s*[\'"`]([^\'"`]{8,})[\'"`]'), 'HIGH'),
    ('JWT令牌', re.compile(r'\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}(?:\.[A-Za-z0-9_\-]{0,})?(?=\s|$|["\'<>,;)})\]])'), 'HIGH'),
    ('Bearer令牌', re.compile(r'\bBearer\s+(?!(?:token|null|undefined|test|demo)\b)[A-Za-z0-9\-._~+/]{8,}=*\b'), 'MED'),
    ('GitHub-PAT', re.compile(r'\bgh[pousr]_[0-9A-Za-z]{36,}\b'), 'HIGH'),
    # S3 主机形态: 经典 `bucket.s3.amazonaws.com` / 区域 `bucket.s3.<region>.amazonaws.com`
    #   / `bucket.s3-<region>.amazonaws.com` / path-style `s3[.<region>].amazonaws.com/bucket/key`。
    #   旧正则 `X\.s3[.-][a-z0-9.-]*\.amazonaws\.com` 因 `[.-]` 吃掉 `s3` 后的点,
    #   **匹配不到经典形态**(实测 bisect 复现) → 改为 `s3(?:[.-]<middle>)?` 可选中间段。
    ('S3-URL', re.compile(r'https?://(?:[a-z0-9.\-]+\.)?s3(?:[.-][a-z0-9.\-]+)?\.amazonaws\.com[^\s\'"]*'), 'HIGH'),
    # ---- 数据库URI (HIGH/MED) ----
    # 字符类补上 `<>` —— 旧规则 `[^\s'"]+` 会一路吃掉 HTML 标签,
    #   证据里出现 `mysql://root:pw@10.0.0.1/x</html>` 这种尾巴, 影响可读性。
    ('MongoDB-URI', re.compile(r'\bmongodb(?:\+srv)?://[^\s\'"<>]+'), 'HIGH'),
    ('MySQL-URI', re.compile(r'\bmysql://[^\s\'"<>]+'), 'HIGH'),
    ('PostgreSQL-URI', re.compile(r'\bpostgres(?:ql)?://[^\s\'"<>]+'), 'HIGH'),
    ('Redis-URI', re.compile(r'\bredis://[^\s\'"<>]+'), 'MED'),
    # ---- 内网泄露 (MED) ----
    ('内网地址', re.compile(r'https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)[0-9.]+(?::\d+)?'), 'MED'),
    # ---- 硬编码账密 / AK-SK (用户需求: JS中 username/password/key/ak/sk) ----
    ('硬编码用户名', re.compile(r'(?<![\w.])[\'"`]?(?:username|user_name|login_name|account)["\'`]?\s*[:=]\s*["\'`]([^\'"`\s]{4,32})["\'"]'), 'MED'),
    ('硬编码密码', re.compile(r'(?<![\w.])[\'"`]?(?:password|passwd|pwd)["\'`]?\s*[:=]\s*["\'`]([^\'"`\s]{6,64})["\'"]'), 'HIGH'),
    ('硬编码AK/SK', re.compile(r'(?<![\w.])[\'"`]?(?:access_key|secret_key|access_key_id|secret_access_key|AccessKeyId|SecretAccessKey|accessKeySecret|ak_id|ak_secret|ak|sk)["\'`]?\s*[:=]\s*["\'`]([A-Za-z0-9+/=_\-]{8,64})["\'"]'), 'HIGH'),
    ('硬编码密钥', re.compile(r'(?<![\w.])[\'"`]?(?:app_key|app_secret|client_secret|auth_key|sign_key)["\'`]?\s*[:=]\s*["\'`]([^\'"`\s]{8,64})["\'"]'), 'HIGH'),
    ('ClientID-公开', re.compile(r'(?<![\w.])[\'"`]?(?:client_id)["\'`]?\s*[:=]\s*["\'`]([^\'"`\s]{6,64})["\'"]'), 'INFO'),
    # 通用 API Key 前缀(按**值**判定, 不依赖键名) —— 旧 `硬编码AK/SK` 只认
    #   键名(ak/sk/access_key…)且值需紧随其后, 于是 `mapAk:"ak_live_…"` 这类"键名不标准 +
    #   Stripe 风格前缀"的硬编码 AK 全漏。这里直接匹配值前缀, 覆盖 Stripe/通用 SaaS 形态。
    ('通用AK前缀', re.compile(r'(?<![\w])(?:ak_live|sk_live|pk_live|rk_live|ak_test|sk_test|pk_test)_[A-Za-z0-9]{8,64}(?![\w])'), 'HIGH'),
    # 内网主机名(.internal/.local/.corp/…) —— 旧 `内网地址` 只认 RFC1918 的
    #   IP 形态, 于是 `http://risk-gw.starmall.internal/...` 这类内网域名不被捕获。
    #   实测(真实站点): 裸正则会把 JS 的**属性访问**当成内网域名 —— `this.internal` / `e.internal`
    #   (压缩代码里的变量)被判为"内网主机名"误报。加两个负向先行断言:
    #     ① 首段不是"单字母."(排除 `e.internal` 这类压缩变量属性);
    #     ② 首段不是 JS 关键字/常见全局(this/self/window/document/…)后跟 `.`。
    ('内网主机名', re.compile(
        r'(?<![\w.-])'
        r'(?![a-z]\.)'
        r'(?!(?:this|self|window|document|global|module|exports|process|'
        r'prototype|constructor|import|require)\.)'
        r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:internal|intranet|local|corp|lan)(?![\w.-])',
        re.I), 'MED'),
    # ---- CTF 目标标记 (MED) ----
    #   CTF 靶场把"答案"以 `flag{...}` / `CTF{...}` / 各平台前缀写在页面 / JS 里。旧实现只认
    #   凭据 → **CTF 场景完全不 surface**(实测: 反混淆已能还原出 `flag{...}`, 报告里却没有)。
    #   前缀限定 + "flag 体非空、无空白、≤200 字符"两条**形态**约束把误报压到最低。
    #   证据**原样输出**(flag 不是凭据, 其全部价值就是"被看到")。
    ('CTF-flag', CTF_FLAG_RE, 'MED'),

    # ---- 服务商密钥规则扩容(对齐 Mantra / Gitleaks 的覆盖面) ----
    #   收录原则: **只收"带独特前缀"的形态** —— 前缀本身已足够特异, 误报率低;
    #   无前缀的通用形态仍交给 `硬编码AK/SK` / `密钥键值对`(熵过滤)处理。
    #   OpenAI: 旧 `sk-` + 48 位 / 新 `sk-proj-` + 长串; 负向前瞻排除 Anthropic(`sk-ant-`)避免重复命中
    ('OpenAI-APIKey',        re.compile(r'\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{32,}\b'), 'HIGH'),
    ('Anthropic-APIKey',     re.compile(r'\bsk-ant-[A-Za-z0-9\-_]{20,}\b'), 'HIGH'),
    ('HuggingFace-Token',    re.compile(r'\bhf_[A-Za-z0-9]{30,}\b'), 'HIGH'),
    ('Groq-APIKey',          re.compile(r'\bgsk_[A-Za-z0-9]{40,}\b'), 'HIGH'),
    ('Replicate-Token',      re.compile(r'\br8_[A-Za-z0-9]{30,}\b'), 'HIGH'),
    ('Perplexity-APIKey',    re.compile(r'\bpplx-[A-Za-z0-9]{32,}\b'), 'HIGH'),
    ('Supabase-ServiceKey',  re.compile(r'\bsbp_[a-f0-9]{40}\b'), 'HIGH'),
    ('Neon-APIKey',          re.compile(r'\bnapi_[A-Za-z0-9]{20,}\b'), 'HIGH'),
    ('PlanetScale-Token',    re.compile(r'\bpscale_tkn_[A-Za-z0-9_\-]{20,}\b'), 'HIGH'),
    ('Discord-BotToken',     re.compile(r'\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b'), 'HIGH'),
    ('Telegram-BotToken',    re.compile(r'\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b'), 'HIGH'),
    ('SendGrid-APIKey',      re.compile(r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b'), 'HIGH'),
    ('Snyk-Token',           re.compile(r'\bsnyk_[a-z0-9\-]{30,}\b'), 'HIGH'),
    ('Grafana-Token',        re.compile(r'\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b'), 'HIGH'),
    ('Pulumi-Token',         re.compile(r'\bpul-[a-f0-9]{40}\b'), 'HIGH'),
    ('NewRelic-APIKey',      re.compile(r'\bNRAK-[A-Z0-9]{27}\b'), 'HIGH'),
    ('npm-Token',            re.compile(r'\bnpm_[A-Za-z0-9]{36}\b'), 'HIGH'),
    ('DigitalOcean-Token',   re.compile(r'\bdop_v1_[a-f0-9]{64}\b'), 'HIGH'),
    ('Shopify-Token',        re.compile(r'\bshp(?:at|ca|pa|ss)_[a-f0-9]{32}\b'), 'HIGH'),
    ('Linear-APIKey',        re.compile(r'\blin_api_[A-Za-z0-9]{40}\b'), 'HIGH'),
    ('Notion-Token',         re.compile(r'\bntn_[A-Za-z0-9]{40}\b'), 'HIGH'),
    ('Doppler-Token',        re.compile(r'\bdp\.pt\.[A-Za-z0-9]{40,}\b'), 'HIGH'),
    ('Databricks-Token',     re.compile(r'\bdapi[a-f0-9]{32}\b'), 'HIGH'),
    ('Airtable-PAT',         re.compile(r'\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b'), 'HIGH'),
    ('GitLab-PAT',           re.compile(r'\bglpat-[A-Za-z0-9_\-]{20,}\b'), 'HIGH'),
    #   Slack app-level token 形如 `xapp-1-A012B3CDEF4-1234567890123-<64位hex>`(4 段)
    ('Slack-AppToken',       re.compile(r'\bxapp-[0-9]+-[A-Z0-9]{9,}-[0-9]{10,}-[A-Za-z0-9]{20,}\b'), 'HIGH'),
    ('Stripe-WebhookSecret', re.compile(r'\bwhsec_[A-Za-z0-9]{24,}\b'), 'HIGH'),
    ('Codecov-Token',        re.compile(r'(?i)codecov[^\n]{0,20}?\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'), 'HIGH'),
    ('GCP-ServiceAccount',   re.compile(r'"type"\s*:\s*"service_account"'), 'HIGH'),
    # ---- 继续扩容(仍只收"带独特前缀/强特征"形态) ----
    ('Azure-StorageKey',     re.compile(r'(?i)AccountKey\s*=\s*([A-Za-z0-9+/=]{88})'), 'HIGH'),
    ('Azure-SASToken',       re.compile(r'[?&]sig=[A-Za-z0-9%+/=]{40,}(?:&|$)'), 'HIGH'),
    ('AWS-SessionToken',     re.compile(r'(?i)aws_session_token["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{100,})'), 'HIGH'),
    ('GCP-OAuthToken',       re.compile(r'\bya29\.[0-9A-Za-z\-_]{20,}\b'), 'HIGH'),
    ('Firebase-DBURL',       re.compile(r'https://[a-z0-9\-]+(?:-default-rtdb)?\.firebaseio\.com'), 'MED'),
    ('Firebase-APIKey',      re.compile(r'(?i)firebase[^\n]{0,30}?AIza[0-9A-Za-z\-_]{35}'), 'HIGH'),
    ('Mapbox-Token',         re.compile(r'\bpk\.[A-Za-z0-9]{60,}\b'), 'HIGH'),
    ('Okta-Token',           re.compile(r'\b00[A-Za-z0-9_\-]{40}\b'), 'MED'),
    ('Cloudflare-APIKey',    re.compile(r'(?i)cloudflare[^\n]{0,30}?[a-z0-9_\-]{37}'), 'HIGH'),
    ('Hetzner-Token',        re.compile(r'\b[A-Za-z0-9]{32}ht[A-Za-z0-9]{32}\b'), 'MED'),
    ('Netlify-Token',        re.compile(r'\bnfp_[A-Za-z0-9]{40}\b'), 'HIGH'),
    ('Fly-Token',            re.compile(r'\bFlyV1 fm2_[A-Za-z0-9_\-=]{60,}'), 'HIGH'),
    ('Vercel-Token',         re.compile(r'\bvercel_[A-Za-z0-9]{24}\b'), 'HIGH'),
    ('Heroku-OAuthToken',    re.compile(r'\bHRKU-[A-Za-z0-9\-_]{40,}\b'), 'HIGH'),
    ('Railway-Token',        re.compile(r'\brailway_[A-Za-z0-9]{30,}\b'), 'MED'),
    ('Postman-APIKey',       re.compile(r'\bPMAK-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{34}\b'), 'HIGH'),
    ('SonarQube-Token',      re.compile(r'\bsqp_[A-Fa-f0-9]{40}\b'), 'HIGH'),
    ('CircleCI-Token',       re.compile(r'(?i)circleci[^\n]{0,20}?\b[0-9a-f]{40}\b'), 'HIGH'),
    ('Terraform-CloudToken', re.compile(r'\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}\b'), 'HIGH'),
    ('Pushover-Token',       re.compile(r'\b[a-zA-Z0-9]{30}\b(?=[^\n]{0,40}pushover)'), 'MED'),
    ('Twitch-Token',         re.compile(r'\b[a-z0-9]{30}\b(?=[^\n]{0,40}twitch)'), 'MED'),
    ('Klaviyo-APIKey',       re.compile(r'\bpk_[A-Za-z0-9]{34}\b'), 'HIGH'),
    ('Contentful-Token',     re.compile(r'\bCFPAT-[A-Za-z0-9_\-]{40,}\b'), 'HIGH'),
    ('Datadog-APIKey',       re.compile(r'(?i)datadog[^\n]{0,20}?\b[0-9a-f]{32}\b'), 'HIGH'),
    ('Sentry-DSN',           re.compile(r'https://[0-9a-f]{32}@[a-z0-9.\-]+\.ingest\.sentry\.io/\d+'), 'MED'),
    ('Algolia-APIKey',       re.compile(r'(?i)algolia[^\n]{0,20}?["\']([0-9a-f]{32})["\']'), 'MED'),
    ('Mailjet-Token',        re.compile(r'\b[0-9a-f]{32}\b(?=[^\n]{0,40}mailjet)'), 'MED'),
    ('Intercom-Token',       re.compile(r'\b(?:dG9r|dXNy)[A-Za-z0-9_\-=]{30,}\b'), 'MED'),
]

def load_external_secret_db(path):
    """加载外部敏感规则库(JSON), 返回 [(name, compiled_regex, severity), ...]。

    与 `--fingerprint-db` 同构: **内置规则保留, 外部规则追加**(不覆盖)。
    JSON 格式(顶层数组, 或 `{"rules": [...]}`)::

        [{"name": "MyCorpKey", "pattern": "mycorp_[A-Za-z0-9]{32}",
          "severity": "HIGH", "flags": "i"}, ...]

    容错: 单条正则语法错误/字段缺失 → 跳过该条, 不中断整体加载(与"一条坏规则毁掉整个库"相反)。
    """
    import json
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    items = data.get('rules', []) if isinstance(data, dict) else (data or [])
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        pat = it.get('pattern')
        if not pat:
            continue
        try:
            flags = re.I if 'i' in str(it.get('flags', '')).lower() else 0
            out.append((str(it.get('name') or 'external'),
                        re.compile(pat, flags),
                        str(it.get('severity', 'HIGH')).upper()))
        except Exception:
            continue
    return out


# HaE 规则兼容(演进建议 R6): 直接解析 gh0stkey/HaE 原生 YAML 规则文件。
#   结构(HaE 官方格式; 与 JsOwl 的 HaE 解析器同口径):
#     rules:
#       - group: <分组名>
#         rule:
#           - name: <规则名>
#             loaded: true        # false = 停用(跳过该条)
#             f_regex: '<正则>'   # 空 → 跳过
#             s_regex: ''         # HaE 的 status 规则, 本工具不消费(容忍字段)
#             format: '{0}'
#             color: green        # 无 severity 字段时由颜色推严重度
#             scope: ...          # 容忍但不使用(本工具分析脚本, 不分析代理流量)
#             engine: nfa
#             sensitive: false    # false(默认) → 大小写不敏感
#             # JsOwl/HaE 扩展(可选): severity / category
#   输出与 load_external_secret_db **完全一致** —— [(name, compiled_re, sev)],
#   由 _load_secret_rules 按"内置保留、外部追加"合并, 不覆盖内置规则。
#   HaE 高亮色 → 严重度(HaE 无显式 severity 时, 颜色承载作者的紧急度意图)。
_HAE_COLOR_SEV = {'red': 'CRITICAL', 'orange': 'HIGH', 'pink': 'HIGH',
                  'magenta': 'MED', 'yellow': 'MED', 'green': 'LOW',
                  'blue': 'INFO', 'cyan': 'INFO'}
_HAE_SEV_ALIAS = {'INFO': 'INFO', 'LOW': 'LOW', 'MEDIUM': 'MED', 'MED': 'MED',
                  'HIGH': 'HIGH', 'CRITICAL': 'CRITICAL'}


def _hae_slug(value):
    """HaE 规则名 → slug(非字母数字折叠为 '-', 保留中文等字母字符, 可读且唯一)。"""
    out = []
    last_dash = False
    for ch in str(value or '').lower():
        if ch.isalnum():
            out.append(ch)
            last_dash = False
        elif out and not last_dash:
            out.append('-')
            last_dash = True
    slug = ''.join(out).strip('-')
    return slug or 'rule'


def is_hae_rules_document(data):
    """数据是否 HaE 原生格式(顶层 'rules' 键且为**分组列表**)。

    与内置 JSON 规则库(`{"rules": [{"name":..,"pattern":..}]}`)按结构区分: HaE 的
    rules 项是含 group/rule 键的 dict, JSON 库的项是含 name/pattern 的 dict。
    """
    if not isinstance(data, dict):
        return False
    rules = data.get('rules')
    if not isinstance(rules, list) or not rules:
        return False
    for it in rules:
        if isinstance(it, dict) and ('group' in it or 'rule' in it):
            return True
    return False


def _hae_severity(explicit, color):
    sev = _HAE_SEV_ALIAS.get(str(explicit or '').strip().upper())
    if sev:
        return sev
    return _HAE_COLOR_SEV.get(str(color or '').strip().lower(), 'MED')


def parse_hae_rules(data):
    """解析已加载的 HaE 文档(dict) → [(name, compiled_re, severity), ...]。

    与 load_external_secret_db 同容错口径: 单条正则非法/字段缺失 → 跳过, 不中断。
    """
    rules = data.get('rules') or []
    out = []
    _ids = {}
    for group in rules:
        if not isinstance(group, dict):
            continue
        gname = str(group.get('group') or 'HaE')
        entries = group.get('rule') or []
        if isinstance(entries, dict):       # 容错: rule 直接是单条 dict
            entries = [entries]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get('loaded') is False:        # HaE: 显式停用
                continue
            f_regex = entry.get('f_regex') or entry.get('match') or ''
            f_regex = str(f_regex).strip()
            if not f_regex:
                continue
            rname = str(entry.get('name') or 'HaE-rule')
            rid = f'hae.{_hae_slug(gname)}.{_hae_slug(rname)}'
            n = _ids.get(rid, 0)
            _ids[rid] = n + 1
            if n:                                      # 同名碰撞 → 数字后缀
                rid = f'{rid}-{n + 1}'
            flags = 0 if entry.get('sensitive') else re.I   # sensitive=false → 忽略大小写
            try:
                cre = re.compile(f_regex, flags)
            except Exception:
                continue                               # 单条坏正则不毁整库
            out.append((rid, cre, _hae_severity(entry.get('severity'), entry.get('color'))))
    return out


def load_secret_db_any(path):
    """外部敏感规则库加载(R6 扩展): **自动识别内置 JSON 与 HaE 原生 YAML** 两种格式。

    返回 (rules, format_name); format_name ∈ {'json', 'HaE', 'none'}。
    识别不确定时退回原始 JSON 加载器(与旧行为一致, 由它负责容错/报错)。
    """
    import json as _json
    import os as _os
    if not path or not _os.path.exists(path):
        return [], 'none'
    try:
        with open(path, encoding='utf-8') as f:
            raw = f.read()
    except Exception:
        return [], 'none'
    # 流式(flow-style)文档都以 { 或 [ 开头 —— JSON 与其子集走原加载器。
    #   (注意: JSON 是合法 YAML, 故不能"能 yaml 解析就当 HaE", 必须看结构。)
    if raw.lstrip()[:1] in ('{', '['):
        return load_external_secret_db(path), 'json'
    try:
        import yaml as _yaml
        data = _yaml.safe_load(raw)
    except Exception:
        return load_external_secret_db(path), 'json'
    if is_hae_rules_document(data):
        return parse_hae_rules(data), 'HaE'
    # 其余 YAML 形态(如 {"rules":[{name,pattern}]} 的块样式等价物)让 JSON 加载器兜底
    return load_external_secret_db(path), 'json'


# 自定义规则即时配置(原 `recon/custom_rules.py` —— 并入数据层, 收敛"外部规则"分散)
#   与 secret_db / extract_rules / fingerprint_db 同构: 内置保留、外部追加。
#   · api_patterns   → apis / write_apis (正则 + 捕获组 + 方法)
#   · param_patterns → params            (正则 + 捕获组)
#   · sensitive      → finding           (**格式与 secret_db 完全一致**: {name,pattern,severity})
#   失败(文件缺失 / JSON 非法 / 正则非法)一律**静默跳过**, 绝不影响主分析。
def _parse_custom_pattern(pat):
    """把一条自定义模式解析为 (regex_str, group, method)。支持三种写法:
       `"regex"` / `["regex", group, method]` / `{"pattern":.., "group":.., "method":..}`。
    解析失败一律返回 (None, None, None)(调用方跳过, 绝不影响主分析)。"""
    if isinstance(pat, dict):
        rx = pat.get('pattern') or pat.get('regex')
        if not rx:
            return None, None, None
        return str(rx), pat.get('group'), pat.get('method')
    if isinstance(pat, (list, tuple)):
        if not pat or not pat[0]:
            return None, None, None
        return (str(pat[0]),
                pat[1] if len(pat) > 1 else None,
                pat[2] if len(pat) > 2 else None)
    if not pat:
        return None, None, None
    return str(pat), None, None


def load_custom_rules(spec):
    """读取并编译自定义规则(spec: JSON 文件路径 / dict / None); 任何异常都返回空规则(不抛异常)。"""
    import json
    import os
    empty = {'api': [], 'param': [], 'sensitive': []}
    if isinstance(spec, dict):
        data = spec
    elif spec and os.path.exists(spec):
        try:
            with open(spec, encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            return empty
    else:
        return empty
    if not isinstance(data, dict):
        return empty
    out = {'api': [], 'param': [], 'sensitive': []}
    for key in ('api', 'param'):
        for pat in (data.get(key + '_patterns') or []):
            rx, grp, mth = _parse_custom_pattern(pat)
            if rx is None:
                continue
            try:
                out[key].append((re.compile(rx), grp, mth))
            except re.error:
                continue
    for item in (data.get('sensitive') or []):
        if not isinstance(item, dict) or not item.get('pattern'):
            continue
        try:
            rx = re.compile(item['pattern'])
        except re.error:
            continue
        sev = str(item.get('severity', 'MED')).upper()
        out['sensitive'].append((item.get('name', 'custom'), rx,
                                 sev if sev in SEV_SET else 'MED'))
    return out


def get_custom_rules(ctx):
    """按 ctx 缓存加载(避免每个 JS 文件重复读盘)。"""
    cached = getattr(ctx, '_custom_rules_cache', None)
    if cached is not None:
        return cached
    cfg = getattr(ctx, 'config', None) or {}
    rules = load_custom_rules(cfg.get('custom_rules'))
    try:
        ctx._custom_rules_cache = rules
    except Exception:
        pass
    return rules


def _pick_custom_group(m, grp):
    """取捕获组: 指定 grp 优先(越界/非法则回退); 否则有捕获组取组 1, 无捕获组取整串。"""
    if grp is not None:
        try:
            return m.group(int(grp))
        except (IndexError, ValueError, TypeError):
            pass
    return m.group(1) if m.groups() else m.group(0)


def apply_custom_rules(rules, text, src, out, ctx):
    """把自定义规则应用到一段文本; 返回命中计数(供报告/日志)。"""
    hits = 0
    for rx, grp, mth in rules.get('api', []):
        _mth = str(mth).upper() if mth else ''
        for m in rx.finditer(text):
            val = _pick_custom_group(m, grp)
            np = normalize_extracted_path(val)
            if np:
                # 指定 method 且属写方法 → 按写操作登记(与内置调用点模式同口径)
                if _mth in WRITE_METHODS:
                    out.setdefault('write_apis', {})[np] = _mth
                else:
                    out.setdefault('apis', set()).add(np)
                hits += 1
    for rx, grp, mth in rules.get('param', []):
        for m in rx.finditer(text):
            val = _pick_custom_group(m, grp)
            if val:
                out.setdefault('params', set()).add(val)
                hits += 1
    for name, rx, sev in rules.get('sensitive', []):
        for m in rx.finditer(text):
            if ctx is not None:
                try:
                    # 不再脱敏: 自定义规则命中值**原样**输出(本工具已移除全部脱敏)。
                    _cr_ev = (m.group(0) or '')[:160]
                    ctx.add_finding(sev, f'自定义规则-{name}', src, _cr_ev)
                    from .js_lex import note_finding_loc as _nfl
                    _nfl(ctx, (sev, f'自定义规则-{name}', src, _cr_ev), text, [m.group(0)])
                except Exception:
                    pass
            hits += 1
    return hits


# 误报过滤体系 # 规则: 正则匹配后, 通过后过滤函数进行二次校验
# 适用场景: 无法仅靠正则排除的误报(如语义判断、上下文分析)

# 常见占位符/测试值黑名单
# 从黑名单中移除了 admin/root/password/123456/user — 这些是真实凭证风险值, 不是占位符
_BAD_PLACEHOLDERS = {
    '请输入', 'example', 'test', 'demo', 'null', 'undefined',
    'your_token', 'token', 'key', 'secret',
    'your_password', 'your_username', 'sample', 'placeholder'
}

# 弱口令字典(**单一真源** —— 全库审计 S2): 此前模块级表(16 项)与 `_filter_password`
#   内的局部表(20 项)同语义两套且条目已漂移。并集 20 项在此, 两处共用。
_WEAK_PASSWORDS = {
    '123456', 'password', 'admin', 'root', 'qwerty', '12345678',
    '111111', '123456789', '1234567', 'password1', '123123',
    'abc123', 'letmein', 'welcome', 'monkey', 'dragon',
    '1234', '000000', 'master', 'sunshine', 'princess'
}

# 内部服务域名(正常引用, 非泄露)
_INTERNAL_SERVICES = {
    'grafana', 'prometheus', 'kibana', 'jenkins', 'gitlab',
    'nexus', 'registry', 'harbor', 'rancher', 'consul',
    'vault', 'swagger', 'actuator', 'health', 'status',
    'localhost', '127.0.0.1', '0.0.0.0'
}

def _extract_value(match_text, sep=':'):
    """从 'key: "value"' 中提取 value 部分"""
    if sep in match_text:
        parts = match_text.split(sep, 1)
        val = parts[-1].strip().strip('"\'').strip()
        return val
    return match_text

def _has_complexity(val, min_types=2):
    """检查字符串是否包含至少 min_types 种字符类型(大写/小写/数字/符号)"""
    types = sum([
        any(c.isupper() for c in val),
        any(c.islower() for c in val),
        any(c.isdigit() for c in val),
        any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in val)
    ])
    return types >= min_types

# ---------- 各规则的过滤函数 ----------

def _filter_key_value(ev):
    """密钥键值对: 排除占位符, 要求值复杂度≥2种字符类型"""
    val = _extract_value(ev)
    # 排除黑名单
    for bp in _BAD_PLACEHOLDERS:
        if bp in val.lower():
            return False
    # 低熵 → 占位/示例值, 丢弃
    if shannon_entropy(val) < _ENTROPY_MIN:
        return False
    # 要求复杂度
    return _has_complexity(val, 2)

def _filter_username(val):
    """硬编码用户名: 
    - 排除纯数字/占位符
    - admin/root 等默认值标记为 CRITICAL(默认凭证风险)
    - 其他值正常通过
    返回: 'pass'(正常) / 'critical'(提升严重度) / False(误报)
    """
    # 排除占位符
    placeholders = {'null', 'undefined', 'default', 'example', 'sample', 'placeholder'}
    if val.lower() in placeholders:
        return False
    if val.isdigit():
        return False
    # 默认值账户 → 提升为 CRITICAL
    defaults = {'admin', 'root', 'administrator', 'system', 'superuser'}
    if val.lower() in defaults:
        return 'critical'
    return True

def _filter_password(val):
    """硬编码密码: 
    - 排除占位符/null/undefined
    - 弱口令字典(123456/password/admin等)标记为 CRITICAL(默认凭证风险)
    - 其他值要求复杂度≥2种字符类型
    返回: True(正常) / 'critical'(提升严重度) / False(误报)
    """
    # 排除占位符
    placeholders = {'null', 'undefined', 'example', 'sample', 'placeholder', '请输入'}
    if val.lower() in placeholders:
        return False
    # 弱口令 → 提升为 CRITICAL(单一真源 `_WEAK_PASSWORDS`, 见其定义处)
    if val.lower() in _WEAK_PASSWORDS:
        return 'critical'
    # 正常密码要求复杂度
    return _has_complexity(val, 2)

# ---- Shannon 熵过滤 —— 通用型密钥规则的降噪 ----
# 背景: `密钥键值对` / `硬编码密钥` / `硬编码AK/SK` 捕获的是"任意值", 于是
#   `token:"aaaaaaaa"` / `secret:"testtest"` 这类**占位/示例值**也会命中(实测为误报主源)。
#   熵能有效区分"真随机密钥"与"人写占位符": 前者接近 log2(字符集), 后者极低。
#   注: **只作用于通用型规则**; 带固定前缀的规则(ak_live_/sk-ant-/hf_ …)本身已足够特异, 不加熵约束。
_ENTROPY_MIN = 2.8

def shannon_entropy(s):
    """字符串的 Shannon 熵 (bit/char)。空串返回 0.0。"""
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * log2(v / n) for v in freq.values())

def _filter_token(val):
    """硬编码密钥(token等): 排除占位符; 短密钥(8-15位)降级为MED保留, 长度≥16且含字母+数字才为HIGH"""
    for bp in _BAD_PLACEHOLDERS:
        if bp in val.lower():
            return False
    # 低熵 → 占位/示例值, 丢弃
    if shannon_entropy(val) < _ENTROPY_MIN:
        return False
    if len(val) < 16:
        return 'med'  # P1: 短密钥/短token降级而非删除(8~64位由正则约束)
    has_alpha = any(c.isalpha() for c in val)
    has_digit = any(c.isdigit() for c in val)
    return has_alpha and has_digit

_RE_INTERNAL_IP = re.compile(
    r'@(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}'
    r'|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}'
    r'|127\.0\.0\.1|0\.0\.0\.0)(?=[:/]|$)'
)

def _is_internal_ip(url):
    """判定URL中的主机是否内网IP(10.x/192.168.x/172.16-31.x)"""
    return bool(_RE_INTERNAL_IP.search(url))

def _filter_url_password(url):
    """URL内嵌密码: 内部服务域名/内网IP凭据降级为MED保留(真实风险), 占位符/公网弱密码仍过滤"""
    # 内部服务域名或内网IP: 降级而非删除 （内部凭据暴露也是真实风险）
    if _is_internal_ip(url) or any(svc in url.lower() for svc in _INTERNAL_SERVICES):
        return 'med'
    # 提取密码部分
    try:
        passwd = url.split(':')[2].split('@')[0]
    except IndexError:
        return False
    for bp in _BAD_PLACEHOLDERS:
        if bp in passwd.lower():
            return False
    if passwd.lower() in _WEAK_PASSWORDS:
        return False
    return True

def _filter_internal_url(url):
    """内网地址: 排除正常内部服务"""
    for svc in _INTERNAL_SERVICES:
        if svc in url.lower():
            return False
    return True

def _filter_bearer(val):
    """Bearer令牌: 已通过正则排除占位符; 长令牌(≥20)保留, 短令牌(8-19)降级为MED, <8过滤"""
    if len(val) >= 20:
        return True
    if len(val) >= 8:
        return 'med'  # P1: 短Bearer令牌降级而非删除
    return False

def _filter_aws_secret(val):
    """AWS SecretKey: 验证Base64字符集和长度"""
    if len(val) != 40:
        return False
    return bool(re.match(r'^[A-Za-z0-9/+=]+$', val))

def _filter_google_apikey(val):
    """Google APIKey: 排除已知测试前缀"""
    bad_prefixes = ('AIzaSyC0TEST', 'AIzaSyDEMO', 'AIzaSyEXAMPLE', 'AIzaSyTEST')
    return not val.startswith(bad_prefixes)

def _filter_s3_url(val):
    """S3 对象 URL：仅**签名 / 带凭据**的 S3 URL 才算泄露；裸公开对象 URL 属公开资源引用。

    实测（真实站点 vuejs.org `/ecosystem/themes.html`）：页面里的主题截图
    `https://…s3.amazonaws.com/…png` 被 8 条 HIGH「响应体泄露-S3-URL」误报。
    裸 S3 对象 URL 公开可见、无法判定为私有桶泄露 → 非发现；带签名/凭据参数
    （临时授权，泄露即可访问）→ 保留 HIGH。
    """
    low = str(val).lower()
    return any(k in low for k in (
        'x-amz-signature', 'x-amz-credential', 'x-amz-security-token',
        'awsaccesskeyid', 'signature=', 'expires='))


# 误报过滤字典: 规则名 -> 过滤函数
# 规则: 只有同时满足 ①正则匹配 ②过滤函数通过(如果存在) 才记录为发现项
SENSITIVE_FILTERS = {
    '密钥键值对': _filter_key_value,
    '硬编码用户名': _filter_username,
    '硬编码密码': _filter_password,
    '硬编码密钥': _filter_token,
    '硬编码AK/SK': _filter_token,
    'URL内嵌密码': _filter_url_password,
    '内网地址': _filter_internal_url,
    'Bearer令牌': _filter_bearer,
    'AWS-SecretKey': _filter_aws_secret,
    'Google-APIKey': _filter_google_apikey,
    'S3-URL': _filter_s3_url,
}

# 仅适用于**源码 / JS**（不适用于**响应体数据**）的规则：
#   `硬编码用户名` 匹配 `username:"Bret"` 这类键值对 —— 在**源码 / 配置**里是硬编码凭证线索，
#   但在**数据接口响应**里 `username` 是每条记录的普通字段（实测 jsonplaceholder `/users`
#   被误报 10 条 MED「响应体泄露-硬编码用户名」）。故该规则只在 JS / 源码扫描生效，响应体扫描跳过。
#   注：`硬编码密码` / `硬编码AK/SK` / `硬编码密钥` **保留**在响应体扫描 —— 响应里出现明文
#   密码 / 密钥属真实泄露（数据接口很少返回这些字段），噪声远低于 username。
SOURCE_ONLY_SECRET_RULES = frozenset({'硬编码用户名'})

# ---- WebSocket / SSE / gRPC-Web 正则(协议深度支持 ) ----
RE_WS = re.compile(r'new\s+WebSocket\([\'"`](wss?://[^\'"`]+)[\'"`]\)')           # WebSocket URL
RE_WS_SEND = re.compile(r'\.send\([\'"`]([^\'"`]{5,})[\'"`]\)')                     # WebSocket 初始消息
RE_SSE = re.compile(r'new\s+EventSource\([\'"`]([^\'"`]+)[\'"`]\)')                 # SSE 端点
RE_GRPC_METHOD = re.compile(r'methodName\s*:\s*[\'"`]([^\'"`]+)[\'"`]')           # gRPC-Web 方法名


# ==================== 探测规格（数据驱动） ====================
# 「**每个环境（技术栈 / 场景）该探什么、由哪个指纹触发**」全部在此**声明为数据** ——
#   探测函数只读数据，不在代码里硬编码路径 / 触发条件（与指纹库 / 字典同属数据层）。
#   · triggers: 触发指纹名；None = 无条件（如 common）。
#   · paths:    探测路径；None = 该探测自带特殊逻辑（如 waf 探测主页本身）。
#   字段: triggers(触发指纹; None=无条件) / paths(探测路径) /
#         func(专用探测函数名; **省略则走通用数据驱动探测** `_generic_probe`) /
#         marker(通用探测: 响应须含该子串) / severity / finding(发现标题)。
PROBE_SPECS = {
    'graphql': {'triggers': ('GraphQL',), 'func': '_graphql_probe',
                'paths': ('/graphql', '/api/graphql', '/v1/graphql', '/query')},
    'grpc': {'triggers': ('gRPC-Web',), 'func': '_grpc_probe',
             'paths': ('/grpc.reflection.v1.ServerReflection/ServerReflectionInfo',
                       '/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo',
                       '/proto/service.proto', '/protos.zip', '/api.proto')},
    'swagger': {'triggers': ('Spring', 'Spring-Boot', 'Laravel', 'FastAPI', 'Django',
                             'NestJS', 'Express', 'Rails', 'ASP.NET', 'Swagger', 'OpenAPI',
                             'Gin', 'Echo', 'Fiber', 'Hono', 'Flask'), 'func': '_swagger_probe',
                'paths': tuple(SWAGGER_SPEC_PATHS) + tuple(SWAGGER_UI_PATHS) + ('/docs',)},
    'actuator': {'triggers': ('Spring', 'Spring-Boot', 'Spring-Cloud-Alibaba', 'Dubbo', 'JFinal'),
                 'func': '_actuator_probe',
                 'paths': tuple(p for p in _SPRING_PATHS if p.startswith('/actuator'))},
    'druid': {'triggers': ('Spring', 'Spring-Boot', 'Spring-Cloud-Alibaba', 'Dubbo', 'JFinal'),
              'func': '_druid_probe',
              'paths': tuple(p for p in _SPRING_PATHS if p.startswith('/druid'))},
    'wp': {'triggers': ('WordPress',), 'func': '_wp_probe',
           'paths': tuple(p for p in HIDDEN_PATHS_BY_STACK.get('WordPress', [])
                          if p.startswith('/wp-json/wp/v2/'))},
    'django': {'triggers': ('Django',), 'func': '_django_probe',
               'paths': ('/admin/', '/api/v1/', '/api/v2/')},
    'trpc': {'triggers': ('tRPC',), 'func': '_trpc_probe', 'paths': ('/api/trpc', '/trpc')},
    'laravel': {'triggers': ('Laravel',), 'func': '_laravel_probe',
                'paths': ('/.env', '/.env.local', '/.env.backup', '/debug', '/telescope',
                          '/horizon', '/_ignition/health-check', '/vendor/phpunit')},
    'thinkphp': {'triggers': ('ThinkPHP',), 'func': '_thinkphp_probe',
                 'paths': ('/runtime/log', '/runtime/temp', '/application/database.php',
                           '/thinkphp',
                           # 合规论证(全库审计 M19): 该 URL 是已知的 ThinkPHP RCE 触发形态,
                           #   但**未附** `&function=…&vars[0]=…` 参数 —— 裸请求只会触发框架
                           #   路由/抛异常, 不执行任何函数; 方法为 GET、零载荷, 属"版本/存在性
                           #   指纹探测"而非利用。若未来要附参数, 必须先过合规评审。
                           '/index.php?s=index/think\\app/invokefunction')},
    'jeecgboot': {'triggers': ('JeecgBoot',), 'func': '_jeecgboot_probe',
                  'paths': ('/sys/user/list', '/sys/role/list', '/sys/dict/list',
                            '/jeecg-boot/sys/user/list', '/api/sys/user/list')},
    'ruoyi': {'triggers': ('RuoYi',), 'func': '_ruoyi_probe',
              'paths': ('/system/user/list', '/system/role/list', '/system/menu/list',
                        '/ruoyi/system/user/list', '/api/system/user/list')},
    # 注: 触发指纹须为 **FP_RULES 中真实存在**的名字(自审 check E 会校验) ——
    #   原 `'SAML'` 不在指纹库中 → 该触发**永不命中**(死键), 已移除; 补上真实存在的
    #   认证类指纹 Auth0 / FusionAuth(原遗漏)。
    'auth': {'triggers': ('Keycloak', 'CAS', 'SSO', 'OAuth2', 'JWT', 'Auth0', 'FusionAuth'),
             'func': '_auth_probe',
             'paths': ('/auth/admin', '/auth/realms/master', '/cas/login',
                       '/saml/metadata', '/keycloak', '/sso/login')},
    'waf': {'triggers': ('Cloudflare', 'AWS-WAF', 'F5', 'ModSecurity', 'Akamai'),
            'func': '_waf_probe', 'paths': None},
    'common': {'triggers': None, 'func': '_common_probe',
               'paths': ('/api', '/health', '/status')},
}



def load_external_probe_specs(path):
    """加载**外部探测规格**(JSON) —— 使"新增/覆盖环境"**无需改代码**。

    形如: {"drupal": {"triggers": ["Drupal"], "paths": ["/CHANGELOG.txt", "/user/login"],
                      "marker": "drupal", "severity": "MED", "finding": "Drupal特征端点可达"}}
    与内置合并(同名覆盖 / 新增环境)。失败静默返回 {}。
    """
    import json as _json
    import os as _os
    if not path or not _os.path.exists(path):
        return {}
    try:
        with open(path, encoding='utf-8') as f:
            data = _json.load(f)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out = {}
    for k, v in data.items():
        if str(k).startswith('_'):     # 以 `_` 开头的键视为注释(JSON 无注释的约定)
            continue
        if not isinstance(v, dict):
            continue
        out[str(k)] = {
            'triggers': (tuple(v.get('triggers')) or None) if v.get('triggers') is not None else None,
            'paths': tuple(v.get('paths') or ()),
            'func': v.get('func'),
            'marker': v.get('marker'),
            'severity': v.get('severity') or 'MED',
            'finding': v.get('finding'),
        }
    return out


_PROBE_SPECS_CACHE = {}


def get_probe_specs(config=None):
    """返回合并后的探测规格(内置 PROBE_SPECS + 外部 `probe_specs_db`); 带缓存。"""
    path = (config or {}).get('probe_specs_db')
    if not path:
        return PROBE_SPECS
    if path in _PROBE_SPECS_CACHE:
        return _PROBE_SPECS_CACHE[path]
    merged = dict(PROBE_SPECS)
    merged.update(load_external_probe_specs(path))
    _PROBE_SPECS_CACHE[path] = merged
    return merged

# WAF 基线 canary 的"易被拦"特征种子 —— 仅**敏感路径特征**（不含攻击 payload 串）。
CANARY_SEEDS = ('/admin', '/.env', '/wp-login.php', '/phpmyadmin',
                '/.git/config', '/actuator/env', '/config.php.bak')

# 安全策略文件（公开元数据）
WELLKNOWN_SECURITY_PATHS = ('/.well-known/security.txt', '/security.txt')

# 非接口前缀（静态资源目录 —— 不计入"接口"）
NON_API_PREFIX = ('/assets/', '/static/', '/images/', '/image/', '/img/', '/fonts/', '/font/',
                  '/css/', '/js/', '/media/', '/node_modules/', '/@vite/', '/@id/', '/@fs/',
                  '/favicon', '/manifest', '/locales/', '/i18n/', '/lang/', '/_next/',
                  '/__', '/socket.io/', '/sockjs', '/webpack', '/chunks/', '/polyfills')

# 静态资源扩展名（**窄口径**）—— "资源型"后缀的**单一真源**：
#   `report` / `runtime` 判定"不是可测端点"时用它（不含可能泄露数据的 `.json` / `.txt` 等）。
STATIC_ASSET_EXT = ('.js', '.mjs', '.css', '.map', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                    '.woff', '.woff2', '.ttf', '.eot', '.webp', '.mp4', '.webm')

# 静态资源扩展名（**宽口径**，用于"非接口"判定）—— 资源型 + 数据型后缀。
#   🔴 **由 `STATIC_ASSET_EXT` 派生**（单一真源：每个后缀只在一处列出，避免"同值常量第二处"）；
#   数据型后缀（`.json` / `.txt` / …）可能是数据泄露点，故 `report` 的端点标注**保留**它们（用窄口径）。
STATIC_EXT = STATIC_ASSET_EXT + ('.avif', '.json', '.txt', '.html', '.xml', '.pdf', '.zip')

# ---- JS **打包器/构建产物**签名（单一真源）----
#   用途: 给"体量够大却零产出"的 JS 一个**可核查、可操作**的归类 —— 打包产物 ≠ 混淆,
#     二者该给的建议完全不同(打包产物 → `unbundle` 逐模块拆; 混淆 → `strong_deobf`/`dynamic_deobf`)。
#   判据只用**高特异度字面量标记**(如 `__webpack_require__`), 不用 `webpack` 这类裸词 ——
#     否则注释/URL/库名提及即误判。**顺序敏感**: 越具体的签名越靠前(先匹配者胜)。
#   ⚠️ 只登记"有可靠标记"的打包器; 无法可靠识别者(如 Rollup 常规产物)**宁缺勿滥** ——
#     猜错打包器比不猜更糟(会给出错误建议)。
BUNDLER_SIGNATURES = (
    ('webpack',    ('__webpack_require__', '__webpack_modules__', 'webpackChunk', 'webpackJsonp')),
    ('browserify', ('[function(require,module,exports)', 'browserify')),
    ('vite',       ('__vite__mapDeps', '__vite__')),
    ('parcel',     ('parcelRequire',)),
    ('systemjs',   ('System.register(',)),
    ('turbopack',  ('__turbopack',)),
    ('esbuild',    ('__toESM', '__commonJS')),
)

# 静态资源**目录段**（中段亦判）—— 路径里任一"段"命中即视为静态资源路径。
#   与 `NON_API_PREFIX`（仅前缀）/ `STATIC_EXT`（仅结尾）互补, 覆盖 `/x/images/y` 这类
#   **中段**静态形态（实测 `/wls_prs_sps/images/sps/-`、`/x/authError.html/y` 会漏过前缀/结尾判）。
STATIC_DIR_SEGS = frozenset((
    'images', 'image', 'img', 'assets', 'asset', 'static', 'css', 'js',
    'javascript', 'fonts', 'font', 'media', 'locales', 'locale', 'i18n',
    'lang', 'node_modules', 'dist', 'build', 'vendor', 'icons', 'icon',
    'themes', 'styles', 'scripts', 'webpack', 'chunks', 'polyfills',
))


def is_static_or_malformed_path(path):
    """路径是否为**静态资源 / 畸形形态**（不可作端点, 也不可作派生基址）。

    纯**形态**判定, 不含任何站点 / 变量名白名单:
      · 任一**路径段**是静态资源目录（images/assets/static/css/js/fonts…）;
      · 任一**路径段**以静态资源扩展名结尾（.html/.png/.js/.css…）;
      · 以 `/`、`-`、`_` 结尾（拼接残缺）。
    与 `NON_API_PREFIX`（仅前缀）/ `STATIC_EXT`（仅结尾）**互补** —— 本函数额外覆盖**中段**形态。

    三处**同口径**复用（消除"对畸形基址再派生"的噪声）:
      ① `infer_path_variants` 的基址前置校验;
      ② `js_extract._is_dynamic_base_candidate` 的动态基址门禁;
      ③ `orchestrator` 对 `out['apis']` 的最终噪声过滤。
    """
    if not path or not isinstance(path, str) or not path.startswith('/'):
        return True
    if path[-1] in ('/', '-', '_'):
        return True
    segs = [s for s in path.split('?')[0].split('#')[0].split('/') if s]
    if not segs:
        return True
    for s in segs:
        low = s.lower()
        if low in STATIC_DIR_SEGS:
            return True
        if low.endswith(STATIC_EXT):
            return True
    return False

# 前端技术栈 —— 用于"是否走前端构建产物拆包"等门控(**数据层声明**, 不在代码里硬编码)。
FRONTEND_STACKS = frozenset({
    'React', 'Vue', 'Vue3', 'Next.js', 'Nuxt', 'Angular', 'Svelte', 'SolidJS',
    'Vite', 'Webpack', 'Rollup', 'esbuild', 'Parcel', 'SvelteKit', 'Remix',
    'Preact', 'Astro',
})

# URL 中敏感 query 参数名 —— **单一事实来源**: 供泄漏检测(`secret._check_url_leak`)
#   使用（脱敏侧已整体移除, 本常量现仅服务检测）。
URL_SECRET_PARAM_KW = ('token', 'api_key', 'apikey', 'secret', 'password', 'passwd',
                       'auth', 'authorization', 'jwt', 'access_token', 'refresh_token',
                       'session', 'cookie', 'private_key', 'sk', 'ak')


# 凭据类发现的关键词(用于把"响应体泄露"细分为凭据暴露 vs 一般敏感暴露) ——
#   含栈/产品名, 故按"含栈名的集合必须位于数据层"的约定放在此处(自审 check F)。
CREDENTIAL_FINDING_KW = ('MySQL', 'Mongo', 'Postgre', 'Redis', 'URL内嵌',
                         '云AK', 'AWS', 'JWT', '密钥', '凭据', 'AK', 'Token', 'token')

# 配置/调试/文档/框架文件/监控面 暴露类发现的关键词(用于 finding → 候选分类) ——
#   含栈/产品名, 故按"含栈名的集合必须位于数据层"的约定放在此处(自审 check F)。
CONFIG_EXPOSURE_FINDING_KW = ('配置', '隐藏接口暴露', 'Actuator', 'Druid', 'Swagger',
                              'OpenAPI', 'GraphQL', 'introspection', '内省', '文件泄露',
                              '.proto', '敏感信息泄露', '监控面板', '管理面板')

# 只读方法集合 —— **单一真源**(放数据层, 供 core/http 与 recon/runtime 共用)。
#   出站护栏的三条通道(同步 REQ / 异步 _aio_req / 浏览器 route)必须**同口径**, 否则
#   "只读"承诺会在某一条通道上静默失效。此前 `http._READONLY_METHODS` 与
#   `runtime._BROWSER_READONLY_METHODS` 各写一份同值元组 —— 属"同值常量出现第二处"。
READONLY_METHODS = ('GET', 'HEAD', 'OPTIONS')


def is_readonly_method(method):
    """方法是否只读 —— **三通道唯一定义**(审计 D3)。

    同步 <code>REQ</code> / 异步 <code>_aio_req</code> / 浏览器 route 拦截都必须问本函数,
    而不是各自内联 <code>x not in READONLY_METHODS</code> —— 否则将来放宽/收紧只读集时,
    会有某条通道不同步(即"同一判断出现第二处实现")。返回为标准小写无关判定。
    """
    return (str(method or 'GET')).upper() in READONLY_METHODS


# ---- 库 bundle 嗅探数据(演进建议 R2 · 借鉴 JsOwl skip_library_bundles) ----
#   版权注释 banner: 构建时保留的许可头(压缩后通常仍在文件头部)。
VENDOR_SNIFF_BANNERS = ('/*!', '@license', '@preserve', 'copyright', 'licensed under')
#   已知库名 —— **须与 banner 同时出现**才判 vendor, 单独出现不判(防业务代码被误杀)。
VENDOR_SNIFF_LIBS = (
    'jquery', 'lodash', 'underscore', 'axios', 'vue', 'react', 'angular', 'rxjs',
    'echarts', 'element-ui', 'elementui', 'antd', 'ant-design', 'moment', 'dayjs',
    'bootstrap', 'core-js', 'regenerator', 'zone.js', 'highlight.js', 'three.js',
    'swiper', 'xlsx', 'zxcvbn', 'popper', 'hammer', 'd3.js', 'chart.js',
    'font-awesome', 'animate.css', 'normalize.css', 'babel', 'requirejs',
)
#   文件名/路径形态 token: 命中即判 vendor(形态判据, 与正文内容无关)。
VENDOR_URL_TOKENS = (
    'vendor', 'vendors', 'chunk-vendors', 'chunk-libs', 'thirdparty', '3rdparty',
    'polyfill', 'runtime.', 'node_modules', '/libs/', '/umd/', 'dll.',
    'manifest.js', 'preview-manifest',
)
# SourceMap 默认黑名单(演进建议 R2): map URL 命中任一片段即跳过下载(库/vendor 的
#   map 体量大且无业务价值; 仍记录"跳过"事实, 不静默)。
DEFAULT_SOURCEMAP_BLACKLIST = (
    'chunk-vendors', 'chunk-libs', 'vendors~', 'node_modules', '/vendor',
    '/polyfills', '/runtime.', '/libs/', '/umd/', 'axios', 'lodash', 'jquery',
    'element-ui', 'elementui', 'antd', 'echarts', 'moment', 'core-js',
    'zone.js', 'bootstrap', 'highlight.js', 'regenerator-runtime', 'three',
)


# 严重度排序(单一真源, 审计 S11): candidates 与 exporters 曾各写一份, 改一处漏一处。
SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MED': 2, 'LOW': 3, 'INFO': 4}

# 常见公开文件（存在属正常, 不报"暴露"）
BENIGN_WELLKNOWN = (
    '/robots.txt', '/sitemap.xml', '/sitemap_index.xml', '/humans.txt',
    '/ads.txt', '/app-ads.txt', '/security.txt', '/.well-known/security.txt',
    '/manifest.json', '/asset-manifest.json', '/build-manifest.json',
    '/favicon.ico', '/apple-touch-icon.png', '/browserconfig.xml',
    '/3rdpartylicenses.txt', '/licenses.txt', '/license.txt', '/version.json',
    '/service-worker.js', '/sw.js', '/registerSW.js', '/workbox-sw.js',
)

# 访问控制面（**单一事实来源**）—— 供 report(recon_matrix) 使用,
#   避免"未授权访问"判据的关键词多处各写一份而漂移。
#   语义（用户明确）：未授权访问 = **无身份信息访问了"本应需要认证"的资源**；
#   信息泄露只是**结果**（由「敏感信息响应」单独表达，不作触发依据）。
#     · AUTH_PRIVATE_KW  —— **需认证**的账户/会话面(account/session/credential/apikey…)：
#                           匿名可达才是风险。
#     · AUTH_PUBLIC_KW   —— **按设计即匿名可达**的认证入口(login/logout/signup/reset/token/
#                           oauth/sso/captcha…)：登录页/注册/找回密码/换取令牌**本就该匿名可达**
#                           (否则用户无法登录) → **不构成"未授权访问"**。
#                           旧实现把 login/logout 也算作"应需认证" → 把正常登录页/注销接口
#                           误报为"疑似未授权访问"(用户反馈的误报)。
#     · 认证面维度由 `access_control_surface` 以 **AUTH_PUBLIC_KW ∪ AUTH_PRIVATE_KW 在线派生**
#       (无独立 AUTH_SURFACE_KW 符号), 仅作信息性标注, **不作**未授权判据。
#     · UNAUTH_SURFACE_KW —— 内部/运维/调试面(internal/debug/console/env/manage/backup…)
#     · 高危管理面复用 MGMT_HIGH_RISK_KW（见上），避免 health/status/swagger 等本就可能公开的面被误标。
AUTH_PUBLIC_KW = frozenset({
    'login', 'logout', 'signin', 'signout', 'signup', 'register', 'password',
    'reset', 'forgot', 'token', 'oauth', 'sso', 'saml', 'captcha', 'authorize',
    'callback', 'verify', 'activate', 'confirm', 'unlock', 'otp', 'refresh',
})
AUTH_PRIVATE_KW = frozenset({
    'account', 'profile', 'me', 'session', 'sessions', 'credential',
    'credentials', 'apikey', 'api_key', 'secret', 'secrets', 'device', 'devices',
})
# 承载"会话/凭据"的 HTTP 头名(小写) —— **单一事实来源**, engine/report/recon 共用:
#   · 判定"本次扫描是否带认证"(决定 auth_state 披露);
#   · 匿名视图(`no_session`)须剔除哪些头(否则匿名视图仍带 token → 差分失真)。
#   --cookie/--token 走 Cookie/Authorization(此处亦覆盖); 自定义鉴权头(如 X-Access-Token)
#   经 `header` 配置传入, 也必须被识别, 否则报告会误称"未认证"。
AUTH_HEADER_NAMES = frozenset({
    'authorization', 'cookie', 'x-api-key', 'api-key', 'x-auth-token',
    'x-access-token', 'x-session-token',
})


def has_auth_session(cfg):
    """本次扫描是否**带认证会话** —— 覆盖 `--cookie` / `--token` / **自定义鉴权头**(`header` 配置)。

    **单一事实来源**: report(_auth_state) 等共用 —— 否则口径不一, 例如用
    `header: "X-Access-Token: …"` 鉴权时报告会误称"未认证"。
    """
    cfg = cfg or {}
    if str(cfg.get('cookie') or '').strip() or str(cfg.get('token') or '').strip():
        return True
    raw = cfg.get('header')
    items = raw if isinstance(raw, (list, tuple)) else ([raw] if raw else [])
    for it in items:
        s = str(it or '')
        if ':' in s and s.split(':', 1)[0].strip().lower() in AUTH_HEADER_NAMES:
            return True
    return False
UNAUTH_SURFACE_KW = frozenset({
    'internal', 'debug', 'console', 'env', 'manage', 'root', 'shell',
    'test', 'staging', 'dev', 'backup', 'dump', 'phpinfo', 'trace', 'actuator',
    'grafana', 'kibana', 'jenkins', 'phpmyadmin', 'monitor',
})


# 可能本就公开的"配置/文档/探活面"（= MGMT_KEYWORDS − 高危管理面）：**不算风险**,
#   仅作低优先级信息(如 /health · /status · /swagger.json · /graphql 常为公开面)。
MGMT_PUBLIC_KW = MGMT_KEYWORDS - MGMT_HIGH_RISK_KW


def path_segments(path):
    """路径拆成小写段（去 query / fragment / 尾斜杠），供关键词匹配。"""
    p = str(path or '').split('?')[0].split('#')[0].rstrip('/')
    return {s.lower() for s in p.split('/') if s}


# "不该公开面"常带**服务端脚本扩展名或归档/备份扩展名**(/login.aspx · /phpinfo.php · /admin.aspx ·
#   /config.php · /dump.jsp · /manage.do · /backup.zip · /config.bak)。**这些面匹配时**去掉扩展名
#   —— 不去会整类漏判。注: 只在"不该公开面"(认证/内部运维/高危管理)匹配上做, 不影响其它维度。
_SURFACE_EXT_STRIP = frozenset({
    # 服务端脚本 / 页面
    'aspx', 'ashx', 'asmx', 'jsp', 'jspx', 'do', 'action', 'php', 'php3', 'php4',
    'php5', 'phtml', 'asp', 'cgi', 'pl', 'py', 'rb', 'html', 'htm', 'shtml', 'xhtml',
    # 归档 / 备份 / 临时
    'zip', 'tar', 'gz', 'tgz', 'rar', '7z', 'sql', 'bak', 'old', 'save', 'swp',
    'orig', 'copy', 'tmp', 'log',
})


def surface_segments(path):
    """路径段 ∪ **去服务端扩展名**后的段 —— 用于"不该公开面"匹配
    (认证面 / 内部运维面 / 高危管理面): `/phpinfo.php` → phpinfo、`/admin.aspx` → admin。"""
    segs = path_segments(path)
    out = set(segs)
    for s in segs:
        base, _, ext = s.rpartition('.')
        if base and ext in _SURFACE_EXT_STRIP:
            out.add(base)
    return out


def access_control_surface(path):
    """路径命中的**访问控制面**维度集合（子集 of {'auth','unauth','config'}）。

    `auth` 只取**需认证**的账户/会话面(AUTH_PRIVATE_KW) —— **公开认证入口(login/logout/signup/
    reset/token/oauth…)按设计即匿名可达, 不计入**, 否则会把正常登录页/注销接口误报为
    "疑似未授权访问"。config 只取**高危管理面**(MGMT_HIGH_RISK_KW)，排除 health/status/swagger
    等本就可能公开的面。匹配用 `surface_segments`（兼容 /phpinfo.php · /admin.aspx 等带扩展名路径）。
    纯路径命名判定，不发包、不验证。report 与 recon 共用此函数以保证判据一致。
    """
    segs = surface_segments(path)
    dims = set()
    # 公开认证入口优先: 同一路径若**同时**含公开段与私有段(如 `/account/login` —— account∈私有、
    #   login∈公开), 以**公开**为准, 不计入 auth。否则登录/注册页会被当"受保护账户面" →
    #   匿名 200 即误报"疑似未授权访问"(与 report._endpoint_dims 的 has_auth_pub 同口径)。
    if (segs & AUTH_PRIVATE_KW) and not (segs & AUTH_PUBLIC_KW):
        dims.add('auth')
    if segs & UNAUTH_SURFACE_KW:
        dims.add('unauth')
    if segs & MGMT_HIGH_RISK_KW:
        dims.add('config')
    return dims




# 认证机制（E · 认证机制图谱）—— 纯数据映射, 代码只装配。
#   SCHEME_INJECT_POINT: OpenAPI securityScheme 类型/方案 → 凭据注入点。
#   WWW_AUTH_SCHEMES:    WWW-Authenticate 挑战方案 → 机制名(规范化小写)。
SCHEME_INJECT_POINT = {
    'bearer': 'Authorization',
    'basic': 'Authorization',
    'digest': 'Authorization',
    'oauth2': 'Authorization',
    'openidconnect': 'Authorization',
    'apikey': 'Header',        # apiKey 的实际注入点看 in(header/query/cookie), 由调用方细化
    'cookie': 'Cookie',
    'session': 'Cookie',
}
WWW_AUTH_SCHEMES = ('basic', 'bearer', 'digest', 'negotiate', 'ntlm',
                    'aws4-hmac-sha256', 'apikey', 'token')
