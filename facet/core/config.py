# -*- coding: utf-8 -*-
"""facet — 统一配置管理（环境变量 + 用户配置 + CLI 参数）

分层优先级(高 → 低):
    CLI 显式参数 > 环境变量 FACET_* > 配置文件(`--config PATH` 或 ~/.facet/config.yaml) > 内置默认值

"""
import os
import re

import yaml

from ..output.paths import default_output_file
from .dicts import DEFAULT_SOURCEMAP_BLACKLIST  # noqa: F401  (单一真源: 见 dicts 定义处注释)

# 需要边界约束的数值项: key -> (最小值, 最大值, 说明)
BOUNDS = {
    'rate':              (0.05, 60.0, '请求间隔秒数'),
    'max_rpm':           (0, 10000, '每分钟硬顶发包数(0=不限)'),
    'threads':           (1, 64, '并发数'),
    'max_js':            (0, 10000, 'JS递归下限(0=不限)'),
    'max_js_hard_cap':   (0, 20000, 'JS分析上限的硬顶(自适应上浮不超过此值; 0=不设硬顶)'),
    'js_budget_frac':    (0.1, 1.0, 'JS 阶段最多占用的剩余时间预算比例(其余留给探活/报告)'),
    'timeout':           (1, 120, '单请求超时秒数'),
    'max_baseline_cache': (16, 65536, '请求缓存条目上限'),
    'max_duration':      (0, 86400, '全局时间预算秒数(默认 1800=30min; 0=不限)'),
    'max_probe':         (0, 1000000, '探活路径总数上限(0=不限)'),
    'max_probe_extracted': (0, 1000000, '提取接口(no_cap)探活硬顶(0=不限; 防超大提取集失控)'),
    'max_sitemap':       (0, 1000000, 'sitemap <loc> 采纳条数上限(0=不限)'),
    'path_infer_max_variants': (1, 20, '路径推断: 每条路径派生变体上限'),
    'path_infer_max_total': (0, 5000, '路径推断: 全局派生条数上限(0=不限)'),
    'options_probe_max': (0, 500, 'OPTIONS 方法发现: 探测端点数上限(0=不限)'),
    'resp_mine_max':     (0, 2000, '响应挖掘: 每目标采纳 URL 上限(0=不限)'),
    'retries':           (0, 10, '关键请求重试次数'),
    'unbundle_max_modules': (1, 100000, '构建产物拆包模块数上限'),
    'unbundle_max_bytes': (0, 50000000, '拆包体积上限(字节, 超过则跳过拆包; 0=不限)'),
    'unbundle_keep_dirs': (0, 1000, '拆包产物目录保留个数(按 mtime 保留最近 N; 0=不清理)'),
    'strong_deobf_max_bytes': (0, 50000000, '强反混淆体积上限(字节, 超过则跳过; 0=不限)'),
    'silent_js_min_size': (0, 10485760, 'JS"零产出"披露的体积门槛字节(默认 20KB; 0=全部登记)'),
    'batch_concurrency': (1, 32, '批量并发目标数'),
    'crawl_depth':       (0, 5, '同源多页爬取深度(0=关)'),
    'crawl_max_pages':   (1, 1000, '多页爬取页数上限'),
}

# 会被当作布尔解析的取值(含 YAML 1.1 的 yes/no/on/off 与常见字符串写法)
_TRUE_SET = {'1', 'true', 'yes', 'y', 'on', 'enable', 'enabled'}
_FALSE_SET = {'0', 'false', 'no', 'n', 'off', 'disable', 'disabled', ''}

# 三态键(false / true / auto): 环境变量覆写时**保留原字符串**, 否则 'auto' 会被
#   _to_bool 按默认值类型(bool)误判为 True, 使 auto 语义丢失(交 _normalize 统一处理)。
_THREE_STATE_KEYS = ('runtime', 'ast_sidecar', 'dynamic_deobf', 'strong_deobf', 'unbundle',
                     'js_encoding',
                     'hidden_paths_extended', 'crawl_depth',
                     'options_probe', 'unauth_probe', 'tls_cert')   # 后三者: 信号驱动(auto)

class _CfgLoader(yaml.SafeLoader):
    """按 YAML 1.2 语义解析: 仅 true/false 是布尔, yes/no/on/off 保持字符串

    YAML 1.1 默认把裸写的 yes/no/on/off 也解析为布尔, 于是
      · `yes: true` 的**键**变成 Python True, 后续 `k.upper()` 直接崩溃;
      · `common_probe: no` 的**值**变成 Python False, 看似正确实则来自隐式解析,
        而写成 `common_probe: 'no'` 时又变成字符串 'no'(真值)。
    统一收窄解析规则 + 在 _to_bool 里显式识别字符串, 消除这类歧义。
    """

_CfgLoader.yaml_implicit_resolvers = {
    k: [(tag, regexp) for tag, regexp in v if tag != 'tag:yaml.org,2002:bool']
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_CfgLoader.add_implicit_resolver(
    'tag:yaml.org,2002:bool',
    re.compile(r'^(?:true|True|TRUE|false|False|FALSE)$'),
    list('tTfF'))

def _to_bool(v):
    """把常见写法统一成布尔

    """
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if v is None:
        return False
    s = str(v).strip().lower()
    if s in _TRUE_SET:
        return True
    if s in _FALSE_SET:
        return False
    return bool(v)

# ---- 模块整合 —— **纯侦察 / 攻击面测绘** ----
# 定位: 本工具只做**前期侦察**, 不设计任何攻击操作。原有 `cors / param / idor / sqli`
#   四个**主动验证模块已整体移除**。保留的模块都属"发现级":
#   passive : 被动基础 —— 静态提取(接口 / 前端路由 / 参数 / 敏感信息) + 被动打点 / TLS / CT
#             (零发包, 或仅抓静态资源) —— **默认开启, 这是主体**
#   confirm : 最小发包确认 —— 探活(每候选 1 发 GET) + 隐藏路径字典(按栈加载)
#             + 未授权访问**确认**(只回答"是否需要鉴权", 不做利用)
# 注: 模块名 recon-deep / probe / unauth 仍可单独使用。
MODULE_GROUPS = {
    # auto(默认, 懒人式): 全安全面 —— 用户**无需**指定模块; 各能力再由**信号**细粒度门控
    #   (指纹/页面类型/端点/响应行为), 见 orchestrator.resolve_dispatch。
    'auto':    ['recon-deep', 'probe', 'unauth'],
    'passive': ['recon-deep'],
    'confirm': ['probe', 'unauth'],
    'all':     ['recon-deep', 'probe', 'unauth'],
}
# 具体模块名(展开后应落在此集合内; 组名不是模块名)
KNOWN_MODULES = ['recon-deep', 'probe', 'unauth']

def effective_max_js(config, discovered=0):
    """**自适应** JS 分析上限: 发现量超过 `max_js` 时按发现量上浮(最多到 `max_js_hard_cap`)。

    大站(SPA chunk 动辄上千)固定 `max_js=200` 会**静默漏掉 80%+** 的 chunk(接口随之漏);
    但完全不设限又会让流量/耗时失控。折中: `max_js` 为**下限**, 按发现量上浮,
    `max_js_hard_cap` 为**硬顶**。`max_js<=0` = 不限(旧语义); `max_js_hard_cap<=0` = 不设硬顶。
    """
    try:
        base = int(config.get('max_js', 200) or 0)
    except (TypeError, ValueError):
        base = 200
    if base <= 0:
        return 0
    try:
        cap = int(config.get('max_js_hard_cap', 1000) or 0)
    except (TypeError, ValueError):
        cap = 1000
    n = int(discovered or 0)
    return max(base, min(cap, n)) if cap > 0 else max(base, n)


def expand_modules(modules):
    """把模块组名展开为具体模块名(去重、保序)。未知名称原样保留(便于扩展与拼写提示)。

    >>> expand_modules('passive,confirm')  ->  ['recon-deep', 'probe', 'unauth']
    """
    if isinstance(modules, str):
        items = [m.strip() for m in modules.split(',') if m.strip()]
    else:
        items = [str(m).strip() for m in (modules or []) if str(m).strip()]
    out = []
    for it in items:
        for m in MODULE_GROUPS.get(it, [it]):
            if m not in out:
                out.append(m)
    return out

DEFAULT_CONFIG = {
    'url': None,
    'file': None,
    'out': default_output_file('facet_report.html'),
    # **懒人式默认**: `auto` = 全安全面(静态提取 + 探活 + 未授权确认), 用户**无需**指定模块。
    #   细粒度调度由**信号**驱动(指纹/页面类型/端点/响应行为), 不靠参数; `-m` 仅作**高级覆盖**
    #   (显式指定时按模块裁剪: passive / confirm / all / recon-deep / probe / unauth)。
    'modules': 'auto',
    'rate': 0.5,
    'max_rpm': 120,
    'threads': 8,
    'max_js': 200,
    # 自适应硬顶: 发现量超过 max_js 时按发现量上浮(最多到此值) —— 大 SPA 固定 200 会静默漏 80%+。
    #   实测(文档站 macrozheng): 发现 ~1100 JS, 旧硬顶 1000 → 截断 103; 提到 2000 覆盖更全。
    #   仍受 `js_budget_frac` 时间预算 + `max_duration` 保护(设了全局预算时不会因上限调高而跑飞)。
    'max_js_hard_cap': 2000,
    # 时间感知: JS 阶段最多占用剩余时间预算的比例(其余留给探活/报告) —— 防"覆盖↑=时间↑"拖垮大站。
    #   默认 **0.8 = 覆盖优先**(截断会减少"读懂业务"所需的信息, 代价是耗时); 想更快可调低。
    'js_budget_frac': 0.8,
    # 非首页"入口页"JS 收割(默认开): 被动 GET 首页链接 + 高价值入口页猜测(login/dashboard/
    #   admin/account…), 提取其专属 <script src> JS 并入管线, 补齐"非首页才加载的 JS"缺口。
    #   同源 / 只读 GET / 不登录 / 受 max_pages 上限与全局限速·熔断·预算约束。
    'route_harvest': True,
    # SPA 路由感知抓取(B2): 用**已发现的前端路由**(`out['routes']`)当种子页再收割一轮 JS/端点。
    #   与 `route_harvest`(首页链接 + 入口页猜测)互补; 纯客户端 SPA 各路由回同一 shell →
    #   自动停止并如实披露(见 `_harvest_spa_routes`)。
    'spa_route_harvest': True,
    'max_pages': 15,
    'timeout': 10,
    'audit_log': False,
    'audit_log_path': default_output_file('facet_audit.log'),
    # 断点续扫状态存储后端: 'file'(默认, stdlib json) / 'sqlite'(stdlib)。
    #   redis 远程后端已移除(依赖从未声明 + import 失败静默降级 = 假成功)。
    'state_store': 'file',
    'state_path': default_output_file('.facet_state.json'),
    'fingerprint_db': None,
    # 外部敏感规则库(JSON) —— 与 --fingerprint-db 同构, 内置保留、外部追加
    'secret_db': None,
    # 可选密钥实时验证(默认关, 对齐 trufflehog)。开启会向第三方只读验证。
    'verify_secrets': False,
    'debug': False,
    # 阶段计时(只读): 开启后在扫描末尾打印各阶段耗时占比 —— 用于性能基准, 不改变任何行为。
    'profile': False,
    'proxy': None,
    # TLS 证书校验。默认 False —— 侦察目标大量使用自签/内网证书, 强制校验会让绝大多数
    #   目标直接失败(httpx/nuclei 同类工具默认也不校验)。但它此前是**硬编码**且无任何提示:
    #   分析员经中间设备时无法察觉证书异常, 目标证书问题也不会成为一条发现。
    #   现改为可配置 + 启动时显式披露(见 cli.main)。
    'tls_verify': False,
    # ---- 新增 ----
    # 是否沿用运行环境的 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY。
    # 默认 False: requests 在 proxies=None 时会**静默**回落环境变量, 导致扫描流量被
    # 环境代理劫持(实测沙箱内 HTTP_PROXY 指向本地代理, 打本地自建目标全部返回 502,
    # facet 表现为"熔断 + 只发 5 个包 + 报告空白")。显式直连才是可预期的行为。
    'use_env_proxy': False,
    'max_baseline_cache': 128,
    'yes': False,
    'resume': False,
    # ---- 声明范围(in-scope)护栏(SRC 合规边界) ----
    #   默认空列表 → 由 _scan_one_target 用目标同源装配(保守默认); 显式 --scope 声明更宽/更窄范围。
    'scope': [],
    # ---- 授权留痕(SRC 合规) ----
    #   authorized / auth_method 由 CLI 运行时写入(config['authorized']=True / config['auth_method']=...,
    #   见 cli.confirm_authorization / _scan_one_target), 供 ScanContext 读取并渲染"授权声明"卡片。
    #   默认值(均未授权 / 留空)仅作占位: 实际取值在用户确认授权后才写入, 不在加载期生效。
    'authorized': False,
    'auth_method': '',
    # ---- 路径推断(方案 4.6): 由已知路径派生同族候选(动词族/单复数/扩展名/批量↔单品) ----
    #   纯字符串变换; 产出与"提取到的真实接口"**分区存放**(inferred_paths), 报告按来源单列。
    'path_infer': True,
    'path_infer_max_variants': 8,     # 每条路径最多派生几个变体(按类别分桶: 动词4/扩展3/批量1/复数1)
    'path_infer_max_total': 200,      # 全局派生上限(防跑飞)
    # ---- OPTIONS / Allow 方法发现(方案 2-B): 只读 OPTIONS 拿该路由支持的方法 ----
    #   三态(false/true/'auto', **默认 'auto'**): auto = **有端点可探**时才跑(无端点无意义);
    #   由 orchestrator.resolve_dispatch 按信号解析。显式 true/false 一律尊重。
    'options_probe': 'auto',
    'options_probe_max': 60,
    # ---- 未授权访问确认 + 隐藏路径字典(方案 confirm 阶段) ----
    #   三态(false/true/'auto', **默认 'auto'**): auto = 有端点(或有 401/403 受保护迹象)时跑;
    #   由 resolve_dispatch 按信号解析。显式 true/false 一律尊重。
    'unauth_probe': 'auto',
    # ---- 响应体/响应头 URL 挖掘(方案 2-B): 从探活响应正文与头(Location/Link/CSP)挖端点 ----
    'resp_mine': True,
    'resp_mine_max': 100,
    # ---- 框架识别降级(方案六): 识别到开发服务器(Werkzeug/Flask dev 等) → 强制低并发+间隔 ----
    'dev_server_downgrade': True,
    # ---- JS AST 提取 sidecar(方案 4.1「AST 优先, 正则兜底」)----
    #   三态: false / true / 'auto'(默认) —— auto 表示"Python tree-sitter 或 Node+Acorn 可用才启用";
    #   Python 原生引擎优先, Node+Acorn 常驻进程作为回退; 两者均不可用则回退正则。只做静态解析, 不执行目标代码。
    'ast_sidecar': 'auto',
    'ast_node_bin': '',      # node 可执行文件路径(留空=自动探测)
    'ast_node_path': '',     # acorn 所在 node_modules 目录(留空=自动探测)
    # 运行时(Playwright)通道 —— 三态: false / true / auto。
    #   auto(默认): 仅当目标被判定为 SPA(客户端渲染)时启用 —— 静态 JS 分析覆盖最弱、
    #   运行时通道收益最大; 非 SPA 目标保持关闭, 避免无谓的浏览器流量。
    'runtime': 'auto',
    # 运行时(Playwright)通道使用的浏览器: 留空 = 内置捆绑 Chromium(默认);
    #   填可执行文件路径 → 用作 executable_path; 填 'chrome'/'chromium' 等 → 用作 channel
    #   (走系统已装浏览器, 规避沙箱内 Chromium 下载受限)。env: FACET_RUNTIME_BROWSER。
    #   注: 此前 runtime.py 读取该键但**未在 DEFAULT_CONFIG 声明** → 不可发现、不被类型规整
    #   (自审 check H 报出), 此处补齐声明。
    'runtime_browser': '',
    # 运行时(Playwright)通道的同域请求总数上限 —— 防跑飞。浏览器流量已按 route 层逐请求
    #   节流(document/xhr/fetch 用 rate; 静态子资源轻量放行), 该上限是第二道保险。
    'runtime_max_requests': 300,
    # ---- 思考层(规划器, CLI --think) ----
    #   默认**纯本地动态推理**(零外部依赖 / 离线可用 / 零发包); 只在同时配置了
    #   llm_base_url + llm_api_key 时才切换到 LLM 推理(显式 opt-in)。端点/模型**不写死**,
    #   一律来自配置或环境变量: FACET_LLM_BASE_URL / FACET_LLM_API_KEY /
    #   FACET_LLM_MODEL。产出为"建议式计划", 不驱动主流程、不改判定。
    'think': False,
    'llm_base_url': '',
    'llm_api_key': '',
    'llm_model': '',
    'llm_timeout': 30,
    'token': None,
    'login': None,
    'cookie': None,
    'header': None,
    # ---- 新增: 真实目标适用性 ----
    # 默认 User-Agent。此前**完全不发 UA**, requests 默认的 `python-requests/x.y.z`
    # 会被 Cloudflare / 阿里云WAF / 腾讯云WAF 等按默认规则直接拦截(实测 403,
    # 零指纹零接口)。这里给一个常规浏览器 UA; 需要复现特定工具 UA 用 --ua 覆盖。
    'ua': None,
    # 全局时间预算(秒)。默认 1800s(30 分钟)有限值 —— 作为最后防线, 保证单次扫描
    # 绝不会无限挂起(配合 core/watchdog.py 的硬墙钟看门狗: 任一阶段卡死都会被中止
    # 并导出已完成的部分报告)。设为 0 可恢复"不限时"旧行为。
    'max_duration': 1800,
    # 探活路径总数上限。0 = 不限。
    # sitemap.xml 的 <loc> 此前无上限地并入探活集合 —— 实测 800 条 URL 放大成
    # 835 次请求; 真实大站 sitemap 可达数万条(按默认 120 RPM 约 7 小时)。
    'max_probe': 400,
    # 提取接口(no_cap)探活的硬顶: 默认不按 max_probe 截断"所有提取接口"(用户要求必探),
    #   但无上限可被巨型 JS / 超大 sitemap 突破 —— 此硬顶兜底(0=不限; 超限登记截断)。
    'max_probe_extracted': 2000,
    # 库 bundle 嗅探(演进建议 R2 · 借鉴 JsOwl skip_library_bundles): 命中版权注释/
    #   已知库名/路径形态的 JS 跳过深度分析(仍入 JS 清单与指纹补判采样) —— 提速降噪。
    'vendor_bundle_skip': True,
    'vendor_sniff_bytes': 2048,                 # 嗅探检查的文件头字节数
    # SourceMap 黑名单(演进建议 R2): map URL 命中任一片段即跳过下载(默认值见
    #   dicts.DEFAULT_SOURCEMAP_BLACKLIST; 可整体覆盖)。
    'sourcemap_blacklist': list(DEFAULT_SOURCEMAP_BLACKLIST),
    # P2 机会性 SourceMap 收割(默认开): JS **未声明** sourceMappingURL 时, 同源探测
    #   `<js>.map`(只读 GET; 404/跨域/黑名单由 _process_external_sourcemap 静默兜底)。
    #   命中且含 sourcesContent → 原始源码作为高优分析输入, 补静态逆向盲区。
    #   设 false 可关闭(减少额外发包)。
    'sourcemap_probe': True,
    # P2 调度护栏: 机会性 sourcemap 探测的**全局上限**(默认 50; <=0 不限) —— 防 chunk 密集站点
    #   逐文件探测把 JS 阶段发包/时间预算吃光。与 max_js 同口径(0=不限)。
    'sourcemap_probe_max': 100,
    # R4 登录态采集(opt-in): 打开**可见**浏览器 → 操作员手动登录 → 抓 storage_state
    #   回灌 HTTP/浏览器通道(凭据仅内存态, 不落盘)。
    'login_capture': False,
    'login_capture_timeout': 300,
    # R5 浏览器交互模式(opt-in): 填表+点击控件发现动态端点; **写请求由只读护栏拦截**
    #   (观测≠发送, 零写流量)。启动时显著告警。
    'interactive': False,
    'browser_max_interactions': 10,
    # R3 参数轻量污点(演进建议): 调用点参数值来源(upstream/storage/route/unknown)标注。
    #   默认开; 设 false 可跳过这一步静态标注(纯展示增强, 不影响端点发现)。零发包。
    'param_taint': True,
    # sitemap.xml 的 <loc> 采纳上限。此前完全无上限 —— 一个 50k 条的 sitemap 会
    # 直接变成 50k 个探活目标(实测 800 条 → 835 次请求, 11.3× 放大)。
    'max_sitemap': 500,
    # 首个请求(主页)的重试次数。真实站点偶发慢响应很常见, 单次失败会让整轮扫描
    # 退化成空报告(实测首页 13s > timeout 10s → 指纹/JS/接口全为 0)。
    'retries': 1,
    # 429 退避时是否尊重 Retry-After 响应头(仍受 RATE_MAX 封顶)
    'respect_retry_after': True,
    # 是否提取目标 TLS 证书信息(颁发者/有效期/SAN)。
    #   三态(false/true/'auto', **默认 'auto'**): auto = **仅 HTTPS 目标**才提取(非 HTTPS 无证书可谈,
    #   省一次注定失败的握手); 由 orchestrator.resolve_dispatch 按信号解析。
    'tls_cert': 'auto',
    # 注: 子域 / 历史资产枚举已**整体移除** —— `ct_subdomains`(CT 子域枚举) / `wayback`(Wayback
    #   归档) / `dns_brute`(DNS 爆破) 与 `port_scan`(端口探测) 均已删除; 本工具现为**纯 HTTP
    #   侦察**(HTTP 探活 + 被动打点 robots/sitemap/security.txt), 不再有子域枚举 / 历史资产 /
    #   非 HTTP 主动探测。子域信息仅来自 JS/HTML 内容里的同源引用(见 `_extract_subdomains`)。
    # ---- 新增: 探测门控与噪声控制 ----
    'no_color': False,            # 关闭彩色输出(CI 环境)
    'common_probe': True,         # 通用端点探测(/api /health /status)
    'fallback_probe': False,      # 兜底探测: 默认关闭(旧版在未命中指纹时反而追加, 方向错误)
    # Schema 源探测(OpenAPI/Swagger + GraphQL 内省): 默认开(只读 GET); `schema_probe: false` 关闭。
    #   注: 此前代码读取该键但**未在 DEFAULT_CONFIG 声明** → 不可发现、且不被 bool 规整(自审 check H 报出)。
    'schema_probe': True,
    # 注: 原 `cloud_metadata_probe` 已随 `_cloud_probe` 一并移除(1.47.0, 语义越界), 此处为残留键, 已删。
    'catchall_baseline': True,    # 发送 canary 随机路径建立 catch-all 基线
    'html_report': True,          # 生成 HTML 报告
    'json_report': True,          # 生成机器可读 JSON 报告(供流水线消费)
    # 标准格式导出(opt-in, 默认空=不产生额外文件): 'sarif' / 'burp' / 'zap' 任意组合。
    #   CLI: --export sarif,burp   配置: export_formats: [sarif, burp]
    'export_formats': [],
    # ---- 输出精简(默认只产 HTML + JSON 两个主文件) ----
    # 机器可读侧车(recon_matrix / biz_rules / endpoints / diff+基线 / replay.sh / recovered)
    #   默认**不写** —— 避免默认扫描在目录里塞一堆"机器消费用"文件; 真正需要 CI / 流水线 /
    #   跨扫描消费时再显式开启(--sidecars / 配置 sidecars: true)。
    'sidecars': False,
    # 扫描历史库(history.db)默认**不写** —— 避免默认扫描在目录里多出一个 SQLite 文件;
    #   需要跨扫描 diff / 历史记录时显式开启(--save-history / save_history: true)。
    'save_history': False,
    # 断点续扫状态文件的持久化: 默认内存态(不落盘), 仅当 --resume / persist_state: true 才写盘。
    'persist_state': False,
    # 熔断(半开自动恢复)参数:
    #   circuit_max_fail        —— 连续失败多少次要触发熔断(阈值);
    #   circuit_cooldown       —— 熔断后冷却秒数, 冷却结束自动转入半开探活;
    #   circuit_half_open_probes —— 半开期放行的探活请求数(任一成功即自愈关闭)。
    'circuit_max_fail': 5,
    'circuit_cooldown': 30,
    'circuit_half_open_probes': 3,
    # 隐藏路径字典扩展(与 secret_db/fingerprint_db/sca_db 同构)：
    #   extra=内联追加自定义路径; db=外部字典文件(JSON list / {"paths":[...]});
    #   extended=三态(false/true/'auto', **默认 'auto'**): 扩展层(备份变体/容器云凭据/监控中间件面)
    #   是"已知栈"的高价值面(容器凭据 / 管理后台 / 备份文件), 此前需用户**显式开启**才会加载,
    #   是"不知道开关→同类面反复漏"的温床。auto = 仅当**命中技术栈指纹**才追加该层(否则守最小发包),
    #   纯数据驱动、不依赖硬编码栈名; 显式 false 关闭 / true 强制全量加载。
    'hidden_paths_extra': [],
    # 外部字典文件: JSON list / {"paths":[...]} 路径; 或**内置词表名**
    #   (`common` / `highvalue` / `static` / `all`) —— 随包发布, `pip install` 后按名即可用。
    'hidden_paths_db': None,
    'hidden_paths_extended': 'auto',
    # 探测规格外部化(数据驱动): 新增/覆盖"环境"(技术栈)的触发指纹与探测路径,
    #   形如 {"drupal": {"triggers":["Drupal"],"paths":["/CHANGELOG.txt"],"marker":"drupal"}}
    #   —— 加环境**无需改代码**(无 func 的条目走通用探测)。
    'probe_specs_db': None,
    # ---- 新增 ----
    'adapt_rate': True,           # 自适应调速(关闭后严格按 rate 配置恒速)
    'waf_probe': True,            # WAF 探测(命中 WAF 指纹时执行)
    'waf_probe_ua': None,         # WAF 探测使用的 UA(None = 默认浏览器 UA DEFAULT_UA, 与扫描请求同口径)
    # 注: `probe_targets_enabled`(栈专属已知路径探测)已移除 —— 与数据驱动的 hidden_probe 重叠。
    # ---- 新增 ----
    'passive_recon': True,        # 被动打点: robots/sitemap/security.txt/favicon + 安全响应头审计
    # ---- 新增: 第三方库 SCA  ----
    # 纯本地文本分析(识别 JS 库版本并对照已知漏洞表), 零额外请求, 默认开。
    'sca': True,
    # 外部 SCA 库定义 JSON(内置保留 + 外部追加), 与 --fingerprint-db 同构。
    'sca_db': None,
    # 可选 OSV 联网富化(默认关): 会向 api.osv.dev 发送"包名+版本", 属向第三方发包。
    'sca_osv': False,
    # ---- 构建产物拆包（webcrack 可选外部工具）—— 三态，**默认 auto** ----
    # 与 `strong_deobf: auto` 同构：auto = "node + webcrack 可用 **且** 文件是 bundle(_ub.is_bundle)"
    #   才启用 —— 开箱自动拆包 webpack/browserify 产物并逐模块深析(模块也会过 strong/dynamic deobf)。
    #   False=关 / True=启用(内部再自检) / auto=先判依赖可用。受 unbundle_max_modules 上限约束。
    'unbundle': 'auto',
    'unbundle_max_modules': 200,
    # 拆包/强反混淆的**体积上限**(字节)。拆包(webcrack)与强反混淆都要起 Node 子进程,
    #   对 MB 级巨物极贵(每文件最长 120s / 单批 600s) —— 实测正是它们把 JS 阶段预算吃光,
    #   导致承载接口表的业务 chunk 永远轮不到。超阈值**跳过并如实披露**(见报告"扫描完整性"),
    #   不是静默丢弃。0 = 不限。
    'unbundle_max_bytes': 4000000,
    # 拆包产物目录的**保留上限**(按 mtime 保留最近 N 个)。唯一名机制让每次重扫新增一个目录,
    #   不设上限则无界累积; 0 = 不清理(全部保留为可审计证据)。
    'unbundle_keep_dirs': 3,
    'strong_deobf_max_bytes': 6000000,
    # "体量够大却零产出"的 JS 披露门槛（字节）。**必须在默认值表里出现** —— 只登记在
    #   取值范围表(上方 bounds)而不给默认值, 会让 `load_config` 返回 `None` →
    #   调用方 `int(None or 0)` = 0 → 体积过滤被**静默关闭**, 261 字节的小组件也会被
    #   当成"零产出"报出来（实测踩过: 232 条噪声）。
    'silent_js_min_size': 20480,
    # ---- 动态解包（L3–L5 密封离线沙箱，opt-in，默认关闭） ----
    # 与静态强反混淆不同，动态解包会在**本地密封、离线、零网络**的沙箱里运行目标代码以展开
    # VM/字节码混淆。属合规红线例外：默认关闭，需显式 opt-in，且报告明示「已在密封沙箱展开、
    # 未向目标发包」。三态：
    #   False = 关闭（默认，永不执行目标代码）；
    #   True  = 对任意疑似混淆的 JS 启用；
    #   auto  = 仅对静态无法处理的 VM/字节码打包（ConfuserEx 风格，见 orchestrator._looks_vm_packer）
    #           自动启用——普通 javascript-obfuscator(_0x) 由静态 webcrack 还原，不触发动态解包。
    # 环境变量 FACET_DYNAMIC_DEOBF=true|auto；tier: 3=密封vm+桩 / 4=+抗篡改+安全执行 /
    # 5=真实浏览器(无则降级 L3/L4)。
    # ---- 强反混淆（静态 webcrack，opt-in）—— 三态，**默认 auto** ----
    # 静态分析(不执行目标代码); auto = "node + deobf_strong.cjs + webcrack 可用 **且** 文件疑似
    #   混淆(_looks_obfuscated)" 才启用 —— 与 `ast_sidecar: auto` 同构, 显著提升**开箱覆盖**
    #   (自动处理混淆 JS, 消除"用户不知道开关→混淆端点整条漏"的漏报温床); 依赖缺失则跳过该层。
    #   False=关 / True=仅按 `_looks_obfuscated` 门控(依赖缺失时逐文件降级) / auto=先判依赖可用。
    'strong_deobf': 'auto',
    # ---- 简单 JS 编码解码（JSFuck / AAencode 颜文字 / JJencode / Jother）—— 三态，**默认 auto** ----
    # 这类编码本质是「一段怪字符表达式运行后得到字符串, 再交给 Function/eval 执行」。解码 = 在
    #   **密封、离线、零网络**的 vm 沙箱里运行该**编码表达式**; 执行入口(Function/eval)与输出口
    #   (alert/console/document.write)被**捕获桩**截断 —— 拿到明文源码/明文输出, **不向目标发包**。
    #   auto = "node + deobf_encodings.cjs 可用 **且** 命中编码指纹(见 deobf.looks_like_js_encoding)"
    #   才启用; 指纹极特定(≥100 连续 []()!+ / 颜文字 / `$=~[]`), 普通 JS 不误触发。
    #   False=关 / True=仅按指纹门控(依赖缺失时跳过) / auto=先判依赖可用。
    'js_encoding': 'auto',
    'dynamic_deobf': False,
    'dynamic_deobf_tier': 4,
    # ---- 新增: -f 批量并发 ----
    # 多个目标并行扫描时的并发目标数(默认1=串行)。**所有目标共享同一 RateManager**,
    # 因此全局 rate/max_rpm 配额不被放大(并发只提升吞吐, 不绕过限速与熔断)。
    'batch_concurrency': 1,
    # ---- 自定义规则即时配置(加载器已并入数据层 `core/dicts`) ----
    # 外部 JSON: {"api_patterns":[...], "param_patterns":[...], "sensitive":[{name,pattern,severity}]}
    #   · sensitive 与 `secret_db` **格式完全一致** → 两者可互换/合并(同一套 {name,pattern,severity})。
    #   · api_patterns/param_patterns 为正则+捕获组(+可选 method), 与 extract_rules(词表)/
    #     param_rules(关键词→类别) 语义不同, 故保留为独立键。
    'custom_rules': None,
    # ---- 新增: 报告分类规则外部化(动态获取, 非硬编码) ----
    # 下列键指向外部 JSON(或内存 list/dict), 供报告/提取的分类逻辑动态加载;
    # 缺省 None = 使用代码内置默认表(零配置行为不变)。解析失败一律回退默认, 绝不中断报告。
    #   param_rules   参数语义标注(关键词→语义类别), 覆盖 _PARAM_KINDS/_ID_KW/_TIME_KW
    #   source_rules  接口来源分类启发式(note 关键词), 覆盖 classify_api 默认判定
    #   extract_rules 提取侧过滤词表(静态资源后缀/服务端脚本后缀/静态目录前缀/接口关键词)
    #                 + disable_patterns(按名禁用内置调用点模式), 见 extract_rules.example.json
    #   biz_rules     业务域标注 —— **已停用**(业务地图模块整体移除); 键保留仅为旧配置兼容,
    #                 加载后不再参与任何报告输出
    'biz_rules': None,
    'param_rules': None,
    'source_rules': None,
    'extract_rules': None,
    # ---- 新增: 同源多页爬取（三态：整数深度 / 'auto', **默认 'auto'**）----
    # 解决"接口藏在二级页面 / 表单里"的漏抓。auto = 仅当**首页同源链接足够多**(站点确是多页,
    # ≥10 条)才 BFS 爬取(温和深度 2, 受 crawl_max_pages 上限约束); 单页站点自动不爬 —— 守最小发包。
    # 整数深度 = 强制 BFS 深度; 0/关 = 只抓首页。受全局限速约束。
    'crawl_depth': 'auto',
    'crawl_max_pages': 30,
    # ---- JS 目录爆破(发现"未被页面引用但存在"的隐藏 JS · 只读 · 默认开) ----
    #   从已发现 JS 的目录派生候选, 用常见 JS 文件名(JS_FILE_NAMES_COMMON)只读探活;
    #   命中者并入 js_urls 走步骤3 分析。上限 js_dir_fuzz_max 控流量。
    'js_dir_fuzz': True,
    'js_dir_fuzz_max': 300,       # 爆破总请求上限(0=不限)
    #   追加的 JS 文件名: ① 内联列表; 或 ② **字符串** = 内置词表名(`js_common` / `js_highvalue`
    #   / `js_full` / `all`) 或 `.txt`/`.json` 词表文件路径(随包词表见 `facet/assets/wordlists/`)。
    'js_dir_fuzz_names': [],
}

def _env_override(cfg):
    """环境变量覆写配置（FACET_前缀）"""
    for k in list(cfg):
        if not isinstance(k, str):
            continue
        ev = os.environ.get(f'FACET_{k.upper()}')
        if ev is not None:
            if k in _THREE_STATE_KEYS:
                cfg[k] = ev          # 三态键: 保留原字符串, 交由 _normalize 处理('auto' 不被误判)
                continue
            cur = cfg[k]
            if isinstance(cur, bool):
                cfg[k] = _to_bool(ev)
            elif isinstance(cur, int):
                try:
                    cfg[k] = int(ev)
                except ValueError:
                    pass
            elif isinstance(cur, float):
                try:
                    cfg[k] = float(ev)
                except ValueError:
                    pass
            else:
                cfg[k] = ev

def _coerce_int(cfg, k):
    try:
        cfg[k] = int(cfg[k])
    except (TypeError, ValueError):
        cfg[k] = DEFAULT_CONFIG.get(k)

def _normalize(cfg):
    """配置后处理: 类型规整 + 边界约束

    """
    for k in ('threads', 'max_rpm', 'max_js', 'timeout',
              'max_baseline_cache', 'max_duration', 'max_probe', 'max_sitemap',
              'max_probe_extracted',
              'vendor_sniff_bytes',
              'login_capture_timeout', 'browser_max_interactions',
              'retries',
              'unbundle_max_modules', 'unbundle_max_bytes', 'unbundle_keep_dirs',
              'strong_deobf_max_bytes',
              'batch_concurrency',
              'crawl_max_pages',
              'path_infer_max_variants', 'path_infer_max_total',
              'options_probe_max', 'resp_mine_max', 'dynamic_deobf_tier',
              'llm_timeout'):
        _coerce_int(cfg, k)
    try:
        cfg['rate'] = float(cfg['rate'])
    except (TypeError, ValueError):
        cfg['rate'] = DEFAULT_CONFIG['rate']
    # 边界约束(越界即夹取, 并把夹取结果回写, 便于调用方感知)
    for k, (lo, hi, _desc) in BOUNDS.items():
        if k == 'crawl_depth':
            continue    # crawl_depth 由下方三态循环统一规整(保留整数深度语义)
        v = cfg.get(k)
        if v is None:
            cfg[k] = DEFAULT_CONFIG.get(k)
            continue
        try:
            # 目标类型按**边界类型**决定, 而不是按"当前值恰好是什么类型" —— 后者会让
            #   **浮点型配置一旦以字符串给出就被静默丢弃**: `js_budget_frac: "0.6"`(YAML 引号
            #   写法)走到 `int("0.6")` → ValueError → 静默重置为默认 0.8, 用户设的值**不生效也
            #   不报错**(实测; 属项目记录的"静默失效"类缺陷)。`rate` 此前靠 `k == 'rate'` 特判
            #   逃过, 现按边界类型统一 —— 不再需要特判, 也不会再有第二个漏网键。
            v = float(v) if isinstance(lo, float) or isinstance(hi, float) else int(v)
        except (TypeError, ValueError):
            cfg[k] = DEFAULT_CONFIG.get(k)
            continue
        if v < lo:
            v = lo
        elif v > hi:
            v = hi
        cfg[k] = v
    for k in ('no_color', 'common_probe', 'fallback_probe', 'schema_probe',
              'catchall_baseline', 'html_report', 'adapt_rate', 'waf_probe',
              'audit_log', 'yes', 'resume', 'debug', 'profile', 'use_env_proxy',
              # 注: `tls_cert` 已改为**三态**(默认 'auto') → 不在此走 _to_bool(同 options_probe)。
              'passive_recon', 'respect_retry_after',
              'sca', 'sca_osv',
              'route_harvest', 'spa_route_harvest', 'js_dir_fuzz',
              # 注: `options_probe` / `unauth_probe` 已改为**三态**(默认 'auto'), 故**不**在此
              #   走 _to_bool(否则 'auto' 会被 bool('auto') 误判为 True, 信号调度失效) —— 由下方
              #   三态循环统一规整。
              'path_infer', 'resp_mine',
              'dev_server_downgrade', 'sidecars', 'save_history', 'persist_state',
              'think',
              # R2: 库 bundle 嗅探总开关(默认开; false 恢复全量深度分析)。
              'vendor_bundle_skip',
              # R4/R5: 浏览器交互能力开关(均默认关, 启动时显著告警)。
              'login_capture', 'interactive',
              # 此前漏在这张表里的布尔键: YAML 1.2 把裸写 `no` 解析成字符串 'no'(真值),
              #   `verify_secrets: no` 会**反而启用**向第三方发包的实时验证 —— 方向危险的静默失效(全库审计 M11)。
              'verify_secrets', 'param_taint',
              # P2: 机会性 sourcemap 探测开关(默认开)。
              'sourcemap_probe'):
        cfg[k] = _to_bool(cfg.get(k))
    # runtime / auth_matrix 为**三态**(false / true / auto), 单独规整 —— 不走 _to_bool
    #   (否则 'auto' 会被 `bool('auto')` 误判为 True)。
    _rt = cfg.get('runtime')
    cfg['runtime'] = ('auto' if isinstance(_rt, str) and _rt.strip().lower() == 'auto'
                      else _to_bool(_rt))
    _as = cfg.get('ast_sidecar')      # 同上: 'auto' 不能走 _to_bool
    cfg['ast_sidecar'] = ('auto' if isinstance(_as, str) and _as.strip().lower() == 'auto'
                          else _to_bool(_as))
    # 其余三态键(false / true / auto): 'auto' 保留字符串, 其余走 _to_bool。
    #   dynamic_deobf/strong_deobf/unbundle: auto = 依赖/信号门控; hidden_paths_extended: auto = 按信号
    #   options_probe/unauth_probe: auto = 按"是否有端点/受保护迹象"解析(见 resolve_dispatch)
    for _k in ('dynamic_deobf', 'strong_deobf', 'unbundle', 'js_encoding',
               'hidden_paths_extended',
               'options_probe', 'unauth_probe', 'tls_cert',
               'crawl_depth'):
        _v = cfg.get(_k)
        if isinstance(_v, str) and _v.strip().lower() == 'auto':
            cfg[_k] = 'auto'
        elif _k == 'crawl_depth':
            # crawl_depth 三态 + 整数深度; 注意 bool 是 int 子类, 须显式排除,
            #   否则 False/True 会被当成 0/1 深度(破坏"显式关闭")。
            if _v is None:
                cfg[_k] = 'auto'
            elif isinstance(_v, bool):
                cfg[_k] = _v                      # 保持 bool → 编排层 int(True)=1 / int(False)=0
            elif isinstance(_v, int):
                cfg[_k] = max(0, min(5, _v))       # 整数深度 + 夹取 0..5
            elif isinstance(_v, str):
                _s = _v.strip().lower()
                if _s in ('true', 'false'):
                    cfg[_k] = (_s == 'true')
                else:
                    try:
                        cfg[_k] = max(0, min(5, int(_v)))
                    except (TypeError, ValueError):
                        cfg[_k] = 'auto'           # 无法解析 → 回退 auto
            else:
                cfg[_k] = _to_bool(_v)
        else:
            cfg[_k] = _to_bool(_v)
    return cfg

def _load_yaml(path):
    """读取 YAML 配置文件

    使用 _CfgLoader 按 YAML 1.2 语义解析, 并把所有键强制转成 str ——
      YAML 1.1 会把裸写的 yes/no/on/off 解析为布尔值, 于是 `yes: true` 的键会变成
      Python True, 后续 `k.upper()` 直接 AttributeError 崩溃。
    """
    try:
        with open(path, encoding='utf-8') as f:
            data = yaml.load(f, Loader=_CfgLoader) or {}
        if not isinstance(data, dict):
            print(f'[-] 配置文件格式不是映射(键值对): {path}')
            return {}
        return {str(k): v for k, v in data.items()}
    except Exception as e:
        print(f'[-] 配置文件读取失败({path}): {e}')
        return {}

def load_config(cli_args=None):
    """加载分层配置: 默认值 → 用户文件 → 环境变量 → CLI显式参数"""
    cfg = dict(DEFAULT_CONFIG)
    # 配置文件来源: 显式 `--config PATH`(CLI 已暴露) 优先; 否则回退 ~/.facet/config.yaml。
    #   两者**二选一**(显式指定即不再叠加用户文件, 便于"用一份隔离配置跑一次")。
    explicit = getattr(cli_args, 'config', None) if cli_args else None
    if explicit:
        if os.path.exists(explicit):
            cfg.update(_load_yaml(explicit))
        else:
            print(f'[-] --config 指定的文件不存在: {explicit}')
    else:
        user_path = os.path.expanduser('~/.facet/config.yaml')
        if os.path.exists(user_path):
            cfg.update(_load_yaml(user_path))
    # 未知键告警: 拼写错误(如 `max_duraton`)此前**零提示零生效** —— "静默吞掉用户值"类
    #   缺陷(全库审计)。仅提示, 不中断(向后兼容旧配置文件里的历史键)。
    _unknown_cfg = sorted(set(cfg) - set(DEFAULT_CONFIG))
    if _unknown_cfg:
        print(f"[i] 配置里存在未被识别的键(将被忽略, 请检查拼写): {', '.join(_unknown_cfg)}")
    _env_override(cfg)
    if cli_args:
        # 仅覆盖用户**显式传入**的项。可分层参数的 argparse 默认值均为 None
        # (见 cli.build_parser), 因此 `v is not None` 即"用户传了"。
        for k in DEFAULT_CONFIG:
            v = getattr(cli_args, k, None)
            if v is not None:
                cfg[k] = v
    return _normalize(cfg)
