# -*- coding: utf-8 -*-
"""第三方 JS 库 SCA（retire.js 式，纯 Python / 离线优先）
  · 用**已知库特征指纹**（文件名 + banner 注释 + 版本号正则）识别库与版本；
  · 对照一份**内置的"库 → 已知漏洞版本区间"表**（可用 `--sca-db` 外置 JSON 追加/更新）；
  · 报告新增"前端组件（含版本）"与"已知漏洞组件"两节。

设计取舍（"自包含优先"纪律）：
  · 内置表用 Python 字面量（避免 JSON 转义陷阱），外部更新走 JSON（与 --fingerprint-db 同构）；
  · 默认**纯离线**判定；可选的 OSV 联网富化（`--sca-osv`，默认关）会向 api.osv.dev 发送
    "包名+版本"，属向第三方发包，需合规授权，故默认关闭。

零外部依赖：版本比较、区间判定均自实现，仅标准库。
"""
import json
import os
import re

from ..core.dicts import norm_sev
from ..core.log import log

# 内置库特征 + 已知漏洞版本区间（curated subset，覆盖最常见的前端组件）
# 每条：
#   name             规范名
#   filename_patterns  针对**文件名/URL**的正则（版本号放第 1 捕获组，可选）
#   banner_patterns    针对**文件头部注释**的正则（版本号放第 1 捕获组）
#   content_patterns   针对**正文**的正则（版本号放第 1 捕获组）
#   vulns              [{range, id, severity, summary}]
#                     range 形如 "<4.17.21" / ">=1.0.0,<1.2.3"（AND 语义）
BUILTIN_LIBS = [
    {
        'name': 'jQuery',
        'filename_patterns': [r'jquery[.\-]v?(\d+\.\d+\.\d+)', r'\bjquery(?:\.min)?\.js\b'],
        'banner_patterns': [r'jQuery\s+(?:JavaScript\s+Library\s+)?v?(\d+\.\d+\.\d+)'],
        # 收紧: 只认 jQuery **核心** banner 形态(jQuery vX / jQuery JavaScript Library vX),
        # 避免把 "jQuery Validation Plugin v1.13.1" 等**插件**版本误归到 jQuery 核心并套用核心 CVE。
        'content_patterns': [r'jQuery\s+(?:JavaScript\s+Library\s+)?v?(\d+\.\d+\.\d+)'],
        'vulns': [
            {'range': '<3.5.0', 'id': 'CVE-2020-11022/CVE-2020-11023', 'severity': 'MEDIUM',
             'summary': 'htmlPrefilter 处理 <option> 等标签时的 XSS（3.5.0 修复）'},
            {'range': '<3.4.0', 'id': 'CVE-2019-11358', 'severity': 'MEDIUM',
             'summary': 'jQuery.extend(true, ...) 原型污染（3.4.0 修复）'},
            {'range': '<1.9.0', 'id': 'CVE-2015-9251', 'severity': 'MEDIUM',
             'summary': '跨域 ajax 未强制 dataType 导致 XSS（1.9.0 修复）'},
        ],
    },
    {
        'name': 'jQuery Validation Plugin',
        'filename_patterns': [r'jquery[\.\-]validate'],
        'banner_patterns': [r'jQuery\s+Validation\s+Plugin\s+-?\s*v?(\d+\.\d+\.\d+)'],
        'content_patterns': [r'jQuery\s+Validation\s+Plugin\s+-?\s*v?(\d+\.\d+\.\d+)'],
        # 插件自身无广泛确认的核心 CVE; 仅做组件识别(正确归属版本), 不误报漏洞。
        'vulns': [],
    },
    {
        'name': 'lodash',
        'filename_patterns': [r'lodash[.\-]v?(\d+\.\d+\.\d+)', r'\blodash(?:\.min)?\.js\b'],
        'banner_patterns': [r'lodash[^\n]{0,30}?(\d+\.\d+\.\d+)', r'@license\s+lodash'],
        'content_patterns': [r'lodash[^\n]{0,40}?VERSION\s*=\s*[\'"]([\d.]+)'],
        'vulns': [
            {'range': '<4.17.21', 'id': 'CVE-2021-23337', 'severity': 'HIGH',
             'summary': 'template 命令注入（4.17.21 修复）'},
            {'range': '<4.17.19', 'id': 'CVE-2020-8203', 'severity': 'HIGH',
             'summary': 'zipObjectDeep 原型污染（4.17.19 修复）'},
            {'range': '<4.17.11', 'id': 'CVE-2019-10744', 'severity': 'HIGH',
             'summary': 'defaultsDeep 原型污染（4.17.11 修复）'},
        ],
    },
    {
        'name': 'axios',
        'filename_patterns': [r'axios[.\-]v?(\d+\.\d+\.\d+)', r'\baxios(?:\.min)?\.js\b'],
        'banner_patterns': [r'axios[/\sv]+(\d+\.\d+\.\d+)'],
        'content_patterns': [r'axios[^\n]{0,60}?VERSION\s*[=:]\s*[\'"]([\d.]+)'],
        'vulns': [
            {'range': '<1.6.0', 'id': 'CVE-2023-45857', 'severity': 'MEDIUM',
             'summary': '跨站请求时 XSRF-TOKEN 泄露（1.6.0 修复）'},
            {'range': '<0.21.1', 'id': 'CVE-2020-28168', 'severity': 'MEDIUM',
             'summary': '跟随重定向时的 SSRF（0.21.1 修复）'},
        ],
    },
    {
        'name': 'Bootstrap',
        'filename_patterns': [r'bootstrap[.\-]v?(\d+\.\d+\.\d+)', r'\bbootstrap(?:\.bundle)?(?:\.min)?\.js\b'],
        'banner_patterns': [r'Bootstrap\s+v?(\d+\.\d+\.\d+)'],
        'content_patterns': [r'Bootstrap\s+v(\d+\.\d+\.\d+)'],
        'vulns': [
            {'range': '<4.3.1', 'id': 'CVE-2019-8331', 'severity': 'MEDIUM',
             'summary': 'tooltip/popover 的 XSS（4.3.1 / 3.4.1 修复）'},
            {'range': '>=4.0.0,<4.3.1', 'id': 'CVE-2018-14042', 'severity': 'MEDIUM',
             'summary': 'tooltip data-container 属性的 XSS（4.3.1 修复）'},
        ],
    },
    {
        'name': 'Moment.js',
        'filename_patterns': [r'moment[.\-]v?(\d+\.\d+\.\d+)', r'\bmoment(?:\.min)?\.js\b'],
        'banner_patterns': [r'moment\.js[^\n]{0,20}?(\d+\.\d+\.\d+)'],
        'content_patterns': [r'moment[^\n]{0,40}?version\s*[=:]\s*[\'"]([\d.]+)'],
        'vulns': [
            {'range': '<2.29.4', 'id': 'CVE-2022-31129', 'severity': 'HIGH',
             'summary': '字符串解析 ReDoS（2.29.4 修复）'},
        ],
    },
    {
        'name': 'Handlebars',
        'filename_patterns': [r'handlebars[.\-]v?(\d+\.\d+\.\d+)', r'\bhandlebars(?:\.min)?\.js\b'],
        'banner_patterns': [r'Handlebars\s+v?(\d+\.\d+\.\d+)'],
        'content_patterns': [r'Handlebars[^\n]{0,30}?VERSION\s*=\s*[\'"]([\d.]+)'],
        'vulns': [
            {'range': '<4.7.7', 'id': 'CVE-2021-23369', 'severity': 'HIGH',
             'summary': 'compile() 远程代码执行（4.7.7 修复）'},
        ],
    },
    {
        'name': 'AngularJS',
        'filename_patterns': [r'angular[.\-]v?(\d+\.\d+\.\d+)', r'\bangular(?:\.min)?\.js\b'],
        'banner_patterns': [r'AngularJS\s+v?(\d+\.\d+\.\d+)'],
        'content_patterns': [r'AngularJS\s+v(\d+\.\d+\.\d+)'],
        'vulns': [
            {'range': '<1.8.0', 'id': 'CVE-2020-7676', 'severity': 'MEDIUM',
             'summary': 'angular.element 的 XSS（1.8.0 修复）'},
            {'range': '<1.6.5', 'id': 'CVE-2017-1000509', 'severity': 'MEDIUM',
             'summary': '编译 <a> 时的 XSS（1.6.5 修复）'},
        ],
    },
    {
        'name': 'DOMPurify',
        'filename_patterns': [r'purify[.\-]v?(\d+\.\d+\.\d+)', r'\bdompurify(?:\.min)?\.js\b'],
        'banner_patterns': [r'DOMPurify\s+(\d+\.\d+\.\d+)'],
        'content_patterns': [r'DOMPurify[^\n]{0,30}?version\s*[=:]\s*[\'"]([\d.]+)'],
        'vulns': [
            {'range': '<2.4.0', 'id': 'CVE-2022-36067', 'severity': 'HIGH',
             'summary': 'mXSS 绕过（2.4.0 修复）'},
        ],
    },
    {
        'name': 'marked',
        'filename_patterns': [r'marked[.\-]v?(\d+\.\d+\.\d+)', r'\bmarked(?:\.min)?\.js\b'],
        'banner_patterns': [r'marked\s+v?(\d+\.\d+\.\d+)'],
        'content_patterns': [r'marked[^\n]{0,30}?version\s*[=:]\s*[\'"]([\d.]+)'],
        'vulns': [
            {'range': '<4.0.10', 'id': 'CVE-2022-21680', 'severity': 'HIGH',
             'summary': '正则 ReDoS（4.0.10 修复）'},
        ],
    },
    {
        'name': 'Vue',
        'filename_patterns': [r'vue[.\-]v?(\d+\.\d+\.\d+)', r'\bvue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js\b'],
        'banner_patterns': [r'Vue\.js\s+v?(\d+\.\d+\.\d+)'],
        'content_patterns': [r'Vue\.js\s+v(\d+\.\d+\.\d+)'],
        'vulns': [],
    },
    {
        'name': 'React',
        'filename_patterns': [r'react[.\-]v?(\d+\.\d+\.\d+)', r'\breact(?:-dom)?\.production\.min\.js\b'],
        'banner_patterns': [r'React\s+v?(\d+\.\d+\.\d+)'],
        'content_patterns': [r'React\s+v(\d+\.\d+\.\d+)'],
        'vulns': [],
    },
]

# 外部 JSON 的字段白名单（防脏数据）
_LIB_KEYS = ('name', 'filename_patterns', 'banner_patterns', 'content_patterns', 'vulns')


# 版本比较 / 区间判定（纯标准库，容忍 1.2 / 1.2.3 / v1.2.3 / 1.2.3-rc1）
def _ver_tuple(v):
    """把版本串解析为可比较的整数元组；无法解析返回 None

    取全部数字段（忽略 pre-release 后缀，如 1.2.3-rc1 → (1,2,3)），
    便于做"已知漏洞区间"的粗粒度判定（SCA 的标准做法，不需要严格 semver）。
    """
    if v is None:
        return None
    nums = re.findall(r'\d+', str(v))
    if not nums:
        return None
    return tuple(int(n) for n in nums)


def _cmp(a, b):
    """比较两个版本元组：a<b → -1, a==b → 0, a>b → 1（短的一方按 0 补齐）"""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(version, range_str):
    """判定 version 是否落在 range_str 描述的区间内（多约束逗号分隔 = AND）

    range_str 形如 "<4.17.21" / ">=1.0.0,<1.2.3"。version 无法解析时返回 False
    （宁可漏报也不误报——版本不明时不下"存在漏洞"的结论）。
    """
    vt = _ver_tuple(version)
    if vt is None:
        return False
    # 关键: 空 / 全空白 / 无有效约束的区间 → **返回 False**(不判漏洞)。
    #   否则外部 --sca-db 里漏写 range 的条目会把**任意版本**都标成"存在漏洞"(假阳性)。
    parts = [p.strip() for p in str(range_str).split(',') if p.strip()]
    if not parts:
        return False
    for part in parts:
        m = re.match(r'^(<=|>=|<|>|=)?\s*v?([\d.]+)$', part)
        if not m:
            return False
        op, raw = m.group(1) or '=', m.group(2)
        rt = _ver_tuple(raw)
        if rt is None:
            return False
        c = _cmp(vt, rt)
        if op == '<' and not (c < 0):
            return False
        if op == '<=' and not (c <= 0):
            return False
        if op == '>' and not (c > 0):
            return False
        if op == '>=' and not (c >= 0):
            return False
        if op == '=' and c != 0:
            return False
    return True


# 识别
def _first_group(patterns, text):
    """按顺序尝试多个正则，返回第 1 个命中的 (version_or_None, matched_text)"""
    for pat in patterns or []:
        try:
            m = re.search(pat, text, re.IGNORECASE)
        except re.error:
            continue
        if m:
            ver = m.group(1) if (m.groups() and m.group(1)) else None
            return ver, m.group(0)[:80]
    return None, None


def identify_libraries(text, src='', extra_libs=None):
    """从 JS 文本 + 来源 URL 识别第三方库及其版本

    Returns: dict {name: {'version': str|None, 'evidence': str, 'src': src}}
    识别顺序：文件名/URL → 文件头部 banner → 正文。命中即取，不再重复匹配同名库。
    """
    if not text:
        return {}
    head = text[:4000]
    base = os.path.basename(src.split('?', 1)[0]) if src else ''
    libs = list(BUILTIN_LIBS) + list(extra_libs or [])
    found = {}
    for lib in libs:
        name = lib.get('name')
        if not name or name in found:
            continue
        # 关键：**presence（是否命中）**与**version（版本提取）**分开判定。
        #   若"文件名"只命中而无版本（如 jquery.min.js），仍需继续到 banner/content
        #   取版本 —— 否则会把带 banner 版本的库误判为"版本未知"。
        presence = None      # 首个命中(用于证据)
        version = None       # 首个带捕获组的命中(用于版本)
        for label, pats, hay in (
                ('filename', lib.get('filename_patterns'), base),
                ('banner', lib.get('banner_patterns'), head),
                ('content', lib.get('content_patterns'), text)):
            v, e = _first_group(pats, hay)
            if e is None:
                continue
            if presence is None:
                presence = f'{label}:{e}'
            if v is not None and version is None:
                version = v
        if presence is None:
            continue
        found[name] = {'version': version, 'evidence': presence, 'src': src}
    return found


def match_vulns(libs, extra_libs=None):
    """把已识别库对照内置漏洞表，返回命中列表（仅对"有版本"的库判定）

    Returns: list of {'name','version','id','severity','summary','fixed'}
    """
    table = {entry['name']: entry for entry in (list(BUILTIN_LIBS) + list(extra_libs or []))}
    out = []
    for name, info in (libs or {}).items():
        ver = info.get('version') if isinstance(info, dict) else None
        lib = table.get(name)
        if not lib or ver is None:
            continue
        for v in lib.get('vulns', []):
            if in_range(ver, v.get('range', '')):
                out.append({
                    'name': name, 'version': ver, 'id': v.get('id', ''),
                    'severity': norm_sev(v.get('severity', 'MEDIUM')),
                    'summary': v.get('summary', ''),
                    'fixed': v.get('range', ''),
                })
    # 高危优先(内部词汇)
    order = {'CRITICAL': 0, 'HIGH': 1, 'MED': 2, 'LOW': 3}
    out.sort(key=lambda x: (order.get(x['severity'], 9), x['name']))
    return out


# 可选：OSV 联网富化（默认关；会向 api.osv.dev 发送包名+版本）
_OSV_WARNED = False


def _warn_osv_once():
    """OSV 富化是**向第三方发送目标数据**(包名+版本)的动作 —— 首次调用告警一次
    (与 `verify_secrets` 的合规告警一致), 避免"静默向第三方发包"。"""
    global _OSV_WARNED
    if _OSV_WARNED:
        return
    _OSV_WARNED = True
    log('[!] 合规告警: 已开启 OSV 联网富化(sca_osv) —— 将向第三方 api.osv.dev 发送目标的'
        '**包名+版本**(只读查询, 不修改任何资源); 请确认已获授权。')


def osv_query(name, version, timeout=8):
    """查询 OSV（https://api.osv.dev）获取该 npm 包版本的已知漏洞

    失败（网络不可达 / 非 200 / 解析失败）一律返回 []，绝不抛异常——
    SCA 的内置表是主路径，OSV 只是可选富化。
    """
    _warn_osv_once()
    import urllib.request
    payload = json.dumps({'package': {'name': name, 'ecosystem': 'npm'},
                          'version': version}).encode('utf-8')
    req = urllib.request.Request(
        'https://api.osv.dev/v1/query', data=payload,
        headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode('utf-8', 'ignore'))
    except Exception:
        return []
    out = []
    for v in data.get('vulns', []) or []:
        sev = 'MEDIUM'
        for s in (v.get('severity') or []):
            if str(s.get('score', '')).upper().startswith('CVSS'):
                sev = 'HIGH'
        out.append({'id': v.get('id', ''), 'summary': (v.get('summary') or '')[:200],
                    'severity': norm_sev(sev)})
    return out


# 对外主入口
def sca_scan(text, src='', extra_libs=None, osv=False, osv_max=5):
    """一次完整 SCA：识别库 → 对照漏洞表（→ 可选 OSV 富化）

    Returns: {'libs': {name: info}, 'vulns': [ ... ]}
    """
    libs = identify_libraries(text, src, extra_libs)
    vulns = match_vulns(libs, extra_libs)
    if osv and libs:
        have = {(v['name'], v['id']) for v in vulns}
        for i, (name, info) in enumerate(sorted(libs.items())):
            if i >= osv_max:
                break
            ver = info.get('version')
            if not ver:
                continue
            for hit in osv_query(name, ver):
                if (name, hit['id']) in have:
                    continue
                vulns.append({'name': name, 'version': ver, 'id': hit['id'],
                              'severity': norm_sev(hit['severity']), 'summary': hit['summary'],
                              'fixed': '(OSV)'})
                have.add((name, hit['id']))
    return {'libs': libs, 'vulns': vulns}


def load_sca_db(path):
    """读取外部 SCA 库定义 JSON（内置保留 + 外部追加）

    结构：{"libraries": [ {name, filename_patterns, banner_patterns,
                          content_patterns, vulns:[{range,id,severity,summary}]} ]}
    非法结构/字段一律跳过（不因脏数据中断扫描）。
    """
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return []
    libs = data.get('libraries') if isinstance(data, dict) else data
    out = []
    if not isinstance(libs, list):
        return []
    for lib in libs:
        if not isinstance(lib, dict) or not lib.get('name'):
            continue
        clean = {k: lib.get(k) for k in _LIB_KEYS if k in lib}
        clean.setdefault('vulns', [])
        out.append(clean)
    return out
