# -*- coding: utf-8 -*-
"""后端栈指纹（版本级）：从响应头抽取 Web 服务器 / 运行时 / 框架的**产品 + 版本**。

背景：现有 `fingerprint.py` 的 `FP_STRONG_SIGNALS` 能判定"是 Nginx / Tomcat / PHP…"，
但**丢掉版本号** —— 而 `Server: nginx/1.18.0`、`X-Powered-By: PHP/7.4.3`、
`X-AspNet-Version: 4.0.30319` 里恰好带着版本；版本是"已知漏洞区间"映射的关键。
本模块把「产品 + 版本 + 推断语言」显式抽出，供报告 / JSON 消费（与 `sca.py` 对
前端库的版本提取同思路，只是作用于响应头）。

合规：纯只读解析响应头，零发包。
"""
import re

# 逐个头提取（顺序即优先级）
_HEADER_KEYS = ('Server', 'X-Powered-By', 'X-AspNet-Version',
                'X-AspNetMvc-Version', 'Via', 'X-Zuul')

# 产品名 → 运行时/框架语言（只映射"应用运行时/框架"；nginx/apache 等纯 Web 服务器
#   不映射语言 —— 它们常是前置代理，语言与后端无关）
_LANG = {
    'python': 'Python', 'basehttp': 'Python', 'gunicorn': 'Python',
    'uvicorn': 'Python', 'werkzeug': 'Python', 'waitress': 'Python',
    'hypercorn': 'Python', 'daphne': 'Python',
    'php': 'PHP',
    'express': 'Node.js', 'node': 'Node.js', 'next.js': 'Node.js',
    # Nuxt 是 Node 的 SSR 框架(`X-Powered-By: Nuxt`), 与 next.js 同类 → 推断 Node.js
    #   (此前未映射 → `backend_stack.language` 恒为 null, 信息缺口)。
    'nuxt': 'Node.js',
    'jetty': 'Java', 'tomcat': 'Java', 'apache-coyote': 'Java',
    'undertow': 'Java', 'wildfly': 'Java', 'jboss': 'Java',
    'weblogic': 'Java', 'glassfish': 'Java', 'spring': 'Java',
    'zuul': 'Java',
    'kestrel': 'C#/.NET', 'iis': 'C#/.NET', 'asp.net': 'C#/.NET',
    'microsoft-iis': 'C#/.NET',
    'puma': 'Ruby', 'passenger': 'Ruby', 'unicorn': 'Ruby',
    'cowboy': 'Erlang',
}

# 产品显示名别名: 头值可能是网关/框架代号(如 `X-Zuul: zuul`), 映射成可读名。
_PROD_ALIAS = {
    'zuul': 'Spring-Cloud/Zuul',
}

# 头名本身即语言信号（值可能是纯版本号，无法靠产品名映射）
_SOURCE_LANG = {
    'X-AspNet-Version': 'C#/.NET',
    'X-AspNetMvc-Version': 'C#/.NET',
}

_RE_PRODVER = re.compile(r'([A-Za-z][\w+.\-]*?)[/\s]v?(\d+(?:\.\d+){0,3})')
_RE_NOISE = {'http', 'https', 'text', 'html', 'charset', 'utf-8'}


def extract_backend_stack(headers):
    """从响应头提取后端栈（版本级）。

    headers: dict（如 `dict(r.headers)`）或任意 (k, v) 可迭代。

    返回:
        {
          'products': [{'name': str, 'version': str|None, 'source': str}],
          'language': str|None,      # 由产品推断（逗号分隔）
          'raw': {头名: 值},
        }
    """
    hdrs = {}
    try:
        for k, v in (headers or {}).items():
            hdrs[str(k).lower()] = v
    except AttributeError:
        for k, v in (headers or []):
            hdrs[str(k).lower()] = v

    products, raw, seen = [], {}, set()
    for hname in _HEADER_KEYS:
        val = hdrs.get(hname.lower())
        if not val:
            continue
        val = str(val).strip()
        if not val:
            continue
        raw[hname] = val
        matches = list(_RE_PRODVER.finditer(val))
        if matches:
            for m in matches:
                name, ver = m.group(1), m.group(2)
                if name.lower() in _RE_NOISE:
                    continue
                key = (name.lower(), ver, hname)
                if key in seen:
                    continue
                seen.add(key)
                products.append({'name': _PROD_ALIAS.get(name.lower(), name),
                                'orig': name, 'version': ver, 'source': hname})
        else:
            # 无版本形态（如 `X-Powered-By: Express` / `ASP.NET`）。
            #   代理轨迹头(如 `Via: 1.1 vegur` / `2.0 heroku-router`)以**版本号开头**,
            #   整串当产品名会得到 "2.0 heroku-router" 这种噪声 → 去掉前导版本号取产品名。
            nm = val.strip()
            m2 = re.match(r'^\d+(?:\.\d+)*\s+(\S.*)$', nm)
            if m2:
                nm = m2.group(1).strip()
            key = (nm.lower(), None, hname)
            if key not in seen:
                seen.add(key)
                products.append({'name': _PROD_ALIAS.get(nm.lower(), nm),
                                'orig': nm, 'version': None, 'source': hname})

    langs = []
    for p in products:
        lg = (_SOURCE_LANG.get(p['source']) or _LANG.get(p['name'].lower())
              or _LANG.get((p.get('orig') or p['name']).lower()))
        if lg and lg not in langs:
            langs.append(lg)

    return {
        'products': products,
        'language': ','.join(langs) if langs else None,
        'raw': raw,
    }


def format_stack(stack):
    """把 extract_backend_stack 的结果渲染成单行文本（供报告）。空则返回 ''。"""
    if not stack or not stack.get('products'):
        return ''
    parts = []
    for p in stack['products']:
        parts.append(p['name'] + (f"/{p['version']}" if p.get('version') else ''))
    s = ' · '.join(parts)
    if stack.get('language'):
        s += f" | 语言: {stack['language']}"
    return s
