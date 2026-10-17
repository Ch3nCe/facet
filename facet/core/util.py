# -*- coding: utf-8 -*-
"""通用小工具（**基础设施层**）—— 原从 `core/engine.py` 下沉（该门面已删除）。

动机（架构一致性）：`report/report.py`（`_host_of`）与 `recon/runtime.py`
（`_extract_paths_from_obj`）需要这两个纯函数，若从编排层（原 `core/engine.py`）导入即为**向上依赖**。
"""
from urllib.parse import urlsplit


def _host_of(url):
    """取 URL 的 netloc(小写, 含端口)。非法/非 http(s) 返回 ''。"""
    if not url or not (url.startswith('http://') or url.startswith('https://')):
        return ''
    try:
        return urlsplit(url).netloc.lower()
    except Exception:
        return ''


def _extract_paths_from_obj(obj, out, depth=0, prefixes=('/api/',)):
    """递归提取对象中的路径字符串

    增加 prefixes 参数。此前 core 版只收 '/api/' 开头, 而 runtime.py 里的
    同名副本收 '/' 开头 —— 两个同名函数行为不一致, 导致 runtime 通道把前端路由
    (/home、/about 等)也当作 API 并入 out['apis'], 随后被 probe() 真实请求。
    """
    if depth > 5 or not isinstance(obj, (dict, list)):
        if isinstance(obj, str) and obj.startswith(tuple(prefixes)):
            out.add(obj)
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _extract_paths_from_obj(v, out, depth + 1, prefixes)
    elif isinstance(obj, list):
        for v in obj:
            _extract_paths_from_obj(v, out, depth + 1, prefixes)
