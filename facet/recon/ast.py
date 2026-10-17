# -*- coding: utf-8 -*-
"""R7 AST 侧车持久化。

复用 core.ast_sidecar 已有的 Node + Acorn 静态 AST 提取结果，不额外引入一套解析器/依赖，
把扫描中按源文件累计的 AST 结果写成 JSON 供 CI / 流水线消费。只存结构化端点提示，不保存
JS 源码；不执行目标代码、不额外发包。
"""
import json
from datetime import datetime


def _safe(v):
    """序列化（**不再脱敏** —— 原样输出）。"""
    return str(v or '')


def write_ast_sidecar(ctx, meta, path):
    """写出 `facet-ast/v1` 机器可读 JSON。

    返回已记录的源文件数；若没有启用 AST 捕获/无 JS 输入则不写空侧车。
    即使 Acorn 不可用，扫描层会把每个 JS 文件的 ran=false 与原因写入 ast_results，
    让产物准确披露降级状态。
    """
    import os
    from ..output.paths import ensure_parent

    sources = (meta or {}).get('ast_results') or {}
    if not sources:
        return 0
    files = []
    totals = {'analyzed': 0, 'api_calls': 0, 'path_literals': 0, 'write_apis': 0}
    for src, raw in sorted(sources.items(), key=lambda x: str(x[0])):
        item = raw if isinstance(raw, dict) else {}
        apis = sorted({_safe(p) for p in (item.get('apis') or []) if p})
        literals = sorted({_safe(p) for p in (item.get('literals') or []) if p})
        writes = {_safe(p): str(m).upper()
                  for p, m in (item.get('write_apis') or {}).items() if p}
        ran = bool(item.get('ran'))
        files.append({
            'source': _safe(src),
            'ran': ran,
            'reason': str(item.get('reason') or ''),
            'api_calls': apis,
            'path_literals': literals,
            'write_apis': writes,
        })
        if ran:
            totals['analyzed'] += 1
            totals['api_calls'] += len(apis)
            totals['path_literals'] += len(literals)
            totals['write_apis'] += len(writes)
    payload = {
        'schema': 'facet-ast/v1',
        'target': _safe(getattr(ctx, 'target', None) or ''),
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'parser': 'Node.js + Acorn (static AST; target code not executed)',
        'summary': {'files': len(files), **totals},
        'files': files,
    }
    try:
        ensure_parent(path)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return len(files)
    except Exception:
        return 0
