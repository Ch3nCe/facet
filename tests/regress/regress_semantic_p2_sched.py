# -*- coding: utf-8 -*-
"""回归(CI 安全, 无网络/无 node 依赖): 覆盖三处此前只散在 output/ 的验证 ——
  A) P0-1 语义解析: 变量 baseURL + 拼接/模板调用参数 → 还原真实端点;
  B) P2 机会性 sourcemap 收割: 命中 sourcesContent → 端点入 apis(REQ 打桩);
  C) 调度: 探活排序用"证据/来源"分层(ctx.evidence)。
"""
import os
import sys
import json
import tempfile


def _find_repo_root(start):
    d = os.path.dirname(os.path.abspath(start))
    while True:
        if os.path.isdir(os.path.join(d, 'facet')) and os.path.isfile(
                os.path.join(d, 'pyproject.toml')):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return os.path.dirname(os.path.abspath(start))


SRC = _find_repo_root(__file__)
sys.path.insert(0, SRC)


def _t_semantic():
    from facet.core.js_extract import _extract_api_calls
    js = ("const API='/api';"
          "function l(){return request(API+'/admin/user/list');}"
          "fetch(`${API}/admin/config/list`);")
    calls = _extract_api_calls(js, 'http://x/')
    assert '/api/admin/user/list' in calls, '变量 baseURL + 拼接未还原'
    assert '/api/admin/config/list' in calls, '模板串未还原'


def _t_sourcemap():
    import facet.core.orchestrator as O
    sm = json.dumps({"version": 3, "sources": ["a.js"], "mappings": "",
                     "sourcesContent": ["const API='/api';fetch(API+'/admin/user/list');"]})

    class R:
        def __init__(self, t, st): self.text, self.status_code = t, st
    _orig = O.REQ
    O.REQ = lambda ctx, m, url, *a, **k: (R(sm, 200) if url.endswith('.map') else R('', 404))

    class C:
        config = {'sourcemap_probe': True}
        sca_enabled = False
        def add_finding(self, *a, **k): pass
        def log(self, *a, **k): pass

    out = {'write_apis': {}, 'apis': set()}
    try:
        O._process_external_sourcemap(C(), 'http://x/', 'http://x/a.js',
                                      'http://x/a.js.map', out, {'RE_API'}, [])
    finally:
        O.REQ = _orig
    assert any('/api/admin/user/list' in p for p in out['apis']), 'sourcemap sourcesContent 未还原端点'


def _t_scheduling():
    import facet.core.orchestrator as O
    _orig = (O.resolve_dispatch, O.probe, O.options_probe, O.hidden_probe, O.plugins.enabled)
    cap = {}
    O.resolve_dispatch = lambda ctx, out: None
    O.probe = lambda ctx, base, apis, token=None, no_cap=False, hard_cap=0: cap.update(
        evidence=dict(getattr(ctx, 'evidence', {}) or {}))
    O.options_probe = lambda *a, **k: None
    O.hidden_probe = lambda *a, **k: None
    O.plugins.enabled = lambda *a, **k: True

    class C:
        config = {}
        def is_invalid(self, p): return False

    out = {'evidence': {'/api/x': 'runtime', '/api/y': 'static'},
           'api_extractor': {'/api/z': 'route-rebase'}, 'write_apis': {}}
    try:
        O._run_probes(C(), 'http://x/', out, {'/api/x'}, set(), set(), None)
    finally:
        (O.resolve_dispatch, O.probe, O.options_probe, O.hidden_probe, O.plugins.enabled) = _orig
    ev = cap.get('evidence') or {}
    assert ev.get('/api/x') == 3, 'runtime 证据档应=3'
    assert ev.get('/api/y') == 1, 'static 证据档应=1'
    assert ev.get('/api/z') == 0, 'route-rebase 应=最低档 0'


def _t_doc_code_chunk():
    from facet.core.orchestrator import _is_doc_code_chunk
    # VitePress 文档代码块 chunk(形态) → True
    assert _is_doc_code_chunk('https://x/assets/springboot_start.html-maI4TneG.js')
    assert _is_doc_code_chunk('https://x/assets/nginx_https_start.html-B0Rli3RQ.js')
    # 普通业务/入口 JS → False(不误伤)
    assert not _is_doc_code_chunk('https://x/assets/app.6fd08488.js')
    assert not _is_doc_code_chunk('https://x/static/js/index.js')


def main():
    _t_semantic()
    _t_sourcemap()
    _t_scheduling()
    _t_doc_code_chunk()
    print('regress_semantic_p2_sched: PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
