# -*- coding: utf-8 -*-
"""回归: 端点分类(backend_api/frontend_route/unknown) + replay.sh 基址取 origin。

目标无关(合成用例)。证明:
  1) `_endpoint_kind` 按"写方法/relative_apis → 后端; 命中 routes → 前端路由;
     API 前缀 → 后端; 其余 → unknown"分层;
  2) `build_recon_matrix` 每行都带 `kind`;
  3) `write_replay_sh` 的 URL 基址取**目标 origin**, 不再把扫描入口路径(如 /login)当基址。
"""
import os
import sys
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

from facet.report.report import (  # noqa: E402
    _endpoint_kind, build_recon_matrix, write_replay_sh,
)

META = {
    'routes': {'/admin/user/list', '/admin/report'},
    'write_apis': {'/auth/login': 'POST'},
    'relative_apis': {'/board/detail/'},
    'api_extractor': {},
    'apis': {'/api/admin/user/list', '/auth/check-username'},
    'recomb': set(),
    'api_conf': {}, 'api_srcline': {}, 'api_methods': {},
    'wasm_apis': set(), 'external_apis': set(),
}


def main():
    # 1) _endpoint_kind 分层
    cases = [
        ('/api/admin/user/list', 'GET', 'backend_api'),
        ('/admin/user/list', 'GET', 'frontend_route'),
        ('/admin/report', 'GET', 'frontend_route'),
        ('/auth/login', 'POST', 'backend_api'),
        ('/board/detail/', 'GET', 'backend_api'),
        ('/api/user/1/disable', 'GET', 'backend_api'),
        ('/actuator/env', 'GET', 'backend_api'),        # 运维/监控面 → 后端接口
        ('/cart/add', 'GET', 'backend_api'),            # 通用 REST 动作段(无 /api 前缀)
        ('/order/generateOrder', 'GET', 'backend_api'),  # camelCase 动作段
        ('/home/recommendProductList', 'GET', 'backend_api'),
        ('/swagger-ui/index.html', 'GET', 'frontend_route'),  # 静态页 → 前端路由
        ('/login', 'GET', 'unknown'),                   # 页面型词不误判为接口
        ('/settings', 'GET', 'unknown'),
        ('/getting-started', 'GET', 'unknown'),
        ('/accedi', 'GET', 'unknown'),
    ]
    for p, m, exp in cases:
        got = _endpoint_kind(p, META, m)
        assert got == exp, f'_endpoint_kind({p!r})={got!r} != {exp!r}'

    # 2) build_recon_matrix 行带 kind
    class _Ctx:
        all_found = [('/api/admin/user/list', 'GET', 200, '通用探测命中'),
                     ('/admin/report', 'GET', 200, '通用探测命中'),
                     ('/accedi', 'GET', 200, '通用探测命中')]
        pmap = {}
        findings = []
        config = {}

    rows = build_recon_matrix(_Ctx(), META)['rows']
    kinds = {r['path']: r.get('kind') for r in rows}
    assert all('kind' in r for r in rows), '每行都应有 kind'
    assert kinds.get('/api/admin/user/list') == 'backend_api'
    assert kinds.get('/admin/report') == 'frontend_route'
    assert kinds.get('/accedi') == 'unknown'

    # 去重: 同一路径既是写声明(write_apis)又在源码候选(api_srcline) → 只应出一行
    #   (旧实现 1c 去重键写死 "GET", 与 1a 的声明方法不同 → 重复成两行)。
    _meta2 = dict(META)
    _meta2['api_srcline'] = {'/auth/login': ('src.js', 1, 1)}
    _rows2 = build_recon_matrix(_Ctx(), _meta2)['rows']
    _n = sum(1 for r in _rows2 if r['path'] == '/auth/login')
    assert _n == 1, f'/auth/login 应只 1 行, 实为 {_n}(去重键回归)'

    # 3) replay.sh 基址取 origin(入口含 /login 也不应污染)
    class _Ctx2:
        all_found = [('/api/admin/user/list', 'GET', 200, '通用探测命中')]
        pmap = {}
        findings = []
        config = {}

    rp = tempfile.mktemp(suffix='.replay.sh')
    try:
        write_replay_sh(_Ctx2(), 'http://h:8081/login', META, rp)
        content = open(rp, encoding='utf-8').read()
    finally:
        try:
            os.unlink(rp)
        except OSError:
            pass
    curl = [l for l in content.splitlines() if l.startswith('curl')]
    assert curl and 'http://h:8081/api/admin/user/list' in curl[0], 'base 未取 origin'
    assert '/login/api/' not in content, '仍把入口路径当基址'

    print('regress_endpoint_kind: PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
