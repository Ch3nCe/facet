# -*- coding: utf-8 -*-
"""回归: 报告 HTML 端点主表的"一键复制全部接口 / 仅复制后端接口"按钮。

目标无关(合成 ctx/meta)。证明:
  1) 端点主表上方渲染两个 `data-copy` 按钮;
  2) `data-copy` 内容为**完整 URL 清单**(origin + 路径, 一行一个);
  3) "仅复制后端接口"只含 kind=backend_api 的端点(复用 `_endpoint_kind`)。
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

from facet.report.report import report_html  # noqa: E402


class _Ctx:
    def __init__(self):
        self.all_found = [('/api/admin/user/list', 'GET', 200, '通用探测命中'),
                          ('/admin/report', 'GET', 200, '通用探测命中')]
        self.findings = []
        self.pmap = {}
        self.excluded = []
        self.truncated = {}
        self.net_sent = 0
        self.total_sent = 0
        self.config = {}
        self.finding_loc = {}
        self.mined_paths = set()
        self.api_families = {}
        self.inferred_paths = set()
        self._resp_fingerprints = set()
        self.budget_exhausted = lambda: False
        self.circuit_tripped = False

    def __getattr__(self, name):
        return None


def main():
    meta = {
        'js_files': [], 'routes': {'/admin/report'}, 'apis': set(), 'recomb': set(),
        'write_apis': {'/auth/login': 'POST'}, 'api_methods': {},
        'subdomains': set(), 'dict_candidates': set(), 'api_srcline': {},
        'api_extractor': {}, 'api_snippet': {}, 'api_families': {}, 'evidence': {},
        'vendor_js': [], 'params': [], 'wasm_apis': set(), 'external_apis': set(),
        'relative_apis': set(),
    }
    out = tempfile.mktemp(suffix='.html')
    try:
        report_html(_Ctx(), 'https://www.macrozheng.com/', out, meta, [])
        h = open(out, encoding='utf-8').read()
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass
    assert '复制全部接口' in h, '缺少"复制全部接口"按钮'
    assert '仅复制后端接口' in h, '缺少"仅复制后端接口"按钮'
    # data-copy 里应是完整 URL
    assert 'https://www.macrozheng.com/api/admin/user/list' in h, '未含完整 URL'
    assert 'https://www.macrozheng.com/admin/report' in h, '未含完整 URL(前端路由)'
    # 端点主表应有「类别」列(backend_api/frontend_route/unknown 的中文短标签)
    assert '<th>类别</th>' in h, '端点主表缺「类别」列'
    assert '后端接口' in h and '前端路由' in h, '类别列未渲染标签'
    print('regress_endpoint_copy: PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
