# -*- coding: utf-8 -*-
"""端到端复跑 report_json 的端点对象装配, 验证 probe_method 字段真实落到 JSON 端点对象。
用桩替换 build_recon_matrix 等重依赖, 隔离本次改动(端点 dict 装配)。
"""
import sys, os, json, tempfile


def _find_repo_root(start):
    """向上查找含 facet/ 与 pyproject.toml 的仓库根(通用, 不硬编码绝对路径)."""
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
import facet.report.report as R


class _Ctx:
    def __init__(self, all_found):
        self.findings = []
        self.all_found = all_found
        self.excluded = []
        self.pmap = {}
        self.truncated = {}
        self.net_sent = 0
        self.budget_exhausted = lambda: False
        self.circuit_tripped = False
        self.config = {}
        self.tls_cert = None
        self.finding_loc = {}
        self.mined_paths = set()
        self._resp_fingerprints = set()
        self.api_families = {}
        self.inferred_paths = set()

    def __getattr__(self, name):
        # 兜底: 未显式设置的属性返回安全默认, 避免逐个补齐 report_json 的只读访问
        return None


def _run():
    all_found = [
        ('/api/attendance/checkin', 'GET', 403, 'len=137 ct=json'),
        ('/api/user/profile', 'GET', 200, 'len=520 ct=json'),
    ]
    ctx = _Ctx(all_found)
    meta = {
        'js_files': [], 'routes': set(), 'apis': set(), 'recomb': set(),
        'write_apis': {'/api/attendance/checkin': 'POST'},
        'api_methods': {'/api/attendance/checkin': 'POST', '/api/user/profile': 'GET'},
        'subdomains': set(), 'dict_candidates': set(),
        'api_srcline': {}, 'api_extractor': {}, 'api_snippet': {},
        'api_families': {}, 'evidence': {}, 'vendor_js': [], 'params': [],
    }
    out = os.path.join(tempfile.gettempdir(), 'ss_probe_method_test.json')
    R.report_json(ctx, 'http://example.com', out, meta)
    data = json.load(open(out, encoding='utf-8'))
    eps = {e['endpoint']: e for e in data['endpoints']}
    fails = []
    c = eps.get('/api/attendance/checkin')
    if c is None:
        fails.append('写端点缺失')
    else:
        if 'probe_method' not in c:
            fails.append('端点缺 probe_method 字段')
        if c.get('probe_method') != 'GET':
            fails.append(f"probe_method 应为 GET, 实为 {c.get('probe_method')!r}")
        if c.get('methods') != ['POST']:
            fails.append(f"methods 应为 ['POST'], 实为 {c.get('methods')!r}")
        if 'GET 探测(只读降级)' not in c['status']['note']:
            fails.append(f"status.note 未披露降级: {c['status']['note']!r}")
    g = eps.get('/api/user/profile')
    if g and 'GET 探测' in g['status']['note']:
        fails.append('普通 GET 端点不应披露降级')
    # 全端点都应带 probe_method 字段
    for e in data['endpoints']:
        if 'probe_method' not in e:
            fails.append(f"端点 {e['endpoint']} 缺 probe_method 字段")
    os.remove(out)
    if fails:
        print("FAIL:")
        for f in fails:
            print("  -", f)
        return 1
    print("PASS: report_json 端点对象已带 probe_method 字段")
    print(f"  写端点 /api/attendance/checkin -> methods={c['methods']} "
          f"probe_method={c['probe_method']!r} note={c['status']['note']!r}")
    return 0


def main():
    """打桩跑 `_run`, **用完即还原** —— 模块级打桩会污染同进程内后续测试:
    实测旧实现把 `R.build_recon_matrix` 永久替换为空桩, 使后续测试的
    `build_recon_matrix` 恒返回空 rows(连锁失败)。此处改为进入时替换、退出时还原。
    """
    _orig = R.build_recon_matrix
    _orig_dgh = getattr(R, '_dedupe_generic_hidden', None)
    R.build_recon_matrix = lambda ctx, meta: {'rows': [], 'unauth_access_hints': []}
    if _orig_dgh is not None:
        R._dedupe_generic_hidden = lambda ctx: None
    try:
        return _run()
    finally:
        R.build_recon_matrix = _orig
        if _orig_dgh is not None:
            R._dedupe_generic_hidden = _orig_dgh


if __name__ == '__main__':
    sys.exit(main())
