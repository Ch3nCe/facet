# -*- coding: utf-8 -*-
"""回归: 探活方法透明度(P-T) —— 目标无关(通用)验证。

不绑定任何特定目标(无 OA/特定栈/特定路径); 用**合成多形态端点**证明:
  1) 任意写声明方法(POST/PUT/PATCH/DELETE)以只读 GET 探活时, 状态备注标注真实探测方法,
     probe_method 字段 = 实际探测方法;
  2) 普通 GET 端点(声明==探测)不误标;
  3) 无 JS 声明端点(声明 `—`)不误标;
  4) 通用分支: 凡"声明方法 ≠ 实测探活方法"即披露(不写死"GET 降级"假设),
     即便未来出现非只读降级的其它探测方法差异也能诚实标注。
"""
import sys, os


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
        self.all_found = all_found
        self.pmap = {}
        self.inferred_paths = set()
        self.mined_paths = set()


def build():
    # 合成多形态端点(与任何真实目标无关)
    all_found = [
        # 1) POST 声明, 只读 GET 探活 403
        ('/api/orders', 'GET', 403, 'len=137 ct=json'),
        # 2) PUT 声明, 只读 GET 探活 200
        ('/api/orders/1', 'GET', 200, 'len=512 ct=json'),
        # 3) DELETE 声明, 只读 GET 探活 404
        ('/api/orders/1', 'GET', 404, ''),
        # 4) PATCH 声明, 只读 GET 探活 401
        ('/api/profile', 'GET', 401, 'len=33 ct=json'),
        # 5) 普通 GET 端点, 声明==探测
        ('/api/public/health', 'GET', 200, 'len=88 ct=json'),
        # 6) 无 JS 声明(字典/响应挖掘命中), 探测 GET, 200
        ('/actuator/health', 'GET', 200, 'len=40 ct=json'),
        # 7) 通用分支: 声明 GET 但实测探测方法为 POST(模拟未来非只读降级差异)
        ('/api/legacy/x', 'POST', 200, 'len=10 ct=json'),
    ]
    ctx = _Ctx(all_found)
    meta = {
        # 写声明方法覆盖 POST/PUT/DELETE/PATCH
        'write_apis': {'/api/orders': 'POST', '/api/orders/1': 'PUT',
                       '/api/profile': 'PATCH'},
        'api_methods': {'/api/orders': 'POST', '/api/orders/1': 'PUT',
                       '/api/profile': 'PATCH',
                       '/api/public/health': 'GET', '/api/legacy/x': 'GET'},
        'js_files': [], 'routes': set(), 'apis': set(), 'recomb': set(),
    }
    return ctx, meta


def main():
    ctx, meta = build()
    rows = R._endpoint_master_risk(ctx, list(ctx.all_found), meta['write_apis'], meta, None, None)
    by = {r[0]: r for r in rows}
    fails = []

    def check(path, exp_method, exp_probe, exp_disclose, exp_no_disclose=False):
        c, m, src, sn, pp, op, pm, *_ = by[path]
        if m != exp_method:
            fails.append(f"{path}: 声明方法应为 {exp_method}, 实为 {m!r}")
        if pm != exp_probe:
            fails.append(f"{path}: probe_method 应为 {exp_probe}, 实为 {pm!r}")
        if exp_disclose and '探测' not in sn:
            fails.append(f"{path}: 应披露探测方法差异, 但 note={sn!r}")
        if exp_no_disclose and '探测' in sn:
            fails.append(f"{path}: 不应披露, 但 note={sn!r}")

    # 1-4: 写声明 + 只读 GET 探活 → 披露 + probe=GET
    check('/api/orders', 'POST', 'GET', True)
    check('/api/orders/1', 'PUT', 'GET', True)
    check('/api/profile', 'PATCH', 'GET', True)
    # DELETE 端点 404: 仍披露"声明≠探测"(诚实), probe=GET
    del_rows = [r for r in rows if r[0] == '/api/orders/1' and r[1] == 'DELETE']
    if del_rows:
        _, m, _, sn, *_ = del_rows[0]
        if m != 'DELETE':
            fails.append(f"/api/orders/1 DELETE 行方法应为 DELETE, 实为 {m!r}")
        if '探测' not in sn:
            fails.append(f"/api/orders/1 DELETE 行应披露, note={sn!r}")

    # 5: 普通 GET, 不误标
    check('/api/public/health', 'GET', 'GET', False, exp_no_disclose=True)
    # 6: 无声明(`—`), 不误标
    c6, m6, src6, sn6, *_ = by['/actuator/health']
    if m6 != '—':
        fails.append(f"actuator/health: 声明应为 —, 实为 {m6!r}")
    if '探测' in sn6:
        fails.append(f"actuator/health: 无声明不应披露, note={sn6!r}")

    # 7: 通用分支(声明 GET vs 实测 POST) → "探测方法 POST ≠ 声明 GET"
    c7, m7, src7, sn7, pp7, op7, pm7, *_ = by['/api/legacy/x']
    if '探测方法 POST ≠ 声明 GET' not in sn7:
        fails.append(f"/api/legacy/x: 通用分支未触发, note={sn7!r}")

    # 元组长度一致性(13)
    for r in rows:
        if len(r) != 13:
            fails.append(f"元组长度应为 13, 实为 {len(r)}: {r[0]}")

    if fails:
        print("FAIL:")
        for f in fails:
            print("  -", f)
        return 1
    print("PASS: 探活方法透明度 — 通用(目标无关)回归全部通过")
    for p in ('/api/orders', '/api/orders/1', '/api/profile', '/api/legacy/x'):
        c = by[p]
        print(f"  {p:22} methods={c[1]!r:10} probe_method={c[6]!r:8} note={c[3]!r}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
