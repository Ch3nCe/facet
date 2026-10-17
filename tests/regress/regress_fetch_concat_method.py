# -*- coding: utf-8 -*-
"""回归: fetch 写方法提取 —— 覆盖「拼接 URL」形态(通用修复验证)。

不绑定任何特定目标; 用极小代码片段证明:
  1) fetch(API_BASE + '/api/orders', {method:'POST'})  —— 拼接 URL + 写方法, 必须识别为写方法;
  2) fetch('/api/orders/1', {method:'PUT'})            —— 字面量 URL + 写方法(回归: 原行为保持);
  3) axios.post('/api/attendance/checkin', {...})       —— 链式写方法(回归);
  4) fetch(..., {method:'GET'}) / 无 method / 拼接但 GET —— 均**不**进 write_apis(只读交回调用点提取器)。

直接运行: python tests/regress/regress_fetch_concat_method.py  (退出 0=PASS)
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
from facet.core import js_extract as J


# (片段, 期望) —— 期望为 (path, method) 表示 write_apis 应含该键值; None 表示不应出现
CASES = [
    # 1) 拼接 URL + 写方法 —— 本次修复点
    ("fetch(API_BASE + '/api/orders', { method: 'POST', body: JSON.stringify({}) })",
     ('/api/orders', 'POST')),
    # 2) 字面量 URL + 写方法(回归: 旧行为必须保持)
    ("fetch('/api/orders/1', { method: 'PUT' })", ('/api/orders/1', 'PUT')),
    # 3) jQuery $.post 链式写方法(本函数覆盖, 回归)
    ("$.post('/api/widget')", ('/api/widget', 'POST')),
    # 4) 各种非写情形 —— 不应进 write_apis
    ("fetch('/api/public/health', { method: 'GET' })", None),
    ("fetch(API_BASE + '/api/cart/checkout', { method: 'GET' })", None),
    ("fetch(API_BASE + '/api/profile', {})", None),
]


def main():
    fails = []
    for snippet, expect in CASES:
        apis = J._extract_write_text_v45(snippet, '')
        if expect is None:
            # 这些必须不出现在 write_apis(只读, 交回调用点提取器)
            if apis:
                fails.append(f"非写片段不应产出写方法, 但得到 {apis!r}: {snippet!r}")
            continue
        path, method = expect
        got = apis.get(path)
        if got != method:
            fails.append(f"{snippet!r}: 期望 write_apis[{path!r}]={method!r}, 实为 {got!r}")
    if fails:
        print("FAIL:")
        for f in fails:
            print("  -", f)
        return 1
    print("PASS: fetch 写方法提取(含拼接 URL 形态) — 通用回归全部通过")
    for snippet, expect in CASES:
        if expect:
            apis = J._extract_write_text_v45(snippet, '')
            print(f"  {expect[0]:26} -> {apis.get(expect[0])}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
