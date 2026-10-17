# -*- coding: utf-8 -*-
"""端到端冒烟: 本地 fixture 站点 → recon_deep → 报告(HTML/JSON/端点侧车)。

与单元测试互补: 本文件跑**真实扫描链路**(发现 → JS 管线 → 探活 → 编排 → 报告渲染),
目标为本地 http.server fixture(零外网依赖), 验证:

  1) 提取契约: JS 里的变量拼接/模板/调用点/xhr.open/写方法 全部进入 meta;
  2) 报告三件套: HTML(含端点与一键复制按钮) / report.json(completeness) /
     端点侧车 JSON(kind_summary) 均能产出;
  3) 运行时通道披露(批次 B): "已配置但未触发" 与 "已请求但未实际运行" 两种文案
     按 ctx.runtime_requested 分流渲染, 不混淆。

运行: python -m pytest -q tests/
"""
import http.server
import json
import os
import shutil
import sys
import tempfile
import threading

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from facet.core.config import expand_modules  # noqa: E402
from facet.core.orchestrator import recon_deep  # noqa: E402
from facet.core.watchdog import (  # noqa: E402
    cancel_scan_watchdog, install_scan_watchdog,
)
from facet.report.report import (  # noqa: E402
    report_html, report_json, write_endpoints_json,
)

_INDEX_HTML = """<!DOCTYPE html>
<html><head><title>fixture</title></head>
<body><h1>fixture app</h1><script src="app.js"></script></body></html>
"""

# 覆盖四类提取形态: 变量拼接 / 写方法 / $.get / xhr.open
_APP_JS = """const API = '/api';
fetch(API + '/user/list');
axios.post('/api/order/create', {data: {}});
$.get('/api/config/info');
var xhr = new XMLHttpRequest();
xhr.open('GET', API + '/goods/detail');
xhr.send();
"""


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):     # 静音 fixture 服务器日志
        pass


@pytest.fixture()
def workdir():
    """测试工作目录: 项目 output/ 下的临时目录(沙箱限制系统 TMPDIR, 故用仓库内路径),
    测试结束自动清理。output/ 在全新检出中不存在(gitignore), 故先显式创建(兼容 CI)。"""
    out_dir = os.path.join(_REPO, 'output')
    os.makedirs(out_dir, exist_ok=True)
    d = tempfile.mkdtemp(prefix='e2e_', dir=out_dir)
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture()
def fixture_server(workdir):
    """本地 fixture 站点(随机端口), 测试结束自动关闭。"""
    with open(os.path.join(workdir, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(_INDEX_HTML)
    with open(os.path.join(workdir, 'app.js'), 'w', encoding='utf-8') as f:
        f.write(_APP_JS)
    import functools
    handler = functools.partial(_QuietHandler, directory=workdir)
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f'http://127.0.0.1:{port}', workdir
    srv.shutdown()
    srv.server_close()


def _run_scan(url, workdir, runtime_cfg):
    """按 CLI `_scan_one_target` 的最小装配跑一轮真实扫描, 返回 (ctx, meta)。"""
    from facet.core.context import ScanContext
    from facet.core.rate import RateManager
    from facet.core.scope import build_scope

    config = {
        'max_duration': 90,
        'modules': 'passive',       # 显式 passive: 关 options/unauth 探测, 冒烟聚焦提取+报告
        'runtime': runtime_cfg,
        'rate': 0,
        'max_rpm': 10000,
        'max_js': 50,
        'authorized': True,
    }
    tctx = ScanContext(config)
    tctx.scope_rules = []
    tctx.scope = build_scope([], default_base=url)
    tctx.authorized = True
    tctx.auth_method = 'fixture-e2e'
    tctx.rm = RateManager(0, 10000, adapt=False)
    wd = install_scan_watchdog(90)
    try:
        mods = expand_modules(config['modules'])
        meta = recon_deep(tctx, url, mods, None)
    finally:
        cancel_scan_watchdog(wd)
    return tctx, meta


def test_e2e_extraction_and_reports(fixture_server):
    """① 提取: 四类形态全部进入 meta(apis/write_apis);
    ② 报告: HTML(端点+复制按钮) / JSON(completeness) / 端点侧车(kind_summary) 三件套产出。"""
    url, workdir = fixture_server
    tctx, meta = _run_scan(url, workdir, runtime_cfg=False)

    # ① 提取契约
    apis = set(meta.get('apis') or set())
    writes = meta.get('write_apis') or {}
    assert '/api/user/list' in apis, f'变量拼接未提取: {sorted(apis)}'
    assert '/api/config/info' in apis, f'$.get 未提取: {sorted(apis)}'
    assert '/api/goods/detail' in apis, f'xhr.open 未提取: {sorted(apis)}'
    assert writes.get('/api/order/create') == 'POST', f'写方法未分流: {writes}'
    assert (meta.get('js_files') or []) and 'app.js' in ''.join(
        str(j) for j in (meta.get('js_files') or [])), 'app.js 未被分析'

    # ②a HTML 报告
    html_path = os.path.join(workdir, 'r.html')
    report_html(tctx, url, html_path, meta, {})
    html = open(html_path, encoding='utf-8').read()
    assert '/api/user/list' in html, '端点未进 HTML 报告'
    assert '复制全部接口' in html, '一键复制按钮缺失'
    assert '已配置但未触发' not in html and '已请求但未实际运行' not in html, \
        'runtime=false 时不应出现运行时通道披露'

    # ②b report.json: completeness.runtime 如实(runtime=false → 未请求未运行)
    json_path = os.path.join(workdir, 'r.json')
    report_json(tctx, url, json_path, meta)
    payload = json.load(open(json_path, encoding='utf-8'))
    rt = payload['completeness']['runtime']
    assert rt['requested'] is False and rt['triggered'] is False and rt['ran'] is False

    # ②c 端点侧车: kind_summary 计数(写方法 → backend_api)
    ep_path = os.path.join(workdir, 'ep.json')
    write_endpoints_json(tctx, url, meta, ep_path)
    ep = json.load(open(ep_path, encoding='utf-8'))
    assert ep['schema'] == 'facet-endpoints/v1'
    assert ep['kind_summary'].get('backend_api', 0) >= 1
    by_ep = {e['endpoint']: e for e in ep['endpoints']}
    assert by_ep['/api/order/create']['kind'] == 'backend_api'


def test_e2e_runtime_disclosure_branches(fixture_server):
    """批次 B 行为契约: 同一扫描结果, 按 ctx.runtime_requested 渲染两种披露文案 ——
    "已配置但未触发"(auto 非 SPA, 设计不跑) vs "已请求但未实际运行"(请求了没跑成)。"""
    url, workdir = fixture_server
    tctx, meta = _run_scan(url, workdir, runtime_cfg=False)

    # ① 已配置(auto)但未触发(非 SPA) → "已配置但未触发", 不出现 ⚠️ 警告式文案
    tctx.config['runtime'] = 'auto'
    tctx.runtime_requested = False
    tctx.runtime_ran = False
    tctx.runtime_reason = 'runtime=auto: 目标非 SPA(页面类型/框架指纹/前端路由密集均未命中), 未触发运行时通道'
    p1 = os.path.join(workdir, 'r1.html')
    report_html(tctx, url, p1, meta, {})
    h1 = open(p1, encoding='utf-8').read()
    assert '已配置但未触发' in h1, 'auto 未触发文案缺失'
    assert '已请求但未实际运行' not in h1, 'auto 未触发被误述为"已请求但未实际运行"'

    # ② 已请求但没跑成(依赖缺失/异常) → ⚠️ 能力缺口文案
    tctx.runtime_requested = True
    tctx.runtime_ran = False
    tctx.runtime_reason = 'Playwright 未安装'
    p2 = os.path.join(workdir, 'r2.html')
    report_html(tctx, url, p2, meta, {})
    h2 = open(p2, encoding='utf-8').read()
    assert '已请求但未实际运行' in h2, '请求未运行文案缺失'
    assert 'Playwright 未安装' in h2, '原因未披露'

    # ③ JSON 侧同源: triggered 区分两种情形
    jp = os.path.join(workdir, 'r2.json')
    report_json(tctx, url, jp, meta)
    rt = json.load(open(jp, encoding='utf-8'))['completeness']['runtime']
    assert rt == {'requested': 'auto', 'triggered': True, 'ran': False,
                  'reason': 'Playwright 未安装'}
