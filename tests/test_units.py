# -*- coding: utf-8 -*-
"""核心链路单元测试(直接测库函数, 无网络 / 无浏览器)。

与 `tests/test_regressions.py` 互补: 后者是"修复钉子"(包装 tests/regress/ 回归脚本),
本文件是**主动覆盖**核心链路的契约测试:

  · dicts.score_api_priority      —— 探活排序的纯函数打分(管理面/敏感面/文档加分)
  · guard.should_run_runtime      —— runtime 三态裁决 + 未触发原因(批次 B 契约)
  · ast_sidecar.extract           —— Node+Acorn / tree-sitter 双引擎契约
                                      (调用点 / 变量还原 / 模板串 / 写方法分流 / 形参排除 / 循环保护)
  · js_extract.deep_analyze       —— 门控(RE_BASEURL/RE_ROUTE) / 写方法分流 / 归一化去重
  · core.probe.probe              —— 证据档优先于启发式的**排序行为**(monkeypatch 请求层, 零发包)
  · report.write_endpoints_json   —— 端点侧车的 kind / kind_summary
  · nodeenv.find_node / node_modules_dirs —— Node 环境探测的移机通用性
                                              (动态发现: env/cwd 标准解析, 不钉机器路径)
  · task_service._default_output_dir      —— MCP 默认输出目录双形态不变量
                                              (源码检出=仓库根; pip 安装=cwd, 绝不落安装目录)

运行: python -m pytest -q tests/
"""
import json
import os
import shutil
import sys
import tempfile

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from facet.core import ast_sidecar  # noqa: E402
from facet.core import probe as probe_mod  # noqa: E402
from facet.core.dicts import score_api_priority  # noqa: E402
from facet.core.guard import should_run_runtime  # noqa: E402
from facet.core.js_extract import deep_analyze  # noqa: E402
from facet.report.report import write_endpoints_json  # noqa: E402


# ---------- 1) score_api_priority 纯函数打分 ----------

def test_score_api_priority_tiers():
    """安全面分: 管理运维面 > 未鉴权敏感面 > 普通业务; 运维/文档面(swagger/actuator/
    api-docs/druid/openapi)另 +15 —— 其分数必 >100(SECMAP 基础分上限即 100)。"""
    admin = score_api_priority('/admin/panel')
    unauth = score_api_priority('/api/unauthorized-exposed')
    plain = score_api_priority('/api/plain/business')
    assert admin > unauth > plain, (admin, unauth, plain)
    assert admin >= 100 and plain == 0
    # 运维/文档面 +15 加分 → 必 >100(基础分最大 100)
    for p in ('/actuator/prometheus', '/swagger-ui/index', '/v3/api-docs', '/druid/index'):
        assert score_api_priority(p) > 100, f'{p} 未享文档加分: {score_api_priority(p)}'


# ---------- 2) runtime 三态裁决(批次 B 契约) ----------

class _MiniCtx:
    def __init__(self, runtime_cfg, fp_hits=None):
        self.config = {'runtime': runtime_cfg}
        self.fingerprints = {'hits': fp_hits or []}


def test_should_run_runtime_tristate():
    """false/true/auto 三态; auto 未触发时**必须给非空原因**(否则报告只能说"未运行",
    无法区分"没请求"与"请求了没跑成" —— 批次 B 契约)。

    注意: SPA 信号取**out**(页面类型/前端路由)而非 ctx —— 与 guard.should_run_runtime 签名一致;
    框架指纹取 ctx.fingerprints。
    """
    # true: 无条件运行
    run, why = should_run_runtime(_MiniCtx(True), {})
    assert run is True and why
    # false / None: 从不运行, 无原因(false 是用户显式关闭, 无需解释)
    assert should_run_runtime(_MiniCtx(False), {}) == (False, '')
    assert should_run_runtime(_MiniCtx(None), {}) == (False, '')
    # auto + SPA 页面类型(out) → 运行
    run, why = should_run_runtime(_MiniCtx('auto'), {'page_types': {'/': 'SPA'}})
    assert run is True and 'SPA' in why
    # auto + 前端框架指纹(ctx) → 运行
    run, why = should_run_runtime(_MiniCtx('auto', fp_hits=['Vue.js']), {})
    assert run is True and '框架' in why
    # auto + 路由密集(out) → 运行
    _routes = ['/a', '/b', '/c', '/d', '/e']
    run, why = should_run_runtime(_MiniCtx('auto'), {'routes': _routes})
    assert run is True and '路由' in why
    # auto + 非 SPA → 不运行, 且原因非空(旧实现返回 ('', '') 导致报告无法归因)
    run, why = should_run_runtime(_MiniCtx('auto'), {})
    assert run is False and why, 'auto 未触发必须给出原因'


# ---------- 3) AST sidecar 契约(Node+Acorn 强制路径) ----------

@pytest.mark.skipif(not (ast_sidecar._node_bin({}) and ast_sidecar._acorn_dir({})),
                    reason='Node+Acorn 不可用')
def test_ast_sidecar_node_acorn_contract():
    """强制走 Node+Acorn(monkeypatch tree-sitter 为 None), 验证 AST 契约:
    调用点提取 / 变量 baseURL 还原 / 模板串 / 写方法分流 / 形参排除 / 循环保护。"""
    _saved_ts = ast_sidecar._tree_sitter_parser
    ast_sidecar._tree_sitter_parser = lambda: None       # 强制 Node 路径
    try:
        js = (
            "const API = '/api';\n"
            "fetch(API + '/user/list');\n"                       # 变量+拼接 → 可还原
            "axios.get(`${API}/order/detail`);\n"                # 模板串 → 可还原
            "axios.post('/api/order/create');\n"                 # 写方法 → write_apis
            "xhr.open('GET', API + '/config/public');\n"         # xhr.open 第二参是 URL
            "axios.create({baseURL: API, path: '/v1/goods'});\n" # 对象属性还原
            "function helper(P) { fetch(P + '/param-not-resolved'); }\n"  # 形参名不做常量传播
            "var a = b + '/cycle-a';\n"
            "var b = a + '/cycle-b';\n"                          # 循环引用 → seen 保护, 不挂死
        )
        r = ast_sidecar.extract(js, {}, timeout=20)
        assert r is not None, 'Node+Acorn 路径应返回结果'
        # 契约键齐全
        for k in ('apis', 'lits', 'write_apis', 'baseurls', 'routes'):
            assert k in r, f'缺少契约键 {k}'
        # 调用点 + 变量/模板还原
        assert '/api/user/list' in r['apis'], '变量+拼接未还原'
        assert '/api/order/detail' in r['apis'], '模板串未还原'
        # xhr.open 的 URL 在第二参
        assert '/api/config/public' in r['apis'], 'xhr.open URL 未提取'
        # 写方法分流(不进 apis)
        assert r['write_apis'].get('/api/order/create') == 'POST'
        assert '/api/order/create' not in r['apis']
        # baseURL / path 对象属性
        assert '/api' in r['baseurls']
        assert '/v1/goods' in r['routes']
        # 形参排除: P 是形参, `P + '/param-not-resolved'` 不可静态还原
        assert '/param-not-resolved' not in r['apis'], '形参名被误当常量传播'
        # 循环引用不挂死、不产出(返回 None 分支)
        assert '/cycle-a' not in r['apis'] and '/cycle-b' not in r['apis']
    finally:
        ast_sidecar._tree_sitter_parser = _saved_ts
        ast_sidecar._shutdown_node_worker()   # 收尾常驻 Node 进程, 不留孤儿


def test_ast_sidecar_enabled_states():
    """三态开关: 'false'/'no' 恒 False; True → 等于 available()(环境可用即真)。
    环境不可用(node/acorn/tree-sitter 全缺)时 enabled(True) 必须 False(不谎称可用)。"""
    assert ast_sidecar.enabled({'ast_sidecar': 'false'}) is False
    assert ast_sidecar.enabled({'ast_sidecar': 'no'}) is False
    assert ast_sidecar.enabled({}) == ast_sidecar.available({})
    # 模拟环境全不可用: 三个探测函数全部打桩(save/restore, 避免污染后续测试)
    _saved_ts, _saved_nb, _saved_ad = (ast_sidecar._tree_sitter_parser,
                                       ast_sidecar._node_bin, ast_sidecar._acorn_dir)
    ast_sidecar._tree_sitter_parser = lambda: None
    ast_sidecar._node_bin = lambda cfg: None
    ast_sidecar._acorn_dir = lambda cfg: None
    try:
        assert ast_sidecar.available({}) is False
        assert ast_sidecar.enabled({'ast_sidecar': True}) is False, \
            '环境不可用时 enabled(True) 不得谎称可用'
        assert ast_sidecar.enabled({'ast_sidecar': 'auto'}) is False
    finally:
        ast_sidecar._tree_sitter_parser = _saved_ts
        ast_sidecar._node_bin = _saved_nb
        ast_sidecar._acorn_dir = _saved_ad


@pytest.mark.skipif(ast_sidecar._tree_sitter_parser() is None,
                    reason='tree-sitter 不可用')
def test_ast_sidecar_tree_sitter_contract():
    """tree-sitter 引擎(默认优先路径)的调用点/写方法契约。"""
    js = ("fetch('/api/ts-ok');\n"
          "axios.post('/api/ts-write');\n")
    r = ast_sidecar.extract(js, {}, timeout=20)
    assert r is not None
    assert '/api/ts-ok' in r['apis']
    assert r['write_apis'].get('/api/ts-write') == 'POST'
    assert '/api/ts-write' not in r['apis']


def test_ast_sidecar_short_code():
    """过短代码直接返回 None(门控: <16 字符)。"""
    assert ast_sidecar.extract('fetch("/x")', {}, timeout=20) is None


# ---------- 4) deep_analyze 门控 / 写方法分流 / 归一化去重 ----------

class _AnaCtx:
    def __init__(self):
        self.config = {}
        self.findings = []

    def add_finding(self, *a, **k):
        self.findings.append((a, k))

    def note_truncated(self, *a, **k):
        pass

    def link_param(self, *a, **k):
        pass


def test_deep_analyze_gates_and_splits():
    """① RE_BASEURL 门控: 关时 baseURL 不提取, 开时变量 baseURL 可还原(P0-1 正则兜底);
    ② 写方法分流: axios.post 进 write_apis(POST), 同时保留在 apis 供 GET 可达性验证
    (合规: 写操作只提取不发送, 探活用只读 GET —— 与 probe() 口径一致);
    ③ 归一化去重: `/api/user/{id}` 字面量与结构化通道归一为同一 key(`:id`), 不双份。"""
    ctx = _AnaCtx()
    js = (
        "const API = '/api';\n"
        "axios.create({baseURL: API});\n"
        "axios.post('/api/order/create', {data: {}});\n"
        "axios.get('/api/user/{id}');\n"
        "axios.get('/api/user/{id}');\n"
    )
    # ① 门控关闭 → 无 baseurls
    out_off = deep_analyze(ctx, js, 't.js', 'http://h:8081', set())
    assert not out_off['baseurls'], 'RE_BASEURL 关闭时不应提取 baseURL'
    # ① 门控开启 → 变量 baseURL 还原
    out_on = deep_analyze(ctx, js, 't.js', 'http://h:8081', {'RE_BASEURL', 'RE_API'})
    assert '/api' in out_on['baseurls'], '变量 baseURL 未还原(P0-1 正则兜底)'
    # ② 写方法分流(方法声明) + 保留可达性验证路径
    assert out_on['write_apis'].get('/api/order/create') == 'POST'
    assert '/api/order/create' in out_on['apis'], '写路径应保留在 apis 供只读可达性验证'
    # ③ 归一化: {id} → :id, 且重复声明只一份
    assert '/api/user/:id' in out_on['apis']
    assert '/api/user/{id}' not in out_on['apis']
    assert sum(1 for a in out_on['apis'] if 'user' in a) == 1, '同路径重复入集'


# ---------- 5) probe 排序行为(monkeypatch 请求层, 零发包) ----------

class _FakeResp:
    def __init__(self, status=200, text=''):
        self.status_code = status
        self.text = text
        self.headers = {'Content-Type': 'application/json'}


class _ProbeCtx:
    """覆盖 probe() 用到的全部 ctx 面; 请求层由测试 monkeypatch 掉。"""

    def __init__(self, evidence=None):
        self.pmap = {}
        self.evidence = evidence or {}
        self.config = {}
        self.rtt_samples = []
        self.mined_paths = set()
        self.write_apis = {}
        self.findings = []
        self.all_found = []
        self.truncated = {}
        self.invalid = set()

    def budget_left(self):
        return 600.0

    def is_invalid(self, p):
        return p in self.invalid

    def mark_invalid(self, p):
        self.invalid.add(p)

    def note_truncated(self, key, n):
        self.truncated[key] = self.truncated.get(key, 0) + n

    def add_all_found(self, p, m, st, note):
        self.all_found.append((p, m, st, note))

    def add_finding(self, *a, **k):
        self.findings.append((a, k))

    def link_param(self, p, pn):
        pass


def test_probe_sort_evidence_and_priority():
    """探活排序: ① 管理面(安全面分)先于普通业务; ② 同分时**证据档**优先
    (runtime=3 > dict=0) —— 预算截断时先保已验证端点。全程零发包(请求层打桩)。"""
    probed = []

    def fake_req(ctx, url, method='GET', headers=None, no_session=False, **kw):
        probed.append(url)
        return _FakeResp(200, '')

    _saved = probe_mod._probe_req
    probe_mod._probe_req = fake_req
    try:
        ctx = _ProbeCtx(evidence={
            '/api/runtime-hit': 3,   # 浏览器真实观测
            '/api/dict-last': 0,     # 字典猜测
        })
        apis = ['/api/runtime-hit', '/api/dict-last', '/admin/panel', '/api/plain/business']
        probe_mod.probe(ctx, 'http://h:8081', apis)
    finally:
        probe_mod._probe_req = _saved

    paths = [u.replace('http://h:8081', '') for u in probed]
    # ① 管理面最先
    assert paths[0] == '/admin/panel', f'管理面未排最前: {paths}'
    # ② 其余三条(均为普通业务面, 安全面分相同)按证据档降序:
    #    runtime=3 > static 默认=1 > dict=0 —— 字典猜测永远排在有据端点之后。
    rest = paths[1:]
    assert rest == ['/api/runtime-hit', '/api/plain/business', '/api/dict-last'], \
        f'证据档排序不符: {rest}'
    # 每条端点都被登记(all_found), 响应挖掘无脏数据(空体)
    assert len(ctx.all_found) == 4
    assert not ctx.mined_paths


def test_probe_truncation_is_disclosed():
    """max_probe 截断: 丢弃数**如实登记**(note_truncated), 不静默丢弃低优先级路径。"""
    _saved = probe_mod._probe_req
    probe_mod._probe_req = lambda ctx, url, **kw: _FakeResp(200, '')
    try:
        ctx = _ProbeCtx()
        ctx.config = {'max_probe': 2}
        probe_mod.probe(ctx, 'http://h:8081',
                        ['/admin/panel', '/api/a', '/api/b', '/api/c', '/api/d'])
    finally:
        probe_mod._probe_req = _saved
    assert ctx.truncated.get('probe', 0) == 3, f'截断未登记: {ctx.truncated}'
    assert len(ctx.all_found) == 2, '截断后仍探了全部'


# ---------- 6) 端点侧车 JSON: kind / kind_summary ----------

@pytest.fixture()
def workdir():
    """测试工作目录: 项目 output/ 下临时目录(沙箱限制系统 TMPDIR), 结束自动清理。
    output/ 在全新检出中不存在(gitignore), 故先显式创建(兼容 CI)。"""
    out_dir = os.path.join(_REPO, 'output')
    os.makedirs(out_dir, exist_ok=True)
    d = tempfile.mkdtemp(prefix='unit_', dir=out_dir)
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_write_endpoints_json_kind_summary(workdir):
    """write_endpoints_json: 逐端点 kind + kind_summary 汇总计数(供 CI 直接筛真实接口)。"""
    meta = {
        'apis': {'/api/admin/user/list', '/admin/report', '/accedi'},
        'recomb': set(),
        'write_apis': {'/auth/login': 'POST'},
        'routes': {'/admin/report'},
        'api_srcline': {'/api/admin/user/list': ('a.js', 12, 3)},
        'api_extractor': {},
        'api_conf': {},
        'evidence': {'/api/admin/user/list': 'full-url'},
    }
    out = os.path.join(workdir, 'ep.json')
    write_endpoints_json(_ProbeCtx(), 'http://h:8081', meta, out)
    payload = json.load(open(out, encoding='utf-8'))
    assert payload['schema'] == 'facet-endpoints/v1'
    assert payload['kind_summary'] == {'backend_api': 2, 'frontend_route': 1, 'unknown': 1}, \
        payload['kind_summary']
    by_ep = {e['endpoint']: e for e in payload['endpoints']}
    assert by_ep['/api/admin/user/list']['kind'] == 'backend_api'
    assert by_ep['/api/admin/user/list']['source_location']['line'] == 12
    assert by_ep['/api/admin/user/list']['evidence'] == 'full-url'
    assert by_ep['/admin/report']['kind'] == 'frontend_route'   # 命中 routes
    assert by_ep['/accedi']['kind'] == 'unknown'               # i18n 页面猜测
    assert by_ep['/auth/login']['kind'] == 'backend_api'       # 写方法声明


# ---------- 7) Node 环境探测(移机通用性): 动态发现, 不钉机器路径 ----------
#
# 背景(移机安装验证发现的真实缺陷): node / acorn / webcrack 定位历史上写死开发机
# 路径(钉版本号的 `~/.workbuddy-ai/.../22.22.2-3` 等)—— 换台机器整段失效、还把
# 开发者家目录带进发布物(钉的版本在本机都已不存在, 纯死代码)。现统一委托
# `core.nodeenv` 单一真源。本节守护其**通用性**: env 优先 + cwd 标准解析 +
# managed 布局动态扫描, 任何机器无需配置即可发现 PATH/managed/cwd 里的 Node 生态。

def test_node_modules_dirs_cwd_walk(workdir):
    """node_modules 候选含当前工作目录及父目录的标准 Node 解析(移机后无需配置即可发现)。"""
    import facet.core.nodeenv as nodeenv
    nm = os.path.join(workdir, 'node_modules')
    os.makedirs(os.path.join(nm, 'ss_fake_pkg_test'), exist_ok=True)
    _saved_cwd = os.getcwd()
    try:
        os.chdir(workdir)
        dirs = nodeenv.node_modules_dirs()
        assert nm in dirs, f'cwd 的 node_modules 未入候选: {dirs[:5]}'
        # 包发现: 唯一包名避开真实安装(managed workspace 内 acorn 等), 只认 cwd 链上的
        assert nodeenv.find_module_dir('ss_fake_pkg_test') == os.path.join(nm, 'ss_fake_pkg_test')
    finally:
        os.chdir(_saved_cwd)


def test_node_modules_dirs_env_precedence():
    """FACET_NODE_MODULES 最优先, 且宽容「目录本身/父目录」两种约定。"""
    import facet.core.nodeenv as nodeenv
    _saved = os.environ.get('FACET_NODE_MODULES')
    try:
        os.environ['FACET_NODE_MODULES'] = '/opt/custom/node_modules'
        dirs = nodeenv.node_modules_dirs()
        assert dirs[0] == '/opt/custom/node_modules', \
            f'环境变量 node_modules 未排最前: {dirs[:3]}'
        assert '/opt/custom/node_modules/node_modules' in dirs, '父目录约定未入候选'
    finally:
        if _saved is None:
            os.environ.pop('FACET_NODE_MODULES', None)
        else:
            os.environ['FACET_NODE_MODULES'] = _saved


def test_find_node_explicit_over_path(workdir):
    """find_node: 配置键 ast_node_bin / 环境变量 FACET_NODE_BIN 优先于 PATH/managed。"""
    import facet.core.nodeenv as nodeenv
    fake_bin = os.path.join(workdir, 'node')
    with open(fake_bin, 'w', encoding='utf-8') as f:
        f.write('#!/bin/sh\n')
    assert nodeenv.find_node({'ast_node_bin': fake_bin}) == fake_bin, '配置键未优先'
    _saved = os.environ.get('FACET_NODE_BIN')
    try:
        os.environ['FACET_NODE_BIN'] = fake_bin
        assert nodeenv.find_node() == fake_bin, '环境变量未优先于 PATH'
        assert nodeenv.find_node({}) == fake_bin
    finally:
        if _saved is None:
            os.environ.pop('FACET_NODE_BIN', None)
        else:
            os.environ['FACET_NODE_BIN'] = _saved


def test_task_default_output_dir_never_in_install_dir():
    """MCP 任务默认输出目录绝不落进包安装目录(pip 移机安装的硬约束)。

    双形态不变量: 源码检出(包同级有 pyproject.toml)→ 基准=仓库根 output/gui;
    pip 安装(包在 site-packages, 无 pyproject.toml)→ 基准=当前工作目录。
    """
    import pathlib
    import facet
    from facet.core import task_service
    pkg_parent = pathlib.Path(facet.__file__).resolve().parent.parent
    d = task_service._default_output_dir()
    if (pkg_parent / 'pyproject.toml').is_file():
        assert d == pkg_parent / 'output' / 'gui', f'源码检出下基准目录错误: {d}'
    else:
        assert pkg_parent not in d.parents, f'默认输出目录落进安装目录: {d}'
        assert d.name == 'gui' and d.parent.name == 'output', f'基准结构错误: {d}'


def test_should_save_state_gating():
    """断点续扫状态落盘门控: --persist-state 必须触发落盘(回归钉子)。

    缺陷背景: 保存条件此前只含 `--resume` / seen 撞 max_js —— 小站(seen 远小于
    max_js)只传 `--persist-state` 时状态文件**永不生成**, 随后 `--resume`
    "按空状态开始"却无任何提示(假成功), 与 _get_state_store/DEFAULT_CONFIG
    三处 "resume / persist_state 才落盘" 的声明不一致。
    """
    from facet.core.orchestrator import _should_save_state
    # 默认(无开关、未撞上限): 不落盘 —— "默认扫描目录只剩 HTML + JSON"
    assert not _should_save_state({}, 1, 200)
    # --persist-state 显式开启: 落盘(修复核心, 此前恒 False)
    assert _should_save_state({'persist_state': True}, 1, 200)
    assert _should_save_state({'persist_state': True}, 0, 200)
    # --resume: 落盘
    assert _should_save_state({'resume': True}, 0, 200)
    # 撞 max_js 上限: 落盘(无开关也记, 供后续 --resume 续扫)
    assert _should_save_state({}, 200, 200)
    assert _should_save_state({}, 201, 200)
    # max_js=0(不限): 保持旧语义(seen>=0 恒真)
    assert _should_save_state({}, 0, 0)


def test_settle_response_501_not_failure():
    """熔断失败分类: 501(方法未实现)是**成功的否定回答**, 不计失败(回归钉子)。

    缺陷背景: 实测 scope fixture(未实现 do_POST/do_OPTIONS)上, 扫描器自己的
    探测方法触发 8 个 501(3× POST graphql + 5× OPTIONS), `_settle_response`
    把 5xx 全计入熔断失败 → 连续 5 个 OPTIONS 501 → 熔断 OPEN → 60 个后续
    请求被跳过, 53 条隐藏字典探测整段丢失。覆盖损失由探测设计自身造成,
    与目标健康无关(目标对 GET 一直 200/404)。
    """
    from facet.core.http import _settle_response

    class _Resp:
        def __init__(self, st):
            self.status_code = st

    class _RM:
        def adapt(self, *a, **kw):
            pass

    class _Ctx:
        def __init__(self):
            self.fails = 0
            self.resets = 0
            self.config = {}
            self.rm = _RM()

        def record_fail(self):
            self.fails += 1

        def reset_fail(self):
            self.resets += 1

    ctx = _Ctx()
    _settle_response(ctx, _Resp(501))
    assert ctx.fails == 0 and ctx.resets == 1, '501 必须视为成功否定回答(不计失败)'
    ctx2 = _Ctx()
    for _ in range(5):
        _settle_response(ctx2, _Resp(501))
    assert ctx2.fails == 0, '连续 501 不得累积失败计数(熔断器不得因此 OPEN)'
    ctx3 = _Ctx()
    _settle_response(ctx3, _Resp(500))
    assert ctx3.fails == 1, '500 仍计入失败(目标侧故障语义不变)'
    ctx4 = _Ctx()
    _settle_response(ctx4, _Resp(429))
    assert ctx4.fails == 1, '429 仍计入失败(目标限流, "明确放弃"远好于静默爬行)'
    ctx5 = _Ctx()
    _settle_response(ctx5, _Resp(200))
    assert ctx5.resets == 1 and ctx5.fails == 0


def test_file_state_store_creates_parent_dir():
    """FileStateStore.save: 父目录不存在时必须预建(回归钉子)。

    缺陷背景: 状态文件默认落在 output/ 下; "0 JS 落盘 + --persist-state 首扫"
    时该目录尚不存在 → open('w') 抛 FileNotFoundError → 被 except 吞 →
    续扫按空状态开始(假成功)。实测: 审计日志同一 bug 类(已先行修复)。
    """
    import os
    import tempfile
    from facet.core.orchestrator import FileStateStore

    base = tempfile.mkdtemp(prefix='ss_state_')
    try:
        # 刻意指向**尚不存在**的深层子目录
        p = os.path.join(base, 'a', 'b', 'c', '.facet_state.json')
        store = FileStateStore(p)
        store.save('http://x/', 'js', {'u1', 'u2'})
        assert os.path.isfile(p), '父目录未预建导致状态文件静默丢失'
        got = store.load('http://x/', 'js')
        assert got == {'u1', 'u2'}, f'状态往返不一致: {got}'
    finally:
        import shutil
        shutil.rmtree(base, ignore_errors=True)


def test_audit_log_parent_dir_precreated():
    """Context 初始化: audit 开启时审计日志父目录必须预建(回归钉子)。

    缺陷背景: audit_log_path 默认由 default_output_file() 拼接(只拼路径不建
    目录), open('a') 也不建父目录 → 空输出目录下审计写入 FileNotFoundError
    被 except 吞 → "已开启审计"是假成功。实测复现(首跑审计文件根本未生成)。
    """
    import tempfile
    from pathlib import Path

    from facet.core.context import ScanContext

    base = tempfile.mkdtemp(prefix='ss_audit_')
    try:
        audit_path = Path(base) / 'nested' / 'audit.log'
        cfg = {
            'audit_log': True,
            'audit_log_path': str(audit_path),
        }
        ctx = ScanContext(cfg)
        ctx.audit('GET', 'http://127.0.0.1:1/', 'SSRF_BLOCK', 0, 'redirect pivots to private')
        assert audit_path.is_file(), '审计日志父目录未预建, 写入被静默吞掉'
        text = audit_path.read_text(encoding='utf-8')
        assert 'SSRF_BLOCK' in text and 'pivots to private' in text
    finally:
        import shutil
        shutil.rmtree(base, ignore_errors=True)
