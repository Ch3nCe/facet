# -*- coding: utf-8 -*-
"""CI 护栏: 复用 tests/regress/ 下的回归脚本(单一事实来源), 以 pytest 形式跑通。

这样本地 `python -m pytest -q tests/` 与 GitHub Actions 跑的是同一份断言,
避免脚本与测试两份逻辑漂移。脚本自身仍可直接 `python tests/regress/regress_*.py` 运行。

运行方式(仓库内任意位置):
    python -m pytest -q tests/
或:
    make test
"""
import importlib.util
import os

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_OUT = os.path.join(_REPO, 'tests', 'regress')


def _load(name):
    """按文件名从 tests/regress/ 加载回归脚本模块(不依赖包安装位置)."""
    path = os.path.join(_OUT, name + '.py')
    spec = importlib.util.spec_from_file_location('ss_' + name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_probe_method_transparency():
    """P-T 修复: 探活方法透明度(通用/目标无关). 断言 main() 返回 0(全 PASS)."""
    assert _load('regress_probe_method').main() == 0


def test_report_json_probe_method():
    """P-T 修复: probe_method 真实落到 JSON 端点对象. 断言 main() 返回 0(全 PASS)."""
    assert _load('regress_report_json_ep').main() == 0


def test_fetch_concat_method():
    """fetch 写方法提取: 覆盖拼接 URL 形态(fetch(BASE+path,{method})). 断言 main() 返回 0(全 PASS)."""
    assert _load('regress_fetch_concat_method').main() == 0


def test_endpoint_kind_and_replay_base():
    """端点分类(backend_api/frontend_route/unknown) + replay.sh 基址取 origin. 断言 main() 返回 0(全 PASS)."""
    assert _load('regress_endpoint_kind').main() == 0


def test_report_endpoint_copy_button():
    """报告 HTML 端点主表的"一键复制全部接口/仅复制后端接口"按钮. 断言 main() 返回 0(全 PASS)."""
    assert _load('regress_endpoint_copy').main() == 0


def test_semantic_sourcemap_scheduling():
    """P0-1 语义解析 + P2 sourcemap 收割 + 调度证据分层. 断言 main() 返回 0(全 PASS)."""
    assert _load('regress_semantic_p2_sched').main() == 0
