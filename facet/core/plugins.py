# -*- coding: utf-8 -*-
"""插件注册表（方案 9.1）—— Collector / Parser / Prober / Enricher 可插拔。

设计目标（方案原文）: "新增来源只写一个插件, 不改主流程"。

用法:
    from . import plugins
    plugins.register('collector', 'infer', config_key='path_infer', desc='路径推断')
    ...
    if plugins.enabled('collector', 'infer', ctx.config):
        ...

约定:
  · `enabled(stage, name, cfg)`: 由**配置开关**决定; 插件未声明 config_key 时用 `default`。
    三态值('auto')由插件自带 `available` 回调判断(如 AST sidecar 看 node+acorn 是否可用)。
  · (历史) `run(...)` 统一派发引擎已于 v1.0.8 作为死代码移除 —— 现行范式是
    "编排层先 `enabled()` 裁决、再直调能力函数"(见 CONTRIBUTING.md「设计约定」形态 A)。
  · `list_plugins(cfg)`: 供报告/文档列出"本次实际启用的插件", 便于解释"为什么探/没探某些面"。
  · 老流程**可逐步迁移** —— 未迁移的仍走原代码, 缺省行为完全不变。
"""
import threading

# stage → {name: {config_key, default, desc, fn, available}}
_REGISTRY = {}
_LOCK = threading.Lock()

STAGES = ('collector', 'parser', 'prober', 'enricher')


def register(stage, name, fn=None, config_key=None, default=True, desc='', available=None):
    """注册一个插件。`config_key` 为空时用 `default` 决定是否启用。"""
    stage = str(stage).strip().lower()
    if stage not in STAGES:
        raise ValueError(f'未知 stage: {stage}(应为 {STAGES})')
    with _LOCK:
        _REGISTRY.setdefault(stage, {})[str(name)] = {
            'fn': fn, 'config_key': config_key, 'default': bool(default),
            'desc': desc or '', 'available': available,
        }
    return name


def _meta(stage, name):
    return (_REGISTRY.get(str(stage).strip().lower()) or {}).get(str(name))


def enabled(stage, name, cfg=None):
    """该插件在给定配置下是否启用(未注册 → False; 注册但未声明开关 → default)。"""
    m = _meta(stage, name)
    if not m:
        return False
    if m.get('available') is not None:
        try:
            if not m['available'](cfg or {}):
                return False
        except Exception as e:
            # available 回调崩溃 → 插件被静默禁用且 list_plugins 只显示"未启用",
            # 不披露原因 —— 留痕(审计 L)。
            from .log import dbg
            dbg(f'插件 {stage}.{name} available 回调异常(视为未启用): {e}')
            return False
    ck = m.get('config_key')
    if not ck:
        return bool(m.get('default'))
    v = (cfg or {}).get(ck, m.get('default'))
    if isinstance(v, str):
        v = v.strip().lower()
        if v == 'auto':
            return bool(m.get('default'))
        return v in ('1', 'true', 'yes', 'on')
    return bool(v)


def list_plugins(cfg=None, stage=None):
    """列出插件及其启用状态(供报告/文档)。"""
    res = []
    stages = [str(stage).strip().lower()] if stage else list(STAGES)
    for st in stages:
        for name, m in sorted((_REGISTRY.get(st) or {}).items()):
            res.append({'stage': st, 'name': name, 'desc': m.get('desc') or '',
                        'config_key': m.get('config_key') or '',
                        'enabled': enabled(st, name, cfg)})
    return res


def register_builtins():
    """注册内置插件清单(与各实现处一一对应; 迁移一处即在此登记一处)。"""
    _ast_avail = None
    try:
        from . import ast_sidecar
        _ast_avail = ast_sidecar.available
    except Exception as e:
        from .log import dbg
        dbg(f'ast_sidecar 导入失败(AST 插件不可用): {e}')
    # Collector(采集层): 来源渠道
    #   注: 隐藏路径字典(通用 + 栈门控 + 扩展层)不走插件注册 —— 它在 `hidden_probe`
    #       (prober.unauth 门控) 内由 `dicts.get_hidden_paths` 统一装配; 扩展层开关
    #       `hidden_paths_extended` 由 `hidden_probe` 直接读取(三态→布尔), 不经
    #       `enabled('collector','dict')`。历史上曾注册 `collector.dict` 且错绑
    #       `config_key='hidden_paths_extended'`, 既无调用点(plugins.run 已移除)又误导
    #       "字典受 EXTENDED 门控"(实际 COMMON 恒跑、仅 EXTENDED 层 opt-in) → 已删。
    register('collector', 'schema', config_key='schema_probe', desc='OpenAPI/Swagger/GraphQL schema 源')
    register('collector', 'infer', config_key='path_infer', desc='路径推断(动词族/单复数/扩展名/批量↔单品)')
    register('collector', 'mine', config_key='resp_mine', desc='响应体/响应头 URL 挖掘 + 闭环回灌')
    register('collector', 'runtime', config_key='runtime', default=True, desc='运行时通道(Playwright)')
    register('collector', 'jsdir', config_key='js_dir_fuzz', default=True,
             desc='JS 目录爆破(发现未被页面引用但存在的隐藏 JS)')
    # Parser(解析层)
    register('parser', 'deobf', config_key=None, default=True, desc='字符串数组解包(_0x 去混淆)')
    register('parser', 'ast', config_key='ast_sidecar', default=True, available=_ast_avail,
             desc='JS AST 提取(Python tree-sitter 优先; Node+Acorn 常驻进程回退)')
    # Prober(探测层)
    register('prober', 'probe', config_key=None, default=True, desc='端点探活(只读)')
    register('prober', 'options', config_key='options_probe', desc='OPTIONS/Allow 方法发现')
    register('prober', 'unauth', config_key='unauth_probe', default=True,
             desc='未授权访问确认 + 隐藏路径字典(只读)')
    # Enricher(增强层)
    register('enricher', 'sca', config_key='sca', desc='前端组件与已知漏洞(SCA)')


register_builtins()
