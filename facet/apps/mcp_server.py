# -*- coding: utf-8 -*-
"""facet MCP 服务（stdio）—— 可编程接口

把「扫描 / 任务管理 / 报告读取」暴露为 **MCP 工具**，便于被 AI 工作流编排。
传输采用 MCP 标准的 stdio（按行分隔的 JSON-RPC 2.0 消息）。

启动::

    python -m facet.apps.mcp_server   # 或安装后的 `facet-mcp` 入口

暴露的工具：
  · `scan`        对单个目标发起扫描任务（异步），返回 task_id（需 authorized=true）
  · `list_tasks`  列出全部任务
  · `get_task`    查询单个任务快照（含状态/日志/报告路径）
  · `stop_task`   停止任务
  · `get_report`  读取某次扫描的 HTML 报告内容（按 task_id 或 report_path）

合规：`scan` 必须显式传 `authorized=true`，否则拒绝（与 CLI 同一红线）。
本模块零外部依赖，仅标准库；复用 `core.task_service.TaskManager`（不复制扫描逻辑）。
"""
import json
import os
import sys

# 支持 `python facet/mcp_server.py` 直接运行（与 `python -m facet.mcp_server` 兼容）
if __name__ == "__main__" and __package__ is None:
    __package__ = "facet.apps"
    _pkg = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if _pkg not in sys.path:
        sys.path.insert(0, _pkg)

from .. import __version__
from ..core.log import dbg as _dbg
from ..core.task_service import VALUE_OPTIONS, TaskManager, TaskNotFound
from ..output.paths import output_dir as _output_dir_fn

PROTOCOL_VERSION = '2024-11-05'

# 各身份参数的说明(options schema 由 `VALUE_OPTIONS` 生成, 说明表只是文案补充)
_OPTION_DESC = {
    'cookie': 'Cookie 头(需登录目标), 例: SESSIONID=...',
    'token': 'Bearer Token(认证接口用)',
}


def _options_schema():
    """由 `VALUE_OPTIONS` **生成** options schema —— 单一真源, 结构上防止漂移。

    🔴 修复背景: 旧 schema 硬编码宣称支持 `modules/rate/threads/max_rpm`, 而
    `TaskManager._build_options` 只认 `cookie/token` → 调用方(AI 工作流)以为参数生效,
    实际被**静默丢弃**。现 schema 直接由白名单生成 + `additionalProperties: false`,
    且 `_build_options` 对未知键报错 —— 声明与能力不可能再不一致。
    """
    return {
        'type': 'object',
        'description': '可选身份参数(仅 %s；其余调参请走 ~/.facet/config.yaml；'
                       '传入未支持的键会报错，不会静默忽略)' % ' / '.join(sorted(VALUE_OPTIONS)),
        'properties': {k: {'type': 'string', 'description': _OPTION_DESC.get(k, '')}
                       for k in sorted(VALUE_OPTIONS)},
        'additionalProperties': False,
    }


TOOLS = [
    {
        'name': 'scan',
        'description': '对单个目标发起 facet 扫描任务(异步)。需 authorized=true 确认目标已授权。',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string', 'description': '目标根 URL，如 https://example.com'},
                'authorized': {'type': 'boolean', 'description': '确认目标属于自有资产或已获授权范围'},
                'options': _options_schema(),
            },
            'required': ['target', 'authorized'],
        },
    },
    {
        'name': 'list_tasks',
        'description': '列出全部扫描任务(简要)',
        'inputSchema': {'type': 'object', 'properties': {}},
    },
    {
        'name': 'get_task',
        'description': '查询单个任务快照(状态/日志/报告路径)',
        'inputSchema': {'type': 'object', 'properties': {'task_id': {'type': 'string'}},
                        'required': ['task_id']},
    },
    {
        'name': 'stop_task',
        'description': '停止指定任务',
        'inputSchema': {'type': 'object', 'properties': {'task_id': {'type': 'string'}},
                        'required': ['task_id']},
    },
    {
        'name': 'get_report',
        'description': '读取某次扫描的报告内容(HTML, 按 task_id 或 report_path 取)',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'task_id': {'type': 'string', 'description': '任务 ID（与 report_path 二选一）'},
                'report_path': {'type': 'string',
                                'description': '报告文件路径(须在 facet 输出目录内)'},
                'max_chars': {'type': 'integer', 'description': '最大返回字符数，默认 200000'},
            },
        },
    },
]


def _ok(mid, result):
    return {'jsonrpc': '2.0', 'id': mid, 'result': result}


def _err(mid, code, message):
    return {'jsonrpc': '2.0', 'id': mid, 'error': {'code': code, 'message': message}}


def call_tool(name, args, manager):
    """执行工具并返回可 JSON 化的结果；非法参数抛 ValueError。"""
    args = args or {}
    if name == 'scan':
        target = args.get('target')
        if not target:
            raise ValueError('缺少 target')
        if not args.get('authorized'):
            raise ValueError('必须 authorized=true 确认目标已授权')
        return manager.start(target, args.get('options'), True)
    if name == 'list_tasks':
        return manager.list()
    if name == 'get_task':
        tid = args.get('task_id')
        if not tid:
            raise ValueError('缺少 task_id')
        return manager.get(tid).snapshot()
    if name == 'stop_task':
        tid = args.get('task_id')
        if not tid:
            raise ValueError('缺少 task_id')
        return manager.stop(tid)
    if name == 'get_report':
        return _tool_get_report(args, manager)
    raise ValueError('未知工具: %s' % name)


def _tool_get_report(args, manager):
    path = args.get('report_path')
    if not path and args.get('task_id'):
        # 未知 task_id → 抛 TaskNotFound(入口层回结构化 NotFound); **不得**静默吞掉再报
        #   "缺少 task_id 或 report_path" —— 那是**误导**: 参数给了, 是 id 不存在(实测缺陷)。
        path = manager.get(args['task_id']).snapshot().get('report_path')
    if not path:
        raise ValueError('缺少 task_id 或 report_path')
    # **路径护栏(输入校验)**: 本工具语义是"读**本工具产出的报告**", 只允许读 **facet
    #   输出目录** 内的文件 —— 否则 `report_path` 会变成**任意文件读取**入口: 被扫描内容
    #   注入诱导的调用方可传 `/etc/passwd` / `~/.ssh/id_rsa` 让服务端读出并回传。
    #   用 `realpath` 解析符号链接后再判前缀, 防"输出目录内软链指向外部"的逃逸。
    from ..output.paths import output_dir as _output_dir
    _root = os.path.realpath(str(_output_dir()))
    _rp = os.path.realpath(str(path))
    if not (_rp == _root or _rp.startswith(_root + os.sep)):
        raise ValueError('报告路径必须在 facet 输出目录内: %s' % _root)
    if not os.path.isfile(path):
        raise ValueError('报告文件不存在: %s' % path)
    # max_chars 校验(审计 G): 负数此前走 `text[:-n]` 静默截掉尾部, 字符串类型抛
    #   TypeError。现在: 非整数/负数一律显式报错。
    max_chars = args.get('max_chars')
    if max_chars is None:
        max_chars = 200000
    try:
        max_chars = int(max_chars)
    except (TypeError, ValueError):
        return json.dumps({'error': 'max_chars 必须是非负整数'},
                          ensure_ascii=False)
    if max_chars < 0:
        return json.dumps({'error': 'max_chars 必须是非负整数'},
                          ensure_ascii=False)
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()
    truncated = len(text) > max_chars
    if truncated:
        text = text[:max_chars] + '\n…[已截断，共 %d 字符]' % len(text)
    return {'report_path': path, 'truncated': truncated, 'content': text}


def handle_message(msg, manager):
    """处理单条 JSON-RPC 消息；通知类返回 None（不回包）"""
    if not isinstance(msg, dict):
        return _err(None, -32600, 'invalid request')
    mid = msg.get('id')
    method = msg.get('method')
    if method == 'initialize':
        return _ok(mid, {'protocolVersion': PROTOCOL_VERSION,
                         'capabilities': {'tools': {}},
                         'serverInfo': {'name': 'facet', 'version': __version__}})
    if method in ('notifications/initialized', 'initialized', 'notifications/cancelled'):
        return None
    if method == 'tools/list':
        return _ok(mid, {'tools': TOOLS})
    if method == 'tools/call':
        params = msg.get('params') or {}
        try:
            result = call_tool(params.get('name'), params.get('arguments') or {}, manager)
        except TaskNotFound as e:
            # **结构化 NotFound**: 与"内部错误"区分开 —— 调用方可据 error code 判定是
            #   "id 打错了/已被修剪"还是"服务出错了"(旧实现两者同为不可分辨的 isError 文本)。
            return _ok(mid, {'content': [{'type': 'text', 'text': json.dumps(
                {'error': 'task_not_found', 'task_id': e.task_id,
                 'message': '任务不存在(从未提交, 或已完成并被回收)'},
                ensure_ascii=False)}], 'isError': True})
        except Exception as e:
            return _ok(mid, {'content': [{'type': 'text', 'text': str(e)}], 'isError': True})
        return _ok(mid, {'content': [{'type': 'text',
                                      'text': json.dumps(result, ensure_ascii=False)}],
                         'isError': False})
    return _err(mid, -32601, 'method not found: %s' % method)


def main():
    # 输出目录与 `_tool_get_report` 的路径护栏**同源**(output.paths.output_dir, 感知
    #   FACET_OUTPUT_DIR) —— 此前 TaskManager 写死 PROJECT_ROOT/output/gui,
    #   一旦设置该环境变量, 任务报告落在护栏之外, get_report(task_id) 必被拒(审计 M13)。
    manager = TaskManager(output_dir=_output_dir_fn('gui'))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            json.loads(line)
        except Exception as e:
            # 畸形 JSON 行此前静默跳过 —— stdio 协议下调用方无从得知消息未被处理(审计 L)
            _dbg(f'跳过无法解析的 JSON-RPC 行({len(line)} 字节): {e}')
        try:
            msg = json.loads(line)
        except Exception:
            continue
        resp = handle_message(msg, manager)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + '\n')
            sys.stdout.flush()


if __name__ == '__main__':
    main()
