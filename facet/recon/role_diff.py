# -*- coding: utf-8 -*-
"""角色差分（anonymous / user / admin 三次扫描对比）。

动机（Phase B · 缺口④）：同一目标在**不同认证态**下暴露的端点/发现不同——
匿名可见、登录后可见、仅管理员可见，这三者的差集直接指向：
- **仅认证后可见**的端点 → 强制浏览 / 越权访问( IDOR / 未授权 API )面，需人工复核；
- **仅匿名可见**的端点 → 通常无害(登录页/公开资源)，但若是"管理接口匿名可达"则高危；
- **发现(finding)差集** → 登录后才暴露的敏感信息/配置泄露。

实现：复用 `ScanHistory`（SQLite 历史库）保存每次扫描的端点与发现；本模块只做**对比与解释**，
不发起任何新请求（纯只读分析）。三次扫描本身由 CLI `rolescan` 调度（各自独立 ScanContext）。

合规：仅对比用户**已授权目标**的历史扫描；不主动发包、不验证越权，只标注"维度差异"供人工复核。
"""
from __future__ import annotations

AUTH_ROLES = ('anonymous', 'user', 'admin')


def compare_scans(history, a_id, b_id):
    """对比两次历史扫描，返回结构化差集（端点 + 发现）。

    直接复用 `ScanHistory.diff_full`；这是唯一与存储耦合的点，便于替换为内存/JSON 后端。
    """
    return history.diff_full(a_id, b_id)


def format_diff(a_role, b_role, diff):
    """把差集渲染为可读文本（含角色语义解释）。

    a_role / b_role ∈ AUTH_ROLES 或任意自定义标签（如 'anon' / 'user' / 'admin'）。
    """
    a_role = a_role or 'A'
    b_role = b_role or 'B'
    lines = []
    lines.append('角色差分（%s vs %s）' % (a_role, b_role))
    lines.append('=' * 48)

    only_b = diff.get('only_in_b_apis') or []
    only_a = diff.get('only_in_a_apis') or []
    common = diff.get('common_apis') or []

    lines.append('两端点共有: %d' % len(common))
    if only_b:
        lines.append('')
        lines.append('▸ 仅 %s 可见的端点（%d）：' % (b_role, len(only_b)))
        if b_role != a_role and _is_more_priv(a_role, b_role):
            lines.append('   （%s 角色更高 → 疑似需鉴权/越权面，人工复核）' % b_role)
        for p in only_b:
            lines.append('   - %s' % p)
    if only_a:
        lines.append('')
        lines.append('▸ 仅 %s 可见的端点（%d）：' % (a_role, len(only_a)))
        lines.append('   （认证后反而消失 → 多为登录页/公开资源；若含管理接口则高危）')
        for p in only_a:
            lines.append('   - %s' % p)

    only_b_f = diff.get('only_in_b_findings') or []
    only_a_f = diff.get('only_in_a_findings') or []
    if only_b_f or only_a_f:
        lines.append('')
        lines.append('发现(finding)差集:')
        for sev, typ, url in only_b_f:
            lines.append('   + %s 新增[%s] %s' % (b_role, sev, typ))
        for sev, typ, url in only_a_f:
            lines.append('   - %s 消失[%s] %s' % (a_role, sev, typ))

    if not (only_a or only_b or only_b_f or only_a_f):
        lines.append('')
        lines.append('（无差异：两次扫描暴露面一致）')
    return '\n'.join(lines)


def _is_more_priv(a, b):
    """粗略判断 b 是否比 a 权限更高（用于解释差集语义）。"""
    try:
        return AUTH_ROLES.index(b) > AUTH_ROLES.index(a)
    except ValueError:
        return False
