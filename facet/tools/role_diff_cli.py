# -*- coding: utf-8 -*-
"""角色差分 CLI（Phase B · 缺口④）：匿名 / 用户 / 管理员 三态对比。

能力：
  · `list`     列出历史扫描（按目标过滤），挑出要对比的 scan_id。
  · `diff`     对比两次历史扫描，输出端点 + 发现差集，并解释角色语义
               （如"仅认证可见 → 疑似需鉴权/越权面"）。
  · `rolescan` 对同一目标跑 三次扫描（匿名 / 用户 / 管理员），各自独立存档，
               再自动差分 匿名↔用户、用户↔管理员，定位认证态暴露面差异。

合规：仅对比/扫描**已授权目标**；不主动发包验证越权，只标注"维度差异"供人工复核。
      三态扫描各自独立 ScanContext、独立限速配额，互不串味；只读 GET / 受限内省。

用法：
  python -m facet.tools.role_diff_cli list [--base https://x.com]
  python -m facet.tools.role_diff_cli diff --a ID_A --b ID_B [--role-a anonymous --role-b user]
  python -m facet.tools.role_diff_cli rolescan -u https://x.com \
         [--cookie-user "SESSION=..."] [--cookie-admin "ADMIN=..."] [-o outdir]
"""
import argparse
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from facet.core.history import ScanHistory
from facet.recon.role_diff import compare_scans, format_diff


def _hist():
    return ScanHistory()


def _cmd_list(args):
    h = _hist()
    rows = h.list_scans(args.base)
    if not rows:
        print('（无历史扫描）')
        return
    print('%-40s %-28s %-20s %-6s %s' % ('scan_id', 'base', 'time', 'sent', 'ver'))
    for sid, base, t, sent, ver in rows:
        print('%-40s %-28s %-20s %-6s %s' % (sid[:40], base[:28], t, sent, ver))


def _cmd_diff(args):
    h = _hist()
    if not args.a or not args.b:
        print('[-] 需提供 --a 与 --b（scan_id）；可用 `list` 查看'); sys.exit(2)
    diff = compare_scans(h, args.a, args.b)
    print(format_diff(args.role_a, args.role_b, diff))


def _run_one_role(h, target, role, cookie, token, out_dir):
    """跑一次扫描并存历史，返回该次 scan_id。复用 CLI 的 _scan_one_target。"""
    from facet.apps.cli import _scan_one_target
    from facet.core.config import load_config
    # 用主链**同一配置入口** `load_config`(默认→用户 yaml→环境变量→边界约束), 而非
    #   `dict(DEFAULT_CONFIG)` —— 否则用户的 `FACET_RATE`/`FACET_MAX_RPM` 等合规限速
    #   设置会被 rolescan **静默忽略**(工具与主链口径分叉; 合规相关)。
    cfg = load_config()
    cfg['cookie'] = cookie
    cfg['token'] = token
    cfg['out'] = os.path.join(out_dir, 'role_%s_report.md' % role)
    cfg['debug'] = False
    cfg['html_report'] = True
    cfg['json_report'] = True
    from facet.core.config import expand_modules
    # 须**展开**组名: `_scan_one_target` 的模块门控看的是具体模块名(probe/unauth),
    #   传组名 ['passive','confirm'] 会让 'probe' in mods 恒 False → 一直漏跑 OPTIONS/隐藏路径。
    mods = expand_modules('passive,confirm')      # -> ['recon-deep', 'probe', 'unauth']
    _scan_one_target(cfg, target, mods, False, None)
    # 该角色刚写入的最新一条即本次 scan_id（同 base 时序唯一）
    rows = h.list_scans(target)
    return rows[0][0] if rows else None


def _cmd_rolescan(args):
    h = _hist()
    target = args.url.rstrip('/')
    # 输出目录单一真源(审计 G): 此前按**文件位置**推根 → pip 安装时 _ROOT 是
    #   site-packages, 产物写进安装目录(违反 output/paths.py 的设计红线)。
    try:
        from facet.output.paths import output_dir as _od
        _default_out = str(os.path.join(str(_od()), 'rolescan'))
    except Exception:
        _default_out = os.path.join(_ROOT, 'output', 'rolescan')
    out_dir = args.out or _default_out
    os.makedirs(out_dir, exist_ok=True)
    print('[*] 角色差分扫描目标: %s' % target)
    print('[*] ① 匿名扫描(未提供 cookie/token)…')
    anon_id = _run_one_role(h, target, 'anonymous', None, None, out_dir)
    user_id = None
    admin_id = None
    if args.cookie_user or args.token:
        print('[*] ② 用户扫描(cookie-user/token)…')
        user_id = _run_one_role(h, target, 'user', args.cookie_user, args.token, out_dir)
    if args.cookie_admin:
        print('[*] ③ 管理员扫描(cookie-admin)…')
        admin_id = _run_one_role(h, target, 'admin', args.cookie_admin, None, out_dir)

    if user_id:
        print('\n' + '=' * 56)
        print('匿名 ↔ 用户 差分')
        print('=' * 56)
        print(format_diff('anonymous', 'user', compare_scans(h, anon_id, user_id)))
    if admin_id:
        print('\n' + '=' * 56)
        print('用户 ↔ 管理员 差分')
        print('=' * 56)
        print(format_diff('user', 'admin', compare_scans(h, user_id, admin_id)))
    print('\n[+] 三次扫描报告: %s' % out_dir)


def main():
    p = argparse.ArgumentParser(description='facet 角色差分（匿名/用户/管理员）')
    sub = p.add_subparsers(dest='command')

    pl = sub.add_parser('list', help='列出历史扫描')
    pl.add_argument('--base', default=None, help='按目标(base URL)过滤')

    pd = sub.add_parser('diff', help='对比两次历史扫描')
    pd.add_argument('--a', required=True, help='扫描 A 的 scan_id')
    pd.add_argument('--b', required=True, help='扫描 B 的 scan_id')
    pd.add_argument('--role-a', default='anonymous', help='A 的角色标签')
    pd.add_argument('--role-b', default='user', help='B 的角色标签')

    pr = sub.add_parser('rolescan', help='匿名/用户/管理员三态扫描并差分')
    pr.add_argument('-u', '--url', required=True, help='目标根 URL')
    pr.add_argument('--cookie-user', default=None, help='用户态 Cookie')
    pr.add_argument('--cookie-admin', default=None, help='管理员态 Cookie')
    pr.add_argument('--token', default=None, help='Bearer Token(用户态)')
    pr.add_argument('-o', '--out', default=None, help='输出目录')

    args = p.parse_args()
    if args.command == 'list':
        _cmd_list(args)
    elif args.command == 'diff':
        _cmd_diff(args)
    elif args.command == 'rolescan':
        _cmd_rolescan(args)
    else:
        p.print_help()


if __name__ == '__main__':
    try:
        main()
    except Exception as _e:
        import logging
        logging.getLogger('facet.tools.role_diff_cli').exception('role_diff_cli 异常退出')
        print(f'[-] role_diff_cli 发生错误: {_e}', file=sys.stderr)
        sys.exit(1)
