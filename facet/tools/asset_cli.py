# -*- coding: utf-8 -*-
"""跨目标资产库 CLI（独立于主扫描 CLI 暴露面，符合"高级能力藏后台"）。

用法:
    python -m facet.tools.asset_cli targets
    python -m facet.tools.asset_cli endpoints --grep /api
    python -m facet.tools.asset_cli findings --sev HIGH
    python -m facet.tools.asset_cli shared --min 2

所有子命令**只读本地历史库**（`--db` 可指定路径），不发任何网络请求。
"""
import argparse
import os
import sys

if __name__ == '__main__' and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from facet.recon import asset_lib


def _print_table(rows, cols, headers):
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(cols):
            widths[i] = max(widths[i], len(str(r.get(c, ''))))
    print('  '.join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    print('  '.join('-' * w for w in widths))
    for r in rows:
        print('  '.join(str(r.get(c, '')).ljust(widths[i]) for i, c in enumerate(cols)))


def main():
    ap = argparse.ArgumentParser(prog='facet-asset',
                                 description='跨目标资产库检索（只读本地历史，零网络请求）')
    ap.add_argument('--db', default=None, help='历史库路径（默认 facet output/facet_history.db）')
    sub = ap.add_subparsers(dest='cmd', required=True)

    sub.add_parser('targets', help='列出所有扫描过的目标摘要')

    pe = sub.add_parser('endpoints', help='跨目标检索端点')
    pe.add_argument('--base', default=None, help='按目标精确过滤')
    pe.add_argument('--grep', default=None, help='路径子串(大小写不敏感)')
    pe.add_argument('--limit', type=int, default=500)

    pf = sub.add_parser('findings', help='跨目标检索发现')
    pf.add_argument('--base', default=None)
    pf.add_argument('--sev', default=None, help='严重度: CRITICAL/HIGH/MED/LOW/INFO')
    pf.add_argument('--grep', default=None, help='匹配 type/url/evidence')
    pf.add_argument('--limit', type=int, default=500)

    ps = sub.add_parser('shared', help='跨目标重复出现的问题类型')
    ps.add_argument('--min', dest='min_targets', type=int, default=2)
    ps.add_argument('--limit', type=int, default=100)

    args = ap.parse_args()

    if args.cmd == 'targets':
        rows = asset_lib.list_targets(args.db)
        if not rows:
            print('(历史库为空)')
            return 0
        _print_table(rows, ['base', 'scans', 'last_scan', 'findings', 'endpoints'],
                     ['目标', '扫描次数', '最近扫描', '发现', '端点(全集)'])

    elif args.cmd == 'endpoints':
        rows = asset_lib.search_endpoints(args.db, base=args.base,
                                          grep=args.grep, limit=args.limit)
        if not rows:
            print('(无匹配)')
            return 0
        _print_table(rows, ['base', 'path'], ['目标', '端点'])

    elif args.cmd == 'findings':
        rows = asset_lib.search_findings(args.db, base=args.base, sev=args.sev,
                                         grep=args.grep, limit=args.limit)
        if not rows:
            print('(无匹配)')
            return 0
        _print_table(rows, ['base', 'severity', 'type', 'url'],
                     ['目标', '严重度', '类型', 'URL'])

    elif args.cmd == 'shared':
        rows = asset_lib.shared_findings(args.db, min_targets=args.min_targets,
                                         limit=args.limit)
        if not rows:
            print(f'(无出现于 ≥{args.min_targets} 个目标的共性问题)')
            return 0
        for r in rows:
            print(f"[{r['count']}] {r['type']}  <-  {', '.join(r['targets'])}")
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as _e:
        import logging
        logging.getLogger('facet.tools.asset_cli').exception('asset_cli 异常退出')
        print(f'[-] asset_cli 发生错误: {_e}', file=sys.stderr)
        sys.exit(1)
