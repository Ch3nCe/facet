# -*- coding: utf-8 -*-
"""扫描历史库（**基础设施层**）—— 原从 `core/engine.py` 下沉（该门面已删除）。

动机（架构一致性）：`recon/asset_lib.py`、`report/report.py` 需要 `ScanHistory`，若从
编排层（原 `core/engine.py`）导入即为**向上依赖**。下沉后各层向下引用。
"""
from .. import __version__
from ..output.paths import output_dir as _output_dir


class ScanHistory:
    """SQLite 历史库: 支持 diff 两个扫描"""
    def __init__(self, path=None):
        self.path = path or str(_output_dir() / 'facet_history.db')
        self._init()

    def _init(self):
        import sqlite3
        with sqlite3.connect(self.path) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY, base TEXT, time TEXT,
                total_sent INTEGER, version TEXT)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS findings (
                scan_id TEXT, severity TEXT, type TEXT, url TEXT, evidence TEXT)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS apis (
                scan_id TEXT, path TEXT, method TEXT, status INTEGER, note TEXT)''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_apis_scan ON apis(scan_id)')
            conn.execute('''CREATE TABLE IF NOT EXISTS discovery (
                scan_id TEXT, path TEXT)''')
            # 索引建在**表创建之后**(顺序敏感: 先建索引会 "no such table")
            conn.execute('CREATE INDEX IF NOT EXISTS idx_discovery_scan ON discovery(scan_id)')

    def save_scan(self, scan_id, base, ctx):
        import sqlite3
        import time as _time

        # 不再脱敏: 历史库落盘**原样**保存(本工具已移除全部脱敏)。
        with sqlite3.connect(self.path) as conn:
            conn.execute('INSERT OR REPLACE INTO scans VALUES (?, ?, ?, ?, ?)',
                        (scan_id, base, _time.strftime('%Y-%m-%d %H:%M:%S'),
                         ctx.total_sent, __version__))
            conn.execute('DELETE FROM findings WHERE scan_id=?', (scan_id,))
            conn.execute('DELETE FROM apis WHERE scan_id=?', (scan_id,))
            for sev, typ, url, ev in ctx.findings:
                conn.execute('INSERT INTO findings VALUES (?, ?, ?, ?, ?)',
                            (scan_id, sev, typ, url, ev))
            for p, m, st, note in ctx.all_found:
                conn.execute('INSERT INTO apis VALUES (?, ?, ?, ?, ?)',
                            (scan_id, p, m, st, note))
            # 全量发现集（角色差分对比用，含全部提取端点；路径级，不带方法）
            for p in (getattr(ctx, 'discovery', None) or set()):
                if p:
                    conn.execute('INSERT INTO discovery VALUES (?, ?)', (scan_id, p))

    def diff(self, scan_a, scan_b):
        import sqlite3
        with sqlite3.connect(self.path) as conn:
            # A有B没有的路径
            cur = conn.execute('''
                SELECT path, method FROM apis WHERE scan_id=?
                EXCEPT SELECT path, method FROM apis WHERE scan_id=?
            ''', (scan_a, scan_b))
            only_a = cur.fetchall()
            # B有A没有
            cur = conn.execute('''
                SELECT path, method FROM apis WHERE scan_id=?
                EXCEPT SELECT path, method FROM apis WHERE scan_id=?
            ''', (scan_b, scan_a))
            only_b = cur.fetchall()
            return {'only_in_a': only_a, 'only_in_b': only_b}

    def list_scans(self, base=None):
        """列出历史扫描（按时间倒序）；可选按 base 过滤。"""
        import sqlite3
        with sqlite3.connect(self.path) as conn:
            if base:
                cur = conn.execute(
                    'SELECT scan_id, base, time, total_sent, version FROM scans '
                    'WHERE base=? ORDER BY time DESC', (base,))
            else:
                cur = conn.execute(
                    'SELECT scan_id, base, time, total_sent, version FROM scans '
                    'ORDER BY time DESC')
            return cur.fetchall()


    def get_findings(self, scan_id):
        import sqlite3
        with sqlite3.connect(self.path) as conn:
            return conn.execute(
                'SELECT severity, type, url, evidence FROM findings WHERE scan_id=?',
                (scan_id,)).fetchall()

    def get_discovery(self, scan_id):
        """该次扫描的**全量发现集**（discovery 表, 路径级）。"""
        import sqlite3
        with sqlite3.connect(self.path) as conn:
            return [r[0] for r in conn.execute(
                'SELECT path FROM discovery WHERE scan_id=?', (scan_id,))]

    def diff_full(self, scan_a, scan_b):
        """角色差分增强版：对比**全量发现集**(discovery 表, 路径级) + 发现(finding)差集。

        返回结构化结果，便于 CLI / 报告解释「仅匿名可见 / 仅认证可见」等语义。
        """
        import sqlite3
        with sqlite3.connect(self.path) as conn:
            def _disc(sid):
                return set(r[0] for r in conn.execute(
                    'SELECT path FROM discovery WHERE scan_id=?', (sid,)))
            def _findings(sid):
                return set((sev, typ, url) for sev, typ, url in conn.execute(
                    'SELECT severity, type, url FROM findings WHERE scan_id=?', (sid,)))
            a_disc, b_disc = _disc(scan_a), _disc(scan_b)
            a_f, b_f = _findings(scan_a), _findings(scan_b)
        return {
            'only_in_a_apis': sorted(a_disc - b_disc),
            'only_in_b_apis': sorted(b_disc - a_disc),
            'common_apis': sorted(a_disc & b_disc),
            'only_in_a_findings': sorted(a_f - b_f),
            'only_in_b_findings': sorted(b_f - a_f),
        }
