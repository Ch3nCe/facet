# -*- coding: utf-8 -*-
"""性能基准（只读）—— 固定口径跑一次扫描, 打印各阶段耗时/占比 + 发包数。

用法:
    python -m facet.tools.perf_baseline -u https://example.com
    python -m facet.tools.perf_baseline -u https://example.com --rate 0.5

> 会**真实访问目标**(只读 GET), 请自行确认网络与授权环境。它不改任何扫描行为,
> 只是把 `config.profile=True` 的阶段计时以**稳定、可对比**的方式打出来, 供 A/B 优化对照。

结论备忘(2026-09-29 实测 vuejs.org): 探活占 ~53% —— 耗时 ≈ 探活数 × `rate`(合规限速)。
**并发/异步不能突破统一限速**(RateManager 对每次请求起点强制间隔), 故提速只能靠
调 `rate`/`max_probe` 或减少候选数, 而非改并发。
"""
import argparse
import os
import sys

if __name__ == '__main__' and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from facet.core.config import expand_modules, load_config
from facet.core.context import ScanContext
from facet.core.orchestrator import recon_deep  # 调度层已拆至 orchestrator
from facet.core.rate import RateManager


def _to_tristate(v):
    if isinstance(v, bool):
        return v
    s = str(v or '').strip().lower()
    if s == 'auto':
        return 'auto'
    return s in ('1', 'true', 'yes', 'on')


def main(argv=None):
    ap = argparse.ArgumentParser(description='facet 性能基准(只读阶段计时)')
    ap.add_argument('-u', '--url', required=True, help='目标根 URL')
    ap.add_argument('--rate', type=float, default=None, help='覆盖请求间隔(秒)')
    ap.add_argument('--max-rpm', type=int, default=None, help='覆盖每分钟硬顶')
    args = ap.parse_args(argv)

    # 用主链**同一配置入口** `load_config`(尊重 FACET_*/用户 yaml/边界约束) —— 与 CLI 口径一致;
    #   下列显式覆盖(--runtime/--rate/--max-rpm + profile/out)仍优先。
    cfg = load_config()
    # 输出路径单一真源(审计 G): 此前硬编码 /tmp(绕过 FACET_OUTPUT_DIR,
    #   多用户机器还可预测路径互相覆盖)。
    try:
        from facet.output.paths import output_dir as _od
        _perf_out = os.path.join(str(_od()), 'facet_perf')
    except Exception:
        _perf_out = os.path.join(os.path.expanduser('~'), 'facet_perf')
    cfg.update({'profile': True, 'out': _perf_out})
    cfg['runtime'] = _to_tristate('auto')
    if args.rate is not None:
        cfg['rate'] = args.rate
    if args.max_rpm is not None:
        cfg['max_rpm'] = args.max_rpm

    ctx = ScanContext(cfg)
    ctx.rm = RateManager(cfg.get('rate', 0.5), cfg.get('max_rpm', 120),
                         adapt=cfg.get('adapt_rate', True))
    mods = expand_modules('passive,confirm')
    # 与主链 `_scan_one_target` 同款装配(审计 OBS): 此前绕过 CLI 直接 recon_deep,
    #   硬墙钟看门狗与"scope 缺省=目标同源"的护栏默认都没装上。
    from facet.core.scope import ScopeMatcher
    from facet.core.watchdog import cancel_scan_watchdog, install_scan_watchdog
    ctx.scope = ScopeMatcher([])          # 空 = 未声明 → 保守按目标同源
    wd = install_scan_watchdog(cfg.get('max_duration') or 0)
    try:
        meta = recon_deep(ctx, args.url, mods)
    finally:
        cancel_scan_watchdog(wd)

    stages = getattr(ctx, 'stage_times', None) or {}
    total = getattr(ctx, 'stage_total', 0.0) or 0.0
    print('\n================ 性能基准(只读) ================')
    print(f'目标: {args.url} | 模块: {mods} | runtime={cfg["runtime"]} | rate={cfg.get("rate")}')
    print(f'逻辑发包: {ctx.total_sent} | 实际网络请求: {getattr(ctx, "net_sent", 0)}')
    print(f'提取端点: {len(meta.get("apis", set()))} | 发现项: {len(ctx.findings)}')
    print('-' * 48)
    if stages:
        for name, d in sorted(stages.items(), key=lambda kv: -kv[1]):
            pct = (d / total * 100) if total else 0
            print(f'  {d:7.2f}s ({pct:5.1f}%)  {name}')
        print('-' * 48)
        print(f'  合计 {total:.2f}s')
    else:
        print('  (未采集到阶段计时 —— 确认 config.profile=True 生效)')
    print('================================================\n')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        print('[-] 性能基准失败: %s' % e)
        sys.exit(1)
