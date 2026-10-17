# -*- coding: utf-8 -*-
"""facet Suite 命令行入口 - 全量重构版"""
import argparse
import os
import sys
import time

# 支持 `python cli.py` 直接运行(不再仅限 `python -m facet.cli`)
if __name__ == '__main__' and __package__ is None:
    __package__ = 'facet.apps'
    _cli_dir = os.path.dirname(os.path.abspath(__file__))
    _pkg_dir = os.path.dirname(os.path.dirname(_cli_dir))
    if _pkg_dir not in sys.path:
        sys.path.insert(0, _pkg_dir)

from facet import __version__
from facet import core as C

# 编排层符号直接从子模块导入, 不经由 core 门面(recon_deep 属编排层; BROTLI 属数据层 const)
from facet.core.const import BROTLI
from facet.core.orchestrator import (
    _dynamic_deobf_should_run,
    _encoding_on,
    _strong_on,
    recon_deep,  # 调度层已拆至 orchestrator
)
from facet.core.watchdog import (
    ScanGlobalTimeout,
    cancel_scan_watchdog,
    install_scan_watchdog,
)
from facet.report import (
    report_html,
    report_json,
    write_diff_json,
    write_endpoints_json,
    write_exports,
    write_recon_matrix,
    write_recovered_json,
    write_replay_sh,
)
from facet.recon.ast import write_ast_sidecar  # R7: AST 结构化侧车(tree-sitter; 可选依赖)

# Claude Code 风格的极简 banner: 干净字标 + 版本 + 标语 + 作者。
#   (合规条款已在 EPILOG 与 README 完整呈现, 不在 banner 重复, 保持启动清爽)
_BANNER_TAGLINE = '合规优先的 Web 攻击面侦察套件 · 发现级 · 只读 · 合规'
_BANNER_AUTHOR = '作者: 迷麟Aurora'


def build_banner():
    """构建 banner

    改为函数 —— 使 no_color 能在打印前生效(此前 banner 在 import 时即固化配色;
    no_color 由 ~/.facet/config.yaml 的 no_color 键控制)。
    """
    rule = '─' * 46
    return (
        f"\n"
        f"{C.Color.BOLD}{C.Color.CYAN}◆ facet{C.Color.RESET} "
        f"{C.Color.GREY}v{__version__}{C.Color.RESET}\n"
        f"{C.Color.GREY}{_BANNER_TAGLINE}{C.Color.RESET}\n"
        f"{C.Color.GREY}{_BANNER_AUTHOR}{C.Color.RESET}\n"
        f"{C.Color.GREY}{rule}{C.Color.RESET}\n"
    )

def apply_no_color():
    """关闭彩色输出: 把 Color 类的所有属性置空

    由 ~/.facet/config.yaml 的 no_color: true 触发(CI / 日志重定向场景)
    """
    for attr in dir(C.Color):
        if attr.isupper():
            setattr(C.Color, attr, '')

EPILOG = """
使用规则(合规条款):
  1. 授权范围  仅限SRC in-scope/自有资产/书面授权目标; 启动需交互确认(--yes跳过, 责任自负)
  2. 速率      默认0.5s+120发/分钟硬顶, 同步与异步路径共用同一配额; 连续5次5xx/超时自动熔断
  3. 只读红线  删除/修改类接口(DELETE/PUT/PATCH)只做提取, 不发任何验证包;
                写操作接口在报告中以"只提取"标注 — 绝不动业务数据;
                heapdump/threaddump 类大体积端点仅探测可达性, 不下载响应体
  4. 保护目标  连续5次5xx/超时熔断退出
  5. 结果处理  [疑似]必须人工复核; PII提交前脱敏; 不留存泄露数据
  6. UA 头  扫描/探测默认使用常规浏览器 UA(规避 WAF 对 python-requests 等默认特征的拦截, 与真实流量同口径);
             需要自我标识或复现特定 UA 时, 用 ua / waf_probe_ua 配置显式指定(CLI 不暴露)
  7. 动态解包(可选)  默认关闭。它会**在本地密封离线沙箱里运行目标JS**以展开 VM/字节码混淆
                (L3 密封vm / L4 抗篡改+安全执行 / L5 真实浏览器, 无则降级)。沙箱内 fetch/XHR/
                WebSocket 等网络原语只记录不发送, 绝不向目标或第三方发包。
                仅限自有/已授权资产+隔离环境开启; 报告会明示"已在密封沙箱展开、未向目标发包"。
                启用: 配置 dynamic_deobf: true|auto 或环境变量 FACET_DYNAMIC_DEOBF=true|auto(可选 dynamic_deobf_tier:3|4|5); auto=仅对 VM/字节码打包自动启用
  8. 扫描动静  字典类探活(通用隐藏路径 / JS 目录)默认做**只读 GET 枚举** —— 属"发现级"但
                **非纯被动**; 默认紧凑词表, 扩展层需显式 opt-in; 命中仅登记"存在/需登录",
                不大体积下载、不发写请求

调参(限速/并发/扩展侦察/规则库/代理/调试/动态解包等)不在 CLI 暴露, 默认值已合规安全:
  · 配置文件  ~/.facet/config.yaml  (YAML 1.2 语义: 键名请加引号, 如 "yes": true)
  · 环境变量  FACET_RATE=0.5, FACET_THREADS=8, FACET_MAX_JS=80, FACET_DYNAMIC_DEOBF=true 等
  配置分层(优先级): CLI显式参数 > 环境变量 > ~/.facet/config.yaml > 内置默认值
"""

def build_parser():
    """构建命令行参数（精简版 1.18.0）。

    只保留**正常侦察所必需的选项**；其余调参一律下沉到 `~/.facet/config.yaml`
    或环境变量 `FACET_*`（分级见 config.DEFAULT_CONFIG），CLI 表面只暴露必要项。

    正常用法:
        facet -u https://目标 --yes                            # 最简扫描
        facet -u https://目标 --cookie "SESSIONID=xxx" --yes    # 需登录
        facet -f targets.txt --yes                             # 批量
    调参（限速 / 并发 / 扩展侦察 / 规则库 / 代理 / 调试等）不在 CLI 暴露——
    默认值已合规安全（限速 0.5s/120rpm、并发 8、重试 1、5xx 熔断、尊重 Retry-After）。
    """
    p = argparse.ArgumentParser(
        description=f'facet v{__version__} — 合规Web侦察套件'
                    f'\n最小用法: facet -u https://目标 --yes   （需登录再加 --cookie "SESSIONID=xxx"）',
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument('--version', action='version', version=f'facet v{__version__}')
    # 必要选项（正常侦察必须 / 高频使用）：
    #   目标(-u/-f)、身份(--cookie/--token)、输出(-o)、授权(--yes)。
    #   其余速率 / 并发 / 扩展侦察 / 规则库 / 代理 / 调试等全部下沉到
    #   ~/.facet/config.yaml 或 FACET_* 环境变量，不在 CLI 暴露。
    p.add_argument('-u', '--url', help='目标根URL (如 https://example.com); 与 -f 至少提供一个')
    p.add_argument('-f', '--file', help='批量目标文件 (每行一个URL, 逐个扫描)')
    p.add_argument('--cookie', default=None,
                   help='全局 Cookie（如 "SESSIONID=xxx"）—— 扫描需登录的目标时必填')
    p.add_argument('--token', default=None,
                   help='Bearer Token（用于需认证接口的探活/未授权确认）')
    p.add_argument('-o', '--out', default=None,
                   help='输出报告路径 (默认 <输出目录>/facet_report.html —— 主文件 HTML + JSON; '
                        '输出目录=源码根或当前目录下的 output/, 可用 FACET_OUTPUT_DIR 指定)')
    p.add_argument('--export', dest='export', default=None,
                   help='标准格式导出(逗号分隔): sarif,burp,zap —— 在报告同目录生成 .sarif/.burp.xml/.zap.json')
    p.add_argument('--sidecars', action='store_true', default=None,
                   help='额外写出机器可读侧车(端点标注/业务分层/端点清单/增量diff/复现脚本/还原); '
                        '默认关闭 —— 仅产 HTML + JSON 两个主文件')
    p.add_argument('--save-history', dest='save_history', action='store_true', default=None,
                   help='将本次扫描写入历史库(facet_history.db), 供跨扫描 diff / 历史记录')
    p.add_argument('--think', dest='think', action='store_true', default=None,
                   help='扫描后额外产出「思考计划」(建议式, 不改主流程): 打印 + 写 <out>.plan.json。'
                        '默认**本地动态推理**(零外部依赖/离线); 配置 llm_base_url+llm_api_key '
                        '后自动切换 LLM 推理(显式 opt-in, 只发聚合信号, 不含凭据/响应体)')
    p.add_argument('--persist-state', dest='persist_state', action='store_true', default=None,
                   help='持久化断点续扫状态文件(默认内存态不落盘); 配合 --resume 使用')
    # 注: 下面两个开关的**底层实现一直在**(config.load_config 读 `config` 属性;
    #   `resume` 是 DEFAULT_CONFIG 里的键), 但 CLI 层此前漏了声明 —— 于是帮助文本承诺的
    #   `--resume` / `--config` 实际不存在(声明与能力不一致)。此处补齐。
    p.add_argument('--resume', dest='resume', action='store_true', default=None,
                   help='从上次 --persist-state 落盘的状态续扫(未落盘/读不到时按空状态开始)')
    p.add_argument('--config', dest='config', default=None, metavar='PATH',
                   help='指定配置文件路径(默认 ~/.facet/config.yaml)')
    # R4/R5 浏览器交互能力(opt-in; 调参本应下沉配置, 但这两个开关**行为影响面大**,
    #   必须在 CLI 可见并配启动告警 —— 与"调参下沉"不冲突: 它们不是调速/限流参数)。
    p.add_argument('--login-capture', dest='login_capture', action='store_true', default=None,
                   help='R4 登录态采集(opt-in): 打开**可见**浏览器, 手动登录后采集会话'
                        '(cookie 仅内存态, 不落盘), 再以 HTTP 通道续扫')
    p.add_argument('--interactive', dest='interactive', action='store_true', default=None,
                   help='R5 浏览器交互(opt-in): 填表+点击控件发现动态端点; 所有写方法请求'
                        '**被只读护栏拦截**(观测≠发送, 零写流量); 仅限自有/已授权资产')
    p.add_argument('--yes', action='store_true', default=None, help='跳过授权确认 (责任自负)')
    p.add_argument('--scope', action='append', metavar='HOST', default=None,
                   help='声明授权扫描范围(可重复): 域名/子域(*.x.com)/IP/CIDR; '
                        '不传则默认=目标同源(保守边界)')
    # 本地文件反混淆模式（离线只读，不触网）——与"扫 URL"互斥；不是能力开关, 故作为操作选择项。
    p.add_argument('--deobf-file', dest='deobf_file', default=None,
                   help='本地 JS 文件反混淆(离线只读, 不触网, 与 -u/-f 互斥): 静态层默认; '
                        '强/动态层由 config strong_deobf / dynamic_deobf 门控; '
                        '输出 <文件>.deobf.js + <输出>.report.json (用 -o 可指定输出路径)')
    p.add_argument('--deobf-dir', dest='deobf_dir', default=None,
                   help='批量本地反混淆: 目录下所有 *.js 逐个走 --deobf-file 管线')
    return p

# 注: 旧版 `_apply_consolidated` / `_SPEED_PRESETS` / `_PROBE_KEYS` / `_RECON_KEYS`
#   已将 --speed/--budget/--probes/--recon/--proxy/--rules-db 翻译为 config 字段。
#   1.18.0 起这些 CLI 选项已物理移除(下沉到 ~/.facet/config.yaml / FACET_* 环境变量),
#   故翻译层不再需要 —— 直接走 config.DEFAULT_CONFIG 分层即可。

def confirm_authorization():
    print(C.Color.BG_RED + '!!! 合规确认 !!!' + C.Color.RESET)
    print('  1. 目标在SRC授权范围或自有资产?')
    print('  2. 平台允许自动化探测?')
    print('  3. 已阅读合规条款并同意责任自负?')
    ans = input(C.Color.YELLOW + '确认继续? [yes/no]: ' + C.Color.RESET).strip().lower()
    if ans not in ('yes', 'y'):
        print('已取消.')
        sys.exit(0)

def _scan_one_target(config, target, mods, multi, shared_rm=None):
    """扫描单个目标并产出报告（供串行循环与批量并发共用）

    抽出为独立函数 —— 批量并发（`-f` + `--batch-concurrency`）时由线程池调用，
    并传入**共享的** RateManager（全局配额）；串行时 shared_rm=None，各自新建。
    """
    from ..core.context import ScanContext
    from ..core.rate import RateManager
    print(f'\n{C.Color.CYAN}[*] 扫描目标: {target}{C.Color.RESET}')
    # 模块预设 → config 键: "哪些阶段跑"**统一由 `plugins.enabled` 裁决**(单一调度来源),
    #   `mods` 只作输入。消除"mods 门控一半、plugins.enabled 门控一半"的双机制。
    #   · probe  模块 → options_probe(OPTIONS/Allow 方法发现)
    #   · unauth 模块 → unauth_probe(未授权确认 + 隐藏路径字典)
    #   端点探活(probe())是**必做项**, 不受模块门控(见 recon_deep)。
    config = dict(config)                                   # 不污染调用方(多目标共享)
    # **懒人式默认**: `modules='auto'`(默认) → **不按模块裁剪**; options_probe/unauth_probe 保持
    #   `'auto'`, 由编排层 `resolve_dispatch` 按**目标信号**定值(替代"用参数调度模块")。
    #   `-m` 为**高级覆盖**: 仅当用户**显式**指定(非 'auto')时才按模块裁剪, 尊重其选择。
    _mods_explicit = str(config.get('modules', 'auto')).strip().lower() != 'auto'
    if _mods_explicit:
        config['options_probe'] = bool(config.get('options_probe', True)) and ('probe' in mods)
        config['unauth_probe'] = bool(config.get('unauth_probe', True)) and ('unauth' in mods)
    # 每个目标使用**独立的 ScanContext**。
    tctx = ScanContext(config)
    # 声明范围(in-scope)护栏装配: 显式 --scope 用规则构建; 否则回退为"目标同源"(保守默认)。
    #   默认同源 = 旧版"仅同源"行为, 但现在**硬拒**越界(而非靠不生成), 合规更稳。
    from ..core.scope import build_scope
    tctx.scope_rules = list(config.get('scope') or [])
    tctx.scope = build_scope(tctx.scope_rules, default_base=target)
    # 扫描范围声明(审计 D6): 明确本次覆盖边界, 避免使用者误以为"全资产已覆盖"。
    if tctx.scope_rules:
        print(f'{C.Color.CYAN}[*] 授权范围: 显式声明 {tctx.scope_rules}（范围外主机一律硬拒）{C.Color.RESET}')
    else:
        print(f'{C.Color.CYAN}[*] 授权范围: 默认**同源**（仅 {target} 所在主机/子域）—— '
              f'同组织其它主机未纳入; 需扩大请显式 --scope{C.Color.RESET}')
    tctx.authorized = bool(config.get('authorized'))
    tctx.auth_method = str(config.get('auth_method') or '')
    tctx.rm = shared_rm or RateManager(config.get('rate', 0.5), config.get('max_rpm', 120),
                                       adapt=config.get('adapt_rate', True))
    # 硬墙钟看门狗: 任何阶段卡死(连接半关 / 子进程 / CPU 自旋)都会被 SIGALRM 中止,
    # 保证扫描绝不会无限挂起(默认 1800s, 可由 max_duration 调整; 0=关闭看门狗)。
    wd = install_scan_watchdog(config.get('max_duration') or 0)
    if wd is None and (config.get('max_duration') or 0) > 0:
        # 不可用只有两种原因: 非主线程(批量并发的 worker)/ 非 POSIX(Windows)。
        #   此前**静默** → 用户以为有硬墙钟, max_duration 形同虚设(全库审计 M12)。
        import threading as _threading
        _why = ('非主线程(批量并发 worker)' if _threading.current_thread() is not _threading.main_thread() else '当前平台不支持 SIGALRM')
        print(f'{C.Color.YELLOW}[i] 看门狗不可用({_why}): max_duration 本次不生效, '
              f'其余护栏(请求预算/熔断)仍有效{C.Color.RESET}')
    meta = {}
    try:
        try:
            meta = recon_deep(tctx, target, mods, config.get('token'))
        except ScanGlobalTimeout:
            # **立刻取消看门狗** —— handler 会重新武装(见 `watchdog._handler`)，不取消的话
            #   报告生成阶段会被再次中断(且此时异常无人捕获 → 栈回溯退出)。
            cancel_scan_watchdog(wd)
            wd = None
            # 导出**已收集的部分结果**(`recon_deep` 把 `out` 挂在 `ctx._partial_out` 上) ——
            #   旧实现写死 `meta = {}`, 日志说"导出已完成的部分报告"却导出空报告(实测 js_files: 0)。
            meta = getattr(tctx, '_partial_out', None) or {}
            try:
                meta.setdefault('truncated', {})['global_timeout'] = 1
                tctx.note_truncated('global_timeout', 1)
            except Exception:
                pass
            print(f'{C.Color.BG_YELLOW}[!] 超过全局时间预算, 中止并导出已完成的部分报告'
                  f'(已收集 {len(meta.get("apis") or ())} 个接口候选 / '
                  f'{len(meta.get("js_files") or ())} 个 JS){C.Color.RESET}')
        except Exception as e:
            if config.get('debug'):
                import traceback
                traceback.print_exc()
            print(f'{C.Color.RED}[-] 扫描失败: {e}{C.Color.RESET}')
            meta = {}
        # 生成报告（仅 HTML —— 本工具报告输出统一为单文件 HTML Dashboard）
        out_path = config['out']
        if multi:
            # 用 splitext 拆后缀 —— 旧实现 `out_path.replace('.md', ...)`
            #   在 --out 不是 .md 结尾时不替换(多目标互相覆盖), 也会误改目录名里的 .md
            from urllib.parse import urlparse
            host = urlparse(target).netloc.replace(':', '_') or 'target'
            stem, ext = os.path.splitext(out_path)
            out_path = f'{stem}_{host}{ext or ".html"}'
        # HTML 报告（单文件总览，全部人读章节与页内跳转合并其中；JSON / recon_matrix /
        #   业务分层规则 / 标准导出仍各自输出为机器可读文件）。
        if config.get('html_report', True):
            html_path = os.path.splitext(out_path)[0] + '.html'
            try:
                report_html(tctx, target, html_path, meta, tctx.findings)
            except Exception as e:
                print(f'{C.Color.YELLOW}[-] HTML 报告生成失败: {e}{C.Color.RESET}')
                if config.get('debug'):
                    import traceback
                    traceback.print_exc()
        # ---- 侧车输出(默认关闭, 仅 --sidecars 开启) ----
        # 机器可读侧车(recon_matrix / biz_rules / endpoints / diff+基线 / replay.sh / recovered)
        #   默认不写, 避免默认扫描在目录里塞一堆"机器消费用"文件; 真正需要 CI / 流水线 / 跨扫描
        #   消费时再显式开启。报告本体始终是**两个主文件**: HTML(人读) + JSON(机器读)。
        if config.get('sidecars'):
            # R7 AST 侧车(tree-sitter 结构化 JS 摘要; 纯本地解析, 不发包)。
            if config.get('ast_sidecar', True):
                try:
                    ast_path = os.path.splitext(out_path)[0] + '.ast.json'
                    n_ast = write_ast_sidecar(tctx, meta, ast_path)
                    if n_ast:
                        print(f'{C.Color.GREEN}[+] AST 结构化侧车: {ast_path} ({n_ast} 个 JS 源){C.Color.RESET}')
                    else:
                        print(f'{C.Color.CYAN}[*] AST 侧车: 本次无可解析 JS 源(未生成文件){C.Color.RESET}')
                except Exception as e:
                    print(f'{C.Color.YELLOW}[-] AST 侧车生成失败: {e}{C.Color.RESET}')
                    if config.get('debug'):
                        import traceback
                        traceback.print_exc()
            # 端点标注 JSON 侧车（与报告同源, 供 Web/CLI 独立加载, 无需重跑扫描）
            try:
                am_path = os.path.splitext(out_path)[0] + '.recon_matrix.json'
                write_recon_matrix(tctx, meta, am_path)
            except Exception as e:
                print(f'{C.Color.YELLOW}[-] 端点标注生成失败: {e}{C.Color.RESET}')
                if config.get('debug'):
                    import traceback
                    traceback.print_exc()
            # 注: 「业务分层规则」侧车(biz_rules)已随业务模块整体移除(用户要求)。
        # 机器可读 JSON 报告（finding 级结构化导出, 供流水线消费）—— 主文件之一, 默认产出
        if config.get('json_report', True):
            try:
                json_path = os.path.splitext(out_path)[0] + '.json'
                report_json(tctx, target, json_path, meta)
            except Exception as e:
                print(f'{C.Color.YELLOW}[-] JSON 报告生成失败: {e}{C.Color.RESET}')
                if config.get('debug'):
                    import traceback
                    traceback.print_exc()
        # ---- 思考层(规划器, opt-in --think) ----
        #   建议式: 从本次扫描的**机器可读 JSON 报告**动态提取聚合信号 + 从插件注册表动态取
        #   能力清单, 产出"下一步只读计划"。**不驱动主流程、不改判定、不再发包**。
        #   默认本地动态推理; 配置了 LLM 端点则切换(显式 opt-in, 失败自动降级)。
        if config.get('think'):
            try:
                import json as _json

                from ..core import think as _think
                _plan_src = os.path.splitext(out_path)[0] + '.json'
                _rep = {}
                if os.path.exists(_plan_src):
                    with open(_plan_src, encoding='utf-8') as _f:
                        _rep = _json.load(_f)
                _plan = _think.plan(_rep, config)
                print(_think.render_plan_text(_plan))
                _plan_path = os.path.splitext(out_path)[0] + '.plan.json'
                with open(_plan_path, 'w', encoding='utf-8') as _f:
                    _json.dump(_plan, _f, ensure_ascii=False, indent=2)
                print(f'{C.Color.CYAN}[+] 思考计划: {_plan_path}{C.Color.RESET}')
            except Exception as e:
                print(f'{C.Color.YELLOW}[-] 思考计划生成失败: {e}{C.Color.RESET}')
                if config.get('debug'):
                    import traceback
                    traceback.print_exc()
        if config.get('sidecars'):
            # 独立端点侧车(方案 §10): 与报告同源, 单独成文件便于 CI / 流水线消费
            try:
                ep_path = os.path.splitext(out_path)[0] + '.endpoints.json'
                write_endpoints_json(tctx, target, meta, ep_path)
            except Exception as e:
                print(f'{C.Color.YELLOW}[-] 端点侧车生成失败: {e}{C.Color.RESET}')
                if config.get('debug'):
                    import traceback
                    traceback.print_exc()
            # 动态解包还原产物侧车(还原即产出): 仅当本次确有还原时写文件
            try:
                rc_path = os.path.splitext(out_path)[0] + '.recovered.json'
                _n_rec = write_recovered_json(tctx, target, meta, rc_path)
                if _n_rec:
                    print(f'{C.Color.GREEN}[+] 动态解包还原侧车: {rc_path} ({_n_rec} 个源){C.Color.RESET}')
            except Exception as e:
                print(f'{C.Color.YELLOW}[-] 还原侧车生成失败: {e}{C.Color.RESET}')
                if config.get('debug'):
                    import traceback
                    traceback.print_exc()
            # 增量 diff(方案 §2.6): 与上次基线比对, 新增/消失端点供 CI 门禁(同时写 endpoints_baseline.json)
            try:
                write_diff_json(tctx, target, meta, out_path)
            except Exception as e:
                print(f'{C.Color.YELLOW}[-] 增量 diff 生成失败: {e}{C.Color.RESET}')
                if config.get('debug'):
                    import traceback
                    traceback.print_exc()
            # 只读复现脚本(方案 §8 三件套之一): 每条端点一行 curl, 只读方法 + 鉴权占位符
            try:
                rp_path = os.path.splitext(out_path)[0] + '.replay.sh'
                _n_rp = write_replay_sh(tctx, target, meta, rp_path)
                print(f'{C.Color.GREEN}[+] 复现脚本: {rp_path} ({_n_rp} 条端点 · 只读){C.Color.RESET}')
            except Exception as e:
                print(f'{C.Color.YELLOW}[-] 复现脚本生成失败: {e}{C.Color.RESET}')
                if config.get('debug'):
                    import traceback
                    traceback.print_exc()
        else:
            print(f'{C.Color.CYAN}[*] 默认仅产出 HTML + JSON 两个主文件; '
                  f'加 --sidecars 可额外导出端点标注/业务分层/端点清单/diff/复现脚本{C.Color.RESET}')
        # 标准格式导出(opt-in): SARIF / Burp Site Map / OWASP ZAP
        _fmts = config.get('export_formats') or []
        if _fmts:
            try:
                written = write_exports(tctx, target, out_path, meta, _fmts)
                for wp in written:
                    print(f'{C.Color.CYAN}[+] 标准导出: {wp}{C.Color.RESET}')
            except Exception as e:
                print(f'{C.Color.YELLOW}[-] 标准导出失败: {e}{C.Color.RESET}')
                if config.get('debug'):
                    import traceback
                    traceback.print_exc()
        # 保存历史(opt-in): 默认不写 history.db; 需跨扫描 diff / 历史记录时 --save-history
        if config.get('save_history'):
            try:
                from urllib.parse import urlparse
                scan_id = f"{urlparse(target).netloc}_{time.strftime('%Y%m%d_%H%M%S')}"
                hist = C.ScanHistory()
                hist.save_scan(scan_id, target, tctx)
                print(f'[+] 历史已保存: scan_id={scan_id}')
            except Exception:
                if config.get('debug'):
                    import traceback
                    traceback.print_exc()
    except Exception as e:
        if config.get('debug'):
            import traceback
            traceback.print_exc()
        print(f'{C.Color.RED}[-] 扫描失败: {e}{C.Color.RESET}')
    finally:
        cancel_scan_watchdog(wd)
        # 资源收尾: Session 是长驻对象, 不能靠进程退出释放。
        #   多目标扫描若每个目标都留着一个连接池, 会积累文件描述符/TLS连接;
        #   单目标 CLI 虽然最终会退出, 但库调用方/批量模式不一定。
        tctx.close_session()
    return tctx

def _run_deobf_file(config, path, out_path=None):
    """本地 JS 文件反混淆（离线只读，绝不触网/不执行网络）。返回退出码。

    管线与扫描内一致: [strong(opt-in)] → [dynamic(opt-in)] →
    decode_layer(beautify) → unpack_string_array → _decode_js_escapes。
    写出 `<out>`（默认 `<file>.deobf.js`）与 `<out>.report.json`。
    合规: 不接触任何目标/网络; 动态解包(若开启)仍在密封离线沙箱内运行。
    """
    import json as _json

    from ..core import deobf as _deobf
    if not os.path.exists(path):
        print(f'{C.Color.RED}[-] 文件不存在: {path}{C.Color.RESET}')
        return 2
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            raw = f.read()
    except Exception as e:
        print(f'{C.Color.RED}[-] 读取失败: {e}{C.Color.RESET}')
        return 2
    text = raw
    report = {'input': os.path.abspath(path), 'input_bytes': len(raw), 'steps': []}
    print(f'{C.Color.CYAN}[*] 本地反混淆: {path} ({len(raw)} 字节, 离线只读){C.Color.RESET}')
    # 强反混淆（opt-in，静态）—— 与编排层共用三态语义(strong_deobf: auto=依赖可用才启用)
    if _strong_on(config):
        s_out, s_rep = _deobf.deobfuscate_strong(text)
        if s_rep.get('ok') and s_out != text:
            text = s_out
            report['steps'].append({'layer': 'strong', 'detected': s_rep.get('detected'),
                                    'methods': s_rep.get('methods'), 'out_bytes': len(s_out)})
            print(f'  [+] 强反混淆: {s_rep.get("detected")}')
    # 动态解包（opt-in，密封离线沙箱）—— 与编排层共用三态语义(dynamic_deobf: auto=仅 VM/字节码包)
    if _dynamic_deobf_should_run(config, text):
        d_out, d_rep = _deobf.deobfuscate_dynamic(text, tier=config.get('dynamic_deobf_tier') or 4)
        report['dynamic'] = {k: d_rep.get(k) for k in
                             ('available', 'ok', 'tier', 'inner_sources', 'errors')}
        if d_rep.get('module_exports'):
            report['dynamic']['module_exports'] = d_rep.get('module_exports')
        if d_rep.get('ok') and d_out != text:
            text = d_out
            report['steps'].append({'layer': 'dynamic', 'tier': d_rep.get('tier'),
                                    'out_bytes': len(d_out)})
            print(f'  [+] 动态解包: tier={d_rep.get("tier")} '
                  f'inner_sources={d_rep.get("inner_sources")}')
    # 简单 JS 编码解码（JSFuck/AAencode/JJencode；密封离线沙箱；与编排层共用三态 js_encoding）
    if _encoding_on(config) and _deobf.looks_like_js_encoding(text):
        e_out, e_rep = _deobf.decode_js_encodings(text)
        if e_rep.get('ok') and e_out != text:
            text = e_out
            report['steps'].append({'layer': 'js_encoding',
                                    'decoded': len(e_rep.get('decoded', []))})
            print(f'  [+] 简单编码解码: 明文 {len(e_rep.get("decoded", []))} 条')
    # 静态层（默认管线）
    text = _deobf.decode_layer(_deobf._beautify_js(text))
    text, n_unpack = _deobf.unpack_string_array(text)
    text = _deobf._decode_js_escapes(text)
    report['static_unpack_hits'] = n_unpack
    report['output_bytes'] = len(text)
    out_path = out_path or (path + '.deobf.js')
    try:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(text)
        with open(out_path + '.report.json', 'w', encoding='utf-8') as f:
            _json.dump(report, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f'{C.Color.RED}[-] 写出失败: {e}{C.Color.RESET}')
        return 1
    print(f'{C.Color.GREEN}[+] 还原输出: {out_path}{C.Color.RESET}')
    print(f'{C.Color.GREEN}[+] 处理报告: {out_path}.report.json{C.Color.RESET}')
    return 0


def main():
    p = build_parser()
    args = p.parse_args()

    # 加载分层配置 (先于 banner, 以便 no_color 生效)
    from ..core.config import load_config
    config = load_config(args)
    if config.get('no_color'):
        apply_no_color()
    # 标准格式导出：CLI --export 覆盖 config（逗号分隔 → 列表）
    if getattr(args, 'export', None):
        config['export_formats'] = [x.strip().lower()
                                    for x in args.export.split(',') if x.strip()]
    print(build_banner())

    # ---- 本地文件反混淆模式（离线只读，不触网；与"扫 URL"互斥） ----
    #   不接触任何目标, 故**不**走授权确认与 -u/-f 必填校验。
    if getattr(args, 'deobf_file', None):
        sys.exit(_run_deobf_file(config, args.deobf_file, getattr(args, 'out', None)))
    if getattr(args, 'deobf_dir', None):
        _d = args.deobf_dir
        if not os.path.isdir(_d):
            print(f'{C.Color.RED}[-] 目录不存在: {_d}{C.Color.RESET}')
            sys.exit(2)
        import glob as _glob
        # 排除本工具自己的产物(*.deobf.js), 否则会把上次输出当输入反复处理。
        _files = sorted(f for f in _glob.glob(os.path.join(_d, '*.js'))
                        if not f.endswith('.deobf.js'))
        if not _files:
            print(f'{C.Color.YELLOW}[!] 目录内无 .js 文件: {_d}{C.Color.RESET}')
            sys.exit(0)
        print(f'{C.Color.CYAN}[*] 批量本地反混淆: {len(_files)} 个 .js{C.Color.RESET}')
        _rc = 0
        for _f in _files:
            _rc |= _run_deobf_file(config, _f, None)
        sys.exit(_rc)

    # -u 与 -f 至少提供一个(旧实现 -u 强制必填, 用 -f 批量时也必须传 -u)
    if not config.get('url') and not config.get('file'):
        print(f'{C.Color.RED}[-] 必须提供 -u <URL> 或 -f <目标文件>{C.Color.RESET}')
        sys.exit(2)

    # URL 方案校验: 仅允许 http/https(拒绝 file:///ftp:///伪协议等)
    if config.get('url'):
        from urllib.parse import urlparse
        _scheme = urlparse(config['url']).scheme
        if _scheme not in ('http', 'https'):
            print(f'{C.Color.RED}[-] 不支持的 URL 方案 "{_scheme or "<空>"}": '
                  f'仅允许 http/https{C.Color.RESET}')
            sys.exit(2)

    # 导出格式启动期校验: 别扫完才报 `--export sraf` 笔误(调用方 write_exports 现在也会拒)
    _fmts = config.get('export_formats') or []
    if _fmts:
        _bad_f = [f for f in _fmts if str(f).strip().lower() not in ('sarif', 'burp', 'zap')]
        if _bad_f:
            print(f'{C.Color.RED}[-] 不支持的导出格式: {", ".join(map(str, _bad_f))}'
                  f'（仅支持 sarif/burp/zap）{C.Color.RESET}')
            sys.exit(2)

    if not config.get('yes'):
        confirm_authorization()
    # 授权确认留痕(合规证据链): 走到这里即已授权(交互确认或 --yes 跳过)。
    config['authorized'] = True
    config['auth_method'] = ('cli-skip (--yes)' if getattr(args, 'yes', None)
                             else 'interactive')
    # 声明范围: 用户显式 --scope 优先; 否则留空(由 _scan_one_target 回退为"目标同源")。
    if getattr(args, 'scope', None):
        config['scope'] = args.scope

    # 目标级 ScanContext 改为在 `_scan_one_target` 内**按目标**创建(串行/并发共用)。
    #   此处仅按需导入 RateManager —— 批量并发时用于构造**共享**的全局限速配额。
    from ..core.rate import RateManager

    # 代理: 由 ~/.facet/config.yaml 的 proxy / use_env_proxy 承载; 默认直连。
    if config.get('proxy'):
        print(f'{C.Color.CYAN}[*] 代理已启用: {config["proxy"]}{C.Color.RESET}')
    elif config.get('use_env_proxy'):
        _env = {k: os.environ[k] for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                                           'http_proxy', 'https_proxy', 'all_proxy')
                if os.environ.get(k)}
        if _env:
            print(f'{C.Color.BG_YELLOW}[!] 已启用环境代理: '
                  f'{", ".join(f"{k}={v}" for k, v in _env.items())}{C.Color.RESET}')
        else:
            print(f'{C.Color.CYAN}[*] use_env_proxy 已启用(配置), 但环境未设置代理变量{C.Color.RESET}')
    else:
        # 默认直连。若环境里确实有代理变量, 明确告知"已被忽略",
        # 避免使用者以为流量走了代理、或反过来困惑为什么没走。
        _env = {k: os.environ[k] for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                                           'http_proxy', 'https_proxy', 'all_proxy')
                if os.environ.get(k)}
        if _env:
            print(f'{C.Color.YELLOW}[*] 已忽略环境代理变量({", ".join(sorted(_env))}): '
                  f'默认直连。如需走代理请在 ~/.facet/config.yaml 设 proxy / use_env_proxy{C.Color.RESET}')
    if not config.get('adapt_rate', True):
        print(f'{C.Color.CYAN}[*] 自适应调速已关闭: 全程恒速 {config["rate"]}s/请求{C.Color.RESET}')
    _rt = config.get('runtime')
    if _rt is True:
        # 只反映"已请求"(配置层面)。真实是否运行取决于 Playwright 是否安装 —— 扫描后由报告
        #   /JSON **如实**披露(ran/reason), 避免此处"已启用"的措辞让人误以为通道一定跑了。
        print(f'{C.Color.CYAN}[*] 运行时通道: 已请求(显式 runtime=true); 真实浏览器捕获(DevTools 等价), '
              f'route 层逐请求节流(统一 rate), 上限 '
              f'{config.get("runtime_max_requests", 300)} 个同域请求; '
              f'是否实际运行取决于 Playwright 是否安装{C.Color.RESET}')
    elif _rt == 'auto':
        print(f'{C.Color.CYAN}[*] 运行时通道: auto —— 目标判定为 SPA 时自动启用'
              f'(真实浏览器捕获, DevTools 等价; 非 SPA 保持关闭){C.Color.RESET}')
    # brotli 缺失必须显式告警。真实目标普遍返回 Content-Encoding: br,
    #   缺少该包时 requests 静默地交回不可解码的二进制 —— 表现为"指纹 0 项 / 接口 0 个",
    #   既不报错也不提示, 是最难自查的一类"零产出"。
    if not BROTLI:
        print(f'{C.Color.BG_YELLOW}[!] 未安装 brotli: 目标若返回 Content-Encoding: br, '
              f'响应体将无法解码(指纹/接口可能为 0 且无报错)。'
              f'建议 pip install brotli{C.Color.RESET}')

    # R4/R5 浏览器交互能力的**启动显著告警**(opt-in, 行为影响面大):
    if config.get('login_capture'):
        print(f'{C.Color.BG_YELLOW}[!] R4 登录态采集: 即将打开**可见**浏览器, 请手动完成登录; '
              f'凭据仅内存态(不落盘/不进报告); 仅限自有/已授权资产{C.Color.RESET}')
    if config.get('interactive'):
        print(f'{C.Color.BG_RED}[!] R5 交互模式(interactive): 将自动填表并点击页面控件; '
              f'所有写方法(POST/PUT/PATCH/DELETE)请求**被只读护栏拦截**(只观测不发送); '
              f'GET 类副作用由目标自身设计决定 —— 仅限自有/已授权资产{C.Color.RESET}')

    # 解析模块 —— 先展开模块组名(auto/passive/confirm/all), 再校验
    from facet.core.config import KNOWN_MODULES, expand_modules
    mods = expand_modules(config.get('modules', 'passive,confirm'))
    KNOWN = set(KNOWN_MODULES)
    unknown = [m for m in mods if m not in KNOWN]
    if unknown:
        print(f'{C.Color.YELLOW}[!] 忽略未知模块: {unknown} '
              f'(可用: {sorted(KNOWN)} 或组名 passive/confirm/verify/all){C.Color.RESET}')

    targets = []
    if config.get('file'):
        _fpath = config['file']
        if not os.path.isfile(_fpath):
            print(f'{C.Color.RED}[-] 目标文件不存在: {_fpath}{C.Color.RESET}')
            sys.exit(2)
        with open(_fpath, encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        # 方案校验: 与 -u **同等口径**(此前 -f 每行没有 http/https 校验, `file:///` 等
        # 会直接进 recon_deep —— 审计 G)。逐行校验, 不合格行直接退出并报行号。
        from urllib.parse import urlparse as _urlparse
        for _i, _t in enumerate(targets, 1):
            _sc = _urlparse(_t).scheme
            if _sc not in ('http', 'https'):
                print(f'{C.Color.RED}[-] 目标文件第 {_i} 行方案不支持 "{_sc or "<空>"}": '
                      f'仅允许 http/https (行内容: {_t[:80]}){C.Color.RESET}')
                sys.exit(2)
    else:
        targets = [config['url']]

    multi = len(targets) > 1
    conc = int(config.get('batch_concurrency', 1) or 1)
    if multi and conc > 1:
        # `-f` 批量并发 —— 多个目标并行, 但**共享同一 RateManager**(全局限速配额)。
        #   并发只提升吞吐, 不放大发包速率(rate/max_rpm 仍全局生效, 熔断亦共享)。
        #   每个目标仍是独立 ScanContext(发现/计数/缓存互不串味)。
        from concurrent.futures import ThreadPoolExecutor
        shared_rm = RateManager(config.get('rate', 0.5), config.get('max_rpm', 120),
                                adapt=config.get('adapt_rate', True))
        workers = min(conc, len(targets))
        print(f'{C.Color.CYAN}[*] 批量并发: {workers} 个目标并行, 共享全局配额 '
              f'(rate={config.get("rate")}s, max_rpm={config.get("max_rpm")}){C.Color.RESET}')
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(lambda t: _scan_one_target(config, t, mods, multi, shared_rm), targets))
    else:
        for target in targets:
            _scan_one_target(config, target, mods, multi, None)

    print(f'\n{C.Color.GREEN}[+] 全部完成{C.Color.RESET}')

if __name__ == '__main__':
    main()
