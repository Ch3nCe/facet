# -*- coding: utf-8 -*-
"""facet — ScanContext: 全局变量治理, 支持真正的多目标并行"""
import threading
import time
from collections import OrderedDict

from ..output.paths import output_dir as _output_dir
from .dicts import AUTH_HEADER_NAMES
from .log import dbg, log

# 已排除项上限。旧实现无上限, catch-all 站点上可能累积数万条,
#         既占内存也让报告附录膨胀。
MAX_EXCLUDED = 500

class LRUCache:
    """带TTL的LRU缓存（用于请求去重）"""
    def __init__(self, maxsize=128, ttl=300):
        self.maxsize = maxsize
        self.ttl = ttl
        self._data = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            if key in self._data:
                ts, val = self._data[key]
                # **时长用 monotonic**: 墙钟(time.time)会被 NTP 校时/手动改钟跳变,
                #   导致 TTL 缓存提前失效或永不过期。下同(budget)。
                if time.monotonic() - ts > self.ttl:
                    del self._data[key]
                    return None
                self._data.move_to_end(key)
                return val
            return None

    def set(self, key, val):
        with self._lock:
            now = time.monotonic()
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = (now, val)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)


class CircuitBreaker:
    """熔断状态机(相对旧实现的改进)

    旧实现只累积 `fail_count`, 一旦 >= 阈值就**永久** OPEN —— 一次瞬态故障
    (部署抖动 / WAF 偶发挑战 / 短暂 429) 会让整次扫描余下全部请求被静默跳过,
    且永不恢复(OPEN 状态下 REQ 在到达 `_settle_response` 之前就 return None,
    于是 `reset_fail()` 永远没机会执行)。

    新实现引入 **半开(HALF_OPEN)自动恢复**:
        CLOSED ──(连续失败≥阈值)──▶ OPEN ──(冷却 cooldown 后)──▶ HALF_OPEN
           ▲                                                         │
           └───────────────(探活成功)─────────────────────────────────┘
                 (探活失败)──▶ 重新 OPEN(再冷却) ◀──(探活配额耗尽)──────┘
    · 阈值仍为"连续 N 次失败"(保留: 成功即清零, 即只统计连续失败; 同时保留
      "429 必须计入熔断, 避免目标限流时以 60s/请求静默爬行"的既有约束)。
    · 冷却结束后自动转入半开, 放行有限探活; 任一探活成功即回到 CLOSED(清零),
      失败则重新 OPEN。瞬态故障自愈, 扫描不再被一次性打死。
    · 记录 latched 标记 `circuit_tripped` / `circuit_recovered`, 供报告如实披露
      "曾熔断 / 已自动恢复"。
    """

    CLOSED, OPEN, HALF_OPEN = 'closed', 'open', 'half_open'

    def __init__(self, max_fail=5, cooldown=30.0, half_open_probes=3):
        self.max_fail = int(max_fail)
        self.cooldown = float(cooldown)
        self.half_open_probes = max(1, int(half_open_probes))
        self.fail_count = 0
        self.state = self.CLOSED
        self.tripped_at = 0.0
        self._ho_allowed = 0   # 本轮 half-open 已放行探活数
        self._ho_ok = False    # 本轮 half-open 是否出现过成功(预留)

    @staticmethod
    def _now():
        return time.monotonic()

    def should_skip(self, now=None):
        """返回 (skip, event)。

        event:
          'tripped'    —— 本调用恰好由 CLOSED 转入 OPEN(首次熔断);
          'cooling'    —— 处于 OPEN 冷却期, 跳过请求(等待冷却后自动半开探活);
          'recovering' —— 处于 HALF_OPEN, 本次请求被放行作为探活(不跳过);
          None        —— CLOSED, 正常放行。
        """
        if now is None:
            now = self._now()
        if self.state == self.CLOSED:
            if self.fail_count >= self.max_fail:
                self.state = self.OPEN
                self.tripped_at = now
                return True, 'tripped'
            return False, None
        if self.state == self.OPEN:
            if now - self.tripped_at >= self.cooldown:
                # 冷却结束 → 半开探活
                self.state = self.HALF_OPEN
                self._ho_allowed = 0
                self._ho_ok = False
                self._ho_allowed += 1
                return False, 'recovering'
            return True, 'cooling'
        # HALF_OPEN: 在探活配额内放行, 配额耗尽且未成功则重新 OPEN
        if self._ho_allowed < self.half_open_probes:
            self._ho_allowed += 1
            return False, 'recovering'
        self.state = self.OPEN
        self.tripped_at = now
        return True, 'cooling'

    def on_failure(self, now=None):
        """一次(未被只读护栏拦截的)请求失败结算。

        注意: CLOSED→OPEN 的"跳闸"判定只在 `should_skip()`(请求闸门)里发生,
        这里**不**直接跳闸 —— 保证"首次熔断(tripped)"事件总是由闸门发出,
        调用方据此打印醒目告警; 同时让 `circuit_gate()` 能在同一点置位 latched 标记。
        """
        if now is None:
            now = self._now()
        if self.state == self.HALF_OPEN:
            # 探活失败 → 立即重新 OPEN
            self.state = self.OPEN
            self.tripped_at = now
            return
        # CLOSED: 仅累积失败计数; 真正跳闸在 should_skip 判定
        self.fail_count += 1

    def on_success(self, now=None):
        """一次请求成功结算(2xx/3xx/4xx 均视为目标可达, 不计失败)。

        返回 True 表示本次成功使熔断从 HALF_OPEN 关闭(即"已自动恢复")。
        """
        if now is None:
            now = self._now()
        if self.state == self.HALF_OPEN:
            self.state = self.CLOSED
            self.fail_count = 0
            self._ho_ok = True
            return True
        # CLOSED: 成功打断任何连续失败计数(与旧 reset_fail() 语义一致)
        self.fail_count = 0
        return False


class ScanContext:
    """每个目标独立的扫描上下文, 替代模块级全局变量"""
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.findings = []
        # finding 的**来源代码定位**表: key=(sev,typ,url,ev) 4 元组(与 findings 去重键一致)
        #   → {'src','line','col','probe','snippet'}; 由 js_lex.note_finding_loc 在扫描期写入,
        #   报告「完整发现清单」按同键查表渲染可展开的定位/代码端(无定位的 finding 不显示展开)。
        #   scan 级状态(与 findings 同在 ctx, 无需经 _merge_out 合并)。
        self.finding_loc = {}
        # 实时验证密钥需要完整值(报告里的证据已截断到 60 字),
        #   这里在内存里保留 (规则名, 完整值, 来源) 供 verify_secrets 配置用。
        #   仅驻留内存, 不写入报告/磁盘(合规: 不扩散完整密钥)。
        self.secret_hits = []
        self.all_found = []
        # 已排除项(伪命中 / 空回退 / canary 一致), 单独存放
        #   不计入严重度统计, 报告以"附录"形式输出, 供分析师审计扫描器自身判定
        self.excluded = []
        self.excluded_overflow = 0
        self.invalid = set()
        self.total_sent = 0
        # 熔断状态机(替代旧的单计数器 fail_count): 支持半开自动恢复, 不再永久跳过。
        self.breaker = CircuitBreaker(
            max_fail=config.get('circuit_max_fail', 5),
            cooldown=float(config.get('circuit_cooldown', 30)),
            half_open_probes=int(config.get('circuit_half_open_probes', 3)),
        )
        # 熔断 latched 标记(供报告如实披露"曾熔断 / 已自动恢复"); 一经置位不清除。
        self.circuit_tripped = False
        self.circuit_recovered = False
        # 熔断**实际跳过**的请求数(供报告量化"熔断导致漏了多少请求") —— 旧版只披露布尔, 无法量化。
        self.circuit_skipped = 0
        # 运行时通道状态(能力宣称=真实执行): ran 只在浏览器会话**确实启动**后置 True;
        #   reason 记录未运行的原因(依赖缺失/异常)。旧版按配置谎报"已启用"。
        self.runtime_ran = False
        self.runtime_reason = ''
        # 运行时通道请求触顶被丢弃数(供报告/日志披露"预算耗尽导致覆盖率下降");
        #   旧版触顶后静默 abort, 用户无法区分"目标没接口"与"预算不够没跑到"。
        self.runtime_requests_aborted = 0
        # 入口页是否**真正取到响应** —— 退出码契约用它判定"扫描是否有效"。
        #   目标不可达时 detect_and_probe 会提前返回, 旧版仍打印"全部完成"且退出码 0。
        self.entry_fetched = False
        # 已探活路径(跨 probe() 调用累积, 也可由 --resume 从状态恢复)。
        #   续扫时恢复它 → 已探过的路径不再重复发包(旧实现只续 JS 相位, 探活整段重跑)。
        self.probed = set()
        # 本次从状态恢复的已探活条数(报告 completeness 披露, 避免"0 发包却有一堆端点"的误读)。
        self.resumed_probed = 0
        # 声明范围(in-scope)护栏状态(SRC 合规边界): scope_rules=原始声明(报告展示),
        #   scope=ScopeMatcher(空=未声明→同源保守); scope_blocked=被越界硬拒的请求数(报告披露)。
        self.scope_rules = []
        self.scope = None
        self.scope_blocked = 0
        # 授权确认留痕(合规证据链): authorized=是否确认授权; auth_method=确认方式。
        self.authorized = False
        self.auth_method = ''
        # 熔断日志节流(避免冷却期每条跳过都刷屏)
        self._circuit_cool_log_t = 0.0
        self._circuit_halfopen_announced = False
        self.pmap = {}
        # 参数取值形态: {path: {参数名: set(形态)}} —— 来自运行时(浏览器)捕获, 只记形态不存原值。
        self.param_shapes = {}
        # 表单字段 → 端点 的**代码依据**关联(零推断):
        #   form_fields     {form_id: set(字段名)}  —— 来自页面 `<form>`(无 action 时记录)
        #   form_body_links {form_id: set(端点)}    —— 来自 JS 变量链(FormData→fromEntries→body→fetch)
        #   两者在 recon 收尾由 `_resolve_form_body_links` 求交, **唯一对应才 link_param**。
        self.form_fields = {}
        self.form_body_links = {}
        # JS声明的写操作接口 {path: method} (probe时只读引用, 零发包)
        self.write_apis = {}
        # 路径推断(方案 4.6)派生的同族候选 —— **与提取结果分区**, 报告按来源单列
        self.inferred_paths = set()
        # OPTIONS/Allow 方法发现(方案 2-B): {path: [方法…]} —— 目标自述支持的方法
        self.options_methods = {}
        # 响应体/响应头 URL 挖掘(方案 2-B): 从响应里挖出并回灌的同源新路径
        self.mined_paths = set()
        # 跨文件 JS 符号表(动态提取层): {变量名: 字符串值} —— 把内联脚本 + 同源 JS 文件里
        #   识别到的「变量→根相对路径形态值」聚合起来, 供同一页面的所有文件共享解析。
        #   解决「基址变量定义在 HTML 内联脚本、拼接在 JS 文件」(如 RuoYi `var ctx="/xinzuo";
        #   url: ctx + "login"`)导致的整条漏抓。只登记根相对路径形态值, 避免非路径串污染 /
        #   命名冲突。仅作「已知常量值」补充, 不做跨文件遮蔽推断(保守)。
        self.js_symbols = {}
        # 请求缓存去重
        self.request_cache = LRUCache(maxsize=config.get('max_baseline_cache', 128), ttl=300)
        # 审计日志
        self.audit_log_path = config.get('audit_log_path') or str(_output_dir() / 'facet_audit.log')
        self.audit_enabled = config.get('audit_log', False)
        if self.audit_enabled:
            # 审计日志父目录必须预建: default_output_file() 只拼路径**不建目录**,
            # open('a') 也不建父目录 —— 空输出目录(无 JS 落盘 / 无状态持久化的首扫,
            # 实测: FACET_OUTPUT_DIR 指向全新目录)下审计写入会
            # FileNotFoundError 被 except 吞掉, "已开启审计"变**假成功**
            # (与 D5 报告写入同类问题, 复用同一 ensure_parent 防线)。
            try:
                from ..output.paths import ensure_parent
                ensure_parent(self.audit_log_path)
            except Exception as e:
                dbg(f'审计日志父目录创建失败({self.audit_log_path}): {e}')
        self._audit_write_failed = False   # 审计写入失败只警告一次, 避免逐请求刷屏
        # ---- 显式声明此前"动态挂载"的属性 ----
        self.base = None
        self._catchall_baseline = None
        self._catchall_tried = False
        self._catchall_base = None
        self._homepage_fingerprint = ''
        self._resp_fingerprints = set()
        # 路由权重表(由 fingerprint_target 产出, JS 阶段补判指纹时继续抬升)
        self.route = None
        self.rm = None
        # ---- 真实目标适用性 ----
        # 长驻 requests.Session。此前用的是模块级 requests.request(), 它**每次调用
        # 都新建一个 Session** —— 服务端下发的 Set-Cookie 立即被丢弃, 于是任何
        # "先发会话 cookie 再要求回传"的站点(负载均衡会话保持 / CSRF / 反爬挑战)
        # 只能看到第一页。顺带获得连接复用, 省掉每请求一次 TLS 握手。
        self.session = None
        self.session_lock = threading.Lock()
        # 全局时间预算。None = 不限。此前只有单请求超时, 没有总时长上限 ——
        # 目标持续 429 时退避会累积到 60s/请求, 扫描表现为卡死。
        self.deadline = None
        # 各环节被截断的条数 {原因: 条数}, 供报告如实披露
        self.truncated = {}
        # 实际发生的网络请求数(含重定向跳数与重试), 与"逻辑请求数"区分开
        self.net_sent = 0
        # TLS 证书信息 {issuer, subject, san, not_before, not_after}, 未提取到为 None
        self.tls_cert = None
        # 统一在此创建限速器 —— 旧实现由 cli.py 在外部 `ctx.rm = RateManager(...)`,
        #   直接用 ScanContext 时 REQ 会 AttributeError。
        self.ensure_rate_manager()

    def ensure_session(self, headers=None):
        """惰性创建长驻 Session(带全局请求头), 保证 cookie 跨请求持久化。

        ⚠️ **不把"鉴权头"写入 Session 默认头**(Cookie / Authorization / 自定义鉴权头, 见
          `dicts.AUTH_HEADER_NAMES`): `requests` 会把 `session.headers` 与 per-request
          `headers` **合并**(后者仅覆盖同名键), 故一旦把鉴权头烤进 Session 默认头,
          `no_session=True` 的"匿名视图"仍会携带凭据 → 匿名 vs 认证差分**失真**
          (实测: 目标用 `X-Access-Token` 鉴权时, 访问矩阵恒 0 信号 —— 匿名半边其实带 token)。
          鉴权头一律由各请求按需传入(见 engine._merge_headers)。
        """
        if self.session is None:
            with self.session_lock:
                if self.session is None:
                    import requests
                    s = requests.Session()
                    # 连接复用: 同一主机复用 TCP/TLS, 显著降低真实目标的握手开销
                    if headers:
                        s.headers.update({k: v for k, v in dict(headers).items()
                                          if str(k).lower() not in AUTH_HEADER_NAMES})
                    self.session = s
        return self.session

    def close_session(self):
        if self.session is not None:
            try:
                self.session.close()
            except Exception as e:
                dbg(f'关闭会话失败: {e}')
            self.session = None

    # -- 全局时间预算 --
    def start_budget(self, seconds):
        """设定全局时间预算; seconds<=0 表示不限"""
        try:
            seconds = float(seconds or 0)
        except (TypeError, ValueError):
            seconds = 0
        # **时长用 monotonic**(与 `budget_left` 同一时钟): 墙钟被校时会凭空多出/少掉预算。
        self.deadline = (time.monotonic() + seconds) if seconds > 0 else None
        return self.deadline

    def budget_left(self):
        """剩余秒数; 不限时返回 None"""
        if self.deadline is None:
            return None
        return self.deadline - time.monotonic()

    def budget_exhausted(self):
        """预算是否已耗尽"""
        left = self.budget_left()
        return left is not None and left <= 0

    def note_truncated(self, reason, dropped):
        """登记被截断的条数, 报告需如实披露(否则使用者会以为"目标就这些")"""
        if dropped > 0:
            with self.lock:
                self.truncated[reason] = self.truncated.get(reason, 0) + dropped

    def count_net(self, n=1):
        """累计实际网络请求数(含重定向跳数)"""
        with self.lock:
            self.net_sent += n

    def ensure_rate_manager(self):
        """惰性创建/获取 RateManager"""
        if self.rm is None:
            from .rate import RateManager  # 限速器已下沉到 core/rate.py(消除 engine↔context 循环)
            self.rm = RateManager(self.config.get('rate', 0.5) or 0.5,
                                  self.config.get('max_rpm', 120) or 0,
                                  adapt=self.config.get('adapt_rate', True))
        return self.rm

    # -- 审计日志接口 --
    def audit(self, method, url, status, resp_size, note=''):
        if not self.audit_enabled:
            return
        # 不再脱敏: 审计日志 URL/敏感 query 值**原样**落盘(本工具已移除全部脱敏)。
        url = str(url)
        note = str(note)
        try:
            ts = time.strftime('%Y-%m-%dT%H:%M:%S')
            with open(self.audit_log_path, 'a', encoding='utf-8') as f:
                f.write(f'{ts}\t{method}\t{url}\t{status}\t{resp_size}\t{note}\n')
        except Exception as e:
            # 审计日志写不进去必须留痕: 否则"已开启审计"是**假成功**(合规场景尤其致命)。
            dbg(f'审计日志写入失败({self.audit_log_path}): {e}')
            if not self._audit_write_failed:
                # 可见化一次(此前仅 dbg, 非 debug 运行下完全静默)
                self._audit_write_failed = True
                log(f'[!] 审计日志写入失败({self.audit_log_path}): {e} —— 审计留痕不完整')

    # -- 计数与熔断 --

    def check_circuit(self, max_fail=5):
        """向后兼容: 返回是否应跳过请求(熔断 OPEN/冷却中)。

        新代码建议用 `circuit_gate()` 以获取事件类型做差异化日志。
        """
        with self.lock:
            if max_fail != self.breaker.max_fail:
                self.breaker.max_fail = int(max_fail)
            skip = self.breaker.should_skip()[0]
            if skip:
                self.circuit_skipped += 1   # 量化"因熔断被跳过"的请求数(报告披露)
            return skip

    def circuit_gate(self):
        """返回 (skip, event)。详见 CircuitBreaker.should_skip 的 event 说明。

        同时在此处维护 latched 标记 `circuit_tripped` —— 因为 CLOSED→OPEN 的
        跳闸判定只在 `should_skip()` 内发生, 集中在此置位可避免遗漏。
        """
        with self.lock:
            _before = self.breaker.state
            skip, evt = self.breaker.should_skip()
            if _before != CircuitBreaker.OPEN and self.breaker.state == CircuitBreaker.OPEN:
                self.circuit_tripped = True
                self._circuit_halfopen_announced = False
            if skip:
                self.circuit_skipped += 1   # 量化"因熔断被跳过"的请求数(报告披露)
            return skip, evt

    def record_fail(self):
        with self.lock:
            _before = self.breaker.state
            self.breaker.on_failure()
            if _before != CircuitBreaker.OPEN and self.breaker.state == CircuitBreaker.OPEN:
                # 由 CLOSED/半开 进入 OPEN —— latched 标记"曾熔断"
                self.circuit_tripped = True
                self._circuit_halfopen_announced = False  # 下次半开需重新提示

    def reset_fail(self):
        with self.lock:
            if self.breaker.on_success():
                # 半开探活成功 → 关闭熔断, latched 标记"已自动恢复"
                self.circuit_recovered = True
                self._circuit_halfopen_announced = False

    # -- 发现项管理 --
    def add_finding(self, sev, typ, url, ev):
        with self.lock:
            if (sev, typ, url, ev) not in self.findings:
                self.findings.append((sev, typ, url, ev))

    def add_all_found(self, p, m, st, note):
        with self.lock:
            if (p, m, st, note) not in self.all_found:
                self.all_found.append((p, m, st, note))

    def add_excluded(self, path, status, reason):
        """记录已排除项(伪命中/空回退/canary 一致)

        与 findings 分离存放 —— 已排除项不是"发现", 不应污染严重度统计。
        加上限, 防止 catch-all 站点把附录 A 灌爆(超出部分只计数不落盘)。
        """
        with self.lock:
            if (path, status, reason) not in self.excluded:
                if len(self.excluded) >= MAX_EXCLUDED:
                    self.excluded_overflow += 1
                    return
                self.excluded.append((path, status, reason))


    def is_invalid(self, p):
        """路径是否已被判定为**不存在**(404/410 或与 canary 基线一致)。

        键统一为**去 query 的路径** —— 同一路径的所有 query 变体共享同一"不存在"判定。
        与 `mark_invalid()` 同口径, 保证写入/读取键一致。
        """
        return (p or '').split('?')[0] in self.invalid

    def mark_invalid(self, p):
        """记录一个**确认不存在**的路径, 供后续相位(options_probe / hidden_probe / 再次 probe)
        跳过, 避免对同一不存在路径重复探测。

        此前 `invalid` 只有消费者、**无生产者** → `is_invalid()` 恒 False, 无效路径去重整条空转。
        """
        _k = (p or '').split('?')[0]
        if _k:
            with self.lock:
                self.invalid.add(_k)


    def cache_get(self, url):
        return self.request_cache.get(url)

    def cache_set(self, url, val):
        self.request_cache.set(url, val)

    # -- 参数映射 --
    def link_param(self, path, param):
        with self.lock:
            self.pmap.setdefault(path, set()).add(param)

    # -- 状态保存/恢复 --
    #   **静默吞异常 = 假成功**: 用户显式开了 `--resume`/`--persist-state`, 若保存失败,
    #   下次续扫会"从头再来"却毫无提示。故失败一律经 `dbg` 留痕(FACET_DEBUG=1 可见)。
    def save_state(self, base, phase, data, store):
        try:
            store.save(base, phase, data)
        except Exception as e:
            dbg(f'状态保存失败(phase={phase}): {e}')

    def load_state(self, base, phase, store):
        try:
            return store.load(base, phase)
        except Exception as e:
            dbg(f'状态读取失败(phase={phase}), 按空状态续扫: {e}')
            return set()
