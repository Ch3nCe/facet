# -*- coding: utf-8 -*-
"""自适应参数派生（基础设施层 · 纯函数 · 零发包）。

动机：配置里 21 个旋钮原本只有 `max_js`（按发现量）与 `rate`（遇 429 降速）会自适应，
其余是**写死的数字**。写死的问题很实在：
  · `timeout=10` 对慢站批量超时、对快站白等；
  · `silent_js_min_size=20KB` 在小站（文件都 5KB）会把**全部**文件滤掉、在大站又全报；
  · `max_probe=400` 在接口只有 30 条的小站是空转、在大站又不够。

本模块统一提供 `effective_*(config, 观测状态)` —— 与既有 `config.effective_max_js` 同风格。
**信号一律取自目标自身可观测状态**（实测延迟 / 文件体积分布 / 剩余预算 / 实际条目数），
不使用任何站点白名单。

**边界（有意不做的自适应）**：
  · `rate` / `max_rpm` 是**礼貌性约束**（对目标负责），只允许"遇 429 变慢"，
    不允许"目标响应快就加速" —— 那等于把目标当靶子打；
  · `max_duration` 是**用户策略**（愿意花多久），目标无权决定；
  · `silent_js_min_size` 的**门槛**可自适应，但**报什么不能因目标放宽**（诚实性）。

每个派生结果都应通过 `note()` 记录来源，由报告如实披露 —— 否则自适应又成黑箱，
与"可审计交付"的定位冲突。
"""
from __future__ import annotations

# ---------------------------------------------------------------- 通用工具

def percentile(samples, q):
    """样本的 q 分位（0<q<=1）；样本不足返回 None。`q=0.95` → P95。"""
    try:
        s = sorted(float(x) for x in samples if x is not None)
    except (TypeError, ValueError):
        return None
    if not s:
        return None
    if len(s) == 1:
        return s[0]
    _i = int(round(q * (len(s) - 1)))
    return s[max(0, min(len(s) - 1, _i))]


def _f(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return float(default)


def _nz(v, default=0.0):
    """与 `_f` 的区别: **保留显式 0**(仅解析失败/None 才回落默认)。

    `_f(x, d) or d` 的旧写法会把用户显式配的 `0`(如 `silent_js_min_size: 0` 的
    "全部登记"语义)静默替换成默认值 —— 配置语义被吞(审计 L)。
    """
    if v is None:
        return float(default)
    try:
        return float(v)
    except (TypeError, ValueError):
        return float(default)


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def note(ctx, name, base, value, basis):
    """记录一次自适应派生（供报告披露：改了什么、依据是什么）。

    只记**确实变化**的项，避免报告里塞一堆"没变"的噪声。
    """
    if ctx is None:
        return
    try:
        # 数值优先比较 —— 否则 `10` 与 `10.0` 会被当成"发生了变化"(字符串不等),
        #   报告就会显示一次**实际没发生**的自适应（实测踩过）。
        try:
            if float(base) == float(value):
                return
        except (TypeError, ValueError):
            if str(base) == str(value):
                return
        d = getattr(ctx, '_adapt_notes', None)
        if d is None:
            d = {}
            ctx._adapt_notes = d
        d[name] = {'base': base, 'value': value, 'basis': basis}
    except Exception as e:
        # 披露记账失败静默 = 自适应结果不进报告且无痕迹(与"自适应不得成黑箱"相悖, 审计 L)。
        from .log import dbg
        dbg(f'adapt.note({name}) 失败: {e}')


# ---------------------------------------------------------------- ① 超时

# 延迟自适应：以**实测 P95** 为基准，取 `P95 * k`，并夹在 [base, base*MAX_GAIN] 内。
#   为什么用 P95 而不是均值：均值会被少数快请求拉低，而超时是**尾部**问题。
TIMEOUT_K = 2.0
TIMEOUT_MAX_GAIN = 3.0
TIMEOUT_MIN_SAMPLES = 12


def effective_timeout(config, rtts, default=10.0):
    """按**实测响应延迟**派生超时秒数；样本不足 → 用配置值。

    实测意义：慢站（P95 数秒）不再批量超时丢掉接口；快站（P95 几十毫秒）不再白等。
    """
    base = _nz((config or {}).get('timeout', default), default)
    p95 = percentile(rtts, 0.95)
    if p95 is None or len(list(rtts or ())) < TIMEOUT_MIN_SAMPLES:
        return base
    return round(clamp(p95 * TIMEOUT_K, base, base * TIMEOUT_MAX_GAIN), 2)


# ---------------------------------------------------------------- ③ 体积门槛

# "体量够大"= **本站体积分布的 P90**（即该站最大的那 10%），并夹在 [8KB, 128KB]。
#   为什么用分位而不是固定 20KB：小站全是 5KB 文件时固定阈值会把**全部**文件滤掉
#   （等于不披露），大站全是 200KB 时又会**全报**（等于噪声）。
SILENT_Q = 0.90
SILENT_FLOOR = 8 * 1024
SILENT_CEIL = 128 * 1024
SILENT_MIN_SAMPLES = 30


def effective_silent_min(config, sizes, default=20480):
    """按**本站 JS 体积分布**派生"零产出披露"的门槛；样本不足 → 用配置值。"""
    # 默认值单一真源(审计 S13): 兜底取 DEFAULT_CONFIG, 不再各写 20480
    from .config import DEFAULT_CONFIG
    default = DEFAULT_CONFIG.get('silent_js_min_size', default)
    base = int(_nz((config or {}).get('silent_js_min_size', default), default))
    _n = len(list(sizes or ()))
    if _n < SILENT_MIN_SAMPLES:
        return base
    p90 = percentile(sizes, SILENT_Q)
    if p90 is None:
        return base
    return int(clamp(p90, SILENT_FLOOR, SILENT_CEIL))


# ---------------------------------------------------------------- ② 预算派生上限

def effective_stage_cap(config, key, remaining_s, per_item_s, share, hard_default=None):
    """由**剩余时间预算**派生某阶段的条目上限：`上限 = 剩余秒 × share ÷ 单条耗时`。

    取代"各阶段各自写死一个数字"（`max_probe=400` / `options_probe_max=60` /
    `resp_mine_max=100` / `path_infer_max_total=200`）—— 那些数字在小站是空转、
    在大站又不够，且彼此之间没有任何配比关系。

    规则：配置值为**下限**（用户显式调大就尊重），预算派生值不设硬顶
    （`max(下限, 派生值)`）；`0` = 用户显式"不限"，不参与自适应。
    信号不足（无预算/无耗时样本）→ 用配置值。(docstring 与实现此前不符, 审计 D14 订正。)
    """
    cfg = config or {}
    base = int(_nz(cfg.get(key, hard_default), hard_default or 0))
    # **`0` 是用户的显式选择（不限）** —— 自适应不得覆盖它（否则"不限"变成"被限"）。
    if base <= 0:
        return 0
    if remaining_s is None or per_item_s is None:
        return base
    rem, cost, sh = _nz(remaining_s, 0), _nz(per_item_s, 0), _nz(share, 0)
    if rem <= 0 or cost <= 0 or sh <= 0:
        return base
    derived = int(rem * sh / cost)
    if derived <= 0:
        return base
    # 配置值为**下限**（用户显式调大就尊重），预算派生值为上限
    return max(base, derived)


# ---------------------------------------------------------------- ④ 条目数自适应

def effective_module_cap(config, actual, key='unbundle_max_modules', hard=2000):
    """拆包模块数上限 → 按**该 bundle 实际模块数**自适应（配置值为下限，`hard` 为硬顶）。"""
    base = int(_nz((config or {}).get(key, 200), 200))
    n = int(_nz(actual, 0))
    if n <= 0:
        return base
    return max(base, min(n, hard))


def effective_page_cap(config, discovered, key='crawl_max_pages', hard=1000):
    """多页爬取页数上限 → 按**首页实际链接数**自适应（配置值为下限，`hard` 为硬顶）。"""
    base = int(_nz((config or {}).get(key, 30), 30))
    n = int(_nz(discovered, 0))
    if n <= 0:
        return base
    return max(base, min(n, hard))
