# -*- coding: utf-8 -*-
"""自适应限速器（**基础设施层**）—— 原从 `core/engine.py` 下沉（该门面已删除）。

动机（架构一致性）：`core/context.py` 需要 `RateManager`，若从编排层（原 `core/engine.py`）导入即形成
**向上依赖 + 循环依赖**（编排层 → context → 编排层）。下沉后 context 与编排层都向下引用。
"""
import threading
import time


class RateManager:
    """自适应限速: 429→立即降速, 5xx→减速, 正常→可加速

    修复三处限速缺陷:
      1. **单一限速状态** — 新增 reserve(), 由同步路径(guard)与异步路径
         (_AsyncRateGate) 共同调用, 共享同一个 last 与 rpm_window。
      2. **429 降速加上限** — 旧实现 `rate = max(rate*3, 2.0)` 无封顶, 连续 429 时
         rate 会指数涨到 4000s+/请求, 扫描实际卡死。
      3. **自适应加速不得突破用户设定速率** — 旧实现 `rate = max(rate*0.95, 0.2)`
         会把用户显式配置的 `rate: 2.0`(为保护目标而设)自动加速到 0.2, 违背合规承诺。
    """
    RATE_MAX = 60.0          # 单请求最大间隔(429 退避封顶)

    def __init__(self, init_rate, max_rpm, adapt=True):
        self.rate = float(init_rate)
        self.base_rate = float(init_rate)   # 用户设定值: 自适应加速的下限
        self.max_rpm = max_rpm
        self.adapt_enabled = adapt
        self.rate_lock = threading.Lock()
        self.last = 0.0
        self.sent_lock = threading.Lock()
        self.rpm_window = []

    def reserve(self):
        """申请一个发送名额, 返回需要等待的秒数

        同步与异步路径共用本方法 —— 单一限速状态。
        方法内不 sleep(仅占位), 因此持有锁的时间极短, 不会串行化调用方。
        """
        with self.rate_lock:
            # **时长用 monotonic**: 限速窗口(60s)/请求间隔都是时长, 墙钟跳变会让窗口
            #   突然"全部过期"(放行风暴)或"永不过期"(死锁在等待)。
            now = time.monotonic()
            self.rpm_window = [t for t in self.rpm_window if now - t < 60]
            wait = 0.0
            # RPM 硬顶: 窗口内已满则等到最早一个名额过期
            if self.max_rpm > 0 and len(self.rpm_window) >= self.max_rpm:
                wait = 60 - (now - self.rpm_window[0]) + 0.1
            # 请求间隔: 与上一个已占位名额保持 rate 秒
            gap = self.rate - (now - self.last)
            if gap > wait:
                wait = gap
            wait = max(0.0, wait)
            slot = now + wait
            self.last = slot
            self.rpm_window.append(slot)
            return wait

    def guard(self, ctx=None):
        """同步限速: 申请名额 → sleep → 计数

        计数**按 ctx 自增**。原因: `-f` 批量并发下多个目标的 ctx **共享同一个
        RateManager**(全局配额) —— 若取全局值, 每个目标的报告都会显示全局发包数
        (串味); 按 ctx 自增后每个目标只统计自己的发包。
        """
        wait = self.reserve()
        if wait > 0:
            time.sleep(wait)
        with self.sent_lock:
            if ctx:
                ctx.total_sent = getattr(ctx, 'total_sent', 0) + 1

    def count_only(self, ctx=None, n=1):
        """仅计数(供异步路径/浏览器通道使用: 限速由 reserve() 负责, 此处只累计发包数)

        异步路径此前完全不计数, 导致报告"总发包"严重偏低。
        增加 n 参数 —— 浏览器通道一次产生多个请求, 需批量结算。
        """
        with self.sent_lock:
            if ctx:
                ctx.total_sent = getattr(ctx, 'total_sent', 0) + n

    def adapt(self, status, is_timeout=False, retry_after=None):
        """自适应调整速率(可用 adapt=False 整体关闭)

        429 分支尊重 `Retry-After`, 但仍受 `RATE_MAX` 封顶; 任何分支都**不得低于**
        用户设定的 `base_rate` —— 自适应只能"变慢", 绝不能比用户授权的更快。
        """
        if not self.adapt_enabled:
            return
        with self.rate_lock:
            if is_timeout:
                # 连接超时 → 可能被封, 指数退避
                # floor 用户设定值: 封顶(5.0)不得**击穿** base_rate —— 用户设 rate=10
                #   是为保护目标, 一次超时就把间隔压到 5s 等于比用户授权的更快(审计 M7)。
                self.rate = max(min(self.rate * 2, 5.0), self.base_rate)
            elif status == 429:
                # 明确限速 → 大幅降速
                if retry_after:
                    # 修正: 服务端**明确告知**等待时长时, 直接采用该值。
                    #   初版写成 `max(rate*3, retry_after)`, 取的是两者**较大值** ——
                    #   于是目标说"等 5 秒", 我们却等 5→15→45→60 秒逐级递增,
                    #   4 个 429 就累积到 125 秒(实测 100s 超时仍未跑完)。
                    #   目标比自己更清楚什么时候可以再来; 相信它, 既不越界也更快。
                    try:
                        want = float(retry_after)
                    except (TypeError, ValueError):
                        want = max(self.rate * 3, 2.0)
                else:
                    want = max(self.rate * 3, 2.0)
                # 不低于用户设定的速率(与 retry_after 分支同口径) + RATE_MAX 封顶
                self.rate = min(max(want, self.base_rate), self.RATE_MAX)
            elif 500 <= status < 600:
                # 服务端过载 → 温和减速(同样不得击穿 base_rate, 同 M7)
                self.rate = max(min(self.rate * 1.5, 3.0), self.base_rate)
            elif status == 200:
                # 正常响应 → 逐步加速, 但**不得低于用户设定的速率**
                self.rate = max(self.rate * 0.95, self.base_rate)
