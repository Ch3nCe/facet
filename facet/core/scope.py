# -*- coding: utf-8 -*-
"""声明范围（in-scope）匹配器 —— SRC 合规边界的硬护栏。

合规优先定位要求: 工具**只**在授权范围内活动。本模块提供:
  · ScopeMatcher: 判断一个 URL/主机是否在声明范围内(域名后缀 / 通配子域 / IP / CIDR)。
  · build_scope: 由 CLI/配置的规则构建匹配器; 规则为空时回退为 `default_base` 的**同源**
    (保守默认: 不传 --scope 即"目标同源", 与旧版"仅同源"行为一致, 但现在是**硬拒**而非"靠不生成")。

越界请求在出站护栏(REQ / _aio_req / 浏览器通道)被拦截并记 `BLOCKED_SCOPE`, 报告如实披露。
"""
import ipaddress
from urllib.parse import urlparse


def host_of(url):
    """从 URL 提取主机名(小写, 去端口)。无法解析返回 ''。"""
    if not url:
        return ''
    try:
        h = urlparse(str(url)).hostname
        return (h or '').lower()
    except Exception:
        return ''


def _looks_cidr(s):
    # 粗略判定: 含单个 '/' 且 '/' 后纯数字(前缀长度)。
    if s.count('/') != 1:
        return False
    _, _, p = s.partition('/')
    return p.isdigit()


class ScopeMatcher:
    """声明范围匹配器(纯函数式, 可单测)。"""

    def __init__(self, rules):
        # rules: 字符串列表, 每项可为:
        #   · 域名/主机: example.com  → 精确 + 其子域(*.example.com)都算内
        #   · 通配子域: *.example.com → 等价于 example.com(后缀匹配已含子域, 去掉 '*.' 前缀)
        #   · IP:       1.2.3.4
        #   · CIDR:     1.2.3.0/24
        self._hosts = set()     # 规范化后的主机/域名(用于后缀匹配)
        self._cidrs = []        # ip_network 列表
        for r in rules or []:
            r = (r or '').strip().lower()
            if not r:
                continue
            _h_part = r.split('/', 1)[0]
            # CIDR 优先识别(形如 10.0.0.0/24 或 2001:db8::/32, 其 '/' 会被下方当成 path 截断)
            if _looks_cidr(r):
                try:
                    ipaddress.ip_address(_h_part)          # 仅校验 host 部分是合法 IP
                    self._cidrs.append(ipaddress.ip_network(r, strict=False))
                    continue
                except ValueError as e:
                    # 合规护栏**不得静默降级**: 形如 `10.0.0.0/24x` 的坏 CIDR 曾被悄悄
                    #   收窄成单主机 `10.0.0.0`, 与用户声明的授权范围不符且零提示(审计 F)。
                    print(f'[!] scope 规则 {r!r} 不是合法 CIDR({e}), 按单主机处理 —— '
                          f'请检查授权范围声明')
            # 其余: 去掉可能的 scheme / 路径 / 端口, 只留主机
            _pre = r
            r = r.split('//', 1)[-1].split('/', 1)[0].split(':', 1)[0]
            if '/' in _pre.split('//', 1)[-1]:
                # 规则里带了路径(如 example.com/app) —— 路径部分被丢弃 = **放大授权**,
                # 同样不得静默(审计 F)。
                print(f'[!] scope 规则 {_pre!r} 含路径部分, 已按主机 {r!r} 处理(路径不参与匹配)')
                if not r:
                    continue
            if not r:
                continue
            if r.startswith('*.'):           # 通配子域 → 去掉前缀, 后缀匹配已覆盖子域
                r = r[2:]
                if not r:
                    continue
            self._hosts.add(r)

    def in_scope(self, url):
        """url 是否在声明范围内。无法解析或不在任何规则内 → False(越界)。"""
        host = host_of(url)
        if not host:
            return False
        # 域名后缀匹配: host == base 或 host 以 '.base' 结尾(覆盖子域)
        for base in self._hosts:
            if host == base or host.endswith('.' + base):
                return True
        # CIDR 匹配(仅当 host 是 IP)
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        for net in self._cidrs:
            if ip in net:
                return True
        return False


def build_scope(rules, default_base=None):
    """构建 ScopeMatcher。

    - rules 非空: 用规则构建(显式声明授权范围)。
    - rules 为空且 default_base 给定: 回退为 default_base 的**同源**(保守默认)。
    - 两者皆无: 返回空匹配器(in_scope 恒 False —— fail-closed, 但正常调用总有 default_base)。
    """
    _rules = [str(r).strip() for r in (rules or []) if r and str(r).strip()]
    if _rules:
        return ScopeMatcher(_rules)
    if default_base:
        _h = host_of(default_base)
        if _h:
            return ScopeMatcher([_h])
    return ScopeMatcher([])
