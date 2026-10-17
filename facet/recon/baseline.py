# -*- coding: utf-8 -*-
"""按指纹命中选择差异化基线（Per-Fingerprint Baseline）—— 第十九轮后新增。

设计原则(见 docs/plan-per-fingerprint-baseline.md):
  · **薄注册表 + 合并函数**, 不重写已有的接口提取路由(`route` / `ROUTE_EXTRA_PATTERNS`
    已经做了 B1, 本模块只补 B2/B3/B4/B5 维度)。
  · 注册表是**稀疏**的 —— 只给"需要特殊处理"的技术栈写条目, 绝大多数栈走默认行为。
  · 多指纹命中时合并: catchall_mode 取首个非空、confirm_min_hits 逐键取最大、
    annotations 取并集(宁严勿漏)。

当前实现:
  · **B3 存活/响应基线**(catch-all / soft-404 的建法随栈调整):
      WAF_BLOCK(多发+易被拦路径抓拦截页) / SPA_INDEX / CMS_404 / API_JSON_404。
  · **B4 确认基线**(confirm_min_hits): 指纹"确认成立"所需最少命中信号数(count),
    覆盖全局比例阈值 `FP_HIT_THRESHOLD=0.3`。由静态表 `FP_CONFIRM_MIN_HITS`
    (Admin-Panel/OAuth2 等泛化名词 ≥2 条信号才确认) + profile 栈条件覆盖合并,
    经 `get_confirm_overrides()` 注入 `fingerprint_target`/`fingerprint_from_js`。
  · **B2 栈专属探测目标**: 已**移除** —— 原 `probe_targets` 与数据层 `HIDDEN_PATHS_BY_STACK`
    重复; 栈专属路径现由**数据驱动**的 `hidden_probe`(指纹门控)统一处理。
  · **B4 确认基线**(confirm_min_hits) 已落地: 静态表 `FP_CONFIRM_MIN_HITS` + 栈条件覆盖,
    经 `get_confirm_overrides()` 注入评分内核。
  · **B5 报告标注**(annotations) 已落地: 进报告"侦察要点"章节(MD + HTML)。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class BaselineProfile:
    """单条指纹的基线/处置配置(全部可选, 缺省即走默认行为)。"""
    catchall_mode: Optional[str] = None                      # B3: 见 CATCHALL_MODES
    # B4: {指纹名: 确认所需最少命中信号数(count)} —— 覆盖全局比例阈值 FP_HIT_THRESHOLD。
    #   与单值不同, 这里按指纹名分别设定: 泛化名词(易单信号误报)设 >=2 压误报,
    #   稀有框架(强标记但规则多)可设 1 放松召回。缺省 None = 走全局默认阈值。
    confirm_min_hits: Optional[dict] = None
    annotations: List[str] = field(default_factory=list)      # B5: 报告标签


# 稀疏注册表: 只给需要特殊处理的栈写条目。键是 fingerprint_target 返回的指纹名。
FP_BASELINES = {
    # ---------- WAF / 防护 (catchall_mode=WAF_BLOCK) ----------
    'WAF':          BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护']),
    'AWS-WAF':      BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护']),
    'Cloudflare':   BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护(CDN)']),
    'Imperva':      BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护']),
    'F5':           BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护']),
    '安全狗':         BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护']),
    '长亭':           BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护']),
    '创宇盾':         BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护']),
    '360网站卫士':    BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护']),
    'Sucuri':       BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护']),
    'Barracuda':    BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护']),
    'Wallarm':      BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护']),
    '百度云加速':      BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护(CDN)']),
    'ModSecurity':  BaselineProfile(catchall_mode='WAF_BLOCK', annotations=['前方 WAF/防护']),

    # ---------- 前端框架 / SPA (catchall_mode=SPA_INDEX) ----------
    'Nuxt':         BaselineProfile(catchall_mode='SPA_INDEX', annotations=['SPA 前端']),
    'Vue':          BaselineProfile(catchall_mode='SPA_INDEX', annotations=['SPA 前端']),
    'Next.js':      BaselineProfile(catchall_mode='SPA_INDEX', annotations=['SPA 前端']),
    'Angular':      BaselineProfile(catchall_mode='SPA_INDEX', annotations=['SPA 前端']),
    'SvelteKit':    BaselineProfile(catchall_mode='SPA_INDEX', annotations=['SPA 前端']),
    'Qwik':         BaselineProfile(catchall_mode='SPA_INDEX', annotations=['SPA 前端']),
    'Remix':        BaselineProfile(catchall_mode='SPA_INDEX', annotations=['SPA 前端']),
    'Alpine.js':    BaselineProfile(catchall_mode='SPA_INDEX', annotations=['SPA 前端']),
    'htmx':         BaselineProfile(catchall_mode='SPA_INDEX', annotations=['SPA 前端']),

    # ---------- CMS (catchall_mode=CMS_404) ----------
    'WordPress':    BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Drupal':       BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Joomla':       BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Discuz!':      BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'DedeCMS':      BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'PHPCMS':       BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'EmpireCMS':    BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Typecho':      BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Z-Blog':       BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Magento':      BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'PrestaShop':   BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'OpenCart':     BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Ghost':        BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'TYPO3':        BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Plone':        BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Craft CMS':    BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'OctoberCMS':   BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Umbraco':      BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Sitecore':     BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Squarespace':  BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Wix':          BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'Webflow':      BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),
    'HubSpot CMS':  BaselineProfile(catchall_mode='CMS_404', annotations=['CMS 暴露面']),

    # ---------- 后端框架 (catchall_mode=API_JSON_404 + B2 已知端点) ----------
    'Spring-Boot':  BaselineProfile(catchall_mode='API_JSON_404', annotations=['Spring 管理面']),
    'Spring-Cloud-Alibaba': BaselineProfile(catchall_mode='API_JSON_404',
                                            annotations=['Spring 管理面']),
    'Spring-Security': BaselineProfile(catchall_mode='API_JSON_404',
                                       annotations=['Spring 管理面']),
    'Django':       BaselineProfile(catchall_mode='API_JSON_404', annotations=['Django 管理面']),
    'Laravel':      BaselineProfile(catchall_mode='API_JSON_404', annotations=['Laravel 管理面']),
    'ThinkPHP':     BaselineProfile(catchall_mode='API_JSON_404', annotations=['ThinkPHP 管理面']),
}


# B4 静态确认阈值表(按指纹名直接查, **不依赖当前命中**, 避免循环依赖)
# 值 = 该指纹"确认成立"所需的最少命中信号数(count, 即 _score_rules 的 score),
#   覆盖全局比例阈值 FP_HIT_THRESHOLD=0.3。
#   · 泛化名词(易单信号误报): 设 >=2 → 需 ≥2 条独立规则命中才确认, 压误报。
#   · 稀有框架(强标记但规则多): 未来可设 1 → 比例不足(如 1/5=0.2)也能确认(放松召回)。
# 本表由 get_confirm_overrides() 作为主来源注入 fingerprint_target / fingerprint_from_js;
# 与 profile 里的栈条件覆盖合并(取较大值), 二者不冲突。
FP_CONFIRM_MIN_HITS = {
    # 功能型指纹: 单条 body 规则是常见路径词, 巧合命中即误报(其规则数<=3,
    # 单条命中比例已 >=0.3, 全局阈值本就会确认 —— 故需 B4 把"确认门槛"抬到 >=2 条信号)。
    'OAuth2': 2,   # /oauth/·/auth/·/login/oauth: /auth/ 极常见, 单条不可靠
    'SSO':    2,   # /sso/·/cas/·/saml/: 单条 /sso/ 不足以定性
    # Admin-Panel 此前**缺席**本表 —— 模块头宣称"Admin-Panel/OAuth2 等泛化名词 ≥2 条
    #   信号才确认", 实现却只覆盖 OAuth2/SSO(全库审计 M20: 文档承诺未兑现)。
    'Admin-Panel': 2,   # /admin·/manage·/dashboard·/console: 后台词常见于普通业务路径
}


def get_baseline_profile(fingerprint_hits: List[str]) -> BaselineProfile:
    """合并多个指纹命中的基线配置(宁严勿漏)。

    · catchall_mode    取**首个**非空(优先级: 命中顺序靠前的栈决定基线的"形状")
    · confirm_min_hits 取**逐键最大**(按指纹名分别取更严者)
    · annotations      取并集(去重)

    注: 原 `probe_targets`(栈已知路径)**已移除** —— 它与数据层 `HIDDEN_PATHS_BY_STACK`
    重复, 且其专用探测与数据驱动的 `hidden_probe` 功能重叠。栈专属路径现由 `hidden_probe`
    (指纹门控 + 数据层)统一处理。
    """
    mode: Optional[str] = None
    confirm: dict = {}
    anns: List[str] = []
    for name in fingerprint_hits:
        p = FP_BASELINES.get(name)
        if not p:
            continue
        if mode is None and p.catchall_mode:
            mode = p.catchall_mode
        if p.confirm_min_hits:
            for k, v in p.confirm_min_hits.items():
                confirm[k] = max(confirm.get(k, 0), v)
        for a in p.annotations:
            if a not in anns:
                anns.append(a)
    return BaselineProfile(
        catchall_mode=mode,
        confirm_min_hits=confirm or None,
        annotations=anns,
    )


def get_confirm_overrides(profile=None) -> dict:
    """B4 主入口: 返回 {指纹名: 确认所需最少命中信号数} 合并表。

    来源: 静态 FP_CONFIRM_MIN_HITS(主) + profile 里的栈条件覆盖(取较大值)。
    profile 为 None / 无覆盖时退化为仅静态表 —— 因此即便在**首次**
    fingerprint_target 调用(此时 profile 尚未生成)也能正确生效, 无循环依赖。
    """
    out = dict(FP_CONFIRM_MIN_HITS)
    pc = None
    if isinstance(profile, BaselineProfile):
        pc = profile.confirm_min_hits
    elif isinstance(profile, dict):
        pc = profile.get('confirm_min_hits')
    if pc:
        for k, v in pc.items():
            out[k] = max(out.get(k, 0), v)
    return out


# 注: 原 `get_probe_targets()` 已移除(其数据源 `probe_targets` 已删除; 且调用方从未使用)。
