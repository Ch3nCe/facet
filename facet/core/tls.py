# -*- coding: utf-8 -*-
"""TLS 证书 + 安全响应头审计 —— 从 `core/engine.py` 拆出（便于维护）。"""
import os
import re
import socket
import ssl
import tempfile
import traceback
from datetime import datetime, timezone
from urllib.parse import urlsplit

from facet.core.log import log

from .const import INFO_LEAK_HEADERS, SECURITY_HEADERS


def _tls_cert_info(ctx, base):
    """提取目标 TLS 证书信息(颁发者/有效期/SAN), 零 HTTP 请求

    实现: 做一次裸 TLS 握手拿 DER 证书(不发任何 HTTP 请求), 再用标准库解码。
    证书校验关闭(与整体扫描口径一致), 仅作信息提取。
    """
    if not str(base).lower().startswith('https://'):
        return None
    host = port = None
    try:
        sp = urlsplit(base)
        host, port = sp.hostname, (sp.port or 443)
    except Exception:
        return None
    if not host:
        return None
    der = None
    try:
        cctx = ssl.create_default_context()
        cctx.check_hostname = False
        cctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port),
                                      timeout=ctx.config.get('timeout', 10)) as sock:
            with cctx.wrap_socket(sock, server_hostname=host) as ssock:
                # verify_mode=CERT_NONE 时 getpeercert() 返回 {} —— 必须取 binary_form
                der = ssock.getpeercert(binary_form=True)
    except Exception as e:
        if ctx.config.get('debug'):
            traceback.print_exc()
        log(f'[-] TLS 握手失败({host}:{port}): {e}')
        return None
    if not der:
        return None
    cert = _decode_der_cert(der)
    if not cert:
        return None
    issuer = dict(x[0] for x in cert.get('issuer', []) if x)
    subject = dict(x[0] for x in cert.get('subject', []) if x)
    sans = [v for k, v in cert.get('subjectAltName', []) if k == 'DNS']
    info = {'issuer': issuer, 'subject': subject, 'san': sans,
            'not_before': cert.get('notBefore'), 'not_after': cert.get('notAfter')}
    ctx.tls_cert = info
    # 注: 不再把"颁发者 / 有效期"加为 INFO finding —— 去重: 证书信息已由 ctx.tls_cert 承载,
    #   在「扫描完整性」章节与 JSON `completeness.tls` 各呈现一次, 再列成 finding 属重复。
    _audit_tls_cert(ctx, base, info, issuer, subject)
    # SAN 子域: 与目标主域不同的条目才有发现价值
    base_host = (host or '').lower()
    extra = sorted({s for s in sans
                    if s and not s.startswith('*')
                    and s.lower() != base_host
                    and not base_host.endswith('.' + s.lower())})
    if extra:
        # SAN 是证书**公开字段**(任何 TLS 握手都能看到), 属信息性披露而非风险 →
        #   INFO(旧为 MED, 实测每个 HTTPS 站点都命中, 属噪声)。
        ctx.add_finding('INFO', f'TLS SAN 披露子域 ({len(extra)})', base,
                        ', '.join(extra[:12])[:200])
    log(f'[*] TLS: 颁发者 {issuer.get("commonName", "?")} | SAN {len(sans)} 条')
    return info


def _parse_cert_time(s):
    """把证书时间(两种格式)解析成 **naive UTC** datetime; 失败返回 None

    证书里的 notBefore/notAfter 有两种写法:
      · `Jun  1 12:00:00 2025 GMT`  —— OpenSSL 传统格式
      · `2025-06-01T12:00:00Z`      —— RFC 3339

    ⚠️ OpenSSL 格式**不能用 `strptime('%b …')`** —— `%b` 依赖进程 `LC_TIME` locale,
    在非英文 locale(zh_CN / de_DE / ja_JP…)下解析 'Jun' 会失败 → 返回 None →
    **证书过期审计静默失效(漏报"已过期" HIGH)**。改用 `email.utils`(对英文月份名 locale 无关)。
    """
    if not s:
        return None
    s = str(s).strip()
    # OpenSSL 传统格式 —— locale 无关解析
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(s)
        if dt is not None:
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
    except Exception:
        pass
    # RFC 3339(无 `%b`, locale 无关)
    for fmt in ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _audit_tls_cert(ctx, base, info, issuer, subject):
    """TLS 证书有效性审计(零额外请求 —— 数据在握手时已经拿到)

    """
    # 用 naive UTC 与解析出的证书时间(也是 UTC)比较。
    #   `datetime.utcnow()` 在 3.12+ 已弃用, 这里用带时区的 now() 再摘掉 tzinfo。
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    nb = _parse_cert_time(info.get('not_before'))
    na = _parse_cert_time(info.get('not_after'))
    if na is not None:
        days = (na - now).days
        if days < 0:
            ctx.add_finding('HIGH', 'TLS 证书已过期', base,
                            f'{info.get("not_after")} (已过期 {abs(days)} 天)')
        elif days <= 30:
            ctx.add_finding('MED', 'TLS 证书即将过期', base,
                            f'{info.get("not_after")} (剩余 {days} 天)')
    if nb is not None and nb > now:
        ctx.add_finding('MED', 'TLS 证书尚未生效', base, str(info.get('not_before')))
    # 自签: 颁发者与主体完全相同(比较常用字段, 全字典比较会被无关字段差异干扰)
    keys = ('commonName', 'organizationName', 'countryName')
    iss_sig = tuple((k, (issuer or {}).get(k)) for k in keys)
    sub_sig = tuple((k, (subject or {}).get(k)) for k in keys)
    if iss_sig == sub_sig and any(v for _, v in iss_sig):
        ctx.add_finding('MED', 'TLS 证书为自签', base,
                        f'issuer==subject: {(subject or {}).get("commonName", "?")}')


def _decode_der_cert(der):
    """DER 证书 → dict。优先用标准库解码器, 失败则返回 None(不抛异常)

    `ssl._ssl._test_decode_cert` 是 CPython 的实现细节, 但在 3.7~3.13 全系可用;
    这里包一层防御, 因为"拿不到证书详情"不应影响整轮扫描。
    """
    tmp = None
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, tmp = tempfile.mkstemp(suffix='.pem')
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(pem)
        return ssl._ssl._test_decode_cert(tmp)
    except Exception:
        return None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _audit_security_headers(ctx, base, r):
    """安全响应头审计(零额外请求: 直接复用主页响应)

    。缺失的头**合并为一条**发现项 —— 逐个头各报一条会让
    严重度分布被 6 条 MED/LOW 淹没, 而分析师真正需要的是"整体配置成熟度"这一句。
    """
    hdrs = {k.lower(): v for k, v in (getattr(r, 'headers', None) or {}).items()}
    is_https = base.lower().startswith('https://')
    missing, reasons, applicable = [], [], 0
    for name, desc, _sev, https_only in SECURITY_HEADERS:
        if https_only and not is_https:
            continue
        # 分母只计**本目标适用**的头 —— HTTP 站点上 HSTS 不适用, 计入分母会把比例算错
        #   (如 HTTP 目标全缺时报 "5/6", 实际应为 "5/5")。
        applicable += 1
        if name.lower() not in hdrs:
            missing.append(name)
            reasons.append(f'{name}({desc})')
    if missing:
        ctx.add_finding('MED' if len(missing) >= 3 else 'LOW',
                        f'安全响应头缺失 ({len(missing)}/{applicable})',
                        base, '; '.join(reasons)[:200])
    for name, desc in INFO_LEAK_HEADERS:
        v = hdrs.get(name.lower())
        if v:
            _d = desc
            # 版本感知: Server/X-Powered-By 等仅在**确含版本号**时才称"暴露版本",
            # 否则会夸大(如实测 `Server: nginx` 无版本却写"与版本")。
            if name == 'Server' and not re.search(r'[/\\s](?:v)?\d', str(v)):
                _d = '暴露服务端软件（未暴露版本号）'
            ctx.add_finding('LOW', f'响应头信息泄露: {name}', base, f'{_d} → {str(v)[:60]}')
