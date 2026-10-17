# -*- coding: utf-8 -*-
"""JS 词法小工具（注释剥离 / 括号扫描 / 字面量 / 顶层分割） —— 从 `core/engine.py` 拆出（便于维护）。"""
import re

from .const import _REGEX_PREV_CHARS, _REGEX_PREV_WORDS


# ---------- 参数关联提取 ----------
def _stmt_span(text, start, end, max_span=200):
    """返回 [start,end) 所在**语句**的边界 

    以 `;` / `}` / 换行 为界向前后收敛, 且单侧最多展开 max_span 字符。
    用于把"调用点上下文"限制在当前语句内, 避免跨越到相邻调用点。
    """
    lo = max(0, start - max_span)
    seg_lo = lo
    for sep in ('\n', ';', '}'):
        i = text.rfind(sep, lo, start)
        if i > seg_lo:
            seg_lo = i
    hi = min(len(text), end + max_span)
    seg_hi = hi
    for sep in ('\n', ';', '}'):
        i = text.find(sep, end, hi)
        if i != -1 and i < seg_hi:
            seg_hi = i
    return seg_lo, seg_hi


# ---------- JS 深度分析主引擎 ----------
def _strip_comments_safe(text):
    """安全剔除 JS 注释: 先保护字符串 → 剔除 // → 保护正则 → 剔除 /* */ → 恢复
    防止注释中的示例文字触发敏感信息误报 """
    placeholders = []
    def protect(m):
        placeholders.append(m.group(0))
        return '\x00{}\x00'.format(len(placeholders) - 1)

    # 0. 输入净化(碰撞防护, 审计 L): 原文若恰好含 `\x00<数字>\x00` 序列, 恢复阶段会被
    #   误当占位符替换掉。JS 里出现裸 NUL 本就非法 → 在**任何占位符产生之前**剔除。
    #   (必须放在这里: 放到恢复阶段会把待还原的真占位符一起删光。)
    text = re.sub(r'\x00\d+\x00', '', text)

    # 1. 保护字符串/模板串（最优先，防止内容被误伤）
    text = re.sub(r'`(?:\\.|[^`\\])*`', protect, text)
    text = re.sub(r'"(?:\\.|[^"\\])*"', protect, text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", protect, text)

    # 2. 剔除单行注释（字符串已保护，不会误伤 URL/字符串中的 //）
    text = re.sub(r'//.*', '', text)

    # 3. 保护正则字面量（// 已剔除，只剩真正的正则；排除 /* 开头避免误伤多行注释）
    text = re.sub(r'/(?!\*)(?:\\.|[^/\n\\])+/(?:[gimuy]*)', protect, text)

    # 4. 剔除多行注释（正则已保护，不会误伤正则内的 /*）
    text = re.sub(r'/\*[\s\S]*?\*/', '', text)

    # 5. 恢复占位符
    text = re.sub(r'\x00(\d+)\x00', lambda m: placeholders[int(m.group(1))], text)
    return text


def _line_of(text, sub):
    """返回 sub 在 text 中首次出现的 (line, col) [1-based]; 未找到返回 None

    用于把每条提取到的接口/参数定位回源文件"file:line:col"(方案 §1 原则3 / §8 / §9)。
    对"派生"结果(拼接/归一化, 文本中不存在字面量)返回 None, 调用方据此标记为"派生(无精确行)"。
    """
    if not sub:
        return None
    idx = text.find(sub)
    if idx < 0:
        return None
    _nl = text.rfind('\n', 0, idx)
    _line = text.count('\n', 0, idx) + 1
    _col = idx - (_nl + 1) + 1
    return (_line, _col)


# ---------- 命中代码窗口 / finding 来源定位(报告折叠面板数据源) ----------

def code_window(text, sub, before=100, after=120, cap=600):
    """命中代码端: 取 `sub` 首次命中处的**上下文窗口**(供报告折叠面板展示)。

    与 `_line_of` 同源(`text.find` 首次命中) —— 对压缩/单行 bundle, "整行"即整个文件,
    按行列取行毫无意义, 故改为按**偏移量窗口**截取调用现场; 多行格式化源码同样可用。
    超 `cap` 截断并补省略号; 纯字符串切片, 零执行零发包。
    """
    idx = (text or '').find(sub)
    if idx < 0:
        return None
    start = max(0, idx - before)
    end = min(len(text), idx + len(sub) + after)
    seg = text[start:end]
    if start > 0:
        seg = '…' + seg
    if end < len(text):
        seg = seg + '…'
    if len(seg) > cap:
        seg = seg[:cap] + '…'
    return seg


def probes_from_evidence(ev):
    """从 finding evidence 里抽取**定位探针**候选(按优先级):

    ① 反引号 `token` / 引号 "token" 包裹的字面量; ② 长度 ≥6 的 ASCII 词法 token
    (路径/密钥/标识符形状 —— 纯中文散文不会产生候选, 也就不会误定位)。
    调用方按序对 JS 原文 `find`, 第一个命中的即采纳。
    """
    import re as _re
    out = []
    for m in _re.findall(r'`([^`]{4,160})`', ev or ''):
        out.append(m)
    for m in _re.findall(r'"([^"]{4,160})"', ev or ''):
        out.append(m)
    for m in _re.findall(r'\b([A-Za-z0-9_\-/\.]{6,160})\b', ev or ''):
        # 纯数字/版本串不足以定位; 中文说明句里的英文词多属叙述, 仅作兜底
        out.append(m)
    return out


def note_finding_loc(ctx, key, text, probes):
    """给一条 finding 记录**来源代码定位**(供报告「完整发现清单」按接口清单同款展开)。

    key = (sev, typ, url, ev) 4 元组(与 `ctx.add_finding` 去重键一致, 报告侧同键查表);
    text = 命中时的 JS/源码原文; probes = 精确定位字面量候选(如密钥串/命中 token, 按序试)。
    定位失败(派生/文本里找不到字面量)时**不记** —— 报告侧对无定位 finding 如实显示
    「无精确源码位置」。存 `ctx.finding_loc`(scan 级, 与 findings 同在 ctx, 无需 merge)。
    纯静态, 零发包。
    """
    if not probes or not text:
        return
    m = getattr(ctx, 'finding_loc', None)
    if m is None:
        m = {}
        ctx.finding_loc = m
    if key in m:
        return
    for p in probes:
        if not p or len(str(p)) < 3:
            continue
        lc = _line_of(text, str(p))
        if not lc:
            continue
        m[key] = {'src': key[2], 'line': lc[0], 'col': lc[1],
                  'probe': str(p), 'snippet': code_window(text, str(p))}
        return


def _regex_literal_end(text, i):
    """text[i]=='/'; 判断此处是否为**正则字面量**起点。

    是则返回该字面量的结束下标(不含); 否则 None。用于避免把正则内部的 `/` 误判成注释。
    起点判定用标准启发式: 前一个有效字符是运算符/开括号, 或是 return/typeof 等关键字。
    """
    j = i - 1
    while j >= 0 and text[j] in ' \t\r\n':
        j -= 1
    if j < 0:
        return None
    pc = text[j]
    ok = pc in _REGEX_PREV_CHARS
    if not ok and (pc.isalnum() or pc in '_$'):
        k = j
        while k >= 0 and (text[k].isalnum() or text[k] in '_$'):
            k -= 1
        ok = text[k + 1:j + 1] in _REGEX_PREV_WORDS
    if not ok:
        return None
    k, in_class = i + 1, False
    while k < len(text):
        c = text[k]
        if c == '\\':
            k += 2
            continue
        if c == '\n':
            return None                      # 正则字面量不能跨行 → 判定失败
        if c == '[':
            in_class = True
        elif c == ']':
            in_class = False
        elif c == '/' and not in_class:
            return k + 1
        k += 1
    return None


def _strip_js_comments(text, _braces=None):
    """去掉 // 单行与 /* */ 块注释, 降低结构提取的注释误命中。

    **字符串/正则感知** —— 旧实现是两行朴素正则, 在**压缩成单行**的产物上会灾难性误删:
      `re.sub(r'//[^\\n]*', ' ')` 里的 `[^\\n]*` 在无换行的 bundle 中会一路吃到 EOF。
      文件里第一个 `//` 往往出现在**字符串内部**(如 `"https://api.example.com"`),
      实测某 SPA 的 157KB 单行 bundle 被砍到 5.9KB(**丢失 96%**), 使其后所有结构化
      提取通道静默失效(接口主链因此整体归零, 却毫无报错)。
    本实现逐字符扫描, 只在"代码态"识别注释起始, 并原样保留字符串/模板串/正则字面量。

    参数:
      _braces —— 可选 dict; 传入时**顺带**填入代码态括号表(坐标基于**剥离后的文本**),
        键为 `opens` / `depth_at_open` / `close_by_depth`。
        合并两遍扫描的原因: `_extract_struct_apis` 既要去注释、又要建括号表(供形参作用域
        判定), 二者都是全文逐字符扫描 —— 分开做要扫两遍(3.5MB 语料上实测差约 2s)。
    """
    if _braces is not None:
        _braces.setdefault('opens', [])
        _braces.setdefault('depth_at_open', {})
        _braces.setdefault('close_by_depth', {})
        _braces.setdefault('depth', 0)
    elif '//' not in text and '/*' not in text:
        return text
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in '"\'' or c == '`':           # 字符串 / 模板字符串: 整体原样保留
            q = c
            out.append(c)
            i += 1
            while i < n:
                c2 = text[i]
                out.append(c2)
                if c2 == '\\':
                    if i + 1 < n:
                        out.append(text[i + 1])
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
                if c2 == q:
                    break
            continue
        if c == '/':
            nxt = text[i + 1] if i + 1 < n else ''
            if nxt == '/':                   # 单行注释
                while i < n and text[i] != '\n':
                    i += 1
                out.append(' ')
                continue
            if nxt == '*':                   # 块注释
                j = text.find('*/', i + 2)
                i = n if j < 0 else j + 2
                out.append(' ')
                continue
            _rend = _regex_literal_end(text, i)
            if _rend is not None:            # 正则字面量: 原样保留
                # 用 extend 而非 append —— 保证 out 里**每个元素都是单字符**,
                #   这样 `len(out)` 就等于已产出的字符数(括号表坐标依赖这一点)。
                out.extend(text[i:_rend])
                i = _rend
                continue
        if _braces is not None and c == '{':
            _braces['depth'] += 1
            _p = len(out)
            _braces['opens'].append(_p)
            _braces['depth_at_open'][_p] = _braces['depth']
        elif _braces is not None and c == '}':
            _braces['close_by_depth'].setdefault(_braces['depth'], []).append(len(out))
            _braces['depth'] -= 1
        out.append(c)
        i += 1
    return ''.join(out)


def _scan_braces(text):
    """单独扫一遍括号表 —— 供 `_build_param_scopes` 独立使用(测试/回退路径)。

    正常路径下 `_build_param_scopes` 直接复用 `_strip_js_comments` 顺手产出的括号表,
    不再走这里。
    """
    b = {}
    _strip_js_comments(text, b)
    return b['opens'], b['depth_at_open'], b['close_by_depth']


def _unquote_lit(s):
    """去掉引号并反转义, 返回内部字符串; 非引号包裹返回原样"""
    if len(s) >= 2 and s[0] in '"\'' and s[-1:] == s[0]:
        inner = s[1:-1]
        # **顺序重要**: `\uXXXX`/`\xNN` 还原必须**先于** `\\`→哨兵替换 ——
        # 否则反斜杠全被哨兵吃掉, `\uXXXX` 就再也还原不了(曾踩)。
        if '\\u' in inner or '\\x' in inner:
            import re as _re_u

            def _unesc(m):
                s = m.group(0)
                try:
                    return chr(int(s[2:], 16))
                except (ValueError, OverflowError):
                    return s
            inner = _re_u.sub(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}', _unesc, inner)
        inner = (inner.replace('\\', '\x00').replace('\\"', '"')
                       .replace("\\'", "'").replace('\\n', '\n').replace('\\t', '\t')
                       .replace('\\/', '/')
                       .replace('\x00', '\\'))
        return inner
    return s


# ---------- 路径"碎片数组"拼接的公共判据（单一真源） ----------
#   `js_extract` 的数组 join 通道(`['/api','v1','users'].join('/')`)与 `deobf` 的碎片数组
#   拼接(`unpack_string_array`)共用同一组 **HTTP 方法令牌** —— 单一真源, 避免两处各写一份漂移。
HTTP_METHOD_TOKENS = frozenset(('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'))


def has_http_method_element(elements):
    """一组字符串元素中是否含**裸 HTTP 方法**(GET/POST/…)。

    含则把整组元素 join 成路径必然产出"路径 + 方法"垃圾 —— 如 `['/api/orders','POST']`
    会被拼成 `/api/ordersPOST`, 该垃圾会经**上下文无关提取**进入 `extracted_endpoints`
    (污染端点清单 / 白费探活请求)。故任何"数组元素 join 成路径"的通道在拼接前都须先过本判据。
    """
    for s in (elements or ()):
        if str(s or '').strip().upper() in HTTP_METHOD_TOKENS:
            return True
    return False


def _split_top_level_plus(expr):
    """在顶层 + 处切分(不切字符串字面量内部的 +)"""
    parts, cur, in_str, q = [], '', False, ''
    i = 0
    while i < len(expr):
        c = expr[i]
        if in_str:
            cur += c
            if c == '\\' and i + 1 < len(expr):
                cur += expr[i + 1]
                i += 2
                continue
            if c == q:
                in_str = False
            i += 1
            continue
        # **模板串(反引号)也算字符串态**: 此前只认 `"`/`'`, 模板表达式里的
        #   `/a/${x}+y` 被当顶层加号切开 → 各段解析失败、整条拼接链静默漏抓(审计 M)。
        if c in '"\'`':
            in_str = True
            q = c
            cur += c
            i += 1
            continue
        if c == '+':
            parts.append(cur.strip())
            cur = ''
            i += 1
            continue
        cur += c
        i += 1
    if cur.strip():
        parts.append(cur.strip())
    return parts
