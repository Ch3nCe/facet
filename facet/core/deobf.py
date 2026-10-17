# -*- coding: utf-8 -*-
"""JS 反混淆 / 解码层 —— 从 `core/engine.py` 拆出（便于维护）。

职责：把混淆 / 压缩过的 JS 还原为**可提取**的文本 —— 只做**静态替换/解码**，不执行任何代码。
  · decode_layer        —— `unicode_escape` + `atob(base64)` 解码
  · _decode_js_escapes  —— `\\xHH` / `\\uHHHH` / `\\u{...}` / `\\/` 转义还原（稳健，不崩 UTF-8）
  · unpack_string_array —— javascript-obfuscator `_0x` 字符串数组还原（含自定义 prefix /
                           常量下标折叠 / 字符串字面量拼接折叠 / 数字数组fromCharCode解码）
  · _beautify_js        —— jsbeautifier 反压缩（可选）
  · deobfuscate_strong  —— **opt-in 强反混淆**：Node + webcrack（静态 AST 反混淆 / 拆包）
                           + VM/字节码零宽剥离·转义解码。默认扫描**不**调用，需显式启用。

依赖：仅标准库（re / base64 / ast / os）+ 可选 `jsbeautifier`。强反混淆层额外依赖
第三方 Node 工具（webcrack），故默认关闭。**不依赖 engine 其它函数**，故可独立成模块。

合规红线：默认扫描管线（`unpack_string_array` / `_decode_js_escapes` / `_beautify_js`）
保持**纯静态、只读、绝不执行目标代码**。`deobfuscate_strong` 也是静态分析（不 eval /
不运行目标逻辑），但依赖第三方工具，故仅作 opt-in 强反混淆，不影响默认扫描。
"""
import ast
import base64
import os
import re

from . import nodeenv

try:
    import jsbeautifier
except Exception:
    jsbeautifier = None

from .procutil import run_capture


# 解码层
def decode_layer(text):
    out = text
    # **只在纯 ASCII 文本上**跑 `unicode_escape`。
    #   原因（实测缺陷）：`str.encode()` 得到 **UTF-8 字节**，而 `unicode_escape` 按
    #   Latin-1 逐字节解码 → 含非 ASCII 的文本被**静默转成乱码**且**不抛异常**
    #   （`微卡回报信息查询` → `å¾®å¡æ¥æ¯æ¥è¯¢`），所以 try/except 兜不住。
    #   后果是整条 JS 分析管线的**中文内容全部损坏**（业务标签 / i18n / 中文注释 / 中文参数），
    #   直到"从源码取目标自述业务名"时才暴露。
    #   非 ASCII 文本的转义还原交给 `_decode_js_escapes`（定向正则，按字符还原，不崩 UTF-8；
    #   它已在 deep_analyze 入口对全部文本应用，故此处跳过不会丢能力）。
    if text.isascii():
        try:
            out = out.encode().decode('unicode_escape')
        except Exception:
            pass
    for m in re.findall(r'(?:atob\(["\'])([A-Za-z0-9+/=]{40,})["\']', text):
        try:
            out += '\n' + base64.b64decode(m).decode('utf-8', 'ignore')
        except Exception:
            pass
    return out


# §4.2 转义解码回填（方案「处理阶梯」步骤1-2）
#   背景：decode_layer 用 `unicode_escape` 解码，但它对含非 ASCII 的 UTF-8 JS 会抛异常
#   （被 try 吞掉）→ 转义序列从未还原，藏在 \xNN / \uNNNN 里的端点永远提取不到。
#   本函数用**定向正则**稳健解码，不依赖 unicode_escape，可在 UTF-8 文本上工作。
#   只解码"确实是转义"的序列（负向环视排除 `\\x` 这类已转义的），改的是字符本身，
#   不破坏 JS 结构；后续所有 URL/路径提取自动受益（无需单独再跑一遍）。
_JSESC_UNIB = re.compile(r'(?<!\\)\\u\{([0-9a-fA-F]{1,6})\}')
_JSESC_UNI = re.compile(r'(?<!\\)\\u([0-9a-fA-F]{4})')
_JSESC_HEX = re.compile(r'(?<!\\)\\x([0-9a-fA-F]{2})')


def _decode_js_escapes(s):
    r"""把 JS 字符串里的转义序列还原为真实字符（稳健，不崩 UTF-8）。

    还原对象：``\xHH`` / ``\uHHHH`` / ``\u{...}``（十六进制 Unicode 转义）以及
    JSON 风格的 ``\/``。仅做字符级还原，不改结构；返回解码后文本。
    不产生任何网络/执行行为。
    """
    if not s or '\\' not in s:
        return s

    def _cvt(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)
    s = _JSESC_UNIB.sub(_cvt, s)
    s = _JSESC_UNI.sub(_cvt, s)
    s = _JSESC_HEX.sub(_cvt, s)
    # JSON 风格转义：最小化的 JSON 路径里 ``\/`` → ``/``；还原被转义的字面引号
    s = s.replace('\\/', '/').replace('\\"', '"').replace("\\'", "'")
    return s


# 静态构造折叠 / 解码（安全静态，绝不执行目标代码）
#   对「纯字面量」做静态近似还原：常量下标折叠、字符串拼接折叠、
#   数字数组 fromCharCode 解码。任何涉及变量 / 函数 / 运行期行为的都不碰。
# 折叠结果允许的最大量级(2**63) —— 超过即放弃折叠: 下标语义下没有任何理由出现这种数,
#   而 `1 << 10**9` 这类移位与 `9**9**9` 这类幂运算都能把资源打满(目标可控输入)。
_FOLD_MAX_ABS = 2 ** 63

# 允许折叠的运算符 —— **白名单**(而非"排除危险运算符的黑名单")。
#   黑名单漏掉 `ast.Pow` 就让 `9**9**9` 被求值成天文数字整数(实测 CPU/内存放大):
#   混淆器下标算术只用到 `+ - * / % //`, 白名单不会有同类漏网。
_FOLD_BIN_OPS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod)
_FOLD_UNARY_OPS = (ast.UAdd, ast.USub)


def _fold_const_expr(expr):
    """安全地把纯字面量算术表达式折叠为整数。

    只对「整数常量 + 算术运算符（+ - * / % //）」组成的表达式求值；**任何**其它节点
    （变量名 / 函数调用 / 属性 / 下标 / 容器 / 幂运算 / 条件表达式 …）一律返回 None
    （那是运行期才能确定的，静态层不碰）。返回折叠后的 int，否则 None。
    """
    try:
        _tree = ast.parse(expr.strip(), mode='eval')
    except Exception:
        return None
    for _node in ast.walk(_tree):
        if isinstance(_node, ast.Expression):
            continue
        if isinstance(_node, ast.Constant):
            # 只要**非布尔整数**常量(浮点没有下标语义, 折叠了也用不上)
            if not isinstance(_node.value, int) or isinstance(_node.value, bool):
                return None
            continue
        if isinstance(_node, ast.BinOp):
            if not isinstance(_node.op, _FOLD_BIN_OPS):
                return None
            continue
        if isinstance(_node, ast.UnaryOp):
            if not isinstance(_node.op, _FOLD_UNARY_OPS):
                return None
            continue
        if isinstance(_node, (ast.operator, ast.unaryop)):
            continue                      # 由上面的 BinOp / UnaryOp 分支统一校验
        return None
    # 节点数上限: 畸形长表达式不做折叠(折叠是"顺手优化", 不值得为它承担任何放大风险)。
    if sum(1 for _ in ast.walk(_tree)) > 32:
        return None
    try:
        _val = eval(compile(_tree, '<fold>', 'eval'),
                    {'__builtins__': {}}, {})
    except Exception:
        return None
    if isinstance(_val, int) and not isinstance(_val, bool):
        # 结果量级兜底: 位数过多的整数没有下标语义(`1 << 10**9` 这类移位同样能放大),
        #   直接放弃折叠。
        return _val if abs(_val) <= _FOLD_MAX_ABS else None
    return None


_RE_ARR_INDEX_FOLD = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\[\s*([^\[\]]+?)\s*\]")
_RE_IDX_PURE = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+)$")


def _fold_constant_indices(code):
    """把 `_0xN[1 - 1]` 这种纯字面量算术下标折叠成 `_0xN[0]`（不碰变量下标）。"""
    def _rep(m):
        _name, _idx = m.group(1), m.group(2).strip()
        if _RE_IDX_PURE.match(_idx):
            return m.group(0)            # 已是字面量，交给主替换逻辑
        _v = _fold_const_expr(_idx)
        if _v is None:
            return m.group(0)
        return '%s[%d]' % (_name, _v)
    return _RE_ARR_INDEX_FOLD.sub(_rep, code)


_STR_LIT = r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
_RE_STR_CONCAT = re.compile(r"(" + _STR_LIT + r")\s*\+\s*(" + _STR_LIT + r")")


def _unquote_lit(tok):
    _q = tok[0]
    _inner = tok[1:-1]
    return _inner.replace('\\' + _q, _q).replace('\\\\', '\\')


def _fold_str_concat(code):
    """把 `'a' + 'b'` / `"a" + "b"` 这种纯字面量拼接折叠成单个字面量。

    只折叠「两侧都是字符串字面量」的 `+`；涉及变量的一侧不折叠（运行期才确定）。
    """
    _prev, _cur, _guard = None, code, 0
    while _prev != _cur and _guard < 1000:
        _prev = _cur

        def _rep(m):
            _a = _unquote_lit(m.group(1))
            _b = _unquote_lit(m.group(2))
            _merged = (_a + _b).replace('\\', '\\\\').replace("'", "\\'")
            return "'" + _merged + "'"
        _cur = _RE_STR_CONCAT.sub(_rep, _cur)
        _guard += 1
    return _cur


_RE_NUM_ARRAY = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*=\s*\[\s*(\d+(?:\s*,\s*\d+)*)\s*\]")
_RE_CHARMAP_FN = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.map\s*\(\s*function\s*\(\s*([A-Za-z_$]\w*)\s*\)\s*\{\s*"
    r"return\s+String\.fromCharCode\(\s*\2\s*\)\s*;?\s*\}\s*\)\.join\(\s*['\"]\s*['\"]?\s*\)", re.S)
_RE_CHARMAP_ARROW = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.map\s*\(\s*\(?\s*([A-Za-z_$]\w*)\s*\)?\s*=>\s*"
    r"String\.fromCharCode\(\s*\2\s*\)\s*\)\.join\(\s*['\"]\s*['\"]?\s*\)", re.S)
_RE_CHARCODE_CALL = re.compile(
    r"String\.fromCharCode\(\s*(\d+(?:\s*,\s*\d+)*)\s*\)")
# sojson.v4 / jsjiami.com：`String.fromCharCode.apply(null,"<数字+杂字母链>")`
#   链 = 一串 ASCII 码、用无关字母分隔（`"118h97x114w32…"` → 'v','a','r',' '…）。
#   属**明文数字编码**，静态可还原：只提取连续数字 → chr，绝不执行代码。
#   真实形态的链后可能直接跟 `['split'](/[a-zA-Z]{1,}/)`（把链按字母切成数字数组），
#   故**不要求**结尾紧跟 `)`；安全性由 `_decode_charcode_chain` 的形态校验兜底。
_RE_APPLY_CHAIN = re.compile(r'\(\s*null\s*,\s*["\']([0-9A-Za-z]{16,})["\']')


def _decode_char_arrays(code):
    """解码「数字数组 → 字符串」的两种静态形态（数字是明文编码，无需密钥）：

      · `ARR.map(function(x){return String.fromCharCode(x)}).join('')`  （ARR 为纯数字数组）
      · `ARR.map(x => String.fromCharCode(x)).join('')`
      · 独立的 `String.fromCharCode(n1, n2, ...)`

    把解码结果以注释字面量补回，使既有提取通道能拿到明文。绝不执行任何代码。
    """
    _num_arrays = {}
    for _m in _RE_NUM_ARRAY.finditer(code):
        try:
            _nums = [int(x) for x in _m.group(2).split(',') if x.strip()]
        except ValueError:
            continue
        if _nums and all(0 <= n <= 0x10FFFF for n in _nums):
            _num_arrays[_m.group(1)] = _nums
    _out = []
    for _rx in (_RE_CHARMAP_FN, _RE_CHARMAP_ARROW):
        for _m in _rx.finditer(code):
            _arr = _m.group(1)
            if _arr in _num_arrays:
                _s = ''.join(chr(n) for n in _num_arrays[_arr])
                if _s:
                    _out.append(_s)
    for _m in _RE_CHARCODE_CALL.finditer(code):
        try:
            _nums = [int(x) for x in _m.group(1).split(',') if x.strip()]
        except ValueError:
            continue
        if _nums and all(0 <= n <= 0x10FFFF for n in _nums):
            _s = ''.join(chr(n) for n in _nums)
            if _s:
                _out.append(_s)
    if _out:
        return code + '\n/*facet-deobf-char*/' + ' '.join(
            '"%s"' % _x.replace('"', '\\"') for _x in _out), len(_out)
    return code, 0


def _decode_charcode_chain(chain):
    """把「数字+杂字母」链还原为字符串；不是这种编码则返回 None（安全静态，不执行代码）。"""
    if not chain or not re.fullmatch(r'[0-9A-Za-z]+', chain):
        return None
    if not re.search(r'\d', chain) or not re.search(r'[A-Za-z]', chain):
        return None                       # 必须同时含数字(码)与字母(分隔符), 否则非此类编码
    try:
        _vals = [int(n) for n in re.findall(r'\d+', chain)]
    except ValueError:
        return None
    if not _vals or any(v > 0x10FFFF for v in _vals):
        return None
    _s = ''.join(chr(v) for v in _vals)
    _printable = sum(1 for c in _s if c.isprintable() or c in '\n\r\t')
    if _printable < len(_s) * 0.85:
        return None                       # 大部分须为可打印字符, 否则非此类编码
    return _s


def _decode_charcode_apply(code):
    """还原 `(null,"<数字+杂字母链>")` —— sojson.v4 / jsjiami.com 的 fromCharCode.apply 形态。

    把解码结果以字面量补回, 使既有提取通道拿到明文（含隐藏在其中的 flag/端点/密钥）。
    绝不执行任何代码。返回 (还原后代码, 解码条数)。
    """
    _decoded = []
    for _m in _RE_APPLY_CHAIN.finditer(code):
        _s = _decode_charcode_chain(_m.group(1))
        if _s:
            _decoded.append(_s)
    if not _decoded:
        return code, 0
    _blob = ' '.join('"%s"' % _x.replace('\\', '\\\\').replace('"', '\\"')
                     for _x in _decoded)
    return code + '\n/*facet-deobf-charcode*/' + _blob, len(_decoded)


# 扫描管线的**廉价门控预检**：从 `_0x` 放宽到本形态时用（链要求 ≥64 位字母数字，
#   避免误触发普通 `(null,"短串")`；sojson/jsjiami 的链动辄数千位）。
_RE_APPLY_CHAIN_GATE = re.compile(r'\(\s*null\s*,\s*["\'][0-9A-Za-z]{64,}["\']')


def has_charcode_apply(text):
    """文本是否含 sojson.v4 / jsjiami.com 的 `(null,"<长数字链>")` 形态(廉价预检)。"""
    return bool(text) and _RE_APPLY_CHAIN_GATE.search(text) is not None


# 字符串数组解包（方案 4.3）：javascript-obfuscator 的 `_0x…` 字符串数组还原
#   只做**静态替换 / 解码**（含自定义 prefix 结构识别、常量下标折叠、字符串拼接
#   折叠、数字数组 fromCharCode 解码），**不执行任何代码**；还原后交给既有提取
#   通道（正则 + 结构化）。
_RE_STR_ARRAY = re.compile(r"([A-Za-z_$][\w$]*)\s*=\s*\[((?:\s*(?:'[^']*'|\"[^\"]*\")\s*,?)+)\s*\]")
_RE_STR_ELEM = re.compile(r"'([^']*)'|\"([^\"]*)\"")
_RE_ARR_INDEX = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]")
# 包装函数两种写法都要认：具名 `function _0x(i){return arr[i]}` 与
#   匿名赋值 `var _0x = function(i){return arr[i]}`（实测混淆器两种都用）。
_RE_WRAPPER_FN = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)|(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*function)"
    r"\s*\(\s*([A-Za-z_$]\w*)\s*\)\s*\{\s*return\s+([A-Za-z_$][\w$]*)\s*\[\s*\3\s*\]\s*;?\s*\}")
_RE_WRAPPER_CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
# ---- 强化：javascript-obfuscator 的另两种常见形态 ----
# ① 数组"提供函数"：`function _0xF(){const _0xA=[...];_0xF=function(){return _0xA;};return _0xF();}`
#    —— 数组在函数内定义并由函数返回（旧实现只认顶层 `_0xA=[...]`，漏掉这种）。
_RE_ARRAY_PROVIDER = re.compile(
    r"function\s+([A-Za-z_$][\w$]*)\s*\(\s*\)\s*\{\s*"
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\[")
# ② "偏移式自我重写包装"：
#    `function _0xW(...){const _0xV=_0xF();return _0xW=function(x,...){x=x-0xOFF;let r=_0xV[x];return r;},...}`
#    —— 索引带**偏移**（x-OFF）且包装函数自我重写；旧实现只认 `function _0xW(i){return arr[i]}`。
_RE_WRAP_OFFSET = re.compile(
    r"function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{\s*"
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\(\s*\)\s*;\s*"
    r"return\s+\1\s*=\s*function\s*\(\s*([A-Za-z_$]\w*)\s*,[^)]*\)\s*\{\s*"
    r"\4\s*=\s*\4\s*-\s*(0x[0-9a-fA-F]+|\d+)", re.S)
# 旋转（强化）：括号形态 `_0xA['push'](_0xA['shift']())` —— 旧实现只认 `_0xA.push(_0xA.shift())`。
_RE_ROT_BRACKET = re.compile(
    r"([A-Za-z_$]\w*)\s*\[\s*['\"]push['\"]\s*\]\s*\(\s*\1\s*\[\s*['\"]shift['\"]\s*\]\s*\(\s*\)\s*\)")


def unpack_string_array(code):
    """还原 javascript-obfuscator 的**字符串数组**（方案 4.3 第一步）。

    处理：① `_0x…=[…]` 数组定义；② **数组旋转**（`(function(a,n){…a.push(a.shift())…})(arr,n)`）；
          ③ `arr[0x1]` 直接索引；④ 包装函数 `function _0x…(i){return arr[i]}` 的调用 `_0x…(0x2)`；
          ⑤ 数组"提供函数"；⑥ 偏移式自我重写包装；⑦ 包装函数本地别名；⑧ 碎片数组拼接。
    **只做静态替换 / 解码（含自定义 prefix 结构识别、常量下标折叠、字符串拼接折叠、数字数组 fromCharCode 解码），不执行任何代码**。返回 (还原后代码, 替换次数)。
    """
    if not code:
        return code, 0
    # 预通行：纯字面量常量下标折叠 / 字符串字面量拼接折叠（静态，不执行代码）
    code = _fold_constant_indices(code)
    code = _fold_str_concat(code)
    # 数字数组 fromCharCode 解码（即便没有字符串数组也照常解码）
    code, _n_char = _decode_char_arrays(code)
    # sojson.v4 / jsjiami.com：`fromCharCode.apply(null,"<数字+杂字母链>")` 形态（同上, 独立解码）
    code, _n_chain = _decode_charcode_apply(code)
    _n_pre = _n_char + _n_chain            # 预通行(非数组)的还原计数 —— 计入总返回, 否则调用方不采用
    _arrays = {}
    for _m in _RE_STR_ARRAY.finditer(code):
        _name = _m.group(1)
        _elems = [(a if a is not None else b) for a, b in _RE_STR_ELEM.findall(_m.group(2))]
        if len(_elems) >= 2:
            _arrays[_name] = _elems
    if not _arrays:
        return code, _n_pre
    # 数组"提供函数"：`function _0xF(){const _0xA=[…];…}` → `_0xF` → `_0xA`（数组名）。
    _prov = {}
    for _m in _RE_ARRAY_PROVIDER.finditer(code):
        _prov[_m.group(1)] = _m.group(2)
    # 数组旋转：点形态 `x.push(x.shift())` 与括号形态 `x['push'](x['shift']())`，
    #   其后 260 字符内紧跟 `(arr|providerFn, n)` —— 按 n 次旋转（与混淆器同语义）。
    _rot_pos = [m.end() for m in re.finditer(r'\.push\(\s*(\w+)\.shift\(\s*\)\s*\)', code)]
    _rot_pos += [m.end() for m in _RE_ROT_BRACKET.finditer(code)]
    _rot_done = set()                          # 同一 (arr,n) 只旋转一次（try/catch 各命中一次）
    for _pos in _rot_pos:
        _mm = re.search(r'\(\s*([A-Za-z_$][\w$]*)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)',
                        code[_pos:_pos + 260])
        if not _mm:
            continue
        _arr, _raw = _mm.group(1), _mm.group(2)
        _arr = _prov.get(_arr, _arr)          # 首个实参可能是"提供函数"而非数组名
        if _arr not in _arrays or (_arr, _raw) in _rot_done:
            continue
        _rot_done.add((_arr, _raw))
        try:
            _n = int(_raw, 16) if _raw.lower().startswith('0x') else int(_raw)
        except ValueError:
            continue
        _el = _arrays[_arr]
        if _el:
            _n %= len(_el)
            _arrays[_arr] = _el[_n:] + _el[:_n]
    # 包装函数：name → 数组名（简单形态 `function _0xW(i){return arr[i]}`）
    _wrap = {}
    for _m in _RE_WRAPPER_FN.finditer(code):
        _fn = _m.group(1) or _m.group(2)      # 具名 或 匿名赋值
        if _fn and _m.group(4) in _arrays:
            _wrap[_fn] = _m.group(4)
    # 偏移式自我重写包装：name → (数组名, 偏移)。数组名由"提供函数"解析。
    _wrap_off = {}
    for _m in _RE_WRAP_OFFSET.finditer(code):
        _fn, _arrvar, _provfn, _off = _m.group(1), _m.group(2), _m.group(3), _m.group(5)
        _arr = _prov.get(_provfn, _arrvar)
        if _arr not in _arrays:
            continue
        try:
            _offi = int(_off, 16) if str(_off).lower().startswith('0x') else int(_off)
        except ValueError:
            continue
        _wrap_off[_fn] = (_arr, _offi)
    # 包装函数的**本地别名**：`const _0xA=_0xW`（如 `const _0x446205=_0x2d73`）→ _0xA 同 _0xW。
    #   实测混淆器把包装函数赋给局部别名后再调用（`_0x446205(0xf3)`），不解析别名则调用无法还原。
    for _m in re.finditer(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*[,;]", code):
        _al, _src = _m.group(1), _m.group(2)
        if _al in _wrap_off or _al in _wrap:
            continue
        if _src in _wrap_off:
            _wrap_off[_al] = _wrap_off[_src]
        elif _src in _wrap:
            _wrap[_al] = _wrap[_src]
    _cnt = [0]
    _sensible_re = re.compile(r'^[A-Za-z0-9_/.\-]+$')   # 业务串形态（排除混淆器自校验串）

    def _idx(name, raw, off=0):
        try:
            _i = int(raw, 16) if str(raw).lower().startswith('0x') else int(raw)
        except ValueError:
            return None
        _i -= off                             # 偏移式包装：真实下标 = 字面量 - 偏移
        _el = _arrays.get(name)
        if not _el or _i < 0 or _i >= len(_el):
            return None
        _v = _el[_i]
        if not _sensible_re.match(_v):
            # 命中混淆器**自校验串**（如 `(((.+)+)+)` / `\x5c+…` / `return\x20(fu`）—— 不是业务串，
            #   跳过替换，避免把垃圾拼进路径（`/api/v2/us(((.+)+)+)`）污染提取。
            return None
        _cnt[0] += 1
        return '"%s"' % _v.replace('"', '\\"')

    code = _RE_ARR_INDEX.sub(
        lambda m: (_idx(m.group(1), m.group(2)) or m.group(0)), code)
    if _wrap:
        code = _RE_WRAPPER_CALL.sub(
            lambda m: (_idx(_wrap.get(m.group(1), ''), m.group(2)) or m.group(0))
            if m.group(1) in _wrap else m.group(0), code)
    if _wrap_off:
        code = _RE_WRAPPER_CALL.sub(
            lambda m: (_idx(_wrap_off[m.group(1)][0], m.group(2), _wrap_off[m.group(1)][1])
                       or m.group(0)) if m.group(1) in _wrap_off else m.group(0), code)
    # 字符串"碎片数组"拼接：`_0xA=['/','ap','i/','rs',…]` 运行时 join/loop 拼成 `/api/rs…`。
    #   仅当拼接结果**以 `/` 开头** 且 **各元素本身都不是"完整路径/URL/方法"**（即确为"碎片"）
    #   时才补回 —— 否则普通字符串数组（如 `['/api/orders','POST']`）会被误拼成
    #   `/api/ordersPOST` 噪声（实测会污染 extracted_endpoints）。
    # 方法令牌判据**单一真源** = `js_lex.has_http_method_element`(与 js_extract 数组 join 通道同源)。
    from .js_lex import has_http_method_element
    _complete = re.compile(r'^/[^/]+/.+|^https?://', re.I)

    def _is_fragment(_el):
        if len(_el) < 3:
            return False
        _j = ''.join(_el)
        if not (_j.startswith('/') and len(_j) >= 4):
            return False
        if has_http_method_element(_el):
            return False                # 含裸 HTTP 方法 → 不是碎片数组
        for _seg in _el:
            if _seg and _complete.match(_seg):
                return False            # 元素本身是完整路径/URL → 不是碎片数组
        return True

    _frag = []
    for _name, _el in _arrays.items():
        if _is_fragment(_el):
            _frag.append(''.join(_el))
    if _frag:
        code += '\n/*facet-deobf-frag*/' + ' '.join('"%s"' % _x for _x in _frag)
    return code, _cnt[0] + _n_pre


def _beautify_js(code):
    """jsbeautifier 反压缩（可选）"""
    if jsbeautifier:
        try:
            return jsbeautifier.beautify(code)
        except Exception:
            pass
    return code


# 简单 JS 编码解码（JSFuck / AAencode 颜文字 / JJencode / Jother）
#   这类编码的本质是「一段怪字符表达式运行后得到字符串, 再交给 Function/eval 执行」——
#   静态正则无法还原(必须运行 JS)。故在**密封、离线、零网络**的 Node vm 沙箱里运行该**编码
#   表达式**，执行入口(Function/eval)与输出口(alert/console/document.write)被**捕获桩**截断，
#   拿到明文源码/明文输出；网络原语只记录不发送。指纹门控 + Node 可选(缺失优雅跳过)。
# JSFuck / Jother：长串只由 `[]()!+`（Jother 还含 `{}`）构成。普通 JS 不会出现 ≥100 连续这种字符。
_RE_JSFUCKISH = re.compile(r'[\[\]\(\)!\+]{100,}')
_RE_JOTHER = re.compile(r'[\[\]\(\)!\+\{\}]{120,}')
# AAencode 颜文字：半角片假名点 `ﾟ` + 颜文字构件
_RE_AAENCODE = re.compile(r'ﾟ\s*[ωДΘεｰ]')


def looks_like_js_encoding(text):
    """廉价预筛：文本是否命中「简单 JS 编码」指纹（JSFuck / AAencode / JJencode / Jother）。

    指纹极特定（避免对普通 JS 无谓拉起 Node 子进程）：
      · JSFuck/Jother —— ≥100 连续 `[]()!+`（Jother 含 `{}`）字符；
      · AAencode 颜文字 —— 半角片假名点 `ﾟ` 反复出现且伴颜文字构件；
      · JJencode —— `$=~[]` 且对象字面量里出现 `___:++$`。
    """
    if not text or len(text) < 100:
        return False
    # 按**去空白**后的文本判定 JSFuck/Jother/JJencode 连续串 —— 编码常被反压缩/美化器
    #   （webcrack beautify 等）插入换行与空格，按原样匹配会漏判（实测：离线 --deobf-file 线
    #   先跑强反混淆美化，JSFuck 连续串被打断 → 指纹失配）。JSFuck/JJencode 本身空白不敏感。
    _ns = re.sub(r'\s+', '', text)
    if _RE_JSFUCKISH.search(_ns):
        return True
    if _RE_JOTHER.search(_ns):
        return True
    if text.count('ﾟ') >= 4 and _RE_AAENCODE.search(text):
        return True
    if '$=~[]' in _ns and '___:++$' in _ns:
        return True
    return False


def _resolve_node(node_bin=None):
    """定位 Node 可执行文件（显式 → 环境变量 → PATH → managed 动态扫描 → 系统路径）。

    委托 core.nodeenv 单一真源 —— 本文件历史上三处各写一份候选链
    （_resolve_node / _resolve_strong_tool / 动态解包内联），顺序与回退
    各不相同，随环境升级漂移（曾钉死开发机 Node 版本号，移机即失效）。
    """
    if node_bin:
        return node_bin
    return nodeenv.find_node()


def encodings_available():
    """node + deobf_encodings.cjs 是否都可用（`js_encoding: auto` 据此启用）。"""
    return bool(_resolve_node() and _find_bundled_script('deobf_encodings.cjs'))


def decode_js_encodings(code, node_bin=None, script=None):
    """解码 JSFuck / AAencode / JJencode / Jother 等「简单 JS 编码」。

    在**密封、离线、零网络**的 Node vm 沙箱里运行**编码表达式**，捕获其解码出的明文
    （执行入口 Function/eval 与输出口 alert/console/document.write 均为捕获桩；网络原语只记录不发送）。
    解码明文以注释字面量 ``/*facet-deobf-encoding*/"..."`` 补回，使既有提取通道拿到明文。
    返回 (还原后代码, report)；Node / 脚本不可用时优雅降级为 (code, {"available": False, ...})。
    """
    node_bin = _resolve_node(node_bin)
    if script is None:
        script = _find_bundled_script('deobf_encodings.cjs')
    if not node_bin or not script:
        return code, {"available": False, "reason": "node 或 deobf_encodings.cjs 未找到"}
    import json as _json
    import subprocess
    import tempfile
    in_p = out_p = rep_p = None
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False, encoding='utf-8') as f:
            f.write(code or '')
            in_p = f.name
        out_p = in_p + '.decoded.txt'
        try:
            rc, _out, err = run_capture([node_bin, script, in_p, out_p], 60)
        except subprocess.TimeoutExpired:
            return code, {"available": True, "ok": False, "error": "timeout"}
        if rc not in (0, 1):
            return code, {"available": True, "ok": False, "returncode": rc,
                          "stderr": (err or '')[:600]}
        rep_p = out_p + '.report.json'
        report = {"available": True, "ok": False, "decoded": []}
        if os.path.exists(rep_p):
            try:
                report.update(_json.load(open(rep_p, encoding='utf-8')))
            except Exception:
                pass
        decoded = report.get("decoded") or []
        if not decoded and os.path.exists(out_p):
            try:
                decoded = [ln for ln in open(out_p, encoding='utf-8').read().splitlines()
                           if ln.strip()]
            except Exception:
                decoded = []
        report["decoded"] = decoded
        report["ok"] = bool(decoded)
        if decoded:
            _blob = ' '.join('"%s"' % _x.replace('\\', '\\\\').replace('"', '\\"')
                             for _x in decoded)
            code = code + '\n/*facet-deobf-encoding*/' + _blob
        return code, report
    except Exception as e:
        return code, {"available": True, "ok": False, "error": str(e)[:400]}
    finally:
        for p in (in_p, out_p, rep_p):
            if p:
                try:
                    os.remove(p)
                except Exception:
                    pass


# 强反混淆层（opt-in，独立于默认静态管线；默认扫描仍为只读静态）

def _node_path_extra():
    """候选 node_modules 目录拼成 NODE_PATH 前缀（供 cjs 脚本解析 webcrack 等）。

    委托 core.nodeenv 单一真源（与 ast_sidecar._acorn_dir / recon/unbundle 同源）。
    旧实现只把本机 managed workspace 一个目录拼进 NODE_PATH —— 移机后该路径
    不存在，webcrack 随之不可用（强反混淆层整体静默降级）。
    """
    dirs = [d for d in nodeenv.node_modules_dirs() if os.path.isdir(d)]
    return os.pathsep.join(dirs) if dirs else ''


def _find_bundled_script(name):
    """定位随包发布的 Node 辅助脚本；找不到返回 None。

    ① **包内** `facet/assets/` —— wheel / sdist 与源码检出**同一路径**（旧版把脚本放在
       仓库根 `tools/`，而仓库根不进 wheel → `pip install` 后强反混淆 / 动态解包**静默不可用**）；
    ② 旧仓库布局 `<repo>/tools/` —— 兼容仍引用老路径的脚本。
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for rel in (os.path.join('..', 'assets', name),
                os.path.join('..', '..', 'tools', name)):
        cand = os.path.normpath(os.path.join(here, rel))
        if os.path.exists(cand):
            return cand
    return None


def _resolve_strong_tool(node_bin=None, script=None, webcrack_entry=None):
    """定位 Node 可执行文件与 deobf_strong.cjs 辅助脚本；返回 (node_bin, script, webcrack_entry)。

    Node 位置**环境驱动优先**(委托 core.nodeenv 单一真源): 环境变量
    `FACET_NODE_BIN` → PATH → managed 动态扫描 → 系统路径 → 'node'。
    webcrack: 环境变量 `FACET_WEBCRACK` → 候选 node_modules 动态探测
    (env / managed workspace / cwd 标准解析) —— 不钉死任何机器路径。
    """
    if node_bin is None:
        node_bin = nodeenv.find_node() or 'node'
    if script is None:
        script = _find_bundled_script('deobf_strong.cjs')
    if webcrack_entry is None:
        _env_wc = os.environ.get('FACET_WEBCRACK')
        if _env_wc and os.path.exists(_env_wc):
            webcrack_entry = _env_wc
        else:
            webcrack_entry = nodeenv.find_module_dir('webcrack')
    return node_bin, script, webcrack_entry


def strong_available():
    """node + deobf_strong.cjs + webcrack 是否都可用（`strong_deobf: auto` 据此启用）。

    与 `ast_sidecar.available` 同构：`auto` = "依赖齐全才启用"；缺任一 → 跳过该层（不报错）。
    """
    node_bin, script, webcrack_entry = _resolve_strong_tool()
    return bool(node_bin and script and webcrack_entry)


def deobfuscate_strong(code, node_bin=None, script=None, webcrack_entry=None):
    """强反混淆（opt-in，静态分析，绝不执行目标代码）。

    调用 Node + webcrack 对 javascript-obfuscator / webpack 做静态 AST 还原；
    对 VM/字节码打包叠加零宽剥离 + 转义解码的可读化。整个过程**不 eval、不运行目标逻辑**，
    属于静态分析。返回 (code, report_dict)。

    若 Node / webcrack 不可用，优雅降级为 (code, {"available": False, ...})，
    不影响默认静态管线。**本函数不会被默认扫描自动调用**——合规红线要求默认扫描保持
    纯静态只读；强反混淆需调用方显式启用（例如 CLI ``--strong-deobf`` 或工具脚本）。
    """
    node_bin, script, webcrack_entry = _resolve_strong_tool(node_bin, script, webcrack_entry)
    if not node_bin or not script:
        return code, {"available": False, "reason": "node 或 deobf_strong.cjs 未找到"}
    import json as _json
    import subprocess
    import tempfile
    env = dict(os.environ)
    _np = _node_path_extra()
    if _np:
        env['NODE_PATH'] = _np + os.pathsep + env.get('NODE_PATH', '')
    in_p = out_p = rep_p = None
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False, encoding='utf-8') as f:
            f.write(code or '')
            in_p = f.name
        out_p = in_p + '.strong.js'
        rep_p = out_p + '.report.json'
        args = [node_bin, script, in_p, out_p]
        if webcrack_entry:
            args.append(webcrack_entry)
        try:
            rc, _out, err = run_capture(args, 300, env=env)
        except subprocess.TimeoutExpired:
            return code, {"available": True, "ok": False, "error": "timeout"}
        if rc not in (0, 1) or not os.path.exists(out_p):
            return code, {"available": True, "ok": False, "returncode": rc,
                          "stderr": (err or '')[:600]}
        with open(out_p, 'r', encoding='utf-8') as f:
            out = f.read()
        report = {"available": True, "ok": True}
        if os.path.exists(rep_p):
            try:
                report.update(_json.load(open(rep_p, encoding='utf-8')))
            except Exception:
                pass
        return out, report
    except Exception as e:
        return code, {"available": True, "ok": False, "error": str(e)[:400]}
    finally:
        for p in (in_p, out_p, rep_p):
            if p:
                try:
                    os.remove(p)
                except Exception:
                    pass


def deobfuscate_strong_batch(codes, node_bin=None, script=None, webcrack_entry=None):
    """批量强反混淆（opt-in，静态）—— **一次 Node 调用**处理多个源。

    与 `deobfuscate_strong` 同能力，但把多个文件写进一个 manifest，交给
    `deobf_strong.cjs --batch` 一次处理 —— webcrack 只加载一次，省掉逐文件的
    Node + webcrack 启动开销（真实大站常见数十个混淆包，收益显著）。
    返回 list[(out, report)]，**顺序与输入一致**；node/脚本不可用时逐个降级。
    """
    node_bin, script, webcrack_entry = _resolve_strong_tool(node_bin, script, webcrack_entry)
    if not node_bin or not script:
        return [(c, {"available": False, "reason": "node 或 deobf_strong.cjs 未找到"}) for c in codes]
    import json as _json
    import shutil as _shutil
    import tempfile
    env = dict(os.environ)
    _np = _node_path_extra()
    if _np:
        env['NODE_PATH'] = _np + os.pathsep + env.get('NODE_PATH', '')
    d = None
    try:
        d = tempfile.mkdtemp(prefix='fkstrong_')
        jobs = []
        for i, code in enumerate(codes):
            inp = os.path.join(d, 'in%d.js' % i)
            outp = os.path.join(d, 'out%d.js' % i)
            with open(inp, 'w', encoding='utf-8') as f:
                f.write(code or '')
            jobs.append({'in': inp, 'out': outp})
        man = {'jobs': jobs}
        if webcrack_entry:
            man['webcrack_entry'] = webcrack_entry
        mpath = os.path.join(d, 'manifest.json')
        with open(mpath, 'w', encoding='utf-8') as f:
            _json.dump(man, f)
        run_capture([node_bin, script, '--batch', mpath], 600, env=env)
        results = []
        rpath = mpath + '.results.json'
        if os.path.exists(rpath):
            try:
                results = _json.load(open(rpath, encoding='utf-8')).get('results', [])
            except Exception:
                results = []
        out_list = []
        for i, code in enumerate(codes):
            ok = (i < len(results) and isinstance(results[i], dict) and results[i].get('ok'))
            if not ok:
                out_list.append((code, {"available": True, "ok": False}))
                continue
            rep = dict(results[i].get('report') or {})
            rep.setdefault('available', True)
            try:
                with open(jobs[i]['out'], 'r', encoding='utf-8') as f:
                    o = f.read()
            except Exception:
                o = code
            out_list.append((o, rep))
        return out_list
    except Exception as e:
        return [(c, {"available": True, "ok": False, "error": str(e)[:300]}) for c in codes]
    finally:
        if d:
            _shutil.rmtree(d, ignore_errors=True)


def deobfuscate_dynamic(code, tier=3, node_bin=None, script=None):
    """动态解包（opt-in，**本地密封离线沙箱**，零网络；默认扫描不调用）。

    调用 Node + `facet/assets/deobf_dynamic.cjs`，在**密封、离线、零网络**的 vm 沙箱里运行目标代码，
    展开 VM / 字节码混淆，提取其中已声明但未探活的端点字符串 / 配置 / 解密明文 URL。
    沙箱内 ``fetch / XMLHttpRequest / WebSocket / http / https / net / dns`` 全部被替换为
    「只记录、不发送」的桩 —— **绝不**向目标或任何外部地址发包。

    与 ``deobfuscate_strong``（纯静态，不执行目标代码）不同，本函数**会运行目标代码**，
    故仅作 opt-in 强解包，且受 ``dynamic_deobf`` 旋钮门控（默认关闭 + 报告明示）。
    返回 (code, report_dict)；若 Node / 脚本不可用，优雅降级为 (code, {"available": False, ...})。
    """
    # 解析 node 可执行文件（与强反混淆**共用同一候选逻辑**, 委托 core.nodeenv）
    if node_bin is None:
        node_bin = _resolve_node() or 'node'
    if script is None:
        script = _find_bundled_script('deobf_dynamic.cjs')
    if not node_bin or not script:
        return code, {"available": False, "reason": "node 或 deobf_dynamic.cjs 未找到"}
    try:
        tier = int(tier)
    except (TypeError, ValueError):
        tier = 3
    if tier not in (3, 4, 5):
        tier = 4
    import json as _json
    import subprocess
    import tempfile
    env = dict(os.environ)
    _np = _node_path_extra()
    if _np:
        env['NODE_PATH'] = _np + os.pathsep + env.get('NODE_PATH', '')
    in_p = out_p = rep_p = None
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False, encoding='utf-8') as f:
            f.write(code or '')
            in_p = f.name
        out_p = in_p + '.dyn.js'
        args = [node_bin, script, in_p, out_p, str(tier)]
        # 动态解包可能运行目标代码；父进程超时作为兜底（沙箱内另有 30s vm 上限）。
        try:
            rc, _out, err = run_capture(args, 120, env=env)
        except subprocess.TimeoutExpired:
            return code, {"available": True, "ok": False, "error": "timeout"}
        if rc not in (0, 1) or not os.path.exists(out_p):
            return code, {"available": True, "ok": False, "returncode": rc,
                          "stderr": (err or '')[:600]}
        with open(out_p, 'r', encoding='utf-8') as f:
            out = f.read()
        report = {"available": True, "ok": True, "tier": tier}
        rep_p = out_p + '.report.json'
        if os.path.exists(rep_p):
            try:
                report.update(_json.load(open(rep_p, encoding='utf-8')))
            except Exception:
                pass
        return out, report
    except Exception as e:
        return code, {"available": True, "ok": False, "error": str(e)[:400]}
    finally:
        for p in (in_p, out_p, rep_p):
            if p:
                try:
                    os.remove(p)
                except Exception:
                    pass

