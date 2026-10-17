# -*- coding: utf-8 -*-
"""JS **AST** 提取 sidecar（方案 4.1「AST 优先, 正则兜底」）。

用 Node + **acorn** 做真正的语法树解析, 提取:
  · 调用点 URL —— `fetch` / `axios.*` / `ky.*` / `superagent.*` / `XMLHttpRequest.open` /
    `$.ajax|$.get|$.post|$.getJSON`(含对象参数里的 `url`/`method`);
  · **路径样字符串字面量**(`^/[...]$`) —— 覆盖"URL 存变量后再用"的写法;
  · 写方法(post/put/patch/delete)单列, 与只读调用分区。

设计要点:
  · **可选 sidecar** —— 找不到 node / acorn 就静默返回空, 由正则通道兜底(行为与从前一致);
  · 默认 `auto`: 环境可用才启用(对齐方案"AST 优先"), 也可显式 `true`/`false`;
  · **只做静态解析, 绝不执行目标代码**(不 eval、不 vm、不加载模块)。
"""
import atexit
import json
import os
import queue
import re
import subprocess
import tempfile
import threading

from . import nodeenv



# Node worker: persistent JSON-lines protocol. One process is reused for the entire scan;
# every input line is {"code":"..."}, every output line is one extraction JSON object.
_NODE_WORKER_SCRIPT = r"""
const readline = require('readline');
let acorn;
try { acorn = require(process.env.FACET_ACORN || 'acorn'); }
catch (e) { process.stderr.write('acorn unavailable: ' + String(e)); process.exit(2); }
function extract(src) {
  let ast = null, err = null;
  for (const opt of [{sourceType: 'module'}, {sourceType: 'script'}]) {
    try { ast = acorn.parse(src, Object.assign({ecmaVersion: 'latest', allowHashBang: true,
          allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true}, opt)); break; }
    catch (e) { err = e; }
  }
  if (!ast) return {error: String(err && err.message || err)};
  const WRITE = {post: 'POST', put: 'PUT', patch: 'PATCH', delete: 'DELETE'};
  const apis = new Set(), lits = new Set(), writes = {};
  const baseurls = new Set(), routes = new Set();
  const lit = n => (n && n.type === 'Literal' && typeof n.value === 'string') ? n.value : null;
  const prop = (obj, name) => {
    if (!obj || obj.type !== 'ObjectExpression') return null;
    for (const p of (obj.properties || [])) {
      const k = p.key && (p.key.name || p.key.value);
      if (k === name) return p.value;
    }
    return null;
  };
  // ---- P0-1 AST 级字符串还原(方案 4.1「AST 优先」) ----
  //   把 baseURL / 路由 path / 调用参数里的 "标识符 / 模板串 / 二元 + 拼接" 静态还原为字面量。
  //   仅静态求值(不 eval、不执行目标代码)。作用域为**扁平模块近似**: 收集全部 const/let/var
  //   声明与赋值, 但**排除函数形参名**(paramNames)以降低"局部变量同名"误解析。
  const paramNames = new Set();
  (function collectParams(n) {
    if (!n || typeof n !== 'object') return;
    if (Array.isArray(n)) { n.forEach(collectParams); return; }
    if (n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression'
        || n.type === 'ArrowFunctionExpression') {
      (n.params || []).forEach(p => { if (p && p.type === 'Identifier') paramNames.add(p.name); });
    }
    for (const k in n) { if (k === 'type' || k === 'start' || k === 'end') continue; collectParams(n[k]); }
  })(ast);
  const constMap = new Map();
  (function collectConst(n) {
    if (!n || typeof n !== 'object') return;
    if (Array.isArray(n)) { n.forEach(collectConst); return; }
    if (n.type === 'VariableDeclarator' && n.id && n.id.type === 'Identifier' && n.init) {
      if (!paramNames.has(n.id.name)) constMap.set(n.id.name, n.init);
    } else if (n.type === 'AssignmentExpression' && n.operator === '='
               && n.left && n.left.type === 'Identifier') {
      if (!paramNames.has(n.left.name)) constMap.set(n.left.name, n.right);
    }
    for (const k in n) { if (k === 'type' || k === 'start' || k === 'end') continue; collectConst(n[k]); }
  })(ast);
  // 静态还原为字符串; 不可完全还原返回 null。seen 做循环引用保护。
  function resolveStr(node, seen) {
    if (!node) return null;
    if (node.type === 'Literal') return (typeof node.value === 'string') ? node.value : null;
    if (node.type === 'TemplateLiteral') {
      let out = '';
      for (let i = 0; i < node.quasis.length; i++) {
        const q = node.quasis[i].value || {};
        out += (q.cooked != null ? q.cooked : (q.raw || ''));
        if (i < node.expressions.length) {
          const r = resolveStr(node.expressions[i], seen);
          if (r == null) return null;
          out += r;
        }
      }
      return out;
    }
    if (node.type === 'BinaryExpression' && node.operator === '+') {
      const l = resolveStr(node.left, seen); if (l == null) return null;
      const r = resolveStr(node.right, seen); if (r == null) return null;
      return l + r;
    }
    if (node.type === 'Identifier') {
      if (seen.has(node.name)) return null;
      seen.add(node.name);
      const init = constMap.get(node.name);
      const r = init ? resolveStr(init, seen) : null;
      seen.delete(node.name);
      return r;
    }
    return null;
  }
  const rs = n => resolveStr(n, new Set());
  const add = (u, method) => {
    if (!u || typeof u !== 'string') return;
    const m = (method || '').toLowerCase();
    if (WRITE[m]) writes[u] = WRITE[m]; else apis.add(u);
  };
  (function walk(n) {
    if (!n || typeof n !== 'object') return;
    if (Array.isArray(n)) { n.forEach(walk); return; }
    if (n.type === 'CallExpression' || n.type === 'NewExpression') {
      const c = n.callee || {};
      let name = '';
      if (c.type === 'Identifier') name = c.name;
      else if (c.type === 'MemberExpression') {
        const o = c.object || {}, p = c.property || {};
        const on = o.type === 'Identifier' ? o.name : (o.type === 'ThisExpression' ? 'this' : '');
        const pn = p.type === 'Identifier' ? p.name : (p.type === 'Literal' ? String(p.value) : '');
        name = on ? (pn ? on + '.' + pn : on) : pn;
      }
      const args = n.arguments || [];
      if (/^(fetch|ky|superagent|request)$/.test(name) || /^(axios|ky|superagent|request|http|https)\./.test(name)) {
        let u = rs(args[0]);
        let method = null;
        if (args[1] && args[1].type === 'ObjectExpression') method = lit(prop(args[1], 'method'));
        if (!u && args[0] && args[0].type === 'ObjectExpression') {
          u = rs(prop(args[0], 'url'));
          method = method || lit(prop(args[0], 'method'));
        }
        if (!method && /\./.test(name)) method = name.split('.').pop();
        add(u, method);
      } else if (/\.open$/.test(name) || name === 'open') {
        add(rs(args[1]), rs(args[0]));
      } else if (/^\$\.(ajax|get|post|getJSON|getScript)$/.test(name)) {
        const short = name.split('.').pop();
        if (args[0] && args[0].type === 'ObjectExpression') {
          add(rs(prop(args[0], 'url')), rs(prop(args[0], 'type')) || rs(prop(args[0], 'method')));
        } else {
          add(rs(args[0]), short === 'post' ? 'POST' : 'GET');
        }
      }
    }
    // AST 级 baseURL / 路由 path 还原(变量/拼接/模板)
    if (n.type === 'ObjectExpression') {
      const bu = prop(n, 'baseURL'); if (bu) { const r = rs(bu); if (r) baseurls.add(r); }
      const pp = prop(n, 'path'); if (pp) { const r = rs(pp); if (r && r[0] === '/') routes.add(r); }
    }
    if (n.type === 'Literal' && typeof n.value === 'string'
        && /^\/[A-Za-z0-9_\-./{}:$]{3,}$/.test(n.value)) lits.add(n.value);
    for (const k in n) { if (k === 'type' || k === 'start' || k === 'end') continue; walk(n[k]); }
  })(ast);
  return {apis: [...apis], lits: [...lits], write_apis: writes,
          baseurls: [...baseurls], routes: [...routes]};
}
const rl = readline.createInterface({input: process.stdin, crlfDelay: Infinity});
rl.on('line', line => {
  try { const req = JSON.parse(line); process.stdout.write(JSON.stringify(extract(String(req.code || ''))) + '\n'); }
  catch (e) { process.stdout.write(JSON.stringify({error: String(e)}) + '\n'); }
});
"""

_NODE_WORKER_LOCK = threading.RLock()
_NODE_WORKER = None

# node / acorn 定位统一委托 core.nodeenv（单一真源，动态发现、不钉机器路径）——
# 旧实现在此维护钉死开发机版本的 `_NODE_FALLBACKS` / `_ACORN_FALLBACKS` 表,
# 换机即失效且把开发者家目录带进发布物(移机验证发现的真实缺陷)。

_TS_PATH_RE = re.compile(r'^/[A-Za-z0-9_./{}:$-]{3,}$')
_TS_WRITE_METHODS = {'post': 'POST', 'put': 'PUT', 'patch': 'PATCH', 'delete': 'DELETE'}


def _tree_sitter_parser():
    """可选 Python 原生 AST 引擎; 返回 Parser 或 None。"""
    try:
        import tree_sitter
        import tree_sitter_javascript
        lang = tree_sitter.Language(tree_sitter_javascript.language())
        try:
            return tree_sitter.Parser(lang)
        except TypeError:  # tree-sitter 0.22 compatibility
            parser = tree_sitter.Parser()
            if hasattr(parser, 'set_language'):
                parser.set_language(lang)
            else:
                parser.language = lang
            return parser
    except Exception:
        return None


def _ts_string(node):
    """读取简单 JS string / template literal; 动态模板表达式不作为字面量。"""
    if node is None or node.type not in ('string', 'template_string'):
        return None
    raw = node.text.decode('utf-8', 'replace')
    if node.type == 'template_string' and '${' in raw:
        return None
    if len(raw) < 2:
        return None
    value = raw[1:-1]
    # 仅处理 URL 中常见的 escaped quote/slash/backslash; 不执行 JS 转义。
    return (value.replace(r'\/', '/')
            .replace(r'\\', '\\')
            .replace(r'\"', '"')
            .replace(r"\'", "'"))


def _ts_node_name(node):
    if node is None:
        return ''
    if node.type in ('identifier', 'property_identifier'):
        return node.text.decode('utf-8', 'replace')
    if node.type in ('member_expression', 'subscript_expression'):
        return node.text.decode('utf-8', 'replace')
    return ''


def _ts_object_value(node, key):
    if node is None or node.type != 'object':
        return None
    for prop in node.named_children:
        if prop.type != 'pair':
            continue
        key_node = prop.child_by_field_name('key')
        value_node = prop.child_by_field_name('value')
        key_name = (_ts_string(key_node) if key_node and key_node.type == 'string'
                    else key_node.text.decode('utf-8', 'replace') if key_node else '')
        if key_name == key:
            return value_node
    return None


def _extract_tree_sitter(code, parser=None):
    """Python tree-sitter implementation matching {apis,lits,write_apis} Acorn contract."""
    parser = parser or _tree_sitter_parser()
    if parser is None:
        return None
    try:
        tree = parser.parse(code.encode('utf-8', 'replace'))
    except Exception:
        return None
    # tree-sitter 对真实开源 bundle 偶发解析失败(根节点 ERROR / 含 error 节点)——
    # 此时必须返回 None 让 extract() 回退到 Node+Acorn, 否则会**静默返回空结果**
    # (合成片段能正常解析, 故该回退缺口此前被掩盖)。
    if tree is None or getattr(tree.root_node, 'has_error', False) \
            or tree.root_node.type == 'ERROR':
        return None
    apis, lits, writes = set(), set(), {}
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == 'string':
            value = _ts_string(node)
            if value and _TS_PATH_RE.fullmatch(value):
                lits.add(value)
        elif node.type in ('call_expression', 'new_expression'):
            fn = (node.child_by_field_name('function') or node.child_by_field_name('constructor')
                  or node.child_by_field_name('call'))
            name = _ts_node_name(fn)
            args_node = node.child_by_field_name('arguments')
            args = list(args_node.named_children) if args_node else []
            url = method = None
            short = name.rsplit('.', 1)[-1]
            is_http = (name in ('fetch', 'ky', 'superagent', 'request')
                       or name.startswith(('axios.', 'ky.', 'superagent.', 'request.', 'http.', 'https.')))
            if is_http:
                url = _ts_string(args[0]) if args else None
                if len(args) > 1:
                    method = _ts_string(_ts_object_value(args[1], 'method'))
                if args and args[0].type == 'object':
                    url = url or _ts_string(_ts_object_value(args[0], 'url'))
                    method = method or _ts_string(_ts_object_value(args[0], 'method'))
                if not method and '.' in name:
                    method = short
            elif short == 'open' or name == 'open':
                method = _ts_string(args[0]) if args else None
                url = _ts_string(args[1]) if len(args) > 1 else None
            elif name.startswith('$.') and short in ('ajax', 'get', 'post', 'getJSON', 'getScript'):
                if args and args[0].type == 'object':
                    url = _ts_string(_ts_object_value(args[0], 'url'))
                    method = (_ts_string(_ts_object_value(args[0], 'type'))
                              or _ts_string(_ts_object_value(args[0], 'method')))
                else:
                    url = _ts_string(args[0]) if args else None
                    method = 'POST' if short == 'post' else 'GET'
            if url:
                m = str(method or '').lower()
                if m in _TS_WRITE_METHODS:
                    writes[url] = _TS_WRITE_METHODS[m]
                else:
                    apis.add(url)
        stack.extend(reversed(node.children))
    # 契约与 Node+Acorn 一致(含 baseurls/routes 键; tree-sitter 路径暂不做变量还原 → 空集,
    #   缺失的 baseURL/路由变量还原由正则 P0-1 兜底)。
    return {'apis': apis, 'lits': lits, 'write_apis': writes,
            'baseurls': set(), 'routes': set()}


class _NodeWorker:
    """串行化请求、复用 Node AST 进程；worker 无响应时超时杀进程并允许下次重启。"""
    def __init__(self, node, acorn_dir):
        self.node = node
        self.acorn_dir = acorn_dir
        self.proc = None
        self.script_path = None
        self.responses = queue.Queue()
        self.lock = threading.RLock()
        self._start()

    def _start(self):
        fd, self.script_path = tempfile.mkstemp(suffix='.cjs', prefix='facet_ast_')
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(_NODE_WORKER_SCRIPT)
        env = dict(os.environ)
        env['NODE_PATH'] = self.acorn_dir
        env['FACET_ACORN'] = os.path.join(self.acorn_dir, 'acorn')
        self.proc = subprocess.Popen([self.node, self.script_path], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     text=True, encoding='utf-8', errors='replace', bufsize=1, env=env)
        proc, responses = self.proc, self.responses
        threading.Thread(target=self._read_loop, args=(proc, responses), daemon=True,
                         name='facet-ast-reader').start()

    @staticmethod
    def _read_loop(proc, responses):
        try:
            for line in proc.stdout:
                responses.put(line)
        except Exception:
            pass
        finally:
            responses.put(None)

    def _stop(self):
        proc, self.proc = self.proc, None
        if proc is not None:
            try:
                if proc.stdin:
                    proc.stdin.close()
            except Exception:
                pass
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=1)
                except Exception:
                    pass
            for _pipe in (proc.stdout, proc.stderr):
                try:
                    if _pipe:
                        _pipe.close()
                except Exception:
                    pass
        if self.script_path:
            try:
                os.unlink(self.script_path)
            except Exception:
                pass
            self.script_path = None

    def request(self, code, timeout):
        with self.lock:
            if self.proc is None or self.proc.poll() is not None:
                self._stop()
                self.responses = queue.Queue()
                self._start()
            try:
                self.proc.stdin.write(json.dumps({'code': code}, ensure_ascii=True) + '\n')
                self.proc.stdin.flush()
                line = self.responses.get(timeout=timeout)
                if line is None:
                    self._stop()
                    return None
                data = json.loads(line)
                if not isinstance(data, dict) or data.get('error'):
                    return None
                return {'apis': set(data.get('apis') or []),
                        'lits': set(data.get('lits') or []),
                        'write_apis': dict(data.get('write_apis') or {}),
                        # P0-1 AST 级还原: baseURL / 路由 path(变量·拼接·模板已在 Acorn 侧解析)
                        'baseurls': set(data.get('baseurls') or []),
                        'routes': set(data.get('routes') or [])}
            except queue.Empty:
                self._stop()
                return None
            except Exception:
                self._stop()
                return None

    def close(self):
        with self.lock:
            self._stop()


def _shutdown_node_worker():
    global _NODE_WORKER
    with _NODE_WORKER_LOCK:
        if _NODE_WORKER is not None:
            _NODE_WORKER.close()
            _NODE_WORKER = None


atexit.register(_shutdown_node_worker)


def _node_bin(cfg):
    """定位 node 可执行文件。委托 core.nodeenv 单一真源（保留 (cfg) 签名供测试打桩）。"""
    return nodeenv.find_node(cfg)


def _acorn_dir(cfg):
    """定位 acorn 所在的 node_modules 目录（worker 以其为 NODE_PATH）。

    环境驱动(不钉机器路径), 与 core/deobf、recon/unbundle 同范式:
      ① 配置键 `ast_node_path`(显式 node_modules 目录, 调用方自述可信) →
      ② 环境变量 `FACET_NODE_MODULES`(目录本身/父目录双约定) →
      ③ managed workspace 动态探测 → ④ 当前工作目录及父目录标准 Node 解析。
    找不到返回 None —— 可用性如实披露(不谎称可用), 由正则通道兜底。
    """
    _c = (cfg or {}).get('ast_node_path')
    if _c and os.path.isdir(_c):
        return _c
    for _d in nodeenv.node_modules_dirs():
        if os.path.isdir(os.path.join(_d, 'acorn')):
            return _d
    return None


def available(cfg=None):
    """是否存在 AST 引擎: 优先 Python tree-sitter, 降级 Node + Acorn。"""
    return bool(_tree_sitter_parser() is not None or (_node_bin(cfg) and _acorn_dir(cfg)))


def enabled(cfg=None):
    """三态开关: True / False / 'auto'(默认, 环境可用即启用)。"""
    _v = (cfg or {}).get('ast_sidecar', 'auto')
    if isinstance(_v, str):
        _v = _v.strip().lower()
        if _v == 'auto':
            return available(cfg)
        return _v in ('1', 'true', 'yes', 'on')
    return bool(_v) and available(cfg)


def extract(code, cfg=None, timeout=25):
    """对一段 JS 做 AST 提取。返回 {apis:set, lits:set, write_apis:dict}；不可用/失败返回 None。

    引擎顺序: Python tree-sitter(进程内、无 Node 依赖) → 常驻 Node + Acorn(JSON-lines)。
    """
    global _NODE_WORKER
    if not code or len(code) < 16:
        return None
    ts_parser = _tree_sitter_parser()
    if ts_parser is not None:
        result = _extract_tree_sitter(code, ts_parser)
        if result is not None:
            return result
    node, acorn = _node_bin(cfg), _acorn_dir(cfg)
    if not node or not acorn:
        return None
    key = (node, acorn)
    with _NODE_WORKER_LOCK:
        if (_NODE_WORKER is None or
                (_NODE_WORKER.node, _NODE_WORKER.acorn_dir) != key):
            if _NODE_WORKER is not None:
                _NODE_WORKER.close()
            try:
                _NODE_WORKER = _NodeWorker(node, acorn)
            except Exception:
                _NODE_WORKER = None
                return None
        worker = _NODE_WORKER
    return worker.request(code, timeout) if worker is not None else None
