#!/usr/bin/env node
'use strict';
/*
 * facet — 动态解包 Harness（L3–L5，opt-in，合规只读、密封离线）。
 *
 * 定位：仅用于「发现级」侦察。把混淆 / VM / 字节码打包的 JS 在**密封、离线、零网络**的
 *   Node vm 沙箱里展开，提取其中**已声明但未探活**的端点字符串、配置键、解密后的明文 URL。
 *   本工具**绝不**向目标或任何外部地址发包；沙箱内一切网络原语
 *   （fetch / XMLHttpRequest / WebSocket / http / https / net / dns / child_process）
 *   一律被替换为「只记录、不发送」的桩，并打印 [BLOCKED] 证据。
 *
 * 🔴 realm 隔离（防沙箱逃逸）—— 本 Harness 的核心安全不变量：
 *   目标代码一旦拿到**任何宿主对象/函数**，即可经 `<obj>.constructor.constructor('return process')()`
 *   在**宿主 realm** 造出函数并触达真实 require/process（实测：旧实现把宿主 Buffer 经
 *   `Object.create()` 暴露进沙箱，`Buffer.constructor('return process')()` 返回 27 个宿主
 *   versions = 逃逸；同理**任何**宿主函数桩的 `.constructor` 都可达宿主 Function）。
 *   因此：**所有**暴露给沙箱的对象/函数都必须在**上下文内**创建（`build_sandbox_env` 的源码经
 *   `Function.prototype.toString()` 取回后在 `vm.runInContext` 里求值 → 得到上下文函数 →
 *   其创建的一切都是上下文对象）。宿主与沙箱之间只经 `bridge` 传递，且 bridge 的辅助函数
 *   **只返回原始值**（string / number / undefined）—— 原始值不携带 realm，无法用于逃逸。
 *
 * 分层：
 *   L3  密封 vm 沙箱 + 手搓桩环境（无 jsdom/playwright 也跑得起来）+ 解密原语
 *       （atob / JSON.parse / Buffer / decodeURIComponent）/ 网络 API 插桩 + 超时。
 *       运行目标**顶层代码**，捕获其构造的内层 Function/eval 源码（不主动引爆内层函数）。
 *   L4  在 L3 基础上 + 抗篡改桩（固定 Date/perf/random 减少反调试扰动）+ Proxy/Reflect
 *       插桩 + 对「安全门控」通过的内层函数（源码体量 / 循环密度低于阈值）以安全桩参数
 *       **执行**解包，捕获解密明文；对含高密度循环的解释器（如 ConfuserEx 风格 VM）出于
 *       防挂安全默认跳过执行，仅提供内层源码供静态分析，并在报告中注明。
 *   L5  真实浏览器（Playwright/Chromium）+ 请求拦截 BLOCK+LOG + addInitScript 插桩；
 *       若本机无 Playwright/Chromium，则**优雅降级**为 L3/L4（手搓桩环境）。
 *
 * 退出码：0 成功 / 2 参数/输入错误 / 1 运行时错误（仍会写出尽力而为的结果）。
 *
 * 用法：node deobf_dynamic.cjs <in.js> <out.js> <tier>
 *   写出：<out.js>            展开后的产物（原码 + 捕获的内层源码，供下游静态管线再分析）
 *         <out.js>.report.json 捕获报告（urls / strings / config / methods / errors / notes）
 */
const fs = require('fs');
const vm = require('vm');
const path = require('path');

// L4 安全门控：仅当内层函数源码同时低于体量阈值、且循环密度低于阈值时才执行，
// 防止通用 harness 被高密集循环的解释器（如 364 个 while 的字节码 VM）拖挂。
const SAFE_EXEC_MAX_LEN = 20000;     // 内层源码字符数上限
const SAFE_EXEC_MAX_LOOPS = 50;      // while/for 出现次数上限

const URL_RE = /(https?:\/\/|wss?:\/\/)[^\s"'`<>\]\}\)]+/gi;

// ---- 加载浏览器引擎（仅 L5 用；缺失则降级） ----
function load_browser() {
  for (const n of ['playwright', 'playwright-core', 'puppeteer']) {
    try { return require(n); } catch (_) { /* next */ }
  }
  return null;
}

// ---- 把任意对象安全序列化为 JSON 友好结构（处理函数/循环引用/深度上限） ----
function safe_stringify(v, depth) {
  const seen = new Set();
  function walk(o, d) {
    if (d < 0) return '…';
    if (o === null || typeof o !== 'object') {
      if (typeof o === 'function') return '[Function]';
      if (typeof o === 'string' || typeof o === 'number' || typeof o === 'boolean') return o;
      return String(o);
    }
    if (seen.has(o)) return '[Circular]';
    seen.add(o);
    if (Array.isArray(o)) return o.map((x) => walk(x, d - 1));
    const out = {};
    for (const k of Object.keys(o)) {
      try { out[k] = walk(o[k], d - 1); } catch (_) { out[k] = '[err]'; }
    }
    return out;
  }
  try { return walk(v, depth); } catch (_) { return null; }
}

// ---- 递归遍历导出对象，抽取 URL / 明文串（配置另由调用方从 `config` 子对象取，避免噪声） ----
function harvest_exports(obj, capture, record_url, record_str) {
  const seen = new Set();
  (function walk(o, depth) {
    if (depth < 0 || o == null || seen.has(o)) return;
    if (typeof o === 'string') { record_str(o); record_url(o); return; }
    if (typeof o !== 'object') return;
    seen.add(o);
    for (const k of Object.keys(o)) walk(o[k], depth - 1);
  })(obj, 8);
}

/**
 * 🔴 在 **vm 上下文内**构建整个密封桩环境（realm-safe）。
 *
 * 本函数的**源码文本**经 `Function.prototype.toString()` 取回、在上下文里求值 → 得到一个
 * **上下文函数**；由它创建的一切对象/函数都属于沙箱 realm（`.constructor` 指向上下文 Function，
 * 无法触达宿主）。宿主只通过参数 `bridge` 提供辅助，且 bridge 的方法**只返回原始值**。
 *
 * 约束（改动时务必遵守）：
 *   ① 函数体必须**自包含**（不得引用外层闭包变量），否则 toString 后在沙箱里求值会 ReferenceError；
 *   ② 不得把 `bridge` 或其任何成员**存进返回对象/全局**（只可调用），否则宿主函数泄漏；
 *   ③ 不得引用宿主的 `Function`/`eval`/`Buffer`/`process` 等 —— 一律用上下文内建。
 */
function build_sandbox_env(bridge) {
  'use strict';
  const g = globalThis;
  const methods = new Set();
  const innerSources = [];
  const capturedFns = [];
  const tier = bridge.tier;
  // 安全门控阈值由宿主经 bridge 传入（本函数须自包含, 不得引用宿主模块级常量）
  const MAX_LEN = bridge.maxLen;
  const MAX_LOOPS = bridge.maxLoops;

  const recStr = (s) => { if (typeof s === 'string') bridge.recStr(s); };
  const recUrl = (u) => { if (typeof u === 'string') bridge.recUrl(u); };
  const scanUrls = (s) => { if (typeof s === 'string') bridge.recUrl(s); };
  const note = (m) => { bridge.note(String(m)); };

  // ---- 安全返回值：让解包逻辑不因网络桩缺失而崩溃 ----
  const safeResponse = () => ({
    ok: false, status: 0, statusText: '', headers: { get() { return null; } },
    text() { return Promise.resolve(''); }, json() { return Promise.resolve({}); },
    arrayBuffer() { return Promise.resolve(new Uint8Array(0)); },
  });

  // ---- 网络原语桩：只记录，不发送 ----
  const netStub = (label) => function () {
    for (let i = 0; i < arguments.length; i++) {
      const a = arguments[i];
      if (typeof a === 'string') recUrl(a);
      else if (a && typeof a === 'object') {
        if (a.url) recUrl(String(a.url));
        if (typeof a.href === 'string') recUrl(a.href);
      }
    }
    note('[BLOCKED][' + label + '] 离线沙箱拦截, 未向任何地址发送');
    return safeResponse();
  };
  const xhrStub = () => ({
    open() {}, send() {}, abort() {}, setRequestHeader() {},
    addEventListener() {}, overrideMimeType() {},
    status: 0, responseText: '', response: null,
  });

  // ---- Buffer 桩：上下文内建(Uint8Array 子类) + 宿主仅做「字节<->文本」原始值转换 ----
  //   不暴露宿主 Buffer（其 .constructor 可达宿主 Function = 逃逸面）。
  const SSBuf = class extends Uint8Array {
    toString(enc) {
      let s = '';
      for (let i = 0; i < this.length; i++) s += String.fromCharCode(this[i]);
      return bridge.text(s, enc);          // 返回原始值(string)，不携带 realm
    }
  };
  const bufFromLatin1 = (bs) => {
    const u = new SSBuf(bs.length);
    for (let i = 0; i < bs.length; i++) u[i] = bs.charCodeAt(i) & 255;
    return u;
  };
  const Buf = {
    from(x, enc) {
      if (typeof x === 'string') { recStr(x); scanUrls(x); return bufFromLatin1(bridge.bytes(x, enc)); }
      if (x && typeof x.length === 'number') {
        const u = new SSBuf(x.length);
        for (let i = 0; i < x.length; i++) u[i] = x[i] & 255;
        return u;
      }
      return new SSBuf(0);
    },
    alloc(n) { return new SSBuf(Math.max(0, n | 0)); },
    concat(arr) {
      let total = 0;
      for (let i = 0; i < arr.length; i++) total += (arr[i] && typeof arr[i].length === 'number') ? arr[i].length : 0;
      const u = new SSBuf(total);
      let off = 0;
      for (let i = 0; i < arr.length; i++) { const a = arr[i]; if (a) { u.set(a, off); off += a.length; } }
      return u;
    },
    isBuffer(x) { return x instanceof SSBuf; },
    byteLength(x) { return (x && typeof x.length === 'number') ? x.length : (typeof x === 'string' ? x.length : 0); },
  };

  // ---- 解密 / 编码原语插桩（常用作隐藏端点） ----
  const _decURI = g.decodeURIComponent;
  const atobStub = (s) => { recStr(typeof s === 'string' ? s : ''); const d = bridge.b64dec(String(s)); recStr(d); scanUrls(d); return d; };
  const btoaStub = (s) => { recStr(typeof s === 'string' ? s : ''); return bridge.b64enc(String(s)); };
  const decUriStub = (s) => { const d = _decURI(String(s)); recStr(d); scanUrls(d); return d; };
  const cJSON = g.JSON;
  const jpStub = (s) => {
    if (typeof s === 'string') { scanUrls(s); }
    try { return cJSON.parse(s); } catch (_) { return {}; }
  };

  // ---- 基础面 ----
  g.console = { log: (...a) => recStr(a.map(String).join(' ')), warn() {}, error() {}, info() {}, debug() {}, trace() {} };
  g.setTimeout = () => 0; g.setInterval = () => 0; g.setImmediate = () => 0;
  g.clearTimeout = () => {}; g.clearInterval = () => {};
  g.queueMicrotask = (f) => { try { f(); } catch (_) {} };
  g.decodeURIComponent = decUriStub;      // 桩: 记录解码结果
  g.atob = atobStub; g.btoa = btoaStub;
  g.Buffer = Buf;
  g.JSON = { parse: jpStub, stringify: cJSON.stringify };
  // 网络/进程：全部替换为只记录桩（绝不暴露真实 http/https/net/dns/child_process）
  g.fetch = netStub('fetch'); g.XMLHttpRequest = xhrStub;
  g.WebSocket = function () { note('[BLOCKED][WebSocket] 离线沙箱拦截'); return { close() {}, send() {}, addEventListener() {} }; };
  g.importScripts = netStub('importScripts');
  // 浏览器最小面
  g.window = g; g.self = g; g.globalThis = g; g.global = g;
  g.document = { getElementById: () => null, querySelector: () => null, querySelectorAll: () => [], createElement: () => ({ style: {}, setAttribute() {}, appendChild() {} }), createElementNS: () => ({ style: {}, setAttribute() {}, appendChild() {} }), cookie: '', documentElement: {}, body: {}, addEventListener() {}, removeEventListener() {} };
  g.navigator = { userAgent: 'facet-DynamicProbe', language: 'en', platform: 'node', appVersion: '' };
  g.location = { href: '', protocol: 'https:', host: '', hostname: '', port: '', pathname: '/', search: '', hash: '', assign() {}, replace() {} };
  g.history = { pushState() {}, replaceState() {}, back() {}, forward() {} };
  g.screen = { width: 0, height: 0 };
  // Node 最小面（Confuser 风格 VM 尾部 getter 会取这些）
  const safeRequire = (name) => {
    note('[BLOCKED][require:' + String(name) + '] 返回安全空模块, 未加载真实模块');
    if (name === 'buffer') return Buf;
    if (name === 'crypto') return { randomBytes: (n) => new SSBuf(Math.max(0, (n | 0))), createHash: () => ({ update() { return this; }, digest() { return ''; } }) };
    if (name === 'util') return { inspect: () => '', format: () => '' };
    return new Proxy({}, { get() { return () => undefined; } });
  };
  g.require = safeRequire;
  g.module = { exports: {} }; g.exports = g.module.exports;
  g.__dirname = '/'; g.__filename = 'index.js';
  g.process = { env: {}, argv: ['node', 'index.js'], argv0: 'node', platform: 'linux', arch: 'x64', versions: {}, cwd: () => '/', nextTick: (f) => { try { f(); } catch (_) {} }, stdout: { write() {} }, stderr: { write() {} }, on() {}, exit() {} };
  // 抗篡改（L4）：固定常被用于反调试的时钟 / 随机源，减少运行期扰动
  if (tier >= 4) {
    const _t = 1700000000000;
    const cDate = g.Date;
    g.Date = class extends cDate { constructor(...a) { if (a.length === 0) super(_t); else super(...a); } static now() { return _t; } };
    g.performance = { now: () => _t };
    const cMath = g.Math;
    const _r = 0.5;
    g.Math = new Proxy(cMath, { get(t, p) { if (p === 'random') return () => _r; return t[p]; } });
  } else {
    g.performance = { now: () => 0 };
  }

  // ---- Function / eval 插桩: 捕获内层源码; 用**上下文内建**构造, 使创建的函数留在沙箱 realm ----
  const origFunction = g.Function;
  g.Function = function (...args) {
    const body = args.length ? args[args.length - 1] : '';
    if (typeof body === 'string') {
      innerSources.push(body);
      recStr(body.slice(0, 256));
      if (tier >= 4) {
        const loops = (body.match(/\bwhile\b/g) || []).length + (body.match(/\bfor\s*\(/g) || []).length;
        if (body.length <= MAX_LEN && loops <= MAX_LOOPS) {
          capturedFns.push({ fn: origFunction.apply(null, args), len: body.length, loops });
          methods.add('l4-safe-exec-candidate');
        }
      }
      methods.add('inner-source-capture');
    }
    return origFunction.apply(null, args);
  };
  const origEval = g.eval;
  g.eval = function (s) {
    if (typeof s === 'string') { innerSources.push(s); recStr(s.slice(0, 256)); methods.add('inner-source-capture'); }
    return origEval(s);
  };

  methods.add('sealed-vm-offline');
  methods.add('network-stub-blocked');
  methods.add('instrument-atob');
  methods.add('instrument-json-parse');
  methods.add('instrument-buffer');
  methods.add('realm-isolated-stubs');
  if (tier >= 4) methods.add('anti-tamper-stubs');

  // 记录注入的键快照 —— 运行后**新增**的键即目标代码挂到沙箱全局上的(window.X / globalThis.X)
  const preKeys = new Set(Object.keys(g));
  return { methods, innerSources, capturedFns, preKeys };
}

/**
 * 构造密封上下文。所有网络/进程原语都被替换为只记录、不发送的桩。
 *
 * 🔴 沙箱环境在**上下文内**构建（见 `build_sandbox_env`）；宿主只经 `bridge` 传辅助，
 *    bridge 方法**只返回原始值**。返回的句柄（methods/innerSources/capturedFns/preKeys）
 *    都是上下文对象，宿主可安全读取。
 * 返回 { ctx, capture, methods, innerSources, capturedFns, record_url, record_str, scan_urls, preKeys }。
 */
function make_sealed_context(tier) {
  const capture = { urls: [], strings: [], config: {}, notes: [] };
  const seenUrl = new Set();
  const seenStr = new Set();

  const record_url = (u) => {
    if (typeof u !== 'string') return;
    const m = u.match(URL_RE);
    if (!m) return;
    for (const hit of m) {
      const c = hit.replace(/[.,;:)\]}]+$/, '');
      if (!seenUrl.has(c)) { seenUrl.add(c); capture.urls.push(c); }
    }
  };
  const record_str = (s) => {
    if (typeof s !== 'string' || s.length < 6) return;
    if (/^[\d.,\s/+=\-]+$/.test(s)) return;           // 纯数字/符号噪音
    if (seenStr.has(s)) return;
    seenStr.add(s);
    capture.strings.push(s);
  };

  // 宿主↔沙箱桥：**只返回原始值**（string/number/undefined）—— 原始值不携带 realm。
  const bridge = {
    tier,
    maxLen: SAFE_EXEC_MAX_LEN,
    maxLoops: SAFE_EXEC_MAX_LOOPS,
    recStr: (s) => record_str(typeof s === 'string' ? s : String(s)),
    recUrl: (u) => record_url(typeof u === 'string' ? u : String(u)),
    note: (m) => { capture.notes.push(String(m)); },
    b64dec: (s) => { try { return Buffer.from(String(s), 'base64').toString('utf8'); } catch (_) { return ''; } },
    b64enc: (s) => { try { return Buffer.from(String(s), 'utf8').toString('base64'); } catch (_) { return ''; } },
    // string --enc--> 字节(以 latin1 字符串承载，逐字节无损)
    bytes: (s, enc) => { try { return Buffer.from(String(s), enc || 'utf8').toString('latin1'); } catch (_) { return ''; } },
    // 字节(latin1) --enc--> string
    text: (latin1, enc) => { try { return Buffer.from(String(latin1), 'latin1').toString(enc || 'utf8'); } catch (_) { return ''; } },
  };

  const ctx = {};
  vm.createContext(ctx);
  // 取回 build_sandbox_env 的**源码**，在上下文内求值 → 得到上下文函数 → 由它创建的一切属沙箱 realm。
  let makeEnv;
  try {
    makeEnv = vm.runInContext('(' + build_sandbox_env.toString() + '\n)', ctx, { filename: 'sandbox-boot.js' });
  } catch (e) {
    throw new Error('sandbox boot 求值失败(realm 隔离不可用, 拒绝以不安全方式运行): ' + (e && e.message || String(e)));
  }
  const env = makeEnv(bridge);
  return {
    ctx, capture,
    methods: env.methods, innerSources: env.innerSources, capturedFns: env.capturedFns,
    record_url, record_str, scan_urls: (s) => record_url(s), preKeys: env.preKeys,
  };
}

// ---- 从内层源码里抽取「配置键:值」启发式（仅记录非 URL 的短值） ----
function harvest_config(innerSources, capture) {
  const re = /["']([A-Za-z_][\w.\-]{2,48})["']\s*:\s*["']([^"']{1,200})["']/g;
  for (const src of innerSources) {
    let m;
    while ((m = re.exec(src))) {
      const k = m[1], v = m[2];
      if (/^(https?|wss?):/i.test(v)) continue;       // URL 已单独收录
      if (v.length < 2) continue;
      try { capture.config[k] = v; } catch (_) {}
    }
  }
}

function run_vm_tier(code, report, outFile, tier) {
  const { ctx, capture, methods, innerSources, capturedFns, record_url, record_str, scan_urls, preKeys } = make_sealed_context(tier);
  const errors = report.errors || (report.errors = []);
  // 顶层运行（捕获插桩在这个阶段就已生效）。ctx 已由 make_sealed_context 上下文化,
  // 故用 runInContext; vm 内置 timeout 为毫秒下限保护, 防止顶层死循环拖挂。
  try {
    vm.runInContext(code, ctx, { filename: 'target.js', timeout: 30000 });
  } catch (e) {
    errors.push('top-level: ' + (e && e.message || String(e)));
  }
  // 捕获 module.exports / exports —— UMD / 打包器常把「还原后的配置 / 端点」挂在此，
  // 是 VM/字节码解包最直接的产出（比逐条字符串启发式更完整）。
  try {
    const mx = (ctx.module && ctx.module.exports) || ctx.exports;
    if (mx && typeof mx === 'object' && Object.keys(mx).length) {
      report.module_exports = safe_stringify(mx, 8);
      harvest_exports(mx, capture, record_url, record_str);
      // 若导出里带 config 子对象（UMD 常见），直接取其标量键作为配置线索（干净、无端点噪声）
      if (mx.config && typeof mx.config === 'object') {
        for (const k of Object.keys(mx.config)) {
          const v = mx.config[k];
          if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
            try { capture.config[k] = v; } catch (_) {}
          }
        }
      }
      methods.add('module-exports-captured');
    }
  } catch (e) {
    errors.push('exports: ' + (e && e.message || String(e)));
  }
  // 捕获目标代码新增的**沙箱全局**(window.X / globalThis.X)——浏览器包常把配置挂全局
  //   (如 window.__CONFIG__ / __INITIAL_STATE__)。仅取运行后新增的键(排除我们注入的桩)。
  try {
    const globals = {};
    for (const k of Object.keys(ctx)) {
      if (preKeys.has(k)) continue;
      let v;
      try { v = ctx[k]; } catch (_) { continue; }
      if (v === undefined || typeof v === 'function') continue;
      harvest_exports(v, capture, record_url, record_str);
      globals[k] = safe_stringify(v, 4);
    }
    if (Object.keys(globals).length) {
      report.globals = globals;
      methods.add('globals-captured');
    }
  } catch (e) {
    errors.push('globals: ' + (e && e.message || String(e)));
  }
  // L4：对安全门控通过的内层函数执行解包
  if (tier >= 4) {
    for (const item of capturedFns) {
      try {
        item.fn(undefined, {}, '', 0, null);
        methods.add('l4-safe-exec-ran');
      } catch (e) {
        errors.push('exec-fn: ' + (e && e.message || String(e)));
      }
    }
  }
  // 内层源码再扫一遍 URL（有些 URL 仅在源码文本里，运行期未必触发）
  for (const s of innerSources) scan_urls(s);
  harvest_config(innerSources, capture);

  // 展开产物：原码 + 捕获的内层源码（供下游静态管线再分析）
  let out = code;
  if (innerSources.length) {
    out += '\n\n/* ===== facet dynamic unpack (L' + tier + ') captured inner sources ===== */\n';
    out += innerSources.join('\n\n/* ---- inner ---- */\n\n');
  }
  try { fs.writeFileSync(outFile, out); } catch (e) { errors.push('write-out: ' + e.message); }

  report.tier = tier;
  report.methods = Array.from(methods);
  report.captured = capture;
  report.inner_sources = innerSources.length;
  report.ok = true;
}

async function run_browser_tier(code, report, outFile, tier) {
  const pw = load_browser();
  if (!pw) { report.captured.notes.push('L5 Playwright/Chromium 不可用 → 降级 L3/L4'); return false; }
  let browser;
  try {
    const chromium = pw.chromium || (pw.default && pw.default.chromium);
    browser = await chromium.launch({ args: ['--no-sandbox'] });
    const page = await browser.newPage();
    const urls = new Set();
    const strings = new Set();
    // 请求拦截：全部 BLOCK + LOG，绝不真正发出
    await page.route('**/*', (route) => {
      const u = route.request().url();
      urls.add(u);
      report.captured.notes.push('[BLOCKED][browser:' + route.request().method() + '] ' + u);
      return route.abort();
    });
    await page.addInitScript(() => {
      const _f = window.fetch;
      window.fetch = function (...a) { console.log('[BLOCKED][browser-fetch]', a[0]); return Promise.resolve(new Response('', { status: 0 })); };
      window.XMLHttpRequest = function () { return { open() {}, send() {}, abort() {}, setRequestHeader() {}, addEventListener() {} }; };
    });
    page.on('console', (msg) => { const t = msg.text(); strings.add(t); });
    await page.setContent('<html><body></body></html>');
    try { await page.addScriptTag({ content: code }); } catch (e) { report.errors.push('browser-eval: ' + e.message); }
    // 给解包逻辑一点运行时间
    await page.waitForTimeout ? page.waitForTimeout(500) : new Promise((r) => setTimeout(r, 500));
    for (const u of urls) if (/^https?:\/\//i.test(u)) report.captured.urls.push(u);
    for (const s of strings) report.captured.strings.push(s);
    report.methods.push('l5-browser');
    // 浏览器内解包结果同样落盘供下游分析
    try { fs.writeFileSync(outFile, code); } catch (e) {}
    return true;
  } catch (e) {
    report.errors.push('browser: ' + e.message);
    return false;
  } finally {
    if (browser) try { await browser.close(); } catch (_) {}
  }
}

function main() {
  const inPath = process.argv[2];
  const outPath = process.argv[3] || (inPath + '.dyn.js');
  const tier = parseInt(process.argv[4] || '3', 10);
  const repPath = outPath + '.report.json';

  if (!inPath || !fs.existsSync(inPath)) {
    process.stderr.write('USAGE: node deobf_dynamic.cjs <in.js> <out.js> <tier>\n');
    process.exit(2);
  }
  const report = { tool: 'facet-deobf-dynamic', available: true, tier, captured: { urls: [], strings: [], config: {}, notes: [] }, methods: [], errors: [], inner_sources: 0, ok: false };
  let code = '';
  try { code = fs.readFileSync(inPath, 'utf8'); } catch (e) {
    report.available = false; report.reason = 'read-fail: ' + e.message;
    fs.writeFileSync(repPath, JSON.stringify(report, null, 2)); process.exit(2);
  }

  if (tier >= 5) {
    run_browser_tier(code, report, outPath, tier).then(() => {
      if (!report.methods.includes('l5-browser')) {
        // 降级
        run_vm_tier(code, report, outPath, Math.max(3, tier - 1));
      }
      finish(report, repPath);
    }).catch((e) => { report.errors.push('fatal-l5: ' + (e && e.message || String(e))); run_vm_tier(code, report, outPath, 3); finish(report, repPath); });
  } else {
    try { run_vm_tier(code, report, outPath, tier); } catch (e) { report.errors.push('fatal: ' + (e && e.stack || e)); }
    finish(report, repPath);
  }
}

function finish(report, repPath) {
  // 去重
  const c = report.captured;
  c.urls = Array.from(new Set(c.urls));
  c.strings = Array.from(new Set(c.strings)).slice(0, 2000);
  report.methods = Array.from(new Set(report.methods));
  try { fs.writeFileSync(repPath, JSON.stringify(report, null, 2)); } catch (_) {}
  process.stdout.write(JSON.stringify({ tool: report.tool, tier: report.tier, urls: c.urls.length, strings: c.strings.length, inner_sources: report.inner_sources, ok: report.ok }) + '\n');
  process.exit(0);
}

main();
