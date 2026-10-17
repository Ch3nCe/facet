#!/usr/bin/env node
'use strict';
/*
 * facet — JS「简单编码」解码 Harness（JSFuck / AAencode 颜文字 / JJencode / Jother）。
 *
 * 定位：发现级只读。这类编码的本质是「一段用怪字符（[]()!+ / 颜文字 / $ 变量）写成的 JS 表达式，
 *   运行后得到一个字符串，再交给 Function/eval 执行」。本 Harness 在**密封、离线、零网络**的 vm
 *   沙箱里运行这段**编码表达式**，并在**上下文内部**把
 *     · 执行入口（Function / Function.prototype.constructor / eval）包成「捕获 + 委托」
 *       —— 捕获其**入参源码**（即被编码的明文），同时委托真实实现让编码机件自身可用；
 *     · 输出口（alert / confirm / prompt / console.* / document.write）替换为「只捕获」桩
 *       —— 拿到「本来会弹出的明文」；
 *     · 网络/进程原语（fetch/XHR/WebSocket/require/process…）替换为「只记录、不发送」桩。
 *
 * 🔴 realm 隔离：**不向沙箱注入任何宿主内建**（否则目标 `Function(...)` 会在宿主 realm 运行 =
 *   逃逸）。所有桩都在上下文内用 `vm.runInContext` 定义，只用上下文自身的 `Function`/`Object`…
 *
 * 合规：零网络；载荷在本地密封沙箱内展开（等价 dynamic 层的隔离姿态），不向任何地址发包。
 *
 * 退出码：0 成功 / 2 参数/输入错误 / 1 运行时错误（仍尽力写出结果）。
 * 用法：node deobf_encodings.cjs <in.js> <out.txt>
 *   写出：<out.txt>             每行一条解码出的明文字符串
 *         <out.txt>.report.json  捕获报告（decoded / notes / methods / errors）
 */
const fs = require('fs');
const vm = require('vm');

// 在**上下文内部**建立密封环境；捕获结果存于上下文的 `__cap` 数组（宿主运行后读取）。
const SETUP = `
(function () {
  var cap = [];
  try { Object.defineProperty(globalThis, '__cap', { value: cap, writable: false, enumerable: false, configurable: false }); } catch (e) { globalThis.__cap = cap; }
  function push(v) {
    try {
      if (typeof v !== 'string') { if (v && typeof v === 'object') { try { v = JSON.stringify(v); } catch (e) { return; } } else { return; } }
      if (v.length >= 6) cap.push(v);
    } catch (e) {}
  }
  globalThis.__push = push;

  // ---- 执行入口：捕获入参源码 + 委托真实实现（保持编码机件可用） ----
  var _Fn = Function;
  var _FnCtor = Function.prototype.constructor;
  var _eval = eval;
  function capFn() {
    for (var i = 0; i < arguments.length; i++) push(arguments[i]);
    return _Fn.apply(this, arguments);
  }
  globalThis.Function = capFn;
  try { Function.prototype.constructor = function () {
    for (var i = 0; i < arguments.length; i++) push(arguments[i]);
    return _FnCtor.apply(this, arguments);
  }; } catch (e) {}
  globalThis.eval = function (s) { push(s); return _eval(s); };

  // ---- 输出口：只捕获 ----
  function capOut() { push([].join.call(arguments, ' ')); }
  globalThis.alert = capOut;
  globalThis.confirm = function () { capOut.apply(null, arguments); return false; };
  globalThis.prompt = function () { capOut.apply(null, arguments); return ''; };
  globalThis.console = { log: capOut, info: capOut, warn: capOut, error: capOut, debug: capOut, trace: function () {} };
  globalThis.document = {
    write: capOut, writeln: capOut,
    getElementById: function () { return null; }, querySelector: function () { return null; },
    querySelectorAll: function () { return []; },
    createElement: function () { return { style: {}, setAttribute: function () {}, appendChild: function () {} }; },
    createElementNS: function () { return { style: {}, setAttribute: function () {}, appendChild: function () {} }; },
    cookie: '', documentElement: {}, body: {}, addEventListener: function () {}, removeEventListener: function () {}
  };
  globalThis.navigator = { userAgent: 'facet-EncodingProbe', language: 'en', platform: 'node' };
  globalThis.location = { href: '', protocol: 'https:', host: '', hostname: '', port: '', pathname: '/', search: '', hash: '', assign: function () {}, replace: function () {} };
  globalThis.history = { pushState: function () {}, replaceState: function () {}, back: function () {}, forward: function () {} };
  globalThis.screen = { width: 0, height: 0 };
  globalThis.setTimeout = function (f) { if (typeof f === 'function') { try { f(); } catch (e) {} } return 0; };
  globalThis.setInterval = function () { return 0; };
  globalThis.setImmediate = function (f) { if (typeof f === 'function') { try { f(); } catch (e) {} } return 0; };
  globalThis.clearTimeout = function () {}; globalThis.clearInterval = function () {};
  globalThis.queueMicrotask = function (f) { try { f(); } catch (e) {} };

  // ---- 网络 / 进程原语：只记录、不发送 ----
  globalThis.fetch = function () { return { ok: false, status: 0, text: function () { return Promise.resolve(''); }, json: function () { return Promise.resolve({}); } }; };
  globalThis.importScripts = function () {};
  globalThis.XMLHttpRequest = function () { return { open: function () {}, send: function () {}, abort: function () {}, setRequestHeader: function () {}, addEventListener: function () {}, status: 0, responseText: '', response: null }; };
  globalThis.WebSocket = function () { return { close: function () {}, send: function () {}, addEventListener: function () {} }; };
  globalThis.require = function () { return new Proxy({}, { get: function () { return function () {}; } }); };
  globalThis.process = { env: {}, argv: ['node', 'index.js'], argv0: 'node', platform: 'linux', arch: 'x64', versions: {}, cwd: function () { return '/'; }, nextTick: function (f) { try { f(); } catch (e) {} }, stdout: { write: function () {} }, stderr: { write: function () {} }, on: function () {}, exit: function () {} };
  globalThis.module = { exports: {} };
  globalThis.exports = globalThis.module.exports;
  globalThis.window = globalThis; globalThis.self = globalThis; globalThis.global = globalThis;
})();
`;

function make_ctx() {
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(SETUP, ctx);
  return ctx;
}

function run(code, report) {
  const ctx = make_ctx();
  const preKeys = new Set(Object.keys(ctx));   // 桩自身的键(不计入捕获)
  // 1) 先跑整份输入（覆盖「文件本身即编码」的 AAencode / JJencode / JSFuck）。
  try {
    vm.runInContext(code, ctx, { filename: 'encoded.js', timeout: 5000 });
  } catch (e) {
    report.errors.push('run: ' + ((e && e.message) || String(e)));
  }
  // 2) 再抽取「长 `[]()!+` 连续串」逐个求值 —— JSFuck 常**嵌在更大文件里**（如藏在某个函数体内），
  //    顶层运行不会自动触发；而 JSFuck 表达式仅由 `[]()!+` 构成，故按连续串抽出即得该表达式。
  const runs = code.match(/[\[\]\(\)!\+](?:[\[\]\(\)!\+]|\s){99,}/g) || [];
  for (const r of runs.slice(0, 20)) {
    const expr = r.replace(/\s+/g, '');
    if (expr.length < 100) continue;
    try {
      vm.runInContext('(' + expr + ')', ctx, { filename: 'jsfuck.js', timeout: 5000 });
      report.methods.push('jsfuck-run-extracted');
    } catch (e) {
      report.errors.push('jsfuck-run: ' + ((e && e.message) || String(e)));
    }
  }
  // 目标代码**运行后新增**的全局字符串（AAencode 的 `_` / JJencode 的 `$` 等）
  try {
    for (const k of Object.keys(ctx)) {
      if (preKeys.has(k)) continue;
      let v; try { v = ctx[k]; } catch (_) { continue; }
      if (typeof v === 'string') report.decoded.push(v);
      else if (v && typeof v === 'object') {
        try { for (const kk of Object.keys(v)) { if (typeof v[kk] === 'string') report.decoded.push(v[kk]); } } catch (_) {}
      }
    }
  } catch (e) { report.errors.push('globals: ' + ((e && e.message) || String(e))); }
  try {
    const cap = ctx.__cap;
    if (Array.isArray(cap)) for (const s of cap) report.decoded.push(s);
  } catch (_) {}
  // 去重 + 过滤纯符号/数字噪声
  const seen = new Set();
  report.decoded = report.decoded.filter((s) => {
    if (typeof s !== 'string' || s.length < 6 || seen.has(s)) return false;
    if (/^[\d.,\s/+=\-]+$/.test(s)) return false;                       // 纯数字/符号噪声
    if (/^[A-Za-z_$][\w$]*$/.test(s) && s.length < 16) return false;     // 裸标识符(编码机件内部串)
    seen.add(s); return true;
  }).slice(0, 500);
  report.methods = Array.from(new Set(
    ['sealed-vm-offline', 'exec-entry-captured', 'output-captured', 'network-stub-blocked']
      .concat(report.methods || [])));
  report.ok = true;
}

function main() {
  const inPath = process.argv[2];
  const outPath = process.argv[3] || (inPath + '.decoded.txt');
  const repPath = outPath + '.report.json';
  const report = { tool: 'facet-deobf-encodings', available: true, decoded: [], notes: [], methods: [], errors: [], ok: false };
  if (!inPath || !fs.existsSync(inPath)) {
    process.stderr.write('USAGE: node deobf_encodings.cjs <in.js> <out.txt>\n');
    process.exit(2);
  }
  let code = '';
  try { code = fs.readFileSync(inPath, 'utf8'); } catch (e) {
    report.available = false; report.reason = 'read-fail: ' + e.message;
    fs.writeFileSync(repPath, JSON.stringify(report, null, 2)); process.exit(2);
  }
  try { run(code, report); } catch (e) { report.errors.push('fatal: ' + ((e && e.stack) || e)); }
  try { fs.writeFileSync(outPath, (report.decoded || []).join('\n')); } catch (e) { report.errors.push('write-out: ' + e.message); }
  try { fs.writeFileSync(repPath, JSON.stringify(report, null, 2)); } catch (_) {}
  process.stdout.write(JSON.stringify({ tool: report.tool, decoded: (report.decoded || []).length, ok: report.ok }) + '\n');
  process.exit(0);
}

main();
