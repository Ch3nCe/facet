#!/usr/bin/env node
/*
 * facet — 强反混淆辅助脚本（opt-in，静态分析，绝不执行目标代码）。
 *
 * 能力：
 *   1) javascript-obfuscator / webpack 打包：调用 webcrack（纯 AST 静态反混淆 / 拆包），
 *      还原字符串数组、重命名、控制流、还原可读源码。
 *   2) VM / 字节码打包（如 ConfuserEx 风格）：webcrack 无法还原源码。本脚本做
 *      「零宽转义序列 → 可见标记 + \uHHHH/\xHH 转义解码」的可读化（navigability）处理，
 *      使字节码 / 标识符结构可被人工审计，并尽量揭示其中编码过的明文常量。
 *
 * 重要：本脚本只做 AST 解析 / 字符串变换 / 转义解码，**不 eval、不运行目标逻辑**。
 *
 * 用法：
 *   node deobf_strong.cjs <in.js> [out.js] [webcrack_entry]      # 单文件(向后兼容)
 *   node deobf_strong.cjs --batch <manifest.json>                # 批量(webcrack 只加载一次)
 *     manifest = { "webcrack_entry": "...", "jobs": [{"in": "...", "out": "..."}, ...] }
 *     批量结果写 <manifest>.results.json；每 job 的 out + <out>.report.json 照常落盘。
 *   退出码：0 成功 / 2 参数错误 / 1 运行时错误（仍会写出尽力而为的结果）
 */
'use strict';
const fs = require('fs');
const path = require('path');

// ---- 解析 webcrack（优先 NODE_PATH，其次常见位置） ----
function load_webcrack(explicit) {
  const candidates = [];
  if (explicit) candidates.push(explicit);
  if (process.env.NODE_PATH) {
    process.env.NODE_PATH.split(path.delimiter).forEach((p) => {
      if (p) candidates.push(path.join(p, 'webcrack'));
    });
  }
  candidates.push('webcrack');
  for (const c of candidates) {
    try {
      const m = require(c);
      const fn = m && (m.webcrack || m.default || m);
      if (typeof fn === 'function') return fn;
    } catch (_) { /* try next */ }
  }
  return null;
}

// 惰性加载 + 缓存的 webcrack getter —— VM 文件不会白白加载 webcrack；
//   批量模式下第一个非 VM 文件触发加载后**全批复用**(省掉逐文件的 Node+webcrack 启动)。
function make_webcrack_getter(explicit) {
  let loaded = false;
  let cached = null;
  return () => {
    if (!loaded) { cached = load_webcrack(explicit); loaded = true; }
    return cached;
  };
}

// 把 JS 字符串字面量里的 \uHHHH / \u{HHHH} / \xHH 还原为真实字符（仅字符级，不改结构）。
// 负向环视排除已被转义的 \\u / \\x。用于揭示字节码里编码过的明文常量。
function decode_escapes(s) {
  if (!s || s.indexOf('\\') === -1) return s;
  s = s.replace(/(?<!\\)\\u\{([0-9a-fA-F]{1,6})\}/g, (m, p) => {
    try { return String.fromCodePoint(parseInt(p, 16)); } catch (_) { return m; }
  });
  s = s.replace(/(?<!\\)\\u([0-9a-fA-F]{4})/g, (m, p) => {
    try { return String.fromCharCode(parseInt(p, 16)); } catch (_) { return m; }
  });
  s = s.replace(/(?<!\\)\\x([0-9a-fA-F]{2})/g, (m, p) => {
    try { return String.fromCharCode(parseInt(p, 16)); } catch (_) { return m; }
  });
  return s;
}

// 处理单个源 → { code, report }。`getWebcrack` 为惰性 getter（单文件/批量共用）。
async function process_one(src, getWebcrack) {
  let code = src;
  let detected = 'unknown';
  const method = [];
  let note = '';

  // 检测 VM / 字节码打包：源码里大量「字面零宽转义序列」(\u200B/C/D/FEFF 的 ASCII 文本)
  // 或 Function("in...") 自定义解释器入口。注意：这些是 JS 转义文本，并非真实零宽字符。
  const zwEsc = (src.match(/\\u200[bcd]/gi) || []).length + (src.match(/\\uFEFF/gi) || []).length;
  const vmEntry = /Function\(\s*["']in/.test(src);
  const isVM = zwEsc > 20 || (vmEntry && zwEsc > 0);

  if (isVM) {
    // —— 静态可读化：零宽转义序列 → 可见标记；并解码其它 \uHHHH/\xHH 揭示编码常量 ——
    code = src
      .replace(/\\u200[bcd]/gi, '_Z_')
      .replace(/\\uFEFF/gi, '_Z_');
    code = decode_escapes(code);
    detected = 'vm/bytecode packer (ConfuserEx-style) — 源码级还原需动态拆包器；本层仅做静态可读化';
    method.push('zero-width-escape->marker', 'escape-decode');
  } else {
    // —— javascript-obfuscator / webpack：webcrack 静态 AST 还原 ——
    const webcrack = getWebcrack();
    if (webcrack) {
      try {
        const res = await webcrack(src, { mangle: false });
        const out = (res && (res.code || res.deobfuscatedCode)) || '';
        // webcrack 对**纯明文**也会美化(→ out!=src), 故须先判断 src 是否真像混淆/打包产物,
        //   否则会把明文误标为 javascript-obfuscator(标签失真)。
        const _obfHits = (src.match(/_0x[0-9a-fA-F]{2,}/g) || []).length;
        const looksObf = _obfHits > 5 || /String\.fromCharCode/.test(src)
                         || (src.indexOf('\n') === -1 && src.length > 2000);
        if (out && out.length > 0 && out !== src) {
          code = out;
          detected = looksObf
            ? 'javascript-obfuscator / webpack (webcrack static deobfuscate)'
            : 'no-obfuscation (webcrack beautify only)';
          if (looksObf) method.push('webcrack');
        } else {
          detected = 'no-obfuscation / unknown (webcrack no-op)';
        }
      } catch (e) {
        note = 'webcrack error: ' + e.message;
        detected = 'unknown';
      }
    } else {
      note = 'webcrack not available';
      detected = 'unknown';
    }
  }

  const report = {
    tool: 'facet-deobf-strong',
    detected,
    methods: method,
    is_vm_packer: isVM,
    output_bytes: Buffer.byteLength(code, 'utf8'),
    zero_width_escape_sequences: zwEsc,
    demo_lab_strings: (code.match(/demo-lab/g) || []).length,
    note: note || null,
    ok: true,
  };
  return { code, report };
}

async function main() {
  const a2 = process.argv[2];

  // ---- 批量模式: node deobf_strong.cjs --batch <manifest.json> ----
  if (a2 === '--batch') {
    const mpath = process.argv[3];
    if (!mpath || !fs.existsSync(mpath)) {
      process.stderr.write('USAGE: node deobf_strong.cjs --batch <manifest.json>\n');
      process.exit(2);
    }
    const man = JSON.parse(fs.readFileSync(mpath, 'utf8'));
    const getWebcrack = make_webcrack_getter(man.webcrack_entry || null);
    const results = [];
    for (const job of (man.jobs || [])) {
      try {
        const src = fs.readFileSync(job.in, 'utf8');
        const { code, report } = await process_one(src, getWebcrack);
        fs.writeFileSync(job.out, code);
        fs.writeFileSync(job.out + '.report.json', JSON.stringify(report, null, 2));
        results.push({ ok: true, report });
      } catch (e) {
        results.push({ ok: false, error: String((e && e.message) || e) });
      }
    }
    fs.writeFileSync(mpath + '.results.json', JSON.stringify({ results }, null, 2));
    process.stdout.write(JSON.stringify({ batch: true, n: results.length }) + '\n');
    return;
  }

  // ---- 单文件模式(向后兼容) ----
  const inPath = a2;
  const outPath = process.argv[3] || (inPath + '.strong.js');
  const wcEntry = process.argv[4] || null;
  if (!inPath || !fs.existsSync(inPath)) {
    process.stderr.write('USAGE: node deobf_strong.cjs <in.js> [out.js] [webcrack_entry]\n');
    process.exit(2);
  }
  const src = fs.readFileSync(inPath, 'utf8');
  const { code, report } = await process_one(src, make_webcrack_getter(wcEntry));
  fs.writeFileSync(outPath, code);
  fs.writeFileSync(outPath + '.report.json', JSON.stringify(report, null, 2));
  process.stdout.write(JSON.stringify(report) + '\n');
}

main().catch((e) => {
  process.stderr.write('FATAL: ' + (e && e.stack || e) + '\n');
  process.exit(1);
});
