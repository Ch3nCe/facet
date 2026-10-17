# 变更记录（Changelog）

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.1.0] - 2026-10-16

当前版本。在 1.0 侦察内核之上完成**发现质量、披露纪律与自动化**三方面的体系化建设。

### 新增（Added）

- **AST 级 JS 提取**：Node.js + acorn 真 AST 解析——变量拼接基址、模板字符串、
  `xhr.open` 第二参、`baseURL`/`path` 对象属性、形参排除、循环引用保护；
  按 acorn → tree-sitter → 正则三层自动降级，依赖缺失时回退并在报告中如实披露。
- **AST 结构化侧车**（`--sidecars`，`ast_sidecar: auto`）：逐 JS 源输出结构化
  摘要（模块 / 函数 / 基址 / 端点集合），供流水线消费。
- **端点证据分级**：逐端点标注 `runtime` / `full-url` / `static` / `dict` 四级
  证据，报告披露分布；排序契约保证字典猜测端点永远排在有据端点之后。
- **端点 kind 分类**：`backend_api` / `frontend_route` / `unknown` 启发式
  分类（写方法声明 / 前端路由集合 / API 前缀 / REST 动作段等信号）。
- **运行时三态披露**：报告区分「已配置但未触发」（auto 未命中 SPA 信号）与
  「已请求但未实际运行」（浏览器启动失败等能力缺口）；JSON 侧增加
  `completeness.runtime.triggered` 字段。
- **文档站噪声消除**：识别文档 / 演示站点的库 bundle 密集特征
  （`vendor_bundle_skip`），跳过库代码提取并在报告中披露跳过数。
- **语义化 SourceMap 调度**：`.js.map` 声明按语义排入解析队列，还原压缩前
  原始坐标；黑名单可配（`sourcemap_blacklist`）。
- **标准格式导出**：`--export sarif,burp,zap`，与 HTML/JSON 报告同源。
- **侧车体系**（`--sidecars`）：端点标注 JSON / 端点清单 / 增量 diff（供 CI
  门禁）/ 只读复现脚本 `replay.sh` / 动态解包还原产物。
- **复制全部接口**：HTML 报告一键导出全部端点。
- **MCP stdio 服务**（`facet-mcp`）：5 个工具（`scan` / `list_tasks` /
  `get_task` / `stop_task` / `get_report`）；`scan` 需显式 `authorized=true`，
  options schema 严格（仅 `cookie` / `token`）。
- **资产库辅助 CLI**（`facet-asset`）：跨目标只读检索（`targets` /
  `endpoints` / `findings` / `shared`）。
- **思考计划**（`--think`）：默认本地动态推理（零外部依赖），配置
  `llm_base_url` + `llm_api_key` 后切换 LLM 推理（只发聚合信号，不含凭据 /
  响应体）。
- **登录态采集**（`--login-capture`，opt-in）与 **浏览器交互**
  （`--interactive`，opt-in，写方法请求被只读护栏拦截）。

### 变更（Changed）

- **写路径双轨**：写方法端点同时进入 `write_apis`（POST 映射）与 `apis`
  （保留只读 GET 可达性验证），合规红线不变——只提取、不发验证包。
- **报告体积优化**：`<pre>` 内容转义拆分（`_esc_text` 仅转义 `&<>`，属性上下文
  才转义引号），消除 `&quot;` 六倍膨胀。
- **帮助文本准确性**：合规条款第 6 条 UA 表述修正为 `ua` / `waf_probe_ua`
  两个配置键（此前误引不存在的 `--ua` 参数）。

### 修复（Fixed）

- **断点续扫状态落盘门控**：`--persist-state` 此前**不触发**状态文件写入——
  保存条件只含 `--resume` / seen 撞 `max_js` 上限，漏了 `persist_state` 本身：
  小站（seen 远小于上限、未传 `--resume`）只传 `--persist-state` 时状态文件
  永不生成，随后 `--resume`「按空状态开始」却无任何提示（假成功），与
  `_get_state_store` / `MemoryStateStore` / DEFAULT_CONFIG 三处「resume /
  persist_state 才落盘」的声明不一致。已修复（门控提取为
  `_should_save_state`，补回归钉子 `test_should_save_state_gating`）。
- **runtime auto 未触发原因丢失**：未触发时（页面类型 / 框架指纹 / 前端路由
  密集均未命中）现在给出非空原因，报告可区分「没请求」与「请求了没跑成」。
- **探活排序**：字典猜测端点（无证据）正确排在有据端点之后，同档按优先级。
- **熔断失败分类：501 不计失败（自挫式覆盖丢失修复）**：`_settle_response`
  此前把**所有 5xx** 计入熔断失败计数。实测：扫描器对只实现 do_GET 的目标
  会发 OPTIONS/POST 探测，目标以 501（方法未实现）回应——这是**成功的否定
  回答**（目标健康、只是不支持该方法），却被当成目标故障，连续 5 个 OPTIONS
  501 即触发熔断 OPEN，后续请求被整段跳过（scope fixture 实测：60 个请求被吞、
  53 条隐藏字典探测零发出；SPA fixture 实测：`circuit_skipped: 146`）。
  现 501 按「成功否定回答」计入 reset（与 405 等 4xx 同口径），429（目标限流）
  与 5xx 其余码（目标侧故障）仍计失败。补回归钉子 `test_settle_response_501_not_failure`。
- **产物写入静默假成功（审计日志 / 状态文件）**：`ctx.audit()` 与
  `FileStateStore.save()` 此前对已开启的能力写入失败时（父目录尚不存在——
  空输出目录首扫、0 JS 落盘 + `--persist-state` 等场景）用 `except` 吞掉、
  仅 `dbg` 留痕（默认不可见），造成「已开启审计 / 已保存状态」的假成功。
  现：① 审计日志路径在 Context 初始化时 `ensure_parent` 预建父目录，且写入失败
  可见化警告一次；② 状态文件保存前 `ensure_parent` 预建父目录，保存失败可见化
  警告一次（复用 D5 报告写入同一 `ensure_parent` 防线）。补回归钉子
  `test_file_state_store_creates_parent_dir` / `test_audit_log_parent_dir_precreated`。

### 测试（Testing）

- 离线测试 **26 项**（无浏览器 / 网络依赖）：
  - `tests/test_regressions.py` —— 6 项行为回归钉子；
  - `tests/test_units.py` —— 18 项核心链路契约（优先级分层 / runtime 三态 /
    AST sidecar 双引擎 / deep_analyze 门控 / 排序与证据零发包 / 截断登记 /
    端点 kind 汇总 / Node 环境探测单一真源 / 任务默认输出目录双形态 /
    断点续扫状态落盘门控 / 熔断 501 不计失败 / 状态文件父目录预建 /
    审计日志父目录预建）；
  - `tests/test_e2e_fixture.py` —— 2 项端到端冒烟（本地 http.server fixture）。
- CI：GitHub Actions 矩阵（Python 3.8 / 3.10 / 3.12），字节编译 + 全量测试。

## [1.0.0] - 初始版本

初始发布：双渠道发现（静态源码 + Playwright 运行时）内核、只读护栏、
合规条款、HTML + JSON 报告、速率限制与熔断、动态解包沙箱（opt-in）、
强反混淆（opt-in）、SCA（OSV）。

---

[未发布]（Unreleased）变更登记于此。

### 修复（Fixed）

- **Node 生态探测统一为单一真源（移机安装修复）**：新增 `core/nodeenv.py`，
  node 二进制与 node_modules 目录的定位逻辑（显式配置/env → PATH → managed
  布局**动态扫描** → 系统路径 / cwd 标准 Node 解析）三处消费方
  （`ast_sidecar` / `deobf` / `recon.unbundle`）共用，消除三套候选链漂移。
  修复：① 原实现钉死开发机 Node 版本路径（`~/.workbuddy-ai/.../22.22.2-3`
  等，该版本在本机即已不存在，属死代码），移机后 AST 侧车与强反混淆整体
  静默降级；② acorn / webcrack 目录仅有本机 managed 路径一条回退，换机必失效。
  本机解析结果与修复前完全一致（node / acorn / webcrack 同目标发现）。
- **MCP 任务默认输出目录不再落进 site-packages（移机安装修复）**：
  `TaskManager` 默认值此前由 `Path(__file__).parent.parent.parent` 派生，
  pip 安装后即 `site-packages/output/gui`（只读环境 mkdir 失败、可写环境
  污染安装目录）；CLI 子进程的 `cwd`/`PYTHONPATH` 同样被钉进 site-packages，
  导致扫描产物全部落进安装目录。现委托 `output.paths.project_root()`
  （源码检出→仓库根；pip 安装→当前工作目录；`FACET_OUTPUT_DIR`
  显式优先），与 CLI 产物同一基准。源码检出形态下行为不变。
- **全新检出可跑测试套件**：① `workdir` fixture 前置 `makedirs`（此前直接向
  gitignore 的 `output/` 下 mkdtemp，全新检出 ENOENT）；② 6 个回归「修复钉子」
  脚本从 `output/` 迁入 `tests/regress/`（纳入版本控制与 sdist），此前在
  sdist / CI 全新检出中全部 FileNotFoundError。
