# facet

> **合规优先的 Web 攻击面侦察套件** —— 一个目标，两个渠道。**发现级 · 只读 · 合规**。

**作者：迷麟Aurora**

facet 从 **静态源码** 与 **运行时流量** 双向发现 Web 应用的端点、参数与风险线索，产出**带证据、可复核**的侦察报告。它只做**发现与陈述**，不做漏洞验证。

> ⚠️ **仅限自有资产、SRC in-scope 或已获书面授权的目标使用。** 使用者对使用行为自行负责 —— 详见 [合规与免责](#合规与免责)。

<p>    
  <img alt="python" src="https://img.shields.io/badge/python-%E2%89%A53.8-blue">    
  <img alt="version" src="https://img.shields.io/badge/version-1.1.0-informational">    
  <img alt="node" src="https://img.shields.io/badge/node-%E2%89%A518%20(optional)-yellow">    
  <img alt="tests" src="https://img.shields.io/badge/tests-18%20offline-brightgreen">    
  <img alt="license" src="https://img.shields.io/badge/license-authorized--only-red">    
</p>

---

## 目录

- [工具描述](#工具描述)
- [核心特性](#核心特性)
- [快速开始](#快速开始)
- [命令参考](#命令参考)
- [自动化集成](#自动化集成)
- [输出产物](#输出产物)
- [安装与依赖](#安装与依赖)
- [限制与边界](#限制与边界)
- [合规与免责](#合规与免责)
- [卸载与清理](#卸载与清理)
- [开发与测试](#开发与测试)
- [文档](#文档)
- [许可证](#许可证)

---

## 工具描述

一台**发现级** Web 攻击面侦察仪：从静态源码与运行时流量双向发现端点、参数与风险线索，产出**带证据、可复核**的报告，供人工复核。它**只做发现与陈述**——不是漏洞扫描器（不验证、不利用），不发写请求（`DELETE / PUT / PATCH` 只提取不发包），不做子域枚举与历史资产，默认不执行目标代码（唯一例外是 opt-in 的密封离线动态解包）。

| 渠道          | 机制                                 | 擅长                           |
| ----------- | ---------------------------------- | ---------------------------- |
| **A · 静态**  | 解析 HTML / JS（AST 级）、SourceMap、构建产物 | 源码里**写死**的端点、参数、密钥线索         |
| **B · 运行时** | 真实浏览器（Playwright），在页面运行时捕获         | **动态拼接 / 懒加载 / 点击才触发**的请求与路由 |

---

## 核心特性

- 🔍 **双渠道发现** —— 静态（HTML / JS / SourceMap / 构建产物拆包）+ 运行时（Playwright 真实浏览器，捕获动态拼接、懒加载、点击触发的请求与路由）。
- 🌲 **AST 级 JS 还原** —— Node.js + acorn 真 AST 解析：变量拼接基址、模板字符串、`xhr.open` 第二参、`baseURL`/`path` 对象属性、形参排除、循环引用保护。按 **acorn → tree-sitter → 正则** 自动分层降级，缺失即回退并在报告中如实披露。
- 📊 **端点证据分级** —— 逐端点标注 `runtime` / `full-url` / `static` / `dict` 四级证据；**字典猜测的端点永远排在有据端点之后**（排序契约：有据 > 无据，同档按优先级），报告披露分级分布。
- 🏷️ **端点 kind 分类** —— `backend_api` / `frontend_route` / `unknown` 启发式分类（发现级、非判定）：写方法声明、前端路由集合、API 前缀形态（`/api`·`/rest`·`/v1`·`/graphql`·`/actuator`…）、REST 动作段等。
- 🚫 **文档站噪声消除** —— 识别文档 / 演示站点的库 bundle 密集特征，跳过库代码提取并**在报告中披露跳过数**，不让 node_modules 类产物淹没真实端点。
- 📖 **语义化 SourceMap 调度** —— 检测 `.js.map` 声明并按语义排入解析队列，还原压缩前的原始坐标。
- 🔒 **只读红线三通道统一** —— HTTP 同步 / 异步 / 浏览器上下文，非只读方法必须由调用点显式声明才放行，否则拒发并记审计。
- 📝 **完整披露** —— 运行时三态披露（已配置 `requested` / 已触发 `triggered` / 实际运行 `ran`）：「没请求」与「请求了没跑成」分开说；playwright / node / acorn 等依赖缺失全部登记降级原因，不静默假装跑过。
- 📋 **三格式输出** —— 单页 HTML（人读，含「复制全部接口」一键导出）+ JSON（机器读，与 HTML 同源）+ 可选 **SARIF / Burp / ZAP** 标准导出。
- 📎 **侧车体系**（`--sidecars`）—— 端点标注 JSON / 端点清单 / 增量 diff（供 CI 门禁）/ 只读复现脚本 `replay.sh` / 动态解包还原产物 / AST 结构化摘要，全部与主报告同源。
- 🌐 **双形态** —— CLI 命令行 + MCP stdio 服务（供 AI Agent 编排调用，`scan` 需显式 `authorized=true`）。

---

## 快速开始

```bash
# 最简扫描（先做授权确认；--yes 跳过，责任自负）
facet -u https://your-authorized-target.example --yes

# 需登录的目标
facet -u https://target.example --cookie "SESSIONID=xxx" --yes

# 批量（文件每行一个 URL）
facet -f targets.txt --yes

# 标准格式导出（SARIF / Burp / ZAP，与 HTML/JSON 同源）
facet -u https://target.example --export sarif,burp --yes

# 机器可读侧车 + 历史库（供跨扫描 diff / CI 消费）
facet -u https://target.example --sidecars --save-history --yes

# 只还原一个本地 JS（离线、不触网）
facet --deobf-file ./bundle.js
```

> **完整能力需要先装浏览器**：核心静态扫描纯 Python 即可跑；但**运行时通道**（SPA 渲染、JS 动态接口/路由提取）依赖 Playwright + Chromium。若只装基础 wheel 而**未装浏览器**，运行时通道会优雅降级（报告如实披露 `runtime.ran=false`），你将**漏掉大量动态接口**。要拿全结果，请按下方「安装与依赖」装好浏览器（一行 `facet --install-browser` 即可）。

**调参不在 CLI 暴露**：限速 / 并发 / 扩展侦察 / 规则库 / 代理 / 调试 / 动态解包等一律走配置文件 —— 默认值已合规安全。

- **配置文件**：`~/.facet/config.yaml`（YAML 1.2 语义：键名请加引号，如 `"yes": true`）
- **环境变量**：`FACET_RATE=0.5`、`FACET_THREADS=8`、`FACET_MAX_JS=80`、`FACET_DYNAMIC_DEOBF=true` 等
- **配置分层（优先级）**：CLI 显式参数 > 环境变量 > `~/.facet/config.yaml` > 内置默认值

---

## 命令参考

安装后得到 **3 个命令**：

```bash
facet --version        # 版本
facet --help           # 完整参数 + 合规条款（8 条）
facet-mcp              # MCP stdio 服务（读 stdin，无 --help）
facet-asset --help     # 资产库辅助 CLI（只读历史检索）
```

### facet（主扫描）

| 参数                  | 说明                                                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `-u, --url URL`     | 目标根 URL（与 `-f` 至少提供一个）                                                                                                                           |
| `-f, --file FILE`   | 批量目标文件（每行一个 URL，逐个扫描）                                                                                                                            |
| `--cookie COOKIE`   | 全局 Cookie（如 `"SESSIONID=xxx"`）—— 扫描需登录的目标时必填                                                                                                     |
| `--token TOKEN`     | Bearer Token（用于需认证接口的探活 / 未授权确认）                                                                                                                 |
| `-o, --out OUT`     | 输出报告路径（默认 `<输出目录>/facet_report.html` —— 主文件 HTML + JSON；输出目录 = 源码根或当前目录下的 `output/`，可用 `FACET_OUTPUT_DIR` 指定）                      |
| `--export EXPORT`   | 标准格式导出（逗号分隔）：`sarif` / `burp` / `zap` —— 在报告同目录生成 `.sarif` / `.burp.xml` / `.zap.json`                                                           |
| `--sidecars`        | 额外写出机器可读侧车（端点标注 / 端点清单 / 增量 diff / 复现脚本 / 还原 / AST 结构化）；默认关闭 —— 仅产 HTML + JSON 两个主文件                                                             |
| `--save-history`    | 将本次扫描写入历史库 `facet_history.db`，供跨扫描 diff / 历史记录                                                                                            |
| `--think`           | 扫描后额外产出「思考计划」（建议式，不改主流程）：打印 + 写 `<out>.plan.json`。默认本地动态推理（零外部依赖 / 离线）；配置 `llm_base_url`+`llm_api_key` 后自动切换 LLM 推理（显式 opt-in，只发聚合信号，不含凭据 / 响应体） |
| `--persist-state`   | 持久化断点续扫状态文件（默认内存态不落盘）；配合 `--resume` 使用                                                                                                           |
| `--resume`          | 从上次 `--persist-state` 落盘的状态续扫（未落盘 / 读不到时按空状态开始）                                                                                                  |
| `--config PATH`     | 指定配置文件路径（默认 `~/.facet/config.yaml`）                                                                                                       |
| `--login-capture`   | 登录态采集（opt-in）：打开**可见**浏览器，手动登录后采集会话（cookie 仅内存态，不落盘），再以 HTTP 通道续扫                                                                                |
| `--interactive`     | 浏览器交互（opt-in）：填表 + 点击控件发现动态端点；**所有写方法请求被只读护栏拦截**（观测 ≠ 发送，零写流量）；仅限自有 / 已授权资产                                                                      |
| `--yes`             | 跳过授权确认（责任自负）                                                                                                                                     |
| `--scope HOST`      | 声明授权扫描范围（可重复）：域名 / 子域（`*.x.com`）/ IP / CIDR；不传则默认 = 目标同源（保守边界）                                                                                   |
| `--deobf-file FILE` | 本地 JS 文件反混淆（离线只读，不触网，与 `-u`/`-f` 互斥）：静态层默认；强 / 动态层由 `strong_deobf` / `dynamic_deobf` 配置门控；输出 `<文件>.deobf.js` + `<输出>.report.json`（用 `-o` 指定输出路径） |
| `--deobf-dir DIR`   | 批量本地反混淆：目录下所有 `*.js` 逐个走 `--deobf-file` 管线                                                                                                       |

---

## 自动化集成

### facet-mcp（MCP stdio 服务）

stdio JSON-RPC 2.0 服务，5 个工具，供 AI Agent 编排：

| 工具           | 说明                                                                                     |
| ------------ | -------------------------------------------------------------------------------------- |
| `scan`       | 提交扫描任务（异步，**需 `authorized=true`**）；options 仅支持 `cookie` / `token` 两项（schema 严格，额外字段拒绝） |
| `list_tasks` | 列出所有任务                                                                                 |
| `get_task`   | 查询单个任务状态                                                                               |
| `stop_task`  | 停止任务                                                                                   |
| `get_report` | 获取任务报告                                                                                 |

### facet-asset（资产库辅助 CLI）

跨目标资产库检索（**只读本地历史，零网络请求**）：

```bash
facet-asset targets                  # 列出所有扫描过的目标摘要
facet-asset endpoints --path admin   # 跨目标检索端点
facet-asset findings                 # 跨目标检索发现
facet-asset shared                   # 跨目标重复出现的问题类型
facet-asset --db PATH targets        # 指定历史库路径
```

---

## 输出产物

默认产出 **HTML + JSON 两个主文件**（同源同目录）：

| 产物                                   | 内容                                                                                                                                         |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `facet_report.html`           | 单页总览：概览 · 授权声明 · 未授权面 · 基础提取（端点主表 + 接口清单）· 参数总表 · 完整发现清单（溯源：来源文件:行:列 + extractor 层）· 覆盖模式 · JS 资源清单；含证据分级分布、端点 kind 汇总、运行时三态披露、`复制全部接口` 按钮 |
| `facet_report.json`           | 机器可读同源数据（含 `completeness.runtime.triggered` 等披露字段）                                                                                         |
| `.sarif` / `.burp.xml` / `.zap.json` | `--export` 标准格式导出                                                                                                                          |
| 侧车（`--sidecars`）                     | 端点标注 JSON / 端点清单 / 增量 diff（基线对比，供 CI 门禁）/ `replay.sh` 只读复现脚本 / 还原产物 / AST 结构化摘要                                                            |
| `facet_history.db`            | `--save-history` 写入的历史库，供 `facet-asset` 与跨扫描 diff                                                                                   |

**端点字段**（JSON 消费者）：

| 字段 | 说明 |
| --- | --- |
| `path` / `methods` | 端点路径 / JS 声明的真实方法（写方法标注「只提取」） |
| `kind` | `backend_api` / `frontend_route` / `unknown`（启发式分类，非判定） |
| `evidence` | `runtime` / `full-url` / `static` / `dict` 四级证据 |
| `source` | 来源文件:行:列 + extractor 层 |
| `params` | 参数及类型 / 必填 / 意图推断 |
| `status` | 探活结果（200 / 需登录 / 未授权等） |

**审计与隐私**：报告 / JSON / 侧车 / 历史库 / 审计日志**不做任何脱敏打码** —— 你需要自己保管好产物（PII 提交前自行脱敏、不留存泄露数据）。开启 `audit_log` 后每行记录方法与目标，**零写包校验**：`grep -c "只读护栏拦截" <log>` 应为 0，网络层仅出现 `GET/HEAD/OPTIONS`。

---

## 安装与依赖

本工具**未发布到 PyPI**，请用本地路径安装。

```bash
# A) wheel
pip install facet-1.1.0-py3-none-any.whl

# B) 源码包（解压即用 / 就地安装）
unzip facet-1.1.0-release.zip
cd facet-1.1.0-release
pip install .                       # 或 pip install -e . （可编辑安装）

# C) 开发安装（含测试与 lint 依赖）
pip install -e ".[dev]"             # pytest + ruff
```

**可选依赖**（可一次装多个）：

```bash
pip install ".[async,runtime,js]"                          # 源码目录内
pip install "./facet-1.1.0-py3-none-any.whl[js]"    # 或对 wheel 加 extras
pip install ./facet-1.1.0-release.zip               # 也可直接装发布压缩包
```

### 运行时浏览器（关键：不装则漏扫动态接口）

facet 的**运行时通道**依赖 **Playwright + Chromium Headless Shell**。`pyproject.toml` 的 `runtime` extra 已将 playwright **钉死为 `playwright==1.60.0`**，因此只要你用「装了 facet 的那个 Python」去装浏览器，版本必然一致，不会出现"浏览器装了却起不来"的错位。

```bash
pip install ".[runtime]"          # 装 facet + 钉死的 playwright
facet --install-browser           # 用 facet 自己的 playwright 装 Chromium（推荐，自动对齐版本）
# 等效手动方式（注意必须用装了 facet 的 python）:
python -m playwright install chromium-headless-shell
```

> ⚠️ **务必用「装了 facet 的同一个 Python」执行浏览器安装**。若本机另有其它 playwright（全局或其他 venv），用错版本会把不同构建号的浏览器塞进同一缓存目录，导致 facet 要的版本缺失、运行时通道起不来。最省心的方式就是上面的 `facet --install-browser`（它自动用 facet 的 python 调用 playwright）。

> **探针默认关闭**：`options_probe`（OPTIONS / Allow 方法发现）与 `unauth_probe`（未授权确认 + 隐藏路径字典）默认**关闭**（保守默认）。需要更全覆盖时，在 `~/.facet/config.yaml` 设 `"options_probe": true` / `"unauth_probe": true`，或临时加环境变量 `FACET_OPTIONS_PROBE=true FACET_UNAUTH_PROBE=true facet -u <目标> --yes`。


### 环境依赖

核心扫描**纯 Python、无外部服务依赖**。「必需」是硬要求，其余全是**可选能力**，缺失时优雅降级、不会让核心扫描失败。

| 必需       | 要求                                                                                                                        |
| -------- | ------------------------------------------------------------------------------------------------------------------------- |
| Python   | **≥ 3.8**（`pyproject.toml` 的 `requires-python`）                                                                           |
| Python 包 | `requests` · `urllib3` · `pyyaml` · `brotli`（CPython）/ `brotlicffi`（非 CPython）· `colorama`（仅 Windows），`pip install` 时自动拉取 |
| 网络       | 出站 HTTP(S)；无网络时只能跑 `--deobf-file` / `--deobf-dir` 等离线模式                                                                   |

| 可选能力                                 | 依赖                                                | 获取方式                                                       | 缺失时                                    |
| ------------------------------------ | ------------------------------------------------- | ---------------------------------------------------------- | -------------------------------------- |
| 异步并发通道（吞吐↑）                          | `aiohttp` ≥ 3.8                                   | `pip install ".[async]"`                                   | 自动降级为同步通道                              |
| 浏览器运行时通道（配置 `runtime`，默认 `auto`）     | `playwright==1.60.0`（已钉死）+ Chromium Headless Shell 二进制 | `pip install ".[runtime]"` 后 `facet --install-browser`（推荐，自动对齐版本） | 该能力不可用，运行时发现退化为仅静态（报告披露「已请求但未实际运行」及原因） |
| JS 美化（提升提取率）                         | `jsbeautifier` ≥ 1.14                             | `pip install ".[js]"`                                      | 自动降级为无美化提取                             |
| JS AST 提取（acorn 优先 / tree-sitter 备选） | **Node.js ≥ 18** + `acorn`；或 `tree-sitter` ≥ 0.22 | `npm install acorn`；或 `pip install ".[ast]"`               | 自动回退正则提取                               |
| 强反混淆（静态，opt-in）                      | **Node.js ≥ 18** + `webcrack`                     | `npm install webcrack`                                     | 默认关闭 / 依赖缺失即跳过                         |
| 动态解包（执行目标代码，opt-in）                  | **Node.js ≥ 18**（本地 `vm` 密封沙箱）                    | 同上（Node）                                                   | 默认关闭，不影响静态扫描                           |
| 依赖成分分析（SCA）                          | 在线只读查询 **OSV 数据库**                                | 联网即可                                                       | 无网络时不查询，跳过 SCA                         |

> 上表所有「可选」项都是**运行时探测**的：启动时检测依赖是否可用，缺了就降级并**在报告里如实披露**，不会静默假装跑过。  
> Node 生态（node / acorn / webcrack）统一经 `core/nodeenv.py` **动态探测**（单一真源，不钉死任何机器路径）：node 按 `ast_node_bin` 配置 / `FACET_NODE_BIN` 环境变量 → PATH → managed 布局动态扫描 → 常见系统路径查找；`acorn` / `webcrack` 按 `ast_node_path` 配置 / `FACET_NODE_MODULES` 环境变量 → managed workspace → **当前目录及父目录的标准 Node 解析**（本地 `npm install` 后自动发现，无需配置）查找。

---

## 限制与边界

**收益接近 0 的场景**：纯客户端渲染 SPA 的路由页收割（回同一份 shell）· 只做 minify 的站点上的强反混淆 · 参数对象与 URL 不同处的站点的参数关联 · 匿名扫描业务型系统（只得登录门面）· RPC 约定型目标要看参数名。

**结构性做不到**：

- **不做 CT/DNS 子域枚举、不做 Wayback 历史资产、不做端口探测**（三块已整体移除）—— 子域信息**只来自 JS/HTML 里的同源引用**，因此**同组织的其它主机很可能未纳入**；
- 认证墙后的接口不可见（除非提供 `--cookie` / `--token`，或用 `--login-capture` 采集会话）；
- 不验证漏洞、不给利用载荷、不发写请求；
- 给不出「漏了多少」的绝对数 —— 真值不在工具手里；
- 运行时构造的 URL 依赖运行时通道（需 Playwright + 浏览器二进制；缺失时报告如实披露能力缺口）；
- AST 级提取依赖 Node.js（缺失自动降级正则提取，报告披露）。

**使用成本**：默认限速下大站全量扫描是几十分钟量级；多目标默认串行；产出需**人工判读**。

**可选能力缺失时的行为**（全部降级并在报告中如实登记，不静默假装跑过）：

| 依赖缺失 | 行为 |
| --- | --- |
| playwright / 浏览器 | 运行时通道不可用，退化为仅静态发现（报告披露「已请求但未实际运行」+ 原因） |
| Node.js | AST 提取降级为正则；反混淆 / 拆包跳过 |
| acorn | AST 降级为 tree-sitter，再降级正则 |
| tree-sitter | AST sidecar 跳过 |
| aiohttp | 异步通道降级为同步 |
| jsbeautifier | 无美化提取 |
| 网络 | 离线模式（`--deobf-file` / `--deobf-dir`） |

---

## 合规与免责

- **仅限自有资产 / 已书面授权 / SRC in-scope 目标**，且平台允许自动化探测。使用者对使用行为**自行负责**。
- **只读**：删除 / 修改类接口（`DELETE` / `PUT` / `PATCH`）只做提取，不发任何验证包；heapdump / threaddump 类大体积端点仅探测可达性，不下载响应体。
- **保护目标**：默认限速（0.5s/请求 + 120 发/分钟硬顶，三通道共用同一配额）+ 连续 5 次 5xx/超时自动熔断；WAF 探测使用自我标识 UA（`ua` / `waf_probe_ua` 配置可显式指定，CLI 不暴露）。
- **只读护栏三通道统一**：HTTP 同步 / 异步 / 浏览器上下文，非只读方法必须由调用点显式声明才放行，否则拒发并记审计。
- **结果处理**：所有产出均为**发现级线索**，需**人工复核**，非漏洞判定；PII 提交前须脱敏，不留存泄露数据。
- 本工具**不做漏洞验证 / 利用**；发现能力与边界以报告「覆盖模式」章节为准。

**动态解包的合规例外**（opt-in，默认关闭）：它会在**本地、密封、离线**的 Node `vm` 沙箱里**运行目标 JS** 以展开 VM / 字节码混淆；沙箱内 `fetch / XHR / WebSocket / http(s) / net / dns / child_process` 全被替换为「只记录、不发送」的桩，**绝不**向目标或任何外部地址发包。必须显式开启（`dynamic_deobf: true|auto` 或 `FACET_DYNAMIC_DEOBF=true`，可选 `dynamic_deobf_tier: 3|4|5`；`auto` = 仅对 VM / 字节码打包自动启用），报告会明示「已在密封离线沙箱展开、未向目标发送任何请求」。请仅在**自有 / 已授权资产、且隔离环境**下开启。

---

## 卸载与清理

```bash
pip uninstall facet        # 卸载包（同时移除 3 个入口脚本）
```

**但运行产物不在 `site-packages` 里，`pip uninstall` 不会碰它们**，需要手工清理：

| 路径                                                                             | 内容                                     |
| ------------------------------------------------------------------------------ | -------------------------------------- |
| `<输出目录>/`                                                                      | 报告、抓到的 JS、拆包产物、历史库、审计日志、状态文件（**占用最大**） |
| `~/.facet/config.yaml`                                                  | 你的个人配置（工具只读不写）                         |
| `~/Library/Caches/ms-playwright/`（macOS）<br />`~/.cache/ms-playwright/`（Linux） | Playwright 浏览器二进制                      |
| `__pycache__/` · `.pytest_cache/` · `.ruff_cache/` · `*.egg-info/`             | Python 缓存                              |

> ⚠️ 删 `output/` 会一并删掉**所有扫描报告与历史库**，执行前先备份。  
> 只清理单次扫描产物：删该次扫描对应的输出子目录即可（`--save-history` 的历史库记录可用 `facet-asset` 查询确认后再清）。

---

## 开发与测试

```bash
make compile    # 字节编译全包（语法 / 导入零错误即 fail-closed）
make test       # 跑离线测试套件（不依赖浏览器 / 网络）
make check      # = compile + test
```

**离线测试 22 项**（tree-sitter 未安装时 1 项环境跳过）：

- `tests/test_regressions.py` —— 6 项行为回归钉子（探活方法透明 / 报告 JSON 探活方法 / fetch 拼接 / 端点 kind 与复现基址 / 复制按钮 / sourcemap 调度）
- `tests/test_units.py` —— 14 项核心链路契约（优先级分层 / runtime 三态 / AST sidecar 双引擎 / deep_analyze 门控 / 排序与证据零发包 / 截断登记 / 端点 kind 汇总 / Node 环境探测移机通用性 / MCP 默认输出目录双形态不变量）
- `tests/test_e2e_fixture.py` —— 2 项端到端冒烟（本地 http.server fixture 零外网：四类提取形态 + 报告三件套 / 披露双分支）

CI：`.github/workflows/ci.yml`（编译 + 测试）；`.github/workflows/landing-readiness.yml`（落地就绪手动工作流，需受控网络 + 浏览器环境）；`.github/workflows/release.yml`（tag 推送自动构建发布产物）。

---

## 文档

本文档为**使用者入口**；深度参考在 `docs/`（仅 3 篇，无重复）：

| 文档 | 内容 |
| --- | --- |
| [docs/configuration.md](docs/configuration.md) | 配置参考：配置键全量 / 环境变量 / 分层 |
| [docs/architecture.md](docs/architecture.md) | 架构说明：模块地图 / 数据流 / 设计原则 |
| [docs/landing-readiness.md](docs/landing-readiness.md) | 落地就绪检查清单（受控环境执行） |
| [CHANGELOG.md](CHANGELOG.md) | 版本变更记录（Keep a Changelog） |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献指南：开发门禁 / 代码约定 / 发布流程 |
| [SECURITY.md](SECURITY.md) | 安全政策：工具自身漏洞的报告渠道 |

---

## 作者

**迷麟Aurora** —— 本工具的设计、实现与维护。

## 许可证

`LicenseRef-Proprietary` —— 仅限授权范围内使用。详见 [LICENSE](LICENSE)。
本仓库按开源工程惯例组织（README / CHANGELOG / CONTRIBUTING / docs / CI），
但**未以 OSI 认可的开源许可证发布**；未经作者明确决定，不得以开源名义
再许可或再分发。
