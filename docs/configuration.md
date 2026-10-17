# 配置参考

facet 的调参**不在 CLI 暴露**，统一走配置层。默认值已合规安全。

## 配置分层（优先级从高到低）

```
CLI 显式参数  >  环境变量  >  ~/.facet/config.yaml  >  内置默认值
```

- **配置文件**：`~/.facet/config.yaml`（或 `--config PATH` 指定）。
  YAML 1.2 语义：**键名请加引号**（如 `"yes": true`），避免 `yes`/`no`/`on`/`off`
  被解析为布尔量。
- **环境变量**：任意配置键 `k` 可用 `FACET_<K大写>` 覆写
  （如 `FACET_RATE=0.5`）。布尔键接受 `true/false/1/0`；
  三态键（`auto|true|false`）保留原字符串交由归一化处理，`auto` 不会被误判。
  数值键解析失败时静默保留原值。

### 专用环境变量（非配置键映射）

| 环境变量 | 用途 |
| --- | --- |
| `FACET_OUTPUT_DIR` | 输出根目录（默认 `<源码根|当前目录>/output/`） |
| `FACET_NODE_BIN` | Node.js 可执行文件路径（留空自动探测：PATH → managed 布局动态扫描 → 常见系统路径） |
| `FACET_NODE_MODULES` | node_modules 目录（acorn / webcrack 查找；宽容「目录本身 / 其父目录」两种写法；留空自动探测：managed workspace → 当前目录及父目录标准 Node 解析） |
| `FACET_WEBCRACK` | webcrack 路径（强反混淆；留空在候选 node_modules 内动态查找） |
| `FACET_RUNTIME_BROWSER` | 系统浏览器可执行文件路径（绕过沙箱浏览器下载受限） |
| `FACET_DYNAMIC_DEOBF` | `true/false/auto`（可选 `dynamic_deobf_tier: 3|4|5`） |
| `FACET_LLM_BASE_URL` / `FACET_LLM_API_KEY` / `FACET_LLM_MODEL` | `--think` 的 LLM 推理通道（opt-in） |
| `FACET_DEBUG` | 调试输出 |
| `FACET_NO_COLOR` | 关闭彩色输出（CI 环境） |

> Node 生态（node 二进制 / acorn / webcrack）的自动探测统一收口于 `core/nodeenv.py`
> （单一真源）：**环境驱动、动态发现，不钉死任何版本号或机器路径** —— 移机安装后
> 无需任何配置即可发现 PATH / managed 布局 / 当前目录链上的 Node 生态；探测失败
> 时对应能力如实降级（报告披露），不中断扫描。

## 配置键全量参考

> 表中「范围」为启动校验区间（越界取边界并告警）；默认值以 `core/config.py`
> 的 `DEFAULT_CONFIG` 为权威。

### 速率与保护目标（合规红线相关）

| 键 | 默认 | 范围 | 说明 |
| --- | --- | --- | --- |
| `rate` | 0.5 | 0.05–60 | 请求间隔秒数 |
| `max_rpm` | 120 | 0–10000 | 每分钟硬顶发包数（0=不限） |
| `threads` | 8 | 1–64 | 并发数 |
| `timeout` | 10 | 1–120 | 单请求超时秒数 |
| `retries` | 1 | 0–10 | 关键请求重试次数 |
| `respect_retry_after` | true | — | 尊重 `Retry-After` 头 |
| `circuit_max_fail` | 5 | — | 连续失败熔断阈值 |
| `circuit_cooldown` | 30 | — | 熔断冷却秒数 |
| `circuit_half_open_probes` | 3 | — | 半开探测数 |
| `adapt_rate` | true | — | 自适应调速（关闭后恒速） |
| `max_duration` | 1800 | 0–86400 | 全局时间预算秒数（0=不限） |
| `batch_concurrency` | 1 | 1–32 | 批量目标并发数 |

### 时间与规模预算

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `max_js` | 200 | JS 递归分析条数下限（0=不限） |
| `max_js_hard_cap` | 2000 | JS 分析上限的硬顶 |
| `js_budget_frac` | 0.8 | JS 阶段最多占用的剩余时间预算比例 |
| `max_probe` | 400 | 探活路径总数上限 |
| `max_probe_extracted` | 2000 | 提取接口探活硬顶（防超大提取集失控） |
| `max_sitemap` | 500 | sitemap `<loc>` 采纳条数上限 |
| `resp_mine_max` | 100 | 响应挖掘：每目标采纳 URL 上限 |
| `options_probe_max` | 60 | OPTIONS 方法发现：探测端点数上限 |
| `path_infer_max_variants` | 8 | 每条路径派生变体上限（动词4/扩展3/批量1/复数1） |
| `path_infer_max_total` | 200 | 路径推断全局派生上限 |
| `unbundle_max_modules` | 200 | 拆包模块数上限 |
| `unbundle_max_bytes` | 4000000 | 拆包体积上限（超过跳过） |
| `unbundle_keep_dirs` | 3 | 拆包产物目录保留个数 |
| `strong_deobf_max_bytes` | 6000000 | 强反混淆体积上限（超过跳过） |
| `silent_js_min_size` | 20480 | JS「零产出」披露的体积门槛（默认 20KB） |
| `crawl_depth` | auto | 同源多页爬取深度（0=关） |
| `crawl_max_pages` | 30 | 多页爬取页数上限 |
| `max_pages` | 15 | SPA 路由页面上限 |
| `max_baseline_cache` | 128 | 请求缓存条目上限 |

### 模块调度（modules 组）

| 组名 | 展开模块 | 说明 |
| --- | --- | --- |
| `auto`（默认） | recon-deep + probe + unauth | 全安全面，各能力由信号细粒度门控 |
| `passive` | recon-deep | 静态提取 + 被动打点（零发包或仅抓静态资源） |
| `confirm` | probe + unauth | 最小发包确认（每候选 1 发 GET） |
| `all` | recon-deep + probe + unauth | 同 auto |

模块名 `recon-deep` / `probe` / `unauth` 也可单独使用。

### 探活与字典（只读 GET 枚举，非纯被动）

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `common_probe` | true | 通用端点探测（`/api` `/health` `/status`） |
| `fallback_probe` | false | 兜底探测（默认关闭：旧版未命中指纹时反而追加，方向错误） |
| `schema_probe` | true | Schema / 文档端点探测 |
| `catchall_baseline` | true | 发送 canary 随机路径建立 catch-all 基线 |
| `js_dir_fuzz` | true | JS 目录爆破（从已发现 JS 目录派生候选，只读探活） |
| `js_dir_fuzz_max` | 300 | 爆破总请求上限（0=不限） |
| `js_dir_fuzz_names` | [] | 追加 JS 文件名：内联列表，或内置词表名（`js_common` / `js_highvalue` / `js_full` / `all`），或 `.txt`/`.json` 词表文件路径 |
| `hidden_paths_extra` | [] | 追加隐藏路径词表 |
| `hidden_paths_db` | null | 自定义隐藏路径库路径 |
| `hidden_paths_extended` | auto | 扩展词表（需显式 opt-in） |
| `unauth_probe` | auto | 未授权访问确认（只回答「是否需要鉴权」，不做利用） |
| `options_probe` | auto | OPTIONS 方法发现 |
| `resp_mine` | true | 响应挖掘（从响应体提取 URL） |
| `dev_server_downgrade` | true | 开发服务器降级处理 |
| `path_infer` | true | 路径推断 |

### JS 分析与反混淆

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `ast_sidecar` | auto | AST 结构化侧车（tree-sitter；可选依赖） |
| `ast_node_bin` | '' | node 可执行文件路径（留空自动探测，顺序同 `FACET_NODE_BIN`） |
| `ast_node_path` | '' | acorn 所在 node_modules 目录（留空自动探测，顺序同 `FACET_NODE_MODULES`） |
| `vendor_bundle_skip` | true | 文档站库 bundle 跳过（文档 / 演示站点降噪） |
| `vendor_sniff_bytes` | 2048 | 库 bundle 嗅探检查的文件头字节数 |
| `sourcemap_probe` | true | SourceMap 探测调度 |
| `sourcemap_probe_max` | 100 | SourceMap 探测上限 |
| `sourcemap_blacklist` | 内置默认 | SourceMap 黑名单 |
| `js_encoding` | auto | JS 编码处理 |
| `strong_deobf` | auto | 强反混淆（webcrack，静态，opt-in） |
| `dynamic_deobf` | false | 动态解包（执行目标代码，**默认关闭**；密封离线沙箱） |
| `dynamic_deobf_tier` | 4 | 解包层级（L3 密封 vm / L4 抗篡改 / L5 真实浏览器，无则降级） |
| `unbundle` | auto | 构建产物拆包（webpack / browserify） |

### 运行时通道（Playwright）

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `runtime` | auto | `auto` = 信号命中（SPA 指纹 / 页面类型 / 前端路由密集）才触发；`true` 强制；`false` 关闭 |
| `runtime_browser` | '' | 浏览器可执行文件路径 |
| `runtime_max_requests` | 300 | 运行时可捕获请求数上限 |
| `route_harvest` | true | 前端路由收割 |
| `spa_route_harvest` | true | SPA 路由页收割 |
| `login_capture` | false | 登录态采集（opt-in，可见浏览器手动登录） |
| `login_capture_timeout` | 300 | 登录态采集超时秒数 |
| `interactive` | false | 浏览器交互（opt-in；写方法请求被只读护栏拦截） |
| `browser_max_interactions` | 10 | 浏览器交互次数上限 |

### 认证与请求头

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `cookie` | null | 全局 Cookie |
| `token` | null | Bearer Token |
| `login` | null | 登录配置 |
| `header` | null | 自定义请求头 |
| `ua` | null | 扫描请求 UA（null = 默认浏览器 UA，与真实流量同口径） |
| `waf_probe_ua` | null | WAF 探测 UA（null = 默认浏览器 UA） |
| `waf_probe` | true | WAF 探测（命中 WAF 指纹时执行） |
| `tls_cert` | auto | TLS 证书校验策略 |

### 被动打点与 SCA

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `passive_recon` | true | robots / sitemap / security.txt / favicon + 安全响应头审计 |
| `sca` | true | 依赖成分分析（在线只读查 OSV） |
| `sca_db` | null | 自定义 SCA 库路径 |
| `sca_osv` | false | OSV 在线查询（需网络） |

### 报告与产物

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `html_report` | true | 生成 HTML 报告 |
| `json_report` | true | 生成 JSON 报告 |
| `export_formats` | [] | 标准导出格式列表（`sarif` / `burp` / `zap`） |
| `sidecars` | false | 机器可读侧车 |
| `save_history` | false | 写入历史库 |
| `persist_state` | false | 断点续扫状态落盘 |
| `state_store` | file | 状态存储方式 |
| `audit_log` | false | 审计日志（每行记录方法，零写包校验依据） |
| `audit_log_path` | `<out>/facet_audit.log` | 审计日志路径 |
| `param_taint` | true | 参数污染分析 |

### 思考计划（--think）

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `think` | false | 产出思考计划（建议式，不改主流程） |
| `llm_base_url` | '' | LLM API 地址（配置后切换 LLM 推理） |
| `llm_api_key` | '' | LLM API Key |
| `llm_model` | '' | LLM 模型名 |
| `llm_timeout` | 30 | LLM 推理超时秒数 |

### 其他

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `yes` | false | 跳过授权确认 |
| `resume` | false | 断点续扫 |
| `scope` | [] | 授权范围声明（fail-closed） |
| `authorized` | false | 授权声明（MCP `scan` 强制显式 `true`） |
| `auth_method` | '' | 认证方式标注 |
| `out` | `<out>/facet_report.html` | 输出报告路径 |
| `url` / `file` | null | 目标（CLI 参数映射） |
| `modules` | auto | 模块组 |
| `debug` | false | 调试输出 |
| `profile` | false | 性能剖析 |
| `proxy` | null | 代理 |
| `use_env_proxy` | false | 使用系统代理环境变量 |
| `no_color` | false | 关闭彩色输出 |
| `fingerprint_db` | null | 指纹库路径 |
| `secret_db` | null | 敏感信息模式库路径 |
| `verify_secrets` | false | 敏感信息验证 |
| `probe_specs_db` | null | 探活规格库路径 |
| `custom_rules` | null | 自定义规则文件 |
| `param_rules` | null | 参数规则文件 |
| `source_rules` | null | 来源规则文件 |
| `extract_rules` | null | 提取规则文件 |
| `state_path` | `<out>/.facet_state.json` | 状态文件路径 |
| `fallback_probe` | false | 兜底探测（默认关） |

## 配置示例

```yaml
# ~/.facet/config.yaml
"rate": 1.0                # 保守限速
"max_rpm": 60              # 更严的硬顶
"threads": 4               # 低并发
"runtime": "auto"          # 运行时通道（默认）
"sidecars": true           # 侧车默认开
"export_formats": ["sarif"]  # 流水线导出
"sourcemap_blacklist": ["example.com"]  # SourceMap 黑名单
```
