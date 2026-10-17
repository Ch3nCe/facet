# 架构说明

## 模块地图

```
facet/
├── apps/                    # 入口形态
│   ├── cli.py               # 主 CLI（argparse + 合规条款 epilog + 扫描编排）
│   └── mcp_server.py        # MCP stdio 服务（5 工具，scan 需 authorized=true）
├── core/                    # 内核
│   ├── orchestrator.py      # 扫描编排（ScanContext / 模块调度 / 运行时三态）
│   ├── context.py           # ScanContext（配置 / 元数据 / 运行时状态载体）
│   ├── config.py            # 配置加载（CLI > env > config.yaml > 默认）+ 校验
│   ├── guard.py             # 合规护栏（授权确认 / 运行时触发判定 / 范围）
│   ├── scope.py             # 范围解析与越界拦截（BLOCKED_SCOPE，fail-closed）
│   ├── rate.py              # 速率管理（三通道共用配额）
│   ├── http.py              # HTTP 同步通道（UA / 代理 / 超时 / 重试）
│   ├── probe.py             # 探活（证据分级 / 排序契约 / 截断登记）
│   ├── js_extract.py        # JS 端点提取（AST / 正则分层）
│   ├── js_lex.py            # JS 词法分析（提取前置）
│   ├── html_extract.py      # HTML 端点 / 参数 / 路由提取
│   ├── ast_sidecar.py       # AST sidecar 持久化（tree-sitter 优先，Node+Acorn 兜底）
│   ├── deobf.py             # 反混淆（静态 / 强 / 动态三层）
│   ├── dicts.py             # 字典与词表管理
│   ├── secret.py            # 敏感信息模式
│   ├── history.py           # 历史库（facet_history.db）
│   ├── task_service.py      # 任务服务（MCP 异步任务）
│   ├── asset_enum.py        # 资产枚举
│   ├── adapt.py             # 自适应调速
│   ├── const.py             # 常量（DEFAULT_UA 等）
│   ├── procutil.py          # 子进程工具（Node 调用）
│   ├── nodeenv.py           # Node 环境探测（node 二进制 / node_modules 单一真源，动态发现）
│   ├── plugins.py           # 插件机制
│   └── log.py               # 日志
├── recon/                   # 侦察阶段
│   ├── runtime.py           # 运行时通道（Playwright）
│   ├── unbundle.py          # 构建产物拆包（webpack / browserify）
│   ├── ast.py               # AST 提取（Node + acorn）
│   ├── fingerprint.py       # 指纹识别
│   ├── fingerprint_extra.py # 扩展指纹
│   ├── stack.py             # 技术栈识别
│   ├── schema.py            # Schema / 文档端点
│   ├── sca.py               # 依赖成分分析（OSV）
│   ├── baseline.py          # catch-all 基线
│   ├── asset_lib.py         # 资产库
│   └── role_diff.py         # 角色差分（匿名 / 用户 / 管理员）
├── report/                  # 报告
│   ├── report.py            # HTML + JSON 报告（单源渲染）
│   ├── exporters.py         # SARIF / Burp / ZAP 导出
│   └── params.py            # 参数表渲染
├── tools/                   # 辅助 CLI
│   ├── asset_cli.py         # facet-asset（跨目标只读检索）
│   ├── role_diff_cli.py     # 角色差分 CLI（list / diff / rolescan）
│   └── perf_baseline.py     # 性能基线
├── output/                  # 输出路径管理
│   └── paths.py             # 输出目录解析 + 父目录确保
└── assets/                  # 随包资源
    ├── wordlists/           # 词表（js 文件名 / 路径 / 高价值）
    ├── deobf_dynamic.cjs    # 动态解包沙箱（密封 vm）
    ├── deobf_encodings.cjs  # 编码还原
    └── deobf_strong.cjs     # 强反混淆
```

## 扫描数据流

```
CLI / MCP
   │
   ▼
配置加载（CLI > env > config.yaml > 默认）+ 合规护栏（授权 / 范围）
   │
   ▼
ScanContext 构建
   │
   ▼
orchestrator.resolve_dispatch（模块组展开：auto → recon-deep + probe + unauth）
   │
   ├─► recon-deep ─► 指纹 → 首页 → HTML 提取 ─► JS 抓取 ─► JS 相位
   │                 （AST 三层降级 / sourcemap / 拆包 / 反混淆）
   │                 └─► 运行时通道（Playwright，三态披露）
   │
   ├─► probe ─────► 探活（证据分级 / 排序契约 / 截断登记 / 只读红线）
   │                 实际调用**两次**: ① 提取面(no_cap + hard_cap) ② 字典/推断补充面(受 max_probe)
   │                 结束时输出一行汇总(可达 / 需鉴权 / 异常 / 不存在 / 基线一致)
   │
   └─► unauth ────► 未授权访问确认（只回答「是否需要鉴权」）
                     实现上挂在 `_run_probes` 末尾(hidden_probe), 不是独立阶段
   │
   ▼
build_recon_matrix（端点 / 参数 / 发现的单一真源）
   │
   ▼
report.py ──► HTML + JSON（同源）
   │
   ├─► exporters.py ──► SARIF / Burp / ZAP
   └─► 侧车（端点标注 / 清单 / diff / replay.sh / 还原 / AST）
```

## 设计原则

### 1. 能力 / 路由分离

- **能力**（能做什么）与**路由**（怎么到达）分离：端点发现能力集中在
  recon/core，编排路由在 orchestrator；
- 模块调度走 `MODULE_GROUPS` 组名展开，新增能力不影响调度配置。

### 2. 单一真源

- 版本号：`facet/__init__.py` 的 `__version__` 与 `pyproject.toml`
  的 `version`（两处必须一致，不硬编码第三处）；
- 报告数据：HTML / JSON / 导出 / 侧车全部来自同一份
  `build_recon_matrix`，不存在多源漂移；
- 配置：`core/config.py` 的 `DEFAULT_CONFIG` 是唯一默认值权威。

### 3. 合规护栏内置

- 只读红线三通道统一（HTTP 同步 / 异步 / 浏览器上下文）：非只读方法必须
  由调用点显式声明才放行，否则拒发并记审计；
- 范围声明 fail-closed：越界请求 `BLOCKED_SCOPE` 拦截；
- 速率限制三通道共用配额 + 熔断。

### 4. 披露纪律

- 可选能力缺失（playwright / node / acorn / tree-sitter）→ 降级并**在报告
  中如实登记原因**，不静默假装跑过；
- 运行时三态：`requested`（配置）/ `triggered`（是否实际请求）/
  `ran`（浏览器是否真跑完）——「没请求」与「请求了没跑成」分开说；
- 截断（max_probe / max_js 等触发）在报告中登记。

### 5. 排序契约

- 证据分级：`runtime` > `full-url` > `static` > `dict`；
- **字典猜测的端点永远排在有据端点之后**（`_evid.get(p, 1)` 默认值 1 =
  static，dict = 0 垫底）——字典猜测永远不能冒充有据发现。

### 6. 不硬编码

识别逻辑（基址、框架、路径形态）用**形态 / 用法启发式**动态发现，不靠
预设站点名 / 变量名白名单打补丁；换目标即通用。

## 测试布局

| 层 | 文件 | 定位 |
| --- | --- | --- |
| 回归钉子 | `tests/test_regressions.py` | 修过的 bug 必须有钉子，防回潮（CI 护栏） |
| 契约测试 | `tests/test_units.py` | 直接测库函数契约（主动覆盖） |
| 端到端冒烟 | `tests/test_e2e_fixture.py` | 本地 http.server fixture，零外网依赖 |

详见 [CONTRIBUTING.md](../CONTRIBUTING.md)。
