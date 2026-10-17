# facet 落地就绪检查清单（Landing Readiness Checklist）

> 用途：判定 facet 是否具备「对任何授权目标一键跑通全链路」的生产落地资格。
> 适用：在**具备真实网络 + 可用浏览器**的受控环境执行（本沙箱因浏览器运行时缺失/网络受限无法跑通全链路，故清单在执行环境侧落地）。
> 原则：只读、零写包；所有目标须已获书面授权；范围显式声明（fail-closed）。

## 0. 通用约定（先读）

**调用方式**（二选一，等价）：
```bash
# 源码直接跑
python -m facet.apps.cli -u <URL> [选项]
# 或安装后的控制台命令
facet -u <URL> [选项]
```

**关键 CLI / 环境变量**（已核对 `apps/cli.py` 与 `core/config.py`）：

| 目的 | 选项 / 环境变量 |
|---|---|
| 目标根 URL | `-u/--url <URL>` |
| 扩大同组织范围 | `--scope <HOST>`（可重复，fail-closed） |
| 鉴权 | `--cookie <C>` / `--token <T>` |
| 输出目录 | `-o/--out <DIR>` 或 `FACET_OUTPUT_DIR` |
| 侧车文件 | `--sidecars` |
| 跳过授权确认 | `--yes`（责任自负） |
| 运行时通道 | 配置键 `runtime: auto|true|false`，等价 `FACET_RUNTIME` |
| 指定系统浏览器（规避沙箱下载受限） | `FACET_RUNTIME_BROWSER=/path/chromium` |
| 吞吐调控 | `FACET_MAX_JS` / `FACET_THREADS` / `FACET_RATE` |
| 解混淆/拆包依赖 | `FACET_NODE_BIN` / `FACET_WEBCRACK` / `FACET_DYNAMIC_DEOBF` |

**零写包校验（每项必做）**：扫描日志 `<out>/scan*.log` 中
- `grep -c "只读护栏拦截" <log>` 应为 **0**（说明没有任何写方法请求被发出/尝试）；
- 网络层确认仅出现 `GET/HEAD/OPTIONS`（审计文件每行首列即方法）。

**通过标准总门槛**：全部 4 项「绿」→ 具备完全落地资格；任一红 → 条件落地，须先修。

---

## 检查项 1 · 全链路实战（3 类代表目标）

**目标**：证明 `recon_deep` 全链路（指纹 → 首页 → JS 相位 → 运行时 → 探活 → 报告）在真实目标上可用、输出可用。

**环境前置**：可出网；目标已授权；如用运行时，先 `which chromium` 并设置 `FACET_RUNTIME_BROWSER`。

**三档目标（用你已获授权的真实目标替换占位符）**：
1. 传统多页站：`https://TARGET-A.example.com`
2. Vue3 / Vite SPA：`https://TARGET-B.example.com`
3. React 后台管理：`https://TARGET-C.example.com`

**执行命令**（每档独立目录，全特性开启）：
```bash
export FACET_RUNTIME_BROWSER=/usr/bin/chromium   # 无浏览器则删此行(runtime 走 auto 降级)
export FACET_OUTPUT_DIR=./runs/target-A
python -m facet.apps.cli -u https://TARGET-A.example.com \
  --scope TARGET-A.example.com --sidecars --persist-state --yes

# TARGET-B / TARGET-C 同理，仅改 URL 与 OUTPUT_DIR
```

**通过标准（全绿）**：
- [ ] 进程正常退出，退出码 0，无未捕获异常栈；
- [ ] 产出 `facet_report.html` + `facet_report.json` 且**非空**；
- [ ] 报告中端点 `methods` 为 JS 声明真实方法、写端点状态备注含 `· GET 探测(只读降级)`（透明度修复生效）；
- [ ] 三类目标**均**跑通（非仅一类）；
- [ ] 零写包校验通过（见 §0）。

**记录项**：每条命令、耗时、端点数、findings 数、审计日志行数、零写包 grep 结果。

---

## 检查项 2 · 运行时通道（Playwright）可用性与降级

**目标**：量化 SPA 在无运行时时的覆盖损失，并确认 `auto` 模式不崩。

**执行命令**（对同一 SPA 目标跑两遍对比）：
```bash
# A. 关闭运行时
export FACET_RUNTIME=false
export FACET_OUTPUT_DIR=./runs/spa-no-rt
python -m facet.apps.cli -u https://TARGET-B.example.com --scope TARGET-B.example.com
_EP_NO_RT=$(jq '.summary.endpoints_total' ./runs/spa-no-rt/facet_report.json)

# B. 开启运行时(走系统浏览器)
export FACET_RUNTIME=true
export FACET_RUNTIME_BROWSER=/usr/bin/chromium
export FACET_OUTPUT_DIR=./runs/spa-rt
python -m facet.apps.cli -u https://TARGET-B.example.com --scope TARGET-B.example.com
_EP_RT=$(jq '.summary.endpoints_total' ./runs/spa-rt/facet_report.json)

# C. auto 模式(默认)压一遍确认不崩
export FACET_RUNTIME=auto
export FACET_OUTPUT_DIR=./runs/spa-auto
python -m facet.apps.cli -u https://TARGET-B.example.com --scope TARGET-B.example.com
```

**通过标准（全绿）**：
- [ ] B 比 A 端点更多或持平（SPA 静态收割常"新增 0 个 JS"，运行时应补回路由/懒加载 chunk）；
- [ ] 覆盖损失 `loss = 1 - _EP_NO_RT/_EP_RT` 被**量化记录**，并在可接受范围（建议 ≤ 某阈值，由你定）；
- [ ] C（`auto`）正常完成、无崩溃、无挂起；
- [ ] 若环境无浏览器：B 应**优雅降级**为空结果而非异常退出（降级纪律已内置）。

**记录项**：`_EP_NO_RT`、`_EP_RT`、loss%、三遍退出码。

---

## 检查项 3 · 授权使用清单 + scope 模板

**目标**：把「只读 + 字典爆破需明确授权」落到流程，杜绝越界。

**3.1 授权确认模板**（每次实战前由授权人填写并归档）：
```markdown
# facet 授权扫描确认单
- 目标: <URL / 网段>
- 授权范围: <明确列出的主机/路径>
- 授权性质: [ 书面合同 / 渗透测试委托书 / 内部自评 ]
- 已知约束: [ 禁止写操作 / 限时间段 / 限速率 ]
- 操作人: <姓名>  审批人: <姓名>  日期: <YYYY-MM-DD>
- 确认: 本人已知悉本工具仅做只读攻击面测绘, 字典爆破亦为只读 GET, 不发送任何写请求。
```

**3.2 scope 声明与越界护栏验证**：
```bash
# 显式声明范围(生产必做); 超出即 BLOCKED_SCOPE(fail-closed)
python -m facet.apps.cli -u https://TARGET-A.example.com \
  --scope TARGET-A.example.com --scope api.TARGET-A.example.com --yes
```
- [ ] 启动时有授权/范围提示（非 `--yes` 时应有交互确认）；
- [ ] 日志中 `grep -c "BLOCKED_SCOPE" <log>`：若只声明了同源且无越界请求则为 **0**（护栏静默生效）；
- [ ] 若故意越界探测，应出现 `BLOCKED_SCOPE` 计数 > 0（证明护栏真实拦截）。

**通过标准（全绿）**：
- [ ] 每次扫描前归档授权确认单；
- [ ] `--scope` 生效且 fail-closed；
- [ ] 越界请求被拦截（有 BLOCKED_SCOPE 证据或 0 越界尝试）。

---

## 检查项 4 · 大 SPA 压测（吞吐 / 超时 / 预算）

**目标**：验证在超大前端（数千 JS / 多 MB bundle）下，工具在 `max_duration` 预算内可控完成、不 OOM、看门狗可中途杀出部分结果。

**执行命令**：
```bash
export FACET_MAX_JS=500 FACET_THREADS=16 FACET_RATE=2.0
export FACET_OUTPUT_DIR=./runs/bigspa
# 可选: 故意限时, 验证看门狗
FACET_MAX_DURATION=600 python -m facet.apps.cli \
  -u https://BIGSPA.example.com --scope BIGSPA.example.com --persist-state
```

**通过标准（全绿）**：
- [ ] 在 `max_duration` 预算内完成或**优雅中止**（非卡死/OOM kill）；
- [ ] 内存稳定（监控 `RSS` 无持续增长至 OOM）；
- [ ] 若中途被看门狗杀掉，仍导出**部分结果**报告（非空、可定位已扫部分）；
- [ ] 限速/熔断生效（日志可见降速或熔断恢复，无雪崩）。

**记录项**：峰值 RSS、实际耗时 vs 预算、是否产出部分报告、限速/熔断触发次数。

---

## 汇总判定

| 项 | 结果 | 备注 |
|---|---|---|
| 1 全链路实战 | ☐ 绿 / ☐ 红 | |
| 2 运行时可用/降级 | ☐ 绿 / ☐ 红 | loss%= |
| 3 授权/scope | ☐ 绿 / ☐ 红 | |
| 4 大 SPA 压测 | ☐ 绿 / ☐ 红 | |

**判定**：4 项全绿 → **具备完全落地资格**（在已授权 + 显式 scope 前提下）。
任一红 → **条件落地**：定位红项根因（多为环境/授权/依赖，而非核心算法），修复后复测该项。

> 注：本清单验证的是「运行态工程化 + 全链路实战」这一最后拼图（见成熟度评估）。提取/解析/报告等组件层已在此前多轮回归（42/42 等）与 9 个真实开源项目静态分析中验证充分。
