# 贡献指南（Contributing）

感谢你对 facet 的关注。本指南说明开发环境、门禁要求与代码约定。

## 开发环境

```bash
git clone <repo-url> && cd facet
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"        # pytest + ruff
```

可选能力（按需装）：

```bash
pip install -e ".[async,runtime,js,ast]"
playwright install chromium    # 运行时通道
```

## 开发门禁（必须先过）

```bash
make check      # = compile + test，CI 同款
make compile    # 字节编译全包（语法/导入零错误即 fail-closed）
make test       # 离线测试套件（不依赖浏览器/网络）
```

**CI 矩阵**：Python 3.8 / 3.10 / 3.12，`compileall` + `pytest` 全绿方可合并。

## 测试布局

| 文件 | 定位 | 约定 |
| --- | --- | --- |
| `tests/test_regressions.py` | 行为回归钉子（CI 护栏） | 修过的 bug 必须有钉子，防回潮 |
| `tests/test_units.py` | 核心链路契约（主动覆盖） | 直接测库函数契约；环境不可用时**跳过并说明原因**，不静默失败 |
| `tests/test_e2e_fixture.py` | 端到端冒烟 | 本地 `http.server` fixture，零外网依赖 |

新增行为 → 先在对应文件加用例；环境依赖类用例（如 tree-sitter）用
`pytest.mark.skipif` 探测真实可用性后跳过。

## 代码约定

- **单一真源**：版本号只出现在 `facet/__init__.py` 的 `__version__`
  与 `pyproject.toml` 的 `version`（两处必须一致）；不硬编码第三处。
- **测试隔离**：模块级 monkeypatch 必须 try/finally 还原（如
  `ast_sidecar._tree_sitter_parser`、`probe._probe_req`）；测试工作目录用
  `tempfile.mkdtemp(dir=...)`，**不要**依赖 pytest `tmp_path`（沙箱环境
  `TMPDIR` 可能被拦截）。
- **披露纪律**：任何「可选能力缺失」必须在报告里如实登记降级原因，不静默
  假装跑过；新增发现渠道必须接入三态披露（requested / triggered / ran）。
- **只读红线**：任何变更不得引入对目标的写请求；写方法端点只提取、不发
  验证包（双轨：`write_apis` + `apis`）。
- **转义纪律**：HTML 元素内容用 `_esc_text`（仅 `&<>`），属性上下文才用
  `_esc`（quote=True）；避免 `&quot;` 类六倍膨胀。
- **不硬编码白名单**：识别逻辑（基址、框架、路径形态）用形态/用法启发式
  动态发现，不靠预设站点名 / 变量名表打补丁。

## 提交与 PR 流程

1. 从 `main` 拉分支：`feat/xxx`、`fix/xxx`、`docs/xxx`；
2. 改动完成后跑 `make check`，全绿再提交；
3. PR 描述包含：**为什么改**（问题/动机）、**改了什么**（范围）、**怎么验的**
   （测试 / 回归证据）；
4. 合规相关改动（护栏、披露、红线）在 PR 描述中**显式声明影响面**；
5. 行为变更同步更新 `CHANGELOG.md` 的 [未发布] 段与相关 `docs/` 文档。

## 合规红线（所有贡献的共同前提）

本工具仅用于**自有资产、已获书面授权、或 SRC in-scope** 目标。提交任何代码
前，确认你的改动不会削弱：授权确认、范围护栏（`--scope` fail-closed）、
只读红线、速率限制与熔断、披露完整性。

## 发布流程（Release）

版本结构：每个 tag `vX.Y.Z` 对应 **4 件套**（`.github/workflows/release.yml`
自动构建）：

| 产物 | 命名 | 用途 |
| --- | --- | --- |
| 运行 wheel | `facet-X.Y.Z-py3-none-any.whl` | `pip install` 安装产物（纯 Python） |
| 审计源码包 | `facet-X.Y.Z.tar.gz` | 完整源码（含 `tests/`、`docs/`、`CHANGELOG`、`LICENSE`，由 `MANIFEST.in` 控制）—— 安全工具的分发必须可审计 |
| 校验和 | `SHA256SUMS.txt` | 两件套的 SHA256 —— 授权分发场景下使用者可验证完整性 |
| Release Notes | GitHub Release 正文 | 自动提取自 `CHANGELOG.md` 对应版本段 |

**版本号单一真源**（两处必须同号，`make version-check` 与发布工作流都会拦截
不一致）：

1. `facet/__init__.py` 的 `__version__`
2. `pyproject.toml` 的 `version`

发布步骤：

```bash
# 1. 改版本号（两处）
# 2. 更新 CHANGELOG.md 对应版本段
# 3. 门禁全绿
make check
# 4. 打 tag 推送 —— 以下全自动（版本三处同号闸 → 编译闸 → build → checksums → GitHub Release）
git tag vX.Y.Z && git push origin vX.Y.Z
```

本地手工发布（无 CI 时）：`make release`（= check + build，产物落 `dist/`），
或手工将 `dist/` 三件套传给分发渠道。使用者校验：

```bash
shasum -a 256 -c SHA256SUMS.txt    # macOS
sha256sum -c SHA256SUMS.txt        # Linux
```
