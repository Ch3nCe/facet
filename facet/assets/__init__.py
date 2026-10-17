# -*- coding: utf-8 -*-
"""运行时数据资产（**随包发布**，无 Python 逻辑）。

为什么放包内而不是仓库根的 `tools/`：仓库根目录**不进 wheel**（`[tool.setuptools.packages.find]`
只收 `facet*`，且根目录非包目录）→ `pip install` 之后强反混淆 / 动态解包会**静默不可用**
（实测 wheel 66 个条目里一个 `.cjs` 都没有）。移入包内 + `package-data` 后，**源码检出与安装态
是同一路径**，`core/deobf.py` 的定位逻辑也只需一个分支。

- `deobf_strong.cjs`  —— 静态强反混淆（webcrack，opt-in，只做静态提取/解码）
- `deobf_dynamic.cjs` —— 密封离线沙箱内的动态解包（opt-in，**不联网**）

两者均由 Node 执行；缺少 Node 时调用方自动降级（`available: False`），不报错。
"""
