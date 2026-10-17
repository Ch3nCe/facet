# facet — 本地 / CI 复用入口
#
# 主要目标:
#   make test      跑离线回归套件(探活透明度 P-T 护栏), 不依赖浏览器/网络
#   make compile   字节编译全包(语法/导入零错误即 fail-closed)
#   make check     = compile + test
#   make build     构建发布产物(wheel + sdist + SHA256SUMS)到 dist/
#   make release   = check + build, 并提示打 tag 走 GitHub Release 自动发布
#   make landing   指向落地就绪清单(需受控网络+浏览器环境, 不在本机跑)
#
# 说明: 发布流程(版本号两处单一真源 / CHANGELOG / tag 驱动 CI)见 CONTRIBUTING.md 发布流程节。
#       wheel 为运行产物(pip install), sdist 为审计源码包(含 tests/docs)。
#       离线回归是常驻护栏; 全链路 4 项检查见 docs/landing-readiness.md,
#       由 GitHub Actions 的 "Landing Readiness" 手动工作流或在受控环境本地触发。

PY ?= python3

.PHONY: all test compile check build release landing

all: check

compile:
	$(PY) -m compileall -q facet

test:
	$(PY) -m pytest -q tests/

check: compile test

# 版本一致性: __init__.__version__ 与 pyproject version 两处单一真源必须一致
version-check:
	@$(PY) -c "import re,sys; \
	v1=re.search(r'__version__\s*=\s*\"([^\"]+)\"', open('facet/__init__.py').read()).group(1); \
	v2=re.search(r'version\s*=\s*\"([^\"]+)\"', open('pyproject.toml').read()).group(1); \
	print(f'版本: {v1} (__init__) / {v2} (pyproject)'); \
	sys.exit(0 if v1==v2 else 1)"

build: version-check
	@$(PY) -c "import build" 2>/dev/null || { echo "[-] 缺少 build 模块: $(PY) -m pip install build"; exit 1; }
	@echo "[*] 构建 wheel + sdist 到 dist/ ..."
	$(PY) -m build --outdir dist .
	@cd dist && (shasum -a 256 facet-*.whl facet-*.tar.gz 2>/dev/null || sha256sum facet-*.whl facet-*.tar.gz) > SHA256SUMS.txt
	@cat dist/SHA256SUMS.txt
	@echo "[+] dist/ 产物 + SHA256SUMS.txt 就绪"

release: check build
	@echo ""
	@echo "产物已就绪(dist/)。发布步骤:"
	@echo "  1. 更新 CHANGELOG.md 的版本段(如尚未)"
	@echo "  2. git tag v<版本号> && git push origin v<版本号>"
	@echo "  3. GitHub Release 由 .github/workflows/release.yml 自动完成(产物+notes)"

landing:
	@echo "落地就绪清单见 docs/landing-readiness.md"
	@echo "需在已授权 + 有网络/浏览器的受控环境执行(本机/CI 默认不跑全链路)。"
	@echo "用 GitHub Actions 'Landing Readiness' 手动工作流触发, 或本地: make check && 参考清单第 1/4 项。"
