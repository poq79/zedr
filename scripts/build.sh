#!/usr/bin/env bash
# 构建全部 Windows 二进制。
#
# 重要：不要加 -ldflags "-s -w"，剥离符号的 PE 会被多数终端安全软件识别为
# "加壳样本"并直接拦截，表现为链接产物随即消失、编译报 Access is denied。
set -euo pipefail

cd "$(dirname "$0")/.."

# 版本号单一事实源：发版只改这里（可用环境变量 VERSION 覆盖做本地实验）。
# 历史教训：默认值长期停在 0.1.0，/metrics 版本分布与运维台账全部失真。
# （2026-11-05 教训续：0.9.10 发布时这里仍停在 0.9.9——发版流程必须含此行。）
# （2026-11-14 教训续：0.9.12~0.9.14 三轮都忘了带这行，/health 自报 0.9.11。）
VERSION="${VERSION:-0.9.15}"
mkdir -p bin

# ---- 前端（React 19 + Vite + Tailwind v4）----
# 管理台源码在 webapp/，构建产物输出到 internal/server/web/static/（go:embed）。
# 有 Node 就重新构建；没有 Node 时若产物已在（static/assets/ 非空）则直接用，
# 保证纯 Go 环境也能出包。
if command -v npm >/dev/null 2>&1; then
  echo ">> building webapp (React) -> internal/server/web/static"
  npm --prefix webapp run build
elif [ -n "$(ls internal/server/web/static/assets 2>/dev/null)" ]; then
  echo ">> node not found, using committed webapp bundle in internal/server/web/static"
else
  echo "ERROR: node 不可用且 webapp 产物缺失（internal/server/web/static/assets 为空）。" >&2
  echo "       请安装 Node ≥20 后运行: npm --prefix webapp install && npm --prefix webapp run build" >&2
  exit 1
fi

build() {
  local pkg="$1" out="$2"
  echo ">> building $pkg -> bin/$out"
  # 桌面面板用 GUI 子系统：双击启动不闪控制台窗口；其余保留控制台
  # （服务端/探针要打印日志与 -install 输出，服务化也依赖控制台语义）。
  if [ "$pkg" = "desktop" ]; then
    go build -ldflags "-X main.version=${VERSION} -H=windowsgui" -o "bin/$out" "./cmd/$pkg"
  else
    go build -ldflags "-X main.version=${VERSION}" -o "bin/$out" "./cmd/$pkg"
  fi
}

build server     zedr-server.exe
build agent      zedr-agent.exe
build desktop    zedr-ui.exe
build diag       zedr-diag.exe
build resetadmin resetadmin.exe

# ---- Linux 交叉编译（v0.9.14 起，RESEARCH-LINUX-AGENT）----
# server：Linux 服务端已在路线图（svc 拆分后全链路可编译）；agent：Linux
# 探针组合根（lapp）。产物带 -linux 后缀避免与 Windows PE 混淆；不加 -s -w
# 的纪律与此处相同（不过 Linux 产物无 AV 拦截问题，保持一致便于对拍）。
# 未在 Linux 实机验证：产物能在目标机跑起来才算数，交接时诚实标注。
build_linux() {
  local pkg="$1" out="$2"
  echo ">> building linux/amd64 $pkg -> bin/$out"
  GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=${VERSION}" -o "bin/$out" "./cmd/$pkg"
}
if [ "${SKIP_LINUX:-0}" != "1" ]; then
  build_linux server zedr-server-linux
  build_linux agent  zedr-agent-linux
fi

# ---- 部署包（"接入新主机"引导的下载物，HG_SERVER_DEPLOY_PACKAGE 指向它）----
# zip：探针 + 桌面托盘 + 官方安装/卸载脚本 + 包内说明。
# Compress-Archive 而非 tar：目标机解压用 PowerShell Expand-Archive 即可，
# 且 zip 保留的路径结构对 install-agent.ps1 的 $PSScriptRoot 定位友好。
DEPLOY_ZIP="bin/zedr-deploy-v${VERSION}.zip"
if command -v powershell.exe >/dev/null 2>&1; then
  echo ">> packaging deploy bundle -> ${DEPLOY_ZIP}"
  rm -f "${DEPLOY_ZIP}"
  powershell.exe -NoProfile -Command "Compress-Archive -Force \
    -Path 'bin/zedr-agent.exe','bin/zedr-ui.exe', \
           'scripts/deploy/install-agent.ps1','scripts/deploy/uninstall-agent.ps1', \
           'scripts/deploy/README-DEPLOY.md' \
    -DestinationPath '${DEPLOY_ZIP}'"
  # Compress-Archive 平铺打包（无目录层级），解压即脚本所在目录，符合预期。
else
  echo ">> powershell.exe 不可用，跳过部署包打包（服务端 deploy 端点将不可用）" >&2
fi

echo
echo "构建完成（版本 ${VERSION}）："
ls -lh bin/*.exe bin/*.zip 2>/dev/null || ls -lh bin/*.exe
