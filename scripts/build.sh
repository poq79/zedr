#!/usr/bin/env bash
# 构建全部 Windows 二进制。
#
# 重要：不要加 -ldflags "-s -w"，剥离符号的 PE 会被多数终端安全软件识别为
# "加壳样本"并直接拦截，表现为链接产物随即消失、编译报 Access is denied。
set -euo pipefail

cd "$(dirname "$0")/.."

# 版本号单一事实源：发版只改这里（可用环境变量 VERSION 覆盖做本地实验）。
# 历史教训：默认值长期停在 0.1.0，/metrics 版本分布与运维台账全部失真。
VERSION="${VERSION:-0.9.5}"
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
  go build -ldflags "-X main.version=${VERSION}" -o "bin/$out" "./cmd/$pkg"
}

build server     secserver.exe
build agent      secagent.exe
build desktop    secui.exe
build hgdiag     hgdiag.exe
build resetadmin resetadmin.exe

echo
echo "构建完成（版本 ${VERSION}）："
ls -lh bin/*.exe
