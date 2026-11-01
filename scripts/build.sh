#!/usr/bin/env bash
# 构建全部 Windows 二进制。
#
# 重要：不要加 -ldflags "-s -w"，剥离符号的 PE 会被多数终端安全软件识别为
# "加壳样本"并直接拦截，表现为链接产物随即消失、编译报 Access is denied。
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${VERSION:-0.1.0}"
mkdir -p bin

build() {
  local pkg="$1" out="$2"
  echo ">> building $pkg -> bin/$out"
  go build -ldflags "-X main.version=${VERSION}" -o "bin/$out" "./cmd/$pkg"
}

build server  secserver.exe
build agent   secagent.exe
build desktop secui.exe
build hgdiag  hgdiag.exe

echo
echo "构建完成（版本 ${VERSION}）："
ls -lh bin/*.exe
