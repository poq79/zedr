#!/bin/sh
# 启用仓库内 git 钩子（.githooks/）——克隆后执行一次即可
set -e

# 某些环境（如从 cmd 直接调 bash）PATH 里没有 git：按常见安装位置兜底
if ! command -v git >/dev/null 2>&1; then
  for d in "/c/Program Files/Git/cmd" "/c/dev-tools/git/cmd" "$LOCALAPPDATA/Programs/Git/cmd"; do
    if [ -x "$d/git.exe" ]; then PATH="$d:$PATH"; export PATH; break; fi
  done
fi
command -v git >/dev/null 2>&1 || { echo "ERROR: 找不到 git，请先安装 Git for Windows 或将其加入 PATH" >&2; exit 1; }

cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
echo "已启用 core.hooksPath=.githooks"
echo "  - pre-commit：密钥/敏感文件扫描（scripts/security/secret-scan.sh）"
echo "  - 手动全量审计：sh scripts/security/secret-scan.sh all"
echo "  - 跳过单次检查：git commit --no-verify（不建议）"
