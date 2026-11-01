#!/bin/sh
# Z-EDR pre-commit 密钥扫描器（零依赖：仅 POSIX sh + grep）
#
# 用法：
#   sh scripts/security/secret-scan.sh          # 扫描暂存区（pre-commit 钩子调用）
#   sh scripts/security/secret-scan.sh all      # 扫描全部已跟踪文件（手动审计）
#
# 设计原则：
#   - 不联网、不依赖任何第三方二进制（规避供应链风险，见 AGENTS.md 约束 2）
#   - 高信号优先：私钥块 / 主流令牌格式 / 非占位符的凭据赋值 / 敏感文件名
#   - 占位符自动放行：change-me、example、$VAR、<...>、dummy 等
set -u

MODE=${1:-staged}
# 某些环境 PATH 里没有 git：按常见安装位置兜底
if ! command -v git >/dev/null 2>&1; then
  for d in "/c/Program Files/Git/cmd" "/c/dev-tools/git/cmd" "$LOCALAPPDATA/Programs/Git/cmd"; do
    if [ -x "$d/git.exe" ]; then PATH="$d:$PATH"; export PATH; break; fi
  done
fi
root=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "[secret-scan] 不在 git 仓库内" >&2; exit 1; }
cd "$root" || exit 1

hits=$(mktemp 2>/dev/null || echo "/tmp/zedr-secret-hits.$$")
: > "$hits"
trap 'rm -f "$hits"' EXIT

emit() { printf '%s\n' "$1" >> "$hits"; }

# ---- 文件名黑名单：即使被 git add -f 也拦截 ----
check_name() {
  name=$1
  case "$name" in
    .env|.env.*) [ "$name" = ".env.example" ] || emit "敏感文件名: $name";;
    *.pem|*.key|*.p12|*.pfx|*.jks|*.keystore|id_rsa|id_ed25519|*.kdbx) emit "敏感文件名: $name";;
  esac
}

# ---- 内容规则：文件 行号 文本 ----
PLACEHOLDER='change[-_]?me|placeholder|example|your[-_]|<[^>]+>|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|redacted|dummy|sample|\<test\>|fake|mock|x{3,}|\*\*\*|wrong[-_]?pass|bad[-_]|invalid[-_]?|no[-_]?secret|\\\\|\.\.\.'
# 代码文件：只认"引号包裹的字面量"（避免把变量/regex 当凭据）
CRED_CODE="(password|passwd|secret|token|api[_-]?key|access[_-]?key)['\"]?[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}['\"]"
# 配置文件（.env/.yaml/.ini 等）：允许裸值
CRED_CONF="(password|passwd|secret|token|api[_-]?key|access[_-]?key)[[:space:]]*[:=][[:space:]]*['\"]?[^'\";[:space:]]{8,}"

check_line() {
  f=$1; l=$2; text=$3
  case "$text" in
    *'BEGIN RSA PRIVATE KEY'*|*'BEGIN OPENSSH PRIVATE KEY'*|*'BEGIN EC PRIVATE KEY'*|*'BEGIN PGP PRIVATE KEY'*)
      emit "$f:$l 私钥块";;
  esac
  printf '%s' "$text" | grep -qE 'AKIA[0-9A-Z]{16}' && emit "$f:$l AWS Access Key"
  printf '%s' "$text" | grep -qE 'gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,}' && emit "$f:$l GitHub Token"
  printf '%s' "$text" | grep -qE 'xox[baprs]-[0-9A-Za-z-]{10,}' && emit "$f:$l Slack Token"
  printf '%s' "$text" | grep -qE 'AIza[0-9A-Za-z_-]{35}' && emit "$f:$l Google API Key"
  printf '%s' "$text" | grep -qE '(sk|pk)-[0-9A-Za-z]{24,}' && emit "$f:$l API Key（OpenAI 等格式）"

  # 测试文件只保留高信号格式检查（夹具里的假凭据不告警）
  case "$f" in
    *_test.go|*_test.ts|*_test.tsx|*_test.py|test_*.py|*.test.js|*.test.ts|*.spec.ts|*.spec.tsx) return 0;;
  esac

  # 按文件类型选择凭据赋值规则
  case "$f" in
    *.go|*.ts|*.tsx|*.js|*.jsx|*.py|*.sh|*.ps1|*.rs|*.c|*.h|*.java|*.css|*.html) pat=$CRED_CODE;;
    *) pat=$CRED_CONF;;
  esac
  if printf '%s' "$text" | grep -qiE "$pat"; then
    printf '%s' "$text" | grep -qiE "$PLACEHOLDER" || emit "$f:$l 疑似硬编码凭据"
  fi
}

# ---- 暂存区模式 ----
scan_staged() {
  files=$(git diff --cached --name-only --diff-filter=ACMR 2>/dev/null)
  if [ -z "$files" ]; then
    echo "[secret-scan] 暂存区为空，跳过"
    exit 0
  fi

  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # 自引用豁免：扫描器自身源码包含检测规则的字面量
    case "$f" in
      scripts/security/secret-scan.sh|.githooks/pre-commit) continue;;
    esac
    check_name "$f"
    case "$f" in
      *.png|*.jpg|*.jpeg|*.gif|*.ico|*.woff2|*.woff|*.ttf|*.exe|*.dll|*.zip|*.gz) continue;;
    esac
    git diff --cached -U0 -- "$f" 2>/dev/null | awk '
      /^@@/ { if (match($0, /\+[0-9]+/)) n = substr($0, RSTART+1, RLENGTH-1) + 0; next }
      /^\+\+\+/ { next }
      /^\+/ { printf "%d\t%s\n", n, substr($0, 2); n++ }
      /^-/ { next }
    ' | while IFS="$(printf '\t')" read -r ln text; do
      check_line "$f" "$ln" "$text"
    done
  done <<EOF
$files
EOF
}

# ---- 全量模式（手动审计用；一次 grep 粗筛 + 少量复核，避免逐行开销） ----
scan_all() {
  echo "[secret-scan] 全量扫描已跟踪文件..."
  git grep -nIiE "(password|passwd|secret|token|api[_-]?key|access[_-]?key)" 2>/dev/null | \
  grep -iE "$CRED_CONF" 2>/dev/null | while IFS= read -r line; do
    f=${line%%:*}; rest=${line#*:}; ln=${rest%%:*}; text=${rest#*:}
    case "$f" in
      *_test.go|*_test.ts|*_test.tsx|*_test.py|test_*.py|*.test.js|*.test.ts|*.spec.ts|*.spec.tsx) continue;;
    esac
    case "$f" in
      *.go|*.ts|*.tsx|*.js|*.jsx|*.py|*.sh|*.ps1|*.rs|*.c|*.h|*.java|*.css|*.html)
        printf '%s' "$text" | grep -qiE "$CRED_CODE" || continue;;
    esac
    printf '%s' "$text" | grep -qiE "$PLACEHOLDER" && continue
    emit "$f:$ln 疑似硬编码凭据"
  done
  git grep -nIE 'AKIA[0-9A-Z]{16}|gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,}|xox[baprs]-[0-9A-Za-z-]{10,}|AIza[0-9A-Za-z_-]{35}|BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY' 2>/dev/null | while IFS= read -r line; do
    f=${line%%:*}; rest=${line#*:}; ln=${rest%%:*}
    emit "$f:$ln 高信号密钥格式"
  done
  git ls-files | while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
      scripts/security/secret-scan.sh|.githooks/pre-commit) continue;;
    esac
    check_name "$f"
  done
}

case "$MODE" in
  all) scan_all;;
  *)   scan_staged;;
esac

if [ -s "$hits" ]; then
  echo "" >&2
  echo "✗ pre-commit 安全检查未通过（发现 $(wc -l < "$hits" | tr -d ' ') 处问题）：" >&2
  sed 's/^/    /' "$hits" >&2
  echo "" >&2
  echo "  处理建议：" >&2
  echo "    - 真实凭据：移除并轮换密钥（历史已提交的必须轮换，清理历史不代表安全）" >&2
  echo "    - 占位符误报：改名为 change-me-xxx / example / \$ENV_VAR 形式即可放行" >&2
  echo "    - 确需跳过本次检查：git commit --no-verify（不建议，请先确认无真实凭据）" >&2
  exit 1
fi

echo "[secret-scan] 通过"
exit 0
