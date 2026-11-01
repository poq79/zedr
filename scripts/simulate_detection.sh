#!/usr/bin/env bash
# =============================================================================
# Z-EDR 检测能力受控验证脚本
#
# 安全声明：本脚本**不下载任何外部文件**，全部样本在本地生成：
#   1) 二进制改名样本 —— 复制我们自己的 zedr-diag.exe 并改名，内容完全无害；
#   2) 可疑命令行样本 —— 只做 echo + 网络回环延时，不执行任何实际危险动作；
#   3) EICAR 测试串   —— 由行业标准字符串拼接生成，本身不包含可执行代码。
#
# 所有产物位于 %TEMP%\hg-simtest，脚本结束自动清理。
# =============================================================================
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TD_POSIX="$LOCALAPPDATA/Temp/hg-simtest"
AGENT_API="http://127.0.0.1:8843"
SERVER_API="http://127.0.0.1:8080"

mkdir -p "$TD_POSIX"

banner() { printf '\n\033[1m===== %s =====\033[0m\n' "$1"; }
winpath() { cygpath -w "$1"; }

cleanup() {
  rm -rf "$TD_POSIX" 2>/dev/null
  echo "已清理 $TD_POSIX"
}
trap cleanup EXIT

banner "0. 环境检查"
if curl -s -m 3 "$AGENT_API/api/local/status" >/dev/null 2>&1; then
  echo "探针本地接口: 正常"
else
  echo "探针未运行，请先启动 bin/zedr-agent.exe"; exit 1
fi
if curl -s -m 3 "$SERVER_API/health" >/dev/null 2>&1; then
  echo "总控服务端: 正常"
else
  echo "总控服务端: 未运行（本次仅做本地验证）"
fi

banner "1. 伪装系统进程 —— 期望命中 HG-016（系统进程在非系统目录运行）"
cp -f "$ROOT/bin/zedr-diag.exe" "$TD_POSIX/svchost.exe"
echo "生成: $(winpath "$TD_POSIX/svchost.exe")"
cmd //c start "" "$(winpath "$TD_POSIX/svchost.exe")" -hold 12s >/dev/null 2>&1
sleep 9

banner "2. 改名扫描器 —— 期望命中 N-009 / HG-019（名称类 IOC）"
cp -f "$ROOT/bin/zedr-diag.exe" "$TD_POSIX/nmap.exe"
echo "生成: $(winpath "$TD_POSIX/nmap.exe")"
cmd //c start "" "$(winpath "$TD_POSIX/nmap.exe")" -hold 12s >/dev/null 2>&1
sleep 9

banner "3. 可疑命令行 —— 期望命中 K-022（清空事件日志）"
# 用 ping 回环做延时，确保进程存活时间跨越采集轮询；echo 不执行任何实际操作
cmd //c "echo wevtutil cl security & ping -n 9 127.0.0.1 >nul" >/dev/null 2>&1 &
sleep 10

banner "4. EICAR 标准测试串 —— 静态哈希层"
# 分两段拼接，避免脚本文件自身被当成特征样本
E1='X5O!P%@AP[4\PZX54(P^)7CC)7}$'
E2='EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
printf '%s%s' "$E1" "$E2" > "$TD_POSIX/eicar_test.com"
echo "生成: $(winpath "$TD_POSIX/eicar_test.com")"
echo "SHA256: $(sha256sum "$TD_POSIX/eicar_test.com" | cut -d' ' -f1)"
echo "（仅含标准测试串，无可执行代码；用于验证静态指纹层能否命中已知样本哈希）"
cmd //c start "" "$(winpath "$TD_POSIX/eicar_test.com")" >/dev/null 2>&1
sleep 5

banner "5. 本地告警结果"
python "$ROOT/scripts/show_alerts.py" || true

printf '\n验证结束。可登录总控后台 http://127.0.0.1:8080 查看同一批告警。\n'
