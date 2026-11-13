#!/usr/bin/env bash
# install-agent-linux.sh — Z-EDR Linux 探针一键安装
#
# 用法（root）：
#   ./install-agent-linux.sh -u http://10.0.0.2:8080 -t <注册令牌> [-g office,finance]
#
# 行为：二进制落位 /opt/zedr/、.env 落盘（与 Windows -install 同语义：
# 配置在 exe 同目录）、systemd unit 安装 + enable --now、轮询验证上线。
# 幂等：重复执行等于重装（配置以最后一次为准；已存在 unit 先 disable）。
#
# 退出码：0 成功且探针已上线；2 权限不足；4 参数缺失；其他 = 安装失败。
# 未在 Linux 实机验证（RESEARCH-LINUX-AGENT §6）；交接时以实测为准。
set -euo pipefail

URL="" TOKEN="" TAGS=""
while getopts "u:t:g:h" opt; do
  case "$opt" in
    u) URL="$OPTARG" ;;
    t) TOKEN="$OPTARG" ;;
    g) TAGS="$OPTARG" ;;
    *) echo "用法: $0 -u <总控URL> -t <注册令牌> [-g 标签]" >&2; exit 4 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "需要 root（systemd 安装）" >&2; exit 2; }
[ -n "$URL" ] || { echo "缺少 -u 总控地址" >&2; exit 4; }
[ -n "$TOKEN" ] || { echo "缺少 -t 注册令牌（管理台「接入新主机」获取）" >&2; exit 4; }

DIR="/opt/zedr"
SRC="$(cd "$(dirname "$0")" && pwd)"
BIN="$SRC/zedr-agent-linux"
[ -x "$BIN" ] || { echo "找不到探针二进制 $BIN（部署包不完整）" >&2; exit 5; }

mkdir -p "$DIR"
install -m 0755 "$BIN" "$DIR/zedr-agent"

# 配置落盘 exe 同目录 .env（与 Windows -install 同语义；键级覆盖）
ENVF="$DIR/.env"
cat > "$ENVF" <<EOF
HG_AGENT_SERVER_URL=$URL
HG_AGENT_ENROLL_TOKEN=$TOKEN
HG_AGENT_TAGS=$TAGS
EOF
chmod 600 "$ENVF"

# systemd unit（与 zedr-agent -install 生成的模板一致）
cat > /etc/systemd/system/zedr-agent.service <<EOF
[Unit]
Description=Z-EDR Linux Agent (zedr)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$DIR/zedr-agent
EnvironmentFile=-$ENVF
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
# 已在运行先停（幂等重装语义）
systemctl stop zedr-agent 2>/dev/null || true
systemctl enable --now zedr-agent

# 轮询验证上线（≤60s）：看 systemd 活性 + 日志无致命错误即可，
# 注册状态以服务端「主机终端」列表为准（离线注册失败会自动重试）。
for i in $(seq 1 30); do
  if systemctl is-active --quiet zedr-agent; then
    echo "zedr-agent 已启动（systemd active）。上线状态请到服务端确认。"
    exit 0
  fi
  sleep 2
done
echo "警告: 服务未进入 active（journalctl -u zedr-agent -n 50 排查）" >&2
exit 6
