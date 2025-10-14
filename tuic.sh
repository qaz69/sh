#!/bin/bash
# ======================================================
# Tuic 一键安装脚本（官方版本下载，QUIC UDP 模式）
# 支持 Debian / Ubuntu / CentOS / Fedora / Amazon Linux
# 来源：EAimTY/tuic 官方仓库
# 作者改良：A Q 专用 QUIC 版
# ======================================================

set -e

# ---------- 颜色 ----------
green(){ echo -e "\033[32m$1\033[0m"; }
red(){ echo -e "\033[31m$1\033[0m"; }
yellow(){ echo -e "\033[33m$1\033[0m"; }

# ---------- 系统检测 ----------
SYS=$(uname -s)
if [[ "$SYS" != "Linux" ]]; then
  red "本脚本仅支持 Linux 系统"
  exit 1
fi

# ---------- 架构检测 ----------
archAffix(){
  case "$(uname -m)" in
    x86_64) echo "x86_64-unknown-linux-musl" ;;
    aarch64) echo "aarch64-unknown-linux-musl" ;;
    armv7l) echo "armv7-unknown-linux-musleabi" ;;
    *) red "暂不支持该架构: $(uname -m)"; exit 1 ;;
  esac
}

ARCH=$(archAffix)

# ---------- 确认 root ----------
if [[ $EUID -ne 0 ]]; then
  red "请以 root 身份运行此脚本"
  exit 1
fi

# ---------- 安装依赖 ----------
yellow "安装必要依赖..."
if command -v apt >/dev/null 2>&1; then
  apt update -y
  apt install -y curl wget unzip jq openssl
elif command -v yum >/dev/null 2>&1; then
  yum install -y curl wget unzip jq openssl
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y curl wget unzip jq openssl
else
  red "不支持的包管理器，请手动安装 curl wget jq 后重试"
  exit 1
fi

# ---------- 获取最新版本 ----------
yellow "获取 Tuic 最新版本号..."
TUIC_VER=$(curl -s https://api.github.com/repos/EAimTY/tuic/releases/latest | jq -r '.tag_name')

if [[ -z "$TUIC_VER" || "$TUIC_VER" == "null" ]]; then
  red "无法获取最新版本，请检查网络或 GitHub API 限制"
  exit 1
fi

green "检测到最新版本: ${TUIC_VER}"

# ---------- 下载 Tuic ----------
mkdir -p /usr/local/bin
TUIC_URL="https://github.com/EAimTY/tuic/releases/download/${TUIC_VER}/tuic-server-${TUIC_VER}-${ARCH}"

yellow "正在下载 Tuic 官方二进制文件..."
wget -qO /usr/local/bin/tuic "$TUIC_URL" || {
  red "下载失败，请检查网络或 GitHub 访问状态"
  exit 1
}

chmod +x /usr/local/bin/tuic
green "Tuic 下载并安装完成！"

# ---------- 创建配置目录 ----------
mkdir -p /etc/tuic
cd /etc/tuic

# ---------- 随机端口、UUID、密码 ----------
PORT=$(shuf -i 20000-65000 -n 1)
UUID=$(cat /proc/sys/kernel/random/uuid)
PASS=$(openssl rand -hex 8)

# ---------- 生成配置文件（QUIC UDP 模式） ----------
cat > /etc/tuic/tuic.json <<EOF
{
  "server": "[::]:${PORT}",
  "users": {
    "${UUID}": "${PASS}"
  },
  "certificate": "/etc/tuic/tuic.crt",
  "private_key": "/etc/tuic/tuic.key",
  "congestion_control": "bbr",
  "udp_relay_mode": "quic",
  "zero_rtt_handshake": false,
  "heartbeat": 10,
  "alpn": ["h3", "quic"],
  "log_level": "info"
}
EOF

green "配置文件已生成：/etc/tuic/tuic.json"

# ---------- 创建自签证书 ----------
yellow "生成自签 TLS 证书..."
openssl req -x509 -newkey rsa:2048 -keyout /etc/tuic/tuic.key -out /etc/tuic/tuic.crt -days 3650 -nodes -subj "/CN=tuic"
chmod 600 /etc/tuic/tuic.key

# ---------- 创建 systemd 服务 ----------
cat > /etc/systemd/system/tuic.service <<EOF
[Unit]
Description=Tuic Server (official build)
After=network.target

[Service]
ExecStart=/usr/local/bin/tuic -c /etc/tuic/tuic.json
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# ---------- 启动服务 ----------
systemctl daemon-reload
systemctl enable tuic
systemctl restart tuic

sleep 1
systemctl status tuic --no-pager

# ---------- 输出结果 ----------
green "\n✅ Tuic 已成功安装并启动！（QUIC UDP 模式）"
echo "----------------------------------------"
echo "配置路径: /etc/tuic/tuic.json"
echo "服务端口: ${PORT}"
echo "UUID: ${UUID}"
echo "密码: ${PASS}"
echo "----------------------------------------"
echo "客户端示例（Tuic v5 QUIC UDP）:"
echo "tuic://$UUID:$PASS@your_server_ip:$PORT?congestion_control=bbr&udp_relay_mode=quic&alpn=h3,quic"
echo "----------------------------------------"
