#!/usr/bin/env bash
set -euo pipefail

APP_NAME="dae-web"
INSTALL_DIR="/opt/dae-web"
SERVICE_NAME="dae-web.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
ENV_PATH="/etc/default/dae-web"

HOST="${DAE_WEB_HOST:-0.0.0.0}"
PORT="${DAE_WEB_PORT:-8080}"
TOKEN="${DAE_WEB_TOKEN:-}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

msg() {
  printf '\033[1;36m[%s]\033[0m %s\n' "$APP_NAME" "$1"
}

warn() {
  printf '\033[1;33m[%s]\033[0m %s\n' "$APP_NAME" "$1"
}

die() {
  printf '\033[1;31m[%s]\033[0m %s\n' "$APP_NAME" "$1" >&2
  exit 1
}

need_file() {
  local path="$1"
  [[ -f "$path" ]] || die "缺少文件: $path"
}

check_env() {
  [[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux"
  [[ "${EUID}" -eq 0 ]] || die "请用 root 运行: sudo bash install_dae_web.sh"
  command -v systemctl >/dev/null 2>&1 || die "未找到 systemctl，本脚本当前仅支持 systemd"
  command -v python3 >/dev/null 2>&1 || die "未找到 python3，请先安装"
}

pick_token() {
  if [[ -n "$TOKEN" ]]; then
    return
  fi

  if [[ -t 0 ]]; then
    read -r -p "是否为 Web 面板设置 Token 认证? [Y/n]: " answer
    answer="${answer:-Y}"
    if [[ "$answer" =~ ^[Yy]$ ]]; then
      read -r -p "请输入 Token: " TOKEN
      [[ -n "$TOKEN" ]] || die "Token 不能为空"
    else
      warn "未设置 Token。请确保仅在可信内网开放端口。"
    fi
  else
    warn "非交互模式且未设置 DAE_WEB_TOKEN，将不启用 Token。"
  fi
}

install_files() {
  msg "复制应用文件到 ${INSTALL_DIR}"
  mkdir -p "$INSTALL_DIR"

  need_file "$SCRIPT_DIR/dae_web.py"
  need_file "$SCRIPT_DIR/dae.py"

  install -m 0644 "$SCRIPT_DIR/dae_web.py" "$INSTALL_DIR/dae_web.py"
  install -m 0644 "$SCRIPT_DIR/dae.py" "$INSTALL_DIR/dae.py"
}

write_env() {
  msg "写入环境配置 ${ENV_PATH}"
  umask 077
  cat > "$ENV_PATH" <<EOF
DAE_WEB_HOST=${HOST}
DAE_WEB_PORT=${PORT}
DAE_WEB_TOKEN=${TOKEN}
EOF
}

write_service() {
  msg "生成 systemd 服务 ${SERVICE_PATH}"
  cat > "$SERVICE_PATH" <<'EOF'
[Unit]
Description=DAE Web Console
After=network-online.target dae.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/dae-web
EnvironmentFile=/etc/default/dae-web
ExecStart=/usr/bin/python3 /opt/dae-web/dae_web.py --host ${DAE_WEB_HOST} --port ${DAE_WEB_PORT} --token ${DAE_WEB_TOKEN}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

reload_and_start() {
  msg "重载 systemd 并启动服务"
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
}

show_result() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  msg "安装完成"
  printf '  安装目录: %s\n' "$INSTALL_DIR"
  printf '  服务状态:\n'
  systemctl --no-pager --full status "$SERVICE_NAME" | sed -n '1,8p'
  printf '\n'
  if [[ -n "$ip" ]]; then
    printf '  访问地址: http://%s:%s\n' "$ip" "$PORT"
  else
    printf '  访问地址: http://你的路由器IP:%s\n' "$PORT"
  fi
  if [[ -n "$TOKEN" ]]; then
    printf '  Token: %s\n' "$TOKEN"
  else
    printf '  Token: 未启用\n'
  fi
}

main() {
  check_env
  pick_token
  install_files
  write_env
  write_service
  reload_and_start
  show_result
}

main "$@"