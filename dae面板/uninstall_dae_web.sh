#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="dae-web.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
INSTALL_DIR="/opt/dae-web"
ENV_PATH="/etc/default/dae-web"

die() {
  printf '\033[1;31m[dae-web]\033[0m %s\n' "$1" >&2
  exit 1
}

[[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux"
[[ "${EUID}" -eq 0 ]] || die "请用 root 运行: sudo bash uninstall_dae_web.sh"

systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
rm -f "$SERVICE_PATH"
rm -f "$ENV_PATH"
rm -rf "$INSTALL_DIR"
systemctl daemon-reload

printf '\033[1;36m[dae-web]\033[0m 已卸载\n'