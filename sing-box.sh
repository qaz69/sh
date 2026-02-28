#!/bin/bash

# =========================================================
#  Sing-Box 一键管理脚本 - TUI 美化版
#  版本: 3.1 - Whiptail TUI Interface
#  原作者: Enhanced Edition
# =========================================================

# 修复 SSH 乱码问题 - 设置 UTF-8 编码
export LANG=zh_CN.UTF-8
export LC_ALL=zh_CN.UTF-8
export LANGUAGE=zh_CN.UTF-8

# 如果系统不支持中文 locale,尝试使用 en_US.UTF-8
if ! locale -a 2>/dev/null | grep -q "zh_CN.utf8\|zh_CN.UTF-8"; then
    export LANG=en_US.UTF-8
    export LC_ALL=en_US.UTF-8
    export LANGUAGE=en_US.UTF-8
fi

# --- 检查 whiptail ---
if ! command -v whiptail &> /dev/null; then
    echo "未检测到 whiptail，正在安装..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y whiptail
    elif command -v yum &> /dev/null; then
        yum install -y newt
    fi
fi

# --- TUI 颜色配置 (蓝底灰框) ---
export NEWT_COLORS='
root=,blue
window=black,lightgray
border=black,lightgray
shadow=black,gray
button=black,white
actbutton=white,red
compactbutton=black,lightgray
title=black,lightgray
textbox=black,lightgray
acttextbox=black,cyan
entry=black,lightgray
disentry=gray,lightgray
checkbox=black,lightgray
actcheckbox=black,cyan
listbox=black,lightgray
actlistbox=black,cyan
sellistbox=white,blue
actsellistbox=white,blue
'

# --- 原有颜色定义 (保留用于终端输出) ---
RED='\e[0;31m'
GREEN='\e[0;37m'
YELLOW='\e[1;33m'
BLUE='\e[1;33m'
CYAN='\e[1;33m'
MAGENTA='\e[0;31m'
WHITE='\e[0;37m'
NC='\e[0m'
BOLD='\033[1m'
DIM='\033[2m'

# --- 背景色 ---
BG_RED='\033[41m'
BG_GREEN='\033[43m'
BG_BLUE='\033[43m'
BG_CYAN='\033[43m'

# --- 配置变量 ---
VERSION="1.12.21"
CONF_DIR="/etc/sing-box"
CONF_FILE="$CONF_DIR/config.json"
BIN_PATH="/usr/local/bin/sing-box"
CERT_PATH="$CONF_DIR/server.crt"
KEY_PATH="$CONF_DIR/server.key"
SERVICE_FILE="/etc/systemd/system/sing-box.service"
INFO_PATH="$CONF_DIR/node.info"
LOG_FILE="/var/log/sing-box.log"

# --- 工具函数 (保持原逻辑) ---
print_banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════════╗
║                      Sing-Box 管理脚本                              ║
╚════════════════════════════════════════════════════════════════════╝
EOF
}

print_line() {
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
}

print_double_line() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
}

info() { echo -e "${BLUE}[信息]${NC} $1"; }
success() { echo -e "${GREEN}[成功]${NC} $1"; }
warn() { echo -e "${YELLOW}[警告]${NC} $1"; }
error() { echo -e "${RED}[错误]${NC} $1"; exit 1; }

get_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) BIN_ARCH="amd64"; FILE_ARCH="amd64" ;;
        aarch64|arm64) BIN_ARCH="arm64"; FILE_ARCH="arm64" ;;
        armv7l) BIN_ARCH="armv7"; FILE_ARCH="armv7" ;;
        *) BIN_ARCH="amd64"; FILE_ARCH="amd64" ;;
    esac
}

# --- 智能IP检测 ---
detect_network() {
    info "正在检测网络配置..."
    MAIN_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    IP4=$(ip -4 addr show $MAIN_IFACE 2>/dev/null | grep inet | grep -v 127.0.0.1 | awk '{print $2}' | cut -d/ -f1 | head -n1)
    if [[ -z "$IP4" ]]; then IP4=$(curl -s4 --max-time 3 https://api.ipify.org 2>/dev/null || echo ""); fi
    IP6=$(ip -6 addr show $MAIN_IFACE 2>/dev/null | grep "scope global" | awk '{print $2}' | cut -d/ -f1 | head -n1)
    if [[ -z "$IP6" ]]; then IP6=$(curl -s6 --max-time 3 https://api64.ipify.org 2>/dev/null || echo ""); fi
    
    HAS_IPV4=false
    HAS_IPV6=false
    [[ -n "$IP4" ]] && HAS_IPV4=true
    [[ -n "$IP6" ]] && HAS_IPV6=true
    
    echo -e "\n${BOLD}网络环境检测结果:${NC}"
    print_line
    echo -e "  主网卡: ${BLUE}$MAIN_IFACE${NC}"
    echo -e "  IPv4 : ${HAS_IPV4} && echo -e "${CYAN}$IP4 ✓${NC}" || echo -e "${DIM}未配置${NC}"
    echo -e "  IPv6 : ${HAS_IPV6} && echo -e "${CYAN}$IP6 ✓${NC}" || echo -e "${DIM}未配置${NC}"
    print_line
}

# --- 防火墙配置 ---
configure_firewall() {
    local port=$1
    info "配置防火墙规则 (端口: ${YELLOW}$port/UDP${NC})..."
    if command -v ufw &> /dev/null; then ufw allow $port/udp >/dev/null 2>&1; success "UFW 规则已添加"; fi
    if command -v firewall-cmd &> /dev/null; then firewall-cmd --permanent --add-port=$port/udp >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1; success "Firewalld 规则已添加"; fi
    if command -v iptables &> /dev/null; then iptables -I INPUT -p udp --dport $port -j ACCEPT 2>/dev/null; success "Iptables 规则已添加"; fi
}

# --- TLS证书配置 ---
configure_tls() {
    mkdir -p "$CONF_DIR" && cd "$CONF_DIR"
    print_double_line
    echo -e "${BOLD}         TLS 证书配置选项${NC}"
    print_double_line
    echo -e "  ${CYAN}1${NC}. 复制真实网站证书 ${DIM}(推荐)${NC}"
    echo -e "  ${CYAN}2${NC}. 生成自签名证书   ${DIM}(快速)${NC}"
    print_line
    echo -ne "${BLUE}请选择 [1-2, 默认: 1]${NC}: "
    read -r cert_choice
    cert_choice=${cert_choice:-1}
    echo ""

    if [ "$cert_choice" == "1" ]; then
        echo -ne "${BLUE}请输入要伪造的域名 [默认: www.bing.com]${NC}: "
        read -r target_domain
        target_domain=${target_domain:-www.bing.com}
        get_arch
        info "下载证书复制工具..."
        URL="https://github.com/virusdefender/copy-cert/releases/latest/download/copy-cert-linux-$BIN_ARCH"
        if curl -L -o /usr/local/bin/copy-cert "$URL" && chmod +x /usr/local/bin/copy-cert; then
            success "工具下载成功"
        else
            warn "工具下载失败，降级为自签名证书"; cert_choice="2"
        fi

        if [ "$cert_choice" == "1" ]; then
            info "正在从 ${YELLOW}$target_domain${NC} 复制证书..."
            rm -rf certs/
            if /usr/local/bin/copy-cert "$target_domain:443"; then
                local sub_dir=$(ls -dt certs/* 2>/dev/null | head -n 1)
                if [[ -n "$sub_dir" ]]; then
                    local keyword=$(echo $target_domain | cut -d'.' -f2)
                    local tmp_crt=$(ls "$sub_dir"/*"$keyword"*.crt 2>/dev/null | head -n 1)
                    local tmp_key=$(ls "$sub_dir"/*"$keyword"*.key 2>/dev/null | head -n 1)
                    [[ -z "$tmp_crt" ]] && tmp_crt=$(ls -S "$sub_dir"/*.crt 2>/dev/null | head -n 1)
                    [[ -z "$tmp_key" ]] && tmp_key=$(ls -S "$sub_dir"/*.key 2>/dev/null | head -n 1)
                    if [[ -n "$tmp_crt" && -n "$tmp_key" ]]; then
                        cp -f "$tmp_crt" "$CERT_PATH"
                        cp -f "$tmp_key" "$KEY_PATH"
                        rm -rf certs/
                        FINAL_DOMAIN=$target_domain
                        success "✅ 证书复制成功: ${GREEN}$target_domain${NC}"
                        return 0
                    fi
                fi
            fi
            warn "证书抓取失败，自动降级为自签名证书"; cert_choice="2"
        fi
    fi

    if [ "$cert_choice" == "2" ]; then
        echo -ne "${BLUE}请输入自签名证书域名 [默认: www.bing.com]${NC}: "
        read -r self_domain
        FINAL_DOMAIN=${self_domain:-www.bing.com}
        info "生成自签名证书 (EC P-256)..."
        openssl ecparam -genkey -name prime256v1 -out "$KEY_PATH" 2>/dev/null
        openssl req -new -x509 -days 36500 -key "$KEY_PATH" -out "$CERT_PATH" -subj "/CN=$FINAL_DOMAIN" >/dev/null 2>&1
        success "自签名证书已生成 (域名: ${YELLOW}$FINAL_DOMAIN${NC})"
    fi
}

# --- 安装主程序 ---
install_singbox() {
    [[ $EUID -ne 0 ]] && error "请使用 root 权限运行此脚本"
    print_banner
    echo -e "${BOLD}${BG_CYAN}                     开始安装 Sing-Box                      ${NC}\n"
    info "安装系统依赖..."
    if command -v apt-get &> /dev/null; then apt-get update -qq && apt-get install -y curl jq openssl net-tools tar wget iproute2 >/dev/null 2>&1;
    elif command -v yum &> /dev/null; then yum install -y curl jq openssl net-tools tar wget iproute >/dev/null 2>&1; fi
    success "依赖安装完成"
    echo ""
    configure_tls; detect_network; get_arch
    echo ""
    info "下载 Sing-Box ${YELLOW}v$VERSION${NC}..."
    DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v$VERSION/sing-box-$VERSION-linux-$FILE_ARCH.tar.gz"
    if wget -q --show-progress -O /tmp/singbox.tar.gz "$DOWNLOAD_URL" 2>&1 | grep -oP '\d+%' | tail -1; then
        tar -xzf /tmp/singbox.tar.gz -C /tmp 2>/dev/null
        mv /tmp/sing-box-*/sing-box "$BIN_PATH" 2>/dev/null
        chmod +x "$BIN_PATH"; rm -rf /tmp/singbox* /tmp/sing-box-*
        success "Sing-Box 主程序安装完成"
    else
        error "下载失败，请检查网络连接"
    fi

    # 生成配置
    info "生成配置参数..."
    TUIC_PORT=$((RANDOM % 50000 + 10000))
    ANY_PORT=$((RANDOM % 50000 + 10000))
    UUID=$(cat /proc/sys/kernel/random/uuid)
    PASS=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)
    
    configure_firewall $TUIC_PORT
    configure_firewall $ANY_PORT

    info "生成服务配置..."
    cat > "$CONF_FILE" <<EOF
{
  "log": { "level": "info", "timestamp": true, "output": "$LOG_FILE" },
  "inbounds": [
    {
      "type": "tuic", "tag": "tuic-in", "listen": "0.0.0.0", "listen_port": $TUIC_PORT,
      "users": [ { "uuid": "$UUID", "password": "$PASS" } ],
      "congestion_control": "bbr", "auth_timeout": "3s", "zero_rtt_handshake": false, "heartbeat": "10s",
      "tls": { "enabled": true, "server_name": "$FINAL_DOMAIN", "alpn": ["h3"], "certificate_path": "$CERT_PATH", "key_path": "$KEY_PATH" }
    },
    {
      "type": "anytls", "tag": "anytls-in", "listen": "0.0.0.0", "listen_port": $ANY_PORT,
      "users": [ { "name": "user", "password": "$PASS" } ],
      "tls": { "enabled": true, "server_name": "$FINAL_DOMAIN", "alpn": ["h3", "h2", "http/1.1"], "certificate_path": "$CERT_PATH", "key_path": "$KEY_PATH" }
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Sing-Box Proxy Service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
Wants=network.target
[Service]
Type=simple
User=root
ExecStart=$BIN_PATH run -c $CONF_FILE
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
LimitNPROC=512
[Install]
WantedBy=multi-user.target
EOF

    info "启动 Sing-Box 服务..."
    systemctl daemon-reload
    systemctl enable sing-box --now >/dev/null 2>&1
    sleep 2

    cat > "$INFO_PATH" <<EOF
DOMAIN=$FINAL_DOMAIN
TUIC_PORT=$TUIC_PORT
ANY_PORT=$ANY_PORT
UUID=$UUID
PASSWORD=$PASS
INSTALL_TIME=$(date '+%Y-%m-%d %H:%M:%S')
EOF

    if systemctl is-active --quiet sing-box; then
        echo ""; success "✨ Sing-Box 安装成功并已启动！"; echo ""; sleep 1; show_links
    else
        echo ""; error "服务启动失败，请运行 '系统诊断' 查看详情"
    fi
}

# --- 查看连接信息 ---
show_links() {
    [[ ! -f "$CONF_FILE" ]] && error "未找到配置文件，请先安装"
    source "$INFO_PATH" 2>/dev/null
    detect_network
    
    local tuic_p=$(jq -r '.inbounds[] | select(.type=="tuic") | .listen_port' "$CONF_FILE")
    local any_p=$(jq -r '.inbounds[] | select(.type=="anytls") | .listen_port' "$CONF_FILE")
    local uuid=$(jq -r '.inbounds[] | select(.type=="tuic") | .users[0].uuid' "$CONF_FILE")
    local pass=$(jq -r '.inbounds[] | select(.type=="tuic") | .users[0].password' "$CONF_FILE")

    print_banner
    print_double_line
    echo -e "${BOLD}                    节点连接信息${NC}"
    print_double_line

    local has_output=false
    if $HAS_IPV4 && [[ -n "$IP4" ]]; then
        echo -e "\n${BG_BLUE}${WHITE} IPv4 节点链接 ${NC}\n"
        echo -e "${BOLD}TUIC:${NC}\n${CYAN}tuic://$uuid:$pass@$IP4:$tuic_p?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=$DOMAIN&allow_insecure=1#TUIC-IPv4${NC}"
        echo -e "\n${BOLD}AnyTLS:${NC}\n${CYAN}anytls://$pass@$IP4:$any_p?sni=$DOMAIN&allow_insecure=1#AnyTLS-IPv4${NC}"
        has_output=true
    fi
    if $HAS_IPV6 && [[ -n "$IP6" ]]; then
        echo -e "\n${BG_CYAN}${WHITE} IPv6 节点链接 ${NC}\n"
        echo -e "${BOLD}TUIC:${NC}\n${CYAN}tuic://$uuid:$pass@[$IP6]:$tuic_p?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=$DOMAIN&allow_insecure=1#TUIC-IPv6${NC}"
        echo -e "\n${BOLD}AnyTLS:${NC}\n${CYAN}anytls://$pass@[$IP6]:$any_p?sni=$DOMAIN&allow_insecure=1#AnyTLS-IPv6${NC}"
        has_output=true
    fi
    if ! $has_output; then warn "未检测到有效的公网IP地址"; fi
    echo ""; print_double_line
}

# --- 服务状态 ---
show_status() {
    print_banner
    print_double_line
    echo -e "${BOLD}                    服务运行状态${NC}"
    print_double_line
    if systemctl is-active --quiet sing-box; then echo -e "  服务状态 : ${CYAN}● 运行中${NC}"; else echo -e "  服务状态 : ${RED}● 已停止${NC}"; fi
    if [[ -f "$CONF_FILE" ]]; then
        local tuic_p=$(jq -r '.inbounds[] | select(.type=="tuic") | .listen_port' "$CONF_FILE" 2>/dev/null)
        local any_p=$(jq -r '.inbounds[] | select(.type=="anytls") | .listen_port' "$CONF_FILE" 2>/dev/null)
        echo -e "  TUIC端口 : ${BLUE}$tuic_p${NC} $(ss -ulnp | grep -q ":$tuic_p " && echo "${CYAN}[监听]${NC}" || echo "${RED}[未监听]${NC}")"
        echo -e "  ANY 端口 : ${BLUE}$any_p${NC} $(ss -ulnp | grep -q ":$any_p " && echo "${CYAN}[监听]${NC}" || echo "${RED}[未监听]${NC}")"
    fi
    detect_network
    echo -e "  公网IPv4 : ${HAS_IPV4} && echo "${CYAN}$IP4${NC}" || echo "${DIM}无${NC}"
    echo -e "  公网IPv6 : ${HAS_IPV6} && echo "${CYAN}$IP6${NC}" || echo "${DIM}无${NC}"
    if [[ -f "$INFO_PATH" ]]; then source "$INFO_PATH"; echo -e "  安装时间 : ${YELLOW}${INSTALL_TIME:-未知}${NC}"; fi
    print_double_line; echo ""; systemctl status sing-box --no-pager -l
}

# --- 查看日志 ---
show_logs() {
    print_banner
    echo -e "${BOLD}${BG_CYAN}                    实时日志监控                        ${NC}\n"
    echo -e "${DIM}按 Ctrl+C 退出日志查看${NC}\n"; print_line
    if [[ -f "$LOG_FILE" ]]; then tail -f "$LOG_FILE"; else journalctl -u sing-box -f -n 100; fi
}

# --- 系统诊断 ---
diagnose() {
    print_banner
    print_double_line
    echo -e "${BOLD}                    系统诊断工具${NC}"
    print_double_line
    echo -e "\n${BLUE}[1] 服务状态检查${NC}"; print_line; systemctl status sing-box --no-pager
    echo -e "\n${BLUE}[2] 配置文件验证${NC}"; print_line
    if $BIN_PATH check -c $CONF_FILE 2>&1; then success "配置文件语法正确"; else error "配置文件存在错误"; fi
    echo -e "\n${BLUE}[3] 端口监听状态${NC}"; print_line; ss -ulnp | grep sing-box || echo "未发现监听端口"
    echo -e "\n${BLUE}[4] 网络连通性测试${NC}"; print_line; detect_network
    echo -e "\n${BLUE}[5] 最近50条日志${NC}"; print_line
    if [[ -f "$LOG_FILE" ]]; then tail -n 50 "$LOG_FILE"; else journalctl -u sing-box -n 50 --no-pager; fi
    echo -e "\n${BLUE}[6] 防火墙规则${NC}"; print_line
    if command -v ufw &> /dev/null; then ufw status verbose; elif command -v firewall-cmd &> /dev/null; then firewall-cmd --list-all; else echo "未安装防火墙管理工具"; fi
    print_double_line
}

# --- 配置管理 ---
show_config() {
    print_banner
    print_double_line
    echo -e "${BOLD}                    配置文件内容${NC}"
    print_double_line
    if [[ -f "$CONF_FILE" ]]; then cat "$CONF_FILE" | jq '.' --color-output 2>/dev/null || cat "$CONF_FILE"; else warn "配置文件不存在"; fi
    print_double_line
}

# --- 卸载程序 ---
uninstall() {
    print_banner
    print_double_line
    echo -e "${RED}${BOLD}                    ⚠️  卸载确认  ⚠️${NC}"
    print_double_line
    echo -e "\n  这将删除: Sing-Box 主程序, 所有配置文件, TLS证书, 系统服务\n"
    print_line
    echo -ne "${YELLOW}确认要卸载吗? [y/N]${NC}: "
    read -r confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        info "正在停止服务..."
        systemctl stop sing-box 2>/dev/null; systemctl disable sing-box 2>/dev/null
        info "正在删除文件..."
        rm -rf "$CONF_DIR" "$BIN_PATH" "$SERVICE_FILE" "$LOG_FILE"
        systemctl daemon-reload
        success "✨ 卸载完成！"
    else
        warn "已取消卸载操作"
    fi
}

# --- Whiptail 主菜单逻辑 ---
main_menu() {
    # 获取服务状态文字
    if systemctl is-active --quiet sing-box 2>/dev/null; then
        STATUS_TEXT="运行中 (Running)"
    elif [[ -f "$SERVICE_FILE" ]]; then
        STATUS_TEXT="已停止 (Stopped)"
    else
        STATUS_TEXT="未安装 (Not Installed)"
    fi

    CHOICE=$(whiptail --title "Sing-box管理脚本" \
    --backtitle "Sing-Box Manager - Enhanced Edition | 当前状态: $STATUS_TEXT" \
    --menu "请使用上下键或数字键选择操作:" \
    20 60 11 \
    "1" "安装服务 (Install)" \
    "2" "启动服务 (Start)" \
    "3" "停止服务 (Stop)" \
    "4" "重启服务 (Restart)" \
    "5" "服务状态 (Status)" \
    "6" "查看日志 (View Logs)" \
    "7" "节点信息 (Node Links)" \
    "8" "配置文件 (Config)" \
    "9" "系统诊断 (Diagnose)" \
    "10" "卸载服务 (Uninstall)" \
    "0" "退出脚本 (Exit)" \
    3>&1 1>&2 2>&3)

    # 捕获取消按钮
    exitstatus=$?
    if [ $exitstatus != 0 ]; then
        exit 0
    fi

    # 核心逻辑执行（暂时退出TUI以显示原生输出）
    case $CHOICE in
        1) clear; install_singbox; read -n 1 -s -r -p "按任意键返回..." ;;
        2) 
            clear
            info "正在启动服务..."
            systemctl start sing-box
            sleep 2
            if systemctl is-active --quiet sing-box; then success "服务启动成功"; else error "服务启动失败，请查看日志"; fi
            read -n 1 -s -r -p "按任意键返回..."
            ;;
        3) 
            clear
            info "正在停止服务..."
            systemctl stop sing-box; sleep 1
            if ! systemctl is-active --quiet sing-box; then success "服务已停止"; else error "服务停止失败"; fi
            read -n 1 -s -r -p "按任意键返回..."
            ;;
        4) 
            clear
            info "正在重启服务..."
            systemctl restart sing-box; sleep 2
            if systemctl is-active --quiet sing-box; then success "服务重启成功"; else error "服务重启失败，请查看日志"; fi
            read -n 1 -s -r -p "按任意键返回..."
            ;;
        5) clear; show_status; read -n 1 -s -r -p "按任意键返回..." ;;
        6) clear; show_logs; ;;
        7) clear; show_links; read -n 1 -s -r -p "按任意键返回..." ;;
        8) clear; show_config; read -n 1 -s -r -p "按任意键返回..." ;;
        9) clear; diagnose; read -n 1 -s -r -p "按任意键返回..." ;;
        10) clear; uninstall; read -n 1 -s -r -p "按任意键返回..." ;;
        0) clear; exit 0 ;;
    esac
}

# --- 主循环 ---
while true; do
    main_menu
done
