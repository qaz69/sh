#!/bin/bash

# ================== 界面配色设置 ==================
export NEWT_COLORS='
root=,blue
window=,lightgray
border=black,lightgray
shadow=black,gray
button=black,lightgray
actbutton=blue,lightgray
compactbutton=black,lightgray
title=black,lightgray
listbox=,lightgray
actlistbox=blue,lightgray
'

# ================== 常量定义 ==================
SHOES_BIN="/usr/local/bin/shoes"
COPY_CERT_BIN="/usr/local/bin/copy-cert"
SHOES_CONF_DIR="/etc/shoes"
SHOES_CONF_FILE="${SHOES_CONF_DIR}/config.yaml"
SHOES_LINK_FILE="${SHOES_CONF_DIR}/config.txt"
SYSTEMD_FILE="/etc/systemd/system/shoes.service"
TMP_DIR="/tmp/shoesdl"

# 颜色代码 (Ubuntu neofetch 风格: 红色警告/错误, 亮黄色标签/提示, 白色内容)
RED='\e[0;31m'
GREEN='\e[0;37m'
YELLOW='\e[1;33m'
CYAN='\e[1;33m'
RESET='\e[0m'

# ================== 核心检查 ==================
require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}必须使用 root 权限运行此脚本！${RESET}"
        exit 1
    fi
}

check_dependencies() {
    if ! command -v whiptail &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y whiptail
        elif command -v yum &> /dev/null; then
            yum install -y newt
        else
             echo -e "${RED}无法自动安装 whiptail，请手动安装。${RESET}"
             exit 1
        fi
    fi
    # 检查 curl，用于获取公网IP
    if ! command -v curl &> /dev/null; then
        if command -v apt-get &> /dev/null; then apt-get install -y curl; else yum install -y curl; fi
    fi
}

# ================== 功能函数 ==================

download_copy_cert() {
    echo -e "${GREEN}正在获取 copy-cert...${RESET}"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  FILE_ARCH="amd64" ;;
        aarch64|arm64) FILE_ARCH="arm64" ;;
        *) echo -e "${RED}不支持的架构: $ARCH${RESET}"; exit 1 ;;
    esac

    LATEST_VER=$(curl -s https://api.github.com/repos/virusdefender/copy-cert/releases/latest | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')
    
    DOWNLOAD_URL="https://github.com/virusdefender/copy-cert/releases/download/v${LATEST_VER}/copy-cert-linux-${FILE_ARCH}"
    
    if ! wget -O "${COPY_CERT_BIN}" "$DOWNLOAD_URL"; then
        echo -e "${RED}copy-cert 下载失败！${RESET}"
        exit 1
    fi
    
    chmod +x "${COPY_CERT_BIN}"
}

download_shoes() {
    GLIBC_VERSION=$(ldd --version | head -n1 | awk '{print $NF}')
    GLIBC_MINOR=$(echo "$GLIBC_VERSION" | cut -d. -f2)
    ARCH=$(uname -m)
    
    LATEST_VER=$(curl -s https://api.github.com/repos/cfal/shoes/releases/latest | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')
    
    if [[ "$ARCH" == "x86_64" ]]; then
        FILE_TYPE="x86_64-unknown-linux-gnu.tar.gz"
        [[ $GLIBC_MINOR -lt 38 ]] && FILE_TYPE="x86_64-unknown-linux-musl.tar.gz"
    else
        FILE_TYPE="aarch64-unknown-linux-gnu.tar.gz"
        [[ $GLIBC_MINOR -lt 38 ]] && FILE_TYPE="aarch64-unknown-linux-musl.tar.gz"
    fi

    mkdir -p "${TMP_DIR}" && cd "${TMP_DIR}" || exit 1
    if ! wget -O shoes.tar.gz "https://github.com/cfal/shoes/releases/download/v${LATEST_VER}/shoes-${FILE_TYPE}"; then
        echo -e "${RED}Shoes 下载失败！${RESET}"
        exit 1
    fi
    tar -xzf shoes.tar.gz
    mv shoes "${SHOES_BIN}" && chmod +x "${SHOES_BIN}"
    cd - > /dev/null
    rm -rf "${TMP_DIR}"
}

copy_certificate() {
    local domain=$1
    mkdir -p "${SHOES_CONF_DIR}"
    if ! cd /tmp; then
        echo -e "${RED}无法切换到 /tmp 目录${RESET}"
        exit 1
    fi
    
    if ! "${COPY_CERT_BIN}" "${domain}:443"; then
        echo -e "${RED}证书复制失败！${RESET}"
        exit 1
    fi
    
    CERT_DIR=$(find /tmp/certs -maxdepth 1 -type d -name "20*" | sort -r | head -n1)
    
    if [[ -z "$CERT_DIR" ]] || [[ ! -f "${CERT_DIR}/bundle.crt" ]] || [[ ! -f "${CERT_DIR}/bundle.key" ]]; then
        echo -e "${RED}证书文件生成失败！${RESET}"
        exit 1
    fi
    
    mv "${CERT_DIR}/bundle.crt" "${SHOES_CONF_DIR}/cert.pem"
    mv "${CERT_DIR}/bundle.key" "${SHOES_CONF_DIR}/key.pem"
    chmod 600 "${SHOES_CONF_DIR}/cert.pem"
    chmod 600 "${SHOES_CONF_DIR}/key.pem"
    
    rm -rf /tmp/certs
}

# ================== 动作函数 ==================

install_shoes() {
    # 检查是否已安装
    if [[ -f "$SHOES_BIN" ]] && [[ -f "$SHOES_CONF_FILE" ]]; then
        whiptail --title "重复安装检查" --yesno "检测到 Shoes 已经安装。\n\n是否重新安装？\n(选择'是'将覆盖现有配置和证书)" 10 60
        if [[ $? -ne 0 ]]; then
            return # 用户选择否或取消，返回主菜单
        fi
    fi

    clear
    download_shoes
    download_copy_cert
    
    DOMAIN=$(whiptail --title "配置" --inputbox "输入伪装域名 (用于生成证书)" 10 60 "bing.com" 3>&1 1>&2 2>&3)
    # [修复] 严格检查退出状态，如果点击取消(代码1)或Esc(代码255)，则返回
    if [[ $? -ne 0 ]]; then
        return
    fi
    
    [[ -z "$DOMAIN" ]] && DOMAIN="bing.com"
    
    copy_certificate "$DOMAIN"
    
    # 生成随机配置
    UUID=$(cat /proc/sys/kernel/random/uuid)
    ANYTLS_PASS=$(openssl rand -hex 16)
    TUIC_PORT=$(shuf -i 20000-60000 -n 1)
    ANYTLS_PORT=$(shuf -i 20000-60000 -n 1)

    cat > "${SHOES_CONF_FILE}" <<EOF
# TUIC 协议配置
- address: "0.0.0.0:${TUIC_PORT}"
  transport: quic
  quic_settings:
    cert: ${SHOES_CONF_DIR}/cert.pem
    key: ${SHOES_CONF_DIR}/key.pem
    alpn_protocols:
      - h3
  protocol:
    type: tuic
    uuid: ${UUID}
    password: ${ANYTLS_PASS}

# AnyTLS 协议配置  
- address: "0.0.0.0:${ANYTLS_PORT}"
  protocol:
    type: tls
    tls_targets:
      "${DOMAIN}":
        cert: ${SHOES_CONF_DIR}/cert.pem
        key: ${SHOES_CONF_DIR}/key.pem
        protocol:
          type: anytls
          users:
            - name: user1
              password: ${ANYTLS_PASS}
          udp_enabled: true
EOF

    chmod 600 "${SHOES_CONF_FILE}"

    cat > "${SYSTEMD_FILE}" <<EOF
[Unit]
Description=Shoes Service
After=network.target
[Service]
ExecStart=${SHOES_BIN} ${SHOES_CONF_FILE}
Restart=always
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now shoes
    
    echo -e "${GREEN}正在获取公网 IP...${RESET}"
    
    # 获取 IPv4
    IPV4=$(curl -s4m5 https://api.ipify.org || curl -s4m5 https://ipv4.icanhazip.com)
    if [[ -z "$IPV4" ]]; then
        echo -e "${YELLOW}警告: 无法获取公网 IPv4 地址${RESET}"
        IPV4="YOUR_PUBLIC_IPV4"
    fi

    # 获取 IPv6
    IPV6=$(curl -s6m5 https://api64.ipify.org || curl -s6m5 https://ipv6.icanhazip.com)
    
    # 构建链接变量
    TUIC_IPV4="tuic://${UUID}:${ANYTLS_PASS}@${IPV4}:${TUIC_PORT}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=${DOMAIN}&allow_insecure=1#TUIC-IPv4"
    ANYTLS_IPV4="anytls://${ANYTLS_PASS}@${IPV4}:${ANYTLS_PORT}?sni=${DOMAIN}&allow_insecure=1#AnyTLS-IPv4"

    # [修复] 动态生成配置文件内容，仅当 IPv6 存在时才写入 IPv6 链接
    echo "=== Shoes 代理服务配置 ===" > "${SHOES_LINK_FILE}"
    echo "" >> "${SHOES_LINK_FILE}"
    echo "域名: ${DOMAIN}" >> "${SHOES_LINK_FILE}"
    echo "UUID: ${UUID}" >> "${SHOES_LINK_FILE}"
    echo "密码: ${ANYTLS_PASS}" >> "${SHOES_LINK_FILE}"
    echo "" >> "${SHOES_LINK_FILE}"
    
    echo "========== TUIC 协议 ==========" >> "${SHOES_LINK_FILE}"
    echo "" >> "${SHOES_LINK_FILE}"
    echo "IPv4 分享链接:" >> "${SHOES_LINK_FILE}"
    echo "${TUIC_IPV4}" >> "${SHOES_LINK_FILE}"
    echo "" >> "${SHOES_LINK_FILE}"

    if [[ -n "$IPV6" ]]; then
        TUIC_IPV6="tuic://${UUID}:${ANYTLS_PASS}@[${IPV6}]:${TUIC_PORT}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=${DOMAIN}&allow_insecure=1#TUIC-IPv6"
        echo "IPv6 分享链接:" >> "${SHOES_LINK_FILE}"
        echo "${TUIC_IPV6}" >> "${SHOES_LINK_FILE}"
        echo "" >> "${SHOES_LINK_FILE}"
    fi

    echo "========== AnyTLS 协议 ==========" >> "${SHOES_LINK_FILE}"
    echo "" >> "${SHOES_LINK_FILE}"
    echo "IPv4 分享链接:" >> "${SHOES_LINK_FILE}"
    echo "${ANYTLS_IPV4}" >> "${SHOES_LINK_FILE}"
    echo "" >> "${SHOES_LINK_FILE}"

    if [[ -n "$IPV6" ]]; then
        ANYTLS_IPV6="anytls://${ANYTLS_PASS}@[${IPV6}]:${ANYTLS_PORT}?sni=${DOMAIN}&allow_insecure=1#AnyTLS-IPv6"
        echo "IPv6 分享链接:" >> "${SHOES_LINK_FILE}"
        echo "${ANYTLS_IPV6}" >> "${SHOES_LINK_FILE}"
        echo "" >> "${SHOES_LINK_FILE}"
    fi

    chmod 600 "${SHOES_LINK_FILE}"
    
    # 直接在终端打印
    clear
    echo -e "${GREEN}================ 安装成功 =================${RESET}"
    echo -e "${CYAN}配置文件路径: ${SHOES_LINK_FILE}${RESET}"
    echo ""
    cat "${SHOES_LINK_FILE}"
    echo ""
    echo -e "${GREEN}===========================================${RESET}"
    echo ""
    read -p "按回车键返回主菜单..." dummy
}

# ================== 菜单循环 ==================
require_root
check_dependencies

while true; do
    CHOICE=$(whiptail --title "Shoes 管理脚本" --menu "请选择操作:" 16 60 8 \
        "1" "安装 Shoes" \
        "2" "卸载 Shoes" \
        "3" "启动服务" \
        "4" "停止服务" \
        "5" "重启服务" \
        "6" "查看配置" \
        "7" "查看日志" \
        "0" "退出" 3>&1 1>&2 2>&3)
    
    # [修复] 检查主菜单的退出状态
    if [[ $? -ne 0 ]]; then
        exit 0
    fi

    case "$CHOICE" in
        1) install_shoes ;;
        2) 
           systemctl stop shoes
           rm -rf "${SHOES_CONF_DIR}" "${SHOES_BIN}" "${COPY_CERT_BIN}" "${SYSTEMD_FILE}"
           systemctl daemon-reload
           whiptail --msgbox "已卸载" 8 40 
           ;;
        3) 
           systemctl start shoes 
           whiptail --msgbox "服务已尝试启动" 8 40 
           ;;
        4) 
           systemctl stop shoes 
           whiptail --msgbox "服务已停止" 8 40 
           ;;
        5) 
           systemctl restart shoes 
           whiptail --msgbox "服务已重启" 8 40 
           ;;
        6) 
            if [[ -f "${SHOES_LINK_FILE}" ]]; then
                clear
                echo -e "${GREEN}================ 当前配置 =================${RESET}"
                cat "${SHOES_LINK_FILE}"
                echo -e "${GREEN}===========================================${RESET}"
                echo ""
                read -p "按回车键返回主菜单..." dummy
            else
                whiptail --msgbox "未找到配置，请先安装。" 8 40
            fi
            ;;
        7) clear; journalctl -u shoes -f ;;
        0) exit 0 ;;
        *) exit 0 ;;
    esac
done
