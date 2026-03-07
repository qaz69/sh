#!/bin/bash

# =========================================================
#  Sing-Box 一键管理脚本 - TUI 美化版
#  版本: 4.0 - 含 Reality 协议 + 自动偷邻居证书
# =========================================================

export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# --- 检查 whiptail ---
if ! command -v whiptail &> /dev/null; then
    echo "未检测到 whiptail，正在安装..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y whiptail
    elif command -v yum &> /dev/null; then
        yum install -y newt
    fi
fi

# --- TUI 颜色配置 ---
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

# --- 颜色定义 ---
RED='\e[0;31m'
GREEN='\e[0;37m'
YELLOW='\e[1;33m'
BLUE='\e[1;33m'
CYAN='\e[1;33m'
WHITE='\e[0;37m'
NC='\e[0m'
BOLD='\033[1m'
DIM='\033[2m'
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

# --- 工具函数 ---
print_banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════════╗
║                      Sing-Box 管理脚本 v4.0                         ║
║              TUIC + AnyTLS + Reality 三协议版                        ║
╚════════════════════════════════════════════════════════════════════╝
EOF
}

print_line() {
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
}

print_double_line() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
}

info()    { echo -e "${BLUE}[信息]${NC} $1"; }
success() { echo -e "${GREEN}[成功]${NC} $1"; }
warn()    { echo -e "${YELLOW}[警告]${NC} $1"; }
error()   { echo -e "${RED}[错误]${NC} $1"; exit 1; }

get_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)          BIN_ARCH="amd64"; FILE_ARCH="amd64" ;;
        aarch64|arm64)   BIN_ARCH="arm64"; FILE_ARCH="arm64" ;;
        armv7l)          BIN_ARCH="armv7"; FILE_ARCH="armv7" ;;
        *)               BIN_ARCH="amd64"; FILE_ARCH="amd64" ;;
    esac
}

# --- 智能IP检测 ---
detect_network() {
    info "正在检测网络配置..."
    MAIN_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    IP4=$(ip -4 addr show $MAIN_IFACE 2>/dev/null | grep inet | grep -v 127.0.0.1 | awk '{print $2}' | cut -d/ -f1 | head -n1)
    if [[ -z "$IP4" ]]; then IP4=$(curl -s4 --max-time 5 https://api.ipify.org 2>/dev/null || echo ""); fi
    IP6=$(ip -6 addr show $MAIN_IFACE 2>/dev/null | grep "scope global" | awk '{print $2}' | cut -d/ -f1 | head -n1)
    if [[ -z "$IP6" ]]; then IP6=$(curl -s6 --max-time 5 https://api64.ipify.org 2>/dev/null || echo ""); fi

    HAS_IPV4=false; HAS_IPV6=false
    [[ -n "$IP4" ]] && HAS_IPV4=true
    [[ -n "$IP6" ]] && HAS_IPV6=true

    echo -e "\n${BOLD}网络环境检测结果:${NC}"
    print_line
    echo -e "  主网卡: ${BLUE}$MAIN_IFACE${NC}"
    if $HAS_IPV4; then echo -e "  IPv4 : ${CYAN}$IP4 ✓${NC}"; else echo -e "  IPv4 : ${DIM}未配置${NC}"; fi
    if $HAS_IPV6; then echo -e "  IPv6 : ${CYAN}$IP6 ✓${NC}"; else echo -e "  IPv6 : ${DIM}未配置${NC}"; fi
    print_line
}

# --- 防火墙配置 ---
configure_firewall() {
    local port=$1
    local proto=${2:-udp}
    info "配置防火墙规则 (端口: ${YELLOW}$port/$proto${NC})..."
    if command -v ufw &> /dev/null; then ufw allow $port/$proto >/dev/null 2>&1; fi
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=$port/$proto >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
    if command -v iptables &> /dev/null; then
        if [[ "$proto" == "tcp" ]]; then
            iptables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
        else
            iptables -I INPUT -p udp --dport $port -j ACCEPT 2>/dev/null
        fi
    fi
}

# =========================================================
#  自动偷邻居网站 (用于 Reality SNI)
#  搜索范围: 单IP + C段 (/24) 全部254个IP并发查询
# =========================================================
find_neighbor_domains() {
    local my_ip="$1"
    local c_segment
    c_segment=$(echo "$my_ip" | cut -d'.' -f1-3)
    local all_results=""
    local tmp_dir
    tmp_dir=$(mktemp -d)

    # --- 来源1: rapiddns.io 查单IP ---
    info "查询单IP反解域名 ($my_ip)..." >&2
    curl -s --max-time 10 \
        "https://rapiddns.io/sameip/$my_ip?full=1" 2>/dev/null | \
        grep -oP '(?<=<td>)[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?=</td>)' | \
        grep -v "^$my_ip$" > "$tmp_dir/r1.txt" 2>/dev/null

    # --- 来源2: hackertarget + rapiddns 并发扫C段全部IP ---
    info "并发扫描C段 ${c_segment}.0/24 ..." >&2
    for i in $(seq 1 254); do
        local scan_ip="${c_segment}.$i"
        (
            # hackertarget
            curl -s --max-time 4 \
                "https://api.hackertarget.com/reverseiplookup/?q=$scan_ip" 2>/dev/null | \
                grep -v "^error\|^API\|^No \|^$" > "$tmp_dir/ht_$i.txt" 2>/dev/null
            # rapiddns
            curl -s --max-time 5 \
                "https://rapiddns.io/sameip/$scan_ip?full=1" 2>/dev/null | \
                grep -oP '(?<=<td>)[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?=</td>)' | \
                grep -v "^$scan_ip$" > "$tmp_dir/rd_$i.txt" 2>/dev/null
        ) &
        # 每30个并发等一下，避免限速
        if (( i % 30 == 0 )); then
            wait
            echo -ne "  已扫描: ${i}/254 个IP\r" >&2
        fi
    done
    wait
    echo -e "  已扫描: 254/254 个IP - 完成" >&2

    # 合并所有结果，去重过滤
    local all_domains
    all_domains=$(cat "$tmp_dir"/*.txt 2>/dev/null | \
        grep -v "^$" | \
        grep -v "^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$" | \
        grep '\.' | \
        sort -u | head -100)
    rm -rf "$tmp_dir"

    if [[ -z "$all_domains" ]]; then
        echo ""
        return
    fi

    echo "$all_domains"
}

test_reality_compatible() {
    # 测试域名是否支持 TLSv1.3 + X25519，适合作为 Reality 目标
    local domain="$1"
    local timeout=5

    # 检查域名格式
    [[ "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$ ]] || return 1

    # 测试TLS连接，获取协议版本
    local tls_info
    tls_info=$(echo | timeout $timeout openssl s_client \
        -connect "$domain:443" \
        -servername "$domain" \
        -tls1_3 2>/dev/null)

    # 检查是否成功握手（openssl输出格式: "New, TLSv1.3, Cipher is ..."）
    echo "$tls_info" | grep -qiE "TLSv1\.3" || return 1

    # X25519检测（部分服务器不输出，不强制要求）
    # echo "$tls_info" | grep -qiE "X25519|ECDH" || return 1

    return 0
}

auto_find_reality_sni() {
    detect_network

    # 内网IP判断函数
    is_private_ip() {
        local ip="$1"
        [[ "$ip" =~ ^10\. ]] && return 0
        [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 0
        [[ "$ip" =~ ^192\.168\. ]] && return 0
        return 1
    }

    # 强制通过外部接口获取真实公网IP（避免拿到内网地址）
    local my_ip
    my_ip=$(curl -s4 --max-time 5 https://api.ipify.org 2>/dev/null || \
            curl -s4 --max-time 5 https://ip.sb 2>/dev/null || \
            curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null || echo "")

    # 如果还是内网地址或为空，提示手动输入
    if [[ -z "$my_ip" ]] || is_private_ip "$my_ip"; then
        warn "无法获取公网IP（检测到: ${my_ip:-无}），请手动输入SNI域名"
        echo -ne "${BLUE}请输入 Reality SNI 域名 [默认: www.microsoft.com]${NC}: "
        read -r manual_sni
        REALITY_SNI=${manual_sni:-www.microsoft.com}
        return
    fi

    echo ""
    info "公网IP: ${YELLOW}$my_ip${NC}"
    info "正在搜索邻居网站..."
    echo ""

    local candidates
    candidates=$(find_neighbor_domains "$my_ip")

    if [[ -z "$candidates" ]]; then
        warn "未找到邻居网站，使用默认域名"
        REALITY_SNI="www.microsoft.com"
        return
    fi

    info "找到候选域名，正在逐一测试 TLSv1.3 兼容性..."
    print_line

    local valid_domains=()
    local count=0

    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        [[ $count -ge 15 ]] && break  # 最多测试15个

        echo -ne "  测试 ${CYAN}$domain${NC} ... "

        if test_reality_compatible "$domain"; then
            echo -e "${GREEN}✓ 可用${NC}"
            valid_domains+=("$domain")
        else
            echo -e "${DIM}✗ 不支持${NC}"
        fi
        ((count++))
    done <<< "$candidates"

    print_line
    echo ""

    if [[ ${#valid_domains[@]} -eq 0 ]]; then
        warn "邻居网站均不支持 TLSv1.3，使用备选域名"
        # 备选测试
        for fallback in "www.microsoft.com" "addons.mozilla.org" "www.cloudflare.com"; do
            echo -ne "  测试备选 ${CYAN}$fallback${NC} ... "
            if test_reality_compatible "$fallback"; then
                echo -e "${GREEN}✓ 可用${NC}"
                valid_domains+=("$fallback")
                break
            else
                echo -e "${DIM}✗${NC}"
            fi
        done
    fi

    if [[ ${#valid_domains[@]} -eq 0 ]]; then
        warn "所有候选均失败，手动输入"
        echo -ne "${BLUE}请输入 Reality SNI 域名${NC}: "
        read -r manual_sni
        REALITY_SNI=${manual_sni:-www.microsoft.com}
        return
    fi

    # 让用户从有效列表中选择
    echo -e "${BOLD}可用的邻居网站:${NC}"
    print_line
    for i in "${!valid_domains[@]}"; do
        echo -e "  ${CYAN}$((i+1))${NC}. ${valid_domains[$i]}"
    done
    echo -e "  ${CYAN}0${NC}. 手动输入"
    print_line
    echo -ne "${BLUE}请选择 [0-${#valid_domains[@]}, 默认: 1]${NC}: "
    read -r sni_choice
    sni_choice=${sni_choice:-1}

    if [[ "$sni_choice" == "0" ]]; then
        echo -ne "${BLUE}请输入 SNI 域名${NC}: "
        read -r manual_sni
        REALITY_SNI=${manual_sni:-www.microsoft.com}
    elif [[ "$sni_choice" =~ ^[0-9]+$ ]] && (( sni_choice >= 1 && sni_choice <= ${#valid_domains[@]} )); then
        REALITY_SNI="${valid_domains[$((sni_choice-1))]}"
        success "已选择邻居: ${GREEN}$REALITY_SNI${NC}"
    else
        REALITY_SNI="${valid_domains[0]}"
        success "已自动选择: ${GREEN}$REALITY_SNI${NC}"
    fi
}

# =========================================================
#  生成 Reality 密钥对
# =========================================================
generate_reality_keys() {
    info "生成 Reality 密钥对..."
    local key_output
    key_output=$("$BIN_PATH" generate reality-keypair 2>/dev/null)

    if [[ -z "$key_output" ]]; then
        error "Reality 密钥生成失败，请确认 sing-box 版本支持 Reality"
    fi

    REALITY_PRIVATE_KEY=$(echo "$key_output" | grep -i "PrivateKey\|private" | awk '{print $2}')
    REALITY_PUBLIC_KEY=$(echo "$key_output" | grep -i "PublicKey\|public" | awk '{print $2}')

    if [[ -z "$REALITY_PRIVATE_KEY" || -z "$REALITY_PUBLIC_KEY" ]]; then
        error "无法解析 Reality 密钥，输出: $key_output"
    fi

    success "Reality 密钥对生成完成"
}

# =========================================================
#  TLS 证书配置 (用于 TUIC + AnyTLS)
# =========================================================
configure_tls() {
    mkdir -p "$CONF_DIR" && cd "$CONF_DIR"
    print_double_line
    echo -e "${BOLD}         TLS 证书配置 (TUIC / AnyTLS 使用)${NC}"
    print_double_line
    echo -e "  ${CYAN}1${NC}. 复制邻居网站证书 ${DIM}(推荐，伪装效果好)${NC}"
    echo -e "  ${CYAN}2${NC}. 生成自签名证书   ${DIM}(快速)${NC}"
    print_line
    echo -ne "${BLUE}请选择 [1-2, 默认: 1]${NC}: "
    read -r cert_choice
    cert_choice=${cert_choice:-1}
    echo ""

    if [ "$cert_choice" == "1" ]; then
        echo -ne "${BLUE}请输入要复制证书的域名 [默认: bing.com]${NC}: "
        read -r target_domain
        target_domain=${target_domain:-bing.com}
        get_arch

        info "下载证书复制工具..."
        # arm64 没有对应二进制，回退 amd64
        local dl_arch="$BIN_ARCH"
        [[ "$dl_arch" == "arm64" ]] && dl_arch="amd64"
        local cert_url="https://github.com/virusdefender/copy-cert/releases/latest/download/copy-cert-linux-$dl_arch"

        # 修复: 去掉 -f，使用 -L --max-time 30 避免重定向误判失败
        if curl -L --max-time 30 -o /usr/local/bin/copy-cert "$cert_url" 2>/dev/null; then
            chmod +x /usr/local/bin/copy-cert
            success "工具下载成功"
        else
            warn "工具下载失败，降级为自签名证书"
            cert_choice="2"
        fi

        if [ "$cert_choice" == "1" ]; then
            info "正在从 ${YELLOW}$target_domain${NC} 抓取证书..."
            rm -rf certs/
            if /usr/local/bin/copy-cert "$target_domain:443" > /tmp/copy_cert.log 2>&1; then
                local sub_dir=$(ls -dt certs/* 2>/dev/null | head -n 1)
                if [[ -n "$sub_dir" ]]; then
                    local tmp_crt=$(ls "$sub_dir"/*.{crt,pem} 2>/dev/null | head -n 1)
                    local tmp_key=$(ls "$sub_dir"/*.key 2>/dev/null | head -n 1)
                    if [[ -n "$tmp_crt" && -n "$tmp_key" ]]; then
                        cp -f "$tmp_crt" "$CERT_PATH"
                        cp -f "$tmp_key" "$KEY_PATH"
                        rm -rf certs/
                        FINAL_DOMAIN=$target_domain
                        success "证书复制成功: ${GREEN}$target_domain${NC}"
                        return 0
                    fi
                fi
            fi
            warn "证书抓取失败，自动降级为自签名证书"
            cert_choice="2"
        fi
    fi

    if [ "$cert_choice" == "2" ]; then
        FINAL_DOMAIN="bing.com"
        info "生成自签名证书..."
        openssl req -x509 -nodes -newkey rsa:2048 \
            -keyout "$KEY_PATH" -out "$CERT_PATH" \
            -days 3650 -subj "/CN=$FINAL_DOMAIN" >/dev/null 2>&1
        success "自签名证书已生成 (域名: ${YELLOW}$FINAL_DOMAIN${NC})"
    fi
}

# =========================================================
#  安装主程序
# =========================================================
install_singbox() {
    [[ $EUID -ne 0 ]] && error "请使用 root 权限运行此脚本"
    print_banner
    echo -e "${BOLD}${BG_CYAN}                  开始安装 Sing-Box (三协议版)                ${NC}\n"

    info "安装系统依赖..."
    if command -v apt-get &> /dev/null; then
        apt-get update -qq && apt-get install -y curl jq openssl net-tools tar wget iproute2 >/dev/null 2>&1
    elif command -v yum &> /dev/null; then
        yum install -y curl jq openssl net-tools tar wget iproute >/dev/null 2>&1
    fi
    success "依赖安装完成"
    echo ""

    # 下载 Sing-Box
    get_arch
    info "下载 Sing-Box ${YELLOW}v$VERSION${NC}..."
    DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v$VERSION/sing-box-$VERSION-linux-$FILE_ARCH.tar.gz"
    if wget -q --show-progress -O /tmp/singbox.tar.gz "$DOWNLOAD_URL"; then
        tar -xzf /tmp/singbox.tar.gz -C /tmp 2>/dev/null
        mv /tmp/sing-box-*/sing-box "$BIN_PATH" 2>/dev/null
        chmod +x "$BIN_PATH"
        rm -rf /tmp/singbox* /tmp/sing-box-*
        success "Sing-Box 主程序安装完成"
    else
        error "下载失败，请检查网络连接"
    fi

    # 配置 TLS 证书 (TUIC / AnyTLS 用)
    echo ""
    configure_tls

    # 自动寻找邻居网站作为 Reality SNI
    echo ""
    print_double_line
    echo -e "${BOLD}         Reality 协议配置 - 自动寻找邻居网站${NC}"
    print_double_line
    auto_find_reality_sni

    # 生成 Reality 密钥对
    echo ""
    generate_reality_keys

    # 生成端口和认证信息
    echo ""
    info "生成配置参数..."
    TUIC_PORT=$((RANDOM % 50000 + 10000))
    ANY_PORT=$((RANDOM % 50000 + 10000))
    REALITY_PORT=$((RANDOM % 50000 + 10000))
    UUID=$(cat /proc/sys/kernel/random/uuid)
    PASS=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)
    SHORT_ID=$(openssl rand -hex 4)

    configure_firewall $TUIC_PORT udp
    configure_firewall $ANY_PORT tcp
    configure_firewall $REALITY_PORT tcp

    # 写入配置文件 (三协议)
    info "生成服务配置..."
    cat > "$CONF_FILE" <<EOF
{
  "log": { "level": "info", "timestamp": true, "output": "$LOG_FILE" },
  "inbounds": [
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": $TUIC_PORT,
      "users": [ { "uuid": "$UUID", "password": "$PASS" } ],
      "congestion_control": "bbr",
      "auth_timeout": "3s",
      "zero_rtt_handshake": false,
      "heartbeat": "10s",
      "tls": {
        "enabled": true,
        "server_name": "$FINAL_DOMAIN",
        "alpn": ["h3"],
        "certificate_path": "$CERT_PATH",
        "key_path": "$KEY_PATH"
      }
    },
    {
      "type": "anytls",
      "tag": "anytls-in",
      "listen": "::",
      "listen_port": $ANY_PORT,
      "users": [ { "name": "user", "password": "$PASS" } ],
      "tls": {
        "enabled": true,
        "server_name": "$FINAL_DOMAIN",
        "alpn": ["h3", "h2", "http/1.1"],
        "certificate_path": "$CERT_PATH",
        "key_path": "$KEY_PATH"
      }
    },
    {
      "type": "vless",
      "tag": "reality-in",
      "listen": "::",
      "listen_port": $REALITY_PORT,
      "users": [ { "uuid": "$UUID", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SNI",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$REALITY_SNI",
            "server_port": 443
          },
          "private_key": "$REALITY_PRIVATE_KEY",
          "short_id": ["$SHORT_ID"]
        }
      }
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
REALITY_SNI=$REALITY_SNI
REALITY_PUBLIC_KEY=$REALITY_PUBLIC_KEY
REALITY_SHORT_ID=$SHORT_ID
TUIC_PORT=$TUIC_PORT
ANY_PORT=$ANY_PORT
REALITY_PORT=$REALITY_PORT
UUID=$UUID
PASSWORD=$PASS
INSTALL_TIME=$(date '+%Y-%m-%d %H:%M:%S')
EOF

    if systemctl is-active --quiet sing-box; then
        echo ""
        success "✨ Sing-Box 三协议版安装成功并已启动！"
        echo ""
        sleep 1
        show_links
    else
        echo ""
        error "服务启动失败，请运行 '系统诊断' 查看详情"
    fi
}

# =========================================================
#  查看连接信息
# =========================================================
show_links() {
    [[ ! -f "$CONF_FILE" ]] && error "未找到配置文件，请先安装"
    source "$INFO_PATH" 2>/dev/null
    detect_network

    local tuic_p=$(jq -r '.inbounds[] | select(.type=="tuic") | .listen_port' "$CONF_FILE")
    local any_p=$(jq -r '.inbounds[] | select(.type=="anytls") | .listen_port' "$CONF_FILE")
    local reality_p=$(jq -r '.inbounds[] | select(.type=="vless") | .listen_port' "$CONF_FILE")
    local uuid=$(jq -r '.inbounds[] | select(.type=="tuic") | .users[0].uuid' "$CONF_FILE")
    local pass=$(jq -r '.inbounds[] | select(.type=="tuic") | .users[0].password' "$CONF_FILE")
    local pub_key="$REALITY_PUBLIC_KEY"
    local short_id="$REALITY_SHORT_ID"
    local rsni="$REALITY_SNI"

    print_banner
    print_double_line
    echo -e "${BOLD}                    节点连接信息${NC}"
    print_double_line

    print_node_links() {
        local label="$1"
        local ip="$2"
        local bracket_l="" bracket_r=""
        [[ "$label" == *"IPv6"* ]] && bracket_l="[" && bracket_r="]"

        echo -e "\n${BOLD}━━━ $label ━━━${NC}\n"

        echo -e "${BOLD}[TUIC]${NC}"
        echo -e "${CYAN}tuic://$uuid:$pass@${bracket_l}${ip}${bracket_r}:$tuic_p?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=$DOMAIN&allow_insecure=1#TUIC-$label${NC}"

        echo -e "\n${BOLD}[AnyTLS]${NC}"
        echo -e "${CYAN}anytls://$pass@${bracket_l}${ip}${bracket_r}:$any_p?sni=$DOMAIN&allow_insecure=1#AnyTLS-$label${NC}"

        echo -e "\n${BOLD}[Reality/VLESS]${NC}"
        echo -e "${CYAN}vless://$uuid@${bracket_l}${ip}${bracket_r}:$reality_p?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$rsni&fp=chrome&pbk=$pub_key&sid=$short_id&type=tcp&headerType=none#Reality-$label${NC}"
    }

    local has_output=false
    if $HAS_IPV4 && [[ -n "$IP4" ]]; then
        print_node_links "IPv4" "$IP4"
        has_output=true
    fi
    if $HAS_IPV6 && [[ -n "$IP6" ]]; then
        print_node_links "IPv6" "$IP6"
        has_output=true
    fi

    if ! $has_output; then warn "未检测到有效的公网IP地址"; fi

    echo ""
    print_double_line
    echo -e "${BOLD}Reality 邻居网站:${NC} ${GREEN}$rsni${NC}"
    echo -e "${BOLD}Reality 公钥:${NC}     ${YELLOW}$pub_key${NC}"
    echo -e "${BOLD}Reality Short ID:${NC} ${YELLOW}$short_id${NC}"
    print_double_line
}

# --- 服务状态 ---
show_status() {
    print_banner
    print_double_line
    echo -e "${BOLD}                    服务运行状态${NC}"
    print_double_line
    if systemctl is-active --quiet sing-box; then
        echo -e "  服务状态   : ${CYAN}● 运行中${NC}"
    else
        echo -e "  服务状态   : ${RED}● 已停止${NC}"
    fi
    if [[ -f "$CONF_FILE" ]]; then
        local tuic_p=$(jq -r '.inbounds[] | select(.type=="tuic") | .listen_port' "$CONF_FILE" 2>/dev/null)
        local any_p=$(jq -r '.inbounds[] | select(.type=="anytls") | .listen_port' "$CONF_FILE" 2>/dev/null)
        local reality_p=$(jq -r '.inbounds[] | select(.type=="vless") | .listen_port' "$CONF_FILE" 2>/dev/null)
        echo -e "  TUIC 端口  : ${BLUE}$tuic_p${NC} $(ss -ulnp | grep -q ":$tuic_p " && echo "${CYAN}[监听]${NC}" || echo "${RED}[未监听]${NC}")"
        echo -e "  AnyTLS端口 : ${BLUE}$any_p${NC} $(ss -tlnp | grep -q ":$any_p " && echo "${CYAN}[监听]${NC}" || echo "${RED}[未监听]${NC}")"
        echo -e "  Reality端口: ${BLUE}$reality_p${NC} $(ss -tlnp | grep -q ":$reality_p " && echo "${CYAN}[监听]${NC}" || echo "${RED}[未监听]${NC}")"
    fi
    detect_network
    if $HAS_IPV4; then echo -e "  公网IPv4   : ${CYAN}$IP4${NC}"; else echo -e "  公网IPv4   : ${DIM}无${NC}"; fi
    if $HAS_IPV6; then echo -e "  公网IPv6   : ${CYAN}$IP6${NC}"; else echo -e "  公网IPv6   : ${DIM}无${NC}"; fi
    if [[ -f "$INFO_PATH" ]]; then
        source "$INFO_PATH"
        echo -e "  Reality SNI: ${YELLOW}${REALITY_SNI:-未知}${NC}"
        echo -e "  安装时间   : ${YELLOW}${INSTALL_TIME:-未知}${NC}"
    fi
    print_double_line
    echo ""
    systemctl status sing-box --no-pager -l
}

# --- 查看日志 ---
show_logs() {
    print_banner
    echo -e "${BOLD}${BG_CYAN}                    实时日志监控                        ${NC}\n"
    echo -e "${DIM}按 Ctrl+C 退出日志查看${NC}\n"
    print_line
    if [[ -f "$LOG_FILE" ]]; then tail -f "$LOG_FILE"; else journalctl -u sing-box -f -n 100; fi
}

# --- 系统诊断 ---
diagnose() {
    print_banner
    print_double_line
    echo -e "${BOLD}                    系统诊断工具${NC}"
    print_double_line
    echo -e "\n${BLUE}[1] 服务状态检查${NC}"; print_line
    systemctl status sing-box --no-pager
    echo -e "\n${BLUE}[2] 配置文件验证${NC}"; print_line
    if "$BIN_PATH" check -c "$CONF_FILE" 2>&1; then
        success "配置文件语法正确"
    else
        warn "配置文件存在错误"
    fi
    echo -e "\n${BLUE}[3] 端口监听状态${NC}"; print_line
    ss -tlnp | grep -E "sing|$(jq -r '.inbounds[].listen_port' "$CONF_FILE" 2>/dev/null | tr '\n' '|' | sed 's/|$//')" 2>/dev/null || echo "未发现监听端口"
    echo -e "\n${BLUE}[4] Reality SNI 连通性${NC}"; print_line
    if [[ -f "$INFO_PATH" ]]; then
        source "$INFO_PATH"
        echo -ne "测试 $REALITY_SNI ... "
        if test_reality_compatible "$REALITY_SNI"; then
            echo -e "${GREEN}✓ TLSv1.3 + X25519 正常${NC}"
        else
            echo -e "${RED}✗ 不可用，建议重新配置${NC}"
        fi
    fi
    echo -e "\n${BLUE}[5] 网络连通性${NC}"; print_line
    detect_network
    echo -e "\n${BLUE}[6] 最近50条日志${NC}"; print_line
    if [[ -f "$LOG_FILE" ]]; then tail -n 50 "$LOG_FILE"; else journalctl -u sing-box -n 50 --no-pager; fi
    echo -e "\n${BLUE}[7] 防火墙规则${NC}"; print_line
    if command -v ufw &> /dev/null; then ufw status verbose
    elif command -v firewall-cmd &> /dev/null; then firewall-cmd --list-all
    else echo "未安装防火墙管理工具"; fi
    print_double_line
}

# --- 配置文件 ---
show_config() {
    print_banner
    print_double_line
    echo -e "${BOLD}                    配置文件内容${NC}"
    print_double_line
    if [[ -f "$CONF_FILE" ]]; then
        cat "$CONF_FILE" | jq '.' --color-output 2>/dev/null || cat "$CONF_FILE"
    else
        warn "配置文件不存在"
    fi
    print_double_line
}

# --- 卸载 ---
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
        systemctl stop sing-box 2>/dev/null
        systemctl disable sing-box 2>/dev/null
        info "正在删除文件..."
        rm -rf "$CONF_DIR" "$BIN_PATH" "$SERVICE_FILE" "$LOG_FILE" /usr/local/bin/copy-cert
        systemctl daemon-reload
        success "✨ 卸载完成！"
    else
        warn "已取消卸载操作"
    fi
}

# =========================================================
#  Whiptail 主菜单
# =========================================================
main_menu() {
    if systemctl is-active --quiet sing-box 2>/dev/null; then
        STATUS_TEXT="运行中 (Running)"
    elif [[ -f "$SERVICE_FILE" ]]; then
        STATUS_TEXT="已停止 (Stopped)"
    else
        STATUS_TEXT="未安装 (Not Installed)"
    fi

    CHOICE=$(whiptail --title "Sing-box 管理脚本 v4.0" \
    --backtitle "Sing-Box | TUIC + AnyTLS + Reality | 状态: $STATUS_TEXT" \
    --menu "请使用上下键或数字键选择操作:" \
    20 65 11 \
    "1"  "安装/重装服务 (Install)" \
    "2"  "启动服务 (Start)" \
    "3"  "停止服务 (Stop)" \
    "4"  "重启服务 (Restart)" \
    "5"  "服务状态 (Status)" \
    "6"  "查看日志 (View Logs)" \
    "7"  "节点信息 (Node Links)" \
    "8"  "配置文件 (Config)" \
    "9"  "系统诊断 (Diagnose)" \
    "10" "卸载服务 (Uninstall)" \
    "0"  "退出脚本 (Exit)" \
    3>&1 1>&2 2>&3)

    exitstatus=$?
    [[ $exitstatus != 0 ]] && exit 0

    case $CHOICE in
        1)  clear; install_singbox; read -n 1 -s -r -p "按任意键返回..." ;;
        2)
            clear; info "正在启动服务..."
            systemctl start sing-box; sleep 2
            if systemctl is-active --quiet sing-box; then success "服务启动成功"
            else warn "服务启动失败，请查看日志"; fi
            read -n 1 -s -r -p "按任意键返回..."
            ;;
        3)
            clear; info "正在停止服务..."
            systemctl stop sing-box; sleep 1
            if ! systemctl is-active --quiet sing-box; then success "服务已停止"
            else warn "服务停止失败"; fi
            read -n 1 -s -r -p "按任意键返回..."
            ;;
        4)
            clear; info "正在重启服务..."
            systemctl restart sing-box; sleep 2
            if systemctl is-active --quiet sing-box; then success "服务重启成功"
            else warn "服务重启失败，请查看日志"; fi
            read -n 1 -s -r -p "按任意键返回..."
            ;;
        5)  clear; show_status;  read -n 1 -s -r -p "按任意键返回..." ;;
        6)  clear; show_logs ;;
        7)  clear; show_links;   read -n 1 -s -r -p "按任意键返回..." ;;
        8)  clear; show_config;  read -n 1 -s -r -p "按任意键返回..." ;;
        9)  clear; diagnose;     read -n 1 -s -r -p "按任意键返回..." ;;
        10) clear; uninstall;    read -n 1 -s -r -p "按任意键返回..." ;;
        0)  clear; exit 0 ;;
    esac
}

# --- 主循环 ---
while true; do
    main_menu
done
