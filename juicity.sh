#!/bin/bash

#==============================================================
# Juicity 管理脚本
# 功能：快捷指令、随机端口、双栈 IP、证书复制
# 系统支持：Ubuntu / Debian / CentOS
# 协议：基于 QUIC 的高性能代理
#==============================================================

set -e

#=========================
# 颜色和样式定义
# 配色风格: bash-style 256色方案
#   BLUE   111  蓝色   → 标题、边框、标签
#   ORANGE 214  橙色   → 分隔线、序号、数值
#   YELLOW 180  暖黄   → 提示文字、路径、SNI
#   GREEN   78  绿色   → 成功、运行中、链接
#   RED    203  红色   → 错误、警告、卸载
#   DIM          暗色   → 次要说明文字
#=========================
readonly BLUE=$'\e[38;5;111m'
readonly ORANGE=$'\e[38;5;214m'
readonly YELLOW=$'\e[38;5;180m'
readonly GREEN=$'\e[38;5;78m'
readonly RED=$'\e[38;5;203m'
readonly BOLD=$'\033[1m'
readonly DIM=$'\033[2m'
readonly NC=$'\e[0m'

# read -rp 提示符专用（readline 边界标记，防退格乱码）
readonly P_BLUE=$'\001\e[38;5;111m\002'
readonly P_ORANGE=$'\001\e[38;5;214m\002'
readonly P_YELLOW=$'\001\e[38;5;180m\002'
readonly P_GREEN=$'\001\e[38;5;78m\002'
readonly P_RED=$'\001\e[38;5;203m\002'
readonly P_BOLD=$'\001\033[1m\002'
readonly P_DIM=$'\001\033[2m\002'
readonly P_NC=$'\001\e[0m\002'

#=========================
# 路径定义
#=========================
readonly CERT_DIR="/etc/juicity"
readonly CONFIG_PATH="/etc/juicity/server.json"
readonly CLIENT_PATH="/root/juicity/client.json"
readonly URL_PATH="/root/juicity/url.txt"
readonly INFO_PATH="/etc/juicity/node_info.conf"
readonly SYSTEMD_PATH="/etc/systemd/system/juicity-server.service"
readonly SCRIPT_PATH="$(realpath "$0")"
readonly SHORTCUT="/usr/local/bin/juicity"

#=========================
# 日志函数
#=========================
info() {
    echo -e "${BLUE}[✓]${NC} ${YELLOW}$1${NC}"
}

warning() {
    echo -e "${ORANGE}[!]${NC} ${YELLOW}$1${NC}"
}

error() {
    echo -e "${RED}[✗]${NC} ${RED}$1${NC}"
    exit 1
}

success() {
    echo -e "${GREEN}[✓]${NC} ${GREEN}$1${NC}"
}

#=========================
# 检查 Root 权限
#=========================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "此脚本必须以 root 权限运行！请使用 sudo 或切换到 root 用户。"
    fi
}

#=========================
# 设置快捷指令
#=========================
setup_shortcut() {
    check_root

    if [[ "$SCRIPT_PATH" != "$SHORTCUT" ]]; then
        ln -sf "$SCRIPT_PATH" "$SHORTCUT" 2>/dev/null || warning "创建软链接失败"
        chmod +x "$SHORTCUT" 2>/dev/null
    fi
}

#=========================
# 获取系统架构
#=========================
arch_affix() {
    case "$(uname -m)" in
        x86_64|amd64)   echo 'x86_64' ;;
        aarch64|arm64)  echo 'arm64' ;;
        *)              error "不支持的 CPU 架构: $(uname -m)" ;;
    esac
}

copy_cert_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo 'amd64' ;;
        aarch64|arm64)  echo 'arm64' ;;
        *)              echo 'amd64' ;;
    esac
}

#=========================
# 获取所有 IP 地址
#=========================
get_all_ips() {
    IPV4=$(curl -s4 --max-time 5 https://api.ipify.org 2>/dev/null || \
           curl -s4 --max-time 5 https://ip.sb 2>/dev/null || \
           curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null)

    if [[ -z "$IPV4" ]]; then
        IPV4=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n 1)
    fi

    # 只保留公网 IPv6：全球单播地址以 2 或 3 开头（2000::/3）
    # 排除：ULA(fc/fd)、链路本地(fe80)、回环(::1)、临时隐私地址(temporary/deprecated)
    IPV6_LIST=""
    while IFS= read -r ip6; do
        [[ -z "$ip6" ]] && continue
        # 只接受 2xxx: 或 3xxx: 开头的全球单播地址
        [[ "$ip6" =~ ^[23] ]] || continue
        IPV6_LIST="${IPV6_LIST}${ip6}"$'\n'
    done < <(ip -6 addr show scope global | grep -v "temporary" | grep -v "deprecated" | grep inet6 | awk '{print $2}' | cut -d/ -f1)
    IPV6_LIST=$(printf "%s" "$IPV6_LIST" | sed '/^$/d')
}

#=========================
# 获取地理位置 Emoji
#=========================
get_geo_emoji() {
    local country_code
    country_code=$(curl -s --max-time 5 https://ipapi.co/country_code/ 2>/dev/null)

    if [[ -z "$country_code" || "$country_code" == "null" ]]; then
        country_code=$(curl -s --max-time 5 https://ip-api.com/json/ | jq -r .countryCode 2>/dev/null)
    fi

    case $country_code in
        CN) echo "🇨🇳" ;; HK) echo "🇭🇰" ;; MO) echo "🇲🇴" ;; TW) echo "🇹🇼" ;;
        SG) echo "🇸🇬" ;; JP) echo "🇯🇵" ;; US) echo "🇺🇸" ;; KR) echo "🇰🇷" ;;
        GB) echo "🇬🇧" ;; DE) echo "🇩🇪" ;; FR) echo "🇫🇷" ;; NL) echo "🇳🇱" ;;
        CA) echo "🇨🇦" ;; AU) echo "🇦🇺" ;; RU) echo "🇷🇺" ;; IN) echo "🇮🇳" ;;
        BR) echo "🇧🇷" ;; IT) echo "🇮🇹" ;; ES) echo "🇪🇸" ;; SE) echo "🇸🇪" ;;
        *) echo "🌐" ;;
    esac
}

#=========================
# 获取安全可用端口
#=========================
get_safe_port() {
    local port
    while true; do
        port=$((RANDOM % 55535 + 10000))
        ! ss -tunlp 2>/dev/null | grep -q ":$port " && echo "$port" && break
    done
}

#=========================
# 生成/复制证书
#=========================
generate_cert() {
    mkdir -p "$CERT_DIR"
    cd "$CERT_DIR" || error "无法进入证书目录"

    echo ""
    echo -e "${BLUE}────────────────────────────────────────────────────${NC}"
    echo -e "${BOLD}${ORANGE}  证书配置${NC}"
    echo -e "${BLUE}────────────────────────────────────────────────────${NC}"
    echo -e "${DIM}  提示：输入真实域名可复制其证书以提高伪装效果${NC}"
    echo -e "${DIM}        留空则默认使用 www.bing.com 生成自签名证书${NC}"
    echo ""

    read -rp "${P_ORANGE}  请输入域名 ${P_DIM}[默认: www.bing.com]${P_ORANGE}: ${P_NC}" target_domain
    target_domain=${target_domain:-www.bing.com}

    local bin_arch
    bin_arch=$(copy_cert_arch)
    local url="https://github.com/virusdefender/copy-cert/releases/latest/download/copy-cert-linux-$bin_arch"

    info "正在从 $target_domain 复制证书..."

    if curl -L --max-time 30 -o /usr/local/bin/copy-cert "$url" 2>/dev/null && \
       chmod +x /usr/local/bin/copy-cert; then

        rm -rf certs/ 2>/dev/null

        if /usr/local/bin/copy-cert "$target_domain:443" 2>/dev/null; then
            local sub_dir
            sub_dir=$(ls -dt certs/* 2>/dev/null | head -n 1)

            if [[ -n "$sub_dir" ]]; then
                local keyword
                keyword=$(echo "$target_domain" | cut -d'.' -f2)
                local tmp_crt
                local tmp_key
                tmp_crt=$(ls "$sub_dir"/*"$keyword"*.crt 2>/dev/null | head -n 1)
                tmp_key=$(ls "$sub_dir"/*"$keyword"*.key 2>/dev/null | head -n 1)

                [[ -z "$tmp_crt" ]] && tmp_crt=$(ls -S "$sub_dir"/*.crt 2>/dev/null | head -n 1)
                [[ -z "$tmp_key" ]] && tmp_key=$(ls -S "$sub_dir"/*.key 2>/dev/null | head -n 1)

                if [[ -n "$tmp_crt" && -n "$tmp_key" ]]; then
                    cp -f "$tmp_crt" certificate.crt
                    cp -f "$tmp_key" private.key
                    rm -rf certs/
                    FINAL_DOMAIN=$target_domain
                    success "成功从 $target_domain 复制证书！"
                    return 0
                fi
            fi
        fi
    fi

    # 证书复制失败，回退到自签名
    warning "证书复制失败，生成自签名证书..."

    openssl ecparam -genkey -name prime256v1 -out private.key 2>/dev/null || \
        error "OpenSSL 生成密钥失败"

    openssl req -new -x509 -days 36500 -key private.key -out certificate.crt \
        -subj "/CN=$target_domain" 2>/dev/null || \
        error "OpenSSL 生成证书失败"

    FINAL_DOMAIN=$target_domain
    success "自签名证书生成完成（SNI: $target_domain）"
}

#=========================
# 安装系统依赖
#=========================
install_dependencies() {
    info "正在检查并安装系统依赖..."

    if command -v apt-get &>/dev/null; then
        apt-get update -qq 2>/dev/null || warning "软件源更新失败，继续安装..."
        for pkg in curl jq openssl unzip wget iproute2 uuid-runtime; do
            dpkg -l | grep -q "^ii  $pkg" || apt-get install -y -qq "$pkg" 2>/dev/null || warning "安装 $pkg 失败"
        done
    elif command -v yum &>/dev/null; then
        for pkg in curl jq openssl unzip wget iproute util-linux; do
            rpm -q "$pkg" &>/dev/null || yum install -y -q "$pkg" 2>/dev/null || warning "安装 $pkg 失败"
        done
    elif command -v dnf &>/dev/null; then
        dnf install -y -q curl jq openssl unzip wget iproute util-linux 2>/dev/null || warning "部分依赖安装失败"
    else
        warning "无法识别的包管理器，请手动安装: curl jq openssl unzip wget"
    fi

    success "依赖检查完成"
}

#=========================
# 下载 Juicity 二进制
#=========================
download_juicity() {
    local version="$1"
    local arch
    arch=$(arch_affix)

    info "正在下载 Juicity $version ($arch)..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local zip_url="https://github.com/juicity/juicity/releases/download/$version/juicity-linux-$arch.zip"

    wget -q --show-progress "$zip_url" -O "$tmp_dir/juicity.zip" || \
        error "下载 Juicity 失败，请检查网络连接"

    cd "$tmp_dir" || error "无法进入临时目录"
    unzip -q juicity.zip || error "解压失败"

    if [[ ! -f "$tmp_dir/juicity-server" ]]; then
        error "解压后未找到 juicity-server 二进制文件"
    fi

    cp -f "$tmp_dir/juicity-server" /usr/local/bin/juicity-server
    chmod +x /usr/local/bin/juicity-server

    rm -rf "$tmp_dir"
    success "Juicity $version 下载完成"
}

#=========================
# 更新 Juicity
#=========================
update_juicity() {
    if [[ ! -f /usr/local/bin/juicity-server ]]; then
        error "未检测到 Juicity 安装，请先执行安装"
    fi

    info "正在检查更新..."

    local latest_version
    latest_version=$(curl -s --max-time 10 \
        "https://api.github.com/repos/juicity/juicity/releases/latest" | \
        jq -r .tag_name 2>/dev/null)

    if [[ -z "$latest_version" || "$latest_version" == "null" ]]; then
        # 备用：jsdelivr
        latest_version="v$(curl -Ls 'https://data.jsdelivr.com/v1/package/resolve/gh/juicity/juicity' | \
            jq -r '.version' 2>/dev/null)"
    fi

    [[ -z "$latest_version" || "$latest_version" == "v" ]] && error "无法获取最新版本信息"

    local current_version
    current_version="$(/usr/local/bin/juicity-server -v 2>/dev/null | grep -oP 'v\d+\.\d+\.\d+' | head -n 1 || echo "unknown")"

    echo -e "  ${BLUE}当前版本:${NC} ${YELLOW}$current_version${NC}"
    echo -e "  ${BLUE}最新版本:${NC} ${GREEN}$latest_version${NC}"

    if [[ "$latest_version" == "$current_version" ]]; then
        success "已经是最新版本，无需更新"
        return 0
    fi

    systemctl stop juicity-server 2>/dev/null || true
    download_juicity "$latest_version"
    systemctl start juicity-server 2>/dev/null || error "服务重启失败"

    success "Juicity 已更新至 $latest_version"
}

#=========================
# 安装 Juicity
#=========================
install_juicity() {
    check_root
    install_dependencies

    # 获取最新版本
    local version
    version=$(curl -s --max-time 10 \
        "https://api.github.com/repos/juicity/juicity/releases/latest" | \
        jq -r .tag_name 2>/dev/null)

    if [[ -z "$version" || "$version" == "null" ]]; then
        version="v$(curl -Ls 'https://data.jsdelivr.com/v1/package/resolve/gh/juicity/juicity' | \
            jq -r '.version' 2>/dev/null)"
    fi

    [[ -z "$version" || "$version" == "v" ]] && error "无法获取 Juicity 版本信息，请检查网络"

    # 停止旧服务（如存在）
    systemctl stop juicity-server 2>/dev/null || true

    # 下载二进制
    download_juicity "$version"

    # 生成/复制证书
    generate_cert

    # 配置端口
    echo ""
    echo -e "${BLUE}────────────────────────────────────────────────────${NC}"
    echo -e "${BOLD}${ORANGE}  端口配置${NC}"
    echo -e "${BLUE}────────────────────────────────────────────────────${NC}"
    read -rp "${P_ORANGE}  请输入端口 ${P_DIM}[1-65535，回车随机分配]${P_ORANGE}: ${P_NC}" PORT
    if [[ -z "$PORT" ]]; then
        PORT=$(get_safe_port)
        info "随机分配端口: ${ORANGE}$PORT${NC}"
    else
        if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
            error "端口格式不正确"
        fi
    fi

    # 配置 UUID
    echo ""
    echo -e "${BLUE}────────────────────────────────────────────────────${NC}"
    echo -e "${BOLD}${ORANGE}  UUID 配置${NC}"
    echo -e "${BLUE}────────────────────────────────────────────────────${NC}"
    read -rp "${P_ORANGE}  请输入 UUID ${P_DIM}[回车随机生成]${P_ORANGE}: ${P_NC}" uuid
    if [[ -z "$uuid" ]]; then
        uuid=$(cat /proc/sys/kernel/random/uuid)
        info "随机生成 UUID: ${ORANGE}$uuid${NC}"
    fi

    # 配置密码
    echo ""
    echo -e "${BLUE}────────────────────────────────────────────────────${NC}"
    echo -e "${BOLD}${ORANGE}  密码配置${NC}"
    echo -e "${BLUE}────────────────────────────────────────────────────${NC}"
    read -rp "${P_ORANGE}  请输入密码 ${P_DIM}[回车随机生成]${P_ORANGE}: ${P_NC}" password
    if [[ -z "$password" ]]; then
        password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
        info "随机生成密码: ${ORANGE}$password${NC}"
    fi

    # 写入服务端配置
    mkdir -p /etc/juicity /root/juicity

    cat > "$CONFIG_PATH" << EOF
{
    "listen": ":$PORT",
    "users": {
        "$uuid": "$password"
    },
    "certificate": "$CERT_DIR/certificate.crt",
    "private_key": "$CERT_DIR/private.key",
    "congestion_control": "bbr",
    "log_level": "info"
}
EOF

    # 获取 IP
    get_all_ips
    local server_ip="${IPV4:-127.0.0.1}"

    # 写入客户端配置
    cat > "$CLIENT_PATH" << EOF
{
    "listen": ":7080",
    "server": "$server_ip:$PORT",
    "uuid": "$uuid",
    "password": "$password",
    "sni": "$FINAL_DOMAIN",
    "allow_insecure": true,
    "congestion_control": "bbr",
    "log_level": "info"
}
EOF

    # 始终强制写入 systemd 服务文件，确保路径指向 /usr/local/bin
    cat > "$SYSTEMD_PATH" << EOF
[Unit]
Description=Juicity Proxy Server
Documentation=https://github.com/juicity/juicity
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/juicity-server run -c $CONFIG_PATH
Restart=on-failure
RestartSec=10s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    # 启动服务
    systemctl daemon-reload
    systemctl enable juicity-server --now 2>/dev/null || error "服务启动失败"

    sleep 2

    if systemctl is-active --quiet juicity-server; then
        success "Juicity 服务启动成功"
    else
        error "服务启动失败，请查看日志: journalctl -u juicity-server -n 50"
    fi

    # 生成分享链接并保存
    local share_link
    share_link=$(juicity-server generate-sharelink -c "$CONFIG_PATH" 2>/dev/null || true)
    if [[ -z "$share_link" ]]; then
        share_link="juicity://$uuid:$password@$server_ip:$PORT?sni=$FINAL_DOMAIN&allow_insecure=1&congestion_control=bbr#Juicity"
    fi
    echo "$share_link" > "$URL_PATH"

    # 保存节点信息
    local emoji
    emoji=$(get_geo_emoji)
    cat > "$INFO_PATH" << EOF
DOMAIN=$FINAL_DOMAIN
EMOJI=$emoji
VERSION=$version
INSTALL_DATE=$(date '+%Y-%m-%d %H:%M:%S')
PORT=$PORT
UUID=$uuid
PASSWORD=$password
EOF

    echo ""
    success "安装完成！"
    echo ""

    view_link
}

#=========================
# 查看连接信息
#=========================
view_link() {
    if [[ ! -f "$CONFIG_PATH" ]]; then
        warning "配置文件不存在，请先安装 Juicity"
        return 1
    fi

    source "$INFO_PATH" 2>/dev/null || EMOJI="[NODE]"
    get_all_ips

    local port uuid password
    port=$(jq -r '.listen' "$CONFIG_PATH" | awk -F ':' '{print $NF}')
    uuid=$(jq -r '.users | keys[0]' "$CONFIG_PATH")
    password=$(jq -r ".users.\"$uuid\"" "$CONFIG_PATH")

    clear
    echo ""
    echo -e "${BLUE}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC}        ${BOLD}${ORANGE}Juicity 节点配置信息${NC}  $EMOJI                      ${BLUE}│${NC}"
    echo -e "${BLUE}├────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${BLUE}│${NC}  ${DIM}端口        ${NC}${ORANGE}$port${NC}"
    echo -e "${BLUE}│${NC}  ${DIM}UUID        ${NC}${YELLOW}$uuid${NC}"
    echo -e "${BLUE}│${NC}  ${DIM}密码        ${NC}${YELLOW}$password${NC}"
    echo -e "${BLUE}│${NC}  ${DIM}SNI         ${NC}${YELLOW}$DOMAIN${NC}"
    echo -e "${BLUE}│${NC}  ${DIM}拥塞控制    ${NC}${GREEN}BBR${NC}"
    echo -e "${BLUE}│${NC}  ${DIM}Insecure    ${NC}${RED}True (必须开启)${NC}"
    echo -e "${BLUE}│${NC}  ${DIM}安装日期    ${NC}${DIM}$INSTALL_DATE${NC}"
    echo -e "${BLUE}└────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${BOLD}${ORANGE}客户端连接链接${NC}"
    echo -e "${BLUE}──────────────────────────────────────────────────────────────${NC}"

    # IPv4
    if [[ -n "$IPV4" ]]; then
        local link_v4="juicity://$uuid:$password@$IPV4:$port?sni=$DOMAIN&allow_insecure=1&congestion_control=bbr#$EMOJI-Juicity-v4"
        echo ""
        echo -e "  ${BLUE}${BOLD}[IPv4]${NC}  ${YELLOW}$IPV4${NC}"
        echo -e "  ${GREEN}$link_v4${NC}"
    else
        echo -e "  ${DIM}[未检测到 IPv4 地址]${NC}"
    fi

    # IPv6
    if [[ -n "$IPV6_LIST" ]]; then
        local i=1
        for ip6 in $IPV6_LIST; do
            local link_v6="juicity://$uuid:$password@[$ip6]:$port?sni=$DOMAIN&allow_insecure=1&congestion_control=bbr#$EMOJI-Juicity-v6-$i"
            echo ""
            echo -e "  ${BLUE}${BOLD}[IPv6-$i]${NC}  ${YELLOW}$ip6${NC}"
            echo -e "  ${GREEN}$link_v6${NC}"
            ((i++))
        done
    else
        echo ""
        echo -e "  ${DIM}[未检测到 IPv6 地址]${NC}"
    fi

    echo ""
    echo -e "${BLUE}──────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${DIM}客户端配置文件路径${NC}  ${YELLOW}$CLIENT_PATH${NC}"
    echo -e "  ${DIM}分享链接保存路径  ${NC}  ${YELLOW}$URL_PATH${NC}"
    echo ""
    echo -e "${ORANGE}客户端 JSON 配置内容如下：${NC}"
    echo -e "${BLUE}──────────────────────────────────────────────────────────────${NC}"
    cat "$CLIENT_PATH"
    echo ""
}

#=========================
# 卸载 Juicity
#=========================
uninstall_juicity() {
    clear
    echo -e "${RED}┌──────────────────────────────────────────┐${NC}"
    echo -e "${RED}│${NC}    ${BOLD}${RED}卸载 Juicity 服务${NC}                   ${RED}│${NC}"
    echo -e "${RED}└──────────────────────────────────────────┘${NC}"
    echo ""
    warning "此操作将完全删除 Juicity 及其所有配置文件"
    echo ""

    read -rp "${P_RED}  确定要卸载吗？[y/N]: ${P_NC}" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "已取消卸载"
        return
    fi

    info "正在停止服务..."
    systemctl stop juicity-server 2>/dev/null || true
    systemctl disable juicity-server 2>/dev/null || true

    info "正在删除文件..."
    rm -rf /etc/juicity /root/juicity
    rm -f /usr/local/bin/juicity-server /usr/local/bin/copy-cert
    rm -f "$SYSTEMD_PATH" "$SHORTCUT"

    systemctl daemon-reload 2>/dev/null

    success "Juicity 已完全卸载！"
    read -rp "  按 Enter 键退出..." && exit 0
}

#=========================
# 查看服务状态
#=========================
view_status() {
    clear
    echo -e "${BLUE}┌──────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC}    ${BOLD}${ORANGE}Juicity 服务状态${NC}                   ${BLUE}│${NC}"
    echo -e "${BLUE}└──────────────────────────────────────────┘${NC}"
    echo ""

    if systemctl is-active --quiet juicity-server; then
        echo -e "  ${GREEN}[✓]${NC} ${GREEN}服务状态: 运行中${NC}"
    else
        echo -e "  ${RED}[✗]${NC} ${RED}服务状态: 已停止${NC}"
    fi

    if systemctl is-enabled --quiet juicity-server 2>/dev/null; then
        echo -e "  ${GREEN}[✓]${NC} ${GREEN}开机启动: 已启用${NC}"
    else
        echo -e "  ${ORANGE}[!]${NC} ${YELLOW}开机启动: 未启用${NC}"
    fi

    echo ""
    echo -e "  ${BOLD}${ORANGE}详细状态:${NC}"
    echo -e "${BLUE}──────────────────────────────────────────${NC}"
    systemctl status juicity-server --no-pager -l
    echo ""
}

#=========================
# 主菜单
#=========================
main_menu() {
    setup_shortcut
    clear

    echo -e "${BLUE}┌────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC}            ${BOLD}${ORANGE}Juicity 管理脚本${NC}                          ${BLUE}│${NC}"
    echo -e "${BLUE}├────────────────────────────────────────────────────────┤${NC}"
    echo -e "${BLUE}│${NC}  ${DIM}功能: 快捷指令 | 随机端口 | 双栈IP | 证书复制${NC}     ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}  ${DIM}系统: Ubuntu / Debian / CentOS${NC}                     ${BLUE}│${NC}"
    echo -e "${BLUE}└────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "  ${ORANGE}1.${NC}  ${YELLOW}安装/重装 Juicity${NC}"
    echo -e "  ${ORANGE}2.${NC}  ${YELLOW}更新到最新版本${NC}"
    echo -e "  ${ORANGE}3.${NC}  ${GREEN}启动服务${NC}"
    echo -e "  ${ORANGE}4.${NC}  ${RED}停止服务${NC}"
    echo -e "  ${ORANGE}5.${NC}  ${YELLOW}重启服务${NC}"
    echo -e "  ${ORANGE}6.${NC}  ${BLUE}查看服务状态${NC}"
    echo -e "  ${ORANGE}7.${NC}  ${BLUE}查看实时日志${NC}"
    echo -e "  ${ORANGE}8.${NC}  ${BLUE}查看连接信息${NC}"
    echo -e "  ${ORANGE}9.${NC}  ${RED}卸载 Juicity${NC}"
    echo -e "  ${DIM}0.${NC}  ${DIM}退出脚本${NC}"
    echo ""
    echo -e "${BLUE}────────────────────────────────────────────────────────${NC}"
    echo -e "  ${DIM}安装后可使用快捷命令 ${NC}${BOLD}${ORANGE}juicity${NC}${DIM} 管理服务${NC}"
    echo ""

    read -rp "${P_ORANGE}  请选择操作 [0-9]: ${P_NC}" choice

    case $choice in
        1) install_juicity ;;
        2) update_juicity ;;
        3) systemctl start juicity-server && success "服务已启动" || error "启动失败" ;;
        4) systemctl stop juicity-server && success "服务已停止" || error "停止失败" ;;
        5) systemctl restart juicity-server && success "服务已重启" || error "重启失败" ;;
        6) view_status ;;
        7)
            echo ""
            info "正在查看实时日志 (按 Ctrl+C 退出)..."
            echo ""
            sleep 1
            journalctl -u juicity-server -f --no-pager
            ;;
        8) view_link ;;
        9) uninstall_juicity ;;
        0)
            echo ""
            success "感谢使用，再见！"
            echo ""
            exit 0
            ;;
        *)
            warning "无效的选择，请重新输入"
            sleep 1
            ;;
    esac
}

#=========================
# 入口检查
#=========================
check_root

#=========================
# 主循环
#=========================
while true; do
    main_menu
    echo ""
    read -n 1 -s -r -p "${P_DIM}  按任意键返回主菜单...${P_NC}"
    echo ""
done
