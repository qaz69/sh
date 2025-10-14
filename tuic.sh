#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){ echo -e "\033[31m\033[01m$1\033[0m"; }
green(){ echo -e "\033[32m\033[01m$1\033[0m"; }
yellow(){ echo -e "\033[33m\033[01m$1\033[0m"; }

[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

# 系统判断
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove")

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" \
     "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" \
     "$(lsb_release -sd 2>/dev/null)" \
     "$(grep . /etc/redhat-release 2>/dev/null)" \
     "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((i=0;i<${#REGEX[@]};i++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[i]} ]] && SYSTEM="${RELEASE[i]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "暂不支持你的系统！" && exit 1

# 安装依赖
if [[ -z $(type -P curl) ]]; then
    ${PACKAGE_UPDATE[i]}
    ${PACKAGE_INSTALL[i]} curl wget sudo
fi

archAffix(){
    case "$(uname -m)" in
        x86_64|amd64) echo 'x86_64' ;;
        arm64|aarch64) echo 'aarch64' ;;
        *) red "不支持的架构!" && exit 1 ;;
    esac
}

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

# 获取官方最新版本
get_latest_version(){
    LATEST_VERSION=$(curl -sL https://mirror.ghproxy.com/https://api.github.com/repos/Itsusinn/tuic/releases/latest \
        | grep -o '"tag_name": *"[^"]*"' | head -n1 | sed 's/.*: "//;s/"//')
    [[ -z $LATEST_VERSION ]] && red "无法获取 Tuic 最新版本，请检查网络或 GitHub API" && exit 1
    green "检测到 Tuic 最新版本：$LATEST_VERSION"
}

download_tuic(){
    ARCH=$(archAffix)
    URL="https://github.com/Itsusinn/tuic/releases/download/${LATEST_VERSION}/tuic-${LATEST_VERSION}-linux-${ARCH}"
    wget -O /usr/local/bin/tuic $URL || curl -Lo /usr/local/bin/tuic $URL
    chmod +x /usr/local/bin/tuic
    [[ ! -f /usr/local/bin/tuic ]] && red "下载 Tuic 二进制失败！" && exit 1
    green "Tuic 二进制下载完成"
}

# Tuic V4 安装
inst_tuv4(){
    get_latest_version
    download_tuic

    mkdir -p /etc/tuic /root/tuic

    read -p "设置 Tuic 端口 [1-65535] (回车随机): " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n1)
    read -p "设置 Tuic Token (回车随机): " token
    [[ -z $token ]] && token=$(date +%s%N | md5sum | cut -c 1-8)
    
    realip

    cat << EOF > /etc/tuic/tuic.json
{
    "port": $port,
    "token": ["$token"],
    "ip": "::",
    "congestion_controller": "bbr",
    "alpn": ["h3"]
}
EOF

    cat << EOF > /root/tuic/tuic-client.json
{
    "relay": {
        "server": "$ip",
        "port": $port,
        "token": "$token",
        "ip": "$ip",
        "congestion_controller": "bbr",
        "udp_relay_mode": "quic",
        "alpn": ["h3"]
    },
    "local": {
        "port": 6080,
        "ip": "127.0.0.1"
    },
    "log_level": "off"
}
EOF

    cat << EOF >/etc/systemd/system/tuic.service
[Unit]
Description=Tuic Service
After=network.target
[Service]
User=root
ExecStart=/usr/local/bin/tuic -c /etc/tuic/tuic.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable tuic
    systemctl start tuic

    green "Tuic V4 安装完成，已启动"
    yellow "客户端配置保存：/root/tuic/tuic-client.json"
}

# Tuic V4 卸载
unst_tuv4(){
    systemctl stop tuic
    systemctl disable tuic
    rm -rf /usr/local/bin/tuic /etc/tuic /root/tuic /etc/systemd/system/tuic.service
    green "Tuic V4 已卸载完成"
}

# 启动 / 停止 Tuic
starttuic(){ systemctl start tuic; systemctl enable tuic >/dev/null 2>&1; }
stoptuic(){ systemctl stop tuic; systemctl disable tuic >/dev/null 2>&1; }

# 主菜单
menu(){
    clear
    echo "###########################################################"
    echo -e "#                 ${RED}Tuic 一键安装脚本${PLAIN}               #"
    echo "###########################################################"
    echo -e " ${GREEN}1.${PLAIN} 安装 Tuic V4"
    echo -e " ${GREEN}2.${PLAIN} 卸载 Tuic V4"
    echo -e " ${GREEN}3.${PLAIN} 启动 Tuic"
    echo -e " ${GREEN}4.${PLAIN} 停止 Tuic"
    echo -e " ${GREEN}0.${PLAIN} 退出"
    echo "###########################################################"
    read -rp "请输入选项 [0-4]: " choice
    case $choice in
        1) inst_tuv4 ;;
        2) unst_tuv4 ;;
        3) starttuic ;;
        4) stoptuic ;;
        0) exit 0 ;;
        *) exit 1 ;;
    esac
}

menu
