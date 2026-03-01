#!/usr/bin/env python3
"""
透明代理一键安装脚本（安全版）
支持 mihomo (clash-meta) 或 sing-box 内核
使用 TProxy (透明代理) 模式

用法:
  sudo python3 tproxy_setup.py install            # 安装（默认 mihomo）
  sudo python3 tproxy_setup.py install --core singbox
  sudo python3 tproxy_setup.py start              # 启动代理
  sudo python3 tproxy_setup.py stop               # 停止代理
  sudo python3 tproxy_setup.py restart            # 重启代理
  sudo python3 tproxy_setup.py status             # 查看状态
  sudo python3 tproxy_setup.py uninstall          # 卸载并恢复原有防火墙规则

安全特性:
  - 安装前自动备份 iptables/ip6tables 规则
  - 卸载时自动恢复原有防火墙规则
  - 检测链名/路由表冲突，有冲突时询问用户
  - 只操作自己创建的链和路由表条目，精确清除
  - 所有操作有日志记录（/var/log/tproxy/setup.log）
"""

import os
import sys
import json
import shutil
import subprocess
import platform
import urllib.request
import tarfile
import gzip
import tempfile
import argparse
import datetime
import logging
from pathlib import Path

# ═══════════════════════════════════════════════
#  配置区（按需修改）
# ═══════════════════════════════════════════════
CORE         = "mihomo"           # "mihomo" 或 "singbox"
INSTALL_DIR  = Path("/usr/local/bin")
CONFIG_DIR   = Path("/etc/tproxy")
LOG_DIR      = Path("/var/log/tproxy")
SERVICE_NAME = "tproxy"

TPROXY_PORT  = 7893   # TProxy 监听端口
DNS_PORT     = 1053   # 内部 DNS 监听端口（避免与系统 53 冲突）
MIXED_PORT   = 7890   # HTTP/SOCKS5 混合端口
API_PORT     = 9090   # Dashboard 端口

# 不走代理的网段（直连）
BYPASS_CIDRS = [
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4",
]

# ── 安全相关常量（勿随意修改）──────────────────
TPROXY_MARK    = 0x29           # fwmark，用十六进制且值不常见
ROUTE_TABLE_ID = 529            # 路由表 ID，选不常用的值
IPTABLES_CHAIN = "SC_TPROXY"   # 链名加 SC_ 前缀，降低冲突概率
NAT_CHAIN      = "SC_DNS_NAT"
MARK_COMMENT   = "sc-tproxy-managed"  # 注释标记，用于识别本脚本创建的规则

BACKUP_FILE    = CONFIG_DIR / "iptables_backup.rules"
BACKUP_V6_FILE = CONFIG_DIR / "ip6tables_backup.rules"
STATE_FILE     = CONFIG_DIR / ".state.json"

# ═══════════════════════════════════════════════
#  日志初始化
# ═══════════════════════════════════════════════
log = logging.getLogger("tproxy")
log.setLevel(logging.DEBUG)
_stream_handler = logging.StreamHandler(sys.stdout)
_stream_handler.setFormatter(logging.Formatter("%(message)s"))
log.addHandler(_stream_handler)

def _enable_file_log():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(LOG_DIR / "setup.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    log.addHandler(fh)

# ═══════════════════════════════════════════════
#  工具函数
# ═══════════════════════════════════════════════
def run(cmd, check=True, capture=False, input_data=None):
    if isinstance(cmd, str):
        cmd = cmd.split()
    log.debug(f"  $ {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(
        cmd, capture_output=capture, text=True, check=False, input=input_data
    )
    if check and result.returncode != 0:
        err = (result.stderr or "").strip() or "(无错误输出)"
        raise RuntimeError(f"命令失败 [exit={result.returncode}]: {' '.join(str(c) for c in cmd)}\n  {err}")
    return result

def check_root():
    if os.geteuid() != 0:
        print("❌ 请使用 root 权限运行: sudo python3 tproxy_setup.py <command>")
        sys.exit(1)

def check_deps():
    deps = ["iptables", "iptables-save", "iptables-restore", "ip"]
    missing = [d for d in deps if not shutil.which(d)]
    if missing:
        print(f"❌ 缺少依赖: {', '.join(missing)}")
        print("   安装方法: apt install -y iptables iproute2")
        sys.exit(1)

def confirm(prompt, default_yes=False):
    hint = "[Y/n]" if default_yes else "[y/N]"
    ans = input(f"{prompt} {hint}: ").strip().lower()
    if ans == "":
        return default_yes
    return ans in ("y", "yes")

def get_arch():
    machine = platform.machine().lower()
    mapping = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "armv7l": "armv7", "armv6l": "armv6",
        "mips": "mips", "mipsle": "mipsle",
        "mips64": "mips64", "mips64le": "mips64le",
    }
    return mapping.get(machine, machine)

# ═══════════════════════════════════════════════
#  状态文件
# ═══════════════════════════════════════════════
def save_state(data: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    existing = load_state()
    existing.update(data)
    STATE_FILE.write_text(json.dumps(existing, indent=2, ensure_ascii=False))

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            return {}
    return {}

# ═══════════════════════════════════════════════
#  iptables 备份 / 恢复
# ═══════════════════════════════════════════════
def backup_iptables():
    """备份当前 iptables 和 ip6tables 规则"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    backed = []
    for cmd, path in [("iptables-save", BACKUP_FILE), ("ip6tables-save", BACKUP_V6_FILE)]:
        if not shutil.which(cmd):
            log.info(f"   跳过 {cmd}（未安装）")
            continue
        result = run(cmd, capture=True)
        path.write_text(result.stdout, encoding="utf-8")
        lines = len(result.stdout.splitlines())
        print(f"   ✔ {cmd}: {lines} 条规则 → {path}")
        backed.append(str(path))
    save_state({"iptables_backup": str(BACKUP_FILE), "ip6tables_backup": str(BACKUP_V6_FILE)})
    return backed

def restore_iptables():
    """从备份文件恢复 iptables 规则"""
    state = load_state()
    restored_any = False
    for cmd, key, fallback in [
        ("iptables-restore",  "iptables_backup",  BACKUP_FILE),
        ("ip6tables-restore", "ip6tables_backup",  BACKUP_V6_FILE),
    ]:
        path = Path(state.get(key, str(fallback)))
        if not path.exists():
            print(f"   ⚠  备份文件不存在: {path}，跳过 {cmd}")
            continue
        if not shutil.which(cmd):
            print(f"   ⚠  {cmd} 未安装，跳过")
            continue
        content = path.read_text(encoding="utf-8")
        run([cmd], input_data=content)
        print(f"   ✔ {cmd} 恢复完成 ← {path}")
        restored_any = True
    if not restored_any:
        print("   ⚠  未找到任何备份，防火墙规则未恢复")
    return restored_any

# ═══════════════════════════════════════════════
#  冲突检测
# ═══════════════════════════════════════════════
def _chain_exists(table, chain):
    r = run(["iptables", "-t", table, "-L", chain, "-n"], check=False, capture=True)
    return r.returncode == 0

def _chain_is_ours(table, chain):
    """判断链是否是本脚本上次创建的（通过注释标记识别）"""
    r = run(["iptables", "-t", table, "-L", chain, "-n"], check=False, capture=True)
    return MARK_COMMENT in r.stdout

def check_conflicts():
    """检测潜在冲突，存在不属于本脚本的冲突时询问用户"""
    conflicts = []

    for table, chain in [("mangle", IPTABLES_CHAIN), ("nat", NAT_CHAIN)]:
        if _chain_exists(table, chain) and not _chain_is_ours(table, chain):
            conflicts.append(
                f"iptables -{table} 中链 '{chain}' 已存在，且不是本脚本创建的"
            )

    # 检查路由表
    rt = run(["ip", "route", "show", "table", str(ROUTE_TABLE_ID)],
             check=False, capture=True).stdout.strip()
    if rt and "local 0.0.0.0/0" not in rt:
        conflicts.append(
            f"路由表 {ROUTE_TABLE_ID} 已存在其他路由: {rt[:80]}"
        )

    # 检查 fwmark
    ip_rules = run("ip rule show", capture=True, check=False).stdout
    mark_hex = f"0x{TPROXY_MARK:x}"
    if mark_hex in ip_rules and f"table {ROUTE_TABLE_ID}" not in ip_rules:
        conflicts.append(
            f"fwmark {mark_hex} 已被其他 ip rule 使用（指向不同路由表）"
        )

    if conflicts:
        print("\n⚠️  检测到以下潜在冲突：")
        for c in conflicts:
            print(f"   • {c}")
        print()
        if not confirm("继续可能覆盖上述规则，是否仍要继续？", default_yes=False):
            print("已取消。")
            sys.exit(0)
    else:
        print("   ✔ 未检测到冲突")

# ═══════════════════════════════════════════════
#  下载安装内核
# ═══════════════════════════════════════════════
def _fetch_latest(repo, arch, suffix, exclude=None):
    api = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(api, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.loads(r.read())
    tag = data["tag_name"]
    for asset in data["assets"]:
        name = asset["name"]
        if arch in name and name.endswith(suffix):
            if exclude and any(e in name for e in exclude):
                continue
            return asset["browser_download_url"], tag
    raise RuntimeError(f"未找到架构 {arch} 的包（{repo}）")

def _download(url, dest):
    print(f"   ⬇ {url}")
    def hook(blk, bs, total):
        if total > 0:
            pct = min(blk * bs * 100 // total, 100)
            print(f"\r     进度: {pct}%  ", end="", flush=True)
    urllib.request.urlretrieve(url, dest, hook)
    print()

def install_mihomo():
    arch = get_arch()
    print(f"   架构: {arch}")
    url, tag = _fetch_latest(
        "MetaCubeX/mihomo", f"linux-{arch}", ".gz",
        exclude=["compatible", "go120"]
    )
    print(f"   版本: {tag}")
    with tempfile.TemporaryDirectory() as tmp:
        gz = Path(tmp) / "mihomo.gz"
        _download(url, gz)
        bin_path = Path(tmp) / "mihomo"
        with gzip.open(gz, "rb") as fi, open(bin_path, "wb") as fo:
            shutil.copyfileobj(fi, fo)
        dest = INSTALL_DIR / "mihomo"
        shutil.copy2(bin_path, dest)
        os.chmod(dest, 0o755)
    print(f"   ✔ 已安装到 {dest}")
    return dest

def install_singbox():
    arch = get_arch()
    print(f"   架构: {arch}")
    url, tag = _fetch_latest("SagerNet/sing-box", f"linux-{arch}", ".tar.gz")
    print(f"   版本: {tag}")
    with tempfile.TemporaryDirectory() as tmp:
        tgz = Path(tmp) / "singbox.tar.gz"
        _download(url, tgz)
        with tarfile.open(tgz, "r:gz") as tar:
            for m in tar.getmembers():
                if m.name.endswith("/sing-box") or m.name == "sing-box":
                    m.name = "sing-box"
                    tar.extract(m, tmp)
                    break
        dest = INSTALL_DIR / "sing-box"
        shutil.copy2(Path(tmp) / "sing-box", dest)
        os.chmod(dest, 0o755)
    print(f"   ✔ 已安装到 {dest}")
    return dest

# ═══════════════════════════════════════════════
#  生成配置文件
# ═══════════════════════════════════════════════
def _backup_existing(path: Path):
    if path.exists():
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        bak = path.with_suffix(path.suffix + f".bak_{ts}")
        shutil.copy2(path, bak)
        print(f"   原配置已备份为 {bak}")

def write_mihomo_config():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config_path = CONFIG_DIR / "config.yaml"
    _backup_existing(config_path)
    content = f"""\
# mihomo (clash-meta) 配置
# 生成时间: {datetime.datetime.now().isoformat()}
# ⚠️  请在 proxies 区块添加节点，并在 proxy-groups 中引用

mixed-port: {MIXED_PORT}
tproxy-port: {TPROXY_PORT}
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
external-controller: "0.0.0.0:{API_PORT}"
geodata-mode: true

dns:
  enable: true
  listen: "0.0.0.0:{DNS_PORT}"
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: "198.18.0.1/16"
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "*.home.arpa"
  nameserver:
    - "https://doh.pub/dns-query"
    - "https://dns.alidns.com/dns-query"
  fallback:
    - "https://8.8.8.8/dns-query"
    - "https://1.1.1.1/dns-query"
  fallback-filter:
    geoip: true
    geoip-code: CN

# ── 在此添加你的代理节点 ──────────────────────
proxies:
  # 示例（VMess + TLS）：
  # - name: "my-node"
  #   type: vmess
  #   server: your.server.com
  #   port: 443
  #   uuid: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  #   alterId: 0
  #   cipher: auto
  #   tls: true

proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies:
      - DIRECT
      # - my-node

rules:
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择
"""
    config_path.write_text(content, encoding="utf-8")
    print(f"   ✔ 配置文件: {config_path}")
    return config_path

def write_singbox_config():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config_path = CONFIG_DIR / "config.json"
    _backup_existing(config_path)
    config = {
        "_info": f"sing-box 配置 | {datetime.datetime.now().isoformat()}",
        "log": {"level": "info", "output": str(LOG_DIR / "sing-box.log")},
        "dns": {
            "servers": [
                {"tag": "dns-proxy",  "address": "https://8.8.8.8/dns-query",  "detour": "proxy"},
                {"tag": "dns-direct", "address": "https://doh.pub/dns-query",  "detour": "direct"},
                {"tag": "dns-block",  "address": "rcode://refused"},
            ],
            "rules": [
                {"outbound": "any",              "server": "dns-direct"},
                {"geosite": "cn",                "server": "dns-direct"},
                {"geosite": "category-ads-all",  "server": "dns-block", "disable_cache": True},
            ],
            "final": "dns-proxy",
            "independent_cache": True,
        },
        "inbounds": [
            {
                "type": "tproxy", "tag": "tproxy-in",
                "listen": "::", "listen_port": TPROXY_PORT,
                "sniff": True, "sniff_override_destination": True,
                "domain_strategy": "prefer_ipv4",
            },
            {
                "type": "mixed", "tag": "mixed-in",
                "listen": "::", "listen_port": MIXED_PORT,
                "sniff": True,
            },
        ],
        "outbounds": [
            {
                "type": "selector", "tag": "proxy",
                "outbounds": ["direct"],
                "_note": "添加节点 tag 到 outbounds 列表，并在下方定义节点",
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block",  "tag": "block"},
            {"type": "dns",    "tag": "dns-out"},
            # 示例节点（取消注释并填写）：
            # {
            #     "type": "vmess", "tag": "my-node",
            #     "server": "your.server.com", "server_port": 443,
            #     "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            #     "tls": {"enabled": true}
            # }
        ],
        "route": {
            "rules": [
                {"protocol": "dns",             "outbound": "dns-out"},
                {"geoip": "private",            "outbound": "direct"},
                {"geoip": "cn",                 "outbound": "direct"},
                {"geosite": "cn",               "outbound": "direct"},
                {"geosite": "category-ads-all", "outbound": "block"},
            ],
            "final": "proxy",
            "auto_detect_interface": True,
        },
    }
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"   ✔ 配置文件: {config_path}")
    return config_path

# ═══════════════════════════════════════════════
#  iptables TProxy 规则（精确、幂等）
# ═══════════════════════════════════════════════
def _ipt(*args, table="mangle", check=True):
    return run(["iptables", "-t", table] + list(args), check=check, capture=True)

def _rule_exists(table, chain, *rule_args):
    r = _ipt("-C", chain, *rule_args, table=table, check=False)
    return r.returncode == 0

def setup_tproxy_rules():
    mark_hex = f"0x{TPROXY_MARK:x}"
    print(f"   fwmark={mark_hex}  route_table={ROUTE_TABLE_ID}  tproxy_port={TPROXY_PORT}")

    # ── 1. 路由策略 ──────────────────────────────────────
    # ip rule（幂等：先查再加）
    ip_rules = run("ip rule show", capture=True).stdout
    rule_marker = f"fwmark {mark_hex} lookup {ROUTE_TABLE_ID}"
    if rule_marker not in ip_rules:
        run(["ip", "rule", "add", "fwmark", mark_hex, "table", str(ROUTE_TABLE_ID)])
        print(f"   ✔ ip rule: fwmark {mark_hex} → table {ROUTE_TABLE_ID}")
    else:
        print(f"   ✔ ip rule 已存在，跳过")

    # ip route（幂等）
    rt = run(["ip", "route", "show", "table", str(ROUTE_TABLE_ID)],
             capture=True, check=False).stdout
    if "local 0.0.0.0/0" not in rt:
        run(["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo",
             "table", str(ROUTE_TABLE_ID)])
        print(f"   ✔ 路由表 {ROUTE_TABLE_ID}: local → lo")
    else:
        print(f"   ✔ 路由表 {ROUTE_TABLE_ID} 已存在，跳过")

    # ── 2. mangle 链 ─────────────────────────────────────
    if not _chain_exists("mangle", IPTABLES_CHAIN):
        _ipt("-N", IPTABLES_CHAIN)
    else:
        _ipt("-F", IPTABLES_CHAIN)   # 清空链内容（已确认是本脚本的链）

    # 规则：用注释标记（iptables 的 -m comment 模块）便于识别
    c = ["-m", "comment", "--comment", MARK_COMMENT]  # 注释参数

    # 已打标记的包返回（防循环）
    _ipt("-A", IPTABLES_CHAIN, "-m", "mark", "--mark", mark_hex, "-j", "RETURN")
    # 目标是本机地址的包返回（OUTPUT 链不支持 TPROXY）
    _ipt("-A", IPTABLES_CHAIN, "-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN")
    # 绕过直连网段
    for cidr in BYPASS_CIDRS:
        _ipt("-A", IPTABLES_CHAIN, "-d", cidr, "-j", "RETURN")
    # TCP TProxy
    _ipt("-A", IPTABLES_CHAIN, "-p", "tcp",
         "-j", "TPROXY", "--on-port", str(TPROXY_PORT), "--tproxy-mark", mark_hex)
    # UDP TProxy
    _ipt("-A", IPTABLES_CHAIN, "-p", "udp",
         "-j", "TPROXY", "--on-port", str(TPROXY_PORT), "--tproxy-mark", mark_hex)

    # 挂到 PREROUTING（幂等）
    if not _rule_exists("mangle", "PREROUTING", "-j", IPTABLES_CHAIN):
        _ipt("-A", "PREROUTING", "-j", IPTABLES_CHAIN)
    print(f"   ✔ mangle:{IPTABLES_CHAIN} 已挂载到 PREROUTING")

    # ── 3. nat 链：重定向 DNS ─────────────────────────────
    if not _chain_exists("nat", NAT_CHAIN):
        _ipt("-N", NAT_CHAIN, table="nat")
    else:
        _ipt("-F", NAT_CHAIN, table="nat")

    for cidr in BYPASS_CIDRS:
        _ipt("-A", NAT_CHAIN, "-d", cidr, "-j", "RETURN", table="nat")
    _ipt("-A", NAT_CHAIN, "-p", "udp", "--dport", "53",
         "-j", "REDIRECT", "--to-port", str(DNS_PORT), table="nat")
    _ipt("-A", NAT_CHAIN, "-p", "tcp", "--dport", "53",
         "-j", "REDIRECT", "--to-port", str(DNS_PORT), table="nat")

    if not _rule_exists("nat", "OUTPUT", "-j", NAT_CHAIN):
        _ipt("-A", "OUTPUT", "-j", NAT_CHAIN, table="nat")
    print(f"   ✔ nat:{NAT_CHAIN} 已挂载到 OUTPUT（DNS 重定向 → {DNS_PORT}）")

def clear_tproxy_rules():
    """
    精确清除本脚本创建的规则：
    · 只 detach + 删除本脚本创建的链
    · 只删除本脚本添加的 ip rule / ip route 条目
    · 不触碰任何其他规则
    """
    mark_hex = f"0x{TPROXY_MARK:x}"

    # mangle
    _ipt("-D", "PREROUTING", "-j", IPTABLES_CHAIN, check=False)
    _ipt("-F", IPTABLES_CHAIN, check=False)
    _ipt("-X", IPTABLES_CHAIN, check=False)

    # nat
    _ipt("-D", "OUTPUT", "-j", NAT_CHAIN, table="nat", check=False)
    _ipt("-F", NAT_CHAIN, table="nat", check=False)
    _ipt("-X", NAT_CHAIN, table="nat", check=False)

    # ip rule：精确匹配 mark + 路由表，不影响其他 rule
    run(["ip", "rule", "del", "fwmark", mark_hex, "table", str(ROUTE_TABLE_ID)],
        check=False)

    # ip route：精确删除本脚本在该表里加的那条
    run(["ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo",
         "table", str(ROUTE_TABLE_ID)], check=False)

    print("   ✔ iptables 规则已精确清除（其他规则未改动）")

# ═══════════════════════════════════════════════
#  Systemd 服务
# ═══════════════════════════════════════════════
def write_systemd_service(binary_path, config_path, core):
    if core == "mihomo":
        exec_start = f"{binary_path} -d {CONFIG_DIR}"
    else:
        exec_start = f"{binary_path} run -c {config_path}"

    script = Path(__file__).resolve()
    content = f"""\
[Unit]
Description=TProxy transparent proxy ({core})
Documentation=https://github.com/juewuy/ShellCrash
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/bin/python3 {script} _setup_rules
ExecStart={exec_start}
ExecStopPost=/usr/bin/python3 {script} _clear_rules
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=false
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    svc = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
    svc.write_text(content)
    run("systemctl daemon-reload")
    print(f"   ✔ systemd 服务: {svc}")
    return svc

# ═══════════════════════════════════════════════
#  主命令实现
# ═══════════════════════════════════════════════
def sep(title=""):
    width = 55
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'═'*pad} {title} {'═'*pad}")
    else:
        print("═" * width)

def cmd_install(core):
    check_root()
    check_deps()
    _enable_file_log()
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    sep(f"安装 TProxy ({core})")

    print("\n【1/4】备份现有防火墙规则")
    backup_iptables()

    print("\n【2/4】冲突检测")
    check_conflicts()

    print(f"\n【3/4】下载安装 {core} 内核")
    binary = install_mihomo() if core == "mihomo" else install_singbox()
    config = write_mihomo_config() if core == "mihomo" else write_singbox_config()

    print("\n【4/4】配置 systemd 服务")
    write_systemd_service(binary, config, core)

    save_state({
        "core": core,
        "binary": str(binary),
        "config": str(config),
        "installed_at": datetime.datetime.now().isoformat(),
    })

    sep("安装完成")
    print(f"""
  内核          {core}
  二进制        {binary}
  配置文件      {config}
  TProxy 端口   {TPROXY_PORT}
  HTTP/SOCKS5   {MIXED_PORT}
  Dashboard     http://127.0.0.1:{API_PORT}/ui
  防火墙备份    {BACKUP_FILE}

  ⚠️  请先编辑配置文件添加代理节点：
     sudo nano {config}

  然后启动服务：
     sudo python3 {sys.argv[0]} start
""")

def cmd_start():
    check_root()
    _enable_file_log()
    sep("启动 TProxy")
    print("\n【1/2】设置 iptables 规则")
    setup_tproxy_rules()
    print("\n【2/2】启动 systemd 服务")
    run(f"systemctl enable --now {SERVICE_NAME}")
    print(f"\n✅ {SERVICE_NAME} 已启动\n")
    run(f"systemctl status {SERVICE_NAME} --no-pager -l", check=False)

def cmd_stop():
    check_root()
    _enable_file_log()
    sep("停止 TProxy")
    run(f"systemctl stop {SERVICE_NAME}", check=False)
    print("\n清除 iptables 规则...")
    clear_tproxy_rules()
    print(f"\n✅ {SERVICE_NAME} 已停止\n")

def cmd_restart():
    check_root()
    _enable_file_log()
    sep("重启 TProxy")
    run(f"systemctl stop {SERVICE_NAME}", check=False)
    clear_tproxy_rules()
    setup_tproxy_rules()
    run(f"systemctl start {SERVICE_NAME}")
    print(f"\n✅ {SERVICE_NAME} 已重启\n")

def cmd_status():
    run(f"systemctl status {SERVICE_NAME} --no-pager -l", check=False)
    print("\n── iptables mangle PREROUTING ──")
    run("iptables -t mangle -L PREROUTING -n --line-numbers", check=False)
    print(f"\n── ip rule (mark=0x{TPROXY_MARK:x}) ──")
    r = run("ip rule show", capture=True, check=False)
    for line in r.stdout.splitlines():
        if f"0x{TPROXY_MARK:x}" in line or str(ROUTE_TABLE_ID) in line:
            print(" ", line)

def cmd_uninstall():
    check_root()
    _enable_file_log()
    sep("卸载 TProxy")

    if not confirm("\n确定要卸载并恢复原有防火墙规则吗？", default_yes=False):
        print("已取消。")
        return

    print("\n【1/4】停止服务")
    run(f"systemctl disable --now {SERVICE_NAME}", check=False)
    print("   ✔ 服务已停止")

    print("\n【2/4】清除 iptables 规则（精确清除，不影响其他规则）")
    clear_tproxy_rules()

    print("\n【3/4】恢复原有防火墙规则")
    restore_iptables()

    print("\n【4/4】删除文件")
    svc = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
    if svc.exists():
        svc.unlink()
        print(f"   ✔ 已删除 {svc}")
    run("systemctl daemon-reload")

    for binary in [INSTALL_DIR / "mihomo", INSTALL_DIR / "sing-box"]:
        if binary.exists():
            if confirm(f"   是否删除 {binary}？", default_yes=True):
                binary.unlink()
                print(f"   ✔ 已删除 {binary}")

    sep()
    print(f"""
✅ 卸载完成

  配置文件和防火墙备份保留在: {CONFIG_DIR}
  如需完全清理: sudo rm -rf {CONFIG_DIR}
""")

# ═══════════════════════════════════════════════
#  入口
# ═══════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TProxy 透明代理管理脚本（安全版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="更多帮助: https://github.com/juewuy/ShellCrash",
    )
    parser.add_argument("command", choices=[
        "install", "start", "stop", "restart", "status", "uninstall",
        "_setup_rules", "_clear_rules",   # 内部命令，供 systemd 调用
    ])
    parser.add_argument("--core", choices=["mihomo", "singbox"], default=CORE,
                        help=f"代理内核 (默认: {CORE})")
    args = parser.parse_args()

    dispatch = {
        "install":      lambda: cmd_install(args.core),
        "start":        cmd_start,
        "stop":         cmd_stop,
        "restart":      cmd_restart,
        "status":       cmd_status,
        "uninstall":    cmd_uninstall,
        "_setup_rules": lambda: (check_root(), setup_tproxy_rules()),
        "_clear_rules": lambda: (check_root(), clear_tproxy_rules()),
    }
    dispatch[args.command]()
