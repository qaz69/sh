#!/usr/bin/env python3
"""
mihomo TProxy 透明代理管理脚本
固定使用 TProxy 模式（iptables），不使用 TUN

用法:
  sudo python3 tproxy_setup.py install [--sub <订阅URL>]  # 安装
  sudo python3 tproxy_setup.py start                       # 启动
  sudo python3 tproxy_setup.py stop                        # 停止
  sudo python3 tproxy_setup.py restart                     # 重启
  sudo python3 tproxy_setup.py status                      # 状态
  sudo python3 tproxy_setup.py update-sub                  # 更新订阅
  sudo python3 tproxy_setup.py update-geo                  # 重新下载 geodata
  sudo python3 tproxy_setup.py uninstall                   # 卸载

安全特性:
  - 安装前自动备份 iptables/ip6tables，卸载时精确恢复
  - 只删除本脚本创建的链/规则，不触碰其他防火墙规则
  - geodata 在 iptables 设置前预下载（解决鸡蛋问题）
  - 配置测试通过后才启动服务
"""

import os, sys, json, shutil, subprocess, platform
import urllib.request, tarfile, gzip, tempfile
import argparse, datetime, logging, time
from pathlib import Path

# ═══════════════════════════════════════════════
#  常量配置
# ═══════════════════════════════════════════════
INSTALL_DIR    = Path("/usr/local/bin")
CONFIG_DIR     = Path("/etc/tproxy")
LOG_DIR        = Path("/var/log/tproxy")
SERVICE_NAME   = "tproxy"

# TProxy
TPROXY_PORT    = 7893
TPROXY_MARK    = 0x29
ROUTE_TABLE_ID = 529
IPTABLES_CHAIN = "SC_TPROXY"
NAT_CHAIN      = "SC_DNS_NAT"
DNS_PORT       = 1053      # mihomo dns listen 端口
MIXED_PORT     = 7890
API_PORT       = 9090

BYPASS_CIDRS = [
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4",
]

# Geodata 下载地址（主源 + 备用源）
GEODATA = {
    "GeoIP.dat":    ("https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
                     "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip.dat"),
    "GeoSite.dat":  ("https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
                     "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat"),
    "country.mmdb": ("https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
                     "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/country.mmdb"),
}

BACKUP_FILE    = CONFIG_DIR / "iptables_backup.rules"
BACKUP_V6_FILE = CONFIG_DIR / "ip6tables_backup.rules"
STATE_FILE     = CONFIG_DIR / ".state.json"

# ═══════════════════════════════════════════════
#  日志
# ═══════════════════════════════════════════════
log = logging.getLogger("tproxy")
log.setLevel(logging.DEBUG)
_sh = logging.StreamHandler(sys.stdout)
_sh.setFormatter(logging.Formatter("%(message)s"))
log.addHandler(_sh)

def _enable_file_log():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(LOG_DIR / "setup.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    log.addHandler(fh)

# ═══════════════════════════════════════════════
#  工具函数
# ═══════════════════════════════════════════════
def run(cmd, check=True, capture=False, input_data=None, silent=False):
    if isinstance(cmd, str):
        cmd = cmd.split()
    if not silent:
        log.debug(f"  $ {' '.join(str(c) for c in cmd)}")
    r = subprocess.run(cmd, capture_output=capture, text=True, check=False, input=input_data)
    if check and r.returncode != 0:
        err = (r.stderr or "").strip() or "(无错误输出)"
        raise RuntimeError(f"命令失败 [exit={r.returncode}]: {' '.join(str(c) for c in cmd)}\n  {err}")
    return r

def check_root():
    if os.geteuid() != 0:
        print("❌ 请用 root 运行: sudo python3 tproxy_setup.py <command>")
        sys.exit(1)

def check_deps():
    missing = [d for d in ["iptables","iptables-save","iptables-restore","ip"] if not shutil.which(d)]
    if missing:
        print(f"❌ 缺少依赖: {', '.join(missing)}  →  apt install -y iptables iproute2")
        sys.exit(1)

def confirm(prompt, default_yes=False):
    hint = "[Y/n]" if default_yes else "[y/N]"
    try:
        ans = input(f"{prompt} {hint}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default_yes
    return (ans == "" and default_yes) or ans in ("y", "yes")

def get_arch():
    m = platform.machine().lower()
    return {"x86_64":"amd64","amd64":"amd64","aarch64":"arm64","arm64":"arm64",
            "armv7l":"armv7","armv6l":"armv6","mips":"mips","mipsle":"mipsle",
            "mips64":"mips64","mips64le":"mips64le"}.get(m, m)

def sep(title=""):
    w = 58
    if title:
        pad = (w - len(title) - 2) // 2
        print(f"\n{'═'*pad} {title} {'═'*(w - pad - len(title) - 2)}")
    else:
        print("═" * w)

# ═══════════════════════════════════════════════
#  状态持久化
# ═══════════════════════════════════════════════
def save_state(data: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    s = load_state(); s.update(data)
    STATE_FILE.write_text(json.dumps(s, indent=2, ensure_ascii=False))

def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    except Exception:
        return {}

# ═══════════════════════════════════════════════
#  防火墙备份 / 恢复
# ═══════════════════════════════════════════════
def backup_iptables():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    for cmd, path in [("iptables-save", BACKUP_FILE), ("ip6tables-save", BACKUP_V6_FILE)]:
        if not shutil.which(cmd):
            continue
        r = run(cmd, capture=True, silent=True)
        path.write_text(r.stdout, encoding="utf-8")
        print(f"   ✔ {cmd} → {path}  ({len(r.stdout.splitlines())} 条规则)")
    save_state({"iptables_backup": str(BACKUP_FILE), "ip6tables_backup": str(BACKUP_V6_FILE)})

def restore_iptables():
    state = load_state()
    ok = False
    for cmd, key, fallback in [
        ("iptables-restore",  "iptables_backup",  BACKUP_FILE),
        ("ip6tables-restore", "ip6tables_backup",  BACKUP_V6_FILE),
    ]:
        path = Path(state.get(key, str(fallback)))
        if not path.exists() or not shutil.which(cmd):
            print(f"   ⚠  跳过 {cmd}（备份不存在）")
            continue
        run([cmd], input_data=path.read_text(encoding="utf-8"), silent=True)
        print(f"   ✔ {cmd} 恢复 ← {path}")
        ok = True
    if not ok:
        print("   ⚠  未找到备份文件，防火墙未恢复")

# ═══════════════════════════════════════════════
#  iptables TProxy 规则
# ═══════════════════════════════════════════════
def _ipt(*args, table="mangle", check=True):
    return run(["iptables", "-t", table] + list(args), check=check, capture=True, silent=True)

def _chain_exists(table, chain):
    return run(["iptables", "-t", table, "-L", chain, "-n"],
               check=False, capture=True, silent=True).returncode == 0

def _rule_exists(table, chain, *rule_args):
    return _ipt("-C", chain, *rule_args, table=table, check=False).returncode == 0

def setup_tproxy_rules():
    mark_hex = f"0x{TPROXY_MARK:x}"

    # 加载内核模块
    for mod in ["xt_TPROXY", "xt_mark", "xt_addrtype", "nf_tproxy_core"]:
        run(["modprobe", mod], check=False, capture=True, silent=True)

    # ── ip rule + ip route ────────────────────────
    ip_rules = run("ip rule show", capture=True, silent=True).stdout
    if f"fwmark {mark_hex} lookup {ROUTE_TABLE_ID}" not in ip_rules:
        run(["ip", "rule", "add", "fwmark", mark_hex, "table", str(ROUTE_TABLE_ID)], silent=True)
        print(f"   ✔ ip rule: fwmark {mark_hex} → table {ROUTE_TABLE_ID}")
    else:
        print(f"   ✔ ip rule 已存在，跳过")

    rt = run(["ip", "route", "show", "table", str(ROUTE_TABLE_ID)],
             capture=True, check=False, silent=True).stdout
    if "local 0.0.0.0/0" not in rt:
        run(["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo",
             "table", str(ROUTE_TABLE_ID)], silent=True)
        print(f"   ✔ 路由表 {ROUTE_TABLE_ID}: local → lo")
    else:
        print(f"   ✔ 路由表 {ROUTE_TABLE_ID} 已存在，跳过")

    # ── mangle 链（接管入站/转发流量）─────────────
    if not _chain_exists("mangle", IPTABLES_CHAIN):
        _ipt("-N", IPTABLES_CHAIN)
    else:
        _ipt("-F", IPTABLES_CHAIN)  # 已确认是本脚本的链，清空重建

    # 已标记的包直接返回（防死循环）
    _ipt("-A", IPTABLES_CHAIN, "-m", "mark", "--mark", mark_hex, "-j", "RETURN")
    # 目标是本机的包不走 TProxy
    _ipt("-A", IPTABLES_CHAIN, "-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN")
    # 直连网段
    for cidr in BYPASS_CIDRS:
        _ipt("-A", IPTABLES_CHAIN, "-d", cidr, "-j", "RETURN")
    # TCP / UDP → TProxy
    _ipt("-A", IPTABLES_CHAIN, "-p", "tcp",
         "-j", "TPROXY", "--on-port", str(TPROXY_PORT), "--tproxy-mark", mark_hex)
    _ipt("-A", IPTABLES_CHAIN, "-p", "udp",
         "-j", "TPROXY", "--on-port", str(TPROXY_PORT), "--tproxy-mark", mark_hex)
    # 挂到 PREROUTING（幂等）
    if not _rule_exists("mangle", "PREROUTING", "-j", IPTABLES_CHAIN):
        _ipt("-A", "PREROUTING", "-j", IPTABLES_CHAIN)
    print(f"   ✔ mangle:{IPTABLES_CHAIN} → PREROUTING")

    # ── nat 链（本机出站 DNS → mihomo DNS 端口）────
    # 注意：TProxy 只能处理 PREROUTING，本机出站走 OUTPUT
    # 本机进程发出的 DNS 需要用 nat REDIRECT 重定向到 mihomo
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
    print(f"   ✔ nat:{NAT_CHAIN} → OUTPUT  (DNS → {DNS_PORT})")

    # ── OUTPUT mangle（本机出站流量自身也需要打标记走代理）─
    OUTPUT_CHAIN = "SC_OUTPUT"
    if not _chain_exists("mangle", OUTPUT_CHAIN):
        _ipt("-N", OUTPUT_CHAIN)
    else:
        _ipt("-F", OUTPUT_CHAIN)

    # 本机 mihomo 自身流量跳过（避免循环）
    _ipt("-A", OUTPUT_CHAIN, "-m", "owner", "--uid-owner", "0", "-j", "RETURN")
    _ipt("-A", OUTPUT_CHAIN, "-m", "mark", "--mark", mark_hex, "-j", "RETURN")
    for cidr in BYPASS_CIDRS:
        _ipt("-A", OUTPUT_CHAIN, "-d", cidr, "-j", "RETURN")
    # 给本机出站包打标记，让 ip rule 把它路由回本机 TProxy
    _ipt("-A", OUTPUT_CHAIN, "-p", "tcp", "-j", "MARK", "--set-mark", mark_hex)
    _ipt("-A", OUTPUT_CHAIN, "-p", "udp", "-j", "MARK", "--set-mark", mark_hex)
    if not _rule_exists("mangle", "OUTPUT", "-j", OUTPUT_CHAIN):
        _ipt("-A", "OUTPUT", "-j", OUTPUT_CHAIN)
    print(f"   ✔ mangle:{OUTPUT_CHAIN} → OUTPUT  (本机流量打标记)")

def clear_tproxy_rules():
    """精确清除，只删本脚本创建的规则，不影响其他防火墙规则"""
    mark_hex = f"0x{TPROXY_MARK:x}"

    # mangle PREROUTING 链
    _ipt("-D", "PREROUTING", "-j", IPTABLES_CHAIN, check=False)
    _ipt("-F", IPTABLES_CHAIN, check=False)
    _ipt("-X", IPTABLES_CHAIN, check=False)

    # mangle OUTPUT 链
    _ipt("-D", "OUTPUT", "-j", "SC_OUTPUT", check=False)
    _ipt("-F", "SC_OUTPUT", check=False)
    _ipt("-X", "SC_OUTPUT", check=False)

    # nat OUTPUT 链
    _ipt("-D", "OUTPUT", "-j", NAT_CHAIN, table="nat", check=False)
    _ipt("-F", NAT_CHAIN, table="nat", check=False)
    _ipt("-X", NAT_CHAIN, table="nat", check=False)

    # ip rule / ip route（精确匹配，不影响其他条目）
    run(["ip", "rule", "del", "fwmark", mark_hex, "table", str(ROUTE_TABLE_ID)],
        check=False, silent=True)
    run(["ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo",
         "table", str(ROUTE_TABLE_ID)], check=False, silent=True)

    print("   ✔ iptables 规则已精确清除（其他防火墙规则未改动）")

# ═══════════════════════════════════════════════
#  Geodata 预下载
# ═══════════════════════════════════════════════
def _dl(url, dest, label=""):
    tmp = Path(str(dest) + ".tmp")
    try:
        def hook(blk, bs, total):
            if total > 0:
                print(f"\r     {label} {min(blk*bs*100//total,100)}%  ", end="", flush=True)
        urllib.request.urlretrieve(url, tmp, hook)
        print()
        tmp.rename(dest)
        return True
    except Exception as e:
        print(f"\r     ✘ 失败: {e}                  ")
        tmp.unlink(missing_ok=True)
        return False

def download_geodata(force=False):
    """
    在 iptables 规则设置 / mihomo 启动之前调用。
    保证 mihomo 启动时能直接读本地文件，不需要联网下载。
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    all_ok = True
    for fname, (primary, fallback) in GEODATA.items():
        dest = CONFIG_DIR / fname
        if dest.exists() and not force and dest.stat().st_size > 100_000:
            print(f"   ✔ {fname} 已存在 ({dest.stat().st_size // 1024} KB)，跳过")
            continue
        print(f"   ⬇ {fname}（主源）...")
        ok = _dl(primary, dest, fname)
        if not ok:
            print(f"   ⬇ {fname}（备用源）...")
            ok = _dl(fallback, dest, fname)
        if ok:
            print(f"   ✔ {fname}  {dest.stat().st_size // 1024} KB")
        else:
            print(f"   ✘ {fname} 下载失败！")
            all_ok = False
    return all_ok

# ═══════════════════════════════════════════════
#  订阅管理
# ═══════════════════════════════════════════════
def fetch_subscription(url: str, dest: Path):
    print(f"   ⬇ {url[:70]}...")
    tmp = Path(str(dest) + ".tmp")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ClashMeta/1.18"})
        with urllib.request.urlopen(req, timeout=30) as r:
            content = r.read()
        text = content.decode("utf-8", errors="replace")
        if "proxies" not in text and "proxy-providers" not in text:
            raise ValueError("不是有效的 Clash 配置（缺少 proxies/proxy-providers）")
        tmp.write_bytes(content)
        if dest.exists():
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            shutil.copy2(dest, dest.with_suffix(f".yaml.bak_{ts}"))
        tmp.rename(dest)
        print(f"   ✔ 订阅已保存 ({len(content)//1024} KB)")
        return True
    except Exception as e:
        tmp.unlink(missing_ok=True)
        print(f"   ✘ 订阅拉取失败: {e}")
        return False

def patch_config(config_path: Path):
    """
    对配置文件做两处修改：
    1. 把 geox-url 改成本地 file:// 路径，避免 mihomo 运行时联网下载
    2. 移除 tun 配置块（如果存在）
    """
    text = config_path.read_text(encoding="utf-8")
    changed = False

    # ── 移除 tun 块 ──────────────────────────────
    if "tun:" in text:
        lines = text.splitlines()
        new_lines = []
        in_tun = False
        for line in lines:
            if line.strip().startswith("tun:"):
                in_tun = True
                new_lines.append("# tun 已禁用（使用 TProxy 模式）")
                continue
            if in_tun:
                # tun 块以下一个非缩进行结束
                if line and not line[0].isspace() and not line.startswith("#"):
                    in_tun = False
                else:
                    continue
            new_lines.append(line)
        text = "\n".join(new_lines)
        changed = True
        print("   ✔ 已移除 tun 配置块")

    # ── 添加/替换 tproxy-port ────────────────────
    if "tproxy-port:" not in text:
        # 插在 mixed-port 行后面
        text = text.replace(
            "mixed-port:", f"tproxy-port: {TPROXY_PORT}\nmixed-port:", 1
        )
        changed = True
        print(f"   ✔ 已添加 tproxy-port: {TPROXY_PORT}")

    # ── geodata 改为本地路径 ──────────────────────
    local_geo = (
        f"geox-url:\n"
        f"  geoip: \"file://{CONFIG_DIR}/GeoIP.dat\"\n"
        f"  geosite: \"file://{CONFIG_DIR}/GeoSite.dat\"\n"
        f"  mmdb: \"file://{CONFIG_DIR}/country.mmdb\"\n"
        f"geo-auto-update: false\n"
    )
    if "geox-url:" in text:
        # 找到 geox-url 块，整块替换
        lines = text.splitlines()
        new_lines = []
        skip = False
        replaced = False
        for line in lines:
            if line.strip().startswith("geox-url:") and not replaced:
                new_lines.append(local_geo.rstrip())
                skip = True
                replaced = True
                changed = True
                continue
            if skip:
                # 跳过原来的 geox-url 子项（缩进行）和 geo-auto-update
                if (line and not line[0].isspace() and not line.startswith("#")
                        and not line.startswith("geo-")):
                    skip = False
                else:
                    continue
            new_lines.append(line)
        text = "\n".join(new_lines)
        print(f"   ✔ geodata 路径已改为本地 file:// 路径")
    else:
        # 没有 geox-url，在文件开头区域追加
        text = local_geo + "\n" + text
        changed = True
        print(f"   ✔ 已添加本地 geodata 路径配置")

    # ── enhanced-mode 改为 fake-ip（TProxy 推荐）─
    if "enhanced-mode: redir-host" in text:
        text = text.replace("enhanced-mode: redir-host", "enhanced-mode: fake-ip")
        # 补充 fake-ip-range
        if "fake-ip-range:" not in text:
            text = text.replace(
                "enhanced-mode: fake-ip",
                "enhanced-mode: fake-ip\n  fake-ip-range: \"198.18.0.1/16\""
            )
        changed = True
        print("   ✔ DNS enhanced-mode: redir-host → fake-ip")

    # ── ipv6 改为 false（TProxy IPv6 复杂，先关）─
    if "ipv6: true" in text:
        text = text.replace("ipv6: true", "ipv6: false")
        changed = True
        print("   ✔ ipv6: true → false（TProxy 模式下先关闭）")

    # ── ip 类规则加 no-resolve ───────────────────
    # RULE-SET,*_ip,xxx 末尾需要加 no-resolve 避免 DNS 循环
    import re
    def add_no_resolve(m):
        line = m.group(0)
        if "no-resolve" not in line:
            return line.rstrip() + ",no-resolve"
        return line
    new_text = re.sub(r"- RULE-SET,\w+_ip,\S+", add_no_resolve, text)
    if new_text != text:
        text = new_text
        changed = True
        print("   ✔ IP 类规则已添加 no-resolve")

    if changed:
        config_path.write_text(text, encoding="utf-8")
    return changed

# ═══════════════════════════════════════════════
#  下载安装 mihomo
# ═══════════════════════════════════════════════
def install_mihomo():
    arch = get_arch()
    print(f"   架构: {arch}")
    api = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
    req = urllib.request.Request(api, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.loads(r.read())
    tag = data["tag_name"]
    print(f"   版本: {tag}")
    url = None
    for asset in data["assets"]:
        name = asset["name"]
        if f"linux-{arch}" in name and name.endswith(".gz") \
                and "compatible" not in name and "go120" not in name:
            url = asset["browser_download_url"]
            break
    if not url:
        raise RuntimeError(f"未找到 linux-{arch} 的 mihomo 包")

    with tempfile.TemporaryDirectory() as tmp:
        gz = Path(tmp) / "mihomo.gz"
        _dl(url, gz, "mihomo")
        bin_path = Path(tmp) / "mihomo"
        with gzip.open(gz, "rb") as fi, open(bin_path, "wb") as fo:
            shutil.copyfileobj(fi, fo)
        dest = INSTALL_DIR / "mihomo"
        shutil.copy2(bin_path, dest)
        os.chmod(dest, 0o755)
    print(f"   ✔ mihomo {tag} → {dest}")
    return dest

# ═══════════════════════════════════════════════
#  Systemd 服务（TProxy 模式，ExecStartPre 设置 iptables）
# ═══════════════════════════════════════════════
def write_systemd_service(binary_path: Path):
    script = Path(__file__).resolve()
    content = f"""\
[Unit]
Description=mihomo TProxy transparent proxy
Documentation=https://github.com/MetaCubeX/mihomo
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStartPre=-/usr/bin/python3 {script} _setup_rules
ExecStart={binary_path} -d {CONFIG_DIR}
ExecStopPost=-/usr/bin/python3 {script} _clear_rules
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tproxy

[Install]
WantedBy=multi-user.target
"""
    svc = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
    svc.write_text(content)
    run("systemctl daemon-reload", silent=True)
    print(f"   ✔ {svc}")
    return svc

# ═══════════════════════════════════════════════
#  启动前检查
# ═══════════════════════════════════════════════
def preflight_checks(binary: Path, config: Path) -> bool:
    ok = True

    if not binary.exists():
        print(f"   ✘ 内核不存在: {binary}")
        ok = False
    else:
        print(f"   ✔ 内核: {binary}")

    if not config.exists():
        print(f"   ✘ 配置文件不存在: {config}")
        ok = False
    else:
        print(f"   ✔ 配置: {config}")

    # geodata 检查（缺失则自动补下）
    missing = [f for f in GEODATA if not (CONFIG_DIR/f).exists()
               or (CONFIG_DIR/f).stat().st_size < 100_000]
    if missing:
        print(f"   ⚠  geodata 缺失: {missing}，正在补下载...")
        download_geodata(force=False)
        still = [f for f in missing if not (CONFIG_DIR/f).exists()
                 or (CONFIG_DIR/f).stat().st_size < 100_000]
        if still:
            print(f"   ✘ 仍然缺失: {still}")
            ok = False
    else:
        print(f"   ✔ geodata 完整")

    # 配置语法测试
    if binary.exists() and config.exists():
        print("   ▷ 测试配置语法...")
        r = run([str(binary), "-d", str(CONFIG_DIR), "-t"],
                check=False, capture=True, silent=True)
        output = (r.stdout + r.stderr).strip()
        if r.returncode != 0:
            print(f"   ✘ 配置语法错误:\n{output}")
            ok = False
        else:
            # 过滤掉 info 日志，只打印 warning/error
            errors = [l for l in output.splitlines()
                      if any(x in l for x in ["error","fatal","warn","WARN","ERROR","FATAL"])]
            if errors:
                print(f"   ⚠  配置警告:\n" + "\n".join(f"     {l}" for l in errors))
            print("   ✔ 配置语法正常")

    return ok

# ═══════════════════════════════════════════════
#  主命令
# ═══════════════════════════════════════════════
def cmd_install(sub_url=None):
    check_root(); check_deps(); _enable_file_log()
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    sep("安装 mihomo TProxy")

    print("\n【1/5】备份现有防火墙规则")
    backup_iptables()

    print("\n【2/5】预下载 geodata（必须在启动前完成）")
    download_geodata(force=False)

    print("\n【3/5】配置文件")
    config_path = CONFIG_DIR / "config.yaml"
    if sub_url:
        fetch_subscription(sub_url, config_path)
    elif not config_path.exists():
        print(f"   ⚠  未提供订阅 URL，且配置文件不存在")
        print(f"   请先把配置放到 {config_path}，或用 --sub 指定订阅")
    if config_path.exists():
        print("   修正配置（移除 tun，添加 tproxy-port，本地 geodata 路径）...")
        patch_config(config_path)

    print("\n【4/5】安装 mihomo 内核")
    binary = install_mihomo()

    print("\n【5/5】配置 systemd 服务")
    write_systemd_service(binary)

    save_state({
        "binary":  str(binary),
        "config":  str(config_path),
        "sub_url": sub_url or "",
        "installed_at": datetime.datetime.now().isoformat(),
    })

    sep("安装完成")
    print(f"""
  配置文件   {config_path}
  Dashboard  http://127.0.0.1:{API_PORT}/ui
  日志       journalctl -u {SERVICE_NAME} -f

  启动:  sudo python3 {sys.argv[0]} start
""")

def cmd_start():
    check_root(); _enable_file_log()
    state = load_state()
    binary = Path(state.get("binary", str(INSTALL_DIR / "mihomo")))
    config = Path(state.get("config", str(CONFIG_DIR / "config.yaml")))
    sep("启动 mihomo")

    print("\n【1/3】启动前检查")
    if not preflight_checks(binary, config):
        print("\n❌ 预检失败，请修复后重试")
        sys.exit(1)
    print("   ✔ 预检通过")

    print("\n【2/3】设置 TProxy iptables 规则")
    setup_tproxy_rules()

    print("\n【3/3】启动 systemd 服务")
    r = run(f"systemctl enable --now {SERVICE_NAME}",
            check=False, capture=True, silent=True)
    if r.returncode != 0:
        print("\n❌ 服务启动失败！")
        run(f"systemctl status {SERVICE_NAME} --no-pager -l", check=False)
        print("\n── journalctl 最近 40 行 ──")
        run(f"journalctl -u {SERVICE_NAME} --no-pager -n 40", check=False)
        print(f"""
── 快速排查 ──
测试配置:  {binary} -d {CONFIG_DIR} -t
手动运行:  {binary} -d {CONFIG_DIR}
更新 geo:  sudo python3 {sys.argv[0]} update-geo
更新订阅:  sudo python3 {sys.argv[0]} update-sub
""")
        sys.exit(1)

    print(f"\n✅ mihomo 已启动（TProxy 模式）\n")
    run(f"systemctl status {SERVICE_NAME} --no-pager -l", check=False)

def cmd_stop():
    check_root(); _enable_file_log()
    sep("停止 mihomo")
    run(f"systemctl stop {SERVICE_NAME}", check=False, silent=True)
    print("\n清除 iptables 规则...")
    clear_tproxy_rules()
    print(f"\n✅ mihomo 已停止")

def cmd_restart():
    check_root(); _enable_file_log()
    state = load_state()
    binary = Path(state.get("binary", str(INSTALL_DIR / "mihomo")))
    config = Path(state.get("config", str(CONFIG_DIR / "config.yaml")))
    sep("重启 mihomo")

    print("\n【1/3】启动前检查")
    if not preflight_checks(binary, config):
        print("\n❌ 预检失败"); sys.exit(1)

    print("\n【2/3】重置 iptables 规则")
    run(f"systemctl stop {SERVICE_NAME}", check=False, silent=True)
    clear_tproxy_rules()
    setup_tproxy_rules()

    print("\n【3/3】启动服务")
    r = run(f"systemctl start {SERVICE_NAME}", check=False, capture=True, silent=True)
    if r.returncode != 0:
        print("❌ 重启失败！")
        run(f"journalctl -u {SERVICE_NAME} --no-pager -n 20", check=False)
        sys.exit(1)
    print(f"\n✅ mihomo 已重启")

def cmd_status():
    run(f"systemctl status {SERVICE_NAME} --no-pager -l", check=False)
    print("\n── iptables mangle PREROUTING ──")
    run("iptables -t mangle -L PREROUTING -n --line-numbers", check=False)
    print(f"\n── ip rule (fwmark=0x{TPROXY_MARK:x}) ──")
    r = run("ip rule show", capture=True, check=False, silent=True)
    for line in r.stdout.splitlines():
        if f"0x{TPROXY_MARK:x}" in line or str(ROUTE_TABLE_ID) in line:
            print(f"  {line}")

def cmd_update_sub():
    check_root(); _enable_file_log()
    state = load_state()
    sub_url = state.get("sub_url", "")
    config  = Path(state.get("config", str(CONFIG_DIR / "config.yaml")))
    if not sub_url:
        print("❌ 未保存订阅 URL，请用 --sub 参数重新 install")
        sys.exit(1)
    sep("更新订阅")
    print(f"\n{sub_url[:70]}...")
    ok = fetch_subscription(sub_url, config)
    if ok:
        patch_config(config)
        r = run(f"systemctl is-active {SERVICE_NAME}",
                check=False, capture=True, silent=True)
        if r.stdout.strip() == "active":
            print("\n服务运行中，正在重启以应用新配置...")
            run(f"systemctl restart {SERVICE_NAME}", check=False, silent=True)
        print("✅ 订阅已更新")

def cmd_update_geo():
    check_root(); _enable_file_log()
    sep("更新 geodata")
    r = run(f"systemctl is-active {SERVICE_NAME}",
            check=False, capture=True, silent=True)
    was_running = r.stdout.strip() == "active"
    if was_running:
        print("\n暂停服务（释放 DNS 劫持）...")
        run(f"systemctl stop {SERVICE_NAME}", check=False, silent=True)
        clear_tproxy_rules()
        time.sleep(1)
    print()
    download_geodata(force=True)
    if was_running:
        setup_tproxy_rules()
        run(f"systemctl start {SERVICE_NAME}", check=False, silent=True)
        print("✅ geodata 已更新，服务已重启")
    else:
        print("✅ geodata 已更新")

def cmd_uninstall():
    check_root(); _enable_file_log()
    sep("卸载 mihomo")
    if not confirm("\n确定要卸载并恢复原有防火墙规则吗？", default_yes=False):
        print("已取消。"); return

    print("\n【1/4】停止服务")
    run(f"systemctl disable --now {SERVICE_NAME}", check=False, silent=True)
    print("   ✔ 已停止")

    print("\n【2/4】清除 iptables 规则（精确清除）")
    clear_tproxy_rules()

    print("\n【3/4】恢复原有防火墙规则")
    restore_iptables()

    print("\n【4/4】删除文件")
    svc = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
    if svc.exists():
        svc.unlink(); print(f"   ✔ 删除 {svc}")
    run("systemctl daemon-reload", silent=True)
    for b in [INSTALL_DIR / "mihomo"]:
        if b.exists() and confirm(f"   删除 {b}？", default_yes=True):
            b.unlink(); print(f"   ✔ 删除 {b}")

    sep()
    print(f"\n✅ 卸载完成\n   配置保留在 {CONFIG_DIR}\n   完全清理: sudo rm -rf {CONFIG_DIR}\n")

# ═══════════════════════════════════════════════
#  TUI 交互菜单（curses）
# ═══════════════════════════════════════════════
import curses, textwrap, threading, io

# 颜色对编号
C_TITLE   = 1   # 标题栏：黑底青字
C_STATUS  = 2   # 状态栏
C_MENU    = 3   # 普通菜单项
C_SELECT  = 4   # 选中项：青底黑字
C_OK      = 5   # 绿色（运行中）
C_ERR     = 6   # 红色（停止/错误）
C_WARN    = 7   # 黄色（警告）
C_BORDER  = 8   # 边框色
C_LOG     = 9   # 日志文字

def _init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_TITLE,  curses.COLOR_BLACK,  curses.COLOR_CYAN)
    curses.init_pair(C_STATUS, curses.COLOR_BLACK,  curses.COLOR_WHITE)
    curses.init_pair(C_MENU,   curses.COLOR_WHITE,  -1)
    curses.init_pair(C_SELECT, curses.COLOR_BLACK,  curses.COLOR_CYAN)
    curses.init_pair(C_OK,     curses.COLOR_GREEN,  -1)
    curses.init_pair(C_ERR,    curses.COLOR_RED,    -1)
    curses.init_pair(C_WARN,   curses.COLOR_YELLOW, -1)
    curses.init_pair(C_BORDER, curses.COLOR_CYAN,   -1)
    curses.init_pair(C_LOG,    curses.COLOR_WHITE,  -1)

def _safe_addstr(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    available = w - x - 1
    if available <= 0:
        return
    try:
        win.addstr(y, x, text[:available], attr)
    except curses.error:
        pass

def _draw_box(win, title=""):
    h, w = win.getmaxyx()
    try:
        win.border(
            curses.ACS_VLINE, curses.ACS_VLINE,
            curses.ACS_HLINE, curses.ACS_HLINE,
            curses.ACS_ULCORNER, curses.ACS_URCORNER,
            curses.ACS_LLCORNER, curses.ACS_LRCORNER,
        )
    except curses.error:
        pass
    if title:
        t = f" {title} "
        x = max(2, (w - len(t)) // 2)
        _safe_addstr(win, 0, x, t, curses.color_pair(C_BORDER) | curses.A_BOLD)

def _get_service_status() -> tuple[str, int]:
    """返回 (状态字符串, 颜色对编号)"""
    r = subprocess.run(
        ["systemctl", "is-active", SERVICE_NAME],
        capture_output=True, text=True, check=False
    )
    s = r.stdout.strip()
    if s == "active":
        return "● 运行中", C_OK
    elif s == "activating":
        return "◑ 启动中", C_WARN
    elif s == "failed":
        return "✗ 已失败", C_ERR
    else:
        return "○ 已停止", C_ERR

def _get_geo_status() -> str:
    parts = []
    for fname in GEODATA:
        p = CONFIG_DIR / fname
        if p.exists() and p.stat().st_size > 100_000:
            parts.append(f"{fname} ✔")
        else:
            parts.append(f"{fname} ✘")
    return "  ".join(parts)

def _get_sub_url_short() -> str:
    url = load_state().get("sub_url", "")
    if not url:
        return "未设置"
    return url[:50] + ("..." if len(url) > 50 else "")

def _run_in_subwin(stdscr, title: str, func, *args, **kwargs):
    """
    在全屏子窗口中运行一个函数，捕获其 stdout 并实时滚动显示，
    完成后等待用户按任意键返回。
    """
    h, w = stdscr.getmaxyx()
    win = curses.newwin(h, w, 0, 0)
    win.keypad(True)
    _init_colors()

    # 标题栏
    _safe_addstr(win, 0, 0, " " * w, curses.color_pair(C_TITLE))
    _safe_addstr(win, 0, 2, f"  {title}", curses.color_pair(C_TITLE) | curses.A_BOLD)
    win.refresh()

    log_lines = []
    log_lock  = threading.Lock()
    done      = threading.Event()

    # 捕获 stdout 并重定向到日志行
    class LineCapture(io.TextIOBase):
        def write(self, s):
            for line in s.splitlines():
                line = line.strip()
                if line:
                    with log_lock:
                        log_lines.append(line)
            return len(s)
        def flush(self):
            pass

    def _draw_logs():
        inner_h = h - 4
        inner_w = w - 4
        with log_lock:
            visible = log_lines[-(inner_h):]
        for i, line in enumerate(visible):
            row = 2 + i
            # 根据关键词着色
            if any(x in line for x in ["✔", "✅", "SUCCESS", "已启动", "已停止", "已更新"]):
                attr = curses.color_pair(C_OK)
            elif any(x in line for x in ["✘", "❌", "error", "fatal", "ERROR", "FATAL"]):
                attr = curses.color_pair(C_ERR)
            elif any(x in line for x in ["⚠", "warn", "WARN", "警告"]):
                attr = curses.color_pair(C_WARN)
            elif line.startswith("  $"):
                attr = curses.color_pair(C_WARN) | curses.A_DIM
            else:
                attr = curses.color_pair(C_LOG)
            _safe_addstr(win, row, 2, line[:inner_w], attr)
        win.refresh()

    def _worker():
        old_stdout = sys.stdout
        sys.stdout = LineCapture()
        try:
            func(*args, **kwargs)
        except SystemExit:
            pass
        except Exception as e:
            with log_lock:
                log_lines.append(f"❌ 异常: {e}")
        finally:
            sys.stdout = old_stdout
            done.set()

    t = threading.Thread(target=_worker, daemon=True)
    t.start()

    while not done.is_set() or not done.wait(timeout=0.05):
        _draw_logs()
        if done.is_set():
            break

    _draw_logs()
    _safe_addstr(win, h - 1, 0, " " * w, curses.color_pair(C_STATUS))
    _safe_addstr(win, h - 1, 2, "按任意键返回菜单...", curses.color_pair(C_STATUS))
    win.refresh()
    win.getch()

def _input_dialog(stdscr, prompt: str, default: str = "") -> str:
    """弹出一个单行输入对话框，返回输入的字符串"""
    h, w = stdscr.getmaxyx()
    dh, dw = 5, min(w - 4, 80)
    dy = (h - dh) // 2
    dx = (w - dw) // 2
    win = curses.newwin(dh, dw, dy, dx)
    win.keypad(True)
    _draw_box(win, "输入")
    _safe_addstr(win, 1, 2, prompt[:dw-4], curses.color_pair(C_MENU))
    _safe_addstr(win, 2, 2, " " * (dw - 4), curses.color_pair(C_SELECT))
    curses.echo()
    curses.curs_set(1)
    win.refresh()
    try:
        buf = win.getstr(2, 2, dw - 5).decode("utf-8", errors="replace").strip()
    except Exception:
        buf = ""
    curses.noecho()
    curses.curs_set(0)
    return buf or default

def _confirm_dialog(stdscr, message: str) -> bool:
    """弹出确认对话框，返回 True/False"""
    h, w = stdscr.getmaxyx()
    lines = textwrap.wrap(message, width=min(w - 8, 60))
    dh = len(lines) + 4
    dw = min(w - 4, 64)
    dy = (h - dh) // 2
    dx = (w - dw) // 2
    win = curses.newwin(dh, dw, dy, dx)
    win.keypad(True)
    _draw_box(win, "确认")
    for i, line in enumerate(lines):
        _safe_addstr(win, 1 + i, 2, line, curses.color_pair(C_MENU))
    sel = 1  # 0=确定 1=取消
    while True:
        for idx, label in enumerate(["  确定  ", "  取消  "]):
            attr = curses.color_pair(C_SELECT) | curses.A_BOLD if idx == sel else curses.color_pair(C_MENU)
            _safe_addstr(win, dh - 2, 4 + idx * 12, label, attr)
        win.refresh()
        k = win.getch()
        if k in (curses.KEY_LEFT, curses.KEY_RIGHT, ord('\t')):
            sel = 1 - sel
        elif k in (curses.KEY_ENTER, 10, 13):
            return sel == 0
        elif k == 27:  # ESC
            return False

def _log_viewer(stdscr):
    """实时日志查看器（journalctl -f）"""
    h, w = stdscr.getmaxyx()
    win = curses.newwin(h, w, 0, 0)
    win.keypad(True)
    _safe_addstr(win, 0, 0, " " * w, curses.color_pair(C_TITLE))
    _safe_addstr(win, 0, 2, f"  实时日志 — {SERVICE_NAME}  (按 q 退出)",
                 curses.color_pair(C_TITLE) | curses.A_BOLD)
    win.refresh()

    lines = []
    proc  = subprocess.Popen(
        ["journalctl", "-u", SERVICE_NAME, "-f", "--no-pager", "-n", "50"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1
    )

    def _reader():
        for line in proc.stdout:
            lines.append(line.rstrip())
        proc.wait()

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    win.nodelay(True)

    while True:
        inner_h = h - 2
        visible = lines[-(inner_h):]
        for i, line in enumerate(visible):
            row = 1 + i
            if any(x in line for x in ["error", "fatal", "ERROR", "FATAL"]):
                attr = curses.color_pair(C_ERR)
            elif any(x in line for x in ["warn", "WARN"]):
                attr = curses.color_pair(C_WARN)
            elif "info" in line.lower():
                attr = curses.color_pair(C_OK) | curses.A_DIM
            else:
                attr = curses.color_pair(C_LOG)
            # 清行再写
            _safe_addstr(win, row, 0, " " * (w - 1), 0)
            _safe_addstr(win, row, 1, line[:w-2], attr)
        _safe_addstr(win, h - 1, 0, " " * w, curses.color_pair(C_STATUS))
        _safe_addstr(win, h - 1, 2, "q 退出  ↑↓ 滚动（自动跟随最新）",
                     curses.color_pair(C_STATUS))
        win.refresh()

        k = win.getch()
        if k in (ord('q'), ord('Q'), 27):
            proc.terminate()
            break
        time.sleep(0.2)

def _tui_main(stdscr):
    curses.curs_set(0)
    _init_colors()
    stdscr.keypad(True)

    MENU_ITEMS = [
        ("安装 mihomo",          "install"),
        ("▶  启动服务",           "start"),
        ("■  停止服务",           "stop"),
        ("↺  重启服务",           "restart"),
        ("📋  查看状态",          "status"),
        ("🔄  更新订阅",          "update-sub"),
        ("🌐  更新 Geodata",      "update-geo"),
        ("📜  实时日志",          "logs"),
        ("🗑  卸载",              "uninstall"),
        ("✕  退出",              "quit"),
    ]

    sel = 0

    while True:
        h, w = stdscr.getmaxyx()
        stdscr.erase()

        # ── 标题栏 ────────────────────────────────
        title = "  mihomo TProxy 管理面板  "
        stdscr.attron(curses.color_pair(C_TITLE) | curses.A_BOLD)
        stdscr.addstr(0, 0, " " * w)
        _safe_addstr(stdscr, 0, max(0, (w - len(title)) // 2), title,
                     curses.color_pair(C_TITLE) | curses.A_BOLD)
        stdscr.attroff(curses.color_pair(C_TITLE) | curses.A_BOLD)

        # ── 状态面板 ─────────────────────────────
        status_str, status_color = _get_service_status()
        panel_w = min(w - 4, 72)
        panel_x = (w - panel_w) // 2
        panel_y = 2
        try:
            pwin = curses.newwin(6, panel_w, panel_y, panel_x)
            _draw_box(pwin, "系统状态")
            state = load_state()
            binary = state.get("binary", str(INSTALL_DIR / "mihomo"))
            installed = "已安装" if Path(binary).exists() else "未安装"
            _safe_addstr(pwin, 1, 2, f"服务状态:  ", curses.color_pair(C_MENU))
            _safe_addstr(pwin, 1, 12, status_str, curses.color_pair(status_color) | curses.A_BOLD)
            _safe_addstr(pwin, 2, 2, f"内核状态:  {installed}", curses.color_pair(C_MENU))
            _safe_addstr(pwin, 3, 2, f"订阅地址:  {_get_sub_url_short()}", curses.color_pair(C_MENU))
            geo_ok = all((CONFIG_DIR/f).exists() and (CONFIG_DIR/f).stat().st_size > 100_000
                         for f in GEODATA)
            geo_str = "全部就绪 ✔" if geo_ok else "部分缺失 ✘"
            geo_color = C_OK if geo_ok else C_ERR
            _safe_addstr(pwin, 4, 2, f"Geodata:   ", curses.color_pair(C_MENU))
            _safe_addstr(pwin, 4, 12, geo_str, curses.color_pair(geo_color))
            pwin.refresh()
        except curses.error:
            pass

        # ── 菜单 ─────────────────────────────────
        menu_y = panel_y + 7
        menu_w = min(w - 4, 40)
        menu_x = (w - menu_w) // 2
        menu_h = len(MENU_ITEMS) + 2
        try:
            mwin = curses.newwin(menu_h, menu_w, menu_y, menu_x)
            _draw_box(mwin, "操作菜单")
            for i, (label, _) in enumerate(MENU_ITEMS):
                if i == sel:
                    attr = curses.color_pair(C_SELECT) | curses.A_BOLD
                    _safe_addstr(mwin, i + 1, 1, " " * (menu_w - 2), attr)
                    _safe_addstr(mwin, i + 1, 3, f"{label}", attr)
                else:
                    _safe_addstr(mwin, i + 1, 3, f"{label}", curses.color_pair(C_MENU))
            mwin.refresh()
        except curses.error:
            pass

        # ── 底部提示栏 ────────────────────────────
        hint = "  ↑↓ 移动   Enter 确认   q 退出  "
        stdscr.attron(curses.color_pair(C_STATUS))
        try:
            stdscr.addstr(h - 1, 0, " " * w)
        except curses.error:
            pass
        _safe_addstr(stdscr, h - 1, max(0, (w - len(hint)) // 2), hint,
                     curses.color_pair(C_STATUS))
        stdscr.attroff(curses.color_pair(C_STATUS))
        stdscr.refresh()

        # ── 按键处理 ─────────────────────────────
        k = stdscr.getch()

        if k in (curses.KEY_UP, ord('k')):
            sel = (sel - 1) % len(MENU_ITEMS)
        elif k in (curses.KEY_DOWN, ord('j')):
            sel = (sel + 1) % len(MENU_ITEMS)
        elif k in (curses.KEY_ENTER, 10, 13):
            _, action = MENU_ITEMS[sel]

            if action == "quit":
                break

            elif action == "logs":
                _log_viewer(stdscr)
                curses.curs_set(0)
                _init_colors()

            elif action == "install":
                sub = _input_dialog(stdscr,
                    "订阅 URL（留空使用已有配置）：",
                    load_state().get("sub_url", ""))
                curses.curs_set(0)
                _run_in_subwin(stdscr, "安装 mihomo",
                               cmd_install, sub or None)

            elif action == "update-sub":
                sub = _input_dialog(stdscr,
                    "订阅 URL（留空使用已保存的）：",
                    load_state().get("sub_url", ""))
                curses.curs_set(0)
                if sub:
                    save_state({"sub_url": sub})
                _run_in_subwin(stdscr, "更新订阅", cmd_update_sub)

            elif action == "uninstall":
                if _confirm_dialog(stdscr, "确定要卸载并恢复原有防火墙规则吗？"):
                    _run_in_subwin(stdscr, "卸载 mihomo", _tui_uninstall)

            elif action == "stop":
                if _confirm_dialog(stdscr, "确定要停止 mihomo 服务吗？"):
                    _run_in_subwin(stdscr, "停止服务", cmd_stop)

            elif action == "start":
                _run_in_subwin(stdscr, "启动服务", cmd_start)
            elif action == "restart":
                _run_in_subwin(stdscr, "重启服务", cmd_restart)
            elif action == "status":
                _run_in_subwin(stdscr, "服务状态", cmd_status)
            elif action == "update-geo":
                _run_in_subwin(stdscr, "更新 Geodata", cmd_update_geo)

        elif k in (ord('q'), ord('Q')):
            break

def _tui_uninstall():
    """TUI 版卸载（跳过 confirm，已在 dialog 确认）"""
    _enable_file_log()
    print("\n【1/4】停止服务")
    run(f"systemctl disable --now {SERVICE_NAME}", check=False, silent=True)
    print("   ✔ 已停止")
    print("\n【2/4】清除 iptables 规则")
    clear_tproxy_rules()
    print("\n【3/4】恢复原有防火墙规则")
    restore_iptables()
    print("\n【4/4】删除文件")
    svc = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
    if svc.exists():
        svc.unlink(); print(f"   ✔ 删除 {svc}")
    run("systemctl daemon-reload", silent=True)
    for b in [INSTALL_DIR / "mihomo"]:
        if b.exists():
            b.unlink(); print(f"   ✔ 删除 {b}")
    print("\n✅ 卸载完成")

def launch_tui():
    check_root()
    _enable_file_log()
    try:
        curses.wrapper(_tui_main)
    except KeyboardInterrupt:
        pass
    finally:
        # 确保终端恢复正常
        try:
            curses.endwin()
        except Exception:
            pass
    print("\n已退出 TUI 菜单。")

# ═══════════════════════════════════════════════
#  入口
# ═══════════════════════════════════════════════
if __name__ == "__main__":
    # 无参数 → 启动 TUI 菜单
    if len(sys.argv) == 1:
        launch_tui()
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description="mihomo TProxy 透明代理管理脚本  (无参数启动 TUI 菜单)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("command", choices=[
        "install", "start", "stop", "restart", "status",
        "update-sub", "update-geo", "uninstall",
        "_setup_rules", "_clear_rules",
        "menu",   # 显式启动 TUI
    ])
    parser.add_argument("--sub", default=None, help="订阅 URL")
    args = parser.parse_args()

    dispatch = {
        "menu":         launch_tui,
        "install":      lambda: cmd_install(args.sub),
        "start":        cmd_start,
        "stop":         cmd_stop,
        "restart":      cmd_restart,
        "status":       cmd_status,
        "update-sub":   cmd_update_sub,
        "update-geo":   cmd_update_geo,
        "uninstall":    cmd_uninstall,
        "_setup_rules": lambda: (check_root(), setup_tproxy_rules()),
        "_clear_rules": lambda: (check_root(), clear_tproxy_rules()),
    }
    dispatch[args.command]()
