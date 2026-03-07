#!/usr/bin/env python3
"""
dtop v7 — Debian 路由器监控  (top.py 统一风格终端界面)
  - 白字蓝底标题栏 / 状态栏，与 top.py 完全一致
  - 青色标签 + 白色数值，统一颜色体系
  - 蓝底节区标题行，替代原 htop 分隔线居中方式
  - CPU/Mem 进度条改用 █ ░ 填充风格
  - ─ 分隔线保留，颜色改为青色 dim
用法: sudo python3 dtop.py
"""

import curses
import time
import os
import re
import subprocess
from pathlib import Path
from collections import deque
from datetime import datetime

# =========================================================================
# Settings & Configuration
# =========================================================================

class Settings:
    WAN_IFACE        = "ppp0"
    LAN_IFACE        = "enp6s18"
    DNSMASQ_LEASES   = "/var/lib/misc/dnsmasq.leases"
    REFRESH_INTERVAL = 2
    SPARK_WIDTH      = 20

# =========================================================================
# Color Pair IDs  (top.py unified style)
# =========================================================================

class C:
    # ── 与 top.py / daetop.py / dae.py 完全相同的编号体系 ──
    TITLE     = 1   # white on blue   — 标题栏 / 状态栏 / 节区标题
    GOOD      = 2   # green           — 进度条填充 / 链路正常
    WARN      = 3   # yellow          — 警告 / 中等
    BAD       = 4   # red             — 错误 / 超限
    NODE      = 5   # 252 light grey  — 次要文字
    DIM       = 6   # 240 dark grey   — 暗色辅助
    NET       = 7   # blue            — 上传 / WAN
    HOST      = 8   # white           — 主标题文字
    PORT      = 9   # 242 mid grey    — 端口 / 次要
    HDR       = 10  # cyan            — 表头 / 标签
    SEP       = 11  # 240 dark grey   — 分隔线
    LABEL     = 12  # green           — CPU/Mem 标签
    HL        = 15  # black on yellow — 高亮
    # ── 蓝底变体（节区标题行右侧提示） ──
    TITLE_HDR = 16  # cyan on blue
    TITLE_WARN= 17  # yellow on blue
    TITLE_BAD = 18  # red on blue
    TITLE_DIM = 19  # white on blue
    # ── 语义别名（供 render 使用，映射到上面） ──
    CPU_USR   = GOOD   # green bar
    CPU_SYS   = BAD    # red bar
    CPU_IO    = NET    # blue bar
    MEM_USED  = GOOD
    MEM_BUF   = NET
    MEM_CAC   = WARN
    SWAP      = BAD
    VALUE     = HOST
    SEC_BAR   = TITLE
    HDR_BAR   = TITLE
    SUB_BAR   = TITLE
    LINK_UP   = GOOD
    LINK_DN   = BAD
    WAN_ACC   = NET
    LAN_ACC   = GOOD
    RX        = GOOD
    TX        = BAD
    SPK_RX    = GOOD
    SPK_TX    = BAD
    FOOTER    = TITLE
    NFT_ACC   = HDR
    DHCP_HDR  = TITLE
    BRACKET   = HOST
    ALT_ROW   = DIM
    PROC_GRN  = GOOD

# =========================================================================
# Platform Helpers
# =========================================================================

def read_file(path, default=""):
    try:
        return Path(path).read_text().strip()
    except Exception:
        return default

def run(cmd, default=""):
    try:
        return subprocess.check_output(cmd, shell=True,
                                       stderr=subprocess.DEVNULL,
                                       timeout=3).decode().strip()
    except Exception:
        return default

def disp_width(s):
    w = 0
    for ch in str(s):
        cp = ord(ch)
        if (0x1100 <= cp <= 0x115F or 0x2E80 <= cp <= 0x9FFF
                or 0xAC00 <= cp <= 0xD7AF or 0xFF00 <= cp <= 0xFF60
                or 0x3000 <= cp <= 0x303F):
            w += 2
        else:
            w += 1
    return w

def pad_right(s, width):
    s = str(s)
    dw = disp_width(s)
    if dw < width:
        s += ' ' * (width - dw)
    return s

def fmt_bytes(val, rate=False):
    val = max(0, val)
    s = "/s" if rate else ""
    if val < 1024:        return f"{val:.0f} B{s}"
    if val < 1 << 20:     return f"{val/1024:.1f} K{s}"
    if val < 1 << 30:     return f"{val/(1<<20):.2f} M{s}"
    return                       f"{val/(1<<30):.3f} G{s}"

def fmt_up(sec_str):
    s = max(0, int(float(sec_str)))
    d, s = divmod(s, 86400)
    h, s = divmod(s,  3600)
    m, s = divmod(s,    60)
    return f"{d}d {h:02d}:{m:02d}:{s:02d}" if d else f"{h:02d}:{m:02d}:{s:02d}"

def sparkline(hist, width=Settings.SPARK_WIDTH):
    BLOCKS = " ▁▂▃▄▅▆▇█"
    data = list(hist)[-width:]
    if not data or max(data) == 0:
        return "▁" * len(data) + " " * (width - len(data))
    mx = max(data)
    out = "".join(BLOCKS[int(v / mx * (len(BLOCKS)-1))] for v in data)
    return out.ljust(width)

# =========================================================================
# Data Collectors
# =========================================================================

class CPUCollector:
    def __init__(self):
        self._prev = self._read()
        self.history = deque(maxlen=Settings.SPARK_WIDTH)
        self.cores   = []

    def _read(self):
        stats = {}
        for line in read_file("/proc/stat").splitlines():
            if line.startswith("cpu"):
                p = line.split()
                stats[p[0]] = list(map(int, p[1:9]))
        return stats

    def _load(self, cur, prev):
        d = [c - p for c, p in zip(cur, prev)]
        tot  = sum(d)
        idle = d[3] + d[4]
        if not tot:
            return 0.0, 0.0, 0.0
        pct = max(0.0, min(100.0, 100.0*(tot-idle)/tot))
        usr = max(0.0, min(100.0, 100.0*d[0]/tot))
        sys = max(0.0, min(100.0, 100.0*d[2]/tot))
        return round(pct,1), round(usr,1), round(sys,1)

    def update(self):
        cur = self._read()
        res = []
        for k in sorted(cur):
            if k in self._prev:
                res.append((k,) + self._load(cur[k], self._prev[k]))
        self._prev = cur
        if res:
            self.history.append(res[0][1])
            self.cores = res[1:]
            return res[0]
        return ("cpu", 0.0, 0.0, 0.0)

class MemoryCollector:
    def update(self):
        m = {}
        for line in read_file("/proc/meminfo").splitlines():
            p = line.split()
            if len(p) >= 2:
                m[p[0].rstrip(":")] = int(p[1]) * 1024
        tot = m.get("MemTotal", 0)
        free = m.get("MemFree", 0)
        buf  = m.get("Buffers", 0)
        cac  = m.get("Cached", 0) + m.get("SReclaimable", 0)
        used = max(0, tot - free - buf - cac)
        st   = m.get("SwapTotal", 0)
        su   = st - m.get("SwapFree", 0)
        return {"tot":tot,"used":used,"buf":buf,"cac":cac,
                "avail":m.get("MemAvailable",free),"st":st,"su":su}

class NetworkCollector:
    def __init__(self):
        self._prev = {}
        self.rx_hist = {Settings.WAN_IFACE: deque(maxlen=Settings.SPARK_WIDTH),
                        Settings.LAN_IFACE: deque(maxlen=Settings.SPARK_WIDTH)}
        self.tx_hist = {Settings.WAN_IFACE: deque(maxlen=Settings.SPARK_WIDTH),
                        Settings.LAN_IFACE: deque(maxlen=Settings.SPARK_WIDTH)}

    def _read(self):
        stats = {}
        for line in read_file("/proc/net/dev").splitlines()[2:]:
            p = line.split()
            if len(p) >= 10:
                stats[p[0].rstrip(":")] = (int(p[1]), int(p[9]))
        return stats

    def update(self, dt):
        cur = self._read()
        res = {}
        for iface in (Settings.WAN_IFACE, Settings.LAN_IFACE):
            if iface in cur and iface in self._prev:
                rx = max(0, (cur[iface][0] - self._prev[iface][0]) / dt)
                tx = max(0, (cur[iface][1] - self._prev[iface][1]) / dt)
            else:
                rx = tx = 0
            trx = cur.get(iface, (0,0))[0]
            ttx = cur.get(iface, (0,0))[1]
            res[iface] = {"rx":rx,"tx":tx,"trx":trx,"ttx":ttx}
            self.rx_hist[iface].append(rx)
            self.tx_hist[iface].append(tx)
        self._prev = cur
        return res

    def ip(self, iface):
        return run(f"ip -4 addr show {iface} 2>/dev/null|grep 'inet '|awk '{{print $2}}'", "N/A")

    def mac(self, iface):
        v = read_file(f"/sys/class/net/{iface}/address", "").strip()
        if not v or v == "00:00:00:00:00:00":
            return ""
        return v

    def state(self, iface):
        operstate = read_file(f"/sys/class/net/{iface}/operstate", "down").strip()
        if operstate == "up":
            return "up"
        ip_out = run(f"ip -4 addr show {iface} 2>/dev/null | grep 'inet '")
        if ip_out.strip():
            return "up"
        carrier = read_file(f"/sys/class/net/{iface}/carrier", "0").strip()
        if carrier == "1":
            return "carrier"
        return "down"

class DiskIOCollector:
    def __init__(self):
        self._prev = {}
        self.r_hist = deque(maxlen=Settings.SPARK_WIDTH)
        self.w_hist = deque(maxlen=Settings.SPARK_WIDTH)

    def _read(self):
        s = {'r':0,'w':0}
        for line in read_file("/proc/diskstats").splitlines():
            p = line.split()
            if len(p) >= 14 and re.match(r"^(sd[a-z]|vd[a-z]|nvme\d+n\d+|mmcblk\d+)$", p[2]):
                s['r'] += int(p[5])
                s['w'] += int(p[9])
        return s

    @staticmethod
    def _disk_usage():
        """
        读取所有已挂载的真实文件系统使用情况（排除 tmpfs/devtmpfs/overlay 等虚拟 fs）。
        返回列表: [{"mount": "/", "dev": "sda1", "total": N, "used": N, "free": N}, ...]
        """
        SKIP_FS = {"tmpfs","devtmpfs","sysfs","proc","cgroup","cgroup2",
                   "overlay","aufs","squashfs","devpts","hugetlbfs",
                   "mqueue","securityfs","pstore","bpf","tracefs",
                   "debugfs","configfs","fusectl","fuse.lxcfs","nsfs"}
        mounts = []
        seen_devs = set()
        try:
            for line in read_file("/proc/mounts").splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                dev, mount, fstype = parts[0], parts[1], parts[2]
                if fstype in SKIP_FS:
                    continue
                if dev.startswith("//") or dev == "none":
                    continue
                # 去重（同一设备多次挂载只取第一个）
                real_dev = dev.split("/")[-1]
                if real_dev in seen_devs:
                    continue
                seen_devs.add(real_dev)
                try:
                    import os as _os
                    st = _os.statvfs(mount)
                    total = st.f_blocks * st.f_frsize
                    free  = st.f_bavail * st.f_frsize
                    used  = total - st.f_bfree * st.f_frsize
                    if total > 0:
                        mounts.append({
                            "mount": mount,
                            "dev":   real_dev,
                            "total": total,
                            "used":  used,
                            "free":  free,
                        })
                except Exception:
                    pass
        except Exception:
            pass
        # 按挂载点排序，/ 优先
        mounts.sort(key=lambda x: (x["mount"] != "/", x["mount"]))
        return mounts

    def update(self, dt):
        cur = self._read()
        rr = max(0,(cur['r']-self._prev.get('r',cur['r']))*512/dt) if self._prev else 0
        wr = max(0,(cur['w']-self._prev.get('w',cur['w']))*512/dt) if self._prev else 0
        self.r_hist.append(rr)
        self.w_hist.append(wr)
        self._prev = cur
        return {"rr":rr,"wr":wr,"tr":cur['r']*512,"tw":cur['w']*512,
                "mounts": self._disk_usage()}

class DHCPCollector:
    # 常见的 dnsmasq 租约文件路径（按优先级排列）
    _LEASE_CANDIDATES = [
        "/var/lib/misc/dnsmasq.leases",       # Debian/Ubuntu 默认
        "/var/lib/dnsmasq/dnsmasq.leases",    # 部分发行版
        "/var/lib/dnsmasq/leases",
        "/tmp/dnsmasq.leases",                # OpenWrt / 嵌入式
        "/tmp/dhcp.leases",                   # OpenWrt 旧版
        "/var/db/dnsmasq.leases",             # BSD 系
        "/var/run/dnsmasq/dnsmasq.leases",
        "/var/run/dnsmasq.leases",
    ]

    # dnsmasq 配置文件扫描路径
    _CONF_CANDIDATES = [
        "/etc/dnsmasq.conf",
        "/etc/dnsmasq.d/",
        "/etc/dnsmasq.d/soft-router.conf",    # debian.py 写入的配置
    ]

    _cached_lease_file: str = ""   # 缓存已找到的路径，避免每次重扫

    @classmethod
    def _find_lease_file(cls) -> str:
        """
        按以下顺序探测租约文件位置：
        1. 缓存命中且文件仍存在 → 直接返回
        2. 扫描 dnsmasq 配置文件，提取 dhcp-leasefile= 指令
        3. 逐一尝试 _LEASE_CANDIDATES 路径
        4. 通过 `dnsmasq --help` 查找编译期默认路径
        5. 全部失败返回空串
        """
        # 1. 缓存命中
        if cls._cached_lease_file and os.path.isfile(cls._cached_lease_file):
            return cls._cached_lease_file

        # 2. 解析配置文件中的 dhcp-leasefile=
        conf_files = []
        for p in cls._CONF_CANDIDATES:
            if os.path.isdir(p):
                try:
                    for fn in os.listdir(p):
                        if fn.endswith(".conf"):
                            conf_files.append(os.path.join(p, fn))
                except OSError:
                    pass
            elif os.path.isfile(p):
                conf_files.append(p)

        for cf in conf_files:
            try:
                for line in Path(cf).read_text(errors="replace").splitlines():
                    line = line.strip()
                    if line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    if k.strip() == "dhcp-leasefile" and v.strip():
                        candidate = v.strip()
                        if os.path.isfile(candidate):
                            cls._cached_lease_file = candidate
                            return candidate
            except OSError:
                pass

        # 3. 逐一尝试已知候选路径
        for p in cls._LEASE_CANDIDATES:
            if os.path.isfile(p):
                cls._cached_lease_file = p
                return p

        # 4. 尝试通过 dnsmasq --help 找编译期默认
        try:
            out = subprocess.check_output(
                ["dnsmasq", "--help"], stderr=subprocess.STDOUT, timeout=2
            ).decode(errors="replace")
            m = re.search(r"lease(?:file)?\s+([/\w.]+\.leases)", out)
            if m and os.path.isfile(m.group(1)):
                cls._cached_lease_file = m.group(1)
                return m.group(1)
        except Exception:
            pass

        # 5. 实在找不到，清空缓存，下次再试
        cls._cached_lease_file = ""
        return ""

    def update(self):
        leases = []
        lease_file = self._find_lease_file()
        source_hint = os.path.basename(lease_file) if lease_file else ""

        if lease_file:
            try:
                with open(lease_file) as f:
                    for line in f:
                        p = line.strip().split()
                        if len(p) < 4:
                            continue
                        try:
                            exp = int(p[0])
                        except ValueError:
                            continue
                        rem = exp - int(time.time())
                        status = "永久" if exp == 0 else ("已过期" if rem < 0 else fmt_up(rem))
                        leases.append({
                            "ip":   p[2],
                            "mac":  p[1],
                            "host": p[3] if p[3] != "*" else "(未知)",
                            "exp":  status,
                        })
            except Exception:
                # 文件可能刚被 dnsmasq 重写，清空缓存，下次重新探测
                self.__class__._cached_lease_file = ""

        def key(l):
            try:
                return tuple(int(o) for o in l["ip"].split("."))
            except Exception:
                return (0,)

        # 把文件路径提示附在返回值里，让渲染层可以显示
        # 用子类而非裸 list，否则给 list 附加属性会 AttributeError
        class LeaseList(list): pass
        result = LeaseList(sorted(leases, key=key))
        result._source = source_hint
        return result

class FirewallCollector:
    """
    自动检测防火墙后端，优先级: nftables → iptables → 两者均无
    兼容策略：
      - 若 nft 可用且有规则 → nftables 模式
      - 若 iptables 可用且有规则 → iptables 模式
      - 两者都有规则 → 均显示
    """

    _backend: str = ""   # 缓存检测结果："nft" / "ipt" / "both" / ""

    @classmethod
    def _detect_backend(cls) -> str:
        if cls._backend:
            return cls._backend

        has_nft = bool(run("which nft 2>/dev/null"))
        has_ipt = bool(run("which iptables 2>/dev/null"))

        nft_active = False
        ipt_active = False

        if has_nft:
            out = run("nft list ruleset 2>/dev/null")
            nft_active = bool(re.search(r"table\s+\w+\s+\w+", out))

        if has_ipt:
            out = run("iptables -L -n --line-numbers 2>/dev/null | head -20")
            # iptables 有非空 chain（除默认策略外还有规则）视为活跃
            ipt_active = bool(re.search(r"^\d+\s+", out, re.M))

        if nft_active and ipt_active:
            cls._backend = "both"
        elif nft_active:
            cls._backend = "nft"
        elif ipt_active:
            cls._backend = "ipt"
        elif has_nft:
            cls._backend = "nft"   # 安装了但无规则
        elif has_ipt:
            cls._backend = "ipt"
        else:
            cls._backend = "none"

        return cls._backend

    @staticmethod
    def _collect_nft() -> dict:
        out = run("nft list ruleset 2>/dev/null")
        tables = re.findall(r"table\s+(\w+)\s+(\w+)", out)
        chains = len(re.findall(r"chain\s+\w+", out))
        rules  = len(re.findall(r"^\s+\w+.*;\s*$", out, re.M))
        return {"backend":"nftables","tables":tables,"chains":chains,"rules":rules}

    @staticmethod
    def _collect_ipt() -> dict:
        """
        解析 iptables -L -n -v 获取链数和规则数。
        支持 iptables-legacy 和 iptables-nft (iptables-over-nftables)。
        """
        tables_names = []
        total_chains = 0
        total_rules  = 0

        for tbl in ("filter", "nat", "mangle", "raw"):
            out = run(f"iptables -t {tbl} -L -n 2>/dev/null")
            if not out:
                continue
            chains_in_tbl = re.findall(r"^Chain\s+(\S+)", out, re.M)
            if not chains_in_tbl:
                continue
            tables_names.append(("ip", tbl))
            total_chains += len(chains_in_tbl)
            # 规则行：不以 Chain/target/pkts 开头，且非空行
            rules_in_tbl = [l for l in out.splitlines()
                            if l and not l.startswith("Chain")
                            and not l.startswith("target")
                            and not l.startswith("pkts")]
            total_rules += len(rules_in_tbl)

        # 尝试 ip6tables
        for tbl in ("filter", "nat"):
            out = run(f"ip6tables -t {tbl} -L -n 2>/dev/null")
            if not out:
                continue
            chains_in_tbl = re.findall(r"^Chain\s+(\S+)", out, re.M)
            if chains_in_tbl:
                tables_names.append(("ip6", tbl))
                total_chains += len(chains_in_tbl)

        # 检测是否是 iptables-over-nftables
        xt_ver = run("iptables --version 2>/dev/null")
        backend_label = "iptables"
        if "nf_tables" in xt_ver or "nft" in xt_ver.lower():
            backend_label = "iptables(nft)"

        return {"backend": backend_label,
                "tables": tables_names,
                "chains": total_chains,
                "rules":  total_rules}

    def update(self):
        backend = self._detect_backend()
        cnt = read_file("/proc/sys/net/netfilter/nf_conntrack_count","?")
        mx  = read_file("/proc/sys/net/netfilter/nf_conntrack_max","?")

        if backend == "both":
            nft_data = self._collect_nft()
            ipt_data = self._collect_ipt()
            result = {
                "backend":  "nftables + iptables",
                "tables":   nft_data["tables"],
                "chains":   nft_data["chains"],
                "rules":    nft_data["rules"],
                "ipt":      ipt_data,
                "cnt": cnt, "mx": mx,
            }
        elif backend == "nft":
            result = {**self._collect_nft(), "cnt":cnt, "mx":mx, "ipt":None}
        elif backend == "ipt":
            ipt = self._collect_ipt()
            result = {**ipt, "tables": ipt["tables"],
                      "chains": ipt["chains"], "rules": ipt["rules"],
                      "cnt":cnt, "mx":mx, "ipt":ipt}
        else:
            result = {"backend":"未检测到防火墙",
                      "tables":[],"chains":0,"rules":0,
                      "cnt":cnt,"mx":mx,"ipt":None}

        return result

class SystemCollector:
    """
    温度采集策略（按优先级依次尝试）：
    1. PVE 宿主机穿透 — 通过 QEMU Guest Agent (qemu-guest-agent) 读取宿主 sensors
    2. PVE 宿主机穿透 — 通过 /dev/mem 或 /sys/bus/pci/... 读取 coretemp
    3. VM 内 /sys/class/thermal/thermal_zoneN  (KVM 暴露的虚拟温度，通常无效)
    4. lm-sensors (sensors 命令) — 取最高 CPU 核心温度
    5. 全部失败 → N/A
    i350 网卡温度：
    - 通过 ethtool -m <iface> 读取光模块温度（i350 SFP 口支持）
    - 通过 lm-sensors / hwmon 读取 i350 SMBus 温度 (i350bb 模块)
    """

    # ── PVE Guest Agent 穿透宿主机温度 ──────────────────────────────
    @staticmethod
    def _temp_via_guest_agent() -> str:
        """
        通过 qemu-guest-agent 向宿主 PVE 发 guest-exec 请求。
        需要宿主安装了 qemu-guest-agent 且虚拟机开启了 ga 通道。
        返回形如 "45.0°C" 或 "" (失败)。
        """
        # 尝试通过 /dev/virtio-ports/org.qemu.guest_agent.0 或 /dev/vport0p1
        agent_paths = [
            "/dev/virtio-ports/org.qemu.guest_agent.0",
            "/dev/vport0p1",
        ]
        for p in agent_paths:
            if not os.path.exists(p):
                continue
            # guest-agent JSON-RPC: execute sensors on host via guest-exec
            # 注意：标准 qemu-ga 不直接支持宿主 exec，
            # 需宿主侧配置 guest-exec 白名单（PVE 默认未开启）。
            # 此处改为更通用的方案：读取 PVE 通过 balloon/hw-info 暴露的温度。
            break

        # 更可靠方案：通过 pve-qemu-kvm 的 hw-info virtio channel
        # 若宿主 PVE 安装了 pve-manager 并配置了 hw-temp passthrough
        hw_temp_path = "/sys/bus/pci/devices"
        # 尝试读取 coretemp via hwmon（有时 PVE 会把 hwmon passthrough 给 VM）
        try:
            import glob
            patterns = [
                "/sys/devices/virtual/hwmon/hwmon*/temp*_input",
                "/sys/class/hwmon/hwmon*/temp*_input",
            ]
            best = 0.0
            found = False
            for pat in patterns:
                for f in sorted(glob.glob(pat)):
                    try:
                        label_f = f.replace("_input", "_label")
                        label = Path(label_f).read_text().strip() if os.path.exists(label_f) else ""
                        # 跳过非 CPU 类温度
                        if label and any(x in label.lower() for x in ("fan", "volt", "curr", "power")):
                            continue
                        val = int(Path(f).read_text().strip())
                        if 1000 <= val <= 150000:   # 合理范围 1~150°C
                            best = max(best, val / 1000.0)
                            found = True
                    except Exception:
                        pass
            if found and best > 0:
                return f"{best:.1f}°C"
        except Exception:
            pass
        return ""

    @staticmethod
    def _temp_via_pve_ssh() -> str:
        """
        尝试通过 SSH 读取 PVE 宿主机温度（需要配置无密码 SSH）。
        仅当环境变量 DTOP_PVE_HOST 已设置时才生效。
        """
        pve_host = os.environ.get("DTOP_PVE_HOST", "")
        if not pve_host:
            return ""
        try:
            out = subprocess.check_output(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=2",
                 "-o", "StrictHostKeyChecking=no",
                 pve_host,
                 "sensors -u 2>/dev/null | awk '/temp[0-9]_input/{if($2>max)max=$2} END{print max}'"],
                stderr=subprocess.DEVNULL, timeout=3
            ).decode().strip()
            val = float(out)
            if 0 < val < 150:
                return f"{val:.1f}°C(PVE)"
        except Exception:
            pass
        return ""

    @staticmethod
    def _temp_via_thermal_zone() -> str:
        """读 /sys/class/thermal/thermal_zoneN — VM 内通常无效，当兜底用"""
        for i in range(10):
            t = read_file(f"/sys/class/thermal/thermal_zone{i}/temp", "")
            typ = read_file(f"/sys/class/thermal/thermal_zone{i}/type", "")
            # 跳过 acpitz / acpi 类型，它们在 VM 里几乎都是假值
            if typ.lower().startswith("acpi"):
                continue
            if t.isdigit():
                val = int(t) / 1000.0
                if 0 < val < 150:
                    return f"{val:.1f}°C"
        # 兜底：取任意 thermal zone
        for i in range(10):
            t = read_file(f"/sys/class/thermal/thermal_zone{i}/temp", "")
            if t.isdigit():
                val = int(t) / 1000.0
                if 0 < val < 150:
                    return f"{val:.1f}°C"
        return ""

    @staticmethod
    def _temp_via_sensors() -> str:
        """lm-sensors sensors 命令 — 取最高 CPU Package/Core 温度"""
        try:
            out = subprocess.check_output(
                ["sensors", "-u"], stderr=subprocess.DEVNULL, timeout=3
            ).decode()
            best = 0.0
            in_cpu_block = False
            for line in out.splitlines():
                # 检测芯片块标题
                if not line.startswith(" ") and ":" not in line:
                    low = line.lower()
                    in_cpu_block = any(x in low for x in
                                       ("coretemp", "k10temp", "zenpower", "cpu", "package"))
                if "temp" in line.lower() and "_input:" in line.lower():
                    try:
                        val = float(line.split(":")[-1].strip())
                        if 0 < val < 150:
                            best = max(best, val)
                    except Exception:
                        pass
            if best > 0:
                return f"{best:.1f}°C"
            # 兜底：简单 grep
            out2 = run("sensors 2>/dev/null | grep -E '(Package|Core|Tdie|CPU Temp)' "
                       "| grep -oP '[0-9]+\\.[0-9]+' | sort -n | tail -1")
            if out2:
                return f"{float(out2):.1f}°C"
        except FileNotFoundError:
            pass
        except Exception:
            pass
        return ""

    # ── i350 网卡温度 ────────────────────────────────────────────────
    @staticmethod
    def _temp_i350() -> str:
        """
        Intel i350 温度采集（多路径，按可靠性排序）：
        1. /sys/class/hwmon/hwmonN — name 匹配 i350/igb/i350bb
        2. PCI 设备树 — 按 i350 PCI ID (0x1521/0x1523/0x1524) 查 hwmon
        3. net device → PCI → hwmon 链路（通过 /sys/class/net/<nic>/device/hwmon）
        4. lm-sensors sensors 命令 — 解析含 i350/igb 关键字的芯片块
        5. ethtool -m — SFP 光模块温度（铜口 i350 无此数据）
        注意: i350 内置温度传感器需 igb 模块编译时带 CONFIG_IGB_HWMON，
              且内核 >= 3.10。若全部 N/A，请确认:
              modprobe igb; ls /sys/class/hwmon/
        """
        import glob

        results = []
        seen_vals = set()

        def add_result(label, val_c):
            key = f"{label}:{val_c:.0f}"
            if key not in seen_vals and 0 < val_c < 120:
                seen_vals.add(key)
                results.append(f"{label}:{val_c:.0f}°C")

        # ── 方法1: hwmon by name ─────────────────────────────────────
        for hwmon_dir in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
            try:
                name = Path(os.path.join(hwmon_dir, "name")).read_text().strip().lower()
            except Exception:
                continue
            if any(x in name for x in ("i350", "igb", "i350bb")):
                for temp_f in sorted(glob.glob(os.path.join(hwmon_dir, "temp*_input"))):
                    try:
                        val = int(Path(temp_f).read_text().strip()) / 1000.0
                        label_f = temp_f.replace("_input", "_label")
                        label = (Path(label_f).read_text().strip()
                                 if os.path.exists(label_f) else "i350")
                        add_result(label, val)
                    except Exception:
                        pass

        # ── 方法2: PCI 设备树 (i350 PCI IDs) ─────────────────────────
        I350_DEVIDS = {"0x1521", "0x1523", "0x1524", "0x1526", "0x1527"}
        for pci_dev in glob.glob("/sys/bus/pci/devices/*"):
            try:
                vendor = Path(os.path.join(pci_dev, "vendor")).read_text().strip()
                device = Path(os.path.join(pci_dev, "device")).read_text().strip()
            except Exception:
                continue
            if vendor != "0x8086" or device not in I350_DEVIDS:
                continue
            for temp_f in glob.glob(os.path.join(pci_dev, "hwmon", "hwmon*", "temp*_input")):
                try:
                    val = int(Path(temp_f).read_text().strip()) / 1000.0
                    add_result("i350", val)
                except Exception:
                    pass

        # ── 方法3: net device → symlink → PCI → hwmon ────────────────
        try:
            for nic in os.listdir("/sys/class/net"):
                dev_path = f"/sys/class/net/{nic}/device"
                if not os.path.exists(dev_path):
                    continue
                # 检查 vendor/device
                try:
                    vendor = Path(os.path.join(dev_path, "vendor")).read_text().strip()
                    device = Path(os.path.join(dev_path, "device")).read_text().strip()
                except Exception:
                    continue
                if vendor != "0x8086" or device not in I350_DEVIDS:
                    continue
                # 找 hwmon
                for temp_f in glob.glob(os.path.join(dev_path, "hwmon", "hwmon*", "temp*_input")):
                    try:
                        val = int(Path(temp_f).read_text().strip()) / 1000.0
                        add_result(f"{nic}", val)
                    except Exception:
                        pass
        except Exception:
            pass

        # ── 方法4: lm-sensors 输出解析 ───────────────────────────────
        if not results:
            try:
                out = subprocess.check_output(
                    ["sensors", "-u"], stderr=subprocess.DEVNULL, timeout=3
                ).decode()
                in_i350 = False
                for line in out.splitlines():
                    stripped = line.strip()
                    if not stripped.startswith(" ") and ":" not in stripped:
                        in_i350 = any(x in stripped.lower()
                                      for x in ("i350", "igb", "i350bb"))
                    if in_i350 and "temp" in stripped.lower() and "_input:" in stripped.lower():
                        try:
                            val = float(stripped.split(":")[-1].strip())
                            add_result("i350(sensors)", val)
                        except Exception:
                            pass
            except Exception:
                pass

        # ── 方法5: ethtool -m (SFP 光模块，铜口无效) ─────────────────
        try:
            for nic in os.listdir("/sys/class/net"):
                if nic == "lo":
                    continue
                out = subprocess.check_output(
                    ["ethtool", "-m", nic], stderr=subprocess.DEVNULL, timeout=2
                ).decode()
                for line in out.splitlines():
                    if "temperature" in line.lower():
                        m = re.search(r"([0-9]+\.[0-9]+)", line)
                        if m:
                            add_result(f"{nic}-sfp", float(m.group(1)))
                        break
        except Exception:
            pass

        return "  ".join(results) if results else ""

        return "  ".join(results) if results else ""

    def update(self):
        host  = run("hostname -f") or run("hostname")
        kern  = run("uname -r")
        up    = fmt_up(read_file("/proc/uptime","0 0").split()[0])
        load  = read_file("/proc/loadavg","0 0 0").split()[:3]
        procs = run("ls /proc|grep -c '^[0-9]'","?")

        # ── CPU 温度（按优先级依次尝试）──
        temp = ""
        for fn in (self._temp_via_pve_ssh,
                   self._temp_via_guest_agent,
                   self._temp_via_sensors,
                   self._temp_via_thermal_zone):
            temp = fn()
            if temp:
                break
        if not temp:
            temp = "N/A"

        # ── i350 网卡温度 ──
        nic_temp = self._temp_i350()

        return {"host":host,"kern":kern,"up":up,"load":load,"procs":procs,
                "temp":temp,"nic_temp":nic_temp}

# =========================================================================
# Screen Manager  (htop-faithful renderer)
# =========================================================================

class ScreenManager:
    def __init__(self, scr):
        self.scr   = scr
        self.cpu   = CPUCollector()
        self.mem   = MemoryCollector()
        self.net   = NetworkCollector()
        self.disk  = DiskIOCollector()
        self.dhcp  = DHCPCollector()
        self.nft   = FirewallCollector()
        self.sys_  = SystemCollector()
        self._t    = time.time()
        self._sdh  = 0   # dhcp scroll offset
        self._privacy = False  # p键：隐私模式，隐藏WAN IP/MAC及DHCP主机名/MAC
        self._cache= None
        self._init_colors()

    # ------------------------------------------------------------------
    # Color init  (top.py / daetop.py / dae.py 统一风格)
    # ------------------------------------------------------------------
    def _init_colors(self):
        curses.start_color()
        curses.use_default_colors()

        def ip(n, fg, fb=-1):
            try:    curses.init_pair(n, fg, -1)
            except: curses.init_pair(n, fb, -1)

        # 1: 白字蓝底 — 标题栏/状态栏/节区标题
        try:    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
        except: curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)

        ip(2,  curses.COLOR_GREEN,  curses.COLOR_GREEN)   # good/green
        ip(3,  curses.COLOR_YELLOW, curses.COLOR_YELLOW)  # warn/yellow
        ip(4,  curses.COLOR_RED,    curses.COLOR_RED)     # bad/red
        ip(5,  252,                 curses.COLOR_WHITE)   # node/light grey
        ip(6,  240,                 curses.COLOR_WHITE)   # dim/dark grey
        ip(7,  curses.COLOR_BLUE,   curses.COLOR_BLUE)    # net/blue
        ip(8,  curses.COLOR_WHITE,  curses.COLOR_WHITE)   # host/white
        ip(9,  242,                 curses.COLOR_WHITE)   # port/mid grey
        ip(10, curses.COLOR_CYAN,   curses.COLOR_CYAN)    # hdr/cyan
        ip(11, 240,                 curses.COLOR_WHITE)   # sep/dark grey
        ip(12, curses.COLOR_GREEN,  curses.COLOR_GREEN)   # label/green

        try:    curses.init_pair(15, curses.COLOR_BLACK, curses.COLOR_YELLOW)
        except: curses.init_pair(15, curses.COLOR_BLACK, curses.COLOR_WHITE)

        def ip_blue(n, fg, fb=curses.COLOR_WHITE):
            try:    curses.init_pair(n, fg, curses.COLOR_BLUE)
            except: curses.init_pair(n, fb, curses.COLOR_BLUE)

        ip_blue(16, curses.COLOR_CYAN)    # title_hdr
        ip_blue(17, curses.COLOR_YELLOW)  # title_warn
        ip_blue(18, curses.COLOR_RED)     # title_bad
        ip_blue(19, curses.COLOR_WHITE)   # title_dim

    # ------------------------------------------------------------------
    # Low-level draw helpers
    # ------------------------------------------------------------------
    def _put(self, y, x, text, attr=0):
        my, mx = self.scr.getmaxyx()
        if y < 0 or y >= my or x < 0 or x >= mx:
            return
        # 按显示列数截断，避免宽字符（汉字占2列）超出边界引发 curses 异常
        avail = mx - x - 1   # 留1列安全边距，防止写到最后一格
        if avail <= 0:
            return
        out, cols = [], 0
        for ch in str(text):
            w = 2 if (0x1100 <= ord(ch) <= 0x115F or 0x2E80 <= ord(ch) <= 0x9FFF
                      or 0xAC00 <= ord(ch) <= 0xD7AF or 0xFF00 <= ord(ch) <= 0xFF60) else 1
            if cols + w > avail:
                break
            out.append(ch)
            cols += w
        try:
            self.scr.addstr(y, x, ''.join(out), attr)
        except curses.error:
            pass

    def _hline(self, y, x, length, ch="─"):
        self._put(y, x, ch * length,
                  curses.color_pair(C.SEP) | curses.A_DIM)

    # top.py 风格节区标题：蓝底白字填满整行，左侧显示标题
    def _section(self, y, title, width):
        MY, MX = self.scr.getmaxyx()
        self._put(y, 0, " " * (MX - 1),
                  curses.color_pair(C.SEC_BAR) | curses.A_BOLD)
        self._put(y, 0, f" {title}",
                  curses.color_pair(C.SEC_BAR) | curses.A_BOLD)

    # ------------------------------------------------------------------
    # Meters
    # ------------------------------------------------------------------
    def _cpu_bar(self, y, x, w, pct, usr, sys_, label=""):
        """top.py 风格 CPU 进度条：█ 填充，░ 空白，颜色按负载变化"""
        if label:
            self._put(y, x, label, curses.color_pair(C.HDR) | curses.A_BOLD)
            x += len(label)

        filled = max(0, min(w, int(w * pct / 100)))
        empty  = w - filled
        cp_bar = C.GOOD if pct < 70 else (C.WARN if pct < 90 else C.BAD)

        self._put(y, x,          "█" * filled, curses.color_pair(cp_bar)  | curses.A_BOLD)
        self._put(y, x + filled, "░" * empty,  curses.color_pair(C.DIM))
        self._put(y, x + w + 1,  f"{pct:5.1f}%", curses.color_pair(cp_bar) | curses.A_BOLD)

    def _mem_bar(self, y, x, w, used, buf, cac, tot, label=""):
        """内存进度条：label [████░░░░] 已用/总计 (xx.x%)  — 绿色加粗，无多余字段"""
        if not tot: tot = 1
        pct    = used / tot * 100
        filled = max(0, min(w, int(w * pct / 100)))
        empty  = w - filled
        # 颜色：<70% 绿，<90% 黄，>=90% 红
        cp_bar = C.GOOD if pct < 70 else (C.WARN if pct < 90 else C.BAD)

        x0 = x
        if label:
            self._put(y, x, label, curses.color_pair(C.HDR) | curses.A_BOLD)
            x += len(label)

        self._put(y, x,          "█" * filled, curses.color_pair(cp_bar) | curses.A_BOLD)
        self._put(y, x + filled, "░" * empty,  curses.color_pair(C.DIM))
        # 数值：固定绿色加粗，格式 "已用/总计 (xx.x%)"
        val_str = f" {fmt_bytes(used)}/{fmt_bytes(tot)} ({pct:.1f}%)"
        self._put(y, x + w, val_str, curses.color_pair(C.GOOD) | curses.A_BOLD)

    def _swap_bar(self, y, x, w, su, st, label=""):
        """Swap 进度条：label [████░░░░] 已用/总计 (xx.x%)  — 绿色加粗，无多余字段"""
        if not st:
            # Swap 不存在时显示 disabled
            if label:
                self._put(y, x, label, curses.color_pair(C.HDR) | curses.A_BOLD)
                x += len(label)
            self._put(y, x, "░" * w, curses.color_pair(C.DIM))
            self._put(y, x + w, " 未配置", curses.color_pair(C.DIM))
            return
        pct    = su / st * 100
        filled = max(0, min(w, int(w * pct / 100)))
        empty  = w - filled
        cp_bar = C.GOOD if pct < 50 else (C.WARN if pct < 80 else C.BAD)

        if label:
            self._put(y, x, label, curses.color_pair(C.HDR) | curses.A_BOLD)
            x += len(label)

        self._put(y, x,          "█" * filled, curses.color_pair(cp_bar) | curses.A_BOLD)
        self._put(y, x + filled, "░" * empty,  curses.color_pair(C.DIM))
        val_str = f" {fmt_bytes(su)}/{fmt_bytes(st)} ({pct:.1f}%)"
        self._put(y, x + w, val_str, curses.color_pair(C.GOOD) | curses.A_BOLD)

    def _mini_bar(self, y, x, w, pct, cp):
        fill  = min(int(w * pct / 100), w)
        empty = w - fill
        self._put(y, x,        "█" * fill,  curses.color_pair(cp)    | curses.A_BOLD)
        self._put(y, x + fill, "░" * empty, curses.color_pair(C.DIM))

    # ------------------------------------------------------------------
    # Main render
    # ------------------------------------------------------------------
    def render(self, refresh=True):
        self.scr.erase()
        MY, MX = self.scr.getmaxyx()

        if refresh or self._cache is None:
            now  = time.time()
            dt   = max(now - self._t, 0.01)
            self._t = now
            self._cache = {
                "cpu":  self.cpu.update(),
                "mem":  self.mem.update(),
                "net":  self.net.update(dt),
                "disk": self.disk.update(dt),
                "dhcp": self.dhcp.update(),
                "nft":  self.nft.update(),
                "sys":  self.sys_.update(),
            }

        D    = self._cache
        _, cpu_pct, cpu_usr, cpu_sys = D["cpu"]
        mem  = D["mem"]
        net  = D["net"]
        disk = D["disk"]
        leases  = D["dhcp"]
        nft     = D["nft"]
        si      = D["sys"]
        row     = 0

        # ── Header bar (top.py 白字蓝底风格) ─────────────────────────
        self._put(row, 0, " " * MX, curses.color_pair(C.HDR_BAR) | curses.A_BOLD)
        left = f"  dtop  {si['host']}"
        self._put(row, 0, left, curses.color_pair(C.HDR_BAR) | curses.A_BOLD)
        center = "─── Debian 路由器监控 ───"
        self._put(row, max(0, (MX - len(center)) // 2), center,
                  curses.color_pair(C.HDR_BAR) | curses.A_BOLD)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._put(row, max(0, MX - len(ts) - 2), ts,
                  curses.color_pair(C.HDR_BAR) | curses.A_BOLD)
        row += 1

        # ── Info bar (蓝底，与 top.py 标题栏同色) ────────────────────
        self._put(row, 0, " " * MX, curses.color_pair(C.SUB_BAR) | curses.A_BOLD)
        segs = [("内核:", si['kern']), ("运行:", si['up']),
                ("负载:", "/".join(si['load'])), ("进程:", si['procs']),
                ("CPU温度:", si['temp'])]
        if si.get('nic_temp'):
            segs.append(("NIC:", si['nic_temp']))
        cx = 1
        for i, (lbl, val) in enumerate(segs):
            if i:
                self._put(row, cx, " │ ",
                          curses.color_pair(C.SUB_BAR) | curses.A_BOLD); cx += 3
            self._put(row, cx, lbl,
                      curses.color_pair(C.TITLE_HDR) | curses.A_BOLD); cx += len(lbl) + 1
            self._put(row, cx, val,
                      curses.color_pair(C.SUB_BAR) | curses.A_BOLD); cx += len(val) + 1
        row += 1

        # ── CPU section ───────────────────────────────────────────────
        self._section(row, "CPU 处理器", MX - 1); row += 1

        BAR_W = max(16, (MX // 2) - 12)
        COL_W = BAR_W + 12

        # Total CPU — full-width bar
        self._cpu_bar(row, 0, BAR_W, cpu_pct, cpu_usr, cpu_sys, "CPU ")
        # 右侧：usr/sys 数值提示
        lx = BAR_W + 14
        self._put(row, lx,    "usr:", curses.color_pair(C.HDR)  | curses.A_BOLD)
        self._put(row, lx+4,  f"{cpu_usr:.1f}%", curses.color_pair(C.GOOD) | curses.A_BOLD)
        self._put(row, lx+11, "sys:", curses.color_pair(C.HDR)  | curses.A_BOLD)
        self._put(row, lx+15, f"{cpu_sys:.1f}%", curses.color_pair(C.BAD)  | curses.A_BOLD)
        row += 1

        # Per-core grid — 2 columns, htop style
        # Each core label: "  N " (right-aligned in 3 chars + space)
        cores     = self.cpu.cores[:64]
        core_rows = max(1, (len(cores)+1)//2)
        HALF      = MX // 2

        for i, (name, pct, usr, sys_) in enumerate(cores):
            gy  = row + i // 2
            gx  = 0 if (i % 2 == 0) else HALF
            num = name.replace("cpu","")
            lbl = f"{int(num):>3} "
            self._cpu_bar(gy, gx, BAR_W, pct, usr, sys_, lbl)

        row += core_rows + 1

        # ── Memory section ────────────────────────────────────────────
        self._section(row, "内存", MX - 1); row += 1

        MB = max(16, (MX // 2) - 12)   # 与 CPU 进度条同宽
        self._mem_bar(row, 0, MB, mem["used"], mem["buf"], mem["cac"], mem["tot"], "Mem  ")
        row += 1

        self._swap_bar(row, 0, MB, mem["su"], mem["st"], "Swap ")
        row += 2

        # ── Network section ───────────────────────────────────────────
        self._section(row, "网络", MX-1); row += 1

        # Each interface occupies exactly 3 rows:
        #   row 0:  ● LABEL [iface]  IP x.x.x.x  MAC xx:..  STATE
        #   row 1:  ↓ RX  rate+total  [sparkline]
        #   row 2:  ↑ TX  rate+total  [sparkline]
        # Two panels side-by-side (WAN left, LAN right)

        HALF = MX // 2
        PW   = HALF - 1          # panel width
        IFACE_ROWS = 3           # rows per interface

        # Draw divider
        for r in range(row, row + IFACE_ROWS):
            self._put(r, HALF, "│", curses.color_pair(C.SEP)|curses.A_BOLD)

        ifaces = [(Settings.WAN_IFACE,"WAN",C.WAN_ACC),
                  (Settings.LAN_IFACE,"LAN",C.LAN_ACC)]

        # Sparkline width that fits inside the panel
        SPK = min(Settings.SPARK_WIDTH, PW - 34)

        for pi, (iface, lbl, acc) in enumerate(ifaces):
            ox   = 0 if pi == 0 else HALF + 1
            ist  = net.get(iface, {})
            st   = self.net.state(iface)   # "up" / "carrier" / "down"
            ip   = self.net.ip(iface)
            mac  = self.net.mac(iface)
            # 三色圆点：绿=在线  黄=载体有信号  红=断线
            if st == "up":
                sc, sym = C.LINK_UP, "●"
            elif st == "carrier":
                sc, sym = C.WARN,    "●"
            else:
                sc, sym = C.LINK_DN, "●"
            rx   = ist.get("rx", 0); tx  = ist.get("tx", 0)
            trx  = ist.get("trx",0); ttx = ist.get("ttx",0)
            spkr = sparkline(self.net.rx_hist.get(iface, deque()), SPK)
            spkt = sparkline(self.net.tx_hist.get(iface, deque()), SPK)

            # Row 0: status line（去掉"上线/下线"文字，圆点颜色即表示状态）
            self._put(row,   ox,    sym,  curses.color_pair(sc)|curses.A_BOLD)
            self._put(row,   ox+2,  lbl,  curses.color_pair(acc)|curses.A_BOLD)
            self._put(row,   ox+6,  f"[{iface}]", curses.color_pair(C.DIM))
            ip_x = ox + 6 + len(iface) + 2
            # 隐私模式：WAN口隐藏真实IP和MAC
            is_wan = (iface == Settings.WAN_IFACE)
            disp_ip  = "***.***.***.***" if (self._privacy and is_wan) else ip
            disp_mac = "**:**:**:**:**:**" if (self._privacy and is_wan and mac) else mac
            self._put(row,   ip_x,     "IP:", curses.color_pair(C.LABEL)|curses.A_BOLD)
            self._put(row,   ip_x + 4, f"{disp_ip:<20}", curses.color_pair(C.VALUE)|curses.A_BOLD)
            if mac:
                mac_x = ip_x + 25
                self._put(row, mac_x,     "MAC:", curses.color_pair(C.LABEL)|curses.A_BOLD)
                self._put(row, mac_x + 5, disp_mac, curses.color_pair(C.DIM))

            # Row 1: RX — rate  total  [sparkline]
            # 速率：自动换算单位，右对齐12字符（含单位）
            # 累计：自动换算单位，固定列位
            rx_rate_s  = fmt_bytes(rx,  rate=True)
            tx_rate_s  = fmt_bytes(tx,  rate=True)
            rx_total_s = fmt_bytes(trx)
            tx_total_s = fmt_bytes(ttx)
            COL_RATE  = ox + 7           # 速率起始列
            COL_TOT   = ox + 21          # 累计起始列
            COL_SPK   = ox + PW - SPK - 1

            self._put(row+1, ox+1,     "↓ 收包", curses.color_pair(C.RX)|curses.A_BOLD)
            self._put(row+1, COL_RATE, f"{rx_rate_s:>12}", curses.color_pair(C.RX)|curses.A_BOLD)
            self._put(row+1, COL_TOT,  "累计:", curses.color_pair(C.DIM))
            self._put(row+1, COL_TOT+3,f"{rx_total_s:>10}", curses.color_pair(C.VALUE))
            self._put(row+1, COL_SPK,  spkr, curses.color_pair(C.SPK_RX)|curses.A_BOLD)

            self._put(row+2, ox+1,     "↑ 发包", curses.color_pair(C.TX)|curses.A_BOLD)
            self._put(row+2, COL_RATE, f"{tx_rate_s:>12}", curses.color_pair(C.TX)|curses.A_BOLD)
            self._put(row+2, COL_TOT,  "累计:", curses.color_pair(C.DIM))
            self._put(row+2, COL_TOT+3,f"{tx_total_s:>10}", curses.color_pair(C.VALUE))
            self._put(row+2, COL_SPK,  spkt, curses.color_pair(C.SPK_TX)|curses.A_BOLD)

        row += IFACE_ROWS + 1

        # ── Disk I/O section ──────────────────────────────────────────
        self._section(row, "磁盘 I/O", MX-1); row += 1

        SPK2 = min(Settings.SPARK_WIDTH, MX - 50)
        self._put(row, 1, "↓ 读取 ", curses.color_pair(C.RX)|curses.A_BOLD)
        self._put(row, 9, f"{fmt_bytes(disk['rr'],rate=True):>11}",
                  curses.color_pair(C.RX)|curses.A_BOLD)
        self._put(row, 21, sparkline(self.disk.r_hist, SPK2),
                  curses.color_pair(C.SPK_RX)|curses.A_BOLD)
        self._put(row, 21+SPK2+2, "累计:", curses.color_pair(C.DIM))
        self._put(row, 21+SPK2+9, fmt_bytes(disk['tr']),
                  curses.color_pair(C.VALUE))
        row += 1

        self._put(row, 1, "↑ 写入", curses.color_pair(C.TX)|curses.A_BOLD)
        self._put(row, 9, f"{fmt_bytes(disk['wr'],rate=True):>11}",
                  curses.color_pair(C.TX)|curses.A_BOLD)
        self._put(row, 21, sparkline(self.disk.w_hist, SPK2),
                  curses.color_pair(C.SPK_TX)|curses.A_BOLD)
        self._put(row, 21+SPK2+2, "累计:", curses.color_pair(C.DIM))
        self._put(row, 21+SPK2+9, fmt_bytes(disk['tw']),
                  curses.color_pair(C.VALUE))
        row += 1

        # ── 磁盘空间使用 ──────────────────────────────────────────────
        mounts = disk.get("mounts", [])
        # 布局：col1=标签(12), col2=进度条(BAR_DK), col3=数值(~26)
        # 保证 12 + BAR_DK + 26 <= MX
        VAL_W  = 26          # " 8.23G/20.0G (41.2%)" 最长约25字符
        LBL_W  = 12          # 挂载点标签列宽
        BAR_DK = max(16, (MX // 2) - 12)   # 与 CPU 进度条同宽
        for mt in mounts:
            total, used, free = mt["total"], mt["used"], mt["free"]
            pct  = used / total * 100 if total else 0
            fill = max(0, min(BAR_DK, int(BAR_DK * pct / 100)))
            empty= BAR_DK - fill
            cp   = C.GOOD if pct < 70 else (C.WARN if pct < 90 else C.BAD)
            # 挂载点标签 + 设备名（暗色小字）
            mnt_label = mt['mount'][:10]
            dev_label = f"({mt['dev']})"
            self._put(row, 1,              f"{mnt_label:<10}", curses.color_pair(C.HDR)|curses.A_BOLD)
            self._put(row, 1+len(mnt_label)+1, f"{dev_label:<8}",  curses.color_pair(C.DIM))
            # 进度条
            bx = LBL_W
            self._put(row, bx,        "█" * fill,  curses.color_pair(cp)|curses.A_BOLD)
            self._put(row, bx + fill, "░" * empty, curses.color_pair(C.DIM))
            # 数值：已用/总量 (pct%)
            val_s = f" {fmt_bytes(used)}/{fmt_bytes(total)} ({pct:.1f}%)"
            self._put(row, bx + BAR_DK, val_s, curses.color_pair(C.GOOD)|curses.A_BOLD)
            row += 1
        row += 1

        # ── DHCP Leases section ───────────────────────────────────────
        n_leases  = len(leases)
        src_hint  = getattr(leases, "_source", "")
        lease_lbl = f"  [{src_hint}]" if src_hint else ""
        self._section(row, f"DHCP 租约  [{n_leases} 台设备]  dnsmasq{lease_lbl}", MX-1)
        row += 1

        # 列位固定（与图片对齐，不随终端宽度浮动）
        # #(4) | IP(5~20) | MAC(22~39) | HOST(41~70) | EXP(72~)
        C_IDX  = 0    # 序号
        C_IP   = 5    # IP 地址      最长15字符
        C_MAC  = 22   # MAC 地址     17字符
        C_HOST = 41   # 主机名       最长30显示列
        HOST_W = 30   # 主机名列宽（显示列数）
        C_EXP  = 72   # 到期时间     固定列位

        self._put(row, 0, " " * MX, curses.color_pair(C.DHCP_HDR) | curses.A_BOLD)
        self._put(row, C_IDX,  "  #",      curses.color_pair(C.DHCP_HDR) | curses.A_BOLD)
        self._put(row, C_IP,   "IP 地址",  curses.color_pair(C.DHCP_HDR) | curses.A_BOLD)
        self._put(row, C_MAC,  "MAC 地址", curses.color_pair(C.DHCP_HDR) | curses.A_BOLD)
        self._put(row, C_HOST, "主机名",   curses.color_pair(C.DHCP_HDR) | curses.A_BOLD)
        self._put(row, C_EXP,  "到期时间", curses.color_pair(C.DHCP_HDR) | curses.A_BOLD)
        row += 1

        RESERVED = 5
        avail    = max(1, MY - row - RESERVED)

        if n_leases == 0:
            lf = DHCPCollector._find_lease_file()
            if lf:
                hint = f"(租约文件为空 — {lf}  dnsmasq 是否正在运行？)"
            else:
                hint = "(未找到租约文件 — 请检查 dnsmasq 配置或 dhcp-leasefile= 路径)"
            self._put(row, 4, hint, curses.color_pair(C.DIM)|curses.A_DIM)
            row += 1
        else:
            if n_leases <= avail:
                self._sdh = 0
            else:
                self._sdh = max(0, min(self._sdh, n_leases - avail))

            visible = leases[self._sdh : self._sdh + avail]
            for i, ls in enumerate(visible):
                idx  = self._sdh + i
                ec   = C.DIM if ls['exp'] in ("永久", "已过期") else C.WARN
                # 主机名：按显示列数截断到 HOST_W，再用 pad_right 补齐
                host_raw = ls['host']
                # 截断超长主机名
                truncated, w = [], 0
                for ch in host_raw:
                    cw = 2 if (0x2E80 <= ord(ch) <= 0x9FFF or 0xAC00 <= ord(ch) <= 0xD7AF) else 1
                    if w + cw > HOST_W:
                        break
                    truncated.append(ch)
                    w += cw
                host = pad_right(''.join(truncated), HOST_W)
                d_mac  = "**:**:**:**:**:**" if self._privacy else f"{ls['mac']:<17}"
                d_host = pad_right("******", HOST_W)  if self._privacy else host
                self._put(row, C_IDX,  f"{idx+1:>4}",      curses.color_pair(C.DIM))
                self._put(row, C_IP,   f"{ls['ip']:<15}",  curses.color_pair(C.VALUE)|curses.A_BOLD)
                self._put(row, C_MAC,  d_mac,               curses.color_pair(C.LABEL))
                self._put(row, C_HOST, d_host,              curses.color_pair(C.PROC_GRN)|curses.A_BOLD)
                self._put(row, C_EXP,  ls['exp'],           curses.color_pair(ec)|curses.A_BOLD)
                row += 1

            if n_leases > avail:
                end = self._sdh + len(visible)
                ind = f" ↑↓  {self._sdh+1}-{end}/{n_leases} "
                self._put(row-1, MX-len(ind)-1, ind,
                          curses.color_pair(C.WARN)|curses.A_BOLD)

        row += 1

        # ── Firewall section ──────────────────────────────────────────
        fw_backend = nft.get("backend", "防火墙")
        self._section(row, f"防火墙  [{fw_backend}]", MX-1); row += 1

        tbl_str = ", ".join(f"{f} {t}" for f,t in nft["tables"]) or "(无规则表)"
        self._put(row, 1, "表:", curses.color_pair(C.NFT_ACC)|curses.A_BOLD)
        self._put(row, 5, tbl_str, curses.color_pair(C.VALUE))
        cx = 5 + len(tbl_str) + 3
        self._put(row, cx,    "链:", curses.color_pair(C.NFT_ACC)|curses.A_BOLD)
        self._put(row, cx+4,  str(nft['chains']), curses.color_pair(C.VALUE)|curses.A_BOLD)
        self._put(row, cx+8,  "规则:", curses.color_pair(C.NFT_ACC)|curses.A_BOLD)
        self._put(row, cx+15, str(nft['rules']),  curses.color_pair(C.VALUE)|curses.A_BOLD)

        # 若同时存在 iptables，第二行显示 iptables 信息
        ipt = nft.get("ipt")
        if ipt and fw_backend == "nftables + iptables":
            row += 1
            ipt_tbl_str = ", ".join(f"{f} {t}" for f,t in ipt.get("tables",[])) or "(无)"
            self._put(row, 1, f"  iptables 表:", curses.color_pair(C.WARN)|curses.A_BOLD)
            self._put(row, 15, ipt_tbl_str, curses.color_pair(C.VALUE))
            cx2 = 15 + len(ipt_tbl_str) + 2
            self._put(row, cx2, f"链:{ipt.get('chains',0)}", curses.color_pair(C.VALUE)|curses.A_BOLD)
            self._put(row, cx2+8, f"规则:{ipt.get('rules',0)}", curses.color_pair(C.VALUE)|curses.A_BOLD)
        elif ipt and "iptables" in fw_backend:
            # 纯 iptables 模式，显示各表
            pass  # 已在上面的 tbl_str 里显示了

        row += 1
        cnt, mx_ct = nft["cnt"], nft["mx"]
        if cnt.isdigit() and mx_ct.isdigit():
            cv, mv = int(cnt), int(mx_ct)
            pct    = 100*cv/mv if mv else 0
            cc     = C.LINK_UP if pct<60 else (C.WARN if pct<85 else C.LINK_DN)
            self._put(row, 1, "连接跟踪:", curses.color_pair(C.NFT_ACC)|curses.A_BOLD)
            self._mini_bar(row, 12, 20, pct, cc)
            val_s = f" {cv}/{mv} ({pct:.1f}%)"
            self._put(row, 35, val_s, curses.color_pair(cc)|curses.A_BOLD)

        # ── Footer ───────────────────────────────────────────────────
        priv_lbl = "显示" if self._privacy else "隐藏"
        keys = [("q", "退出"), ("r", "刷新"), ("↑↓", "滚动DHCP"), ("jk", "vi滚动"), ("p", f"{priv_lbl}隐私")]
        ftxt = "  " + "   ".join(f"[{k}] {v}" for k, v in keys) + "  "
        self._put(MY - 1, 0, " " * MX, curses.color_pair(C.FOOTER) | curses.A_BOLD)
        self._put(MY - 1, max(0, (MX - len(ftxt)) // 2), ftxt,
                  curses.color_pair(C.FOOTER) | curses.A_BOLD)

        self.scr.refresh()

    # ------------------------------------------------------------------
    # Event loop
    # ------------------------------------------------------------------
    def run(self):
        curses.curs_set(0)
        self.scr.nodelay(True)
        self.scr.keypad(True)

        self.net.update(0.1)
        self.disk.update(0.1)
        time.sleep(0.4)
        self._t = time.time()

        while True:
            try:
                self.render(refresh=True)
            except Exception as _e:
                # render 出错时把错误显示在屏幕上，而不是吞掉后黑屏
                try:
                    self.scr.erase()
                    self.scr.addstr(0, 0, f"[dtop render error] {_e}")
                    self.scr.addstr(1, 0, "按 q 退出，按 r 重试")
                    self.scr.refresh()
                except Exception:
                    pass

            deadline = time.time() + Settings.REFRESH_INTERVAL
            while time.time() < deadline:
                key = self.scr.getch()
                if key == curses.ERR:
                    time.sleep(0.05); continue

                if key in (ord('q'), ord('Q'), 27):
                    return
                elif key == ord('r'):
                    deadline = 0
                elif key in (ord('p'), ord('P')):
                    self._privacy = not self._privacy
                    try: self.render(refresh=False)
                    except Exception: pass
                elif key in (curses.KEY_UP, ord('k')):
                    self._sdh = max(0, self._sdh - 1)
                    try: self.render(refresh=False)
                    except Exception: pass
                elif key in (curses.KEY_DOWN, ord('j')):
                    self._sdh += 1
                    try: self.render(refresh=False)
                    except Exception: pass

# =========================================================================
# Entry Point
# =========================================================================

def main():
    if os.geteuid() != 0:
        print("⚠  非 root 权限 — nftables/conntrack/传感器功能可能不可用。")
        print("   请使用: sudo python3 dtop.py")
        time.sleep(1)
    try:
        curses.wrapper(lambda s: ScreenManager(s).run())
    except KeyboardInterrupt:
        pass
    print("\ndtop 已退出。")

if __name__ == "__main__":
    main()