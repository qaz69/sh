#!/usr/bin/env python3
"""
dae-monitor  —  htop 风格的 dae 代理监控面板
延迟通过 ping (ICMP) 探测，支持 IPv4/IPv6，不依赖日志。
"""
import curses, time, threading, subprocess, collections, re, os, socket, psutil
from urllib.parse import unquote

# ── 配置 ─────────────────────────────────────────────────────────────────────
CONFIG_PATH      = "/usr/local/etc/dae/config.dae"
LOG_MAX_LEN      = 200
REFRESH_INTERVAL = 1.0
PROBE_INTERVAL   = 20.0   # 每轮探测间隔 (秒)
PING_COUNT       = 3      # ping 次数，取平均
PING_TIMEOUT     = 4      # ping 单次超时 (秒)
# ─────────────────────────────────────────────────────────────────────────────

log_buffer   = collections.deque(maxlen=LOG_MAX_LEN)
nodes        = []            # list[dict]
nodes_lock   = threading.Lock()
running      = True
log_scroll   = 0
search_mode  = False         # 是否在搜索框输入中
search_str   = ""            # 已确认的过滤关键词
search_input = ""            # 搜索框正在输入的内容
privacy_mode = False         # [P] 隐私模式：遮盖节点名/主机/端口

# ── 资源缓存（后台线程写，draw 只读，彻底消除闪烁） ──────────────────────────
_res_lock = threading.Lock()
_res = dict(
    cpu=0.0, mem_pct=0.0, mem_used=0, mem_total=1,
    up_s=0.0, dn_s=0.0, net_sent=0, net_recv=0,
    load1=0.0, load5=0.0, load15=0.0,
    dae_cpu=0.0, dae_mem=0, dae_status='unknown', dae_pid=None,
    dae_create_time=None,
)

def _get_dae_proc():
    """找到 dae 主进程"""
    for p in psutil.process_iter(['pid','name','cmdline']):
        try:
            nm = p.info['name'] or ''
            cmdline = p.info['cmdline'] or []
            cl = ' '.join(cmdline)
            # 精确匹配：进程名为 dae，且（无参数 或 第一个参数含 run/透明代理关键词）
            # 避免匹配到路径中含 /dae 的其他进程（如 config.dae 相关脚本）
            if nm == 'dae':
                return p
            # 兜底：cmdline[0] 以 dae 结尾（绝对路径启动），且有 run 子命令
            if cmdline and (cmdline[0].endswith('/dae') or cmdline[0] == 'dae'):
                if len(cmdline) > 1 and cmdline[1] == 'run':
                    return p
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None

def _res_loop():
    """每秒采样一次系统资源，写入 _res 缓存"""
    def _ppp0():
        """读取 ppp0 网卡的 io 计数，不存在时返回 None"""
        ioc = psutil.net_io_counters(pernic=True)
        return ioc.get('ppp0')

    prev_ppp = _ppp0()
    prev_t   = time.time()
    dae_proc = None
    while running:
        time.sleep(1.0)
        cpu  = psutil.cpu_percent(interval=None)
        mem  = psutil.virtual_memory()
        now  = time.time()
        dt   = max(now - prev_t, 0.001)

        cur_ppp = _ppp0()
        if cur_ppp and prev_ppp:
            up_s     = (cur_ppp.bytes_sent - prev_ppp.bytes_sent) / dt
            dn_s     = (cur_ppp.bytes_recv - prev_ppp.bytes_recv) / dt
            net_sent = cur_ppp.bytes_sent
            net_recv = cur_ppp.bytes_recv
        else:
            up_s = dn_s = net_sent = net_recv = 0
        prev_ppp = cur_ppp
        prev_t   = now

        # dae 进程采样
        dae_cpu, dae_mem_b, dae_status, dae_pid, dae_ct = 0.0, 0, 'unknown', None, None
        try:
            if dae_proc is None or not dae_proc.is_running():
                new_proc = _get_dae_proc()
                if new_proc is not None:
                    # 首次拿到进程对象，先调用一次 cpu_percent 做初始化
                    # （psutil 规定：interval=None 时首次调用返回 0.0，需两次调用才有值）
                    try:
                        new_proc.cpu_percent(interval=None)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        new_proc = None
                dae_proc = new_proc
            if dae_proc and dae_proc.is_running():
                dae_cpu    = dae_proc.cpu_percent(interval=None)
                # 读取 RSS 内存，兼容权限受限情况
                try:
                    mem_info  = dae_proc.memory_info()
                    dae_mem_b = mem_info.rss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # 权限不足时尝试读取 /proc/<pid>/status
                    try:
                        with open(f'/proc/{dae_proc.pid}/status') as f:
                            for line in f:
                                if line.startswith('VmRSS:'):
                                    dae_mem_b = int(line.split()[1]) * 1024
                                    break
                    except Exception:
                        dae_mem_b = 0
                dae_status = dae_proc.status()
                dae_pid    = dae_proc.pid
                dae_ct     = dae_proc.create_time()
            else:
                dae_status = 'stopped'
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            dae_proc   = None
            dae_status = 'stopped'

        with _res_lock:
            _res['cpu']        = cpu
            _res['mem_pct']    = mem.percent
            _res['mem_used']   = mem.used
            _res['mem_total']  = mem.total
            _res['up_s']       = up_s
            _res['dn_s']       = dn_s
            _res['net_sent']   = net_sent
            _res['net_recv']   = net_recv
            _res['load1']      = os.getloadavg()[0]
            _res['load5']      = os.getloadavg()[1]
            _res['load15']     = os.getloadavg()[2]
            _res['dae_cpu']         = dae_cpu
            _res['dae_mem']         = dae_mem_b
            _res['dae_status']      = dae_status
            _res['dae_pid']         = dae_pid
            _res['dae_create_time'] = dae_ct

# ── 工具 ─────────────────────────────────────────────────────────────────────

def fmt_bytes(b):
    for u in ['B','KB','MB','GB','TB']:
        if b < 1024.0: return f"{b:5.1f}{u}"
        b /= 1024.0
    return f"{b:.1f}PB"

def wcslen(s):
    """计算字符串终端显示宽度（处理宽字符/emoji）"""
    return sum(2 if ord(c) > 0x2E7F else 1 for c in s)

def wcslice(s, n):
    """截断字符串到终端宽度 n，返回 (截断串, 实际宽度)"""
    out, w = [], 0
    for c in s:
        cw = 2 if ord(c) > 0x2E7F else 1
        if w + cw > n: break
        out.append(c); w += cw
    return ''.join(out), w

def pad_wcs(s, n):
    """截断+右补空格到终端宽度 n"""
    t, w = wcslice(s, n)
    return t + ' ' * (n - w)

def safe_add(win, y, x, s, attr=0):
    try: win.addstr(y, x, s, attr)
    except curses.error: pass

# ── 节点解析 ─────────────────────────────────────────────────────────────────

def parse_node_url(raw: str):
    """返回 (name, host, port, proto)"""
    raw = raw.strip().strip("'\"")
    # fragment = 显示名
    fm = re.search(r'#(.+)$', raw)
    name     = unquote(fm.group(1).strip()) if fm else None
    url_body = raw[:fm.start()] if fm else raw

    proto_m = re.match(r'(\w+)://', url_body)
    proto   = proto_m.group(1).lower() if proto_m else 'unknown'

    # vmess base64
    if proto == 'vmess':
        b64 = url_body[8:]
        try:
            import base64, json
            obj  = json.loads(base64.b64decode(b64 + '=='*2).decode())
            host = obj.get('add','')
            port = int(obj.get('port', 443))
            if not name: name = obj.get('ps', f"vmess:{host}")
            return name, host, port, proto
        except Exception: pass

    # 去掉 query string 再解析 netloc
    url_no_qs = url_body.split('?')[0]
    nm = re.search(r'://(.+)$', url_no_qs)
    if not nm: return name or raw[:20], None, None, proto
    netloc = nm.group(1)
    if '@' in netloc: netloc = netloc.rsplit('@', 1)[1]

    # IPv6 [addr]:port
    v6 = re.match(r'^\[([^\]]+)\]:(\d+)', netloc)
    if v6:
        host, port = v6.group(1), int(v6.group(2))
    else:
        parts = netloc.rstrip('/').split(':')
        host  = parts[0]
        port  = int(parts[1]) if len(parts) > 1 else 443

    if not name: name = f"{host}:{port}"
    return name, host, port, proto

def load_nodes():
    result = []
    if not os.path.exists(CONFIG_PATH):
        log_buffer.append((f"配置文件不存在: {CONFIG_PATH}", "ERRO"))
        return result
    try:
        with open(CONFIG_PATH, encoding='utf-8', errors='replace') as f:
            content = f.read()
        bm = re.search(r'\bnode\s*\{([^}]*)\}', content, re.DOTALL)
        if not bm:
            log_buffer.append(("未找到 node {} 块", "WARN"))
            return result
        for line in bm.group(1).splitlines():
            line = line.strip()
            if not line or line.startswith('#'): continue
            um = re.search(r"'([^']+)'|\"([^\"]+)\"", line)
            if not um: continue
            url = um.group(1) or um.group(2)
            try:
                name, host, port, proto = parse_node_url(url)
                result.append(dict(name=name, host=host or '',
                                   port=port or 443, proto=proto,
                                   latency=None, status='wait'))
            except Exception as e:
                log_buffer.append((f"解析节点失败: {e}", "WARN"))
    except Exception as e:
        log_buffer.append((f"读取配置失败: {e}", "ERRO"))
    return result

# ── 延迟探测 —— 使用系统 ping 命令 ────────────────────────────────────────────

def ping_host(host: str, count=PING_COUNT, timeout=PING_TIMEOUT):
    """
    用系统 ping / ping6 测量 ICMP 延迟，返回平均 ms 或 None。
    自动判断 IPv4/IPv6。
    """
    if not host: return None

    # 判断是否 IPv6
    is_v6 = ':' in host
    if is_v6:
        # 优先 ping -6，其次 ping6
        cmds = [
            ['ping', '-6', '-c', str(count), '-W', str(timeout), host],
            ['ping6',      '-c', str(count), '-W', str(timeout), host],
        ]
    else:
        cmds = [
            ['ping',  '-4', '-c', str(count), '-W', str(timeout), host],
            ['ping',        '-c', str(count), '-W', str(timeout), host],
        ]

    for cmd in cmds:
        try:
            out = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, timeout=timeout * count + 2
            ).decode(errors='replace')
            # 解析 "rtt min/avg/max/mdev = 1.234/5.678/9.012/0.123 ms"
            m = re.search(r'rtt[^=]*=\s*[\d.]+/([\d.]+)/', out)
            if m: return int(float(m.group(1)))
            # macOS: "round-trip min/avg/max/stddev = ..."
            m = re.search(r'round-trip[^=]*=\s*[\d.]+/([\d.]+)/', out)
            if m: return int(float(m.group(1)))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                FileNotFoundError):
            continue
    return None

def probe_loop():
    global running
    time.sleep(0.5)
    while running:
        with nodes_lock:
            snap = [(i, n['host']) for i, n in enumerate(nodes)]

        threads = []
        results = {}

        def do_probe(idx, host):
            ms = ping_host(host)
            results[idx] = ms

        for idx, host in snap:
            t = threading.Thread(target=do_probe, args=(idx, host), daemon=True)
            t.start()
            threads.append(t)

        # 等所有探测完成（最多 PING_TIMEOUT*PING_COUNT + 5 秒）
        deadline = time.time() + PING_TIMEOUT * PING_COUNT + 5
        for t in threads:
            remaining = max(0, deadline - time.time())
            t.join(timeout=remaining)

        with nodes_lock:
            for idx, ms in results.items():
                if idx < len(nodes):
                    nodes[idx]['latency'] = ms
                    nodes[idx]['status']  = 'ok' if ms is not None else 'timeout'

        for _ in range(int(PROBE_INTERVAL / 0.2)):
            if not running: break
            time.sleep(0.2)

# ── 日志监听 ─────────────────────────────────────────────────────────────────

def resolve_dialer(dialer_id: str) -> str:
    """将 dae 内部 dialer 名（如 node4）映射为节点真实名称"""
    # 尝试从 nodes 列表按顺序匹配：node0→nodes[0], node1→nodes[1] ...
    m = re.match(r'^node(\d+)$', dialer_id, re.IGNORECASE)
    if m:
        idx = int(m.group(1))
        with nodes_lock:
            if 0 <= idx < len(nodes):
                return nodes[idx]['name']
    # 若已经是具体名字或无法映射，原样返回
    return dialer_id

def parse_log(raw: str):
    lm = re.search(r'level=(\w+)', raw)
    mm = re.search(r'msg="([^"]*)"', raw)
    tm = re.search(r'(\d{2}:\d{2}:\d{2})', raw)
    t   = tm.group(1) if tm else time.strftime('%H:%M:%S')
    msg = mm.group(1) if mm else raw[-110:]
    lvl_raw = lm.group(1).lower() if lm else 'info'
    lmap = {'info':'INFO','warning':'WARN','warn':'WARN',
            'error':'ERRO','err':'ERRO','debug':'DEBG'}
    lvl = lmap.get(lvl_raw, 'INFO')

    # ── 结构化字段提取 ──────────────────────────────────────────────────────────
    # 源地址/目标地址 (src -> dst 或 connection 字段)
    src_m  = re.search(r'src="?([^\s"]+)"?', raw)
    dst_m  = re.search(r'dst="?([^\s"]+)"?', raw)
    # 协议
    proto_m = re.search(r'\b(tcp6?|udp6?|tun)\b', raw, re.IGNORECASE)
    proto   = proto_m.group(1).lower() if proto_m else ''

    # 策略组：outbound/group
    om = re.search(r'outbound="([^"]+)"', raw) or \
         re.search(r'outbound=(\S+)',     raw) or \
         re.search(r'group="([^"]+)"',   raw) or \
         re.search(r'group=(\S+)',        raw)
    group = om.group(1) if om else ''

    # dialer → 节点
    dm = re.search(r'dialer=(\S+)', raw)
    node_name = resolve_dialer(dm.group(1)) if dm else ''

    # qname（DNS 查询域名）
    qm = re.search(r'_qname[="]([^\s"]+)', raw)
    qname = qm.group(1) if qm else ''

    # ── 拼装显示行（对齐图中样式） ─────────────────────────────────────────────
    # 有源/目的地址时，格式：src <-> dst  proto  → proxy  [group]
    if src_m and dst_m:
        src, dst = src_m.group(1), dst_m.group(1)
        parts = [f"{src} <-> {dst}"]
        if proto:   parts.append(f"  {proto}")
        if node_name: parts.append(f"  → {node_name}")
        elif group:   parts.append(f"  → proxy")
        if group:   parts.append(f"  [{group}]")
        body = ''.join(parts)
    else:
        # 普通消息：保留原始 msg，附加可用字段
        extras = []
        if group:     extras.append(f"[{group}]")
        if node_name: extras.append(f"→ {node_name}")
        if qname:     extras.append(qname)
        suf  = '   ' + '  '.join(extras) if extras else ''
        body = f"{msg}{suf}"

    # lvl 标签宽度固定为 4 字符，作为独立段便于 curses 上色
    return f" {lvl} \t{t}  {body}", lvl

raw_log_buffer = collections.deque(maxlen=50)   # 保留最近50条原始日志行

def log_loop():
    global running
    try:
        proc = subprocess.Popen(
            ['journalctl', '-u', 'dae', '-f', '-n', '50', '--no-pager'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while running:
            line = proc.stdout.readline()
            if line:
                raw_log_buffer.append(line.rstrip())
                log_buffer.append(parse_log(line.strip()))
    except Exception as e:
        log_buffer.append((f"日志线程异常: {e}", "ERRO"))

# ── UI ───────────────────────────────────────────────────────────────────────

BAR_CHARS = '▏▎▍▌▋▊▉█'
BAR_EMPTY = '░'

def hbar(val, maxval, width, empty=BAR_EMPTY):
    """htop 风格进度条，空白用 ░ 填充"""
    if maxval <= 0: maxval = 1
    r    = min(val / maxval, 1.0) * width
    full = int(r)
    frac = r - full
    bar  = '█' * full
    if full < width:
        sub = BAR_CHARS[int(frac * 8)] if int(frac * 8) > 0 else empty
        bar += sub + empty * (width - full - 1)
    return bar[:width]

def hbar_plain(val, maxval, width):
    """无 ░ 版，用于小型 dae 仪表"""
    if maxval <= 0: maxval = 1
    r    = min(val / maxval, 1.0) * width
    full = int(r)
    frac = r - full
    bar  = '█' * full
    if full < width:
        sub = BAR_CHARS[int(frac * 8)] if int(frac * 8) > 0 else ' '
        bar += sub + ' ' * (width - full - 1)
    return bar[:width]

def lat_c(ms, p):
    if ms is None: return p['warn']
    if ms < 150:   return p['good']
    if ms < 400:   return p['warn']
    return p['bad']

def fmt_speed(b):
    """格式化速度，固定宽度 9 字符：'  1.23 MB'"""
    for u in ['B ', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024.0: return f"{b:6.2f} {u}"
        b /= 1024.0
    return f"{b:6.2f} PB"

def fmt_size(b):
    """格式化大小，紧凑形式"""
    for u in ['B','KB','MB','GB','TB']:
        if b < 1024.0: return f"{b:.1f}{u}"
        b /= 1024.0
    return f"{b:.1f}PB"

def draw(stdscr, p):
    H, W = stdscr.getmaxyx()
    stdscr.erase()
    SEP = '─' * (W - 1)

    # ── 从缓存读取（无闪烁）────────────────────────────────────────────────────
    with _res_lock:
        up_s       = _res['up_s']
        dn_s       = _res['dn_s']
        net_sent   = _res['net_sent']
        net_recv   = _res['net_recv']
        load1      = _res['load1']
        load5      = _res['load5']
        load15     = _res['load15']
        dae_cpu    = _res['dae_cpu']
        dae_mem    = _res['dae_mem']
        dae_status = _res['dae_status']
        dae_pid    = _res['dae_pid']
        dae_ct     = _res['dae_create_time']
        sys_mem    = _res['mem_total']

    # dae mem 占总内存百分比（用于进度条）
    dae_mem_pct = (dae_mem / sys_mem * 100.0) if sys_mem > 0 else 0.0

    # dae 运行时长字符串
    def fmt_uptime(ct):
        if ct is None: return '—'
        secs = int(time.time() - ct)
        d, r = divmod(secs, 86400)
        h, r = divmod(r, 3600)
        m, s = divmod(r, 60)
        if d:   return f"{d}d {h:02d}:{m:02d}:{s:02d}"
        return f"{h:02d}:{m:02d}:{s:02d}"

    # ── 颜色阈值 ───────────────────────────────────────────────────────────────
    def pct_color(v):
        return p['good'] if v < 60 else (p['warn'] if v < 85 else p['bad'])

    cpu_c  = pct_color(dae_cpu)
    mem_c  = pct_color(dae_mem_pct)

    # ── 进度条宽度（自适应终端宽度）──────────────────────────────────────────
    # 新布局：  "  CPU[|||||||  20.7%]   右侧信息"
    # 百分比数字宽 7 (" 20.7%") + 1空格padding，内嵌在进度条右端
    LABEL_W  = 5    # "  CPU"
    INFIX_W  = 7    # " 20.7%" 在括号内右侧占位
    # 右侧信息区宽度估算（dae状态+负载约40字符）
    RIGHT_W  = min(44, W // 2)
    BAR_W    = max(14, min(40, W - LABEL_W - INFIX_W - 4 - RIGHT_W))

    def draw_row(row, label, label_c, bar_pct, bar_c, pct_str, right_str):
        """
        新 htop 风格：
          {label}[|||||||||  20.7%]   {right_str}
          百分比嵌入 [] 右端，进度条缩短为剩余空间
        """
        x = 0
        lbl = f"  {label:3s}"
        safe_add(stdscr, row, x, lbl, curses.color_pair(label_c) | curses.A_BOLD)
        x += len(lbl)
        safe_add(stdscr, row, x, '[', curses.color_pair(p['hdr']))
        x += 1

        bar_inner = BAR_W  # 进度条实际字符数（填充 + 空白 + pct_str）
        filled = max(0, min(bar_inner, int(bar_pct / 100.0 * bar_inner)))

        # 填充段：彩色 |
        if filled > 0:
            safe_add(stdscr, row, x, '|' * filled,
                     curses.color_pair(bar_c) | curses.A_BOLD)
        # 空白段（百分比字符之前）
        blank = bar_inner - filled - len(pct_str)
        if blank > 0:
            safe_add(stdscr, row, x + filled, ' ' * blank,
                     curses.color_pair(p['sep']))
        # 百分比，嵌在 [] 最右端（暗色，叠在空白段上）
        pct_x = x + bar_inner - len(pct_str)
        safe_add(stdscr, row, pct_x, pct_str,
                 curses.color_pair(bar_c) | curses.A_BOLD)

        x += bar_inner
        safe_add(stdscr, row, x, ']', curses.color_pair(p['hdr']))
        x += 1
        if right_str and x + 1 < W - 1:
            safe_add(stdscr, row, x, right_str[:W-1-x], curses.color_pair(p['good']) | curses.A_BOLD)

    # ════════════════════════════════════════════════════════════════════════════
    # 行 0：标题栏（蓝底填满，左右分段渲染，用 wcslen 正确计算宽字符宽度）
    # ════════════════════════════════════════════════════════════════════════════
    now  = time.strftime('%H:%M:%S')
    left = " dae-monitor "
    if search_mode:
        right = f" {now} [Enter]确认 [Esc]取消 "
    elif search_str:
        right = f" {now} [/]搜索 [Esc]清除 [D]转储 [P]隐私 [Q]退出 "
    else:
        right = f" {now} [/]搜索 [D]转储 [P]隐私 [Q]退出 "
    safe_add(stdscr, 0, 0, ' ' * (W - 1), curses.color_pair(p['title']) | curses.A_BOLD)
    safe_add(stdscr, 0, 0, left, curses.color_pair(p['title']) | curses.A_BOLD)
    rw  = wcslen(right)
    lw  = wcslen(left)
    rx  = max(lw, W - 1 - rw)
    safe_add(stdscr, 0, rx, right, curses.color_pair(p['title']) | curses.A_BOLD)

    # ════════════════════════════════════════════════════════════════════════════
    # 行 1：dae CPU     行 2：dae Mem
    # ════════════════════════════════════════════════════════════════════════════
    st_icon = {'running':'●','sleeping':'●','stopped':'○','zombie':'✗'}.get(dae_status, '?')
    st_c    = p['good'] if dae_status in ('running','sleeping') else p['bad']
    pid_s   = f"pid {dae_pid}" if dae_pid else "未运行"

    draw_row(1, 'CPU', p['label'], dae_cpu, cpu_c,
             f" {dae_cpu:5.1f}%",
             f"   运行 {fmt_uptime(dae_ct)}")

    draw_row(2, 'Mem', p['label'], dae_mem_pct, mem_c,
             f" {fmt_size(dae_mem):>9s}",
             None)

    # ════════════════════════════════════════════════════════════════════════════
    # 行 3：网速（实时）+ 累计流量（同行右侧）
    # ════════════════════════════════════════════════════════════════════════════
    x = 0
    safe_add(stdscr, 3, x, '  Net', curses.color_pair(p['label']) | curses.A_BOLD); x += 5
    safe_add(stdscr, 3, x, '  ↑ ', curses.color_pair(p['good']) | curses.A_BOLD);   x += 4
    up_str = fmt_speed(up_s) + '/s'
    safe_add(stdscr, 3, x, up_str, curses.color_pair(p['good']) | curses.A_BOLD);   x += len(up_str)
    safe_add(stdscr, 3, x, '  ↓ ', curses.color_pair(p['good']) | curses.A_BOLD);   x += 4
    dn_str = fmt_speed(dn_s) + '/s'
    safe_add(stdscr, 3, x, dn_str, curses.color_pair(p['good']) | curses.A_BOLD);   x += len(dn_str)
    safe_add(stdscr, 3, x, '   已发 ', curses.color_pair(p['good']) | curses.A_BOLD);  x += 8
    sent_s = fmt_size(net_sent)
    safe_add(stdscr, 3, x, sent_s, curses.color_pair(p['good']) | curses.A_BOLD);   x += len(sent_s)
    safe_add(stdscr, 3, x, '   已收 ', curses.color_pair(p['good']) | curses.A_BOLD);  x += 8
    recv_s = fmt_size(net_recv)
    safe_add(stdscr, 3, x, recv_s[:W-1-x], curses.color_pair(p['good']) | curses.A_BOLD)

    # ════════════════════════════════════════════════════════════════════════════
    # 行 4/5/6：节点表头
    # ════════════════════════════════════════════════════════════════════════════
    # 新列布局：[延迟] 节点名   主机:端口
    C_LAT  =  9   # "[123ms]" 最宽约8字符，留1空格
    C_NODE = 26
    C_HOST = max(20, W - C_LAT - C_NODE - 2)

    safe_add(stdscr, 4, 0, SEP, curses.color_pair(p['sep']))

    # 表头整行蓝底白字，右侧加隐私模式状态提示
    safe_add(stdscr, 5, 0, ' ' * (W - 1), curses.color_pair(p['title']) | curses.A_BOLD)
    x = 0
    for label, width in [
        ('延迟',   C_LAT),
        ('节点名', C_NODE),
        ('主机:端口', C_HOST),
    ]:
        safe_add(stdscr, 5, x, f' {label}', curses.color_pair(p['title']) | curses.A_BOLD)
        x += width + 1
    # 右侧隐私模式提示
    if privacy_mode:
        priv_hint = ' [P] 已隐藏 '
        safe_add(stdscr, 5, W - 1 - len(priv_hint), priv_hint,
                 curses.color_pair(p['title_warn']) | curses.A_BOLD)
    else:
        priv_hint = ' [P] 隐私 '
        safe_add(stdscr, 5, W - 1 - len(priv_hint), priv_hint,
                 curses.color_pair(p['title']))

    safe_add(stdscr, 6, 0, SEP, curses.color_pair(p['sep']))

    # ════════════════════════════════════════════════════════════════════════════
    # 行 7+：节点列表
    # ════════════════════════════════════════════════════════════════════════════
    y = 7
    with nodes_lock:
        nsnap = list(nodes)

    # 按延迟排序：在线(ms升序) → 等待 → 超时
    def sort_key(nd):
        if nd['status'] == 'ok' and nd['latency'] is not None:
            return (0, nd['latency'])
        elif nd['status'] == 'wait':
            return (1, 0)
        else:
            return (2, 0)
    nsnap.sort(key=sort_key)

    for i, nd in enumerate(nsnap):
        if y >= H - 4: break
        ms, st = nd['latency'], nd['status']

        # 延迟列：[123ms] 格式，颜色表示好/中/差
        if st == 'wait':
            lat_s = '[wait…]'
            lc    = p['dim']
        elif ms is None:
            lat_s = '[timeout]'
            lc    = p['bad']
        else:
            lat_s = f'[{ms}ms]'
            lc    = lat_c(ms, p)
        # 延迟列固定宽度右对齐
        lat_field = lat_s.rjust(C_LAT)

        # 主机:端口列
        host    = nd['host'] or '—'
        port    = nd['port']
        hostport = f"{host}:[{port}]"
        hostport_s = hostport[:C_HOST]

        # 节点名颜色奇偶交替
        name_c = p['node'] if i % 2 == 0 else p['host']

        # 隐私模式：用 *** 替换节点名和主机端口
        if privacy_mode:
            disp_name = '•' * min(C_NODE, 12)
            disp_host = '•' * min(C_HOST, 16)
        else:
            disp_name = nd['name']
            host    = nd['host'] or '—'
            port    = nd['port']
            disp_host = f"{host}:[{port}]"

        x = 0
        safe_add(stdscr, y, x, lat_field, curses.color_pair(lc) | curses.A_BOLD)
        x += C_LAT + 1
        safe_add(stdscr, y, x, pad_wcs(disp_name, C_NODE), curses.color_pair(lc))
        x += C_NODE + 1
        safe_add(stdscr, y, x, disp_host[:W-1-x], curses.color_pair(lc))
        y += 1

    # ════════════════════════════════════════════════════════════════════════════
    # 日志区
    # ════════════════════════════════════════════════════════════════════════════
    if y + 2 < H - 1:
        safe_add(stdscr, y, 0, SEP, curses.color_pair(p['sep'])); y += 1

        ll        = list(log_buffer)
        total     = len(ll)
        active_kw = (search_input if search_mode else search_str).lower()
        filtered  = [(m, l) for m, l in ll if (not active_kw or active_kw in m.lower())]
        fcount    = len(filtered)
        info_n    = sum(1 for _, l in ll if l == 'INFO')
        warn_n    = sum(1 for _, l in ll if l == 'WARN')
        erro_n    = sum(1 for _, l in ll if l == 'ERRO')

        # 日志标题行  —  整行蓝底，所有字符均用蓝底色对，底色完整覆盖
        safe_add(stdscr, y, 0, ' ' * (W - 1), curses.color_pair(p['title']) | curses.A_BOLD)
        x = 0
        log_hdr = ' 日志'
        safe_add(stdscr, y, x, log_hdr,
                 curses.color_pair(p['title']) | curses.A_BOLD)
        x += wcslen(log_hdr)

        # 统计徽章：蓝底+对应前景色，底色不会被覆盖
        for badge, cnt, cp in [
            (f"  INFO:{info_n}", info_n, p['title_hdr']),
            (f"  WARN:{warn_n}", warn_n, p['title_warn']),
            (f"  ERRO:{erro_n}", erro_n, p['title_bad']),
            (f"  共{total}条",   1,      p['title_dim']),
        ]:
            if x >= W - 2: break
            safe_add(stdscr, y, x, badge[:W-1-x],
                     curses.color_pair(cp) | (curses.A_BOLD if cnt > 0 else 0))
            x += wcslen(badge)
        if active_kw:
            match_s = f"  ▶ 匹配 {fcount} 条"
            if x < W - 2:
                safe_add(stdscr, y, x, match_s[:W-1-x],
                         curses.color_pair(p['hl']) | curses.A_BOLD)
                x += wcslen(match_s)

        # 搜索提示右对齐，蓝底上叠加
        if search_mode:
            hint = f" 搜索: {search_input}▌ "
            hx = max(x + 2, W - 1 - len(hint))
            safe_add(stdscr, y, hx, hint[:W-1-hx],
                     curses.color_pair(p['hl']) | curses.A_BOLD)
        elif search_str:
            hint = f" 筛选: {search_str}  [Esc 清除] "
            hx = max(x + 2, W - 1 - len(hint))
            safe_add(stdscr, y, hx, hint[:W-1-hx],
                     curses.color_pair(p['title_warn']) | curses.A_BOLD)
        else:
            hint = " [/] 搜索 "
            hx = max(x + 2, W - 1 - len(hint))
            safe_add(stdscr, y, hx, hint[:W-1-hx],
                     curses.color_pair(p['title_dim']))
        y += 1

        # 日志条目：INFO 绿、WARN 黄、ERRO 红、DEBG 暗灰
        lvl_cp  = {'INFO': p['hdr'], 'WARN': p['warn'], 'ERRO': p['bad'], 'DEBG': p['dim']}
        avail   = (H - y - 2) if search_mode else (H - y - 1)
        avail   = max(0, avail)
        # 关键词高亮：黄底黑字（htop 搜索风格）
        hl_attr = curses.color_pair(p['hl']) | curses.A_BOLD

        global log_scroll
        log_scroll = max(0, min(log_scroll, max(0, fcount - avail)))
        start = max(0, fcount - avail - log_scroll)

        # 动态申请日志标签专用颜色对（20-23），初始化一次
        _LVL_PAIR = {'INFO': 20, 'WARN': 21, 'ERRO': 22, 'DEBG': 23}
        _LBL_COLORS = {
            'INFO': (curses.COLOR_BLACK, curses.COLOR_CYAN),
            'WARN': (curses.COLOR_BLACK, curses.COLOR_YELLOW),
            'ERRO': (curses.COLOR_WHITE, curses.COLOR_RED),
            'DEBG': (curses.COLOR_WHITE, 240),
        }
        for _lv, (_fg, _bg) in _LBL_COLORS.items():
            try: curses.init_pair(_LVL_PAIR[_lv], _fg, _bg)
            except Exception: pass

        for msg, lvl in filtered[start:start + avail]:
            if y >= H - 1: break
            # 日志格式：" LVL \tTIME  BODY"，\t 为标签与正文分隔符
            if '\t' in msg:
                label_part, body_part = msg.split('\t', 1)
            else:
                label_part, body_part = msg, ''

            # 标签：实色背景方块
            lbl_attr = curses.color_pair(_LVL_PAIR.get(lvl, p['dim'])) | curses.A_BOLD
            # 正文颜色
            body_cp = curses.color_pair({'INFO': p['hdr'], 'WARN': p['warn'],
                                          'ERRO': p['bad'],  'DEBG': p['dim']}.get(lvl, p['dim']))

            lbl_w = len(label_part)
            safe_add(stdscr, y, 0, label_part, lbl_attr)
            safe_add(stdscr, y, lbl_w, body_part[:W - 1 - lbl_w], body_cp)

            # 关键词高亮
            if active_kw:
                full_line = label_part + body_part
                lo, idx2 = full_line.lower(), 0
                while True:
                    pos = lo.find(active_kw, idx2)
                    if pos == -1: break
                    safe_add(stdscr, y, pos, full_line[pos:pos+len(active_kw)], hl_attr)
                    idx2 = pos + len(active_kw)
            y += 1

        # 搜索输入框（贴底，黄底黑字，有闪烁光标）
        if search_mode:
            prompt  = " / "
            field   = search_input
            display = (prompt + field).ljust(min(W - 1, 72))
            safe_add(stdscr, H-2, 0, display[:W-1],
                     curses.color_pair(p['hl']) | curses.A_BOLD)
            cur_x = len(prompt) + len(field)
            if cur_x < W - 1:
                safe_add(stdscr, H-2, cur_x, '▌',
                         curses.color_pair(p['warn']) | curses.A_BOLD | curses.A_BLINK)

    # ════════════════════════════════════════════════════════════════════════════
    # 底部状态栏
    # ════════════════════════════════════════════════════════════════════════════
    ok = sum(1 for n in nsnap if n['status'] == 'ok')
    to = sum(1 for n in nsnap if n['status'] == 'timeout')
    wt = sum(1 for n in nsnap if n['status'] == 'wait')

    # 状态栏：分段渲染，蓝底填满整行
    # 先用空格填满整行蓝底
    safe_add(stdscr, H-1, 0, ' ' * (W-1),
             curses.color_pair(p['title']) | curses.A_BOLD)

    fx = 0
    def fadd(s, attr=0):
        nonlocal fx
        if fx >= W - 1: return
        clipped, w = wcslice(s, W - 1 - fx)
        safe_add(stdscr, H-1, fx, clipped,
                 curses.color_pair(p['title']) | curses.A_BOLD | attr)
        fx += w

    fadd(f" 节点 ")
    fadd(f"{len(nsnap)}", curses.A_BOLD)
    fadd(f" 个    ")
    fadd(f"✓ {ok} 在线", curses.A_BOLD)
    fadd(f"   ")
    fadd(f"✗ {to} 超时", curses.A_BOLD)
    fadd(f"   ")
    fadd(f"◌ {wt} 等待", curses.A_BOLD)
    fadd(f"   ping×{PING_COUNT}  每{PROBE_INTERVAL:.0f}s探测")
    fadd(f"   {CONFIG_PATH}")
    stdscr.refresh()

# ── 主 ───────────────────────────────────────────────────────────────────────

def main(stdscr):
    global running, log_scroll, nodes, search_mode, search_str, search_input, privacy_mode
    curses.curs_set(0); stdscr.nodelay(1)
    curses.start_color(); curses.use_default_colors()

    def ip(n, fg, fb=-1):
        try: curses.init_pair(n, fg, -1)
        except: curses.init_pair(n, fb, -1)

    # ── 颜色方案（真·htop 风格）────────────────────────────────────────────────
    # 标题栏/状态栏：白字蓝底（htop 最标志性的蓝色顶栏）
    try:
        curses.init_pair(1,  curses.COLOR_WHITE,  curses.COLOR_BLUE)   # title  白字蓝底
    except curses.error:
        curses.init_pair(1,  curses.COLOR_WHITE,  curses.COLOR_BLACK)

    ip(2,  curses.COLOR_GREEN,   curses.COLOR_GREEN)    # good   绿（进度条/在线）
    ip(3,  curses.COLOR_YELLOW,  curses.COLOR_YELLOW)   # warn   黄（中等延迟/警告）
    ip(4,  curses.COLOR_RED,     curses.COLOR_RED)      # bad    红（超时/错误）
    ip(5,  252,                  curses.COLOR_WHITE)    # node   浅灰（节点名，中层）
    ip(6,  240,                  curses.COLOR_WHITE)    # dim    深灰（次要信息，暗层）
    ip(7,  curses.COLOR_BLUE,    curses.COLOR_BLUE)     # net    蓝（上传）
    ip(8,  curses.COLOR_WHITE,   curses.COLOR_WHITE)    # host   白（主机名，主层）
    ip(9,  242,                  curses.COLOR_WHITE)    # port   中灰（端口，暗层）
    ip(10, curses.COLOR_CYAN,    curses.COLOR_CYAN)     # hdr    青（表头/日志标题）
    ip(11, 240,                  curses.COLOR_WHITE)    # sep    深灰（分隔线/括号）
    ip(12, curses.COLOR_GREEN,   curses.COLOR_GREEN)    # label  绿（CPU/Mem/Net标签，同进度条）
    ip(13, curses.COLOR_GREEN,   curses.COLOR_GREEN)    # dae_ok 绿
    ip(14, 240,                  curses.COLOR_WHITE)    # dae_dim 深灰

    # 搜索高亮：黄底黑字（htop 搜索风格）
    try:
        curses.init_pair(15, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    except curses.error:
        curses.init_pair(15, curses.COLOR_BLACK, curses.COLOR_WHITE)

    # 蓝底版颜色对（专用于日志标题行/节点表头，保持蓝底不被覆盖）
    def ip_blue(n, fg, fb=curses.COLOR_WHITE):
        try: curses.init_pair(n, fg, curses.COLOR_BLUE)
        except: curses.init_pair(n, fb, curses.COLOR_BLUE)

    ip_blue(16, curses.COLOR_CYAN)     # title_hdr  蓝底青字（INFO）
    ip_blue(17, curses.COLOR_YELLOW)   # title_warn 蓝底黄字（WARN）
    ip_blue(18, curses.COLOR_RED)      # title_bad  蓝底红字（ERRO）
    ip_blue(19, curses.COLOR_WHITE)    # title_dim  蓝底白字（共N条）

    p = dict(title=1, good=2, warn=3, bad=4, node=5, dim=6,
             net=7, host=8, port=9, hdr=10, sep=11, label=12,
             dae_ok=13, dae_dim=14, hl=15,
             title_hdr=16, title_warn=17, title_bad=18, title_dim=19)

    with nodes_lock:
        nodes = load_nodes()
    log_buffer.append((f"已加载 {len(nodes)} 个节点，开始 ping 探测…", "INFO"))

    threading.Thread(target=probe_loop, daemon=True).start()
    threading.Thread(target=log_loop,   daemon=True).start()
    threading.Thread(target=_res_loop,  daemon=True).start()

    while running:
        try: draw(stdscr, p)
        except curses.error: pass

        # 搜索模式下加快刷新，普通模式按配置间隔
        stdscr.timeout(100 if search_mode else int(REFRESH_INTERVAL * 1000))
        ch = stdscr.getch()

        if search_mode:
            if ch == 27:                          # ESC：取消搜索，清空
                search_mode = False
                search_input = ""
                search_str   = ""
                log_scroll   = 0
            elif ch in (10, 13, curses.KEY_ENTER): # Enter：确认过滤
                search_str   = search_input
                search_mode  = False
                log_scroll   = 0
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                search_input = search_input[:-1]
                log_scroll   = 0
            elif ch == curses.KEY_UP:
                log_scroll += 1
            elif ch == curses.KEY_DOWN:
                log_scroll = max(0, log_scroll - 1)
            elif 32 <= ch <= 126:                 # 可打印 ASCII
                search_input += chr(ch)
                log_scroll   = 0
        else:
            if ch in (ord('q'), ord('Q')):
                break
            elif ch == ord('/'):                  # 进入搜索
                search_mode  = True
                search_input = search_str         # 从上次过滤词开始编辑
                log_scroll   = 0
            elif ch in (ord('p'), ord('P')):      # 切换隐私模式
                privacy_mode = not privacy_mode
            elif ch in (ord('d'), ord('D')):      # 转储原始日志到 /tmp/dae-raw.log
                try:
                    with open('/tmp/dae-raw.log', 'w') as f:
                        for line in raw_log_buffer:
                            f.write(line + '\n')
                    log_buffer.append((f"已转储 {len(raw_log_buffer)} 条原始日志到 /tmp/dae-raw.log", "INFO"))
                except Exception as e:
                    log_buffer.append((f"转储失败: {e}", "ERRO"))
            elif ch == 27:                        # ESC：清空过滤但不进搜索
                search_str  = ""
                search_input = ""
                log_scroll  = 0
            elif ch == curses.KEY_UP:
                log_scroll += 1
            elif ch == curses.KEY_DOWN:
                log_scroll = max(0, log_scroll - 1)

    running = False

if __name__ == '__main__':
    try: curses.wrapper(main)
    except KeyboardInterrupt: pass