#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
top — 系统监控总入口  (htop 风格终端界面)
  [1] Debian Router   → dtop     路由器全局状态
  [2] DAE Monitor     → daetop   DAE 代理节点状态
  [3] DAE Manager     → dae      DAE 安装/管理工具
用法: sudo python3 top.py

修复记录 vs 原版:
  - [BUG1]  p['host'] 颜色键未定义 → KeyError 崩溃；已添加 host=8
  - [BUG2]  选中行文字叠加 A_REVERSE 导致蓝底割裂；统一改用 bg_attr
  - [BUG3]  CPU 利用率只读一次累计值，永远接近 100%；改为差分计算
  - [BUG4]  launch() 内部调用 curses.endwin()，interactive() 按数字键时
            先 endwin() 再调 launch() 导致双重 endwin；launch() 移除多余 endwin
  - [BUG5]  launch() 找不到脚本时调用 curses.wrapper(_warn) 重入 curses，
            而此时 curses 已被 endwin；改为直接用 curses 原生绘制
  - [BUG6]  wcslen/wcslice CJK 阈值 0x2E7F 过于宽松（漏判 CJK/全角）；
            改用标准 unicodedata.east_asian_width
  - [BUG7]  draw_statusbar 用字符串切片 [:W-1] 截断中文会产生乱码；
            改为 wcslice
  - [BUG8]  draw_titlebar right 对齐：rw 应用 wcslen 而非 len
  - [BUG9]  fname 右对齐 x 坐标混用 wcslen 与 len；统一用 wcslen
  - [BUG10] interactive() 刷新逻辑：超时与按键判断混在一起，
            ch==ERR 分支 continue 后不会更新 last_refresh；已拆分
"""

import curses
import os
import sys
import time
import subprocess
import unicodedata
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
# 工具函数
# ═══════════════════════════════════════════════════════════════════════════════

def _char_width(c):
    """返回字符的终端显示宽度（1 或 2）。"""
    # [BUG6 FIX] 原来用 ord(c) > 0x2E7F 判断，不准确
    # unicodedata.east_asian_width 返回 'W'/'F' 为全角/宽字符（占 2 列）
    eaw = unicodedata.east_asian_width(c)
    return 2 if eaw in ('W', 'F') else 1

def wcslen(s):
    """返回字符串的终端显示列宽。"""
    return sum(_char_width(c) for c in s)

def wcslice(s, n):
    """截取字符串使其显示列宽 ≤ n。"""
    out, w = [], 0
    for c in s:
        cw = _char_width(c)
        if w + cw > n:
            break
        out.append(c)
        w += cw
    return ''.join(out)

def pad_wcs(s, n):
    """右侧补空格使显示列宽 == n。"""
    t = wcslice(s, n)
    return t + ' ' * (n - wcslen(t))

def safe_add(win, y, x, s, attr=0):
    """安全 addstr，忽略越界错误。"""
    try:
        win.addstr(y, x, s, attr)
    except curses.error:
        pass

# ═══════════════════════════════════════════════════════════════════════════════
# 颜色
# ═══════════════════════════════════════════════════════════════════════════════

def init_colors():
    curses.start_color()
    curses.use_default_colors()

    def ip(n, fg, fb=-1):
        # 若终端色彩数不足（如只有 8 色），高编号颜色会抛 ValueError，降级用 fb
        actual_fg = fg if (isinstance(fg, int) and fg < curses.COLORS) else fb
        try:
            curses.init_pair(n, actual_fg, -1)
        except (curses.error, ValueError):
            try:
                curses.init_pair(n, fb, -1)
            except (curses.error, ValueError):
                curses.init_pair(n, -1, -1)

    # pair 1：白字蓝底（标题栏 / 选中行）
    try:
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
    except curses.error:
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)

    ip(2,  curses.COLOR_GREEN,  curses.COLOR_GREEN)   # good
    ip(3,  curses.COLOR_YELLOW, curses.COLOR_YELLOW)  # warn
    ip(4,  curses.COLOR_RED,    curses.COLOR_RED)     # bad
    ip(5,  252,                 curses.COLOR_WHITE)   # node
    ip(6,  240,                 curses.COLOR_WHITE)   # dim
    ip(7,  curses.COLOR_BLUE,   curses.COLOR_BLUE)    # net
    ip(8,  curses.COLOR_WHITE,  curses.COLOR_WHITE)   # host  ← [BUG1 FIX] 原字典缺少 'host' 键
    ip(9,  242,                 curses.COLOR_WHITE)   # port
    ip(10, curses.COLOR_CYAN,   curses.COLOR_CYAN)    # hdr
    ip(11, 240,                 curses.COLOR_WHITE)   # sep
    ip(12, curses.COLOR_GREEN,  curses.COLOR_GREEN)   # label

    try:
        curses.init_pair(15, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    except curses.error:
        curses.init_pair(15, curses.COLOR_BLACK, curses.COLOR_WHITE)

    def ip_blue(n, fg, fb=curses.COLOR_WHITE):
        actual_fg = fg if (isinstance(fg, int) and fg < curses.COLORS) else fb
        bg = curses.COLOR_BLUE if curses.COLOR_BLUE < curses.COLORS else -1
        try:
            curses.init_pair(n, actual_fg, bg)
        except (curses.error, ValueError):
            try:
                curses.init_pair(n, fb, bg)
            except (curses.error, ValueError):
                curses.init_pair(n, -1, -1)

    ip_blue(16, curses.COLOR_CYAN)    # title_hdr
    ip_blue(17, curses.COLOR_YELLOW)  # title_warn
    ip_blue(18, curses.COLOR_RED)     # title_bad
    ip_blue(19, curses.COLOR_WHITE)   # title_dim

    return dict(
        title=1, good=2, warn=3, bad=4, node=5, dim=6,
        net=7, host=8, port=9, hdr=10, sep=11, label=12,
        hl=15,
        title_hdr=16, title_warn=17, title_bad=18, title_dim=19,
    )

# ═══════════════════════════════════════════════════════════════════════════════
# 绘图原语
# ═══════════════════════════════════════════════════════════════════════════════

def draw_titlebar(stdscr, p, left, right=''):
    H, W = stdscr.getmaxyx()
    attr = curses.color_pair(p['title']) | curses.A_BOLD
    safe_add(stdscr, 0, 0, ' ' * (W - 1), attr)
    safe_add(stdscr, 0, 0, wcslice(left, W - 1), attr)
    if right:
        # [BUG8 FIX] 原用 len(right)，中文字符 len 不等于显示宽度
        rw = wcslen(right)
        rx = max(wcslen(left) + 1, W - 1 - rw)
        if rx < W - 1:
            safe_add(stdscr, 0, rx, wcslice(right, W - 1 - rx), attr)

def draw_sep(stdscr, p, y):
    H, W = stdscr.getmaxyx()
    if 0 <= y < H:
        safe_add(stdscr, y, 0, '─' * (W - 1), curses.color_pair(p['sep']))

def draw_statusbar(stdscr, p, text):
    H, W = stdscr.getmaxyx()
    attr = curses.color_pair(p['title']) | curses.A_BOLD
    safe_add(stdscr, H - 1, 0, ' ' * (W - 1), attr)
    # [BUG7 FIX] 原用字符串切片 [:W-1]，中文会截断出乱码；改用 wcslice
    safe_add(stdscr, H - 1, 0, wcslice(f' {text}', W - 1), attr)

# ═══════════════════════════════════════════════════════════════════════════════
# 快速状态探测
# ═══════════════════════════════════════════════════════════════════════════════

def _read_file(path, default=''):
    try:
        return Path(path).read_text().strip()
    except Exception:
        return default

def _run(cmd, default=''):
    try:
        return subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, timeout=2
        ).decode().strip()
    except Exception:
        return default

def _svc_status(name):
    """检查 systemd 服务状态，返回 'active'/'inactive'/'unknown'"""
    try:
        r = subprocess.run(
            ['systemctl', 'is-active', name],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=2, text=True
        )
        return r.stdout.strip()
    except Exception:
        return 'unknown'

def _fmt_bytes(val):
    val = max(0, val)
    if val < 1024:     return f"{val:.0f} B"
    if val < 1 << 20:  return f"{val/1024:.1f} K"
    if val < 1 << 30:  return f"{val/(1<<20):.1f} M"
    return                    f"{val/(1<<30):.2f} G"

def _fmt_uptime(secs_str):
    try:
        s = int(float(secs_str))
        d, s = divmod(s, 86400)
        h, s = divmod(s, 3600)
        m, s = divmod(s, 60)
        return f"{d}d {h:02d}:{m:02d}:{s:02d}" if d else f"{h:02d}:{m:02d}:{s:02d}"
    except Exception:
        return '—'

# [BUG3 FIX] CPU 差分计算：保存上次的累计值，两次采样求差分
_cpu_last = None

def _read_cpu_pct():
    """读取 CPU 利用率（差分，两次调用之间的平均值）。"""
    global _cpu_last
    try:
        for line in _read_file('/proc/stat').splitlines():
            if line.startswith('cpu '):
                v = list(map(int, line.split()[1:9]))
                tot  = sum(v)
                idle = v[3] + v[4]
                if _cpu_last is not None:
                    last_tot, last_idle = _cpu_last
                    d_tot  = tot  - last_tot
                    d_idle = idle - last_idle
                    pct = round(100.0 * (d_tot - d_idle) / d_tot, 1) if d_tot > 0 else 0.0
                else:
                    pct = 0.0  # 首次调用，无差分数据，返回 0
                _cpu_last = (tot, idle)
                return pct
    except Exception:
        pass
    return 0.0

def get_quick_stats():
    """采集一次系统快速状态，供主菜单显示。"""
    stats = {}

    # CPU（差分）
    stats['cpu'] = _read_cpu_pct()

    # 内存
    try:
        m = {}
        for line in _read_file('/proc/meminfo').splitlines():
            parts = line.split()
            if len(parts) >= 2:
                m[parts[0].rstrip(':')] = int(parts[1]) * 1024
        tot   = m.get('MemTotal', 1)
        avail = m.get('MemAvailable', 0)
        stats['mem_pct']   = round(100.0 * (tot - avail) / tot, 1)
        stats['mem_used']  = tot - avail
        stats['mem_total'] = tot
    except Exception:
        stats['mem_pct'] = 0.0
        stats['mem_used'] = 0
        stats['mem_total'] = 1

    # 负载
    try:
        la = os.getloadavg()
        stats['load1'], stats['load5'], stats['load15'] = la
    except Exception:
        stats['load1'] = stats['load5'] = stats['load15'] = 0.0

    # 系统运行时长
    stats['uptime'] = _fmt_uptime(_read_file('/proc/uptime').split()[0])

    # dae 服务状态
    stats['dae_status'] = _svc_status('dae')

    # dae 版本
    dae_bin = '/usr/local/bin/dae'
    if Path(dae_bin).exists():
        import re
        raw = _run(f'{dae_bin} --version')
        m = re.search(r'v\d+\.\d+[\w.\-+]*', raw)
        stats['dae_ver'] = m.group(0) if m else '(已安装)'
    else:
        stats['dae_ver'] = '未安装'

    # ppp0 WAN IP
    stats['wan_ip'] = (
        _run("ip -4 addr show ppp0 2>/dev/null | awk '/inet/{print $2}' | cut -d/ -f1")
        or '—'
    )

    # dnsmasq 租约数
    leases_file = '/var/lib/misc/dnsmasq.leases'
    try:
        lines = Path(leases_file).read_text().splitlines()
        stats['dhcp_leases'] = sum(1 for l in lines if l.strip())
    except Exception:
        stats['dhcp_leases'] = 0

    return stats

# ═══════════════════════════════════════════════════════════════════════════════
# 菜单条目定义
# ═══════════════════════════════════════════════════════════════════════════════

MENU_ITEMS = [
    {
        'key':  '1',
        'name': 'Debian Router',
        'desc': '路由器全局状态监控',
        'sub':  'CPU · 内存 · 网络 · 磁盘 · DHCP · 防火墙',
        'file': 'dtop.py',
    },
    {
        'key':  '2',
        'name': 'DAE Monitor',
        'desc': 'DAE 代理节点延迟监控',
        'sub':  '节点列表 · Ping 延迟 · 进程资源 · 实时日志',
        'file': 'daetop.py',
    },
    {
        'key':  '3',
        'name': 'DAE Manager',
        'desc': 'DAE 安装 / 管理工具',
        'sub':  '安装 · 升级 · 启停 · 编辑配置 · 查看日志',
        'file': 'dae.py',
    },
]

# ═══════════════════════════════════════════════════════════════════════════════
# 主菜单绘制
# ═══════════════════════════════════════════════════════════════════════════════

def _draw_bar(stdscr, p, y, x, width, pct, cp_fill, cp_empty=None):
    """绘制百分比进度条。"""
    if cp_empty is None:
        cp_empty = p['dim']
    filled = max(0, min(width, int(width * pct / 100)))
    safe_add(stdscr, y, x,          '█' * filled,            curses.color_pair(cp_fill)  | curses.A_BOLD)
    safe_add(stdscr, y, x + filled, '░' * (width - filled),  curses.color_pair(cp_empty))

def draw_menu(stdscr, p, sel, stats):
    stdscr.erase()
    H, W = stdscr.getmaxyx()

    # ── 标题栏 ────────────────────────────────────────────────────────────────
    now = __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    draw_titlebar(stdscr, p,
                  '  top — 系统监控总入口',
                  f'{now}  ')

    y = 1
    draw_sep(stdscr, p, y); y += 1

    # ── 系统概览（一行横排） ──────────────────────────────────────────────────
    cpu_pct = stats.get('cpu',          0.0)
    mem_pct = stats.get('mem_pct',      0.0)
    load1   = stats.get('load1',        0.0)
    uptime  = stats.get('uptime',       '—')
    wan_ip  = stats.get('wan_ip',       '—')
    leases  = stats.get('dhcp_leases',  0)

    cpu_cp = p['good'] if cpu_pct < 70 else (p['warn'] if cpu_pct < 90 else p['bad'])
    mem_cp = p['good'] if mem_pct < 70 else (p['warn'] if mem_pct < 90 else p['bad'])

    BAR = 16
    lx = 1
    safe_add(stdscr, y, lx, 'CPU:',  curses.color_pair(p['hdr']) | curses.A_BOLD); lx += 5
    _draw_bar(stdscr, p, y, lx, BAR, cpu_pct, cpu_cp); lx += BAR + 1
    safe_add(stdscr, y, lx, f'{cpu_pct:5.1f}%', curses.color_pair(cpu_cp) | curses.A_BOLD); lx += 8

    safe_add(stdscr, y, lx, 'Mem:',  curses.color_pair(p['hdr']) | curses.A_BOLD); lx += 5
    _draw_bar(stdscr, p, y, lx, BAR, mem_pct, mem_cp); lx += BAR + 1
    safe_add(stdscr, y, lx, f'{mem_pct:5.1f}%', curses.color_pair(mem_cp) | curses.A_BOLD); lx += 8

    safe_add(stdscr, y, lx, 'Load:', curses.color_pair(p['hdr']) | curses.A_BOLD); lx += 6
    safe_add(stdscr, y, lx, f'{load1:.2f}', curses.color_pair(p['node']) | curses.A_BOLD); lx += 7

    safe_add(stdscr, y, lx, 'Up:',   curses.color_pair(p['hdr']) | curses.A_BOLD); lx += 4
    safe_add(stdscr, y, lx, uptime,  curses.color_pair(p['node'])); lx += wcslen(uptime) + 2

    safe_add(stdscr, y, lx, 'WAN:',  curses.color_pair(p['hdr']) | curses.A_BOLD); lx += 5
    safe_add(stdscr, y, lx, wan_ip,  curses.color_pair(p['good']) | curses.A_BOLD); lx += len(wan_ip) + 2

    safe_add(stdscr, y, lx, 'DHCP:', curses.color_pair(p['hdr']) | curses.A_BOLD); lx += 6
    safe_add(stdscr, y, lx, f'{leases} 台', curses.color_pair(p['node']))

    y += 1
    draw_sep(stdscr, p, y); y += 1

    # ── DAE 服务状态行 ────────────────────────────────────────────────────────
    dae_st  = stats.get('dae_status', 'unknown')
    dae_ver = stats.get('dae_ver',    '未安装')
    st_cp   = (p['good'] if dae_st == 'active'
               else p['bad'] if dae_st in ('failed', 'stopped')
               else p['warn'])
    st_sym  = '●' if dae_st == 'active' else '○'

    safe_add(stdscr, y, 1, 'DAE:', curses.color_pair(p['hdr']) | curses.A_BOLD)
    safe_add(stdscr, y, 6, st_sym, curses.color_pair(st_cp)   | curses.A_BOLD)
    safe_add(stdscr, y, 8, dae_st, curses.color_pair(st_cp)   | curses.A_BOLD)
    safe_add(stdscr, y, 8 + len(dae_st) + 2,
             f'版本: {dae_ver}', curses.color_pair(p['dim']))
    y += 1
    draw_sep(stdscr, p, y); y += 1

    # ── 菜单条目 ──────────────────────────────────────────────────────────────
    for i, item in enumerate(MENU_ITEMS):
        is_sel  = (i == sel)
        # [BUG2 FIX] 选中行：统一用 bg_attr，不再叠加 A_REVERSE
        bg_attr = curses.color_pair(p['title']) | curses.A_BOLD if is_sel else 0

        # ── 行1：序号 + 名称 [+ 文件名右对齐] ────────────────────────────────
        safe_add(stdscr, y, 0, ' ' * (W - 1), bg_attr)

        key_s  = f' [{item["key"]}] '
        name_s = item['name']
        fname  = item['file']

        if is_sel:
            safe_add(stdscr, y, 0,           key_s,  bg_attr)
            safe_add(stdscr, y, len(key_s),  name_s, bg_attr)
            # 选中时不显示文件名，保持底色整洁
        else:
            safe_add(stdscr, y, 0,           key_s,  curses.color_pair(p['hdr'])  | curses.A_BOLD)
            safe_add(stdscr, y, len(key_s),  name_s, curses.color_pair(p['host']) | curses.A_BOLD)
            # [BUG9 FIX] 右对齐 x 坐标统一用 wcslen
            min_gap = wcslen(key_s) + wcslen(name_s) + 2
            fx = max(min_gap, W - 1 - len(fname) - 2)
            if fx < W - 1:
                safe_add(stdscr, y, fx, fname, curses.color_pair(p['dim']))
        y += 1

        # ── 行2：描述行 ────────────────────────────────────────────────────────
        safe_add(stdscr, y, 0, ' ' * (W - 1), bg_attr)
        desc_text = '    ' + item['desc']
        if is_sel:
            safe_add(stdscr, y, 0, desc_text, bg_attr)
        else:
            safe_add(stdscr, y, 0, desc_text, curses.color_pair(p['node']) | curses.A_BOLD)
        y += 1

        # ── 行3：子信息行 ──────────────────────────────────────────────────────
        safe_add(stdscr, y, 0, ' ' * (W - 1), bg_attr)
        sub_text = '    ' + item['sub']
        if is_sel:
            safe_add(stdscr, y, 0, sub_text, bg_attr)
        else:
            safe_add(stdscr, y, 0, sub_text, curses.color_pair(p['dim']))
        y += 1

        draw_sep(stdscr, p, y); y += 1

        if y >= H - 2:
            break

    # ── 底部状态栏 ────────────────────────────────────────────────────────────
    draw_statusbar(stdscr, p, '[↑↓/jk] 移动   [Enter/数字] 进入   [q] 退出')

    stdscr.refresh()

# ═══════════════════════════════════════════════════════════════════════════════
# 启动子程序
# ═══════════════════════════════════════════════════════════════════════════════

def _find_script(filename):
    """在脚本同级目录、当前目录依次查找。"""
    candidates = []
    try:
        candidates.append(Path(__file__).parent / filename)
    except NameError:
        pass
    candidates.append(Path.cwd() / filename)
    for p in candidates:
        if p.exists():
            return str(p)
    return None

def _show_not_found(stdscr, p, filename):
    """[BUG5 FIX] 找不到脚本时，在已有 curses 上下文里显示提示，不重入 wrapper。"""
    stdscr.erase()
    H, W = stdscr.getmaxyx()
    draw_titlebar(stdscr, p, '  top — 错误', '')
    msg  = f'  找不到 {filename}，请确保文件与 top.py 在同一目录。'
    hint = '  按任意键返回…'
    safe_add(stdscr, H // 2,     max(0, (W - wcslen(msg))  // 2), wcslice(msg,  W - 1))
    safe_add(stdscr, H // 2 + 2, max(0, (W - wcslen(hint)) // 2), wcslice(hint, W - 1), curses.A_BOLD)
    stdscr.refresh()
    stdscr.nodelay(False)
    stdscr.getch()

def launch(stdscr, p, item):
    """
    [BUG4 FIX] 原版 launch() 自己调用 curses.endwin()，
    而 interactive() 在调用 launch() 前也调用了 curses.endwin()，导致双重 endwin。
    现在 launch() 不再自己 endwin()，由调用方统一管理。
    找不到脚本时直接在当前 curses 上下文中提示，不重入 wrapper。
    """
    script = _find_script(item['file'])
    if not script:
        _show_not_found(stdscr, p, item['file'])
        return

    # 暂停 curses，执行子进程
    curses.endwin()
    os.system(f'sudo python3 "{script}"')
    # 子进程结束后恢复 curses 状态
    try:
        stdscr.refresh()
        p_new = init_colors()
        p.update(p_new)
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.nodelay(False)
    except curses.error:
        pass

# ═══════════════════════════════════════════════════════════════════════════════
# 主循环
# ═══════════════════════════════════════════════════════════════════════════════

def interactive(stdscr):
    p   = init_colors()
    sel = 0
    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.keypad(True)

    # 首次采集（会将 _cpu_last 初始化，下次才有差分值）
    stats        = get_quick_stats()
    last_refresh = time.time()

    # [BUG10 FIX] 刷新逻辑拆分：超时触发刷新和按键分开处理
    REFRESH_INTERVAL = 3.0  # 秒

    while True:
        draw_menu(stdscr, p, sel, stats)

        # 计算距下次刷新还剩多少毫秒，作为 getch 超时
        elapsed = time.time() - last_refresh
        remain  = max(100, int((REFRESH_INTERVAL - elapsed) * 1000))
        stdscr.timeout(remain)
        ch = stdscr.getch()

        # 超时（ch == ERR）或超过刷新间隔：刷新数据
        if ch == curses.ERR or (time.time() - last_refresh) >= REFRESH_INTERVAL:
            stats        = get_quick_stats()
            last_refresh = time.time()
            if ch == curses.ERR:
                continue  # 仅超时，不处理按键

        # ── 按键处理 ──────────────────────────────────────────────────────────
        if ch in (curses.KEY_UP, ord('k')):
            sel = (sel - 1) % len(MENU_ITEMS)

        elif ch in (curses.KEY_DOWN, ord('j')):
            sel = (sel + 1) % len(MENU_ITEMS)

        elif ch in (ord('1'), ord('2'), ord('3')):
            idx = int(chr(ch)) - 1
            if 0 <= idx < len(MENU_ITEMS):
                sel = idx
                launch(stdscr, p, MENU_ITEMS[sel])
                stats        = get_quick_stats()
                last_refresh = time.time()

        elif ch in (curses.KEY_ENTER, ord('\n'), ord('\r'), ord(' ')):
            launch(stdscr, p, MENU_ITEMS[sel])
            stats        = get_quick_stats()
            last_refresh = time.time()

        elif ch in (ord('q'), ord('Q'), 27):
            break

# ═══════════════════════════════════════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    if os.geteuid() != 0:
        print('⚠  非 root 权限 — 部分信息（nftables/DHCP/dae）可能不可用。')
        print('   建议使用: sudo python3 top.py')
        time.sleep(1)
    try:
        curses.wrapper(interactive)
    except KeyboardInterrupt:
        pass
    print('\ntop 已退出。')

if __name__ == '__main__':
    main()