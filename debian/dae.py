#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dae-manager — DAE 管理工具  (daetop.py 风格 htop TUI)
完整对应 dae.sh 功能，修复操作逻辑，统一二级菜单风格
"""
import curses, os, sys, re, time, shutil, hashlib, tempfile, textwrap
import threading, subprocess, platform, zipfile
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
# 常量
# ═══════════════════════════════════════════════════════════════════════════════
DAE_BIN       = "/usr/local/bin/dae"
DAE_CFG       = "/usr/local/etc/dae/config.dae"
DAE_EXAMPLE   = "/usr/local/etc/dae/example.dae"
DAE_SHARE     = "/usr/local/share/dae"
SYSTEMD_SVC   = "/etc/systemd/system/dae.service"
OPENRC_SVC    = "/etc/init.d/dae"
MANAGER_BIN   = "/usr/local/bin/dae-manager"
GITHUB_LATEST = "https://api.github.com/repos/daeuniverse/dae/releases/latest"
GITHUB_API    = "https://api.github.com/repos/daeuniverse/dae"
GEO_BASE      = "https://github.com/v2rayA/dist-v2ray-rules-dat/raw/master"
TOKEN_FILE    = "/usr/local/etc/dae/.gh_token"

# ═══════════════════════════════════════════════════════════════════════════════
# 工具函数（与 daetop.py 完全一致）
# ═══════════════════════════════════════════════════════════════════════════════

def wcslen(s):
    return sum(2 if ord(c) > 0x2E7F else 1 for c in s)

def wcslice(s, n):
    out, w = [], 0
    for c in s:
        cw = 2 if ord(c) > 0x2E7F else 1
        if w + cw > n: break
        out.append(c); w += cw
    return ''.join(out)

def pad_wcs(s, n):
    t = wcslice(s, n)
    return t + ' ' * (n - wcslen(t))

def safe_add(win, y, x, s, attr=0):
    try: win.addstr(y, x, s, attr)
    except curses.error: pass

# ═══════════════════════════════════════════════════════════════════════════════
# GitHub Token 管理
# ═══════════════════════════════════════════════════════════════════════════════

def load_gh_token():
    """从配置文件读取已保存的 GitHub Token，不存在则返回 None。"""
    try:
        p = Path(TOKEN_FILE)
        if p.exists():
            return p.read_text().strip() or None
    except Exception:
        pass
    return None

def save_gh_token(token):
    """将 GitHub Token 保存到配置文件（权限 600）。"""
    try:
        Path(TOKEN_FILE).parent.mkdir(parents=True, exist_ok=True)
        Path(TOKEN_FILE).write_text(token.strip())
        os.chmod(TOKEN_FILE, 0o600)
        return True
    except Exception:
        return False

def gh_api_get(path, token=None):
    """向 GitHub API 发送 GET 请求，返回 (dict|list|None, error_str|None)。"""
    import urllib.request, json
    url = f'https://api.github.com{path}'
    headers = {'User-Agent': 'dae-manager/2.0', 'Accept': 'application/vnd.github+json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read()), None
    except Exception as e:
        return None, str(e)

def gh_api_download(url, dest, token, on_progress=None):
    """
    下载 GitHub artifact zip。
    GitHub artifact 的 archive_download_url 会 302 重定向到 Azure Blob Storage，
    重定向目标不接受 Authorization 头（否则 401）。
    策略：第一步带 Token 请求 GitHub API，手动捕获 302 拿到真实 URL；
          第二步不带任何认证头直接下载该 URL。
    """
    import urllib.request, urllib.error

    # ── 第一步：带 Token 请求，手动捕获重定向，拿到真实下载 URL ───
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # 不跟随重定向

    opener = urllib.request.build_opener(_NoRedirect)
    real_url = url
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'dae-manager/2.0',
                     'Authorization': f'Bearer {token}',
                     'Accept': 'application/vnd.github+json'})
        opener.open(req, timeout=15)
        # 没有重定向则直接用原 URL（少数情况）
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            real_url = e.headers.get('Location', url)
        else:
            return False, f'HTTP Error {e.code}: {e.reason}'
    except Exception as e:
        return False, str(e)

    # ── 第二步：不带 Authorization 下载真实文件 URL ────────────────
    try:
        req2 = urllib.request.Request(
            real_url,
            headers={'User-Agent': 'dae-manager/2.0'})
        with urllib.request.urlopen(req2, timeout=90) as r:
            total = int(r.headers.get('Content-Length', 0))
            done  = 0
            with open(dest, 'wb') as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk: break
                    f.write(chunk); done += len(chunk)
                    if on_progress: on_progress(done, total)
        return True, None
    except Exception as e:
        return False, str(e)

def find_pr_artifacts(pr_number, token, log=None):
    """
    通过 PR 号找到该 PR 所有 workflow runs，然后遍历每个 run 检查是否有
    artifact，返回第一个找到 artifact 的 (artifacts_list, run_id, conclusion)。
    找不到时返回 (None, None, error_str)。

    dae 的 PR build 是两段式：push 触发第一个 workflow run（无 artifact），
    该 run 完成后触发第二个 run（有 artifact）。所以必须遍历全部 runs。
    """
    # 1. 获取 PR 信息（head sha + PR 事件 runs）
    data, err = gh_api_get(f'/repos/daeuniverse/dae/pulls/{pr_number}', token)
    if err or not data:
        return None, None, f'获取 PR #{pr_number} 信息失败: {err}'
    head_sha = data.get('head', {}).get('sha', '')

    def _log(msg):
        if log: log.add(msg, 'INFO')

    # 2. 通过 head_sha 查 runs（最多取 30 条）
    runs = []
    if head_sha:
        rd, _ = gh_api_get(
            f'/repos/daeuniverse/dae/actions/runs?head_sha={head_sha}&per_page=30', token)
        if rd:
            runs = rd.get('workflow_runs', [])

    # 3. 同时通过 PR event 查 runs（补充触发方式不同的情况）
    rd2, _ = gh_api_get(
        f'/repos/daeuniverse/dae/actions/runs?event=pull_request&per_page=50', token)
    if rd2:
        def _matches_pr(r):
            prs = r.get('pull_requests') or []
            if prs and str(prs[0].get('number', '')) == str(pr_number):
                return True
            return head_sha and head_sha in r.get('head_sha', '')
        pr_runs = [r for r in rd2.get('workflow_runs', []) if _matches_pr(r)]
        # 合并去重
        existing_ids = {r['id'] for r in runs}
        for r in pr_runs:
            if r['id'] not in existing_ids:
                runs.append(r)
                existing_ids.add(r['id'])

    if not runs:
        return None, None, (f'PR #{pr_number} 未找到关联的 Actions 运行，'
                            '请确认 CI 已触发且未过期')

    _log(f'找到 {len(runs)} 个关联 runs，逐一检查 artifact…')

    # 4. 按优先级排序：completed+success > completed > 其他，同级按时间倒序
    def run_priority(r):
        st, co = r.get('status', ''), r.get('conclusion', '')
        if st == 'completed' and co == 'success': return 0
        if st == 'completed': return 1
        return 2
    runs.sort(key=run_priority)

    # 5. 遍历每个 run，找第一个有 artifact 的
    for r in runs:
        rid = str(r['id'])
        conclusion = r.get('conclusion') or r.get('status', '?')
        art_data, err2 = gh_api_get(
            f'/repos/daeuniverse/dae/actions/runs/{rid}/artifacts', token)
        if err2 or not art_data:
            continue
        arts = art_data.get('artifacts', [])
        if arts:
            _log(f'Run {rid} ({conclusion}) 有 {len(arts)} 个 artifact')
            return arts, rid, conclusion
        _log(f'Run {rid} ({conclusion}) 无 artifact，继续…')

    # 6. 全都没有 artifact，最后尝试按仓库级搜索（name 包含 dae）
    _log('所有 run 均无 artifact，尝试仓库级搜索…')
    repo_arts, err3 = gh_api_get(
        f'/repos/daeuniverse/dae/actions/artifacts?per_page=100', token)
    if not err3 and repo_arts:
        all_arts = repo_arts.get('artifacts', [])
        # 只取属于该 PR head sha 的（workflow_run.head_sha 字段）
        matched = [a for a in all_arts
                   if head_sha and a.get('workflow_run', {}).get('head_sha', '') == head_sha]
        if matched:
            rid2 = str(matched[0].get('workflow_run', {}).get('id', ''))
            _log(f'仓库级找到 {len(matched)} 个匹配 artifact')
            return matched, rid2, 'success'

    return None, None, (
        f'PR #{pr_number} 的所有 runs 均无构建 artifact\n'
        '可能原因:\n'
        '  · PR build CI 尚未完成（请稍后重试）\n'
        '  · Artifact 已过期（默认保留 90 天）\n'
        '  · 该 PR 没有触发 build workflow')

def get_run_artifacts(run_id, token):
    """获取某次 Actions 运行的全部 artifact 列表（保留供 CLI 兼容使用）。"""
    data, err = gh_api_get(
        f'/repos/daeuniverse/dae/actions/runs/{run_id}/artifacts', token)
    if err or not data:
        return None, f'获取 artifact 列表失败: {err}'
    return data.get('artifacts', []), None

# ═══════════════════════════════════════════════════════════════════════════════
# 颜色（严格复用 daetop.py 颜色对编号）
# ═══════════════════════════════════════════════════════════════════════════════

def init_colors():
    curses.start_color()
    curses.use_default_colors()

    def ip(n, fg, fb=-1):
        try:    curses.init_pair(n, fg, -1)
        except: curses.init_pair(n, fb, -1)

    try:    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
    except: curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)

    ip(2,  curses.COLOR_GREEN,  curses.COLOR_GREEN)
    ip(3,  curses.COLOR_YELLOW, curses.COLOR_YELLOW)
    ip(4,  curses.COLOR_RED,    curses.COLOR_RED)
    ip(5,  252,                 curses.COLOR_WHITE)
    ip(6,  240,                 curses.COLOR_WHITE)
    ip(7,  curses.COLOR_BLUE,   curses.COLOR_BLUE)
    ip(8,  curses.COLOR_WHITE,  curses.COLOR_WHITE)
    ip(9,  242,                 curses.COLOR_WHITE)
    ip(10, curses.COLOR_CYAN,   curses.COLOR_CYAN)
    ip(11, 240,                 curses.COLOR_WHITE)
    ip(12, curses.COLOR_GREEN,  curses.COLOR_GREEN)

    try:    curses.init_pair(15, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    except: curses.init_pair(15, curses.COLOR_BLACK, curses.COLOR_WHITE)

    def ip_blue(n, fg, fb=curses.COLOR_WHITE):
        try:    curses.init_pair(n, fg, curses.COLOR_BLUE)
        except: curses.init_pair(n, fb, curses.COLOR_BLUE)

    ip_blue(16, curses.COLOR_CYAN)
    ip_blue(17, curses.COLOR_YELLOW)
    ip_blue(18, curses.COLOR_RED)
    ip_blue(19, curses.COLOR_WHITE)

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
    safe_add(stdscr, 0, 0, ' ' * (W - 1),
             curses.color_pair(p['title']) | curses.A_BOLD)
    safe_add(stdscr, 0, 0, left,
             curses.color_pair(p['title']) | curses.A_BOLD)
    if right:
        rw = wcslen(right)
        rx = max(wcslen(left) + 1, W - 1 - rw)
        if rx < W - 1:
            safe_add(stdscr, 0, rx, right,
                     curses.color_pair(p['title']) | curses.A_BOLD)

def draw_section_hdr(stdscr, p, y, text, right=''):
    H, W = stdscr.getmaxyx()
    safe_add(stdscr, y, 0, ' ' * (W - 1),
             curses.color_pair(p['title']) | curses.A_BOLD)
    safe_add(stdscr, y, 0, f' {text}',
             curses.color_pair(p['title']) | curses.A_BOLD)
    if right:
        rw = wcslen(right)
        rx = max(wcslen(f' {text}') + 2, W - 1 - rw)
        if rx < W - 1:
            safe_add(stdscr, y, rx, right,
                     curses.color_pair(p['title_dim']))

def draw_sep(stdscr, p, y):
    H, W = stdscr.getmaxyx()
    safe_add(stdscr, y, 0, '─' * (W - 1), curses.color_pair(p['sep']))

def draw_statusbar(stdscr, p, text):
    H, W = stdscr.getmaxyx()
    safe_add(stdscr, H - 1, 0, ' ' * (W - 1),
             curses.color_pair(p['title']) | curses.A_BOLD)
    safe_add(stdscr, H - 1, 0, f' {text}'[:W - 1],
             curses.color_pair(p['title']) | curses.A_BOLD)

# ═══════════════════════════════════════════════════════════════════════════════
# 系统工具
# ═══════════════════════════════════════════════════════════════════════════════

def run(cmd, timeout=30):
    try:
        r = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=timeout
        )
        return r.returncode, (r.stdout or '').strip()
    except subprocess.TimeoutExpired:
        return -1, '命令超时'
    except Exception as e:
        return -1, str(e)

def is_systemd():
    return Path(SYSTEMD_SVC).exists() and bool(shutil.which('systemctl'))

def is_openrc():
    return Path(OPENRC_SVC).exists() and Path('/sbin/openrc-run').exists()

def svc_status():
    if is_systemd():
        _, out = run(['systemctl', 'is-active', 'dae'])
        return out.strip()
    if is_openrc():
        rc, _ = run([OPENRC_SVC, 'status'])
        return 'active' if rc == 0 else 'inactive'
    return 'not-installed'

def local_ver():
    """返回已安装 dae 的版本字符串，获取不到时返回 None。
    兼容正式版 (v0.7.0) 和 PR/dev build。
    dae --version 在 dev build 中退出码可能非 0，故不检查 rc。
    """
    if not Path(DAE_BIN).exists():
        return None
    _, out = run([DAE_BIN, '--version'])
    if out:
        m = re.search(r'v\d+\.\d+[\w.\-+]*', out)
        if m:
            return m.group(0)
        first = out.splitlines()[0].strip()
        if first:
            return first[:40]
    return '(已安装)'

def remote_ver():
    import urllib.request, json
    try:
        req = urllib.request.Request(
            GITHUB_LATEST, headers={'User-Agent': 'dae-manager/2.0'})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get('tag_name')
    except Exception:
        return None

def detect_arch():
    m = platform.machine().lower()
    MAP = {
        'x86_64': None, 'amd64': None,
        'aarch64': 'arm64', 'arm64': 'arm64',
        'armv7l': 'armv7', 'armv7': 'armv7',
        'armv6l': 'armv6',
        'i386': 'x86_32', 'i686': 'x86_32',
        'mips': 'mips32', 'mipsle': 'mips32le',
        'mips64': 'mips64', 'mips64le': 'mips64le',
        'riscv64': 'riscv64',
    }
    if m not in MAP:
        return None, f'不支持的架构: {m}'
    if MAP[m]:
        return MAP[m], None
    cpu = Path('/proc/cpuinfo').read_text(errors='replace') \
          if Path('/proc/cpuinfo').exists() else ''
    if 'avx2' in cpu:  return 'x86_64_v3_avx2', None
    if 'sse'  in cpu:  return 'x86_64_v2_sse',  None
    return 'x86_64', None

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for blk in iter(lambda: f.read(65536), b''): h.update(blk)
    return h.hexdigest()

def download(url, dest, on_progress=None):
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'dae-manager/2.0'})
        with urllib.request.urlopen(req, timeout=90) as r:
            total = int(r.headers.get('Content-Length', 0))
            done  = 0
            with open(dest, 'wb') as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk: break
                    f.write(chunk); done += len(chunk)
                    if on_progress: on_progress(done, total)
        return True, None
    except Exception as e:
        return False, str(e)

# ═══════════════════════════════════════════════════════════════════════════════
# 状态缓存（后台线程定期刷新，主菜单不阻塞）
# ═══════════════════════════════════════════════════════════════════════════════

_state = {'ver': None, 'svc': '…', 'ts': 0}
_state_lock = threading.Lock()

def _refresh_state():
    while True:
        v = local_ver()
        s = svc_status()
        with _state_lock:
            _state['ver'] = v
            _state['svc'] = s
            _state['ts']  = time.time()
        time.sleep(3)

def get_state():
    with _state_lock:
        return _state['ver'], _state['svc']

# ═══════════════════════════════════════════════════════════════════════════════
# TaskLog
# ═══════════════════════════════════════════════════════════════════════════════

class TaskLog:
    def __init__(self):
        self._lines = []
        self._lock  = threading.Lock()

    def add(self, msg, level='INFO'):
        with self._lock: self._lines.append((msg, level))

    def update_last(self, msg, level='INFO'):
        with self._lock:
            if self._lines: self._lines[-1] = (msg, level)
            else:           self._lines.append((msg, level))

    def snapshot(self):
        with self._lock: return list(self._lines)

# ═══════════════════════════════════════════════════════════════════════════════
# 任务执行界面
# ═══════════════════════════════════════════════════════════════════════════════

_LVL_CLR = {'INFO': 'good', 'WARN': 'warn', 'ERRO': 'bad', 'STEP': 'hdr'}

def run_task(stdscr, p, title, fn):
    """
    后台执行 fn(log)，实时显示日志。
    任务完成后：成功自动在 0.8 秒内退出（可提前按键跳过等待）；
    失败则等待用户按键确认后退出。
    返回 (ok, msg) 供调用方弹结果框。
    """
    log    = TaskLog()
    result = {'done': False, 'ok': True, 'msg': ''}

    def worker():
        try:
            result['msg'] = fn(log) or '完成'
        except Exception as e:
            result['msg'] = str(e)
            result['ok']  = False
            log.add(f'错误: {e}', 'ERRO')
        finally:
            result['done'] = True

    threading.Thread(target=worker, daemon=True).start()

    scroll     = 0
    done_at    = None   # 任务完成时的时间戳
    AUTO_EXIT  = 0.8    # 成功后自动退出的等待秒数
    stdscr.nodelay(1)

    while True:
        H, W = stdscr.getmaxyx()
        stdscr.erase()

        # 标题栏状态
        if not result['done']:
            state_s = '执行中…'
            state_cp = curses.color_pair(p['title_dim'])
        elif result['ok']:
            state_s = '✓ 完成'
            state_cp = curses.color_pair(p['title_hdr']) | curses.A_BOLD
        else:
            state_s = '✗ 失败'
            state_cp = curses.color_pair(p['title_bad']) | curses.A_BOLD

        # 标题栏（蓝底，左侧任务名，右侧状态）
        safe_add(stdscr, 0, 0, ' ' * (W - 1),
                 curses.color_pair(p['title']) | curses.A_BOLD)
        safe_add(stdscr, 0, 0, f' {title} ',
                 curses.color_pair(p['title']) | curses.A_BOLD)
        rw = wcslen(f' {state_s} ')
        safe_add(stdscr, 0, W - 1 - rw, f' {state_s} ', state_cp)

        # 日志区
        lines = log.snapshot()
        avail = H - 4
        if len(lines) - scroll > avail:
            scroll = len(lines) - avail
        scroll = max(0, min(scroll, max(0, len(lines) - avail)))

        for i, (msg, lvl) in enumerate(lines[scroll: scroll + avail]):
            y   = 1 + i
            ck  = _LVL_CLR.get(lvl, 'dim')
            cp  = curses.color_pair(p[ck])
            tag = f' [{lvl}] '
            safe_add(stdscr, y, 0,        tag,                    cp | curses.A_BOLD)
            safe_add(stdscr, y, len(tag), msg[:W - 1 - len(tag)], cp)

        # 分隔 + 状态栏
        draw_sep(stdscr, p, H - 2)
        if not result['done']:
            hint = ' [↑↓] 滚动 '
        elif result['ok']:
            remain = max(0.0, AUTO_EXIT - (time.time() - done_at)) if done_at else AUTO_EXIT
            hint = f' ✓ 操作成功，{remain:.0f}s 后自动继续   [任意键] 立即继续 '
        else:
            hint = ' ✗ 操作失败   [任意键] 查看详情 '
        draw_statusbar(stdscr, p, hint)
        stdscr.refresh()
        time.sleep(0.08)

        # 记录完成时间
        if result['done'] and done_at is None:
            done_at = time.time()

        ch = stdscr.getch()
        if result['done']:
            if ch != -1:
                break   # 用户提前按键，立即跳出
            if result['ok'] and done_at and (time.time() - done_at) >= AUTO_EXIT:
                break   # 成功自动跳出
            if not result['ok']:
                pass    # 失败时一直等用户按键
        elif ch == curses.KEY_UP:
            scroll = max(0, scroll - 1)
        elif ch == curses.KEY_DOWN:
            scroll += 1

    stdscr.nodelay(0)
    return result['ok'], result['msg']

# ═══════════════════════════════════════════════════════════════════════════════
# 对话框组件
# ═══════════════════════════════════════════════════════════════════════════════

def _wrap(text, width):
    out = []
    for raw in text.splitlines():
        out += textwrap.wrap(raw, width) if raw.strip() else ['']
    return out

def _box_base(stdscr, p, title, lines, bw_min=46):
    """居中对话框底层，返回 (by, bx, bh, bw)"""
    H, W = stdscr.getmaxyx()
    bw = min(max(bw_min,
                 max((wcslen(l) for l in lines), default=20) + 6,
                 wcslen(title) + 6),
             W - 4)
    bh = min(len(lines) + 5, H - 4)
    by = max(1, (H - bh) // 2)
    bx = max(0, (W - bw) // 2)
    # 背景暗化
    for r in range(H - 1):
        safe_add(stdscr, r, 0, ' ' * (W - 1), curses.color_pair(p['dim']))
    # 对话框背景
    for r in range(bh):
        safe_add(stdscr, by + r, bx, ' ' * bw, curses.color_pair(p['host']))
    # 蓝底标题行
    safe_add(stdscr, by, bx, ' ' * bw,
             curses.color_pair(p['title']) | curses.A_BOLD)
    safe_add(stdscr, by, bx, f' {title} '[:bw],
             curses.color_pair(p['title']) | curses.A_BOLD)
    return by, bx, bh, bw

def msg_box(stdscr, p, title, message, color='host'):
    """消息框，任意键关闭"""
    H, W = stdscr.getmaxyx()
    lines = _wrap(message, W - 10)
    stdscr.nodelay(0)
    while True:
        stdscr.erase()
        by, bx, bh, bw = _box_base(stdscr, p, title, lines)
        for i, ln in enumerate(lines[:bh - 5]):
            ck = color if ln.strip() else 'dim'
            safe_add(stdscr, by + 2 + i, bx + 2, ln[:bw - 4],
                     curses.color_pair(p[ck]))
        # 底部提示
        hint = ' [ 按任意键关闭 ] '
        safe_add(stdscr, by + bh - 2, bx + (bw - len(hint)) // 2, hint,
                 curses.color_pair(p['title']) | curses.A_BOLD)
        # 底部分隔
        safe_add(stdscr, by + bh - 3, bx, '─' * bw,
                 curses.color_pair(p['sep']))
        stdscr.refresh()
        if stdscr.getch() != -1: break

def confirm_box(stdscr, p, title, message):
    """确认框 [←→/Tab] 切换，[Y/N] 快捷键，[Enter] 确认"""
    H, W = stdscr.getmaxyx()
    lines = _wrap(message, W - 10)
    sel   = False   # False=取消  True=确认
    stdscr.nodelay(0)
    while True:
        stdscr.erase()
        by, bx, bh, bw = _box_base(stdscr, p, title, lines)
        for i, ln in enumerate(lines[:bh - 5]):
            safe_add(stdscr, by + 2 + i, bx + 2, ln[:bw - 4],
                     curses.color_pair(p['host']))
        # 分隔
        safe_add(stdscr, by + bh - 3, bx, '─' * bw,
                 curses.color_pair(p['sep']))
        # 按钮（居中，固定间距）
        btn_y  = by + bh - 2
        yes_s  = ' [ 确  认 ] '
        no_s   = ' [ 取  消 ] '
        gap    = 4
        total  = len(yes_s) + gap + len(no_s)
        base_x = bx + max(0, (bw - total) // 2)
        yes_x  = base_x
        no_x   = base_x + len(yes_s) + gap
        yes_a  = (curses.color_pair(p['good']) | curses.A_BOLD | curses.A_REVERSE) \
                 if sel else curses.color_pair(p['dim'])
        no_a   = (curses.color_pair(p['bad'])  | curses.A_BOLD | curses.A_REVERSE) \
                 if not sel else curses.color_pair(p['dim'])
        safe_add(stdscr, btn_y, yes_x, yes_s, yes_a)
        safe_add(stdscr, btn_y, no_x,  no_s,  no_a)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (curses.KEY_LEFT, curses.KEY_RIGHT, ord('\t')):
            sel = not sel
        elif ch in (ord('y'), ord('Y')):   return True
        elif ch in (ord('n'), ord('N'), 27): return False
        elif ch in (10, 13, curses.KEY_ENTER): return sel

def input_box(stdscr, p, title, prompt, default=''):
    """单行输入框，Esc 取消返回 None"""
    H, W = stdscr.getmaxyx()
    bw   = min(72, W - 4)
    prompt_lines = _wrap(prompt, bw - 4)
    bh   = len(prompt_lines) + 6
    by   = max(1, (H - bh) // 2)
    bx   = max(0, (W - bw) // 2)
    buf  = list(default)
    stdscr.nodelay(0)
    while True:
        stdscr.erase()
        for r in range(H - 1):
            safe_add(stdscr, r, 0, ' ' * (W - 1), curses.color_pair(p['dim']))
        for r in range(bh):
            safe_add(stdscr, by + r, bx, ' ' * bw, curses.color_pair(p['host']))
        safe_add(stdscr, by, bx, ' ' * bw,
                 curses.color_pair(p['title']) | curses.A_BOLD)
        safe_add(stdscr, by, bx, f' {title} '[:bw],
                 curses.color_pair(p['title']) | curses.A_BOLD)
        for i, ln in enumerate(prompt_lines):
            safe_add(stdscr, by + 2 + i, bx + 2, ln[:bw - 4],
                     curses.color_pair(p['host']))
        # 输入行（黄底黑字，daetop 搜索框风格）
        inp_y = by + 2 + len(prompt_lines)
        inp   = ''.join(buf)[-(bw - 6):]
        safe_add(stdscr, inp_y, bx + 2, ' ' * (bw - 4),
                 curses.color_pair(p['hl']))
        safe_add(stdscr, inp_y, bx + 2, inp,
                 curses.color_pair(p['hl']) | curses.A_BOLD)
        # 分隔 + 提示
        safe_add(stdscr, by + bh - 3, bx, '─' * bw,
                 curses.color_pair(p['sep']))
        hint = ' [Enter] 确认   [Esc] 取消 '
        safe_add(stdscr, by + bh - 2, bx + (bw - len(hint)) // 2, hint,
                 curses.color_pair(p['title']) | curses.A_BOLD)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch == 27:                              return None
        elif ch in (10, 13, curses.KEY_ENTER):    return ''.join(buf)
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if buf: buf.pop()
        elif 32 <= ch <= 126: buf.append(chr(ch))

def checklist_box(stdscr, p, title, prompt, options):
    """
    多选框，返回选中项下标集合（set），Esc 取消返回 None。
    options: list of (label, default_checked: bool)
    [Space] 切换，[Enter] 确认，[A] 全选，[N] 全不选
    """
    H, W = stdscr.getmaxyx()
    bw   = min(60, W - 4)
    prompt_lines = _wrap(prompt, bw - 4)
    bh   = len(prompt_lines) + len(options) + 7
    bh   = min(bh, H - 4)
    by   = max(1, (H - bh) // 2)
    bx   = max(0, (W - bw) // 2)
    checked = {i for i, (_, d) in enumerate(options) if d}
    cur     = 0
    # max visible option index (capped by box height)
    max_vis = bh - 4 - len(prompt_lines) - 2  # items that fit
    stdscr.nodelay(0)
    while True:
        stdscr.erase()
        for r in range(H - 1):
            safe_add(stdscr, r, 0, ' ' * (W - 1), curses.color_pair(p['dim']))
        for r in range(bh):
            safe_add(stdscr, by + r, bx, ' ' * bw, curses.color_pair(p['host']))
        safe_add(stdscr, by, bx, ' ' * bw,
                 curses.color_pair(p['title']) | curses.A_BOLD)
        safe_add(stdscr, by, bx, f' {title} '[:bw],
                 curses.color_pair(p['title']) | curses.A_BOLD)
        for i, ln in enumerate(prompt_lines):
            safe_add(stdscr, by + 2 + i, bx + 2, ln[:bw - 4],
                     curses.color_pair(p['host']))
        opt_base = by + 2 + len(prompt_lines) + 1
        # Calculate scroll offset so selected item is always visible
        scroll_off = max(0, cur - max_vis + 1) if max_vis > 0 else 0
        for i, (label, _) in enumerate(options):
            vis_i = i - scroll_off
            if vis_i < 0:
                continue
            y = opt_base + vis_i
            if y >= by + bh - 4:
                break
            mark = '●' if i in checked else '○'
            is_cur = (i == cur)
            text = f'  {mark}  {label}'
            if is_cur:
                safe_add(stdscr, y, bx + 2, pad_wcs(text, bw - 4)[:bw - 4],
                         curses.color_pair(p['title']) | curses.A_BOLD)
            else:
                mk_cp = curses.color_pair(p['good'] if i in checked else p['dim'])
                safe_add(stdscr, y, bx + 2, '  ', curses.color_pair(p['host']))
                safe_add(stdscr, y, bx + 4, mark, mk_cp | curses.A_BOLD)
                safe_add(stdscr, y, bx + 7, label[:bw - 9],
                         curses.color_pair(p['host']))
        safe_add(stdscr, by + bh - 3, bx, '─' * bw,
                 curses.color_pair(p['sep']))
        hint = ' [Space]切换  [A]全选  [N]全不选  [Enter]确认  [Esc]取消 '
        safe_add(stdscr, by + bh - 2, bx + max(0, (bw - len(hint)) // 2),
                 hint[:bw], curses.color_pair(p['title']) | curses.A_BOLD)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch == 27: return None
        elif ch in (10, 13, curses.KEY_ENTER): return checked
        elif ch == curses.KEY_UP:   cur = (cur - 1) % len(options)
        elif ch == curses.KEY_DOWN: cur = (cur + 1) % len(options)
        elif ch == ord(' '):
            if cur in checked: checked.discard(cur)
            else: checked.add(cur)
        elif ch in (ord('a'), ord('A')): checked = set(range(len(options)))
        elif ch in (ord('n'), ord('N')): checked = set()

# ═══════════════════════════════════════════════════════════════════════════════
# 主菜单（单列 + 分组，htop 风格左侧菜单 + 右侧状态面板）
# ═══════════════════════════════════════════════════════════════════════════════

# 菜单项定义：(id, label, group)
# group 为 None 时是分组标题行
MENU_ITEMS = [
    # id,  label,              快捷说明
    (None, '─── 服务管理 ───', None),
    ('start',     '启动服务',           's'),
    ('stop',      '停止服务',           'x'),
    ('restart',   '重启服务',           'r'),
    ('reload',    '重载配置',           'l'),
    ('status',    '查看服务状态',       't'),
    ('logs',      '查看实时日志',       'g'),
    (None, '─── 安装管理 ───', None),
    ('install',   '安装 / 更新 dae',    'i'),
    ('update',    '检查并更新',         'u'),
    ('install_pr','安装 PR 构建版',     'p'),
    ('uninstall', '卸载 dae',           None),
    (None, '─── 配置管理 ───', None),
    ('edit',      '编辑配置文件',       'e'),
    ('geoip',     '更新 GeoIP 数据库',  None),
    ('geosite',   '更新 GeoSite 数据库',None),
    (None, '─── 其他 ───', None),
    ('quit',      '退出',               'q'),
]

BANNER = [
    r"   __| | __ _  ___",
    r"  / _` |/ _` |/ _ \ ",
    r" | (_| | (_| |  __/ ",
    r"  \__,_|\__,_|\___| ",
]

# 只含实际菜单项（排除分组标题）
_SELECTABLE = [(i, item) for i, item in enumerate(MENU_ITEMS)
               if item[0] is not None]

def draw_main(stdscr, p, sel_idx):
    """sel_idx：在 _SELECTABLE 中的下标"""
    H, W = stdscr.getmaxyx()
    stdscr.erase()

    ver, svc = get_state()
    ver_s  = ver or '未安装'
    svc_ck = 'good' if svc == 'active' else ('warn' if svc in ('…', 'unknown') else 'bad')
    svc_sym = '●' if svc == 'active' else '○'
    svc_cp  = p['good'] if svc == 'active' else (p['warn'] if svc in ('…','unknown') else p['bad'])

    # ── 标题栏 ──
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    draw_titlebar(stdscr, p, '  dae-manager  DAE 管理工具', f'{now}  ')

    # ── 副信息栏（蓝底，服务状态一览）──
    y = 1
    safe_add(stdscr, y, 0, ' ' * (W - 1),
             curses.color_pair(p['title']) | curses.A_BOLD)
    cx = 1
    safe_add(stdscr, y, cx, '版本:', curses.color_pair(p['title_hdr']) | curses.A_BOLD); cx += 3
    safe_add(stdscr, y, cx, f' {ver_s} ', curses.color_pair(p['title']) | curses.A_BOLD); cx += wcslen(ver_s) + 2
    safe_add(stdscr, y, cx, ' │ ', curses.color_pair(p['title']) | curses.A_BOLD); cx += 3
    safe_add(stdscr, y, cx, '服务:', curses.color_pair(p['title_hdr']) | curses.A_BOLD); cx += 3
    safe_add(stdscr, y, cx, f' {svc_sym} ', curses.color_pair(p['title']) | curses.A_BOLD); cx += 3
    svc_color_key = 'title_hdr' if svc == 'active' else ('title_dim' if svc in ('…', 'unknown') else 'title_warn')
    safe_add(stdscr, y, cx, svc, curses.color_pair(p[svc_color_key]) | curses.A_BOLD); cx += len(svc) + 1
    safe_add(stdscr, y, cx, ' │ ', curses.color_pair(p['title']) | curses.A_BOLD); cx += 3
    cfg_exists = Path(DAE_CFG).exists()
    safe_add(stdscr, y, cx, '配置:', curses.color_pair(p['title_hdr']) | curses.A_BOLD); cx += 3
    safe_add(stdscr, y, cx, f' {DAE_CFG} ', curses.color_pair(p['title_hdr'] if cfg_exists else p['title_warn']) | curses.A_BOLD)
    y += 1

    sel_raw_idx = _SELECTABLE[sel_idx][0]   # 在 MENU_ITEMS 中的绝对下标
    cur_id, cur_label, _ = MENU_ITEMS[sel_raw_idx]

    # ── 菜单节区 ──
    draw_section_hdr(stdscr, p, y, '菜单',
                     f' 当前: {cur_label} ')
    y += 1

    # ── 菜单条目 ──
    # 双栏布局：左右各半宽，节省纵向空间
    COL_W = max(28, (W - 2) // 2)

    # 把 MENU_ITEMS 拆成左右两列，分组标题单独占一行
    # 先收集所有行（含分组标题），再双列渲染
    menu_rows = []   # 每项: ('group', label) | ('item', raw_i, label, is_sel)
    for raw_i, (item_id, label, shortcut) in enumerate(MENU_ITEMS):
        if item_id is None:
            menu_rows.append(('group', label))
        else:
            is_sel = (raw_i == sel_raw_idx)
            key_hint = f'[{shortcut}]' if shortcut else '   '
            menu_rows.append(('item', raw_i, label, is_sel, key_hint))

    for row_data in menu_rows:
        if y >= H - 3:
            break
        if row_data[0] == 'group':
            # 分组标题：用 draw_sep + 文字叠加，青色暗色
            _, grp_label = row_data
            draw_sep(stdscr, p, y)
            # 在分隔线上叠加分组名（青色加粗）
            safe_add(stdscr, y, 2, f' {grp_label} ',
                     curses.color_pair(p['hdr']) | curses.A_BOLD)
        else:
            _, raw_i, label, is_sel, key_hint = row_data
            if is_sel:
                # 选中行：蓝底白字填满整行
                safe_add(stdscr, y, 0, ' ' * (W - 1),
                         curses.color_pair(p['title']) | curses.A_BOLD)
                safe_add(stdscr, y, 2, f'▶ {key_hint} {label}',
                         curses.color_pair(p['title']) | curses.A_BOLD)
                # 右侧显示当前项的快捷描述
                desc_short = _MENU_DESC.get(cur_id, '').splitlines()[0][:W - 40] if _MENU_DESC.get(cur_id) else ''
                if desc_short:
                    rx = max(wcslen(f'▶ {key_hint} {label}') + 4,
                             W - 1 - wcslen(desc_short) - 2)
                    safe_add(stdscr, y, rx, desc_short,
                             curses.color_pair(p['title_dim']))
            else:
                safe_add(stdscr, y, 2, f'  {key_hint} ',
                         curses.color_pair(p['dim']))
                safe_add(stdscr, y, 2 + wcslen(f'  {key_hint} '), label,
                         curses.color_pair(p['host']))
        y += 1

    # ── 描述区（选中项详细说明）──
    if y < H - 3:
        draw_sep(stdscr, p, y); y += 1
        desc = _MENU_DESC.get(cur_id, '')
        if desc and y < H - 2:
            safe_add(stdscr, y, 2, f'说明  ',
                     curses.color_pair(p['hdr']) | curses.A_BOLD)
            for di, dline in enumerate(_wrap(desc, W - 10)):
                if y + di >= H - 2: break
                safe_add(stdscr, y + di, 8, dline[:W - 10],
                         curses.color_pair(p['dim']))

    # ── 状态栏 ──
    draw_statusbar(stdscr, p,
                   ' [↑↓] 移动   [Enter] 执行   [Q] 退出'
                   '   ──   s启动  x停止  r重启  e编辑  i安装  u更新  q退出')
    stdscr.refresh()

_MENU_DESC = {
    'start':      '启动 dae 代理服务。\n若服务已在运行则提示无需重复启动。',
    'stop':       '停止 dae 代理服务。\n若服务未运行则提示。',
    'restart':    '先停止再启动服务，\n用于应用新配置或重置连接状态。',
    'reload':     '验证配置文件后重载，\n不中断现有连接（支持时）。',
    'status':     '显示 systemd/OpenRC 服务详细状态，\n可上下滚动查看。',
    'logs':       '退出 TUI，接管终端显示实时日志。\nCtrl+C 退出日志模式后自动返回。',
    'install':    '从 GitHub 下载并安装最新版 dae，\n同时更新 GeoIP/GeoSite 数据库。',
    'update':     '检查最新版本，若有更新则询问\n是否下载安装。',
    'install_pr': '输入 PR 号自动查找最新构建版本。\n首次使用需输入 GitHub Token，之后无需再输入。',
    'uninstall':  '卸载 dae 主程序及服务，\n可选保留配置文件和数据文件。',
    'edit':       '使用系统编辑器编辑配置文件。\n编辑后自动验证并询问是否重载。',
    'geoip':      '从 v2rayA 仓库下载最新\nGeoIP 数据库并替换。',
    'geosite':    '从 v2rayA 仓库下载最新\nGeoSite 数据库并替换。',
    'quit':       '退出 dae-manager。',
}

def interactive_menu(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(0)
    p   = init_colors()
    sel = 0  # 在 _SELECTABLE 中的下标

    # 启动状态刷新线程
    threading.Thread(target=_refresh_state, daemon=True).start()
    # 立即做一次同步刷新，避免首次显示时状态为 '…'
    with _state_lock:
        _state['ver'] = local_ver()
        _state['svc'] = svc_status()

    while True:
        draw_main(stdscr, p, sel)
        stdscr.timeout(2000)  # 2 秒超时，用于自动刷新状态
        ch = stdscr.getch()
        stdscr.timeout(-1)

        n = len(_SELECTABLE)
        if ch == -1:          # 超时，刷新状态显示
            continue
        elif ch == curses.KEY_UP:
            sel = (sel - 1) % n
        elif ch == curses.KEY_DOWN:
            sel = (sel + 1) % n
        elif ch in (10, 13, curses.KEY_ENTER):
            item_id = _SELECTABLE[sel][1][0]
            if item_id == 'quit': return
            _dispatch(stdscr, p, item_id)
        elif ch in (ord('q'), ord('Q')):
            return
        else:
            # 快捷键
            c = chr(ch).lower() if 0 <= ch <= 127 else ''
            for si, (_, (iid, _, shortcut)) in enumerate(_SELECTABLE):
                if shortcut and c == shortcut:
                    sel = si
                    draw_main(stdscr, p, sel)
                    if iid == 'quit': return
                    _dispatch(stdscr, p, iid)
                    break

# ═══════════════════════════════════════════════════════════════════════════════
# 分发
# ═══════════════════════════════════════════════════════════════════════════════

def _dispatch(stdscr, p, key):
    {
        'start':      act_start,
        'stop':       act_stop,
        'restart':    act_restart,
        'reload':     act_reload,
        'status':     act_status,
        'logs':       act_logs,
        'install':    act_install,
        'update':     act_update,
        'install_pr': act_install_pr,
        'uninstall':  act_uninstall,
        'edit':       act_edit,
        'geoip':      act_geoip,
        'geosite':    act_geosite,
    }.get(key, lambda s, p: None)(stdscr, p)
    # 操作完成后刷新状态缓存
    with _state_lock:
        _state['ver'] = local_ver()
        _state['svc'] = svc_status()

# ═══════════════════════════════════════════════════════════════════════════════
# 共享子任务
# ═══════════════════════════════════════════════════════════════════════════════

def _install_dae_bin(log, ver, arch):
    url   = (f'https://github.com/daeuniverse/dae/releases/download'
             f'/{ver}/dae-linux-{arch}.zip')
    log.add(f'下载 dae {ver} ({arch})…', 'STEP')
    tmp   = tempfile.mkdtemp(prefix='dae.')
    zpath = os.path.join(tmp, 'dae.zip')
    log.add('下载中…', 'INFO')
    def prog(done, total):
        if total:
            log.update_last(
                f'下载中  {done/1048576:.1f} / {total/1048576:.1f} MB'
                f'  ({done/total*100:.0f}%)', 'INFO')
    ok, err = download(url, zpath, prog)
    if not ok:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f'下载 dae 失败: {err}')
    log.add('解压…', 'STEP')
    with zipfile.ZipFile(zpath) as zf:
        zf.extractall(tmp)
    binary = None
    for root, _, files in os.walk(tmp):
        for f in files:
            if f.startswith('dae-linux-') and not f.endswith('.zip'):
                binary = os.path.join(root, f); break
    if not binary:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError('解压后未找到可执行文件')
    Path(DAE_BIN).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, DAE_BIN)
    os.chmod(DAE_BIN, 0o755)
    shutil.rmtree(tmp, ignore_errors=True)
    log.add(f'dae 已安装到 {DAE_BIN}', 'INFO')

def _download_geo(log, kind):
    url  = f'{GEO_BASE}/{kind}.dat'
    log.add(f'下载 {kind}.dat…', 'STEP')
    tmp  = tempfile.mkdtemp(prefix='dae.')
    dest = os.path.join(tmp, f'{kind}.dat')
    log.add('下载中…', 'INFO')
    def prog(done, total):
        if total:
            log.update_last(
                f'下载 {kind}.dat  {done/1048576:.1f}/{total/1048576:.1f} MB'
                f'  ({done/total*100:.0f}%)', 'INFO')
    ok, err = download(url, dest, prog)
    if not ok:
        shutil.rmtree(tmp, ignore_errors=True)
        log.add(f'{kind}.dat 下载失败: {err}', 'WARN')
        return False
    ok2, _ = download(url + '.sha256sum', dest + '.sha256sum')
    if ok2 and Path(dest + '.sha256sum').exists():
        expected = Path(dest + '.sha256sum').read_text().split()[0]
        if sha256(dest) != expected:
            shutil.rmtree(tmp, ignore_errors=True)
            log.add(f'{kind}.dat 校验和不匹配！', 'ERRO')
            return False
        log.add(f'{kind}.dat 校验通过', 'INFO')
    os.makedirs(DAE_SHARE, exist_ok=True)
    shutil.copy2(dest, os.path.join(DAE_SHARE, f'{kind}.dat'))
    shutil.rmtree(tmp, ignore_errors=True)
    log.add(f'{kind}.dat 已安装到 {DAE_SHARE}', 'INFO')
    return True

def _install_service(log, ver):
    if Path('/usr/lib/systemd/systemd').exists():
        url = f'https://github.com/daeuniverse/dae/raw/{ver}/install/dae.service'
        log.add('下载 systemd 服务文件…', 'STEP')
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.service')
        tmp.close()
        ok, err = download(url, tmp.name)
        if not ok:
            os.unlink(tmp.name)
            log.add(f'下载服务文件失败: {err}，跳过', 'WARN')
            return
        content = Path(tmp.name).read_text()
        # BUG FIX: use leading slash to avoid corrupting unrelated path strings
        content = content.replace('/usr/bin', '/usr/local/bin')
        content = content.replace('/etc/dae', '/usr/local/etc/dae')
        Path(SYSTEMD_SVC).write_text(content)
        os.unlink(tmp.name)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', 'dae'])
        log.add('systemd 服务已安装，已设置开机自启', 'INFO')
    elif Path('/sbin/openrc-run').exists():
        url = 'https://github.com/daeuniverse/dae-installer/raw/main/OpenRC/dae'
        log.add('下载 OpenRC 服务文件…', 'STEP')
        ok, err = download(url, OPENRC_SVC)
        if not ok:
            log.add(f'下载失败: {err}，跳过', 'WARN')
            return
        os.chmod(OPENRC_SVC, 0o755)
        run(['rc-update', 'add', 'dae', 'default'])
        log.add('OpenRC 服务已安装，已设置开机自启', 'INFO')
    else:
        log.add('未检测到 systemd/OpenRC，跳过服务安装', 'WARN')

def _download_example_cfg(log, ver):
    Path(DAE_CFG).parent.mkdir(parents=True, exist_ok=True)
    if not Path(DAE_EXAMPLE).exists():
        url = f'https://github.com/daeuniverse/dae/raw/{ver}/example.dae'
        log.add('下载示例配置文件…', 'STEP')
        ok, err = download(url, DAE_EXAMPLE)
        log.add(f'示例配置已保存到 {DAE_EXAMPLE}' if ok
                else f'下载示例配置失败: {err}（可手动下载）',
                'INFO' if ok else 'WARN')

def _install_global_cmd(log):
    script = os.path.abspath(__file__)
    if script != MANAGER_BIN:
        try:
            shutil.copy2(script, MANAGER_BIN)
            os.chmod(MANAGER_BIN, 0o755)
            log.add(f'全局命令已安装: {MANAGER_BIN}', 'INFO')
        except Exception as e:
            log.add(f'全局命令安装失败: {e}', 'WARN')
            return
    for rc_file in ['/etc/bash.bashrc', '/etc/bashrc', '/root/.bashrc',
                    '/etc/zsh/zshrc', '/root/.zshrc']:
        if Path(rc_file).exists():
            txt = Path(rc_file).read_text()
            if 'alias dae=' not in txt:
                # BUG FIX: use context manager to ensure file handle is closed
                with Path(rc_file).open('a') as f:
                    f.write(f'\n# dae management alias\nalias dae=\'{MANAGER_BIN}\'\n')
    fish_d = Path('/root/.config/fish/conf.d')
    if fish_d.exists():
        (fish_d / 'dae.fish').write_text(f"alias dae='{MANAGER_BIN}'\n")
    log.add('shell alias 已配置', 'INFO')

def _svc_start(log):
    if is_systemd():    rc, out = run(['systemctl', 'start', 'dae'])
    elif is_openrc():   rc, out = run([OPENRC_SVC, 'start'])
    else: raise RuntimeError('未找到服务文件，请先安装 dae')
    if rc != 0: raise RuntimeError(f'启动失败: {out}')

def _svc_stop(log):
    if is_systemd():    rc, out = run(['systemctl', 'stop', 'dae'])
    elif is_openrc():   rc, out = run([OPENRC_SVC, 'stop'])
    else: raise RuntimeError('未找到服务文件')
    if rc != 0: raise RuntimeError(f'停止失败: {out}')

# ═══════════════════════════════════════════════════════════════════════════════
# 各功能 action（正确的操作逻辑）
# ═══════════════════════════════════════════════════════════════════════════════

def act_start(stdscr, p):
    svc = svc_status()
    if svc == 'active':
        msg_box(stdscr, p, '提示', 'dae 服务当前已在运行中。\n若需重启请使用"重启服务"。', 'warn')
        return
    if not Path(DAE_BIN).exists():
        msg_box(stdscr, p, '错误', f'未找到 dae 可执行文件:\n{DAE_BIN}\n\n请先安装 dae。', 'bad')
        return
    def task(log):
        log.add('启动 dae 服务…', 'STEP')
        _svc_start(log)
        time.sleep(1)
        st = svc_status()
        log.add(f'当前状态: {st}', 'INFO' if st == 'active' else 'WARN')
        if st != 'active':
            raise RuntimeError(f'服务启动后状态异常: {st}')
        return '服务启动成功'
    ok, msg = run_task(stdscr, p, '启动 dae 服务', task)
    msg_box(stdscr, p, '启动' + ('成功' if ok else '失败'), msg,
            'good' if ok else 'bad')

def act_stop(stdscr, p):
    svc = svc_status()
    if svc != 'active':
        msg_box(stdscr, p, '提示', f'dae 服务当前未在运行（状态: {svc}）。', 'warn')
        return
    if not confirm_box(stdscr, p, '确认停止', '确定要停止 dae 服务吗？'):
        return
    def task(log):
        log.add('停止 dae 服务…', 'STEP')
        _svc_stop(log)
        log.add('服务已停止', 'INFO')
        return '服务已停止'
    ok, msg = run_task(stdscr, p, '停止 dae 服务', task)
    msg_box(stdscr, p, '停止' + ('成功' if ok else '失败'), msg,
            'good' if ok else 'bad')

def act_restart(stdscr, p):
    if not Path(DAE_BIN).exists():
        msg_box(stdscr, p, '错误', f'未找到 dae:\n{DAE_BIN}\n\n请先安装。', 'bad')
        return
    def task(log):
        log.add('重启 dae 服务…', 'STEP')
        if is_systemd():    rc, out = run(['systemctl', 'restart', 'dae'])
        elif is_openrc():   rc, out = run([OPENRC_SVC, 'restart'])
        else: raise RuntimeError('未找到服务文件')
        if rc != 0: raise RuntimeError(f'重启失败: {out}')
        time.sleep(1)
        st = svc_status()
        log.add(f'当前状态: {st}', 'INFO' if st == 'active' else 'WARN')
        return f'重启成功，当前状态: {st}'
    ok, msg = run_task(stdscr, p, '重启 dae 服务', task)
    msg_box(stdscr, p, '重启' + ('成功' if ok else '失败'), msg,
            'good' if ok else 'bad')

def act_reload(stdscr, p):
    if not Path(DAE_CFG).exists():
        msg_box(stdscr, p, '错误', f'配置文件不存在:\n{DAE_CFG}', 'bad')
        return
    def task(log):
        log.add('验证配置文件…', 'STEP')
        rc, out = run([DAE_BIN, 'validate', '-c', DAE_CFG])
        if rc != 0: raise RuntimeError(f'配置验证失败:\n{out}')
        log.add('验证通过', 'INFO')
        log.add('重载配置…', 'STEP')
        if is_systemd():
            rc, out = run(['systemctl', 'reload', 'dae'])
            if rc != 0:
                log.add('reload 不支持，改用 restart…', 'WARN')
                rc, out = run(['systemctl', 'restart', 'dae'])
        elif is_openrc():
            rc, out = run([OPENRC_SVC, 'reload'])
            if rc != 0: rc, out = run([OPENRC_SVC, 'restart'])
        else:
            raise RuntimeError('未找到服务文件')
        if rc != 0: raise RuntimeError(f'重载失败: {out}')
        log.add('配置已重载', 'INFO')
        return '配置重载成功'
    ok, msg = run_task(stdscr, p, '重载 dae 配置', task)
    msg_box(stdscr, p, '重载' + ('成功' if ok else '失败'), msg,
            'good' if ok else 'bad')

def act_edit(stdscr, p):
    # 若配置不存在，先尝试从示例复制
    if not Path(DAE_CFG).exists():
        if Path(DAE_EXAMPLE).exists():
            ok = confirm_box(stdscr, p, '配置文件不存在',
                             f'发现示例配置:\n{DAE_EXAMPLE}\n\n'
                             '是否复制为正式配置文件后打开编辑？')
            if not ok: return
            shutil.copy2(DAE_EXAMPLE, DAE_CFG)
            os.chmod(DAE_CFG, 0o600)
        else:
            msg_box(stdscr, p, '错误',
                    f'配置文件不存在:\n{DAE_CFG}\n\n'
                    '请先安装 dae（会自动下载示例配置）。', 'bad')
            return

    editor = next((e for e in ['micro', 'nano', 'vi', 'vim'] if shutil.which(e)), None)
    if not editor:
        msg_box(stdscr, p, '错误', '未找到可用编辑器\n(micro / nano / vi / vim)', 'bad')
        return

    # 备份
    bak = f'{DAE_CFG}.backup.{time.strftime("%Y%m%d_%H%M%S")}'
    shutil.copy2(DAE_CFG, bak)

    curses.endwin()
    os.system(f'{editor} "{DAE_CFG}"')
    stdscr.refresh()

    # 验证
    if Path(DAE_BIN).exists():
        rc, out = run([DAE_BIN, 'validate', '-c', DAE_CFG])
        if rc == 0:
            if confirm_box(stdscr, p, '配置验证通过',
                           '配置文件语法验证通过。\n\n是否立即重载配置？'):
                act_reload(stdscr, p)
        else:
            # BUG FIX: use iterative loop instead of recursion to avoid stack overflow
            while confirm_box(stdscr, p, '⚠ 配置验证失败',
                              f'验证失败（已自动备份原文件）:\n\n{out[:400]}\n\n'
                              '是否重新编辑？'):
                curses.endwin()
                os.system(f'{editor} "{DAE_CFG}"')
                stdscr.refresh()
                rc, out = run([DAE_BIN, 'validate', '-c', DAE_CFG])
                if rc == 0:
                    if confirm_box(stdscr, p, '配置验证通过',
                                   '配置文件语法验证通过。\n\n是否立即重载配置？'):
                        act_reload(stdscr, p)
                    break

def act_logs(stdscr, p):
    curses.endwin()
    print('\033[1;34m════ dae 实时日志  [Ctrl+C 返回] ════\033[0m')
    try:
        if shutil.which('journalctl') and Path(SYSTEMD_SVC).exists():
            subprocess.run(['journalctl', '-u', 'dae', '-f',
                            '--no-pager', '-n', '80'])
        elif Path('/var/log/dae.log').exists():
            subprocess.run(['tail', '-f', '/var/log/dae.log'])
        else:
            print('\033[33m未找到日志来源 (journalctl / /var/log/dae.log)\033[0m')
            input('\n按 Enter 返回…')
    except KeyboardInterrupt:
        pass
    stdscr.refresh()

def act_status(stdscr, p):
    if is_systemd():
        _, out = run(['systemctl', 'status', 'dae', '--no-pager'])
    elif is_openrc():
        _, out = run([OPENRC_SVC, 'status'])
    else:
        out = '未找到 dae 服务文件'
    lines = out.splitlines() + [
        '', f'已安装版本 : {local_ver() or "未安装"}',
        f'服务状态   : {svc_status()}',
        f'配置文件   : {DAE_CFG}',
        f'数据目录   : {DAE_SHARE}',
    ]
    scroll = 0
    stdscr.nodelay(0)
    while True:
        H, W = stdscr.getmaxyx()
        stdscr.erase()
        draw_titlebar(stdscr, p, ' dae 服务状态 ')
        draw_section_hdr(stdscr, p, 1,
                         f'systemd 输出  共 {len(lines)} 行',
                         ' [↑↓] 滚动   [Q/Esc] 返回 ')
        avail = H - 4
        for i, line in enumerate(lines[scroll: scroll + avail]):
            y = 2 + i
            if 'active (running)' in line:
                cp = curses.color_pair(p['good']) | curses.A_BOLD
            elif 'inactive' in line or 'failed' in line:
                cp = curses.color_pair(p['bad'])
            elif '●' in line or (line.startswith(' ') and ':' in line):
                cp = curses.color_pair(p['hdr'])
            else:
                cp = curses.color_pair(p['host'])
            safe_add(stdscr, y, 1, line[:W - 2], cp)
        draw_sep(stdscr, p, H - 2)
        draw_statusbar(stdscr, p, ' [↑↓] 滚动   [Q/Esc] 返回 ')
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (ord('q'), ord('Q'), 27):      break
        elif ch == curses.KEY_UP:   scroll = max(0, scroll - 1)
        elif ch == curses.KEY_DOWN: scroll = min(max(0, len(lines) - avail), scroll + 1)

def act_install(stdscr, p):
    # 先异步检测版本，再给用户选项
    cur  = local_ver()
    is_update = cur is not None

    # 询问安装选项（多选框）
    options = [
        ('下载并安装最新版 dae 主程序',           True),
        ('更新 GeoIP 数据库',                     True),
        ('更新 GeoSite 数据库',                   True),
        ('安装/更新 systemd/OpenRC 服务文件',     not is_update),
        ('安装全局命令及 shell alias',             not is_update),
    ]
    prompt = ('当前已安装版本: ' + cur if cur else '尚未安装 dae') + \
             '\n\n请选择要执行的操作:'
    chosen = checklist_box(stdscr, p,
                           '安装 / 更新 dae',
                           prompt, options)
    if chosen is None: return
    if not chosen:
        msg_box(stdscr, p, '提示', '未选择任何操作。', 'warn')
        return

    do_bin     = 0 in chosen
    do_geoip   = 1 in chosen
    do_geosite = 2 in chosen
    do_service = 3 in chosen
    do_alias   = 4 in chosen

    def task(log):
        ver = None
        arch = None
        if do_bin:
            log.add('检查系统架构…', 'STEP')
            arch, err = detect_arch()
            if err: raise RuntimeError(err)
            log.add(f'架构: {arch}', 'INFO')
            log.add('获取最新版本号…', 'STEP')
            ver = remote_ver()
            if not ver: raise RuntimeError('获取版本号失败，请检查网络')
            log.add(f'最新版本: {ver}', 'INFO')
            if cur == ver and not is_update:
                log.add(f'已是最新版本 {ver}', 'WARN')
            # 停止服务（如果在运行）
            if svc_status() == 'active':
                log.add('停止当前服务…', 'STEP')
                if is_systemd():  run(['systemctl', 'stop', 'dae'])
                elif is_openrc(): run([OPENRC_SVC, 'stop'])
            _install_dae_bin(log, ver, arch)
        if do_geoip:
            if not _download_geo(log, 'geoip'):
                raise RuntimeError('GeoIP 下载失败')
        if do_geosite:
            if not _download_geo(log, 'geosite'):
                raise RuntimeError('GeoSite 下载失败')
        if do_service and ver:
            _install_service(log, ver)
        elif do_service and not ver:
            log.add('未安装主程序，跳过服务文件安装', 'WARN')
        if do_alias:
            _install_global_cmd(log)
        # 安装完后自动启动
        if do_bin:
            _download_example_cfg(log, ver)
            log.add('启动服务…', 'STEP')
            if is_systemd():   run(['systemctl', 'start', 'dae'])
            elif is_openrc():  run([OPENRC_SVC, 'start'])
            time.sleep(1)
            st = svc_status()
            log.add(f'服务状态: {st}', 'INFO' if st == 'active' else 'WARN')
        parts = []
        if do_bin:  parts.append(f'dae {ver} 已安装')
        if do_geoip:   parts.append('GeoIP 已更新')
        if do_geosite: parts.append('GeoSite 已更新')
        return '  |  '.join(parts) or '操作完成'

    ok, msg = run_task(stdscr, p, '安装 / 更新 dae', task)
    msg_box(stdscr, p, '操作' + ('完成' if ok else '失败'), msg,
            'good' if ok else 'bad')

def act_update(stdscr, p):
    cur = local_ver()
    if not cur:
        msg_box(stdscr, p, '提示', 'dae 尚未安装，请使用"安装 / 更新 dae"。', 'warn')
        return

    ver_ref = [None]
    def check_fn(log):
        log.add(f'本地版本: {cur}', 'INFO')
        log.add('查询最新版本…', 'STEP')
        ver = remote_ver()
        if not ver: raise RuntimeError('获取远程版本失败，请检查网络')
        ver_ref[0] = ver
        log.add(f'最新版本: {ver}', 'INFO')
        if cur == ver: return f'已是最新版本 {ver}，无需更新'
        return f'发现新版本: {cur} → {ver}'

    ok, msg = run_task(stdscr, p, '检查 dae 更新', check_fn)
    if not ok:
        msg_box(stdscr, p, '检查失败', msg, 'bad'); return

    ver = ver_ref[0]
    if not ver or cur == ver:
        msg_box(stdscr, p, '检查结果', msg, 'good'); return

    if not confirm_box(stdscr, p, '发现新版本',
                       f'当前版本:  {cur}\n最新版本:  {ver}\n\n是否立即下载并更新？'):
        return

    def update_fn(log):
        arch, err = detect_arch()
        if err: raise RuntimeError(err)
        # 备份配置
        if Path(DAE_CFG).exists():
            bak = f'{DAE_CFG}.backup.{time.strftime("%Y%m%d_%H%M%S")}'
            shutil.copy2(DAE_CFG, bak)
            log.add(f'配置已备份到: {bak}', 'INFO')
        was_up = svc_status() == 'active'
        if was_up:
            log.add('停止服务…', 'STEP')
            if is_systemd():  run(['systemctl', 'stop', 'dae'])
            elif is_openrc(): run([OPENRC_SVC, 'stop'])
        _install_dae_bin(log, ver, arch)
        if was_up:
            log.add('重启服务…', 'STEP')
            if is_systemd():  run(['systemctl', 'start', 'dae'])
            elif is_openrc(): run([OPENRC_SVC, 'start'])
            time.sleep(1)
            st = svc_status()
            log.add(f'服务状态: {st}', 'INFO' if st == 'active' else 'WARN')
        return f'更新完成: {cur} → {ver}'

    ok, msg = run_task(stdscr, p, '更新 dae', update_fn)
    msg_box(stdscr, p, '更新' + ('完成' if ok else '失败'), msg,
            'good' if ok else 'bad')

def act_install_pr(stdscr, p):
    # ── 第一步：输入 PR 号 ──────────────────────────────────────────
    pr_input = input_box(
        stdscr, p, '安装 PR 构建版',
        '请输入 Pull Request 编号:\n'
        '（示例: 936）\n\n'
        '程序将自动查找该 PR 最新的 CI 构建产物。\n\n'
        'PR 列表: https://github.com/daeuniverse/dae/pulls\n\n'
        '请输入 PR 号:',
    )
    if pr_input is None: return
    pr_input = pr_input.strip()
    if not pr_input.isdigit():
        msg_box(stdscr, p, '输入错误', 'PR 号必须为纯数字。', 'bad')
        return
    pr_number = pr_input

    # ── 第二步：检查 / 获取 GitHub Token ───────────────────────────
    token = load_gh_token()
    if not token:
        token_input = input_box(
            stdscr, p, 'GitHub Token（仅需输入一次）',
            '下载 PR 构建产物需要 GitHub Personal Access Token。\n\n'
            '获取方式:\n'
            '  GitHub → Settings → Developer settings\n'
            '  → Personal access tokens → Tokens (classic)\n'
            '  → Generate new token\n'
            '  权限勾选: repo → public_repo (只读即可)\n\n'
            'Token 将保存到:\n'
            f'  {TOKEN_FILE}\n'
            '后续使用无需再次输入。\n\n'
            '请输入 Token (ghp_...):',
        )
        if token_input is None: return
        token_input = token_input.strip()
        if not token_input:
            msg_box(stdscr, p, '输入错误', 'Token 不能为空。', 'bad')
            return
        # 简单校验格式
        if not (token_input.startswith('ghp_') or token_input.startswith('github_pat_')):
            if not confirm_box(stdscr, p, 'Token 格式提示',
                               'Token 通常以 ghp_ 或 github_pat_ 开头，\n'
                               '当前输入格式不符，是否仍然继续？'):
                return
        if not save_gh_token(token_input):
            msg_box(stdscr, p, '警告',
                    f'Token 保存失败（{TOKEN_FILE}），\n本次仍会继续使用。', 'warn')
        token = token_input

    # ── 第三步：查找 artifact → 下载 → 安装 ──────────────────────
    def task(log):
        log.add(f'查找 PR #{pr_number} 的构建产物…', 'STEP')
        artifacts, run_id, conclusion = find_pr_artifacts(pr_number, token, log)
        if not artifacts:
            raise RuntimeError(conclusion)  # conclusion 此时是错误信息字符串

        log.add(f'运行 ID: {run_id}  状态: {conclusion}', 'INFO')

        # 探测系统架构
        arch, aerr = detect_arch()
        if aerr: raise RuntimeError(aerr)
        base_arch = re.sub(r'_v\d+_.*', '', arch)
        log.add(f'系统架构: {arch}', 'INFO')

        # 按架构优先级匹配 artifact（artifact name 可能只叫 "dae"，不含架构）
        def score(name):
            n = name.lower()
            if arch in n:      return 0
            if base_arch in n: return 1
            if 'linux' in n:   return 2
            if n == 'dae':     return 3   # dae 项目单一产物名就叫 "dae"
            return 99
        scored = sorted(artifacts, key=lambda a: score(a['name']))
        log.add('可用产物: ' + ', '.join(a['name'] for a in artifacts[:6]), 'INFO')

        for art in scored[:3]:
            art_name = art['name']
            art_id   = art['id']
            dl_url   = art.get('archive_download_url',
                               f'https://api.github.com/repos/daeuniverse/dae/actions/artifacts/{art_id}/zip')
            log.add(f'下载产物: {art_name}', 'STEP')
            tmp  = tempfile.mkdtemp(prefix='dae.')
            dest = os.path.join(tmp, 'pr.zip')

            def prog(done, total):
                if total:
                    log.update_last(
                        f'下载 {art_name}  {done/1048576:.1f}/{total/1048576:.1f} MB'
                        f'  ({done/total*100:.0f}%)', 'INFO')
            ok2, dl_err = gh_api_download(dl_url, dest, token, prog)
            if not ok2:
                shutil.rmtree(tmp, ignore_errors=True)
                log.add(f'下载失败: {dl_err}', 'WARN')
                continue

            try:
                with zipfile.ZipFile(dest) as zf:
                    zf.extractall(os.path.join(tmp, 'ex'))
            except Exception as ze:
                shutil.rmtree(tmp, ignore_errors=True)
                log.add(f'解压失败: {ze}', 'WARN')
                continue

            binary = None
            for root, _, files in os.walk(os.path.join(tmp, 'ex')):
                for f in sorted(files):
                    if 'dae' in f.lower() and not f.endswith(('.zip','.txt','.md','.sha256')):
                        binary = os.path.join(root, f); break
                if binary: break

            if not binary:
                shutil.rmtree(tmp, ignore_errors=True)
                log.add('未在压缩包中找到可执行文件，尝试下一个…', 'WARN')
                continue

            was_up = svc_status() == 'active'
            if was_up:
                log.add('停止服务…', 'STEP')
                if is_systemd():  run(['systemctl', 'stop', 'dae'])
                elif is_openrc(): run([OPENRC_SVC, 'stop'])

            Path(DAE_BIN).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(binary, DAE_BIN)
            os.chmod(DAE_BIN, 0o755)
            shutil.rmtree(tmp, ignore_errors=True)

            _, raw_v = run([DAE_BIN, '--version'])
            installed = local_ver() or (raw_v.splitlines()[0].strip() if raw_v else '（版本未知）')
            log.add(f'安装成功，版本: {installed}', 'INFO')

            if was_up:
                log.add('重启服务…', 'STEP')
                if is_systemd():  run(['systemctl', 'start', 'dae'])
                elif is_openrc(): run([OPENRC_SVC, 'start'])
                time.sleep(1)
                log.add(f'服务状态: {svc_status()}', 'INFO')
            return f'PR #{pr_number} 安装成功\n已安装版本: {installed}'

        raise RuntimeError(
            f'PR #{pr_number} 未找到可用的构建产物\n'
            '可能原因:\n'
            '  · CI 尚未完成\n'
            '  · 产物已过期（超过 90 天）\n'
            '  · Token 权限不足')

    ok, msg = run_task(stdscr, p, f'安装 PR #{pr_number}', task)
    msg_box(stdscr, p, '安装' + ('成功' if ok else '失败'), msg,
            'good' if ok else 'bad')

def act_uninstall(stdscr, p):
    # 一个多选框替代三次确认弹窗
    options = [
        ('停止并卸载 dae 主程序及服务',        True),
        ('删除配置目录 /usr/local/etc/dae/',   False),
        ('删除数据目录 /usr/local/share/dae/', False),
        ('移除 shell alias 和全局命令',        True),
    ]
    chosen = checklist_box(
        stdscr, p, '卸载 dae',
        '请选择要删除的内容。\n\n'
        '⚠  此操作不可逆，请谨慎选择！',
        options
    )
    if chosen is None: return
    if 0 not in chosen:
        msg_box(stdscr, p, '提示',
                '必须勾选"卸载主程序及服务"才能继续。\n'
                '若只想删除配置/数据，请手动操作。', 'warn')
        return
    if not confirm_box(stdscr, p, '最终确认',
                       '确定要卸载 dae 吗？\n此操作不可撤销。'):
        return

    del_cfg    = 1 in chosen
    del_data   = 2 in chosen
    del_alias  = 3 in chosen

    def task(log):
        log.add('停止并禁用服务…', 'STEP')
        if is_systemd():
            run(['systemctl', 'stop',    'dae'])
            run(['systemctl', 'disable', 'dae'])
            Path(SYSTEMD_SVC).unlink(missing_ok=True)
            run(['systemctl', 'daemon-reload'])
            log.add('systemd 服务已移除', 'INFO')
        elif is_openrc():
            run([OPENRC_SVC, 'stop'])
            run(['rc-update', 'del', 'dae', 'default'])
            Path(OPENRC_SVC).unlink(missing_ok=True)
            log.add('OpenRC 服务已移除', 'INFO')
        for f in [DAE_BIN, MANAGER_BIN]:
            if Path(f).exists():
                Path(f).unlink()
                log.add(f'已删除 {f}', 'INFO')
        if del_alias:
            for rc_file in ['/etc/bash.bashrc', '/etc/bashrc', '/root/.bashrc',
                            '/etc/zsh/zshrc', '/root/.zshrc']:
                if Path(rc_file).exists():
                    try:
                        txt = Path(rc_file).read_text()
                        txt = re.sub(r'\n# dae management alias\nalias dae=.*\n',
                                     '\n', txt)
                        Path(rc_file).write_text(txt)
                    except Exception: pass
            Path('/root/.config/fish/conf.d/dae.fish').unlink(missing_ok=True)
            for c in ['/usr/share/bash-completion/completions/dae',
                      '/usr/share/zsh/site-functions/_dae',
                      '/usr/share/fish/vendor_completions.d/dae.fish']:
                Path(c).unlink(missing_ok=True)
            log.add('shell alias 已清理', 'INFO')
        if del_cfg and Path(DAE_CFG).parent.exists():
            shutil.rmtree(str(Path(DAE_CFG).parent))
            log.add('配置目录已删除', 'INFO')
        if del_data and Path(DAE_SHARE).exists():
            shutil.rmtree(DAE_SHARE)
            log.add('数据目录已删除', 'INFO')
        return 'dae 已卸载完成'

    ok, msg = run_task(stdscr, p, '卸载 dae', task)
    msg_box(stdscr, p, '卸载' + ('完成' if ok else '失败'), msg,
            'good' if ok else 'bad')

def act_geoip(stdscr, p):
    def task(log):
        if not _download_geo(log, 'geoip'):
            # BUG FIX: raise exception so run_task correctly reports failure
            raise RuntimeError('GeoIP 数据库下载失败')
        return 'GeoIP 更新完成'
    ok, msg = run_task(stdscr, p, '更新 GeoIP 数据库', task)
    msg_box(stdscr, p, '更新' + ('完成' if ok else '失败'), msg,
            'good' if ok else 'bad')

def act_geosite(stdscr, p):
    def task(log):
        if not _download_geo(log, 'geosite'):
            # BUG FIX: raise exception so run_task correctly reports failure
            raise RuntimeError('GeoSite 数据库下载失败')
        return 'GeoSite 更新完成'
    ok, msg = run_task(stdscr, p, '更新 GeoSite 数据库', task)
    msg_box(stdscr, p, '更新' + ('完成' if ok else '失败'), msg,
            'good' if ok else 'bad')

# ═══════════════════════════════════════════════════════════════════════════════
# CLI 模式
# ═══════════════════════════════════════════════════════════════════════════════

CLI_HELP = """\033[1;36mdae-manager\033[0m  —  DAE 管理工具

用法: dae-manager [命令] [参数]

命令:
  \033[36minstall\033[0m              安装/更新 dae（自动检测最新版）
  \033[36minstall-pr\033[0m \033[33m<PR号>\033[0m        安装指定 PR 的最新构建版（首次需输入 GitHub Token）
  \033[36mstart\033[0m                启动服务
  \033[36mstop\033[0m                 停止服务
  \033[36mrestart\033[0m              重启服务
  \033[36mreload\033[0m               重载配置（先验证后重载）
  \033[36medit\033[0m                 编辑配置文件
  \033[36mlogs\033[0m                 查看实时日志
  \033[36mstatus\033[0m               查看服务状态
  \033[36mupdate\033[0m               检查版本（需要更新时提示）
  \033[36mupdate-geoip\033[0m         更新 GeoIP 数据库
  \033[36mupdate-geosite\033[0m       更新 GeoSite 数据库
  \033[36muninstall\033[0m            卸载 dae
  \033[36mhelp\033[0m                 显示此帮助

不带参数时进入交互式 TUI 菜单。
"""

def clog(msg, level='INFO'):
    C = {'INFO': '\033[32m', 'STEP': '\033[36m',
         'WARN': '\033[33m', 'ERRO': '\033[31m'}
    print(f'{C.get(level, "")}[{level}]\033[0m {msg}')

def cli_task(fn):
    class L:
        def add(self, m, lv='INFO'): clog(m, lv)
        def update_last(self, m, lv='INFO'): clog(m, lv)
    try:
        msg = fn(L())
        if msg: clog(msg)
        return 0
    except Exception as e:
        clog(str(e), 'ERRO')
        return 1

def main():
    if platform.system() != 'Linux':
        sys.exit('\033[1;31m错误: 仅支持 Linux！\033[0m')
    if os.geteuid() != 0:
        sys.exit('\033[1;31m错误: 请以 root 权限运行！\033[0m')
    os.environ.setdefault('LANG', 'zh_CN.UTF-8')
    os.environ.setdefault('LC_ALL', 'zh_CN.UTF-8')

    args = sys.argv[1:]
    if not args:
        try: curses.wrapper(interactive_menu)
        except KeyboardInterrupt: pass
        return

    cmd = args[0].lower()

    if cmd in ('help', '--help', '-h'):
        print(CLI_HELP)

    elif cmd == 'install':
        def t(log):
            arch, err = detect_arch()
            if err: raise RuntimeError(err)
            ver = remote_ver()
            if not ver: raise RuntimeError('获取版本失败')
            log.add(f'版本: {ver}  架构: {arch}', 'INFO')
            if svc_status() == 'active':
                if is_systemd():  run(['systemctl', 'stop', 'dae'])
                elif is_openrc(): run([OPENRC_SVC, 'stop'])
            _install_dae_bin(log, ver, arch)
            _download_geo(log, 'geoip')
            _download_geo(log, 'geosite')
            _install_service(log, ver)
            _download_example_cfg(log, ver)
            _install_global_cmd(log)
            if is_systemd():   run(['systemctl', 'start', 'dae'])
            elif is_openrc():  run([OPENRC_SVC, 'start'])
            return f'安装完成: {ver}'
        sys.exit(cli_task(t))

    elif cmd == 'install-pr':
        pr_number = (args[1] if len(args) > 1 else
                     input('请输入 PR 号: ').strip())
        if not pr_number.isdigit():
            sys.exit('\033[31mPR 号必须为纯数字\033[0m')
        # 获取或读取 Token
        token = load_gh_token()
        if not token:
            token = input('请输入 GitHub Personal Access Token (ghp_...): ').strip()
            if not token:
                sys.exit('\033[31mToken 不能为空\033[0m')
            if save_gh_token(token):
                clog(f'Token 已保存到 {TOKEN_FILE}，下次无需再次输入', 'INFO')
            else:
                clog(f'Token 保存失败，本次仍会继续', 'WARN')
        else:
            clog(f'使用已保存的 Token ({TOKEN_FILE})', 'INFO')
        def t(log):
            log.add(f'查找 PR #{pr_number} 的构建产物…', 'STEP')
            artifacts, run_id, conclusion = find_pr_artifacts(pr_number, token, log)
            if not artifacts:
                raise RuntimeError(conclusion)
            log.add(f'运行 ID: {run_id}  状态: {conclusion}', 'INFO')
            arch, aerr = detect_arch()
            if aerr: raise RuntimeError(aerr)
            base_arch = re.sub(r'_v\d+_.*', '', arch)
            log.add(f'架构: {arch}，产物: {[a["name"] for a in artifacts[:4]]}', 'INFO')
            def score(name):
                n = name.lower()
                if arch in n:      return 0
                if base_arch in n: return 1
                if 'linux' in n:   return 2
                if n == 'dae':     return 3
                return 99
            for art in sorted(artifacts, key=lambda a: score(a['name']))[:3]:
                dl_url = art.get('archive_download_url',
                    f'https://api.github.com/repos/daeuniverse/dae/actions/artifacts/{art["id"]}/zip')
                log.add(f'下载: {art["name"]}', 'STEP')
                tmp  = tempfile.mkdtemp(prefix='dae.')
                dest = os.path.join(tmp, 'pr.zip')
                ok2, dl_err = gh_api_download(dl_url, dest, token)
                if not ok2:
                    shutil.rmtree(tmp, ignore_errors=True)
                    log.add(f'下载失败: {dl_err}', 'WARN'); continue
                try:
                    with zipfile.ZipFile(dest) as zf:
                        zf.extractall(os.path.join(tmp, 'ex'))
                except Exception as ze:
                    shutil.rmtree(tmp, ignore_errors=True)
                    log.add(f'解压失败: {ze}', 'WARN'); continue
                binary = None
                for root, _, files in os.walk(os.path.join(tmp, 'ex')):
                    for f in sorted(files):
                        if 'dae' in f.lower() and not f.endswith(('.zip','.txt','.md','.sha256')):
                            binary = os.path.join(root, f); break
                    if binary: break
                if not binary:
                    shutil.rmtree(tmp, ignore_errors=True)
                    log.add('未找到可执行文件', 'WARN'); continue
                if svc_status() == 'active':
                    if is_systemd():  run(['systemctl', 'stop', 'dae'])
                    elif is_openrc(): run([OPENRC_SVC, 'stop'])
                Path(DAE_BIN).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(binary, DAE_BIN); os.chmod(DAE_BIN, 0o755)
                shutil.rmtree(tmp, ignore_errors=True)
                _, raw_v = run([DAE_BIN, '--version'])
                installed = local_ver() or (raw_v.splitlines()[0].strip() if raw_v else '未知')
                return f'PR #{pr_number} 安装成功: {installed}'
            raise RuntimeError(f'PR #{pr_number} 未找到有效构建产物')
        sys.exit(cli_task(t))

    elif cmd == 'start':
        def t(log):
            if svc_status() == 'active':
                return '服务已在运行中，无需重复启动'
            log.add('启动…', 'STEP')
            _svc_start(log)
            return '服务启动成功'
        sys.exit(cli_task(t))

    elif cmd == 'stop':
        def t(log):
            if svc_status() != 'active':
                return '服务未在运行'
            log.add('停止…', 'STEP')
            _svc_stop(log)
            return '服务已停止'
        sys.exit(cli_task(t))

    elif cmd == 'restart':
        def t(log):
            log.add('重启…', 'STEP')
            if is_systemd():    rc, out = run(['systemctl', 'restart', 'dae'])
            elif is_openrc():   rc, out = run([OPENRC_SVC, 'restart'])
            else: raise RuntimeError('未找到服务文件')
            if rc != 0: raise RuntimeError(out)
            return '重启成功'
        sys.exit(cli_task(t))

    elif cmd == 'reload':
        def t(log):
            log.add('验证配置…', 'STEP')
            rc, out = run([DAE_BIN, 'validate', '-c', DAE_CFG])
            if rc != 0: raise RuntimeError(f'验证失败: {out}')
            log.add('重载…', 'STEP')
            if is_systemd():    rc, out = run(['systemctl', 'reload-or-restart', 'dae'])
            elif is_openrc():   rc, out = run([OPENRC_SVC, 'reload'])
            else: raise RuntimeError('未找到服务文件')
            if rc != 0: raise RuntimeError(out)
            return '重载成功'
        sys.exit(cli_task(t))

    elif cmd == 'edit':
        editor = next((e for e in ['micro', 'nano', 'vi', 'vim'] if shutil.which(e)), None)
        if not editor: sys.exit('未找到可用编辑器')
        if Path(DAE_CFG).exists():
            shutil.copy2(DAE_CFG, f'{DAE_CFG}.backup.{time.strftime("%Y%m%d_%H%M%S")}')
        os.system(f'{editor} "{DAE_CFG}"')

    elif cmd == 'logs':
        try:
            if shutil.which('journalctl') and Path(SYSTEMD_SVC).exists():
                subprocess.run(['journalctl', '-u', 'dae', '-f', '--no-pager', '-n', '80'])
            elif Path('/var/log/dae.log').exists():
                subprocess.run(['tail', '-f', '/var/log/dae.log'])
            else:
                sys.exit('未找到日志来源')
        except KeyboardInterrupt: pass

    elif cmd == 'status':
        if is_systemd(): _, out = run(['systemctl', 'status', 'dae', '--no-pager'])
        elif is_openrc(): _, out = run([OPENRC_SVC, 'status'])
        else: out = '未找到服务文件'
        print(out)
        print(f'\n已安装版本: {local_ver() or "未安装"}')

    elif cmd in ('update', 'check-update'):
        cur = local_ver()
        if not cur: sys.exit('\033[31m未安装 dae\033[0m')
        clog(f'本地版本: {cur}', 'INFO')
        clog('查询最新版本…', 'STEP')
        ver = remote_ver()
        if not ver: sys.exit('\033[31m获取远程版本失败\033[0m')
        clog(f'最新版本: {ver}', 'INFO')
        if cur == ver: clog('已是最新版本')
        else: clog(f'发现新版本 {ver}，运行 install 命令更新', 'WARN')

    elif cmd == 'update-geoip':
        def t(log):
            if not _download_geo(log, 'geoip'):
                raise RuntimeError('GeoIP 更新失败')
            return 'GeoIP 更新完成'
        sys.exit(cli_task(t))

    elif cmd == 'update-geosite':
        def t(log):
            if not _download_geo(log, 'geosite'):
                raise RuntimeError('GeoSite 更新失败')
            return 'GeoSite 更新完成'
        sys.exit(cli_task(t))

    elif cmd == 'uninstall':
        if input('确定卸载 dae？(y/N): ').strip().lower() != 'y':
            print('已取消'); sys.exit(0)
        def t(log):
            log.add('停止服务…', 'STEP')
            if is_systemd():
                run(['systemctl', 'stop', 'dae']); run(['systemctl', 'disable', 'dae'])
                Path(SYSTEMD_SVC).unlink(missing_ok=True)
                run(['systemctl', 'daemon-reload'])
            elif is_openrc():
                run([OPENRC_SVC, 'stop'])
                run(['rc-update', 'del', 'dae', 'default'])
                Path(OPENRC_SVC).unlink(missing_ok=True)
            for f in [DAE_BIN, MANAGER_BIN]:
                if Path(f).exists(): Path(f).unlink(); log.add(f'删除 {f}', 'INFO')
            if input(f'删除配置目录? (y/N): ').strip().lower() == 'y':
                shutil.rmtree(str(Path(DAE_CFG).parent), ignore_errors=True)
            if input(f'删除数据目录? (y/N): ').strip().lower() == 'y':
                shutil.rmtree(DAE_SHARE, ignore_errors=True)
            return '卸载完成'
        sys.exit(cli_task(t))

    else:
        print(f'\033[31m未知命令: {cmd}\033[0m')
        print(CLI_HELP)
        sys.exit(1)

if __name__ == '__main__':
    main()