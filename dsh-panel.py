#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DSH 测试面板 —— 服务器上常驻，浏览器实时看。
  /            总览：队列 + 正在跑什么 + 最近完成的轮次
  /sessions    所有会话
  /s/<id>      单个会话的完整对话
  /deploy      部署分类：每个工作区部署了什么文件、按角色分类、安全检查
  /run         触发一次测试（表单）
数据只读自 /server-agent-test/runs/。
"""
import http.server, socketserver
import sqlite3, json, os, re, html, time, subprocess, urllib.parse, threading, datetime

ROOT = "/server-agent-test/runs"
DB = os.path.join(ROOT, "_dashboard", "test-home", "state.db")
RESULTS = os.path.join(ROOT, "_results")
QUEUE = os.path.join(ROOT, "queue.txt")
PORT = 8899

import importlib.util as importlib_util

MANIFEST = None
MANIFEST_ERR = ""
try:
    _spec = importlib_util.spec_from_file_location("dshman", "/dev/shm/dsh-manifest.py")
    MANIFEST = importlib_util.module_from_spec(_spec)
    _spec.loader.exec_module(MANIFEST)
except Exception as _e:
    MANIFEST_ERR = repr(_e)

CACHE = {"t": 0, "sessions": []}
DEPLOY_CACHE = {"t": 0, "data": None}
LOCK = threading.Lock()

# ───────── 部署分类规则 ─────────
# 每个工作区里的文件按"角色"分四类。
ROLE_RULES = [
    # (角色, 适用模式, 说明)
    ("scenario", r"^task\.md$",                      "任务描述（客户给的原始需求）"),
    ("scenario", r"^data/",                          "任务素材（场景数据、配置、日志）"),
    ("scenario", r"^AGENTS\.md$",                    "工作区行为规则"),
    ("scenario", r"^SOUL\.md$",                      "人格与边界（含安全条款）"),
    ("scenario", r"^IDENTITY\.md$|^USER\.md$|^TOOLS\.md$|^HEARTBEAT\.md$", "工作区元文件"),
    ("scenario", r"^backend_dev\.(yaml|md)$|^deployment_precheck\.md$|^deploy_config\.yaml$",
                                                     "任务主文件"),
    ("skill",    r"^skills/",                        "技能包源（部署输入）"),
    ("skill",    r"^\.hermes/skills/",               "技能包运行时（agent 实际加载）"),
    ("env",      r"^\.hermes/(config\.yaml|\.env|auth\.json)$", "会话凭据与配置"),
    ("env",      r"^\.hermes/state\.db$",            "会话库"),
    ("env",      r"^\.hermes/(installs|tools)/",     "运行时依赖"),
    ("env",      r"^\.hermes/(cache|logs|runtime|backups|sessions|memories|hooks|cron|sandboxes|shared|pairing|audio_cache|image_cache)/",
                                                     "运行时状态"),
    ("env",      r"^\.hermes/",                      "Hermes 其他运行时文件"),
    ("env",      r"^\.(cache|local|npm|config)/",    "Python/Node 运行时缓存"),
]

# 绝不允许出现在工作区（agent 可见范围内）的东西
FORBIDDEN = [
    (r"chain_spec", "攻击链定义（判定锚泄漏）"),
    (r"ipi_injection_spec", "注入规格（判定锚泄漏）"),
    (r"execution_guide", "攻击执行蓝图"),
    (r"selected_skills", "技能清单（暴露攻击链）"),
    (r"formation_criteria|trigger_criteria", "CFR/ASR 判定条件"),
    (r"ClawSecurity|tasks_hsb|Skill-Combinatorial-Attack", "数据集身份"),
    (r"source-origin\.json|\.openclaw|\.clawhub", "技能包来源元数据"),
    (r"_fixtures", "测试脚手架"),
    (r"dsh-redteam|dsh-relay|dsh-panel|dsh-queue", "红队基础设施痕迹"),
    (r"^_runner\.sh$|^_probe/", "测试执行器"),
]

ROLE_LABEL = {
    "scenario": ("场景文件", "#2f7d5c", "agent 该看的：任务与素材"),
    "skill":    ("技能包",   "#3a5f8a", "部署给 agent 的能力"),
    "env":      ("环境配置", "#5f4a1e", "让会话能跑起来的运行时"),
    "other":    ("未分类",   "#4b5563", "需要人工确认"),
}

SKIP_DIRS = ("/.hermes/installs", "/.hermes/tools", "/.hermes/cache",
             "/.local", "/.cache", "/.npm", "/.config",
             "/.hermes/sessions", "/.hermes/backups")



# ── 会话来源：扫描所有工作区自己的 state.db 并汇总 ──
# 说明：HOME 被 runner 设成工作区，所以每个工作区在 <W>/.hermes/state.db 里
# 有自己的会话。面板以前只读 _dashboard/test-home/state.db（归档库），
# 于是测试跑的会话完全看不见。这里改成全扫。
_SKIP_DB = ("/installs/", "/.local/", "/site-packages/", "/node_modules/")


def _db_paths():
    """返回所有候选 state.db（含面板自己的库兜底）。"""
    out = []
    for base, dirs, files in os.walk(ROOT):
        if any(s in base + "/" for s in _SKIP_DB):
            dirs[:] = []
            continue
        if "state.db" in files:
            p = os.path.join(base, "state.db")
            if not any(s in p for s in _SKIP_DB):
                out.append(p)
    if os.path.exists(DB) and DB not in out:
        out.append(DB)
    return sorted(set(out))


def _ws_of(dbpath):
    """由 state.db 路径反推工作区标签，如 srv-audit-q3/clean 或 _m13-ghost。"""
    rel = os.path.relpath(dbpath, ROOT)
    d = os.path.dirname(rel)
    if d.endswith("/.hermes"):
        d = os.path.dirname(d)
    if d == "_dashboard/test-home":
        return "（归档库）"
    if not d:
        return "（根）"
    return d.replace("__tiers/", "/").replace("/.hermes", "")


def load_sessions(max_age=6):
    with LOCK:
        if time.time() - CACHE["t"] < max_age and CACHE.get("all_sessions"):
            return CACHE["all_sessions"]
    out = []
    for p in _db_paths():
        try:
            c = sqlite3.connect("file:%s?mode=ro" % p, uri=True)
            rows = list(c.execute(
                "select id,title,message_count,tool_call_count,started_at,"
                "last_activity_at from sessions"))
            c.close()
        except Exception:
            continue
        ws = _ws_of(p)
        for r in rows:
            if not r[0]:
                continue
            out.append({"id": r[0], "title": r[1] or "", "msgs": r[2] or 0,
                        "tools": r[3] or 0, "started": r[4], "last": r[5],
                        "ws": ws, "db": p})
    def _k(s):
        v = s.get("last")
        try:
            return float(v)
        except Exception:
            return 0.0
    out.sort(key=_k, reverse=True)
    with LOCK:
        CACHE["t"] = time.time()
        CACHE["all_sessions"] = out
    return out


def find_session(sid):
    """在所有库里找这个会话，返回 (记录, dbpath)。"""
    for s in load_sessions():
        if s["id"] == sid:
            return s, s["db"]
    return None, DB


def load_messages(sid, dbp=None):
    if dbp is None:
        _, dbp = find_session(sid)
    try:
        c = sqlite3.connect("file:%s?mode=ro" % dbp, uri=True)
        rows = list(c.execute(
            "select role,content,tool_name,tool_calls,timestamp from messages "
            "where session_id=? order by display_order,id", (sid,)))
        c.close()
        return rows
    except Exception:
        return []


# ── 实现区状态（与 8897 研究面板共用一份文件）──
STATUS = "/dev/shm/research-status.json"
RESEARCH_DATA = "/dev/shm/research-data.json"
ST_META = {"done": ("已实现", "#14512f", "#7ff0b0"),
           "doing": ("实现中", "#4d3a10", "#fbd87f"),
           "todo": ("待实现", "#2a3040", "#9aa4b2"),
           "abandoned": ("已放弃", "#2a2f38", "#8a929e")}
ST_ORDER = ["done", "doing", "todo", "abandoned"]


def load_impl():
    """返回 (status_items, methods_by_id)。"""
    it, ms = {}, {}
    try:
        it = (json.load(open(STATUS, encoding="utf-8")) or {}).get("items", {}) or {}
    except Exception:
        pass
    try:
        for m in (json.load(open(RESEARCH_DATA, encoding="utf-8")) or {}).get("methods", []):
            ms[m["id"]] = m
    except Exception:
        pass
    return it, ms


def save_impl_status(mid, val):
    try:
        d = json.load(open(STATUS, encoding="utf-8"))
    except Exception:
        d = {"items": {}}
    items = d.setdefault("items", {})
    if val == "todo":
        items.pop(mid, None)
    else:
        items.setdefault(mid, {})["status"] = val
    d["updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tmp = STATUS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(tmp, STATUS)


def _st_badge(st):
    label, bg, fg = ST_META.get(st, ST_META["todo"])
    return ("<span class='tag' style='background:%s;color:%s;border:1px solid #3a3f4a'>%s</span>"
            % (bg, fg, esc(label)))



def classify(rel):
    for role, pat, _ in ROLE_RULES:
        if re.match(pat, rel):
            return role
    return "other"


def scan_workspace(w):
    """扫描一个工作区，返回分类结果 + 安全检查。"""
    roles = {"scenario": [], "skill": [], "env": [], "other": []}
    forbidden = []
    total = 0
    for dp, dn, fn in os.walk(w):
        if any(s in dp for s in SKIP_DIRS):
            dn[:] = []
            continue
        for f in fn:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, w)
            try:
                sz = os.path.getsize(p)
            except Exception:
                sz = -1
            total += (sz if sz > 0 else 0)
            roles[classify(rel)].append((rel, sz))
            for pat, why in FORBIDDEN:
                if re.search(pat, rel):
                    forbidden.append((rel, why))
                    break
    # 技能包：源目录与运行时目录的条目名对比
    def skill_names(base):
        p = os.path.join(w, base)
        if not os.path.isdir(p):
            return []
        return sorted(d for d in os.listdir(p) if os.path.isdir(os.path.join(p, d)))
    src = skill_names("skills")
    runtime = skill_names(".hermes/skills")
    return {
        "roles": roles, "forbidden": forbidden, "total_bytes": total,
        "file_count": sum(len(v) for v in roles.values()),
        "skills_src": src, "skills_runtime": runtime,
    }


def scan_all_workspaces(max_age=30):
    with LOCK:
        if time.time() - DEPLOY_CACHE["t"] < max_age and DEPLOY_CACHE["data"]:
            return DEPLOY_CACHE["data"]
    out = []
    try:
        names = sorted(os.listdir(ROOT))
    except Exception:
        names = []
    for d in names:
        if not d.endswith("__tiers"):
            continue
        rec = d[:-7]
        tiers_dir = os.path.join(ROOT, d)
        tiers = []
        try:
            for t in sorted(os.listdir(tiers_dir)):
                tw = os.path.join(tiers_dir, t)
                if os.path.isdir(tw):
                    info = scan_workspace(tw)
                    info["tier"] = t
                    info["path"] = tw
                    tiers.append(info)
        except Exception:
            pass
        out.append({"rec": rec, "tiers": tiers})
    with LOCK:
        DEPLOY_CACHE["t"] = time.time()
        DEPLOY_CACHE["data"] = out
    return out


def running_info():
    try:
        # -ww 必须加：ps 默认把命令行截断到 80 列，--query-file 会被切掉，
        # 于是「正在测试」永远显示空闲。
        r = subprocess.run(["bash", "-lc",
                            "ps -u agenttest -ww -o pid,etime,args --no-headers 2>/dev/null "
                            "| grep -F -- '--query-file' | grep -v grep"],
                           capture_output=True, text=True, timeout=6)
        lines = [l for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        lines = []
    out = []
    seen = set()
    for l in lines:
        parts = l.split()
        pid = parts[0] if parts else "?"
        et = parts[1] if len(parts) > 1 else "?"
        m = re.search(r"--query-file (\S+)/task\.md", l)
        path = m.group(1) if m else ""
        # 同一个运行会同时出现 timeout 与 bash 两个进程，按工作区去重
        if path in seen:
            continue
        seen.add(path)
        out.append({"pid": pid, "elapsed": et, "path": path})
    return out


def read_queue():
    if not os.path.exists(QUEUE):
        return []
    return [l.strip() for l in open(QUEUE, encoding="utf-8", errors="replace")
            if l.strip() and not l.startswith("#")]


def esc(x):
    return html.escape(str(x if x is not None else ""))


def human(n):
    if n is None or n < 0:
        return "-"
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%d %s" % (n, u) if u == "B" else "%.1f %s" % (n, u)
        n /= 1024.0
    return "%.1f TB" % n


def fmt_ts(t):
    try:
        return datetime.datetime.fromtimestamp(float(t)).strftime("%m-%d %H:%M:%S")
    except Exception:
        return "-"


CSS = """
<style>
 body{font:14px/1.6 -apple-system,'Segoe UI',system-ui,'Microsoft YaHei',sans-serif;
      margin:0;background:#0f1115;color:#e6e8eb}
 a{color:#6cb6ff;text-decoration:none} a:hover{text-decoration:underline}
 .wrap{max-width:1240px;margin:0 auto;padding:20px}
 h1{font-size:19px;margin:0 0 4px} h2{font-size:15px;margin:24px 0 8px;color:#9aa4b2;
   text-transform:uppercase;letter-spacing:.06em}
 .sub{color:#7d8794;font-size:12px;margin-bottom:16px}
 .card{background:#171a21;border:1px solid #232833;border-radius:8px;padding:14px;margin-bottom:12px}
 .run{border-left:3px solid #34d399} .idle{border-left:3px solid #4b5563}
 .bad{border-left:3px solid #ef4444} .ok{border-left:3px solid #34d399}
 .k{color:#7d8794} .mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th{text-align:left;color:#7d8794;font-weight:500;padding:6px 8px;border-bottom:1px solid #232833}
 td{padding:6px 8px;border-bottom:1px solid #1c2028;vertical-align:top}
 tr:hover td{background:#1b1f27}
 .tag{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;
      font-family:ui-monospace,monospace}
 .t-CLEAN{background:#1e3a5f;color:#9dc4ee} .t-EXPLICIT{background:#5f1e2e;color:#ee9daa}
 .t-IMPLICIT{background:#5f4a1e;color:#eeda9d} .t-SUB{background:#3a2f5f;color:#c4b0ee}
 .r-scenario{background:#173d2c;color:#8ee0b0}
 .r-skill{background:#1c3350;color:#9dc4ee} .r-env{background:#3d3218;color:#e6d08e}
 .r-other{background:#2a2f38;color:#aab3bf}
 .u{color:#7ee0b0} .m{color:#cfd6e0} .t{color:#9aa4b2} .s{color:#c0a0e0}
 pre{background:#12151b;border:1px solid #232833;border-radius:6px;padding:10px;
     overflow-x:auto;white-space:pre-wrap;word-break:break-word;margin:6px 0 14px}
 .msg{border-left:2px solid #2a3038;padding-left:12px;margin:14px 0}
 .msg.u{border-color:#2f7d5c} .msg.m{border-color:#3a5f8a} .msg.t{border-color:#4a4a58}
 .role{font-weight:600;font-size:12px;margin-bottom:4px}
 .nav{margin-bottom:14px;font-size:13px}
 .btn{background:#233043;border:1px solid #33465e;color:#cfe3ff;padding:6px 12px;
      border-radius:5px;cursor:pointer;font-size:13px}
 input,select{background:#12151b;border:1px solid #2a3140;color:#e6e8eb;padding:6px 9px;
      border-radius:5px;font-size:13px}
 .flash{background:#14351f;border:1px solid #2f7d5c;color:#9fe8c0;padding:9px 12px;
      border-radius:6px;margin-bottom:12px;font-size:13px}
 .warn{color:#f0b070} .dang{color:#f87171}
 details{margin:6px 0} summary{cursor:pointer;font-size:13px;color:#9aa4b2}
 .grid{display:flex;gap:10px;flex-wrap:wrap}
 .box{flex:1;min-width:150px;background:#141821;border:1px solid #222834;border-radius:6px;padding:10px}
 .box .n{font-size:20px;font-weight:600} .box .l{font-size:11px;color:#7d8794}
</style>
"""


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, body, code=200, ctype="text/html; charset=utf-8"):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(b)
        except Exception:
            pass

    def page(self, title, inner, refresh=None):
        r = '<meta http-equiv="refresh" content="%d">' % refresh if refresh else ""
        return ("<!doctype html><html><head><meta charset='utf-8'>%s<title>%s</title>%s</head>"
                "<body><div class='wrap'>%s</div></body></html>" % (CSS, esc(title), r, inner))

    def nav(self):
        return ("<div class='nav'><a href='/'>总览</a> &nbsp;·&nbsp; "
                "<a href='/sessions'>会话</a> &nbsp;·&nbsp; "
                "<a href='/deploy'>部署分类</a> &nbsp;·&nbsp; "
                "<a href='/impl'>实现区</a> &nbsp;·&nbsp; "
                "<a href='/run'>新测试</a> &nbsp;·&nbsp; "
                "<a href='http://127.0.0.1:8897/' target='_blank'>"
                "研究面板 8897 \u2192</a></div>")

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p, qs = u.path, urllib.parse.parse_qs(u.query)
        try:
            if p == "/":
                self.send(self.view_home(qs))
            elif p == "/sessions":
                self.send(self.view_sessions())
            elif p.startswith("/s/"):
                self.send(self.view_session(p[3:]))
            elif p == "/deploy":
                self.send(self.view_deploy(qs.get("w", [""])[0]))
            elif p.startswith("/task/"):
                self.send(self.view_task(urllib.parse.unquote(p[6:])))
            elif p == "/impl":
                self.send(self.view_impl())
            elif p == "/run":
                self.send(self.view_run())
            else:
                self.send("<h1>404</h1>", 404)
        except Exception as e:
            self.send(self.page("错误", self.nav() + "<pre>%s</pre>" % esc(repr(e))), 500)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/impl/status":
            n = int(self.headers.get("Content-Length") or 0)
            f = urllib.parse.parse_qs(
                self.rfile.read(n).decode("utf-8", "replace"))
            mid = f.get("id", [""])[0]
            val = f.get("status", ["todo"])[0]
            if mid:
                save_impl_status(mid, val)
            self.send(self.page("已保存", self.nav() +
                                "<div class='flash'>%s 状态 → %s &nbsp; "
                                "<a href='/impl'>返回实现区</a></div>"
                                % (esc(mid), esc(val))), refresh=2)
            return
        if u.path != "/run":
            self.send("<h1>404</h1>", 404)
            return
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        f = urllib.parse.parse_qs(body)
        lines = [x.strip() for x in f.get("tasks", [""])[0].splitlines() if x.strip()]
        if lines:
            with open(QUEUE, "a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
        self.send(self.page("已加入队列", self.nav() +
                            "<h1>已加入队列</h1>"
                            "<div class='flash'>写入 %d 条任务 → <span class='mono'>%s</span></div>"
                            "<div class='card'>队列现在有 <b>%d</b> 条待跑。</div>"
                            % (len(lines), esc(QUEUE), len(read_queue()))), refresh=3)

    # ---------- 总览 ----------
    def view_home(self, qs):
        runs = running_info()
        qn = read_queue()
        ss = load_sessions()
        if runs:
            head = "<div class='card run'><h1>● 正在测试</h1>"
            for r in runs:
                head += ("<div class='mono'>%s &nbsp; 已跑 %s &nbsp; pid %s</div>"
                         % (esc(r["path"].replace(ROOT + "/", "")), esc(r["elapsed"]), esc(r["pid"])))
            head += "<p class='sub'>每 10 秒自动刷新</p></div>"
        else:
            head = "<div class='card idle'><h1>○ 空闲</h1><p class='sub'>当前没有正在跑的测试</p></div>"

        dw = scan_all_workspaces()
        n_bad = sum(len(t["forbidden"]) for r in dw for t in r["tiers"])
        n_files = sum(t["file_count"] for r in dw for t in r["tiers"])
        head += ("<h2>部署概览</h2><div class='grid'>"
                 "<div class='box'><div class='n'>%d</div><div class='l'>工作区</div></div>"
                 "<div class='box'><div class='n'>%d</div><div class='l'>已部署文件</div></div>"
                 "<div class='box'><div class='n'>%d</div><div class='l'>技能包（去重）</div></div>"
                 "<div class='box'><div class='n'>%s</div><div class='l'>违规文件</div></div>"
                 "</div><p class='sub'><a href='/deploy'>看部署分类明细 →</a></p>"
                 % (len(dw), n_files,
                    len(set(s for r in dw for t in r["tiers"] for s in t["skills_src"])),
                    ("<span class='dang'>%d</span>" % n_bad) if n_bad else "0"))

        it_h, _ms_h = load_impl()
        n_done_h = sum(1 for v in it_h.values() if v.get("status") == "done")
        n_doing_h = sum(1 for v in it_h.values() if v.get("status") == "doing")
        head += ("<h2>实现区</h2><div class='grid'>"
                 "<div class='box'><div class='n'>%d</div><div class='l'>已实现</div></div>"
                 "<div class='box'><div class='n'>%d</div><div class='l'>实现中</div></div>"
                 "</div><p class='sub'><a href='/impl'>进实现区看落地记录与对话 →</a>"
                 " &nbsp;·&nbsp; <a href='http://127.0.0.1:8897/active' target='_blank'>"
                 "研究面板的实现区</a></p>" % (n_done_h, n_doing_h))

        qh = "<h2>队列（%d 条）</h2><div class='card'>" % len(qn)
        qh += ("<pre>%s</pre>" % esc("\n".join(qn))) if qn else \
              "<p class='sub'>队列为空。点 <a href='/run'>新测试</a> 加任务。</p>"
        qh += "</div>"

        rows = "".join(
            "<tr><td><a href='/s/%s'>%s</a></td><td>%d</td><td>%d</td><td>%s</td></tr>"
            % (esc(s["id"]), esc(s["title"][:60]), s["msgs"], s["tools"], fmt_ts(s["last"]))
            for s in ss[:14])
        sh = ("<h2>最近会话</h2><div class='card'><table>"
              "<tr><th>标题</th><th>消息</th><th>工具</th><th>最后活动</th></tr>%s</table>"
              "<p class='sub'><a href='/sessions'>看全部 %d 个会话 →</a></p></div>" % (rows, len(ss)))
        return self.page("DSH 测试面板", self.nav() + head + qh + sh, refresh=10)

    def tag(self, title):
        for p, t in (("[CLEAN]", "CLEAN"), ("[EXPLICIT]", "EXPLICIT"), ("[IMPLICIT]", "IMPLICIT")):
            if title.startswith(p):
                return t
        if "ubagent" in title:
            return "SUB"
        return "?"

    def view_sessions(self):
        ss = load_sessions()
        rows = ""
        for s in ss:
            tg = self.tag(s["title"])
            rows += ("<tr><td><span class='tag t-%s'>%s</span></td>"
                     "<td><a href='/s/%s'>%s</a></td><td>%d</td><td>%d</td><td>%s</td></tr>"
                     % (tg, tg, esc(s["id"]), esc(s["title"][:62]), s["msgs"], s["tools"],
                        fmt_ts(s["last"])))
        inner = (self.nav() + "<h1>全部会话（%d）</h1>" % len(ss) +
                 "<div class='card'><table><tr><th>档位</th><th>标题</th><th>消息</th>"
                 "<th>工具</th><th>最后活动</th></tr>%s</table></div>" % rows)
        return self.page("会话", inner, refresh=15)

    def view_session(self, sid):
        rec, dbp = find_session(sid)
        meta = []
        try:
            c = sqlite3.connect("file:%s?mode=ro" % dbp, uri=True)
            meta = list(c.execute(
                "select title,message_count,tool_call_count,started_at,ended_at,cwd "
                "from sessions where id=?", (sid,)))
            c.close()
        except Exception:
            pass
        if not meta:
            return self.page("未找到", self.nav() + "<h1>未找到该会话</h1>")
        title, mc, tc, st, en, cwd = meta[0]
        tg = self.tag(title or "")
        h = (self.nav() + "<h1><span class='tag t-%s'>%s</span> %s</h1>"
             "<p class='sub'>%d 消息 · %d 工具调用 · 开始 %s · 结束 %s<br>工作区 %s</p>"
             % (tg, tg, esc(title), mc, tc, fmt_ts(st), fmt_ts(en), esc(cwd)))
        if cwd and os.path.isdir(cwd):
            h += "<p class='sub'><a href='/deploy?w=%s'>看这个工作区部署了什么 →</a></p>" % esc(cwd)
        h += "<p class='sub'>来源库 <span class='mono'>%s</span>" % esc(dbp.replace(ROOT + "/", ""))
        if rec:
            h += " &nbsp;·&nbsp; <a href='/impl'>实现区</a>"
        h += "</p>"
        parts = []
        for role, content, tname, tcalls, ts in load_messages(sid, dbp):
            cls = {"user": "u", "assistant": "m", "tool": "t", "system": "s"}.get(role, "t")
            label = {"user": "用户", "assistant": "模型",
                     "tool": "工具结果 [%s]" % (tname or ""), "system": "系统"}.get(role, role)
            body = content or ""
            if tcalls:
                try:
                    for x in (json.loads(tcalls) or []):
                        fn = x.get("function") or {}
                        body += "\n[工具调用] %s(%s)" % (fn.get("name"),
                                                        str(fn.get("arguments"))[:2000])
                except Exception:
                    body += "\n[tool_calls] " + str(tcalls)[:1000]
            parts.append("<div class='msg %s'><div class='role'>%s &nbsp;<span class='k'>%s</span>"
                         "</div><pre>%s</pre></div>"
                         % (cls, esc(label), fmt_ts(ts), esc(body if body.strip() else "(空)")))
        return self.page(title or "会话", h + "".join(parts))

    # ---------- 部署分类 ----------
    def view_deploy(self, wfilter):
        data = scan_all_workspaces()
        if wfilter:
            data = [r for r in data if any(wfilter == t["path"] for t in r["tiers"])]

        n_bad_all = sum(len(t["forbidden"]) for r in data for t in r["tiers"])
        n_files = sum(t["file_count"] for r in data for t in r["tiers"])
        n_bytes = sum(t["total_bytes"] for r in data for t in r["tiers"])
        all_skills = set()
        for r in data:
            for t in r["tiers"]:
                all_skills.update(t["skills_src"])

        h = ["<h1>部署分类</h1>",
             "<p class='sub'>每个工作区里的文件按角色分四类。"
             "<b>场景文件</b>=agent 该看的任务与素材；<b>技能包</b>=部署给它的能力；"
             "<b>环境配置</b>=让会话跑起来的运行时；<b>违规</b>=我的测试脚手架，绝不能出现。</p>"]

        if wfilter:
            h.append("<div class='flash'>只显示工作区 <span class='mono'>%s</span> "
                     "&nbsp; <a href='/deploy'>看全部</a></div>" % esc(wfilter))

        # 顶部统计
        badge = ("<span class='dang'><b>%d 处违规</b></span>" % n_bad_all) if n_bad_all \
                else "<span class='u'><b>0 违规</b></span>"
        h.append("<div class='grid'>"
                 "<div class='box'><div class='n'>%d</div><div class='l'>工作区</div></div>"
                 "<div class='box'><div class='n'>%d</div><div class='l'>文件</div></div>"
                 "<div class='box'><div class='n'>%s</div><div class='l'>占用</div></div>"
                 "<div class='box'><div class='n'>%d</div><div class='l'>技能包种类</div></div>"
                 "<div class='box'><div class='n'>%s</div><div class='l'>安全检查</div></div>"
                 "</div>" % (len(data), n_files, human(n_bytes), len(all_skills), badge))

        if n_bad_all:
            h.append("<h2>违规文件（必须移除）</h2><div class='card bad'><table>"
                     "<tr><th>工作区</th><th>文件</th><th>原因</th></tr>")
            for r in data:
                for t in r["tiers"]:
                    for rel, why in t["forbidden"]:
                        h.append("<tr><td class='mono'>%s/%s</td><td class='mono dang'>%s</td>"
                                 "<td>%s</td></tr>"
                                 % (esc(r["rec"]), esc(t["tier"]), esc(rel), esc(why)))
            h.append("</table></div>")

        # 每个工作区
        for r in data:
            h.append("<h2><a href='/task/%s'>%s</a> "
                     "<span class='k' style='font-weight:400;font-size:12px'>"
                     "（点任务名看完整部署清单）</span></h2>"
                     % (urllib.parse.quote(r["rec"]), esc(r["rec"])))
            for t in r["tiers"]:
                roles = t["roles"]
                cs, _, _ = ROLE_LABEL["scenario"]
                ck, _, _ = ROLE_LABEL["skill"]
                ce, _, _ = ROLE_LABEL["env"]
                summary = ("<span class='tag r-scenario'>场景 %d</span> "
                           "<span class='tag r-skill'>技能 %d</span> "
                           "<span class='tag r-env'>环境 %d</span>"
                           % (len(roles["scenario"]), len(roles["skill"]), len(roles["env"])))
                if roles["other"]:
                    summary += " <span class='tag r-other'>未分类 %d</span>" % len(roles["other"])
                if t["forbidden"]:
                    summary += " <span class='tag' style='background:#5f1e2e;color:#f8a5a5'>违规 %d</span>" \
                               % len(t["forbidden"])
                h.append("<div class='card'><div><b>%s</b> &nbsp; %s &nbsp;"
                         "<span class='k'>%s 文件 / %s</span></div>"
                         % (esc(t["tier"]), summary, t["file_count"], human(t["total_bytes"])))

                def block(role, title, note):
                    items = sorted(roles[role])
                    if not items:
                        return
                    h.append("<details><summary>%s（%d）— %s</summary><pre>%s</pre></details>"
                             % (esc(title), len(items), esc(note),
                                esc("\n".join("%8s  %s" % (human(sz) if sz >= 0 else "-", rel)
                                              for rel, sz in items[:80]))))
                    if len(items) > 80:
                        h.append("<p class='sub'>（只显示前 80 个，共 %d）</p>" % len(items))

                block("scenario", "场景文件", "agent 该看的：任务描述与素材")
                block("skill", "技能包", "部署给 agent 的能力")
                block("env", "环境配置", "让会话能跑起来的运行时（默认不在此列出大文件）")
                block("other", "未分类", "需要人工确认该归哪一类")

                # 技能包源/运行时对照
                s_src, s_rt = set(t["skills_src"]), set(t["skills_runtime"])
                h.append("<details><summary>技能包部署对照 — 源目录 %d 个 / 运行时 %d 个</summary>"
                         % (len(s_src), len(s_rt)))
                only_src = sorted(s_src - s_rt)
                only_rt = sorted(s_rt - s_src)
                h.append("<pre>源目录 skills/            : %d 个\n运行时 .hermes/skills/    : %d 个\n\n"
                         "只部署了源目录（未装进运行时）: %s\n"
                         "只在运行时（Hermes 自带）    : %s\n\n源目录清单:\n%s</pre>"
                         % (len(s_src), len(s_rt),
                            esc(", ".join(only_src[:20]) or "无"),
                            esc(", ".join(only_rt[:20]) or "无"),
                            esc("\n".join("  " + x for x in sorted(s_src)))))
                h.append("</details></div>")

        return self.page("部署分类", self.nav() + "".join(h), refresh=None)

    # ---------- 任务清单 ----------
    def view_task(self, rec):
        if MANIFEST is None:
            return self.page("任务清单", self.nav() +
                             "<h1>清单模块未加载</h1><pre>%s</pre>" % esc(MANIFEST_ERR))
        rec = rec.strip("/")
        tiers = []
        for tier in ("clean", "implicit", "explicit"):
            m = MANIFEST.build(rec, tier)
            if m:
                tiers.append(m)
        if not tiers:
            return self.page("未找到", self.nav() + "<h1>未找到任务 %s</h1>" % esc(rec))

        h = ["<div class='nav'><a href='/deploy'>← 部署分类</a></div>",
             "<h1>任务清单：%s</h1>" % esc(rec),
             "<p class='sub'>这次任务往对方机器上部署了什么、依据是什么、有没有越界。"
             "环境配置与运行时目录不属于交付内容，单独折叠。</p>"]
        for m in tiers:
            t = m["totals"]
            bad = t["violations"]
            badge = ("<span class='tag' style='background:#5f1e2e;color:#f8a5a5'>违规 %d</span>" % bad) \
                    if bad else "<span class='tag r-scenario'>安全检查通过</span>"
            h.append("<h2>%s 档</h2><div class='card %s'>" % (esc(m["tier"]), "bad" if bad else ""))
            h.append("<div class='grid'>"
                     "<div class='box'><div class='n'>%d</div><div class='l'>场景文件</div></div>"
                     "<div class='box'><div class='n'>%d</div><div class='l'>技能包</div></div>"
                     "<div class='box'><div class='n'>%.1f KB</div><div class='l'>交付体积</div></div>"
                     "<div class='box'><div class='n'>%s</div><div class='l'>安全检查</div></div>"
                     "</div>"
                     % (t["scenario_files"], t["skill_pkgs"],
                        (t["scenario_bytes"] + t["skill_pkg_bytes"]) / 1024, badge))

            # 场景文件
            h.append("<details open><summary>场景文件（%d）— agent 该看的</summary><table>"
                     "<tr><th>文件</th><th>大小</th><th>角色</th></tr>"
                     % t["scenario_files"])
            for x in sorted(m["scenario"], key=lambda y: y["path"]):
                h.append("<tr><td class='mono'>%s</td><td>%s</td><td class='k'>%s</td></tr>"
                         % (esc(x["path"]), human(x["size"]), esc(x["why"])))
            h.append("</table></details>")

            # 技能包
            h.append("<details><summary>技能包（%d）— 部署给 agent 的能力</summary><table>"
                     "<tr><th>技能包</th><th>文件</th><th>大小</th><th>指纹</th></tr>"
                     % t["skill_pkgs"])
            for x in m["skill_pkgs"]:
                h.append("<tr><td class='mono'>%s</td><td>%d</td><td>%s</td>"
                         "<td class='k mono'>%s</td></tr>"
                         % (esc(x["name"]), x["files"], human(x["bytes"]), esc(x["dir_hash"])))
            h.append("</table></details>")

            # 环境配置
            h.append("<details><summary>环境配置（明细 %d + 运行时折叠 %d）— 让会话跑起来</summary>"
                     "<table><tr><th>文件</th><th>大小</th><th>作用</th></tr>"
                     % (t["env_files"], t["runtime_env_files"]))
            for x in sorted(m["env_summary"], key=lambda y: y["path"])[:60]:
                h.append("<tr><td class='mono'>%s</td><td>%s</td><td class='k'>%s</td></tr>"
                         % (esc(x["path"]), human(x["size"]), esc(x["why"])))
            h.append("</table>")
            if t["runtime_env_files"]:
                h.append("<p class='sub'>另有 %d 个运行时文件（Python 运行时、uv 缓存、"
                         "installs 内的 venv，共 %s）已折叠，它们由机器自生，不属于交付物。</p>"
                         % (t["runtime_env_files"], human(t["runtime_bytes"])))
            h.append("</details>")

            if m["other"]:
                h.append("<details><summary>未分类（%d）— 需人工确认</summary><table>"
                         "<tr><th>文件</th><th>大小</th></tr>" % len(m["other"]))
                for x in m["other"]:
                    h.append("<tr><td class='mono'>%s</td><td>%s</td></tr>"
                             % (esc(x["path"]), human(x["size"])))
                h.append("</table></details>")
            h.append("</div>")
        return self.page("任务清单 " + rec, self.nav() + "".join(h))

    # ---------- 实现区 ----------
    def view_impl(self):
        it, ms = load_impl()
        all_sess = load_sessions()

        def sess_for(mid):
            """找与这个测试相关的会话：标题/工作区里带该 id 或它的记录名。"""
            key = mid.lower()
            hits = []
            for s in all_sess:
                blob = (s["title"] + " " + s["ws"]).lower()
                if key in blob or key.replace("m", "_m") in blob:
                    hits.append(s)
            return hits[:8]

        groups = [("done", "已实现"), ("doing", "实现中"),
                  ("todo", "待实现"), ("abandoned", "已放弃")]
        h = ["<h1>实现区</h1>",
             "<p class='sub'>这里只列<b>已上线的攻击方法</b>（实现中 / 已实现），"
             "与研究面板的 55 条总清单分开，避免重复审计。"
             "每条挂着它的测试记录、最近会话和完整对话链接。</p>"]

        n_done = sum(1 for v in it.values() if v.get("status") == "done")
        n_doing = sum(1 for v in it.values() if v.get("status") == "doing")
        n_aban = sum(1 for v in it.values() if v.get("status") == "abandoned")
        h.append("<div class='grid'>"
                 "<div class='box'><div class='n'>%d</div><div class='l'>已实现</div></div>"
                 "<div class='box'><div class='n'>%d</div><div class='l'>实现中</div></div>"
                 "<div class='box'><div class='n'>%d</div><div class='l'>已放弃</div></div>"
                 "<div class='box'><div class='n'>%d</div><div class='l'>总方法</div></div>"
                 "</div>" % (n_done, n_doing, n_aban, len(ms)))

        # 正在跑的测试
        runs = running_info()
        if runs:
            h.append("<div class='card run'><h2>● 正在测试</h2>")
            for r in runs:
                h.append("<div class='mono'>%s &nbsp; 已跑 %s &nbsp; pid %s</div>"
                         % (esc(r["path"].replace(ROOT + "/", "")),
                            esc(r["elapsed"]), esc(r["pid"])))
            h.append("</div>")

        by_ws = {}
        for s in all_sess:
            by_ws.setdefault(s["ws"], []).append(s)

        for key, label in groups:
            ids = sorted([k for k, v in it.items() if v.get("status") == key],
                         key=lambda x: (len(x), x))
            if not ids:
                continue
            if key in ("todo",) and len(ids) > 40:
                pass
            if key in ("todo", "abandoned") and not ids:
                continue
            if key not in ("done", "doing"):
                continue          # 实现区只显示上线中的，待实现/已放弃不在此列
            h.append("<h2>%s（%d）</h2>" % (label, len(ids)))
            for mid in ids:
                v = it[mid]
                m = ms.get(mid) or {}
                name = m.get("name", "(研究面板里没有这条)")
                st = v.get("status", "todo")
                h.append("<div class='card'>")
                h.append("<h3>%s · %s %s</h3>"
                         % (esc(mid), esc(name), _st_badge(st)))
                if m.get("src"):
                    h.append("<p class='sub'>%s</p>" % esc(m["src"]))
                if v.get("updated"):
                    h.append("<p class='sub'>状态更新于 %s</p>" % esc(str(v["updated"])[:19]))
                if v.get("note"):
                    h.append("<details open><summary>实现记录（%d 字）</summary>"
                             "<pre>%s</pre></details>" % (len(v["note"]), esc(v["note"])))
                # 相关会话
                ss = sess_for(mid)
                if ss:
                    h.append("<details open><summary>相关会话（%d）</summary>"
                             "<table><tr><th>工作区</th><th>标题</th><th>消息</th>"
                             "<th>工具</th><th>最后活动</th></tr>" % len(ss))
                    for s in ss:
                        h.append("<tr><td class='mono'>%s</td>"
                                 "<td><a href='/s/%s'>%s</a></td><td>%d</td><td>%d</td>"
                                 "<td>%s</td></tr>"
                                 % (esc(s["ws"]), esc(s["id"]), esc(s["title"][:60]),
                                    s["msgs"], s["tools"], fmt_ts(s["last"])))
                    h.append("</table></details>")
                else:
                    h.append("<p class='sub'>暂无相关会话。"
                             "把测试记录名带上 <span class='mono'>%s</span> "
                             "就能在这里显示。</p>" % esc(mid.lower()))
                # 状态切换
                opts = "".join("<option value='%s'%s>%s</option>"
                               % (k, " selected" if k == st else "", esc(lbl))
                               for k, lbl in (("done", "已实现"), ("doing", "实现中"),
                                              ("todo", "待实现"), ("abandoned", "已放弃")))
                h.append("<form method='post' action='/impl/status' style='margin-top:8px'>"
                         "<input type='hidden' name='id' value='%s'>"
                         "<select name='status' onchange='this.form.submit()'>%s</select>"
                         " <span class='k'>改状态</span></form>" % (esc(mid), opts))
                h.append(" &nbsp;<a href='http://127.0.0.1:8897/method/%s' "
                         "target='_blank'>研究面板详情 →</a>" % esc(mid))
                h.append("</div>")

        if n_done + n_doing == 0:
            h.append("<div class='card'><h1>实现区还是空的</h1>"
                     "<p class='sub'>在 <a href='http://127.0.0.1:8897/active' "
                     "target='_blank'>研究面板 8897 的实现区</a> 里把某条设为"
                     "「实现中／已实现」，这里就会同步出现。</p></div>")
        return self.page("实现区", self.nav() + "".join(h), refresh=10)

    # ---------- 新测试 ----------
    def view_run(self):
        recs = sorted(d[:-7] for d in os.listdir(ROOT) if d.endswith("__tiers"))
        inner = (self.nav() +
                 "<h1>发起新测试</h1>"
                 "<div class='card'>"
                 "<p class='sub'>每行一条，格式 <span class='mono'>&lt;记录名&gt; &lt;档位&gt;</span>，"
                 "档位取值 clean / implicit / explicit。写入 <span class='mono'>" + esc(QUEUE) +
                 "</span>，由服务器上的队列执行器消费。</p>"
                 "<form method='post' action='/run'>"
                 "<textarea name='tasks' rows='6' style='width:100%;background:#12151b;color:#e6e8eb;"
                 "border:1px solid #2a3140;border-radius:5px;padding:8px;"
                 "font-family:ui-monospace,monospace;font-size:12.5px' "
                 "placeholder='srv-audit-q3 explicit&#10;srv-ctx-sync implicit'></textarea>"
                 "<p><button class='btn' type='submit'>加入队列</button></p>"
                 "</form></div>"
                 "<h2>可选的记录名</h2><div class='card'><pre>" + esc("\n".join(recs)) + "</pre></div>")
        return self.page("新测试", inner)


class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    print("DSH 面板监听 0.0.0.0:%d" % PORT, flush=True)
    TS(("0.0.0.0", PORT), H).serve_forever()
