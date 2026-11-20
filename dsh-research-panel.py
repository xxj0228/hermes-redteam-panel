#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
研究面板（服务版 v2）—— 攻击方法研究与实现跟踪。

  /              总方法清单（全部，含状态徽章）
  /active        实现区（只显示 实现中/已实现，与总清单分开，避免重复审计）
  /selected      只看勾选的
  /method/<id>   单条详情
  /export        导出清单

数据文件: /dev/shm/research-data.json   （方法定义，子 agent 维护）
          /dev/shm/research-status.json （实现状态，由本面板维护）
          /dev/shm/research-state.json  （用户勾选与批注）
"""
import http.server, socketserver, json, os, html, urllib.parse, threading, datetime, io, re

PORT = 8898
DATA = r"C:/dsh_work/composkill_test/_panel-win/data/research-data.json"
STATE = r"C:/dsh_work/composkill_test/_panel-win/data/research-state.json"
STATUS = r"C:/dsh_work/composkill_test/_panel-win/data/research-status.json"
LOCK = threading.Lock()

# 状态 → (徽章文案, 颜色类别, 排序权重)
STATUS_META = {
    "todo":      ("待实现", "todo", 3),
    "doing":     ("实现中", "doing", 1),
    "done":      ("已实现", "done", 0),
    "abandoned": ("已放弃", "aban", 4),
}
STATUS_ORDER = ["done", "doing", "todo", "abandoned"]


def load_data():
    with open(DATA, encoding="utf-8") as f:
        return json.load(f)


def load_state():
    if os.path.exists(STATE):
        try:
            with open(STATE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"selected": [], "notes": {}, "updated": None}


def save_state(st):
    st["updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=1)
    os.replace(tmp, STATE)


def load_status():
    if os.path.exists(STATUS):
        try:
            with open(STATUS, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"items": {}, "updated": None}


def save_status(s):
    s["updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tmp = STATUS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=False, indent=1)
    os.replace(tmp, STATUS)


_LTAG = {"planner": "[P]", "validator": "[V]", "isolator": "[I]"}


def _ltag(m):
    return " ".join("<span style='color:#4f7fd0;font-size:12px'>%s</span>"
                    % _LTAG.get(x, "") for x in (m.get("drift_layer") or []))

def esc(x):
    return html.escape(str(x if x is not None else ""))


CAT_MAIN = "攻击方法"
CAT_IR = "意图识别"
CAT_ACAD = "意图识别学术产出"
CAT_MEM = "记忆投毒"


def cat_of(m):
    """分类字段；老条目（M1–M55）没有 category，默认归到 攻击方法。"""
    return m.get("category") or CAT_MAIN


def sub_of(m):
    return m.get("subcategory") or ""


def sid(mid):
    """M12 -> 12；IR-B03 -> 2003；IR-A03 -> 3003；IR-C03 -> 4003（分类内连续排序）。"""
    s = str(mid)
    mm = re.match(r"IR-B(\d+)$", s)
    if mm:
        return 2000 + int(mm.group(1))
    mm = re.match(r"IR-A(\d+)$", s)
    if mm:
        return 3000 + int(mm.group(1))
    mm = re.match(r"IR-C(\d+)$", s)
    if mm:
        return 4000 + int(mm.group(1))
    mm = re.match(r"MP-[ABDS](\d+)$", s)
    if mm:
        return 5000 + int(mm.group(1))
    try:
        return int(s.lstrip("Mm"))
    except Exception:
        return 9999


ACAD_SUBS = ("attack-bench", "bench-other", "reference", "survey")
MEM_SUBS = ("attack", "bench", "defense", "system")


def cat_order(m):
    """分类顺序：攻击方法 → 意图识别 → 意图识别学术产出 → 记忆投毒。"""
    c, s = cat_of(m), sub_of(m)
    if c == CAT_MAIN:
        cg = 0
    elif c == CAT_ACAD:
        cg = 2
    elif c == CAT_MEM:
        cg = 3
    else:
        cg = 1
    if c == CAT_ACAD:
        sg = ACAD_SUBS.index(s) if s in ACAD_SUBS else 3
    elif c == CAT_MEM:
        sg = MEM_SUBS.index(s) if s in MEM_SUBS else len(MEM_SUBS)
    else:
        sg = (0 if s == "benchmark" else
              (1 if s == "benchmark-other" else (2 if s == "attack" else 3)))
    return (cg, sg, sid(m["id"]))


MEM_SUB_META = {
    "attack": ("#c05a5a", "攻击方法", "把内容写进长期记忆并跨会话激活的手法"),
    "bench": ("#4f7fd0", "评测与基准", "度量投毒能否成功、后果多大、防御代价多少"),
    "defense": ("#5b8f7a", "防御方法", "写入准入、来源绑定、检索过滤、行为图检测"),
    "system": ("#c08a3e", "系统与撤回", "记忆系统整体行为：撤回失效、跨会话传播、效用代价"),
}


ACAD_SUB_META = {
    "attack-bench": ("#4f7fd0", "纯攻击 benchmark", "定义了攻击者，度量攻击能否让意图判定失效"),
    "bench-other": ("#5b8f7a", "非攻击 benchmark", "无攻击者的测量/对齐基准（不完整指令、计划质量、覆盖度等）"),
    "reference": ("#7a8598", "可参考工作", "攻击方法/评测方法可复用，但不是专门的意图识别 benchmark"),
    "survey": ("#c08a3e", "综述与立场", "威胁模型、测量方法、立场与治理分析"),
}


def st_of(mid, st_items):
    return st_items.get(mid, {}).get("status", "todo")


def st_badge(status):
    label, cls, _ = STATUS_META.get(status, STATUS_META["todo"])
    return "<span class='tag s-%s'>%s</span>" % (cls, esc(label))


CSS = """
<style>
 body{font:14px/1.65 -apple-system,'Segoe UI',system-ui,'Microsoft YaHei',sans-serif;
      margin:0;background:#0f1115;color:#e6e8eb}
 .wrap{max-width:1180px;margin:0 auto;padding:20px}
 a{color:#6cb6ff;text-decoration:none} a:hover{text-decoration:underline}
 h1{font-size:19px;margin:0 0 4px}
 .sub{color:#7d8794;font-size:12px;margin-bottom:14px}
 .nav{margin-bottom:14px;font-size:13px}
 .bar{position:sticky;top:0;z-index:9;background:#0f1115f2;backdrop-filter:blur(6px);
      border-bottom:1px solid #232833;padding:9px 0;margin-bottom:14px;
      display:flex;gap:9px;align-items:center;flex-wrap:wrap}
 button{background:#233043;border:1px solid #33465e;color:#cfe3ff;padding:6px 13px;
      border-radius:5px;cursor:pointer;font-size:13px}
 button:hover{background:#2b3a50}
 button.on{background:#173d2c;border-color:#2f7d5c;color:#8ee0b0}
 .cnt{color:#7d8794;font-size:12.5px;margin-left:auto}
 .card{background:#171a21;border:1px solid #232833;border-radius:9px;
      padding:15px 16px;margin-bottom:13px;border-left:4px solid #2a3140}
 .card.sel{border-left-color:#34d399;background:#16211c}
 .card.hi{border-left-color:#f0b070}
 .card.done{border-left-color:#4ade80;background:#141f19}
 .card.doing{border-left-color:#fbbf24;background:#1f1c14}
 .card.aban{border-left-color:#6b7280;opacity:.62}
 h2{font-size:15.5px;margin:0 0 3px}
 .meta{color:#7d8794;font-size:12px;margin-bottom:10px}
 .stars{color:#f0b070;letter-spacing:1px}
 .sec{margin:9px 0}
 .sec>b{color:#9aa4b2;font-size:12.5px;display:block;margin-bottom:3px}
 ul{margin:3px 0 0 0;padding-left:20px} li{margin:2px 0}
 code{background:#12151b;padding:1px 5px;border-radius:3px;font-size:12.5px;
      font-family:ui-monospace,Consolas,monospace;color:#9dc4ee}
 pre{background:#12151b;border:1px solid #232833;border-radius:6px;padding:9px;
     overflow-x:auto;white-space:pre-wrap;font-size:12.5px;margin:5px 0}
 .tag{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;margin:0 3px 3px 0;
      background:#1c3350;color:#9dc4ee}
 .tag.g{background:#173d2c;color:#8ee0b0} .tag.r{background:#5f1e2e;color:#f8a5a5}
 .tag.y{background:#3d3218;color:#e6d08e} .tag.p{background:#3a2f5f;color:#c4b0ee}
 .tag.s-done{background:#14512f;color:#7ff0b0;border:1px solid #2f7d5c}
 .tag.s-doing{background:#4d3a10;color:#fbd87f;border:1px solid #8a6a1f}
 .tag.s-todo{background:#2a3040;color:#9aa4b2}
 .tag.s-aban{background:#2a2f38;color:#8a929e}
 textarea{width:100%;background:#12151b;border:1px solid #2a3140;color:#e6e8eb;
      border-radius:5px;padding:7px;font-size:12.5px;
      font-family:ui-monospace,Consolas,monospace;box-sizing:border-box}
 .note-row{display:flex;gap:8px;align-items:flex-start;margin-top:9px}
 .note-row textarea{flex:1}
 .flash{background:#14351f;border:1px solid #2f7d5c;color:#9fe8c0;padding:9px 12px;
      border-radius:6px;margin-bottom:12px;font-size:13px}
 .grid{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
 .box{flex:1;min-width:120px;background:#141821;border:1px solid #222834;border-radius:6px;padding:10px}
 .box .n{font-size:20px;font-weight:600} .box .l{font-size:11px;color:#7d8794}
 label.pick{display:flex;gap:10px;align-items:flex-start;cursor:pointer}
 input[type=checkbox]{margin-top:4px;width:17px;height:17px;cursor:pointer;flex:0 0 auto}
 form{display:inline}
 .strow{display:flex;gap:6px;align-items:center;margin-top:8px;flex-wrap:wrap;
        border-top:1px dashed #262c38;padding-top:8px}
 .strow .lb{color:#7d8794;font-size:11.5px}
 select{background:#12151b;color:#e6e8eb;border:1px solid #2a3140;border-radius:4px;
        padding:4px 7px;font-size:12.5px}
 .grp{font-size:15px;color:#9aa4b2;margin:22px 0 10px;border-bottom:1px solid #232833;
      padding-bottom:6px;letter-spacing:.03em}
 .imp{background:#141821;border:1px solid #2a3140;border-radius:6px;padding:8px 11px;
      margin:9px 0;font-size:12.5px;color:#b9c2cf}
 .imp b{color:#8ee0b0}
.snotebox{background:#1a2333;border-left:3px solid #6cb6ff;padding:10px 12px;border-radius:5px;white-space:pre-wrap;font-family:ui-monospace,Consolas,monospace;font-size:12.5px;line-height:1.65}
</style>
"""


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, body, code=200):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(b)
        except Exception:
            pass

    def page(self, title, inner):
        return ("<!doctype html><html lang='zh'><head><meta charset='utf-8'>"
                "<title>%s</title>%s</head><body><div class='wrap'>%s</div></body></html>"
                % (esc(title), CSS, inner))

    def nav(self, cur=""):
        st = load_status()
        n_act = sum(1 for v in st["items"].values()
                    if v.get("status") in ("doing", "done"))
        n_ir = sum(1 for m in load_data()["methods"] if cat_of(m) == CAT_IR)
        n_ac = sum(1 for m in load_data()["methods"] if cat_of(m) == CAT_ACAD)
        n_mem = sum(1 for m in load_data()["methods"] if cat_of(m) == CAT_MEM)
        items = [("/", "总方法"),
                 ("/ir", "意图识别 (%d)" % n_ir),
                 ("/ir?sub=benchmark", "· 红队 benchmark"),
                 ("/ir?sub=benchmark-other", "· 其它 benchmark"),
                 ("/ir?sub=attack", "· attack"),
                 ("/acad", "学术产出 (%d)" % n_ac),
                 ("/acad?sub=attack-bench", "· 纯攻击 benchmark"),
                 ("/mem", "记忆投毒 (%d)" % n_mem),
                 ("/active", "实现区 (%d)" % n_act),
                 ("/selected", "只看勾选"), ("/export", "导出清单")]
        out = []
        for u, t in items:
            on = " class='on'" if u == cur else ""
            out.append("<a href='%s'%s>%s</a>" % (u, on, t))
        return ("<div class='nav'>" + " &nbsp;·&nbsp; ".join(out) +
                " &nbsp;·&nbsp; <a href='http://127.0.0.1:18900/' target='_blank'>"
                "测试面板 18900 → &nbsp;·&nbsp; <a href='/rounds'>测试轮次</a></a></div>")

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p = u.path
        try:
            if p == "/":
                self.send(self.view_list())
            elif p == "/ir":
                qs = urllib.parse.parse_qs(u.query)
                _sub = (qs.get("sub") or [None])[0]
                _layer = ((qs.get("layer") or [""])[0] or "").upper() or None
                if (_sub is None) and ((qs.get("view") or [""])[0] == "chain"):
                    _sub = "chain"
                self.send(self.view_ir(_sub, _layer))
            elif p == "/acad":
                qs = urllib.parse.parse_qs(u.query)
                _asub = (qs.get("sub") or [None])[0]
                _alayer = (qs.get("layer") or [None])[0]
                self.send(self.view_acad(_asub, _alayer))
            elif p == "/mem":
                qs = urllib.parse.parse_qs(u.query)
                _msub = (qs.get("sub") or [None])[0]
                _mlayer = ((qs.get("layer") or [""])[0] or "").lower() or None
                self.send(self.view_mem(_msub, _mlayer))
            elif p == "/active":
                self.send(self.view_active())
            elif p == "/selected":
                self.send(self.view_list(only_sel=True))
            elif p == "/export":
                self.send(self.view_export())
            elif p == "/rounds":
                self.send(self.view_rounds())
            elif p.startswith("/method/"):
                self.send(self.view_method(urllib.parse.unquote(p[8:])))
            else:
                self.send(self.page("404", self.nav() + "<h1>404</h1>"), 404)
        except Exception as e:
            self.send(self.page("错误", self.nav() +
                                "<pre>%s</pre>" % esc(repr(e))), 500)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        f = urllib.parse.parse_qs(body)
        msg = ""
        with LOCK:
            if u.path == "/status":
                mid = f.get("id", [""])[0]
                val = f.get("status", ["todo"])[0]
                if val not in STATUS_META:
                    val = "todo"
                s = load_status()
                it = s["items"].setdefault(mid, {})
                if val == "todo":
                    s["items"].pop(mid, None)
                else:
                    it["status"] = val
                save_status(s)
                msg = "%s 状态 → %s" % (mid, STATUS_META.get(val, ("?",))[0])
            elif u.path == "/statusnote":
                mid = f.get("id", [""])[0]
                txt = f.get("snote", "").strip()
                s = load_status()
                it = s["items"].setdefault(mid, {})
                it["note"] = txt
                it.setdefault("status", "doing")
                save_status(s)
                msg = "%s 实现备注已保存" % mid
            else:
                st = load_state()
                if u.path == "/toggle":
                    mid = f.get("id", [""])[0]
                    if mid in st["selected"]:
                        st["selected"].remove(mid)
                    else:
                        st["selected"].append(mid)
                    msg = "%s 勾选已切换" % mid
                elif u.path == "/note":
                    mid = f.get("id", [""])[0]
                    txt = f.get("note", [""])[0].strip()
                    if txt:
                        st["notes"][mid] = txt
                    else:
                        st["notes"].pop(mid, None)
                    msg = "%s 批注已保存" % mid
                elif u.path == "/bulk":
                    act = f.get("act", [""])[0]
                    data = load_data()
                    ids = [m["id"] for m in data["methods"]]
                    if act == "all":
                        st["selected"] = ids
                    elif act == "none":
                        st["selected"] = []
                    elif act == "top":
                        st["selected"] = [m["id"] for m in data["methods"]
                                          if m["priority"] <= 3]
                    msg = "批量操作 %s" % act
                save_state(st)
        self.send(self.page("已保存", self.nav() +
                            "<div class='flash'>%s &nbsp; <a href='/'>返回总方法</a>"
                            " &nbsp; <a href='/active'>去实现区</a></div>" % esc(msg)))

    # ---------- 卡片渲染 ----------
    def card(self, m, sel, st_items, show_impl=True):
        mid = m["id"]
        is_sel = mid in sel
        status = st_of(mid, st_items)
        klass = "card"
        if is_sel:
            klass += " sel"
        if m["priority"] <= 2:
            klass += " hi"
        if status == "done":
            klass += " done"
        elif status == "doing":
            klass += " doing"
        elif status == "abandoned":
            klass += " aban"

        h = ["<div class='%s'>" % klass]
        h.append("<label class='pick'>"
                 "<form method='post' action='/toggle'>"
                 "<input type='hidden' name='id' value='%s'>"
                 "<button type='submit' class='%s'>%s</button></form>"
                 "<div style='flex:1'>"
                 "<h2>%s · %s <span class='stars'>%s</span></h2>"
                 "<div class='meta'>%s &nbsp;·&nbsp; "
                 "<a href='%s' target='_blank'>原文 →</a> &nbsp;·&nbsp; "
                 "<a href='/method/%s'>详情</a></div>"
                 % (esc(mid), "on" if is_sel else "",
                    "✓ 已勾选" if is_sel else "勾选",
                    esc(mid), esc(m["name"]),
                    "★" * m["stars"] + "☆" * (5 - m["stars"]),
                    esc(m.get("src") or ""), m["url"], esc(mid)))
        h.append("<div>%s</div>" % "".join(
            "<span class='tag'>%s</span>" % esc(t) for t in m.get("family") or "".split(" / ")))
        if cat_of(m) != CAT_MAIN:
            _sub = sub_of(m)
            if _sub == "benchmark":
                _col, _lab = "#4f7fd0", "benchmark·攻击/红队"
            elif _sub == "benchmark-other":
                _col, _lab = "#7a8598", "benchmark·其它"
            elif _sub in ACAD_SUB_META:
                _col, _lab = ACAD_SUB_META[_sub][0], ACAD_SUB_META[_sub][1]
            else:
                _col, _lab = "#c08a3e", "attack"
            h.append("<div style='margin-top:4px'>"
                     "<span class='tag' style='border-color:%s;color:%s'>%s · %s</span></div>"
                     % (_col, _col, esc(cat_of(m)), esc(_lab)))
        h.append("<div style='margin-top:4px'>"
                 "<span class='tag %s'>注入：%s</span>"
                 "<span class='tag %s'>可复现性：%s</span>"
                 "<span class='tag p'>优先 %d</span>%s</div>"
                 % ("g" if "无" in m.get("injection") or "" else
                    ("y" if "间接" in m.get("injection") or "" else "r"), esc(m.get("injection") or ""),
                    "g" if m.get("repro") or "".startswith("高") else
                    ("r" if m.get("repro") or "".startswith("不支持") else "y"), esc(m.get("repro") or ""),
                    m["priority"], st_badge(status)))
        h.append("</div></label>")

        h.append("<div class='sec'><b>机制</b><ul>%s</ul></div>"
                 % "".join("<li>%s</li>" % esc(x) for x in m.get("mech") or []))
        h.append("<div class='sec'><b>为什么值得看</b><div>%s</div></div>" % esc(m["why"]))
        h.append("<div class='sec'><b>对我们的可复现性</b><div>%s</div></div>"
                 % esc(m.get("repro_note", "")))
        h.append("<div class='sec'><b>我们的改造版</b><pre>%s</pre></div>" % esc(m.get("variant") or ""))
        h.append("<div class='sec'><b>映射到你的高危目标</b><div>%s</div></div>"
                 % "".join("<span class='tag g'>%s</span>" % esc(t) for t in m.get("goal_map") or []))
        if m.get("prereq"):
            h.append("<div class='sec'><b>前置条件</b><ul>%s</ul></div>"
                     % "".join("<li>%s</li>" % esc(x) for x in m.get("prereq") or []))

        # 实现状态行
        if show_impl:
            cur = st_items.get(mid, {})
            sval = cur.get("status", "todo")
            opts = "".join(
                "<option value='%s'%s>%s</option>"
                % (k, " selected" if sval == k else "", esc(STATUS_META[k][0]))
                for k in STATUS_ORDER)
            h.append("<div class='strow'>"
                     "<span class='lb'>实现状态</span>"
                     "<form method='post' action='/status'>"
                     "<input type='hidden' name='id' value='%s'>"
                     "<select name='status' onchange='this.form.submit()'>%s</select>"
                     "</form>" % (esc(mid), opts))
            if cur.get("updated") or cur.get("note"):
                h.append("<span class='lb'>更新于 %s</span>" % esc(cur.get("updated") or "-"))
            h.append("</div>")
            h.append("<form method='post' action='/statusnote'>"
                     "<input type='hidden' name='id' value='%s'>"
                     "<div class='note-row'><textarea name='snote' rows='2' "
                     "placeholder='实现记录：这次怎么做的、结果如何（存服务器）'>%s</textarea>"
                     "<button type='submit'>存实现记录</button></div></form>"
                     % (esc(mid), esc(cur.get("note", ""))))

        cur_note = load_state()["notes"].get(mid, "")
        h.append("<form method='post' action='/note'>"
                 "<input type='hidden' name='id' value='%s'>"
                 "<div class='note-row'><textarea name='note' rows='2' "
                 "placeholder='你的批注（可选）'>%s</textarea>"
                 "<button type='submit'>存批注</button></div></form>"
                 % (esc(mid), esc(cur_note)))
        h.append("</div>")
        return "".join(h)

    # ---------- 总方法 ----------
    def view_list(self, only_sel=False):
        data = load_data()
        st = load_state()
        sr = load_status()
        sel = set(st["selected"])
        items = sr["items"]
        ms = data["methods"]
        shown = [m for m in ms if m["id"] in sel] if only_sel else ms
        shown = sorted(shown, key=lambda m: sid(m["id"]))

        done = sum(1 for m in ms if st_of(m["id"], items) == "done")
        doing = sum(1 for m in ms if st_of(m["id"], items) == "doing")
        aban = sum(1 for m in ms if st_of(m["id"], items) == "abandoned")

        h = ["<h1>%s</h1>" % ("只看勾选" if only_sel else "总方法清单"),
             "<div class='sub'>渠道："
             "<a href='https://aisafetyhot.com/zh/featured?category=attack' target='_blank'>"
             "aisafetyhot.com · attack</a>"
             "&nbsp;·&nbsp;状态与勾选都存服务器，改完即生效</div>",
             "<div class='grid'>"
             "<div class='box'><div class='n'>%d</div><div class='l'>方法总数</div></div>"
             "<div class='box'><div class='n'>%d</div><div class='l'>已勾选</div></div>"
             "<div class='box'><div class='n'>%d</div><div class='l'>已实现</div></div>"
             "<div class='box'><div class='n'>%d</div><div class='l'>实现中</div></div>"
             "<div class='box'><div class='n'>%d</div><div class='l'>已放弃</div></div>"
             "</div>" % (len(ms), len(sel), done, doing, aban)]

        h.append("<div class='bar'>"
                 "<form method='post' action='/bulk'><input type='hidden' name='act' value='top'>"
                 "<button type='submit'>只选推荐（前 3 优先级）</button></form>"
                 "<form method='post' action='/bulk'><input type='hidden' name='act' value='all'>"
                 "<button type='submit'>全选</button></form>"
                 "<form method='post' action='/bulk'><input type='hidden' name='act' value='none'>"
                 "<button type='submit'>全清</button></form>"
                 "<span class='cnt'>本页 %d 条</span></div>" % len(shown))

        h.append("<div class='imp'>行为说明：<b>实现区</b>是单独分类，只有状态为"
                 "「实现中／已实现」的方法会出现在那里 —— 你只需在实现区审计已落地的攻击，"
                 "总清单用来发现新方法，两边不会重复。</div>")

        for m in shown:
            h.append(self.card(m, sel, items))
        return self.page("攻击方法研究", self.nav("/selected" if only_sel else "/") + "".join(h))

    # ---------- 意图识别学术产出 ----------
    def view_acad(self, sub=None, layer=None):
        data = load_data()
        all_ac = [m for m in data["methods"] if cat_of(m) == CAT_ACAD]
        cnt = {k: sum(1 for m in all_ac if sub_of(m) == k) for k in ACAD_SUBS}
        cnt_layer = {k: sum(1 for m in all_ac if k in (m.get("drift_layer") or []))
                     for k in ("planner", "validator", "isolator")}
        n_dl = sum(1 for m in all_ac
                   if "未见公开" not in (m.get("assets") or "")
                   and ("公开代码" in (m.get("assets") or "")
                        or "公开可下载" in (m.get("assets") or "")))
        ms = list(all_ac)
        if sub:
            ms = [m for m in ms if sub_of(m) == sub]
        if layer:
            ms = [m for m in ms if layer in (m.get("drift_layer") or [])]
        ms.sort(key=lambda m: (cat_order(m), sid(m["id"])))

        def chip(u, label, on, color):
            return ("<a href='%s' style='display:inline-block;margin:2px 6px 2px 0;"
                    "padding:3px 10px;border:1px solid %s;border-radius:14px;"
                    "background:%s'>%s</a>"
                    % (u, color if on else "#2a3140", color.replace("#", "#1b") if on else "transparent",
                       esc(label)))

        def lvl_badge(m):
            note = m.get("repro_note") or ""
            for k, lab, col in (("原文级", "原文级", "#2f6b45"), ("arXiv 摘要级", "arXiv 摘要", "#2b4a6f"),
                                ("会议页摘要", "会议页摘要", "#5a4a2f"), ("标题级", "标题级", "#6b2f2f")):
                if k in note:
                    return ("<span class='tag' style='background:%s;color:#fff'>%s</span>"
                            % (col, esc(lab)))
            return "<span class='tag'>摘要级</span>"

        def layer_badge(m):
            LT = {"planner": "P", "validator": "V", "isolator": "I"}
            ls = [LT.get(x, "?") for x in (m.get("drift_layer") or [])]
            if not ls:
                return ""
            return ("<span class='tag' style='background:#1b3a5c;color:#cfe4ff'>打 DRIFT "
                    + "/".join(ls) + "</span>")

        h = ["<h1>意图识别学术产出 · 论文面板</h1>",
             "<div class='meta'>按「产出形态」分三桶："
             "<b>纯攻击 benchmark</b> = 定义了攻击者、专门度量「意图识别/守卫能否被攻破」的评测集；"
             "<b>可参考工作</b> = 攻击方法或评测方法可复用到意图识别，但不是专门 benchmark；"
             "<b>综述与立场</b> = 威胁模型、测量方法、立场与治理分析。"
             "来源优先级：aisafetyhot 论文页 / 会议页 &gt; arXiv；每条都记原链（arXiv abs / 会议页 / 官方仓库）。"
             "共 %d 条，其中标注为公开可下载的 %d 条。</div>" % (len(all_ac), n_dl),
             "<div style='margin:12px 0 6px'>"
             + chip("/acad", "全部 (%d)" % len(all_ac), sub is None, "#4f7fd0")
             + chip("/acad?sub=attack-bench", "纯攻击 benchmark (%d)" % cnt["attack-bench"],
                    sub == "attack-bench", ACAD_SUB_META["attack-bench"][0])
             + chip("/acad?sub=bench-other", "非攻击 benchmark (%d)" % cnt["bench-other"],
                    sub == "bench-other", ACAD_SUB_META["bench-other"][0])
             + chip("/acad?sub=reference", "可参考工作 (%d)" % cnt["reference"],
                    sub == "reference", ACAD_SUB_META["reference"][0])
             + chip("/acad?sub=survey", "综述与立场 (%d)" % cnt["survey"],
                    sub == "survey", ACAD_SUB_META["survey"][0])
             + "</div>",
             "<div style='margin:0 0 10px'>"
             "<span class='meta'>按 DRIFT 层筛选：</span>"
             + chip("/acad", "全部层", not layer, "#8a6fd0")
             + chip("/acad?layer=planner", "P 规划 (%d)" % cnt_layer["planner"],
                    layer == "planner", "#8a6fd0")
             + chip("/acad?layer=validator", "V 判定 (%d)" % cnt_layer["validator"],
                    layer == "validator", "#8a6fd0")
             + chip("/acad?layer=isolator", "I 隔离 (%d)" % cnt_layer["isolator"],
                    layer == "isolator", "#8a6fd0")
             + "</div>"]
        if not all_ac:
            h.append("<div class='meta'>还没有条目，第一批正在采集。</div>")
        cur = None
        for m in ms:
            s = sub_of(m)
            if s != cur:
                cur = s
                color, title, desc = ACAD_SUB_META.get(s, ("#7a8598", s or "未分类", ""))
                n_this = sum(1 for x in all_ac if sub_of(x) == s)
                h.append("<h2 style='margin:20px 0 4px;font-size:15px'>"
                         "<span style='display:inline-block;width:8px;height:8px;border-radius:50%%;"
                         "background:%s;margin-right:8px'></span>%s (%d)</h2>"
                         "<div class='meta' style='margin:0 0 8px'>%s</div>"
                         % (color, esc(title), n_this, esc(desc)))
            src = esc(m.get("src", ""))
            why = ""
            for line in (m.get("why") or "").split("\n"):
                if line.strip():
                    why = line.strip()
                    break
            assets = m.get("assets") or ""
            assets_html = ("<div class='meta' style='margin-top:3px;color:#7f8fa6'>📦 %s</div>"
                           % esc(assets)) if assets else ""
            if len(why) > 170:
                why = why[:170] + "…"
            h.append(
                "<div style='padding:9px 0;border-bottom:1px solid #1e242f'>"
                "<div><span class='tag' style='background:#2a3140'>%s</span>&nbsp;"
                "<a href='%s' target='_blank' style='font-weight:600'>%s</a>"
                "&nbsp;<span class='meta'>%s</span></div>"
                "<div style='margin-top:3px'>%s %s</div>"
                "<div class='meta' style='margin-top:3px'>%s</div>%s"
                "</div>"
                % (esc(m["id"]), esc(m["url"]), esc(m["name"]), src,
                   lvl_badge(m), layer_badge(m), esc(why), assets_html))
        if ms:
            h.append("<div class='meta' style='margin-top:14px'>共 %d 条（当前筛选）。"
                     "核验级别口径：原文级 = 已读原始出处；arXiv 摘要 = 读到 abs 摘要；"
                     "会议页摘要 = 会议页摘要（OpenReview 常被验证码拦）；标题级 = 仅标题。</div>" % len(ms))
        return self.page("意图识别学术产出", self.nav("/acad") + "".join(h))

    # ---------- 记忆投毒（mem0 / OpenViking） ----------
    def view_mem(self, sub=None, layer=None):
        data = load_data()
        all_mm = [m for m in data["methods"] if cat_of(m) == CAT_MEM]
        cnt = {k: sum(1 for m in all_mm if sub_of(m) == k) for k in MEM_SUBS}
        cnt_layer = {k: sum(1 for m in all_mm if k in (m.get("drift_layer") or []))
                     for k in ("planner", "validator", "isolator")}
        ms = list(all_mm)
        if sub in MEM_SUBS:
            ms = [m for m in ms if sub_of(m) == sub]
        if layer in ("planner", "validator", "isolator"):
            ms = [m for m in ms if layer in (m.get("drift_layer") or [])]
        ms.sort(key=lambda m: (cat_order(m), sid(m["id"])))

        def chip(u, label, on, color):
            return ("<a href='%s' style='display:inline-block;margin:2px 6px 2px 0;"
                    "padding:3px 10px;border:1px solid %s;border-radius:14px;"
                    "background:%s'>%s</a>"
                    % (u, color if on else "#2a3140", color.replace("#", "#1b") if on else "transparent",
                       esc(label)))

        def lvl_badge(m):
            note = m.get("repro_note") or ""
            for k, lab, col in (("原文级", "原文级", "#2f6b45"),
                                ("站内摘要级", "站内摘要", "#2b4a6f"),
                                ("arXiv 摘要级", "arXiv 摘要", "#2b4a6f"),
                                ("标题级", "标题级", "#6b2f2f")):
                if k in note:
                    return ("<span class='tag' style='background:%s;color:#fff'>%s</span>"
                            % (col, esc(lab)))
            return "<span class='tag'>摘要级</span>"

        def layer_badge(m):
            LT = {"planner": "P", "validator": "V", "isolator": "I"}
            ls = [LT.get(x, "?") for x in (m.get("drift_layer") or [])]
            if not ls:
                return ""
            return ("<span class='tag' style='background:#1b3a5c;color:#cfe4ff'>打 DRIFT "
                    + "/".join(ls) + "</span>")

        h = ["<h1>记忆投毒 · mem0 / OpenViking</h1>",
             "<div class='meta'>调研口径：<b>只取 aisafetyhot 站内条目</b>（每条原链指向 "
             "/zh/items/&lt;slug&gt; 详情页，非 arXiv 链接），核验级别=站内摘要级。"
             "分类按「对我们两个已接入后端（mem0 原样写入 / OpenViking viking:// 文档）"
             "的可复现性」组织：<b>攻击方法</b> = 怎么投进去并激活；"
             "<b>评测与基准</b> = 怎么量；<b>防御方法</b> = 怎么挡；"
             "<b>系统与撤回</b> = 后端整体行为与清理可信度。共 %d 条。</div>" % len(all_mm),
             "<div style='margin:12px 0 6px'>"
             + chip("/mem", "全部 (%d)" % len(all_mm), sub not in MEM_SUBS, "#8a6fd0")
             + "".join(chip("/mem?sub=" + k,
                            "%s (%d)" % (MEM_SUB_META[k][1], cnt[k]),
                            sub == k, MEM_SUB_META[k][0]) for k in MEM_SUBS)
             + "</div>",
             "<div style='margin:0 0 10px'><span class='meta'>按 DRIFT 层筛选：</span>"
             + chip("/mem", "全部层", not layer, "#8a6fd0")
             + chip("/mem?layer=planner", "P 规划 (%d)" % cnt_layer["planner"],
                    layer == "planner", "#8a6fd0")
             + chip("/mem?layer=validator", "V 判定 (%d)" % cnt_layer["validator"],
                    layer == "validator", "#8a6fd0")
             + chip("/mem?layer=isolator", "I 隔离 (%d)" % cnt_layer["isolator"],
                    layer == "isolator", "#8a6fd0")
             + "</div>"]
        if not all_mm:
            h.append("<div class='meta'>还没有条目。</div>")
        cur = None
        for m in ms:
            s = sub_of(m)
            if s != cur:
                cur = s
                color, title, desc = MEM_SUB_META.get(s, ("#7a8598", s or "未分类", ""))
                n_this = sum(1 for x in all_mm if sub_of(x) == s)
                h.append("<h2 style='margin:20px 0 4px;font-size:15px'>"
                         "<span style='display:inline-block;width:8px;height:8px;border-radius:50%%;"
                         "background:%s;margin-right:8px'></span>%s (%d)</h2>"
                         "<div class='meta' style='margin:0 0 8px'>%s</div>"
                         % (color, esc(title), n_this, esc(desc)))
            why = ""
            for line in (m.get("why") or "").split("\n"):
                if line.strip():
                    why = line.strip()
                    break
            if len(why) > 190:
                why = why[:190] + "…"
            h.append(
                "<div style='padding:9px 0;border-bottom:1px solid #1e242f'>"
                "<div><span class='tag' style='background:#2a3140'>%s</span>&nbsp;"
                "<a href='%s' target='_blank' style='font-weight:600'>%s</a>"
                "&nbsp;<span class='meta'>%s</span></div>"
                "<div style='margin-top:3px'>%s %s</div>"
                "<div class='meta' style='margin-top:3px'>%s</div></div>"
                % (esc(m["id"]), esc(m["url"]), esc(m["name"]), esc(m.get("src", "")),
                   lvl_badge(m), layer_badge(m), esc(why)))
        if ms:
            h.append("<div class='meta' style='margin-top:14px'>共 %d 条（当前筛选）。"
                     "⚠️ 站内检索不到任何 OpenViking 专门的投毒研究："
                     "源内 mem0/通用记忆投毒方法可迁移到 viking:// 文档型记忆，但需自查复现。</div>"
                     % len(ms))
        return self.page("记忆投毒（mem0 / OpenViking）", self.nav("/mem") + "".join(h))

    # ---------- 意图识别分类 ----------
    def view_ir(self, sub=None, layer=None):
        data = load_data()
        st = load_state()
        sr = load_status()
        sel = st["selected"]
        items = sr["items"]
        all_ir = [m for m in data["methods"] if cat_of(m) == CAT_IR]
        view = None
        if sub == "chain":
            view = "chain"
        LAYERS = [("P", "planner", "Secure Planner"), ("V", "validator", "Dynamic Validator"),
                  ("I", "isolator", "Injection Isolator")]
        LK = {tag: key for tag, key, _n in LAYERS}
        if layer and layer not in LK:
            layer = None
        if sub in ("benchmark", "benchmark-other", "attack"):
            ms = [m for m in all_ir if sub_of(m) == sub]
        else:
            ms = list(all_ir)
        if layer and sub == "chain":
            ms = [m for m in ms if LK[layer] in (m.get("drift_layer") or [])]
        ms.sort(key=lambda m: (cat_order(m), sid(m["id"])))
        n_b = sum(1 for m in all_ir if sub_of(m) == "benchmark")
        n_o = sum(1 for m in all_ir if sub_of(m) == "benchmark-other")
        n_a = sum(1 for m in all_ir if sub_of(m) == "attack")

        def chip(u, label, on):
            return ("<a href='%s' style='display:inline-block;margin:2px 6px 2px 0;"
                    "padding:3px 10px;border:1px solid %s;border-radius:14px;"
                    "background:%s'>%s</a>"
                    % (u, "#6cb6ff" if on else "#2a3140",
                       "#1b3a5c" if on else "transparent", esc(label)))

        h = ["<h1>意图识别 · 分类面板</h1>",
             "<div class='meta'>benchmark 按「有没有攻击者」分成两桶："
             "<b>benchmark·攻击/红队</b> = 定义了攻击者或对抗行为（注入/投毒/越狱/协议伪造/监控规避），并度量攻击是否让 agent 越界；"
             "<b>benchmark·其它</b> = 没有攻击者的对齐、漂移测量、指标、框架与防御评测（如 Drift-Bench++、IntentFlux）。"
             "<b>attack</b> = 绕过意图识别的攻击方法。"
             "共 %d 条（攻击 benchmark %d / 其它 benchmark %d / attack %d）。"
             "老方法 M1–M55 仍在「总方法」里，本页只增不改。</div>" % (len(all_ir), n_b, n_o, n_a),
             "<div style='margin:12px 0 6px'>"
             + chip("/ir", "全部 (%d)" % len(all_ir), sub is None)
             + chip("/ir?sub=benchmark", "benchmark·攻击/红队 (%d)" % n_b, sub == "benchmark")
             + chip("/ir?sub=benchmark-other", "benchmark·其它 (%d)" % n_o, sub == "benchmark-other")
             + chip("/ir?sub=attack", "attack (%d)" % n_a, sub == "attack")
             + chip("/ir?view=chain", "攻击链视图", sub == "chain")
             + "</div>"]
        if view == "chain":
            chain_base = [m for m in ms if sub_of(m) == "attack"]
            axes = [("time", "时间轴"), ("cross", "跨体 / 委派"), ("carrier", "载体改写"),
                    ("binding", "绑定错配"), ("judge", "判官本体"), ("monitor", "监控器侧"),
                    ("approval", "审批 / 授权"), ("revocation", "隐蔽承载 / 撤销")]
            h.append("<div class='meta' style='margin-bottom:6px'>DRIFT 层标记："
                     "<b>[P]</b> Secure Planner（计划/参数）&nbsp; "
                     "<b>[V]</b> Dynamic Validator（偏离/权限/监控）&nbsp; "
                     "<b>[I]</b> Injection Isolator（屏蔽冲突指令）</div>")
            _atk_all = [m for m in all_ir if sub_of(m) == "attack"]
            _lc = {tag: sum(1 for m in _atk_all if key in (m.get("drift_layer") or []))
                   for tag, key, _n in LAYERS}
            h.append("<div style='margin:2px 0 8px'>按层筛选："
                     + chip("/ir?view=chain", "全部 (%d)" % len(_atk_all), layer is None)
                     + "".join(chip("/ir?view=chain&layer=%s" % tag,
                                    "[%s] %s (%d)" % (tag, _n, _lc[tag]), layer == tag)
                               for tag, _k, _n in LAYERS)
                     + "</div>")
            if layer:
                h.append("<div class='meta'>当前只看 <b>[%s] %s</b>：%d 条。</div>"
                         % (layer, dict((t, n) for t, _k, n in LAYERS)[layer], len(chain_base)))
            h.append("<div class='meta'>把 %d 条攻击按「攻击者利用的错位类型」重新分组："
                     "同一轴的条目共享同一个判定盲区，可对照 DRIFT 三层的假设缺口。</div>"
                     % len(chain_base))
            SUBKIND = [("text", "文本改写"), ("nontext", "非文本载体"), ("metadata", "元数据")]
            for key, title in axes:
                gms = [m for m in chain_base if key in (m.get("axis") or [])]
                if not gms:
                    continue
                gms.sort(key=cat_order)
                h.append("<div class='grp'>%s &nbsp;· %d 条</div>" % (title, len(gms)))
                if key == "carrier":
                    for kk, ktitle in SUBKIND:
                        ks = [m for m in gms if m.get("carrier_kind") == kk]
                        if not ks:
                            continue
                        h.append("<div class='meta' style='margin:2px 0 2px 8px'>· %s（%d）</div>"
                                 % (ktitle, len(ks)))
                        rows = ["<li><a href='/ir?sub=attack'>%s</a> %s %s</li>"
                                % (esc(m["id"]), esc(m["name"][:70]), _ltag(m)) for m in ks]
                        h.append("<ul style='margin:2px 0 10px 30px;line-height:1.75'>%s</ul>"
                                 % "".join(rows))
                    continue
                rows = []
                for m in gms:
                    rows.append("<li><a href='/ir?sub=attack'>%s</a> %s %s</li>"
                                % (esc(m["id"]), esc(m["name"][:70]), _ltag(m)))
                h.append("<ul style='margin:4px 0 16px 18px;line-height:1.8'>%s</ul>"
                         % "".join(rows))
            return self.page("攻击链视图", self.nav() + "".join(h))
        groups = [("benchmark", "意图识别 · benchmark（攻击/红队：有攻击者，度量攻击是否让 agent 越界）"),
                  ("benchmark-other", "意图识别 · benchmark（其它：对齐/漂移测量/指标/框架/防御评测，无攻击者）"),
                  ("attack", "意图识别 · attack 方法（绕过意图识别）")]
        for g, title in groups:
            gms = [m for m in ms if sub_of(m) == g]
            if not gms:
                continue
            h.append("<div class='grp'>%s &nbsp;· %d 条</div>" % (title, len(gms)))
            for m in gms:
                h.append(self.card(m, sel, items))
        if not ms:
            h.append("<div class='imp'>没有匹配的条目。</div>")
        return self.page("意图识别 · 研究面板", self.nav() + "".join(h))

    # ---------- 实现区 ----------
    def view_active(self):
        data = load_data()
        st = load_state()
        sr = load_status()
        sel = set(st["selected"])
        items = sr["items"]
        ms = data["methods"]

        act = [m for m in ms if st_of(m["id"], items) in ("doing", "done")]
        act.sort(key=lambda m: (STATUS_META[st_of(m["id"], items)][2], sid(m["id"])))
        skipped = [m for m in ms if st_of(m["id"], items) == "abandoned"]

        h = ["<h1>实现区</h1>",
             "<div class='sub'>只放<b>已经被实现或正在实现</b>的方法。"
             "总清单（%d 条）里未上线的不会出现在这里，避免重复审计。</div>" % len(ms),
             "<div class='grid'>"
             "<div class='box'><div class='n'>%d</div><div class='l'>已实现</div></div>"
             "<div class='box'><div class='n'>%d</div><div class='l'>实现中</div></div>"
             "<div class='box'><div class='n'>%d</div><div class='l'>已放弃</div></div>"
             "<div class='box'><div class='n'>%s</div><div class='l'>最后更新</div></div>"
             "</div>" % (
                 sum(1 for m in ms if st_of(m["id"], items) == "done"),
                 sum(1 for m in ms if st_of(m["id"], items) == "doing"),
                 len(skipped), esc(sr.get("updated") or "-"))]

        if not act:
            h.append("<div class='imp'>实现区还是空的。"
                     "做法：在<b><a href='/'>总方法</a></b>里把某条的状态改成"
                     "「实现中」或「已实现」，它就会自动出现在这里。</div>")
        else:
            doing = [m for m in act if st_of(m["id"], items) == "doing"]
            done = [m for m in act if st_of(m["id"], items) == "done"]
            if doing:
                h.append("<div class='grp'>实现中（%d）</div>" % len(doing))
                for m in doing:
                    h.append(self.card(m, sel, items))
            if done:
                h.append("<div class='grp'>已实现（%d）</div>" % len(done))
                for m in done:
                    h.append(self.card(m, sel, items))
        if skipped:
            h.append("<div class='grp'>已放弃（%d）</div>" % len(skipped))
            for m in skipped:
                h.append(self.card(m, sel, items))
        return self.page("实现区", self.nav("/active") + "".join(h))

    # ---------- 详情 ----------
    def view_method(self, mid):
        data = load_data()
        st = load_state()
        sr = load_status()
        m = next((x for x in data["methods"] if x["id"] == mid), None)
        if not m:
            return self.page("未找到", self.nav() + "<h1>未找到 %s</h1>" % esc(mid))
        is_sel = mid in st["selected"]
        status = st_of(mid, sr["items"])
        h = ["<div class='nav'><a href='/'>← 总方法</a> &nbsp;·&nbsp; "
             "<a href='/active'>实现区</a></div>",
             "<h1>%s · %s <span class='stars'>%s</span></h1>"
             % (esc(m["id"]), esc(m["name"]), "★" * m["stars"] + "☆" * (5 - m["stars"])),
             "<div class='meta'>%s &nbsp;·&nbsp; <a href='%s' target='_blank'>原文 →</a>"
             " &nbsp;·&nbsp; %s</div>" % (esc(m.get("src") or ""), m["url"], st_badge(status)),
             "<div class='sec'><b>机制</b><ul>%s</ul></div>"
             % "".join("<li>%s</li>" % esc(x) for x in m.get("mech") or []),
             "<div class='sec'><b>为什么值得看</b><div>%s</div></div>" % esc(m["why"]),
             "<div class='sec'><b>对我们的可复现性</b><div>%s</div></div>" % esc(m.get("repro_note", "")),
             "<div class='sec'><b>我们的改造版</b><pre>%s</pre></div>" % esc(m.get("variant") or ""),
             "<div class='sec'><b>映射到你的高危目标</b><div>%s</div></div>"
             % "".join("<span class='tag g'>%s</span>" % esc(t) for t in m.get("goal_map") or []),
             "<form method='post' action='/toggle'><input type='hidden' name='id' value='%s'>"
             "<button type='submit' class='%s'>%s</button></form>"
             % (esc(mid), "on" if is_sel else "", "✓ 已勾选（点取消）" if is_sel else "勾选这条")]
        if m.get("prereq"):
            h.append("<div class='sec'><b>前置条件</b><ul>%s</ul></div>"
                     % "".join("<li>%s</li>" % esc(x) for x in m.get("prereq") or []))
        _sn = (sr["items"].get(mid) or {}).get("snote", "").strip()
        if _sn:
            h.append("<div class='sec'><b>实现记录（我的实测）</b><div class='snotebox'>%s</div></div>" % esc(_sn))
        return self.page(m["name"], self.nav() + "".join(h))


    # ---------- 测试轮次 ----------
    ROUND_DIR = r"C:/dsh_work/composkill_test/research"

    def view_rounds(self):
        import glob
        fs = sorted([x for x in glob.glob(self.ROUND_DIR + "/*.txt") if "ROUND-" in os.path.basename(x) or "归因" in os.path.basename(x)])
        h = ["<div class='nav'><a href='/'>← 总方法</a></div>",
             "<h1>测试轮次</h1>",
             "<div class='meta'>共 %d 轮 · 每轮含 攻击构造 / agent 响应 / Tier 0 证据 / 失败归因</div>" % len(fs)]
        if not fs:
            h.append("<div class='sec'>还没有轮次记录。</div>")
        for f in reversed(fs):
            name = f.rsplit("/", 1)[-1]
            body = io.open(f, encoding="utf-8", errors="replace").read()
            first = ""
            for ln in body.splitlines():
                if ln.strip() and not ln.startswith("#"):
                    first = ln.strip()[:220]; break
            h.append("<div class='sec'><details><summary><b>%s</b> &nbsp;"
                     "<span class='meta'>%s</span></summary><pre>%s</pre></details></div>"
                     % (esc(name), esc(first), esc(body)))
        return self.page("测试轮次", self.nav() + "".join(h))

    # ---------- 导出 ----------
    def view_export(self):
        data = load_data()
        st = load_state()
        sr = load_status()
        sel = set(st["selected"])
        items = sr["items"]
        picked = sorted([m for m in data["methods"] if m["id"] in sel],
                        key=lambda m: sid(m["id"]))
        L = ["攻击方法勾选清单",
             "导出时间: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             "勾选 %d / %d 条" % (len(picked), len(data["methods"])), ""]
        L.append("── 已勾选（按 id）──")
        for m in picked:
            L.append("  [%s] %s" % (m["id"], m["name"]))
            L.append("        实现状态 %s · 优先 %d · 可复现性 %s"
                     % (STATUS_META[st_of(m["id"], items)][0], m["priority"], m.get("repro") or ""))
            L.append("        出处 %s" % m.get("src") or "")
            it = items.get(m["id"], {})
            if it.get("note"):
                L.append("        实现记录：%s" % it["note"].replace("\n", " "))
            if st["notes"].get(m["id"]):
                L.append("        我的批注：%s" % st["notes"][m["id"]].replace("\n", " "))
        L.append("")
        L.append("── 实现区 ──")
        for m in sorted([x for x in data["methods"]
                         if st_of(x["id"], items) in ("doing", "done")],
                        key=lambda x: (STATUS_META[st_of(x["id"], items)][2], sid(x["id"]))):
            L.append("  [%s] %s — %s" % (m["id"], STATUS_META[st_of(m["id"], items)][0],
                                         m["name"]))
        L.append("")
        L.append("── 未勾选 ──")
        for m in sorted(data["methods"], key=lambda x: sid(x["id"])):
            if m["id"] not in sel:
                L.append("  [%s] %s" % (m["id"], m["name"]))
        txt = "\n".join(L)
        h = ["<h1>导出清单</h1>",
             "<div class='sub'>直接全选复制即可。也可让我读 <span class='mono'>%s</span>。</div>"
             % esc(STATE),
             "<pre>%s</pre>" % esc(txt)]
        return self.page("导出清单", self.nav("/export") + "".join(h))


class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    print("研究面板 v2 监听 0.0.0.0:%d" % PORT, flush=True)
    TS(("0.0.0.0", PORT), H).serve_forever()
