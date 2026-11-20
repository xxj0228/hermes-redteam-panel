#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试面板（Windows 本地，端口 18900）。

为什么在本地：原来在靶机 /dev/shm，靠 ssh -L 才能访问，隧道一断就看不到，
脚本重启就没。现在面板和它的数据都在 Windows，agent 的回复由每轮结束后的
scp 回传到这里，因此查看不再依赖任何隧道。

数据目录: C:\\dsh_work\\composkill_test\\_panel-win\\rounds
  <轮次>-task.txt         发给 agent 的任务原文
  <轮次>-agent-reply.txt  agent 的原始回复
  ROUND-<轮次>.txt        我写的完整记录（攻击构造 / Tier0 证据 / 归因）
  *归因*.txt              失败归因
"""
import http.server, socketserver, os, glob, html, urllib.parse, datetime

PORT = 18900
DIR = r"C:\dsh_work\composkill_test\_panel-win\rounds"
REFRESH_SEC = 5

esc = html.escape


def _read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        return "读取失败: %r" % (e,)


def collect():
    """把 rounds 目录按轮次前缀聚合成结构。"""
    rounds = {}
    for p in sorted(glob.glob(os.path.join(DIR, "*.txt"))):
        name = os.path.basename(p)
        # 轮次前缀：M13b / M13a / M10 ...
        key = None
        if name.startswith("ROUND-"):
            key = name[6:].split(".")[0]
        elif "-agent-reply" in name:
            key = name.split("-agent-reply")[0]
        elif "-task" in name:
            key = name.split("-task")[0]
        elif "归因" in name:
            key = name.split("-")[0]
        else:
            key = name.split("-")[0]
        r = rounds.setdefault(key, {"key": key, "files": [], "mtime": 0})
        r["files"].append((name, p))
        r["mtime"] = max(r["mtime"], os.path.getmtime(p))
    out = sorted(rounds.values(), key=lambda r: r["mtime"], reverse=True)
    for r in out:
        r["task"] = ""
        r["reply"] = ""
        r["record"] = ""
        r["attr"] = ""
        for name, p in r["files"]:
            body = _read(p)
            if name.endswith("-task.txt"):
                r["task"] = body
            elif "-agent-reply" in name:
                r["reply"] = body
            elif name.startswith("ROUND-"):
                r["record"] = body
            elif "归因" in name:
                r["attr"] = body
    return out


CSS = """
body{font:14px/1.7 -apple-system,'Segoe UI',system-ui,'Microsoft YaHei',sans-serif;
     margin:0;background:#0f1115;color:#e6e8eb}
.wrap{max-width:1180px;margin:0 auto;padding:20px}
a{color:#6cb6ff;text-decoration:none} a:hover{text-decoration:underline}
h1{font-size:19px;margin:0 0 4px}
.sub{color:#7d8794;font-size:12px;margin-bottom:16px}
.card{background:#171a21;border:1px solid #232833;border-radius:9px;padding:15px 16px;margin-bottom:13px}
.card.hit{border-left:4px solid #34d399}
.card.miss{border-left:4px solid #ef4444}
.card.unk{border-left:4px solid #6b7280}
h2{font-size:16px;margin:0 0 3px}
.meta{color:#7d8794;font-size:12px;margin-bottom:10px}
.sec{margin:10px 0}
.sec>b{color:#9aa4b2;font-size:12.5px;display:block;margin-bottom:4px}
pre{background:#12151b;border:1px solid #232833;border-radius:6px;padding:10px;
    overflow-x:auto;white-space:pre-wrap;word-break:break-word;margin:0;
    font-family:ui-monospace,Consolas,monospace;font-size:12.5px;line-height:1.6}
.tag{display:inline-block;padding:1px 8px;border-radius:4px;font-size:11px;
     font-family:ui-monospace,monospace;margin-left:6px}
.t-hit{background:#173d2c;color:#8ee0b0} .t-miss{background:#5f1e2e;color:#ee9daa}
.t-unk{background:#2a2f38;color:#aab3bf}
details{margin:6px 0} summary{cursor:pointer;color:#9aa4b2;font-size:13px}
.nav{margin-bottom:14px;font-size:13px}
"""


def verdict(r):
    blob = (r["record"] + r["attr"]).lower()
    if "命中" in blob or "tier 0" in blob or "hit:" in blob:
        # 只有明确写了命中才算
        if "未命中" in blob or "miss" in blob:
            return ("miss", "MISS")
        return ("hit", "HIT")
    if "归因" in blob or "失败" in blob:
        return ("miss", "MISS")
    return ("unk", "未判定")


def page(title, body):
    return ("<!doctype html><html lang='zh'><head><meta charset='utf-8'>"
            "<title>%s</title><style>%s</style></head><body><div class='wrap'>%s"
            "</div></body></html>" % (esc(title), CSS, body)).encode("utf-8")


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p = u.path
        rows = collect()
        nav = "<div class='nav'><a href='/'>测试面板</a> &nbsp;·&nbsp; " \
              "<a href='/reflection'>为什么别人的攻击能成功（反思）</a> &nbsp;·&nbsp; " \
              "<a href='http://127.0.0.1:8898/rounds'>研究面板的轮次</a> &nbsp;·&nbsp; " \
              "<a href='http://127.0.0.1:8898/'>研究面板</a></div>"

        if p == "/":
            h = [nav,
                 "<h1>测试面板 · 每轮实测</h1>",
                 "<div class='sub'>共 %d 轮 · 数据来自每轮回传的任务原文 / agent 原始回复 / 我的记录 · "
                 "目录 %s</div>" % (len(rows), esc(DIR))]
            if not rows:
                h.append("<div class='card'>还没有轮次记录。</div>")
            for r in rows:
                cls, label = verdict(r)
                h.append("<div class='card %s'>" % cls)
                h.append("<h2><a href='/round/%s'>%s</a> <span class='tag t-%s'>%s</span></h2>"
                         % (urllib.parse.quote(r["key"]), esc(r["key"]), cls, label))
                mt = datetime.datetime.fromtimestamp(r["mtime"]).strftime("%Y-%m-%d %H:%M")
                h.append("<div class='meta'>%s · 文件 %d 个</div>" % (mt, len(r["files"])))
                if r["task"]:
                    h.append("<div class='sec'><b>发给 agent 的任务</b><details><summary>展开</summary>"
                             "<pre>%s</pre></details></div>" % esc(r["task"]))
                if r["reply"]:
                    h.append("<div class='sec'><b>agent 原始回复</b><pre>%s</pre></div>" % esc(r["reply"]))
                if r["record"]:
                    h.append("<div class='sec'><b>我的完整记录</b><details><summary>展开</summary>"
                             "<pre>%s</pre></details></div>" % esc(r["record"]))
                if r["attr"]:
                    h.append("<div class='sec'><b>失败归因</b><details><summary>展开</summary>"
                             "<pre>%s</pre></details></div>" % esc(r["attr"]))
                h.append("</div>")
            self._send(200, page("测试面板", "".join(h)))
            return

        if p.startswith("/round/"):
            key = urllib.parse.unquote(p[7:])
            r = next((x for x in rows if x["key"] == key), None)
            if not r:
                self._send(404, page("404", nav + "<h1>未找到 %s</h1>" % esc(key)))
                return
            h = [nav, "<h1>%s</h1>" % esc(key)]
            for label, body in (("任务原文", r["task"]), ("agent 原始回复", r["reply"]),
                                ("完整记录", r["record"]), ("失败归因", r["attr"])):
                if body:
                    h.append("<div class='sec'><b>%s</b><pre>%s</pre></div>" % (label, esc(body)))
            self._send(200, page(key, "".join(h)))
            return

        if p == "/reflection" or p.startswith("/doc/"):
            if p == "/reflection":
                fn = "REFLECTION-why-others-succeed.md"
            else:
                fn = os.path.basename(urllib.parse.unquote(p[5:]))
            fp = os.path.join(DIR, fn)
            if not os.path.isfile(fp):
                self._send(404, page("404", nav + "<h1>未找到 %s</h1>" % esc(fn)))
                return
            body = _read(fp)
            h = [nav, "<h1>%s</h1>" % esc(fn),
                 "<div class='sec'><pre>%s</pre></div>" % esc(body)]
            self._send(200, page(fn, "".join(h)))
            return

        if p == "/health":
            self._send(200, ("ok %d rounds" % len(rows)).encode())
            return

        self._send(404, page("404", nav + "<h1>404</h1>"))


if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", PORT), H) as s:
        print("test panel on :%d" % PORT)
        s.serve_forever()
