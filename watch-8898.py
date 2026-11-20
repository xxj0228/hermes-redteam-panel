#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""8898 研究面板看护：端口不通就拉起 dsh-research-panel.py。

用法（脱离当前进程）：
  Start-Process python -ArgumentList '...watch-8898.py' -WindowStyle Hidden
日志：同目录 watch-8898.log
"""
import socket
import subprocess
import sys
import time
import datetime

PY = r"C:\Users\xuxijian\AppData\Local\Programs\Python\Python312\python.exe"
PANEL = r"C:\dsh_work\composkill_test\_panel-win\dsh-research-panel.py"
LOG = r"C:\dsh_work\composkill_test\_panel-win\watch-8898.log"
PORT = 8898
INTERVAL = 20


def alive():
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect(("127.0.0.1", PORT))
        return True
    except Exception:
        return False
    finally:
        s.close()


def log(msg):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("%s %s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg))


def main():
    log("watchdog start (interval=%ds)" % INTERVAL)
    while True:
        if not alive():
            log("port %d down -> spawn panel" % PORT)
            try:
                subprocess.Popen([PY, PANEL],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            except Exception as e:
                log("spawn failed: %r" % (e,))
            time.sleep(6)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
