#!/usr/bin/env python3
"""
Live tail of the Cowrie honeypot log, pretty-printed in color.

Streams events in real time and prints a running summary on exit.

Usage:
    python3 live.py                          # tail the droplet over SSH (default)
    python3 live.py --history 100            # show last 100 events, then follow
    python3 live.py --local cowrie.json      # tail a local copy instead of SSH
    python3 live.py --no-color               # plain text (for piping/logging)

Defaults target the deployed honeypot (134.199.170.29, admin SSH on 2200, key
~/.ssh/id_honeypot). Ctrl-C stops and prints the session summary.
"""
import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"


def c(text, code):
    return f"{code}{text}{RESET}"


def fmt_event(e, color):
    def c(text, code):
        return f"{code}{text}{RESET}" if color else text

    ts = e.get("timestamp", "")
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%H:%M:%S")
    except (ValueError, AttributeError):
        t = ts
    ip = e.get("src_ip", "?")
    eid = e.get("eventid", "")

    tag = eid.removeprefix("cowrie.").removeprefix("session.").replace(".", "/")
    if color:
        ip = c(ip, CYAN)

    if eid == "cowrie.session.connect":
        body = f"connect from {ip}:{e.get('src_port','?')} ({e.get('protocol','?')})"
        tag = c("CONN", CYAN)
    elif eid == "cowrie.login.success":
        body = f"{c('LOGIN OK', GREEN + BOLD)}  {e.get('username')}:{e.get('password')}  from {ip}"
        tag = ""
    elif eid == "cowrie.login.failed":
        body = f"login fail  {e.get('username')}:{e.get('password')}  from {ip}"
        tag = c("FAIL", RED)
    elif eid == "cowrie.command.input":
        body = c(f"$ {e.get('input','').strip()}", YELLOW)
        tag = ""
    elif eid == "cowrie.command.failed":
        body = c(f"! {e.get('input','').strip()}  (failed)", RED)
        tag = ""
    elif eid == "cowrie.session.file_download":
        body = c(f">> download  {e.get('url','')}", MAGENTA + BOLD)
        tag = ""
    elif eid == "cowrie.session.file_upload":
        body = c(f"<< upload    {e.get('outfile') or e.get('filename','')}", MAGENTA)
        tag = ""
    elif eid == "cowrie.client.version":
        body = f"client {e.get('version','')}"
        tag = c("SSH", DIM)
    elif eid == "cowrie.session.closed":
        body = f"closed ({e.get('duration','?')}s)"
        tag = c("CLOSED", DIM)
    else:
        body = e.get("message", "")[:80]

    if tag:
        return f"{c(t, DIM)}  {tag}  {body}"
    return f"{c(t, DIM)}  {body}"


def build_ssh_cmd(args):
    remote = f"tail -F -n {args.history} {args.logfile}"
    return [
        "ssh",
        "-i", args.key,
        "-p", str(args.admin_port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=30",
        f"{args.user}@{args.host}",
        remote,
    ]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="134.199.170.29")
    ap.add_argument("--admin-port", type=int, default=2200)
    ap.add_argument("--key", default=os.path.expanduser("~/.ssh/id_honeypot"))
    ap.add_argument("--user", default="root")
    ap.add_argument("--logfile", default="/opt/cowrie/var/log/cowrie/cowrie.json")
    ap.add_argument("--history", type=int, default=30, help="events of history to show first")
    ap.add_argument("--local", help="tail a local file instead of SSH")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    color = not args.no_color and sys.stdout.isatty()

    if args.local:
        cmd = ["tail", "-F", "-n", str(args.history), args.local]
    else:
        cmd = build_ssh_cmd(args)

    print(f"live monitor :: {'local' if args.local else f'{args.user}@{args.host}'} {args.logfile}")
    print("(Ctrl-C to stop)" + ("\n" if color else ""))

    counters = Counter()
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
    )

    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            counters["events"] += 1
            eid = e.get("eventid", "")
            counters[eid] += 1
            if e.get("src_ip"):
                counters["ips:" + e["src_ip"]] += 1
            print(fmt_event(e, color), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

    print("\n--- session summary ---")
    print(f"events: {counters['events']}")
    print(f"unique source IPs: {sum(1 for k in counters if k.startswith('ips:'))}")
    for eid in ("cowrie.login.failed", "cowrie.login.success", "cowrie.command.input",
                "cowrie.session.file_download", "cowrie.session.file_upload"):
        if counters[eid]:
            print(f"  {eid.removeprefix('cowrie.')}: {counters[eid]}")
    top_ips = sorted(
        ((k[4:], v) for k, v in counters.items() if k.startswith("ips:")),
        key=lambda kv: -kv[1],
    )[:5]
    if top_ips:
        print("top source IPs:")
        for ip, n in top_ips:
            print(f"  {n:>5}  {ip}")


if __name__ == "__main__":
    main()
