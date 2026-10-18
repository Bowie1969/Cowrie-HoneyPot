#!/usr/bin/env python3
"""
Parse a Cowrie honeypot JSON log into a concise threat report.

Usage:
    python3 analyze.py [cowrie.json] [--top N] [--whois]

Default log path: /opt/cowrie/var/log/cowrie/cowrie.json (on the droplet), or a
local copy you've scp'd down.

Stdlib only. `--whois` shells out to the `whois` binary for org/country of each
unique source IP (optional enrichment).
"""
import argparse
import collections
import json
import subprocess
import sys
from datetime import datetime


def load(path):
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def ts(e):
    t = e.get("timestamp")
    if t:
        try:
            return datetime.fromisoformat(t.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
    return None


def fmt(ip_events):
    """ip_events: list of events for one IP, sorted by time."""
    out = []
    for e in ip_events:
        eid = e.get("eventid", "?")
        t = ts(e)
        tstr = t.strftime("%m-%d %H:%M:%S") if t else "?" * 14
        if eid == "cowrie.login.success":
            out.append(f"    {tstr}  LOGIN OK   {e.get('username')}:{e.get('password')}")
        elif eid == "cowrie.login.failed":
            out.append(f"    {tstr}  login fail {e.get('username')}:{e.get('password')}")
        elif eid == "cowrie.command.input":
            out.append(f"    {tstr}  $ {e.get('input','').strip()}")
        elif eid == "cowrie.command.failed":
            out.append(f"    {tstr}  ! {e.get('input','').strip()} (failed)")
        elif eid == "cowrie.session.file_download":
            out.append(f"    {tstr}  >> download {e.get('url')}")
        elif eid == "cowrie.session.file_upload":
            out.append(f"    {tstr}  << upload {e.get('outfile') or e.get('filename')}")
        elif eid == "cowrie.client.version":
            out.append(f"    {tstr}  client: {e.get('version')}")
        elif eid == "cowrie.session.closed":
            out.append(f"    {tstr}  session closed ({e.get('duration','?')}s)")
    return out


def whois(ip):
    try:
        r = subprocess.run(
            ["whois", ip], capture_output=True, text=True, timeout=20
        )
        hits = []
        for line in r.stdout.splitlines():
            low = line.lower()
            if any(k in low for k in ("country", "netname", "orgname", "descr", "abuse", "netrange", "cidr")):
                hits.append(line.strip())
        return hits[:6]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logfile", nargs="?", default="/opt/cowrie/var/log/cowrie/cowrie.json")
    ap.add_argument("--top", type=int, default=10, help="max IPs / rows to show (default 10)")
    ap.add_argument("--whois", action="store_true", help="whois each unique source IP")
    args = ap.parse_args()

    events = load(args.logfile)
    if not events:
        print("No events found.")
        sys.exit(1)

    srcs = collections.Counter()
    creds = collections.Counter()
    logins = collections.Counter()
    commands = collections.Counter()
    downloads = collections.Counter()
    by_ip = collections.defaultdict(list)

    for e in events:
        ip = e.get("src_ip", "?")
        eid = e.get("eventid")
        srcs[ip] += 1
        by_ip[ip].append(e)
        if eid == "cowrie.login.failed":
            creds[f"{e.get('username')}:{e.get('password')}"] += 1
        elif eid == "cowrie.login.success":
            logins[f"{e.get('username')}:{e.get('password')}"] += 1
        elif eid in ("cowrie.command.input", "cowrie.command.failed"):
            commands[e.get("input", "").strip()] += 1
        elif eid == "cowrie.session.file_download":
            downloads[e.get("url", "")] += 1

    # sort per-IP event lists by time
    for ip in by_ip:
        by_ip[ip].sort(key=lambda e: (ts(e) or datetime.min))

    print("=" * 72)
    print("COWRIE HONEYPOT REPORT")
    print("=" * 72)
    print(f"events: {len(events)}   unique source IPs: {len(srcs)}")
    print()

    if logins:
        print(f"-- successful logins ({len(logins)} unique creds) --")
        for cred, n in logins.most_common(args.top):
            print(f"  {n:>5}  {cred}")
        print()

    print(f"-- top source IPs by activity --")
    for ip, n in srcs.most_common(args.top):
        first = by_ip[ip][0]
        last = by_ip[ip][-1]
        span = ""
        if ts(first) and ts(last):
            span = f"  {ts(first):%m-%d %H:%M} -> {ts(last):%m-%d %H:%M}"
        print(f"  {n:>5}  {ip}{span}")
    print()

    if creds:
        print("-- top attempted credentials --")
        for cred, n in creds.most_common(args.top):
            print(f"  {n:>5}  {cred}")
        print()

    if commands:
        print("-- top commands run --")
        for cmd, n in commands.most_common(args.top):
            print(f"  {n:>5}  {cmd}")
        print()

    if downloads:
        print("-- download URLs (payload/C2 intel) --")
        for url, n in downloads.most_common(args.top):
            print(f"  {n:>5}  {url}")
        print()

    if args.whois:
        print("-- whois enrichment --")
        for ip, _ in srcs.most_common(args.top):
            print(f"\n  {ip}:")
            for line in whois(ip):
                print(f"      {line}")
        print()

    # Per-IP detail for the top offenders
    print("-- per-IP timelines (top offenders) --")
    for ip, _ in srcs.most_common(min(args.top, 5)):
        print(f"\n  {ip}:")
        for line in fmt(by_ip[ip]):
            print(line)


if __name__ == "__main__":
    main()
