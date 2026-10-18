#!/usr/bin/env python3
"""
Stealth scorer for the Cowrie flag-hunt challenge.

Reads the challenge instance's cowrie.json and grades each player (source IP)
by how cleanly they captured the flags:

    stealth score = flag points - detection points

Usage:
    python3 score.py                     # leaderboard, ranked by stealth score
    python3 score.py --ip 1.2.3.4        # detailed report for one player
    python3 score.py --save leaderboard.md
    python3 score.py --logfile /path/to/cowrie.json

Flag/canary paths here MUST match augment_fs.py. Stdlib only.
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime

# flags: name -> points + path substrings that reveal it (in command.input)
FLAGS = {
    "flag1": {"points": 10, "paths": [], "via_login": True},
    "flag2": {"points": 20, "paths": ["flag2.txt"], "via_login": False},
    "flag3": {"points": 30, "paths": ["flag3.txt", "/root/flag3"], "via_login": False},
    "flag4": {"points": 40, "paths": ["flag4.txt", ".canary/flag4"], "via_login": False},
}

# honeytokens: label -> path substrings that count as DETECTED when touched
CANARIES = {
    "id_rsa": ["id_rsa"],
    "wallet_seed": ["seed.txt", ".wallet"],
    "aws_credentials": [".aws/credentials", "aws_access_key"],
    "deploy_config": ["deploy/config.ini"],
    "webapp_config": ["config.php"],
    # flag4 lives in the ".canary" dir: reading it captures the flag but is loud.
    "canary_flag4": [".canary/flag4", "flag4.txt"],
}

NOISY_CMDS = ("wget", "curl", "scp", "ftp ", "nc ", "ncat")
DESTRUCTIVE = ("rm ", "mv ", "dd ", "mkfs", "shutdown", "reboot", "halt", "useradd",
               "usermod", "chmod", "chown", "kill ")

CANARY_COST = 10
NOISY_COST = 5
FAILED_LOGIN_COST = 1


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
    try:
        return datetime.fromisoformat(e.get("timestamp", "").replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def grade(events):
    """events: list of events for one IP. Returns (captured, detections, noise)."""
    captured = set()
    detections = []  # (cost, label, detail)
    noise = 0

    for e in events:
        eid = e.get("eventid")
        if eid == "cowrie.login.success":
            for name, f in FLAGS.items():
                if f["via_login"] and name not in captured:
                    captured.add(name)
        elif eid == "cowrie.login.failed":
            noise += FAILED_LOGIN_COST
            detections.append((FAILED_LOGIN_COST, "failed_login",
                               f"{e.get('username')}:{e.get('password')}"))
        elif eid in ("cowrie.command.input", "cowrie.command.failed"):
            cmd = e.get("input", "")
            for name, f in FLAGS.items():
                if any(p in cmd for p in f["paths"]):
                    captured.add(name)
            for label, paths in CANARIES.items():
                if any(p in cmd for p in paths):
                    noise += CANARY_COST
                    detections.append((CANARY_COST, f"honeytoken:{label}", cmd.strip()))
            if any(cmd.startswith(n) for n in NOISY_CMDS):
                noise += NOISY_COST
                detections.append((NOISY_COST, "noisy", cmd.strip()))
            if any(d in cmd for d in DESTRUCTIVE):
                noise += NOISY_COST
                detections.append((NOISY_COST, "destructive", cmd.strip()))

    flag_points = sum(FLAGS[f]["points"] for f in captured)
    return captured, detections, noise, flag_points


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--logfile", default="/opt/challenge/var/log/cowrie/cowrie.json")
    ap.add_argument("--ip", help="detailed report for one source IP")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--save", help="also write the leaderboard to a file")
    args = ap.parse_args()

    events = load(args.logfile)
    if not events:
        print("No events found.")
        sys.exit(1)

    by_ip = defaultdict(list)
    for e in events:
        ip = e.get("src_ip", "?")
        by_ip[ip].append(e)

    results = {}
    for ip, evs in by_ip.items():
        captured, detections, noise, fp = grade(evs)
        results[ip] = {
            "captured": captured, "detections": detections,
            "noise": noise, "points": fp, "score": fp - noise,
        }

    if args.ip:
        r = results.get(args.ip)
        if not r:
            print(f"no events for {args.ip}")
            sys.exit(1)
        print(f"=== {args.ip} ===")
        print(f"flags captured: {sorted(r['captured'])}  (+{r['points']} pts)")
        print(f"detection events: {len(r['detections'])}  (-{r['noise']} pts)")
        print(f"stealth score: {r['score']}")
        print("timeline:")
        for e in sorted(by_ip[args.ip], key=lambda x: (ts(x) or datetime.min)):
            t = ts(e)
            tstr = t.strftime("%H:%M:%S") if t else "?"
            eid = e.get("eventid", "")
            if eid == "cowrie.login.success":
                print(f"  {tstr}  LOGIN {e.get('username')}:{e.get('password')}")
            elif eid == "cowrie.login.failed":
                print(f"  {tstr}  fail  {e.get('username')}:{e.get('password')}")
            elif eid in ("cowrie.command.input", "cowrie.command.failed"):
                print(f"  {tstr}  $ {e.get('input','').strip()}")
        return

    ranked = sorted(results.items(), key=lambda kv: -kv[1]["score"])
    print("=== FLAG HUNT LEADERBOARD (stealth score = flags - detections) ===")
    print(f"{'rank':<5}{'score':<7}{'flags':<12}{'noise':<7}ip")
    for i, (ip, r) in enumerate(ranked[: args.top], 1):
        flags = ",".join(sorted(r["captured"])) or "-"
        print(f"{i:<5}{r['score']:<7}{flags:<12}{r['noise']:<7}{ip}")

    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            f.write("# Flag Hunt Leaderboard\n\n")
            f.write("| rank | score | flags | noise | ip |\n|---|---|---|---|---|\n")
            for i, (ip, r) in enumerate(ranked, 1):
                flags = ",".join(sorted(r["captured"])) or "-"
                f.write(f"| {i} | {r['score']} | {flags} | {r['noise']} | {ip} |\n")
        print(f"\nleaderboard written to {args.save}")


if __name__ == "__main__":
    main()
