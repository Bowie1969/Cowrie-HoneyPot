"""Extract entities from a Cowrie JSON log.

Entities (deduplicated, with provenance):
    sessions   {session_id, src_ip, start, end, duration, client, commands[], downloads[], uploads[]}
    ips        {ip, first_seen, last_seen, events, success_logins, commands_run, downloads}
    urls       {url, downloaded_by[], sha256[], first_seen}
    hashes     {sha256, outfile, url, size, downloaded_by[]}
    creds      {username:password, successes, failures}
"""
import collections
import json
import re
from datetime import datetime


SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b")


def _ts(e):
    t = e.get("timestamp")
    if not t:
        return None
    try:
        return datetime.fromisoformat(t.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _iso(dt):
    return dt.isoformat() if dt else None


def load_events(path):
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def extract(events):
    sessions = {}
    ips = collections.defaultdict(lambda: {
        "ip": None, "first_seen": None, "last_seen": None, "events": 0,
        "success_logins": 0, "login_failures": 0, "commands_run": 0,
        "downloads": 0, "client_versions": set(), "sessions": set(),
    })
    urls = {}
    hashes = {}
    creds = collections.defaultdict(lambda: {"successes": 0, "failures": 0})

    for e in events:
        ip = e.get("src_ip")
        eid = e.get("eventid") or ""
        t = _ts(e)
        sid = e.get("session")

        if ip:
            rec = ips[ip]
            rec["ip"] = ip
            rec["events"] += 1
            if t:
                if not rec["first_seen"] or t < rec["first_seen"]:
                    rec["first_seen"] = t
                if not rec["last_seen"] or t > rec["last_seen"]:
                    rec["last_seen"] = t
            if sid:
                rec["sessions"].add(sid)

        if sid and sid not in sessions:
            sessions[sid] = {
                "session_id": sid, "src_ip": ip, "start": None, "end": None,
                "duration": None, "client": None,
                "commands": [], "downloads": [], "uploads": [],
                "login_success": None,
            }
        s = sessions.get(sid)

        if eid == "cowrie.session.connect" and s:
            s["start"] = _iso(t)
        elif eid == "cowrie.client.version" and s:
            s["client"] = e.get("version")
            if ip:
                ips[ip]["client_versions"].add(e.get("version", ""))
        elif eid == "cowrie.login.success":
            key = f"{e.get('username')}:{e.get('password')}"
            creds[key]["successes"] += 1
            if ip:
                ips[ip]["success_logins"] += 1
            if s:
                s["login_success"] = key
        elif eid == "cowrie.login.failed":
            key = f"{e.get('username')}:{e.get('password')}"
            creds[key]["failures"] += 1
            if ip:
                ips[ip]["login_failures"] += 1
        elif eid in ("cowrie.command.input", "cowrie.command.failed"):
            cmd = (e.get("input") or "").strip()
            if ip:
                ips[ip]["commands_run"] += 1
            if s:
                s["commands"].append({
                    "ts": _iso(t), "cmd": cmd,
                    "failed": eid == "cowrie.command.failed",
                })
        elif eid == "cowrie.session.file_download":
            url = e.get("url") or ""
            sha = e.get("shasum") or ""
            outfile = e.get("outfile") or ""
            size = e.get("size")
            if ip:
                ips[ip]["downloads"] += 1
            if url:
                u = urls.setdefault(url, {
                    "url": url, "downloaded_by": set(),
                    "sha256": set(), "first_seen": _iso(t),
                })
                if ip:
                    u["downloaded_by"].add(ip)
                if sha:
                    u["sha256"].add(sha)
            if sha:
                h = hashes.setdefault(sha, {
                    "sha256": sha, "outfile": outfile, "url": url,
                    "size": size, "downloaded_by": set(),
                    "first_seen": _iso(t),
                })
                if ip:
                    h["downloaded_by"].add(ip)
            if s:
                s["downloads"].append({
                    "ts": _iso(t), "url": url, "sha256": sha,
                    "outfile": outfile, "size": size,
                })
        elif eid == "cowrie.session.file_upload":
            if s:
                s["uploads"].append({
                    "ts": _iso(t),
                    "filename": e.get("filename") or e.get("outfile"),
                    "sha256": e.get("shasum"),
                })
        elif eid == "cowrie.session.closed" and s:
            s["end"] = _iso(t)
            s["duration"] = e.get("duration")

    # finalize sets -> sorted lists, timestamps -> ISO
    for rec in ips.values():
        rec["first_seen"] = _iso(rec["first_seen"])
        rec["last_seen"] = _iso(rec["last_seen"])
        rec["client_versions"] = sorted(x for x in rec["client_versions"] if x)
        rec["sessions"] = sorted(rec["sessions"])
    for u in urls.values():
        u["downloaded_by"] = sorted(u["downloaded_by"])
        u["sha256"] = sorted(u["sha256"])
    for h in hashes.values():
        h["downloaded_by"] = sorted(h["downloaded_by"])

    return {
        "sessions": list(sessions.values()),
        "ips": list(ips.values()),
        "urls": list(urls.values()),
        "hashes": list(hashes.values()),
        "creds": [
            {"cred": k, **v} for k, v in sorted(
                creds.items(), key=lambda kv: -(kv[1]["successes"] + kv[1]["failures"])
            )
        ],
    }


def extract_from_log(path):
    return extract(load_events(path))
