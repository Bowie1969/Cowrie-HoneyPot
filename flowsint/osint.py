"""OSINT enrichment for IPs, URLs, and file hashes.

All HTTP via stdlib urllib. Every source is optional — a missing key or a 403/429
degrades gracefully (returns a stub with the error noted) rather than failing the
whole pipeline. Results are cached to disk so re-runs don't burn API quota.

Sources:
    whois_asn    stdlib `whois` binary + Team Cymru DNS (origin ASN, no key)
    greynoise    GreyNoise Community API (no key for low volume)
    abuseipdb    AbuseIPDB /check (requires ABUSEIPDB_API_KEY)
    virustotal   VT v3 /ip_addresses, /urls, /files (requires VT_API_KEY)
    shodan       Shodan /shodan/host/{ip} (requires SHODAN_API_KEY)

Keys read from env vars; nothing in this module writes a key anywhere.
"""
import base64
import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


CACHE_DIR = ".flowsint-cache"
UA = "flowsint/0.1 (+honeypot-research)"
TIMEOUT = 25


# ----- cache ----------------------------------------------------------------


def _cache_path(bucket, key):
    os.makedirs(os.path.join(CACHE_DIR, bucket), exist_ok=True)
    safe = hashlib.sha1(key.encode("utf-8")).hexdigest()
    return os.path.join(CACHE_DIR, bucket, f"{safe}.json")


def _cache_get(bucket, key, max_age_sec=86400 * 7):
    p = _cache_path(bucket, key)
    if not os.path.exists(p):
        return None
    if time.time() - os.path.getmtime(p) > max_age_sec:
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _cache_put(bucket, key, value):
    p = _cache_path(bucket, key)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(value, f)


# ----- http -----------------------------------------------------------------


def _get(url, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}", "_detail": e.reason}
    except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
        return {"_error": "network", "_detail": str(e)}
    except (json.JSONDecodeError, ValueError) as e:
        return {"_error": "parse", "_detail": str(e)}


# ----- whois / ASN ----------------------------------------------------------


def _is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_reserved or a.is_unspecified)
    except ValueError:
        return False


def whois_asn(ip):
    """Combine the `whois` binary (netname/org/country) with a Cymru DNS ASN lookup."""
    cached = _cache_get("asn", ip)
    if cached is not None:
        return cached
    out = {"ip": ip, "asn": None, "asn_name": None, "country": None,
           "netname": None, "org": None, "abuse": None}
    if not _is_public(ip):
        out["_error"] = "non-public"
        _cache_put("asn", ip, out)
        return out

    # Team Cymru: reverse the IP, prepend to origin.asn.cymru.com, TXT lookup.
    try:
        rev = ".".join(reversed(ip.split(".")))
        import struct
        # minimal DNS TXT query via socket; falls back to `host` if available
        res = subprocess.run(
            ["host", "-t", "TXT", f"{rev}.origin.asn.cymru.com"],
            capture_output=True, text=True, timeout=10,
        )
        for line in res.stdout.splitlines():
            if "descriptive text" in line:
                txt = line.split("descriptive text", 1)[1].strip().strip('"')
                parts = [p.strip() for p in txt.split("|")]
                if len(parts) >= 3:
                    out["asn"] = parts[0]
                    out["country"] = parts[2]
                break
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    try:
        r = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=20)
        for line in r.stdout.splitlines():
            low = line.lower()
            v = line.split(":", 1)[1].strip() if ":" in line else ""
            if not v:
                continue
            if "netname" in low and not out["netname"]:
                out["netname"] = v
            elif "orgname" in low and not out["org"]:
                out["org"] = v
            elif "descr" in low and not out["org"]:
                out["org"] = v
            elif "country" in low and not out["country"]:
                out["country"] = v
            elif "abuse" in low and "@" in v and not out["abuse"]:
                out["abuse"] = v
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    _cache_put("asn", ip, out)
    return out


# ----- GreyNoise ------------------------------------------------------------


def greynoise(ip):
    cached = _cache_get("greynoise", ip)
    if cached is not None:
        return cached
    if not _is_public(ip):
        return {"_error": "non-public"}
    headers = {}
    key = os.environ.get("GREYNOISE_API_KEY")
    if key:
        headers["key"] = key
    data = _get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
    _cache_put("greynoise", ip, data)
    return data


# ----- AbuseIPDB ------------------------------------------------------------


def abuseipdb(ip):
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return {"_error": "no-key"}
    cached = _cache_get("abuseipdb", ip)
    if cached is not None:
        return cached
    if not _is_public(ip):
        return {"_error": "non-public"}
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
    data = _get(url, headers={"Key": key, "Accept": "application/json"})
    _cache_put("abuseipdb", ip, data)
    return data


# ----- Shodan ---------------------------------------------------------------


def shodan(ip):
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return {"_error": "no-key"}
    cached = _cache_get("shodan", ip)
    if cached is not None:
        return cached
    if not _is_public(ip):
        return {"_error": "non-public"}
    url = f"https://api.shodan.io/shodan/host/{ip}?key={urllib.parse.quote(key)}"
    data = _get(url)
    _cache_put("shodan", ip, data)
    return data


# ----- VirusTotal -----------------------------------------------------------


def _vt(path):
    key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
    if not key:
        return {"_error": "no-key"}
    return _get(f"https://www.virustotal.com/api/v3/{path}",
                headers={"x-apikey": key})


def virustotal_ip(ip):
    cached = _cache_get("vt-ip", ip)
    if cached is not None:
        return cached
    if not _is_public(ip):
        return {"_error": "non-public"}
    data = _vt(f"ip_addresses/{ip}")
    _cache_put("vt-ip", ip, data)
    return data


def virustotal_url(url):
    cached = _cache_get("vt-url", url)
    if cached is not None:
        return cached
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    data = _vt(f"urls/{url_id}")
    _cache_put("vt-url", url, data)
    return data


def virustotal_hash(sha256):
    cached = _cache_get("vt-hash", sha256)
    if cached is not None:
        return cached
    data = _vt(f"files/{sha256}")
    _cache_put("vt-hash", sha256, data)
    return data


# ----- enrichment orchestrators --------------------------------------------


def enrich_ip(ip, sources=("whois", "greynoise", "abuseipdb", "virustotal", "shodan")):
    out = {"ip": ip}
    if "whois" in sources:
        out["asn"] = whois_asn(ip)
    if "greynoise" in sources:
        out["greynoise"] = greynoise(ip)
    if "abuseipdb" in sources:
        out["abuseipdb"] = abuseipdb(ip)
    if "virustotal" in sources:
        out["virustotal"] = virustotal_ip(ip)
    if "shodan" in sources:
        out["shodan"] = shodan(ip)
    out["summary"] = _summarize_ip(out)
    return out


def enrich_url(url):
    return {"url": url, "virustotal": virustotal_url(url)}


def enrich_hash(sha256):
    return {"sha256": sha256, "virustotal": virustotal_hash(sha256)}


# ----- summaries ------------------------------------------------------------


def _summarize_ip(enr):
    """Collapse several sources into a short verdict + tags."""
    tags = []
    verdict = "unknown"
    confidence = 0

    gn = enr.get("greynoise") or {}
    if gn.get("classification"):
        tags.append(f"greynoise:{gn['classification']}")
        if gn["classification"] == "malicious":
            verdict = "malicious"
            confidence = max(confidence, 70)

    ab = (enr.get("abuseipdb") or {}).get("data") or {}
    score = ab.get("abuseConfidenceScore")
    if isinstance(score, int):
        tags.append(f"abuseipdb:{score}")
        if score >= 75:
            verdict = "malicious"
            confidence = max(confidence, score)
        elif score >= 25 and verdict == "unknown":
            verdict = "suspicious"
            confidence = max(confidence, score)

    vt = (enr.get("virustotal") or {}).get("data") or {}
    stats = (vt.get("attributes") or {}).get("last_analysis_stats") or {}
    mal = stats.get("malicious", 0)
    if mal:
        tags.append(f"vt:{mal}")
        verdict = "malicious"
        confidence = max(confidence, min(100, 40 + 10 * mal))

    asn = enr.get("asn") or {}
    if asn.get("asn"):
        tags.append(f"AS{asn['asn']}")
    if asn.get("country"):
        tags.append(asn["country"])

    sh = enr.get("shodan") or {}
    for p in (sh.get("ports") or [])[:6]:
        tags.append(f"port:{p}")

    return {"verdict": verdict, "confidence": confidence, "tags": tags}
