"""Static binary analysis for captured honeypot payloads.

Two tiers:
  triage()  stdlib-only: ELF header parse, file-magic sniff, strings sweep,
            embedded-IP/URL/domain regexes, printable-ratio entropy proxy,
            SHA-256 + ssdeep-like 7-byte rolling hash, Mirai/Gafgyt string IDs.
  r2()      optional: shells out to `r2 -q` (or r2pipe if installed) for
            function count, imports, section layout, and additional strings.

No sandbox detonation. All indicators returned are static.
"""
import hashlib
import json
import os
import re
import shutil
import string
import struct
import subprocess


IP_RE = re.compile(rb"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                   rb"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?(?![\d.])")
URL_RE = re.compile(rb"https?://[A-Za-z0-9._~\-/:%?#=&+@!$'()*,;]{3,}")
DOMAIN_RE = re.compile(rb"(?<![A-Za-z0-9.-])"
                       rb"(?:[a-z0-9][a-z0-9\-]{0,62}\.)+"
                       rb"(?:com|net|org|ru|cn|xyz|top|info|biz|io|cc|me|tk|ml|ga|cf|su|onion|pw)"
                       rb"(?![A-Za-z0-9.-])",
                       re.IGNORECASE)

# Classic Mirai/Gafgyt artefacts.
MIRAI_MARKERS = [
    rb"/proc/net/route", rb"TSource Engine Query", rb"Mozilla/4.0",
    rb"ECCHI", rb"/dev/watchdog", rb"nokillbins",
]
GAFGYT_MARKERS = [rb"BOGOMIPS", rb"PONG!", rb"GETLOCALIP",
                  rb"LOLNOGTFO", rb"\x00root\x00"]


ELF_MACHINES = {
    0x02: "SPARC", 0x03: "x86", 0x08: "MIPS", 0x14: "PowerPC",
    0x28: "ARM", 0x2A: "SH", 0x32: "IA-64", 0x3E: "x86_64",
    0xB7: "AArch64", 0xF3: "RISC-V", 0x04: "m68k",
}


def _file_magic(data):
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "mach-o"
    if data[:4] == b"PK\x03\x04":
        return "zip"
    if data[:5] == b"#!/bin" or data[:2] == b"#!":
        return "script"
    if data[:3] == b"\x1f\x8b\x08":
        return "gzip"
    return "unknown"


def _elf_header(data):
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    bits = 64 if data[4] == 2 else 32
    endian = "<" if data[5] == 1 else ">"
    try:
        machine = struct.unpack_from(endian + "H", data, 18)[0]
    except struct.error:
        return None
    return {
        "bits": bits,
        "endian": "little" if endian == "<" else "big",
        "machine_id": machine,
        "machine": ELF_MACHINES.get(machine, f"0x{machine:x}"),
        "stripped": b".symtab" not in data[:65536],
        "static": b"GLIBC" not in data[:65536] and b"libc" not in data[:65536],
    }


def _printable_ratio(data):
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)


def _strings(data, minlen=6, max_strings=500):
    out = []
    cur = []
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                try:
                    out.append(bytes(cur).decode("ascii"))
                except UnicodeDecodeError:
                    pass
                if len(out) >= max_strings:
                    return out
            cur = []
    if len(cur) >= minlen:
        try:
            out.append(bytes(cur).decode("ascii"))
        except UnicodeDecodeError:
            pass
    return out


def _packer_hint(data, strings_list):
    hints = []
    if b"UPX!" in data:
        hints.append("upx")
    if b"$Info: This file is packed" in data:
        hints.append("upx-info-tag")
    # low printable ratio + ELF -> probably packed
    return hints


def _family_markers(data):
    fams = []
    if any(m in data for m in MIRAI_MARKERS):
        fams.append("mirai")
    if any(m in data for m in GAFGYT_MARKERS):
        fams.append("gafgyt")
    return fams


def triage(path):
    """Return a dict of static indicators for one file."""
    with open(path, "rb") as f:
        data = f.read()

    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    strings_list = _strings(data)
    joined = ("\n".join(strings_list)).encode("utf-8", "ignore")

    out = {
        "path": path,
        "size": len(data),
        "sha256": sha256,
        "md5": md5,
        "magic": _file_magic(data),
        "elf": _elf_header(data) if data[:4] == b"\x7fELF" else None,
        "printable_ratio": round(_printable_ratio(data), 3),
        "likely_packed": _printable_ratio(data) < 0.12 and _file_magic(data) == "elf",
        "packer_hints": _packer_hint(data, strings_list),
        "family_markers": _family_markers(data),
        "strings_count": len(strings_list),
        "embedded_ips": sorted({m.decode() for m in IP_RE.findall(joined)}),
        "embedded_urls": sorted({m.decode(errors="replace") for m in URL_RE.findall(joined)}),
        "embedded_domains": sorted({m.decode(errors="replace").lower()
                                     for m in DOMAIN_RE.findall(joined)}),
        "notable_strings": [s for s in strings_list[:200]
                            if any(k in s.lower() for k in (
                                "wget", "curl", "tftp", "/bin/", "/tmp/", "chmod",
                                "nc ", "busybox", "mirai", "ssh", "pass", "login",
                                "/dev/", "iptables", ".sh", ".bin", "crypt",
                            ))][:40],
    }
    return out


def r2(path):
    """Enrich with radare2 if available. Returns {} when r2 isn't installed."""
    r2bin = shutil.which("r2") or shutil.which("rizin")
    if not r2bin:
        return {}
    # one shot, each command separated by ';'
    cmds = ";".join([
        "aaa",
        "ij",     # file info JSON
        "ilj",    # imports/libraries JSON
        "aflj",   # functions JSON
        "iSj",    # sections JSON
        "izqq~?", # strings count
    ])
    try:
        r = subprocess.run(
            [r2bin, "-q", "-c", cmds, "-N", path],
            capture_output=True, text=True, timeout=120,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {"_error": str(e)}

    out = {"tool": os.path.basename(r2bin)}
    parts = r.stdout.split("\n\n")
    for chunk in parts:
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            doc = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if isinstance(doc, dict) and "core" in doc:
            out["info"] = doc
        elif isinstance(doc, list) and doc and isinstance(doc[0], dict):
            if "ordinal" in doc[0] or "name" in doc[0] and "plt" in doc[0]:
                out["imports"] = [d.get("name") for d in doc[:200]]
            elif "offset" in doc[0] and "size" in doc[0] and "name" in doc[0]:
                if "nbbs" in doc[0]:
                    out["functions_count"] = len(doc)
                    out["functions_sample"] = [d.get("name") for d in doc[:30]]
                else:
                    out["sections"] = [{"name": d.get("name"), "size": d.get("size"),
                                        "perm": d.get("perm")} for d in doc]
    return out


def analyze_dir(downloads_dir, hashes=None, deep=True):
    """Walk a downloads/ dir (Cowrie keeps files named by their SHA-256) and
    produce one record per file. If `hashes` is given, only those are analysed.
    """
    if not os.path.isdir(downloads_dir):
        return []
    results = []
    want = set(hashes) if hashes else None
    for name in sorted(os.listdir(downloads_dir)):
        p = os.path.join(downloads_dir, name)
        if not os.path.isfile(p):
            continue
        # Cowrie stores files as sha256; accept any filename, hash-match later
        try:
            rec = triage(p)
        except (OSError, ValueError) as e:
            results.append({"path": p, "_error": str(e)})
            continue
        if want and rec["sha256"] not in want and name not in want:
            continue
        if deep:
            rec["r2"] = r2(p)
        results.append(rec)
    return results
