"""Human-readable report writer.

Emits one combined markdown report for a flowsint run, plus a standalone
`binaries.md` focused on the static RE findings — that's the file forwarded
back to you directly.
"""
import json
import os
from datetime import datetime


def _h(level, text):
    return f"{'#' * level} {text}\n\n"


def _code(text, lang=""):
    return f"```{lang}\n{text}\n```\n\n"


def _row(cols):
    return "| " + " | ".join(str(c) for c in cols) + " |"


def _table(headers, rows):
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    body = "\n".join(_row(r) for r in rows)
    return _row(headers) + "\n" + sep + "\n" + body + "\n\n"


def _tags(summary):
    return ", ".join(summary.get("tags", [])) or "—"


def binary_markdown(binaries, out_path):
    """Write a focused markdown report of the binary analysis stage."""
    lines = [_h(1, "flowsint — binary analysis report"),
             f"_generated {datetime.utcnow().isoformat()}Z_  \n",
             f"_{len(binaries)} file(s) analysed_\n\n"]

    if not binaries:
        lines.append("No binaries found. Run with a `--downloads-dir` that points at "
                     "Cowrie's `var/lib/cowrie/downloads/` and ensure the log you "
                     "extracted references downloaded files.\n")
    else:
        # One-line summary table at the top.
        rows = []
        for b in binaries:
            if "_error" in b:
                rows.append([b.get("path", "?"), "", "", "", b["_error"]])
                continue
            arch = (b.get("elf") or {}).get("machine") or b.get("magic", "")
            fams = ",".join(b.get("family_markers") or []) or "-"
            packed = "packed" if b.get("likely_packed") else ("upx" if "upx" in b.get("packer_hints", []) else "-")
            rows.append([
                b["sha256"][:12] + "…",
                b.get("size"),
                arch,
                fams,
                packed,
            ])
        lines.append(_table(
            ["sha256", "size", "arch/magic", "family", "packed"], rows
        ))

        # Per-binary sections.
        for b in binaries:
            if "_error" in b:
                lines.append(_h(2, os.path.basename(b.get("path", "?"))))
                lines.append(f"_error: {b['_error']}_\n\n")
                continue
            short = b["sha256"][:16]
            lines.append(_h(2, f"{short}…  ({os.path.basename(b['path'])})"))

            kv = [
                ("sha256",   b["sha256"]),
                ("md5",      b["md5"]),
                ("size",     b["size"]),
                ("magic",    b["magic"]),
                ("printable", b["printable_ratio"]),
                ("packed?",  "yes" if b.get("likely_packed") else "no"),
                ("packer",   ",".join(b.get("packer_hints") or []) or "-"),
                ("family",   ",".join(b.get("family_markers") or []) or "-"),
            ]
            if b.get("elf"):
                elf = b["elf"]
                kv += [
                    ("elf.arch",    elf.get("machine")),
                    ("elf.bits",    elf.get("bits")),
                    ("elf.endian",  elf.get("endian")),
                    ("elf.stripped", elf.get("stripped")),
                    ("elf.static",   elf.get("static")),
                ]
            lines.append(_code("\n".join(f"{k:14s} {v}" for k, v in kv)))

            if b.get("embedded_ips"):
                lines.append("**embedded IPs**\n\n")
                lines.append(_code("\n".join(b["embedded_ips"][:40])))
            if b.get("embedded_urls"):
                lines.append("**embedded URLs**\n\n")
                lines.append(_code("\n".join(b["embedded_urls"][:40])))
            if b.get("embedded_domains"):
                lines.append("**embedded domains**\n\n")
                lines.append(_code("\n".join(b["embedded_domains"][:40])))
            if b.get("notable_strings"):
                lines.append("**notable strings**\n\n")
                lines.append(_code("\n".join(b["notable_strings"])))

            r2 = b.get("r2") or {}
            if r2 and "_error" not in r2 and r2:
                lines.append("**radare2**\n\n")
                r2_summary = {
                    "tool":              r2.get("tool"),
                    "functions_count":   r2.get("functions_count"),
                    "imports_count":     len(r2.get("imports") or []),
                    "sections_count":    len(r2.get("sections") or []),
                }
                lines.append(_code(json.dumps(r2_summary, indent=2), "json"))
                if r2.get("imports"):
                    lines.append("imports (first 40):\n\n")
                    lines.append(_code("\n".join((r2["imports"] or [])[:40])))
                if r2.get("functions_sample"):
                    lines.append("function sample:\n\n")
                    lines.append(_code("\n".join(r2["functions_sample"])))

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("".join(lines))
    return out_path


def pipeline_markdown(result, out_path):
    """Top-level pipeline summary — not forwarded, written next to the artefacts."""
    lines = [_h(1, "flowsint — pipeline summary"),
             f"_generated {datetime.utcnow().isoformat()}Z_\n\n"]
    ents = result["entities"]
    enr = result["enrichment"]
    bins = result["binaries"]

    lines.append(_h(2, "scale"))
    lines.append(_code(
        f"sessions         {len(ents['sessions'])}\n"
        f"ips              {len(ents['ips'])}\n"
        f"urls             {len(ents['urls'])}\n"
        f"captured hashes  {len(ents['hashes'])}\n"
        f"analysed files   {len(bins)}\n"
        f"ips enriched     {len(enr.get('ips', {}))}\n"
    ))

    # top malicious ips
    enr_ips = enr.get("ips", {})
    scored = sorted(
        enr_ips.values(),
        key=lambda x: -(x.get("summary", {}).get("confidence", 0)),
    )[:15]
    if scored:
        lines.append(_h(2, "top enriched source IPs"))
        rows = []
        for e in scored:
            s = e.get("summary", {})
            rows.append([e["ip"], s.get("verdict", "?"),
                         s.get("confidence", 0), _tags(s)])
        lines.append(_table(["ip", "verdict", "confidence", "tags"], rows))

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("".join(lines))
    return out_path
