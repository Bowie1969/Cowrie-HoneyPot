#!/usr/bin/env python3
"""flowsint — turn Cowrie logs + captured binaries into an enriched threat graph.

    python3 flowsint.py cowrie.json \
        --downloads-dir /opt/cowrie/var/lib/cowrie/downloads \
        --out-dir out --top 50 \
        --sources whois,greynoise,abuseipdb,virustotal,shodan

Stages (each writes a standalone JSON in --out-dir, so you can rerun any one):
    extract  cowrie.json              -> entities.json
    osint    entities                 -> enrichment.json
    binary   downloads/*              -> binaries.json + binary_report.md
    graph    merged                   -> graph.json + graph.html (D3 viewer)

Keys are read from env vars; nothing is written anywhere. Each OSINT source
is optional — a missing key degrades gracefully:
    ABUSEIPDB_API_KEY, VT_API_KEY (or VIRUSTOTAL_API_KEY), SHODAN_API_KEY,
    GREYNOISE_API_KEY (optional; the community endpoint works keyless at low rate).

Binary analysis is static only. radare2 (`r2`) or `rizin` is auto-detected and
used when present; without it, flowsint falls back to its stdlib triage
(ELF header, strings, embedded IOCs, Mirai/Gafgyt markers, UPX detection).
"""
import argparse
import sys

from flowsint import run


DEFAULT_SOURCES = ["whois", "greynoise", "abuseipdb", "virustotal", "shodan"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile", help="cowrie.json path")
    ap.add_argument("--out-dir", default="flowsint-out",
                    help="where to drop entities.json/enrichment.json/graph.json/etc.")
    ap.add_argument("--downloads-dir", default=None,
                    help="Cowrie's var/lib/cowrie/downloads/ (or a copy)")
    ap.add_argument("--sources", default=",".join(DEFAULT_SOURCES),
                    help="comma list; subset of " + ",".join(DEFAULT_SOURCES))
    ap.add_argument("--max-ips", type=int, default=50,
                    help="enrich at most N IPs, sorted by activity (default 50)")
    ap.add_argument("--max-urls", type=int, default=20)
    ap.add_argument("--max-hashes", type=int, default=50)
    ap.add_argument("--skip-osint", action="store_true",
                    help="skip IP/URL/hash enrichment entirely")
    ap.add_argument("--no-r2", action="store_true",
                    help="disable radare2 enrichment even if r2 is installed")
    args = ap.parse_args(argv)

    args.sources = [s.strip() for s in args.sources.split(",") if s.strip()]
    try:
        run(args)
    except KeyboardInterrupt:
        print("\n[flowsint] interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
