"""flowsint — turn Cowrie logs + captured binaries into an enriched threat graph.

Pipeline stages:
    extract  cowrie.json       -> entities (IPs, URLs, hashes, binaries, sessions)
    osint    entities          -> IP/URL/hash enrichment (VT, AbuseIPDB, Shodan,
                                  GreyNoise, Team Cymru whois/ASN)
    binary   downloads dir     -> ELF triage + radare2 static analysis
    graph    merged artifacts  -> nodes[] / edges[] JSON (+ HTML viewer)

Public entry point: flowsint.run(args) — invoked by the top-level flowsint.py CLI.
"""

__all__ = ["extract", "osint", "binary", "graph", "run"]

from . import extract, osint, binary, graph  # noqa: F401
from .pipeline import run  # noqa: F401
