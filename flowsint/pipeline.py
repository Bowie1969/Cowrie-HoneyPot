"""Pipeline orchestrator: extract -> osint -> binary -> graph -> report.

Each stage persists its artefact under --out-dir so you can inspect / rerun
any single stage. Enrichment honours a disk cache so re-runs cost no quota.

Public API:
    run(args) -> dict{entities, enrichment, binaries, graph, paths}
"""
import json
import os
import sys
import time

from . import extract, osint, binary, graph, report


def _write_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, default=str)
    return path


def _log(msg):
    print(f"[flowsint] {msg}", file=sys.stderr, flush=True)


def run(args):
    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)
    paths = {}

    # ----- 1. extract --------------------------------------------------------
    _log(f"extract: {args.logfile}")
    t = time.time()
    entities = extract.extract_from_log(args.logfile)
    _log(f"extract: {len(entities['sessions'])} sessions, "
         f"{len(entities['ips'])} ips, {len(entities['urls'])} urls, "
         f"{len(entities['hashes'])} hashes ({time.time()-t:.1f}s)")
    paths["entities"] = _write_json(os.path.join(out_dir, "entities.json"), entities)

    # ----- 2. osint ---------------------------------------------------------
    enrichment = {"ips": {}, "urls": {}, "hashes": {}}
    if not args.skip_osint:
        src = tuple(args.sources)
        # IPs: most-active first; capped by --max-ips (default 50)
        top_ips = sorted(entities["ips"], key=lambda r: -r["events"])[: args.max_ips]
        _log(f"osint: enriching {len(top_ips)} IPs via {','.join(src)}")
        for i, rec in enumerate(top_ips, 1):
            enrichment["ips"][rec["ip"]] = osint.enrich_ip(rec["ip"], sources=src)
            if i % 10 == 0:
                _log(f"  ips: {i}/{len(top_ips)}")

        if "virustotal" in src:
            for u in entities["urls"][: args.max_urls]:
                enrichment["urls"][u["url"]] = osint.enrich_url(u["url"])
            for h in entities["hashes"][: args.max_hashes]:
                enrichment["hashes"][h["sha256"]] = osint.enrich_hash(h["sha256"])

    paths["enrichment"] = _write_json(os.path.join(out_dir, "enrichment.json"), enrichment)

    # ----- 3. binary -------------------------------------------------------
    binaries = []
    if args.downloads_dir:
        _log(f"binary: analysing {args.downloads_dir}")
        hashes = {h["sha256"] for h in entities["hashes"]} if entities["hashes"] else None
        binaries = binary.analyze_dir(args.downloads_dir, hashes=hashes,
                                      deep=not args.no_r2)
        _log(f"binary: {len(binaries)} file(s) analysed")
    else:
        _log("binary: no --downloads-dir given, skipping")
    paths["binaries"] = _write_json(os.path.join(out_dir, "binaries.json"), binaries)
    # markdown report, always written, this is what gets forwarded
    paths["binary_report"] = report.binary_markdown(
        binaries, os.path.join(out_dir, "binary_report.md")
    )

    # ----- 4. graph ---------------------------------------------------------
    _log("graph: building")
    g = graph.build(entities, enrichment, binaries)
    paths["graph"] = _write_json(os.path.join(out_dir, "graph.json"), g)
    paths["viewer"] = graph.write_viewer_html(
        paths["graph"], os.path.join(out_dir, "graph.html")
    )

    # ----- 5. summary report -----------------------------------------------
    result = {"entities": entities, "enrichment": enrichment,
              "binaries": binaries, "graph": g, "paths": paths}
    paths["summary"] = report.pipeline_markdown(
        result, os.path.join(out_dir, "summary.md")
    )
    _log(f"done. artefacts in {out_dir}/")
    _log(f"  entities.json  enrichment.json  binaries.json  graph.json")
    _log(f"  binary_report.md  summary.md  graph.html")
    return result
