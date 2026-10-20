"""Build the flowsint graph from extracted + enriched + analysed artefacts.

Node types:
    ip        source IP seen in cowrie
    session   one SSH session
    url       download URL seen in a session
    hash      sha256 of a captured file
    binary    static-analysis record for a captured file
    asn       autonomous system an IP belongs to
    country   ISO country code
    cred      username:password
    campaign  cluster label (e.g. "mirai", "gafgyt") derived from markers
    c2        IP/URL/domain pulled from a binary's embedded strings
    tag       verdict/signal tag (greynoise:malicious, vt:12, etc.)

Edge types:
    connected_from   session -> ip
    tried_cred       session -> cred
    downloaded       session -> url
    yielded          url -> hash
    analysed_as      hash -> binary
    belongs_to       ip -> asn
    located_in       ip -> country / asn -> country
    beacons_to       binary -> c2
    matches_family   binary -> campaign
    tagged           ip|binary -> tag

Emits:
    nodes: [{id, type, label, props}]
    edges: [{src, dst, type, props}]
    plus a convenience `graph.json` the HTML viewer renders.
"""
import re


def _node(graph, nid, ntype, label=None, **props):
    if nid in graph["_seen"]:
        n = graph["_seen"][nid]
        if label and not n.get("label"):
            n["label"] = label
        for k, v in props.items():
            if v is not None and k not in n["props"]:
                n["props"][k] = v
        return n
    n = {"id": nid, "type": ntype, "label": label or nid, "props": dict(props)}
    graph["nodes"].append(n)
    graph["_seen"][nid] = n
    return n


def _edge(graph, src, dst, etype, **props):
    key = (src, dst, etype)
    if key in graph["_edges"]:
        e = graph["_edges"][key]
        for k, v in props.items():
            if v is not None:
                e["props"][k] = v
        return e
    e = {"src": src, "dst": dst, "type": etype, "props": dict(props)}
    graph["edges"].append(e)
    graph["_edges"][key] = e
    return e


_DOMAIN = re.compile(r"[a-z0-9.-]+\.[a-z]{2,}", re.I)


def _url_host(url):
    m = re.match(r"https?://([^/:]+)", url or "")
    return m.group(1) if m else None


def build(entities, enrichment, binaries):
    g = {"nodes": [], "edges": [], "_seen": {}, "_edges": {}}

    # creds
    for c in entities.get("creds", []):
        _node(g, f"cred:{c['cred']}", "cred", c["cred"],
              successes=c["successes"], failures=c["failures"])

    # ips + enrichment
    enr_ips = enrichment.get("ips", {})
    for ip_rec in entities.get("ips", []):
        ip = ip_rec["ip"]
        nid = f"ip:{ip}"
        e = enr_ips.get(ip, {})
        summary = e.get("summary", {})
        asn = (e.get("asn") or {})
        _node(g, nid, "ip", ip,
              events=ip_rec["events"],
              success_logins=ip_rec["success_logins"],
              login_failures=ip_rec["login_failures"],
              commands_run=ip_rec["commands_run"],
              downloads=ip_rec["downloads"],
              first_seen=ip_rec["first_seen"],
              last_seen=ip_rec["last_seen"],
              verdict=summary.get("verdict", "unknown"),
              confidence=summary.get("confidence", 0),
              client_versions=ip_rec.get("client_versions"),
              abuse_contact=asn.get("abuse"),
              netname=asn.get("netname"),
              org=asn.get("org"))

        if asn.get("asn"):
            an = f"asn:AS{asn['asn']}"
            _node(g, an, "asn", f"AS{asn['asn']}",
                  name=asn.get("asn_name") or asn.get("org"))
            _edge(g, nid, an, "belongs_to")
            if asn.get("country"):
                _node(g, f"country:{asn['country']}", "country", asn["country"])
                _edge(g, an, f"country:{asn['country']}", "located_in")
        if asn.get("country"):
            _node(g, f"country:{asn['country']}", "country", asn["country"])
            _edge(g, nid, f"country:{asn['country']}", "located_in")

        for t in summary.get("tags", []):
            tn = f"tag:{t}"
            _node(g, tn, "tag", t)
            _edge(g, nid, tn, "tagged")

    # sessions, with their creds, downloads, uploads
    for s in entities.get("sessions", []):
        sid = f"session:{s['session_id']}"
        _node(g, sid, "session", s["session_id"],
              src_ip=s["src_ip"], client=s["client"],
              duration=s["duration"], commands=len(s["commands"]),
              downloads=len(s["downloads"]), uploads=len(s["uploads"]),
              login_success=s.get("login_success"))
        if s["src_ip"]:
            _edge(g, sid, f"ip:{s['src_ip']}", "connected_from")
        if s.get("login_success"):
            _node(g, f"cred:{s['login_success']}", "cred", s["login_success"])
            _edge(g, sid, f"cred:{s['login_success']}", "tried_cred", success=True)
        for d in s["downloads"]:
            if d["url"]:
                _node(g, f"url:{d['url']}", "url", d["url"],
                      host=_url_host(d["url"]))
                _edge(g, sid, f"url:{d['url']}", "downloaded", ts=d["ts"])
                if d["sha256"]:
                    _node(g, f"hash:{d['sha256']}", "hash", d["sha256"][:12] + "…",
                          sha256=d["sha256"], size=d.get("size"))
                    _edge(g, f"url:{d['url']}", f"hash:{d['sha256']}", "yielded")

    # url-level enrichment (vt flags)
    enr_urls = enrichment.get("urls", {})
    for url, e in enr_urls.items():
        vt = (e.get("virustotal") or {}).get("data") or {}
        mal = ((vt.get("attributes") or {}).get("last_analysis_stats") or {}).get("malicious", 0)
        if mal:
            tn = f"tag:vt-url:{mal}"
            _node(g, tn, "tag", f"vt-url:{mal}")
            _edge(g, f"url:{url}", tn, "tagged")

    # hash-level enrichment
    enr_hashes = enrichment.get("hashes", {})
    for sha, e in enr_hashes.items():
        vt = (e.get("virustotal") or {}).get("data") or {}
        attrs = vt.get("attributes") or {}
        mal = (attrs.get("last_analysis_stats") or {}).get("malicious", 0)
        hid = f"hash:{sha}"
        _node(g, hid, "hash", sha[:12] + "…", sha256=sha)
        if mal:
            tn = f"tag:vt:{mal}"
            _node(g, tn, "tag", f"vt:{mal}")
            _edge(g, hid, tn, "tagged")
        pop_name = attrs.get("meaningful_name")
        if pop_name:
            # _seen was stripped below; the node is already in g["nodes"] so
            # look it up to attach the VT name.
            for n in g["nodes"]:
                if n["id"] == hid:
                    n["props"]["vt_name"] = pop_name
                    break

    # binary analysis -> binary nodes + C2 edges + family campaigns
    for b in binaries:
        if "_error" in b:
            continue
        sha = b["sha256"]
        hid = f"hash:{sha}"
        _node(g, hid, "hash", sha[:12] + "…", sha256=sha, size=b["size"])
        bid = f"binary:{sha[:16]}"
        _node(g, bid, "binary", sha[:12] + "…",
              arch=(b.get("elf") or {}).get("machine") or b.get("magic"),
              bits=(b.get("elf") or {}).get("bits"),
              packed=b.get("likely_packed"),
              family=",".join(b.get("family_markers") or []),
              size=b["size"])
        _edge(g, hid, bid, "analysed_as")

        for fam in b.get("family_markers") or []:
            cn = f"campaign:{fam}"
            _node(g, cn, "campaign", fam)
            _edge(g, bid, cn, "matches_family")

        for ip in b.get("embedded_ips") or []:
            cid = f"c2:{ip}"
            _node(g, cid, "c2", ip, kind="ip")
            _edge(g, bid, cid, "beacons_to")
        for d in b.get("embedded_domains") or []:
            cid = f"c2:{d}"
            _node(g, cid, "c2", d, kind="domain")
            _edge(g, bid, cid, "beacons_to")
        for u in b.get("embedded_urls") or []:
            cid = f"c2:{u}"
            _node(g, cid, "c2", u, kind="url")
            _edge(g, bid, cid, "beacons_to")

    # drop bookkeeping fields
    g.pop("_seen", None)
    g.pop("_edges", None)
    return g


def write_viewer_html(graph_json_path, html_path):
    """Minimal self-contained D3 force-graph viewer that loads graph.json."""
    html = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>flowsint graph</title>
<style>
  html,body{margin:0;height:100%;background:#0b0f14;color:#dbe4ea;
    font:13px -apple-system,Segoe UI,Roboto,Ubuntu,sans-serif}
  #hud{position:fixed;top:8px;left:8px;background:#141a22;padding:8px 10px;
    border-radius:6px;max-width:340px;line-height:1.5;z-index:10}
  #hud h1{font-size:13px;margin:0 0 4px}
  svg{width:100vw;height:100vh;display:block}
  text{fill:#aab6c0;font-size:10px;pointer-events:none}
  .node{stroke:#0b0f14;stroke-width:1.2}
  .link{stroke:#2a3a4a;stroke-opacity:.7}
</style></head>
<body>
<div id="hud"><h1>flowsint</h1>
  node colour = type · size = degree · drag to rearrange · hover for details
</div>
<svg></svg>
<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
const COLOR = {
  ip:"#ff6b6b", session:"#f1c40f", url:"#5dade2", hash:"#a569bd",
  binary:"#e67e22", asn:"#48c9b0", country:"#2ecc71", cred:"#eb984e",
  campaign:"#d7bde2", c2:"#ec7063", tag:"#566573"
};
fetch("graph.json").then(r=>r.json()).then(g=>{
  const svg=d3.select("svg"),W=innerWidth,H=innerHeight;
  const nodes=g.nodes.map(n=>({...n})),
        links=g.edges.map(e=>({source:e.src,target:e.dst,type:e.type}));
  const deg={};links.forEach(l=>{deg[l.source]=(deg[l.source]||0)+1;deg[l.target]=(deg[l.target]||0)+1});
  const sim=d3.forceSimulation(nodes)
    .force("link",d3.forceLink(links).id(d=>d.id).distance(55).strength(.3))
    .force("charge",d3.forceManyBody().strength(-120))
    .force("center",d3.forceCenter(W/2,H/2));
  const link=svg.append("g").selectAll("line").data(links).join("line").attr("class","link");
  const g2=svg.append("g").selectAll("g").data(nodes).join("g")
    .call(d3.drag()
      .on("start",(ev,d)=>{if(!ev.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y})
      .on("drag",(ev,d)=>{d.fx=ev.x;d.fy=ev.y})
      .on("end",(ev,d)=>{if(!ev.active)sim.alphaTarget(0);d.fx=d.fy=null}));
  g2.append("circle").attr("class","node")
    .attr("r",d=>4+Math.min(14,Math.sqrt(deg[d.id]||1)*2))
    .attr("fill",d=>COLOR[d.type]||"#888")
    .append("title").text(d=>d.type+" · "+d.label+"\n"+JSON.stringify(d.props,null,1));
  g2.append("text").text(d=>d.label).attr("dx",8).attr("dy",3);
  sim.on("tick",()=>{
    link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
        .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
    g2.attr("transform",d=>`translate(${d.x},${d.y})`);
  });
});
</script></body></html>
"""
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    return html_path
