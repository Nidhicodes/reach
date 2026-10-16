"""Reach web UI + JSON API. Standard library only.

Run:  uv run python -m reach.web            -> http://127.0.0.1:8765
Env:  REACH_HOST (default 127.0.0.1), PORT / REACH_PORT (default 8765)

SECURITY: no authentication. Every endpoint works on synthetic estates in a sandbox
(the red-team replay never touches a real tool), and the only writes are estate edits
and scan memory on those synthetic graphs. Bind to loopback for local use; a public
deploy should sit behind auth or be reset on a schedule.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from reach import history as H
from reach import queries as Q
from reach import tools as T
from reach.db import connect

STATIC = Path(__file__).parent / "static"
LOCK = threading.Lock()  # embedded engine: serialise graph access
_graphs: dict = {}

GRAPH_VIEW = """
MATCH (a:Agent)-[:USES]->(t:Tool)-[e:INGESTS|READS|SENDS_TO]->(n)
OPTIONAL MATCH (t)-[:NEEDS]->(m:Scope) WHERE NOT (a)-[:GRANTED]->(m)
WITH a, type(e) AS leg, n, count(m) AS missing, collect(DISTINCT t.name) AS tools
RETURN a.name AS agent, leg, labels(n)[0] AS kind, n.name AS target,
       missing = 0 AS usable, tools
"""
DELEGATION_VIEW = "MATCH (a:Agent)-[:DELEGATES_TO]->(b:Agent) RETURN a.name AS src, b.name AS dst"


ESTATES = ("demo", "real", "gateway", "sample", "mine")
SAMPLE_DIR = Path(__file__).resolve().parents[1] / "examples" / "sample_setup"


def public() -> bool:
    """REACH_PUBLIC=1 on any non-loopback deploy: disables reading this machine's configs."""
    return os.environ.get("REACH_PUBLIC") == "1"


def graph(estate: str):
    if estate not in ESTATES:
        raise ValueError(f"estate must be one of {', '.join(ESTATES)}")
    if estate == "mine" and public():
        raise ValueError("scanning this machine is disabled on a public deploy")
    if estate not in _graphs:
        g = connect(f"ui-{estate}", path=os.environ.get("REACH_DB_PATH", "reach_ui.db"))
        empty = not (Q.ro(g, "MATCH (a:Agent) RETURN count(a) AS n") or [{"n": 0}])[0]["n"]
        if empty and estate == "demo":
            from reach.seed import seed

            seed(g)
            H.record_scan(g)  # baseline memory
        elif empty and estate == "real":
            from reach.real_estate import seed_real

            seed_real(g)
            H.record_scan(g)
        elif empty and estate == "sample":
            scan_setup(g, "sample")
        # gateway: filled by gateway runs; mine: filled by an explicit scan
        _graphs[estate] = g
    return _graphs[estate]


def scan_setup(g, which: str) -> dict:
    """Static scan only (starts nothing). 'mine' = this machine; 'sample' = examples/sample_setup."""
    from reach import setup as S

    if which == "sample":
        clients = S.discover([str(p) for p in sorted(SAMPLE_DIR.glob("*.json"))], include_home=False)
    else:
        clients = S.discover()
    rep = S.scan(g, clients, live=False)
    paths = S.annotate_severity(g, Q.trifecta_paths(g))
    from collections import Counter

    return {
        "clients": [{"client": c["client"], "path": c["path"] if which == "sample" else c["path"].replace(str(Path.home()), "~"),
                     "servers": [{k: s.get(k) for k in ("name", "source", "tools", "env_keys", "auto_approved")}
                                 for s in c["servers"]]} for c in rep["clients"]],
        "unmodelled": [{"server": s, "clients": n} for s, n in
                       Counter(u.rsplit(":", 1)[1] for u in rep["unmodelled"]).most_common()],
        "paths": len(paths),
        "severity": dict(Counter(p["severity"] for p in paths)),
    }


def estate_view(g) -> dict:
    """Collapse tools into agent->target edges so the picture stays readable at 557 tools."""
    edges = Q.ro(g, GRAPH_VIEW)
    nodes = {}
    for e in edges:
        nodes[e["agent"]] = "Agent"
        nodes[e["target"]] = e["kind"]
    for d in Q.ro(g, DELEGATION_VIEW):
        nodes.setdefault(d["src"], "Agent")
        nodes.setdefault(d["dst"], "Agent")
    return {"nodes": [{"id": k, "kind": v} for k, v in nodes.items()],
            "edges": edges, "delegations": Q.ro(g, DELEGATION_VIEW)}


def api(method: str, path: str, q: dict, body: dict) -> dict:
    estate = (q.get("estate") or body.get("estate") or "demo")
    if path == "/api/config":
        return {"public": public(), "llm": bool(os.environ.get("REACH_LLM_BASE_URL")), "estates": list(ESTATES)}
    g = graph(estate)
    if path == "/api/estate":
        return estate_view(g)
    if path == "/api/paths":
        r = {**T.scan_paths(g), "cypher": Q.TRIFECTA.strip()}
        if estate in ("sample", "mine") and r.get("paths"):
            from reach.setup import annotate_severity

            r["paths"] = annotate_severity(g, r["paths"])
        return r
    if path == "/api/chokepoints":
        from reach.algos import chokepoints

        return chokepoints(g, int(q.get("limit", 8)))
    if path == "/api/reach":
        from reach.algos import explain_reach

        return explain_reach(g, q.get("src", ""), q.get("dst", ""), int(q.get("k", 1)))
    if method == "POST" and path == "/api/setup":
        which = body.get("which", "sample")
        if which not in ("sample", "mine"):
            raise ValueError("which must be sample | mine")
        return scan_setup(graph(which), which)
    if method == "POST" and path == "/api/gateway/run":
        from reach import gateway_demo

        use_llm = bool(body.get("llm")) and bool(os.environ.get("REACH_LLM_BASE_URL"))
        return gateway_demo.run(graph("gateway"), str(body.get("scenario", "")), use_llm)
    if method == "POST" and path == "/api/gateway/ask":
        from reach import gateway_demo

        return gateway_demo.start_ask(graph("gateway"), str(body.get("scenario", "")))
    if path == "/api/gateway/ask-status":
        from reach import gateway_demo

        return gateway_demo.ask_status(q.get("job", ""))
    if path == "/api/approvals":
        from reach.gateway import pending_approvals

        return {"pending": pending_approvals(graph("gateway"))}
    if method == "POST" and path == "/api/approvals/decide":
        from reach.gateway import decide

        r = decide(graph("gateway"), str(body.get("id", "")), bool(body.get("approve")), by="ui")
        if not r:
            raise ValueError("no pending approval with that id")
        return r
    if path == "/api/gateway/ledger":
        from reach import gateway_demo

        return gateway_demo.ledger(graph("gateway"))
    if path == "/api/fix":
        return T.propose_fix(g, q.get("mode", "zero_break"))
    if path == "/api/timeline":
        return H.timeline(g)
    if path == "/api/finding":
        return H.finding_history(g, q.get("key", ""))
    if method == "POST" and path == "/api/change":
        return H.apply_change(g, body.get("kind", ""), body.get("agent", ""), body.get("target", ""), actor="ui")
    if method == "POST" and path == "/api/scan":
        return H.record_scan(g)
    if method == "POST" and path == "/api/redteam":
        from reach.redteam import SCENARIOS, replay

        if estate != "demo" or body.get("scenario") not in SCENARIOS:
            raise ValueError("red-team runs on the demo estate: scenario support | cross-agent")
        use_llm = bool(body.get("llm")) and bool(os.environ.get("REACH_LLM_BASE_URL"))
        runs = [replay(g, body["scenario"], guard, use_llm) for guard in (False, True)]
        return {"victim": "llm" if use_llm else "compromised (simulated fully-injected model)",
                "runs": [{"guard": r.guard, "exfiltrated": r.exfiltrated,
                          "events": [asdict(e) for e in r.events]} for r in runs]}
    if method == "POST" and path == "/api/ask":
        from reach import mcp_server
        from reach.agent import ask

        mcp_server.graph = lambda g=g: g  # MCP tools read the same handle this process holds
        a = asyncio.run(ask(str(body.get("question", ""))[:500], mcp_server.mcp))
        return {"text": a.text, "outcome": a.outcome, "checked": a.checked, "planner": a.planner,
                "trace": [asdict(s) for s in a.trace]}
    raise KeyError(path)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _handle(self, method: str):
        u = urlparse(self.path)
        if method == "GET" and u.path in ("/", "/index.html"):
            return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
        if method == "GET" and u.path == "/app.js":
            return self._send(200, (STATIC / "app.js").read_bytes(), "text/javascript; charset=utf-8")
        if not u.path.startswith("/api/"):
            return self._send(404, b"not found", "text/plain")
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        body = {}
        try:
            if method == "POST":
                n = min(int(self.headers.get("Content-Length") or 0), 64_000)
                body = json.loads(self.rfile.read(n) or b"{}")
            with LOCK:
                out = api(method, u.path, q, body)
            code = 200
        except KeyError:
            out, code = {"error": "unknown endpoint"}, 404
        except ValueError as e:
            out, code = {"error": str(e)}, 400
        except Exception as e:  # keep the demo up; report, don't crash
            out, code = {"error": f"{type(e).__name__}: {str(e)[:300]}"}, 500
        self._send(code, json.dumps(out, default=str).encode(), "application/json")

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def log_message(self, fmt, *args):
        pass


def main():
    host = os.environ.get("REACH_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT") or os.environ.get("REACH_PORT", "8765"))
    print(f"Reach UI on http://{host}:{port}  (no auth: synthetic sandbox only)")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
