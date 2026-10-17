"""Reach web UI + JSON API. Standard library only.

Run:  uv run python -m reach.web            -> http://127.0.0.1:8765
Env:  REACH_HOST (default 127.0.0.1), PORT / REACH_PORT (default 8765)

SECURITY: no authentication, by design: this is a public demo over synthetic estates in
a sandbox (the red-team and gateway runs only talk to in-process mock tools), and the only
writes are estate edits and scan memory on those synthetic graphs. Local use binds to
loopback. A public deploy sets REACH_PUBLIC=1, which:
  - refuses to read the host's own MCP configs ("This machine")
  - resets every mutable demo graph every REACH_RESET_MINUTES (default 30)
  - rate-limits each client IP (REACH_RATE_PER_MIN, default 120 requests/min)
  - turns real-LLM calls off unless REACH_PUBLIC_LLM_PER_HOUR > 0, and then caps them
    globally per hour and at 3 per IP per hour, so a visitor cannot burn the API key
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
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
from reach.paths import EXAMPLES  # noqa: E402

SAMPLE_DIR = EXAMPLES / "sample_setup"


def public() -> bool:
    """REACH_PUBLIC=1 on any non-loopback deploy (see the module docstring)."""
    return os.environ.get("REACH_PUBLIC") == "1"


# ------------------------------------------------------------ public-deploy guards
_hits: dict[str, list[float]] = {}
_llm_hits: dict[str, list[float]] = {}
_last_reset = [time.time()]
LLM_PER_IP_HOUR = 3


def _window(log: dict, key: str, span: float) -> list[float]:
    now = time.time()
    log[key] = [t for t in log.get(key, []) if now - t < span]
    return log[key]


def rate_ok(ip: str) -> bool:
    if not public():
        return True
    if len(_hits) > 10_000:  # bound memory under a spray of source IPs
        _hits.clear()
    w = _window(_hits, ip, 60)
    w.append(time.time())
    return len(w) <= int(os.environ.get("REACH_RATE_PER_MIN", "120"))


def llm_configured() -> bool:
    if not os.environ.get("REACH_LLM_BASE_URL"):
        return False
    return not public() or int(os.environ.get("REACH_PUBLIC_LLM_PER_HOUR", "0")) > 0


def llm_ok(ip: str, wanted: bool = True) -> bool:
    """Spend one real-LLM call for this client, or say no (callers then run offline)."""
    if not (wanted and llm_configured()):
        return False
    if not public():
        return True
    total = sum(len(_window(_llm_hits, k, 3600)) for k in list(_llm_hits))
    mine = _window(_llm_hits, ip, 3600)
    if total >= int(os.environ.get("REACH_PUBLIC_LLM_PER_HOUR", "0")) or len(mine) >= LLM_PER_IP_HOUR:
        return False
    mine.append(time.time())
    return True


def maybe_reset() -> bool:
    """Public deploys share one set of graphs between all visitors: wipe and reseed them on
    a schedule so one visitor's edits (or junk) never stick. Called under LOCK."""
    if not public() or time.time() - _last_reset[0] < 60 * float(os.environ.get("REACH_RESET_MINUTES", "30")):
        return False
    _last_reset[0] = time.time()
    names = [f"ui-{e}" for e in ESTATES] + ["ui-harden"]
    for n in names + [f"{n}:flow" for n in names]:
        try:
            connect(n, path=os.environ.get("REACH_DB_PATH", "reach_ui.db")).delete()
        except Exception:
            pass  # graph did not exist
    _graphs.clear()
    return True


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


def api(method: str, path: str, q: dict, body: dict, ip: str = "local") -> dict:
    estate = (q.get("estate") or body.get("estate") or "demo")
    if path == "/api/config":
        return {"public": public(), "llm": llm_configured(), "estates": list(ESTATES),
                "reset_minutes": float(os.environ.get("REACH_RESET_MINUTES", "30")) if public() else None}
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
    if method == "POST" and path == "/api/harden":
        from reach import harden

        files = sorted(SAMPLE_DIR.glob("*.json"))  # dry run on the bundled sample only
        out = []
        for f in files:
            r = harden.plan(connect("ui-harden", path=os.environ.get("REACH_DB_PATH", "reach_ui.db")), str(f))
            r["file"] = f.name
            r["diff"] = r["diff"].replace(str(SAMPLE_DIR) + "/", "")
            out.append({k: v for k, v in r.items() if not k.startswith("_")})
        return {"configs": out, "applied": False, "note": "Apply one with: reach-harden <file> --apply"}
    if method == "POST" and path == "/api/gateway/run":
        from reach import gateway_demo

        use_llm = llm_ok(ip, bool(body.get("llm")))
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
        use_llm = llm_ok(ip, bool(body.get("llm")))
        runs = [replay(g, body["scenario"], guard, use_llm) for guard in (False, True)]
        return {"victim": "llm" if use_llm else "compromised (simulated fully-injected model)",
                "runs": [{"guard": r.guard, "exfiltrated": r.exfiltrated,
                          "events": [asdict(e) for e in r.events]} for r in runs]}
    if method == "POST" and path == "/api/ask":
        from reach import mcp_server
        from reach.agent import ask

        mcp_server.graph = lambda g=g: g  # MCP tools read the same handle this process holds
        a = asyncio.run(ask(str(body.get("question", ""))[:500], mcp_server.mcp, use_llm=llm_ok(ip)))
        return {"text": a.text, "outcome": a.outcome, "checked": a.checked, "planner": a.planner,
                "trace": [asdict(s) for s in a.trace]}
    raise KeyError(path)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
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
        ip = self.client_address[0]
        if public() and self.headers.get("X-Forwarded-For"):
            # the platform's proxy appends the address it saw; earlier entries are client-supplied
            ip = self.headers["X-Forwarded-For"].split(",")[-1].strip()
        if not rate_ok(ip):
            return self._send(429, b'{"error": "rate limited: slow down"}', "application/json")
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        body = {}
        try:
            if method == "POST":
                n = min(int(self.headers.get("Content-Length") or 0), 64_000)
                body = json.loads(self.rfile.read(n) or b"{}")
            with LOCK:
                maybe_reset()
                out = api(method, u.path, q, body, ip)
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
