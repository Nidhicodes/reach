"""Scan history: Reach remembers every scan and which estate change opened or closed each path.

Memory lives in the same graph as the estate, as more nodes (one graph per tenant):

(:Change {id, at, kind, agent, target, actor})-[:ON]->(:Agent)
    kind: grant | revoke | use | unuse | delegate | undelegate
(:Scan {id, at, n_open})-[:FOUND]->(:Finding {key, entry, untrusted, private, sink,
                                              handoff, first_seen, last_seen, status})
(:Finding)-[:OPENED_BY]->(:Change)   candidate cause, from changes since the last scan
(:Finding)-[:CLOSED_BY]->(:Change)

Attribution rule: a change explains a finding if it touches an agent on the finding's
chain AND its target is one of the path's tools, a scope those tools need, or the next
agent on the chain (delegation). Shown with evidence; a candidate, not proof.
"""

from __future__ import annotations

import itertools
import time

from reach.queries import ro, trifecta_paths

_ids = itertools.count(int(time.time() * 1000))

APPLY = {
    "grant": "MATCH (a:Agent {name:$agent}), (s:Scope {name:$target}) MERGE (a)-[:GRANTED]->(s)",
    "revoke": "MATCH (a:Agent {name:$agent})-[r:GRANTED]->(:Scope {name:$target}) DELETE r",
    "use": "MATCH (a:Agent {name:$agent}), (t:Tool {name:$target}) MERGE (a)-[:USES]->(t)",
    "unuse": "MATCH (a:Agent {name:$agent})-[r:USES]->(:Tool {name:$target}) DELETE r",
    "delegate": "MATCH (a:Agent {name:$agent}), (b:Agent {name:$target}) MERGE (a)-[:DELEGATES_TO]->(b)",
    "undelegate": "MATCH (a:Agent {name:$agent})-[r:DELEGATES_TO]->(:Agent {name:$target}) DELETE r",
}
TARGET_LABEL = {"grant": "Scope", "revoke": "Scope", "use": "Tool", "unuse": "Tool",
                "delegate": "Agent", "undelegate": "Agent"}

RECORD_CHANGE = """
MATCH (a:Agent {name:$agent})
CREATE (c:Change {id:$id, at:$at, kind:$kind, agent:$agent, target:$target, actor:$actor})-[:ON]->(a)
"""

CHANGES_SINCE = "MATCH (c:Change) WHERE c.at > $since RETURN c.id AS id, c.kind AS kind, c.agent AS agent, c.target AS target, c.at AS at ORDER BY c.at"
LAST_SCAN_AT = "MATCH (s:Scan) RETURN max(s.at) AS at"
OPEN_FINDINGS = "MATCH (f:Finding {status:'open'}) RETURN f.key AS key"
TOOL_SCOPES = "MATCH (t:Tool)-[:NEEDS]->(s:Scope) WHERE t.name IN $tools RETURN collect(DISTINCT s.name) AS scopes"


def _key(p: dict) -> str:
    return "|".join([p["entry"], p["untrusted"], p["private"], p["sink"]])


def apply_change(g, kind: str, agent: str, target: str, actor: str = "admin", at: int | None = None) -> dict:
    """Mutate the estate AND record the change. Names are resolved first; nothing runs otherwise."""
    if kind not in APPLY:
        raise ValueError(f"kind must be one of {sorted(APPLY)}")
    if not ro(g, "MATCH (a:Agent {name:$n}) RETURN a.name", {"n": agent}):
        return {"outcome": "unknown_agent", "agent": agent}
    if not ro(g, f"MATCH (x:{TARGET_LABEL[kind]} {{name:$n}}) RETURN x.name LIMIT 1", {"n": target}):
        return {"outcome": f"unknown_{TARGET_LABEL[kind].lower()}", "target": target}
    at = at or int(time.time() * 1000)
    g.query(APPLY[kind], {"agent": agent, "target": target})
    cid = f"chg-{next(_ids)}"
    g.query(RECORD_CHANGE, {"id": cid, "at": at, "kind": kind, "agent": agent, "target": target, "actor": actor})
    return {"outcome": "applied", "change": cid, "at": at}


def _explains(g, change: dict, p: dict) -> bool:
    chain = p["handoff"]
    if change["agent"] not in chain:
        return False
    tools = set(p["in_tools"]) | set(p["read_tools"]) | set(p["out_tools"])
    if change["kind"] in ("use", "unuse"):
        return change["target"] in tools
    if change["kind"] in ("grant", "revoke"):
        return change["target"] in ro(g, TOOL_SCOPES, {"tools": sorted(tools)})[0]["scopes"]
    i = chain.index(change["agent"])
    return i + 1 < len(chain) and chain[i + 1] == change["target"]


def record_scan(g, at: int | None = None) -> dict:
    """Run a scan, diff against open findings, attribute opens/closes to recent changes."""
    at = at or int(time.time() * 1000)
    last = ro(g, LAST_SCAN_AT)[0]["at"] if ro(g, "MATCH (s:Scan) RETURN count(s) AS n")[0]["n"] else None
    since = last or 0
    changes = ro(g, CHANGES_SINCE, {"since": since})
    changes = [c for c in changes if c["at"] <= at]
    paths = trifecta_paths(g)
    now = {_key(p): p for p in paths}
    before = {r["key"] for r in ro(g, OPEN_FINDINGS)}
    sid = f"scan-{next(_ids)}"
    g.query("CREATE (:Scan {id:$id, at:$at, n_open:$n})", {"id": sid, "at": at, "n": len(now)})

    opened, closed = [], []
    for k, p in now.items():
        g.query(
            """MERGE (f:Finding {key:$k})
               ON CREATE SET f.first_seen=$at, f.entry=$e, f.untrusted=$u, f.private=$d, f.sink=$s
               SET f.last_seen=$at, f.status='open', f.handoff=$h,
                   f.tools=$tools
               WITH f MATCH (sc:Scan {id:$sid}) CREATE (sc)-[:FOUND]->(f)""",
            {"k": k, "at": at, "e": p["entry"], "u": p["untrusted"], "d": p["private"], "s": p["sink"],
             "h": p["handoff"], "sid": sid, "tools": sorted(set(p["in_tools"]) | set(p["read_tools"]) | set(p["out_tools"]))},
        )
        if k not in before and last is not None:
            why = [c for c in changes if _explains(g, c, p)]
            for c in why:
                g.query("MATCH (f:Finding {key:$k}), (c:Change {id:$c}) MERGE (f)-[:OPENED_BY]->(c)", {"k": k, "c": c["id"]})
            opened.append({"key": k, "path": p, "opened_by": why})
    for k in before - set(now):
        f = ro(g, "MATCH (f:Finding {key:$k}) RETURN f.handoff AS handoff, f.tools AS tools", {"k": k})[0]
        stub = {"handoff": f["handoff"], "in_tools": f["tools"] or [], "read_tools": [], "out_tools": []}
        why = [c for c in changes if _explains(g, c, stub)]
        g.query("MATCH (f:Finding {key:$k}) SET f.status='closed', f.closed_at=$at", {"k": k, "at": at})
        for c in why:
            g.query("MATCH (f:Finding {key:$k}), (c:Change {id:$c}) MERGE (f)-[:CLOSED_BY]->(c)", {"k": k, "c": c["id"]})
        closed.append({"key": k, "closed_by": why})
    return {"outcome": "recorded", "scan": sid, "at": at, "open": len(now),
            "opened": opened, "closed": closed, "baseline": last is None}


FINDING_HISTORY = """
MATCH (f:Finding {key:$k})
OPTIONAL MATCH (f)-[:OPENED_BY]->(o:Change)
OPTIONAL MATCH (f)-[:CLOSED_BY]->(c:Change)
RETURN f.key AS key, f.handoff AS handoff, f.first_seen AS first_seen, f.last_seen AS last_seen,
       f.status AS status, f.closed_at AS closed_at,
       collect(DISTINCT {kind:o.kind, agent:o.agent, target:o.target, at:o.at}) AS opened_by,
       collect(DISTINCT {kind:c.kind, agent:c.agent, target:c.target, at:c.at}) AS closed_by
"""

# Findings a scan at or before $at saw: what did the estate look like then?
OPEN_AT = """
MATCH (s:Scan) WHERE s.at <= $at
WITH s ORDER BY s.at DESC LIMIT 1
MATCH (s)-[:FOUND]->(f:Finding)
RETURN s.id AS scan, s.at AS scan_at, f.key AS key, f.handoff AS handoff
ORDER BY key
"""

TIMELINE = """
MATCH (s:Scan)
OPTIONAL MATCH (s)-[:FOUND]->(f:Finding)
WITH s, count(f) AS open
RETURN s.id AS scan, s.at AS at, open ORDER BY at
"""

CHANGES = "MATCH (c:Change) RETURN c.id AS id, c.at AS at, c.kind AS kind, c.agent AS agent, c.target AS target, c.actor AS actor ORDER BY at"


def _clean(xs: list[dict]) -> list[dict]:
    return [x for x in xs if x.get("kind")]


def finding_history(g, key: str) -> dict:
    r = ro(g, FINDING_HISTORY, {"k": key})
    if not r:
        return {"outcome": "not_in_graph", "key": key}
    r = r[0]
    r["opened_by"], r["closed_by"] = _clean(r["opened_by"]), _clean(r["closed_by"])
    return {"outcome": "answered_from_memory", **r}


def open_at(g, at: int) -> dict:
    rows = ro(g, OPEN_AT, {"at": at})
    if not rows and not ro(g, "MATCH (s:Scan) WHERE s.at <= $at RETURN s LIMIT 1", {"at": at}):
        return {"outcome": "not_in_graph", "note": "No scan was recorded at or before that time."}
    return {"outcome": "answered_from_memory", "scan": rows[0]["scan"] if rows else None,
            "scan_at": rows[0]["scan_at"] if rows else None, "findings": rows}


def timeline(g) -> dict:
    return {"outcome": "answered_from_memory", "scans": ro(g, TIMELINE), "changes": ro(g, CHANGES)}
