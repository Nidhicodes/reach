"""Register a live MCP setup in the graph, idempotently (MERGE, never DELETE).

Used by the gateway (tools it actually proxies) and by `reach.setup` (MCP configs
found on this machine). Same model as the other estates:

  (:Agent {name, source})-[:GRANTED]->(:Scope {name:'conn:<server>'})
  (:Agent)-[:USES]->(:Tool {name:'<server>.<tool>', raw, server, description})
  (:Tool)-[:NEEDS]->(:Scope)  (:Tool)-[:PROVIDED_BY]->(:Server)-[:GATED_BY]->(:Scope)
  (:Tool)-[:INGESTS|READS|SENDS_TO {rule, why}]->(:Source|:Data|:Sink)

Tool names are qualified by server, so two servers that both expose `fetch` stay
distinct. Connecting a server grants every tool it lists; that is how MCP clients work.
"""

from __future__ import annotations

from reach import schema
from reach.classify import GENERIC_RULES, RULES, classify

LABEL = {"INGESTS": "Source", "READS": "Data", "SENDS_TO": "Sink"}
PROPS = {"Source": "n.trust = 'untrusted'", "Data": "n.sensitivity = 'private'", "Sink": "n.external = true"}


def qualified(server: str, tool: str) -> str:
    return f"{server}.{tool}"


def ensure_targets(g) -> None:
    for leg, name in sorted({(r.leg, r.target) for r in RULES + GENERIC_RULES}):
        lab = LABEL[leg]
        schema.write(g, f"MERGE (n:{lab} {{name: $n}}) ON CREATE SET {PROPS[lab]}", {"n": name})


def register(g, agent: str, server: str, tools: list[dict], source: str = "", owner: str = "") -> dict:
    """Agent `agent` is connected to `server`, which lists `tools` [{name, description}]."""
    ensure_targets(g)
    scope = f"conn:{server}"
    schema.write(g,
        """
        MERGE (a:Agent {name: $a}) ON CREATE SET a.source = $src, a.owner = $o
        MERGE (s:Server {name: $s})
        MERGE (sc:Scope {name: $scope})
        MERGE (s)-[:GATED_BY]->(sc)
        MERGE (a)-[:GRANTED]->(sc)
        """,
        {"a": agent, "src": source, "o": owner, "s": server, "scope": scope},
    )
    rows, legs = [], []
    for t in tools:
        q = qualified(server, t["name"])
        rows.append({"q": q, "raw": t["name"], "d": (t.get("description") or "")[:600],
                     "auto": bool(t.get("auto_approved"))})
        for r in classify(server, t.get("classify_as") or t["name"], fallback=True):
            legs.append({"q": q, "leg": r.leg, "target": r.target, "rule": r.id, "why": r.why})
    schema.write(g,
        """
        MATCH (a:Agent {name: $a}), (s:Server {name: $s})-[:GATED_BY]->(sc:Scope)
        UNWIND $rows AS r
        MERGE (t:Tool {name: r.q}) ON CREATE SET t.raw = r.raw, t.server = $s, t.description = r.d
        MERGE (t)-[:PROVIDED_BY]->(s)
        MERGE (t)-[:NEEDS]->(sc)
        MERGE (a)-[u:USES]->(t)
        SET u.auto_approved = r.auto
        """,
        {"a": agent, "s": server, "rows": rows},
    )
    for leg, lab in LABEL.items():
        sel = [x for x in legs if x["leg"] == leg]
        if sel:
            schema.write(g,
                f"UNWIND $rows AS x MATCH (t:Tool {{name: x.q}}), (n:{lab} {{name: x.target}}) "
                f"MERGE (t)-[e:{leg}]->(n) ON CREATE SET e.rule = x.rule, e.why = x.why",
                {"rows": sel},
            )
    return {"agent": agent, "server": server, "tools": len(rows), "legs": len(legs)}


def delegate(g, src: str, dst: str, observed: bool = False) -> None:
    schema.write(g,
        "MATCH (a:Agent {name: $a}), (b:Agent {name: $b}) MERGE (a)-[d:DELEGATES_TO]->(b) "
        "ON CREATE SET d.observed = $o",
        {"a": src, "b": dst, "o": observed},
    )
