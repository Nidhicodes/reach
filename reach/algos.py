"""Graph algorithms as agent tools: chokepoints (algo.betweenness) and
how-does-X-reach-Y (algo.SPpaths).

Both run on a *taint-flow projection* of the estate, written into a sibling
FalkorDB graph (`<estate>:flow`). The estate graph stores permissions
(Agent-USES->Tool-NEEDS->Scope, Tool-READS->Data ...), whose edge directions are
not the direction information moves. The projection re-draws it as data flow:

    Source -> agent/tool -> Agent          (ingest: untrusted text enters an agent)
    Data   -> agent/tool -> Agent          (read: private data enters an agent)
    Agent  -> agent/tool -> Sink           (send: data leaves)
    Agent  -> Agent       DELEGATES (w=1)  (the task, and its taint, move forward)
    Agent  -> Agent       RETURNS   (w=2)  (results come back to the delegator)

Only *usable* tools are projected (the agent holds every scope the tool needs),
and each tool node is per agent ("agent/tool"), so two agents sharing a tool do
not appear connected through it. Rebuilt on every call; estates are small.
"""

from __future__ import annotations

from reach import queries as Q

USABLE_PAIRS = """
MATCH (a:Agent)-[:USES]->(t:Tool)
OPTIONAL MATCH (t)-[:NEEDS]->(m:Scope) WHERE NOT (a)-[:GRANTED]->(m)
WITH a, t, count(m) AS miss WHERE miss = 0
RETURN a.name AS agent, t.name AS tool
"""
LEGS = "MATCH (t:Tool)-[e:INGESTS|READS|SENDS_TO]->(n) RETURN t.name AS tool, type(e) AS leg, n.name AS target, labels(n)[0] AS kind"
DELEGATIONS = "MATCH (a:Agent)-[:DELEGATES_TO]->(b:Agent) RETURN a.name AS src, b.name AS dst"

FLOW_REL_TYPES = ["FLOW"]

BETWEENNESS = """
CALL algo.betweenness({nodeLabels: ['N'], relationshipTypes: ['FLOW'], samplingSize: $n, samplingSeed: 7})
YIELD node, score
RETURN node.name AS name, node.kind AS kind, node.agent AS agent, node.tool AS tool, score
ORDER BY score DESC
"""

SHORTEST = """
MATCH (a:N {name: $src}), (b:N {name: $dst})
CALL algo.SPpaths({sourceNode: a, targetNode: b, relTypes: ['FLOW'],
                   relDirection: 'outgoing', weightProp: 'weight', pathCount: $k})
YIELD path, pathWeight
RETURN [n IN nodes(path) | n.name] AS hops,
       [n IN nodes(path) | n.kind] AS kinds,
       [r IN relationships(path) | r.via] AS via,
       pathWeight AS weight
ORDER BY weight
"""


def flow_graph(g):
    """Sibling graph handle in the same FalkorDB instance (multigraph topology)."""
    return type(g)(g.client, f"{g.name}:flow")


def project(g):
    """(Re)build the taint-flow projection of estate g. Returns the flow graph."""
    pairs = Q.ro(g, USABLE_PAIRS)
    legs = Q.ro(g, LEGS)
    dels = Q.ro(g, DELEGATIONS)
    by_tool: dict[str, list[dict]] = {}
    for leg in sorted(legs, key=lambda l: (l["tool"], l["leg"], l["target"])):
        by_tool.setdefault(leg["tool"], []).append(leg)

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(name, kind, agent="", tool=""):
        nodes.setdefault(name, {"name": name, "kind": kind, "agent": agent, "tool": tool})

    def edge(a, b, via, w=1):
        edges.append({"a": a, "b": b, "via": via, "w": w})

    agents = sorted({p["agent"] for p in pairs} | {d["src"] for d in dels} | {d["dst"] for d in dels})
    pairs = sorted(pairs, key=lambda p: (p["agent"], p["tool"]))
    dels = sorted(dels, key=lambda d: (d["src"], d["dst"]))
    for a in agents:
        node(a, "Agent", agent=a)
    for p in pairs:
        a, t = p["agent"], p["tool"]
        tn = f"{a}/{t}"
        for leg in by_tool.get(t, []):
            node(tn, "Tool", agent=a, tool=t)
            node(leg["target"], leg["kind"])
            if leg["leg"] in ("INGESTS", "READS"):
                edge(leg["target"], tn, leg["leg"])
                edge(tn, a, leg["leg"])
            else:
                edge(a, tn, "SENDS_TO")
                edge(tn, leg["target"], "SENDS_TO")
    for d in dels:
        edge(d["src"], d["dst"], "DELEGATES", 1)
        edge(d["dst"], d["src"], "RETURNS", 2)

    f = flow_graph(g)
    try:
        f.delete()
    except Exception:  # graph did not exist yet
        pass
    f.query("UNWIND $ns AS n CREATE (:N {name: n.name, kind: n.kind, agent: n.agent, tool: n.tool})",
            {"ns": list(nodes.values())})
    f.query("CREATE INDEX FOR (n:N) ON (n.name)")
    # de-duplicate parallel edges (a tool reading two tables projects tn->agent twice)
    uniq = {(e["a"], e["b"], e["via"]): e for e in edges}
    f.query(
        "UNWIND $es AS e MATCH (a:N {name: e.a}), (b:N {name: e.b}) "
        "CREATE (a)-[:FLOW {via: e.via, weight: e.w}]->(b)",
        {"es": list(uniq.values())},
    )
    return f


def _paths_through(paths: list[dict]) -> dict[str, int]:
    """How many trifecta paths each flow node lies on (attack-specific load)."""
    load: dict[str, int] = {}
    for p in paths:
        on = {p["untrusted"], p["private"], p["sink"], *p["handoff"]}
        on |= {f"{p['entry']}/{t}" for t in p["in_tools"]}
        on |= {f"{p['reader']}/{t}" for t in p["read_tools"]}
        on |= {f"{p['sender']}/{t}" for t in p["out_tools"]}
        for n in on:
            load[n] = load.get(n, 0) + 1
    return load


def chokepoints(g, limit: int = 8) -> dict:
    """Rank the agents and per-agent tools that most information flow passes through.

    score         = algo.betweenness on the taint-flow projection (structural: how many
                    shortest flows between any two nodes cross this one). FalkorDB samples
                    source nodes; we pass samplingSize = node count, a fixed seed and a
                    sorted projection, so results are reproducible -- but still an estimate,
                    which is why ranking leads with the exact paths_through count.
    paths_through = how many lethal-trifecta paths use it (attack-specific)
    Sorted by paths_through, then score. A node with high score but 0 paths_through is
    a hub that is not currently exploitable; the reverse is a narrow but live route.
    """
    limit = max(1, min(int(limit), 25))
    paths = Q.trifecta_paths(g)
    f = project(g)
    # exact, not sampled: samplingSize defaults to 32 random sources with a time-based seed
    n = Q.ro(f, "MATCH (n:N) RETURN count(n) AS n")[0]["n"]
    scores = Q.ro(f, BETWEENNESS, {"n": max(int(n), 1)})
    if not scores:
        return {"outcome": "not_in_graph", "chokepoints": [], "note": "Nothing usable to project."}
    load = _paths_through(paths)
    ranked = [
        {**s, "paths_through": load.get(s["name"], 0), "score": round(float(s["score"]), 2)}
        for s in scores if s["kind"] in ("Agent", "Tool")
    ]
    ranked.sort(key=lambda r: (-r["paths_through"], -r["score"], r["name"]))
    return {
        "outcome": "answered_with_path",
        "algorithm": "algo.betweenness over the taint-flow projection",
        "paths_total": len(paths),
        "chokepoints": ranked[:limit],
        "cypher": BETWEENNESS.strip(),
    }


def explain_reach(g, src: str, dst: str, k: int = 1) -> dict:
    """Shortest taint-flow route from src to dst (e.g. an untrusted source to a sink,
    or a data store to a sink), via algo.SPpaths. Names are agents, sources, data,
    sinks, or 'agent/tool'. Unknown names stop before any traversal."""
    k = max(1, min(int(k), 5))
    f = project(g)
    for n in (src, dst):
        if not Q.ro(f, "MATCH (n:N {name: $name}) RETURN n.name", {"name": n}):
            if not Q.ro(g, "MATCH (n {name: $name}) RETURN n.name LIMIT 1", {"name": n}):
                return {"outcome": "unknown_name", "name": n}
            return {"outcome": "not_in_graph", "name": n,
                    "note": f"{n} exists but no usable tool moves data to or from it."}
    routes = Q.ro(f, SHORTEST, {"src": src, "dst": dst, "k": k})
    if not routes:
        return {"outcome": "not_in_graph", "src": src, "dst": dst, "routes": [],
                "note": "No modelled flow connects them. Unmodelled tools or grants would not show up."}
    return {"outcome": "answered_with_path", "src": src, "dst": dst, "routes": routes,
            "algorithm": "algo.SPpaths over the taint-flow projection", "cypher": SHORTEST.strip()}
