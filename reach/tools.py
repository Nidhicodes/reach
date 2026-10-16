"""Fixed tool catalogue the agent picks from. The LLM never writes Cypher.

Every argument naming a graph entity is resolved against the graph first; an
unresolved name returns outcome="unknown_<kind>" and no further query runs.

Outcomes (every tool returns one):
  answered_with_path  -- the graph held the relationships; hops are included
  not_in_graph        -- the entity exists but nothing connects it the way asked
  unknown_agent / unknown_tool -- name not in the graph, nothing ran
  blocked / allowed   -- runtime guard verdicts
"""

from __future__ import annotations

from dataclasses import asdict

from reach import algos as A
from reach import queries as Q

# Which legs a tool realises, per tool name (a tool may realise several).
TOOL_LEGS = """
MATCH (t:Tool {name: $tool})-[e:INGESTS|READS|SENDS_TO]->(n)
RETURN DISTINCT type(e) AS leg, n.name AS target
"""

# Is the agent actually allowed to call this tool (holds every needed scope)?
USABLE = """
MATCH (a:Agent {name: $agent})-[:USES]->(t:Tool {name: $tool})
OPTIONAL MATCH (t)-[:NEEDS]->(m:Scope) WHERE NOT (a)-[:GRANTED]->(m)
RETURN t.name AS tool, count(m) AS missing
"""


def _resolve(g, q: str, name: str) -> bool:
    return bool(Q.ro(g, q, {"name": name}))


def list_agents(g) -> dict:
    return {"outcome": "answered_with_path", "agents": Q.ro(g, Q.LIST_AGENTS)}


def scan_paths(g, agent: str | None = None) -> dict:
    if agent and not _resolve(g, Q.RESOLVE_AGENT, agent):
        return {"outcome": "unknown_agent", "agent": agent}
    paths = Q.trifecta_paths(g)
    if agent:
        paths = [p for p in paths if agent in p["handoff"]]
    if not paths:
        return {"outcome": "not_in_graph", "agent": agent, "paths": [],
                "note": "No trifecta path in the modelled estate. Unmodelled tools or grants would not show up."}
    return {"outcome": "answered_with_path", "paths": paths}


def explain_tool(g, tool: str) -> dict:
    if not _resolve(g, Q.RESOLVE_TOOL, tool):
        return {"outcome": "unknown_tool", "tool": tool}
    ev = Q.ro(g, Q.TOOL_EVIDENCE, {"tool": tool})
    return {"outcome": "answered_with_path" if ev else "not_in_graph", "tool": tool, "evidence": ev}


def propose_fix(g, mode: str = "zero_break") -> dict:
    if mode not in ("zero_break", "close_all"):
        raise ValueError("mode must be zero_break or close_all")
    paths = Q.trifecta_paths(g)
    if mode == "zero_break":
        plan, residual = Q.zero_break_plan(g, paths)
    else:
        plan, residual = Q.plan_fix(g, paths), []
    return {
        "outcome": "answered_with_path",
        "mode": mode,
        "actions": [a.describe() for a in plan.actions],
        "raw_actions": [asdict(a) for a in plan.actions],
        "breaks_workflows": plan.broken,
        "cost": plan.cost,
        "paths_total": len(paths),
        "residual_paths": residual,
        "notes": plan.notes,
        "requires_human_approval": True,
    }


def guard_check(g, agent: str, history: list[str], next_tool: str) -> dict:
    """Runtime guard for paths no permission change can close.

    `history` is the tools already called in this task, across every agent the
    task was delegated through (taint follows the handoff). The next call is
    blocked if it would complete the trifecta: untrusted input already ingested,
    private data already read, and next_tool sends somewhere.
    """
    if not _resolve(g, Q.RESOLVE_AGENT, agent):
        return {"outcome": "unknown_agent", "agent": agent}
    for t in [*history, next_tool]:
        if not _resolve(g, Q.RESOLVE_TOOL, t):
            return {"outcome": "unknown_tool", "tool": t}
    usable = Q.ro(g, USABLE, {"agent": agent, "tool": next_tool})
    if not usable or usable[0]["missing"] > 0:
        return {"outcome": "blocked", "reason": f"{agent} is not granted {next_tool}"}

    seen: dict[str, list[tuple[str, str]]] = {"INGESTS": [], "READS": [], "SENDS_TO": []}
    for t in history:
        for r in Q.ro(g, TOOL_LEGS, {"tool": t}):
            seen[r["leg"]].append((t, r["target"]))
    nxt = Q.ro(g, TOOL_LEGS, {"tool": next_tool})
    sends = [(next_tool, r["target"]) for r in nxt if r["leg"] == "SENDS_TO"]
    # next_tool itself may also ingest/read (e.g. a tool that fetches and posts)
    for r in nxt:
        if r["leg"] != "SENDS_TO":
            seen[r["leg"]].append((next_tool, r["target"]))

    if seen["INGESTS"] and seen["READS"] and sends:
        return {
            "outcome": "blocked",
            "reason": "would complete the lethal trifecta in this task",
            "path": {"untrusted": seen["INGESTS"][0], "private": seen["READS"][0], "sink": sends[0]},
        }
    return {"outcome": "allowed", "tainted": bool(seen["INGESTS"]), "holds_private": bool(seen["READS"])}


CATALOGUE = {
    "list_agents": (list_agents, {}),
    "scan_paths": (scan_paths, {"agent": "agent_name?"}),
    "explain_tool": (explain_tool, {"tool": "tool_name"}),
    "propose_fix": (propose_fix, {"mode": "zero_break|close_all"}),
    "guard_check": (guard_check, {"agent": "agent_name", "history": "tool_name[]", "next_tool": "tool_name"}),
    "chokepoints": (A.chokepoints, {"limit": "int<=25"}),
    "explain_reach": (A.explain_reach, {"src": "node_name", "dst": "node_name", "k": "int<=5"}),
}
