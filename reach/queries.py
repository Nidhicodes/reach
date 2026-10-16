"""Human-written Cypher. The LLM never composes queries; it picks one of these tools.

Every query is read-only, parameterised and time-boxed.

Usable rule: an agent can actually use a tool only if it holds every scope the tool
NEEDS (OPTIONAL MATCH + count(missing) = 0; FalkorDB does not accept filtered pattern
comprehensions, so the check is written as a staged aggregation).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations

TIMEOUT_MS = 5000

# A path = (entry agent ingests untrusted Source) -> 0..3 delegation hops ->
# (reader agent reads private Data) and (some agent on the chain sends to a Sink).
# Grouped per (entry, source, chain, reader, data, sender, sink); the tools that
# realise each leg are collected so a fix can be reasoned about leg by leg.
TRIFECTA = """
MATCH (a:Agent)-[:USES]->(t_in:Tool)-[:INGESTS]->(src:Source)
OPTIONAL MATCH (t_in)-[:NEEDS]->(m1:Scope) WHERE NOT (a)-[:GRANTED]->(m1)
WITH a, t_in, src, count(m1) AS miss1
WHERE miss1 = 0
MATCH chain = (a)-[:DELEGATES_TO*0..3]->(r:Agent)
MATCH (r)-[:USES]->(t_read:Tool)-[:READS]->(d:Data)
OPTIONAL MATCH (t_read)-[:NEEDS]->(m2:Scope) WHERE NOT (r)-[:GRANTED]->(m2)
WITH a, t_in, src, chain, r, t_read, d, count(m2) AS miss2
WHERE miss2 = 0
UNWIND nodes(chain) AS x
MATCH (x)-[:USES]->(t_out:Tool)-[:SENDS_TO]->(k:Sink)
OPTIONAL MATCH (t_out)-[:NEEDS]->(m3:Scope) WHERE NOT (x)-[:GRANTED]->(m3)
WITH a, t_in, src, chain, r, t_read, d, x, t_out, k, count(m3) AS miss3
WHERE miss3 = 0
RETURN a.name AS entry, src.name AS untrusted,
       [n IN nodes(chain) | n.name] AS handoff,
       r.name AS reader, d.name AS private,
       x.name AS sender, k.name AS sink,
       collect(DISTINCT t_in.name)   AS in_tools,
       collect(DISTINCT t_read.name) AS read_tools,
       collect(DISTINCT t_out.name)  AS out_tools
ORDER BY entry, private, sink
"""

# Which workflows break if an agent loses a set of tools.
BROKEN_WORKFLOWS = """
MATCH (w:Workflow)-[:RUN_BY]->(a:Agent {name: $agent})
MATCH (w)-[:REQUIRES]->(t:Tool)
WHERE t.name IN $tools
RETURN DISTINCT w.name AS workflow
"""

# Which workflows rely on a delegation edge (both ends run workflows that hand off).
LIST_AGENTS = """
MATCH (a:Agent)
OPTIONAL MATCH (a)-[:GRANTED]->(s:Scope)
OPTIONAL MATCH (a)-[:DELEGATES_TO]->(b:Agent)
RETURN a.name AS agent, a.owner AS owner,
       collect(DISTINCT s.name) AS scopes, collect(DISTINCT b.name) AS delegates_to
ORDER BY agent
"""

TOOL_EVIDENCE = """
MATCH (t:Tool {name: $tool})-[e:INGESTS|READS|SENDS_TO]->(n)
RETURN t.server AS server, type(e) AS leg, n.name AS target, e.rule AS rule, e.why AS why
"""

RESOLVE_AGENT = "MATCH (a:Agent {name: $name}) RETURN a.name"
RESOLVE_TOOL = "MATCH (t:Tool {name: $name}) RETURN t.name LIMIT 1"


def rows(res) -> list[dict]:
    cols = [c[1] if isinstance(c, (list, tuple)) else c for c in res.header]
    return [dict(zip(cols, row)) for row in res.result_set]


def ro(g, q: str, params: dict | None = None) -> list[dict]:
    try:
        return rows(g.ro_query(q, params or {}, timeout=TIMEOUT_MS))
    except Exception as e:  # FalkorDB: reading a graph nobody has written yet
        if "empty key" in str(e):
            return []
        raise


def trifecta_paths(g) -> list[dict]:
    return ro(g, TRIFECTA)


# --------------------------------------------------------------------------- fixes


@dataclass(frozen=True)
class Action:
    """One atomic remediation."""

    kind: str  # "remove_tools" | "cut_delegation"
    agent: str
    leg: str = ""  # INGESTS | READS | SENDS_TO for remove_tools
    target: str = ""  # Source/Data/Sink name, or delegate agent for cut_delegation
    tools: tuple[str, ...] = ()

    def describe(self) -> str:
        if self.kind == "cut_delegation":
            return f"stop {self.agent} delegating to {self.target}"
        verb = {"INGESTS": "reading", "READS": "reading", "SENDS_TO": "sending to"}[self.leg]
        return f"remove {len(self.tools)} tool(s) from {self.agent} ({verb} {self.target}): {', '.join(self.tools)}"


@dataclass
class Plan:
    actions: list[Action]
    broken: list[str]
    cost: int
    closes: int
    total: int
    notes: list[str] = field(default_factory=list)


WORKFLOW_PENALTY = 100  # breaking a legitimate workflow is far worse than one more edit


def _action_cost(g, a: Action, cache: dict) -> tuple[int, list[str]]:
    if a in cache:
        return cache[a]
    if a.kind == "cut_delegation":
        res = (1, [])
    else:
        broken = [r["workflow"] for r in ro(g, BROKEN_WORKFLOWS, {"agent": a.agent, "tools": list(a.tools)})]
        res = (len(a.tools) + WORKFLOW_PENALTY * len(broken), broken)
    cache[a] = res
    return res


def path_options(p: dict) -> list[Action]:
    """Every atomic action that alone would close path p."""
    opts = [
        Action("remove_tools", p["entry"], "INGESTS", p["untrusted"], tuple(sorted(p["in_tools"]))),
        Action("remove_tools", p["reader"], "READS", p["private"], tuple(sorted(p["read_tools"]))),
        Action("remove_tools", p["sender"], "SENDS_TO", p["sink"], tuple(sorted(p["out_tools"]))),
    ]
    h = p["handoff"]
    opts += [Action("cut_delegation", h[i], target=h[i + 1]) for i in range(len(h) - 1)]
    return opts


def plan_fix(g, paths: list[dict], max_actions: int = 6) -> Plan:
    """Minimum-cost set of actions that closes every path.

    Weighted minimum hitting set: each path lists the actions that would close it;
    choose the cheapest set that hits every path, where breaking a workflow costs
    WORKFLOW_PENALTY. Exact search with branch-and-bound (estates are small).

    A tool shared by several legs (e.g. Gmail_GetEmail both ingests untrusted mail
    and reads the mailbox) is handled naturally: removing it can close several paths.
    """
    if not paths:
        return Plan([], [], 0, 0, 0)
    cache: dict = {}
    options = [path_options(p) for p in paths]

    def closes(chosen: list[Action], opts: list[Action]) -> bool:
        removed = {(c.agent, t) for c in chosen if c.kind == "remove_tools" for t in c.tools}
        cut = {(c.agent, c.target) for c in chosen if c.kind == "cut_delegation"}
        for o in opts:
            if o in chosen:
                return True
            if o.kind == "remove_tools" and o.tools and all((o.agent, t) in removed for t in o.tools):
                return True
            if o.kind == "cut_delegation" and (o.agent, o.target) in cut:
                return True
        return False

    universe = sorted({a for opts in options for a in opts}, key=lambda a: _action_cost(g, a, cache)[0])
    best: tuple[int, list[Action]] | None = None

    def search(i_path: int, chosen: list[Action], cost: int):
        nonlocal best
        if best and cost >= best[0]:
            return
        # first path not yet closed
        while i_path < len(options) and closes(chosen, options[i_path]):
            i_path += 1
        if i_path == len(options):
            best = (cost, list(chosen))
            return
        if len(chosen) >= max_actions:
            return
        for a in sorted(options[i_path], key=lambda a: _action_cost(g, a, cache)[0]):
            chosen.append(a)
            search(i_path + 1, chosen, cost + _action_cost(g, a, cache)[0])
            chosen.pop()

    search(0, [], 0)
    assert best is not None or universe
    cost, actions = best if best else (0, [])
    broken = sorted({w for a in actions for w in _action_cost(g, a, cache)[1]})
    plan = Plan(actions, broken, cost, len(paths), len(paths))
    if broken:
        plan.notes.append(
            "No static fix closes every path without breaking a workflow. The paths left "
            "open by the zero-break option need runtime enforcement (taint tracking), not a permission change."
        )
    return plan


def zero_break_plan(g, paths: list[dict]) -> tuple[Plan, list[dict]]:
    """Close everything that can be closed without breaking any workflow; report the rest."""
    cache: dict = {}
    fixable, residual = [], []
    for p in paths:
        if any(_action_cost(g, a, cache)[0] < WORKFLOW_PENALTY for a in path_options(p)):
            fixable.append(p)
        else:
            residual.append(p)
    return plan_fix(g, fixable), residual
