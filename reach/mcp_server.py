"""Reach as an MCP server: the fixed tool catalogue, nothing else.

Run:  uv run python -m reach.mcp_server            (stdio)
Env:  REACH_ESTATE=demo|real   which estate to seed into an empty graph (default real)
      REACH_GRAPH / FALKORDB_HOST / REACH_DB_PATH  see reach/db.py

Every tool is read-only. propose_fix only PROPOSES; applying a fix is a human
action outside the agent.
"""

from __future__ import annotations

import os
from functools import lru_cache

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from reach import tools as T
from reach.db import connect

RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)


@lru_cache(maxsize=1)
def graph():
    g = connect()
    try:
        empty = not g.ro_query("MATCH (a:Agent) RETURN count(a)").result_set[0][0]
    except Exception as e:  # FalkorDB: "Invalid graph operation on empty key"
        if "empty key" not in str(e):
            raise
        empty = True
    if empty:
        if os.environ.get("REACH_ESTATE", "real") == "demo":
            from reach.seed import seed

            seed(g)
        else:
            from reach.real_estate import seed_real

            seed_real(g)
    return g


mcp = MCPServer(
    name="reach",
    instructions=(
        "Reach maps what AI agents can reach if prompt-injected. Call scan_paths before "
        "claiming any risk; quote only agent, tool and data names that a tool returned. "
        "'not_in_graph' means not modelled, never 'safe'."
    ),
)


@mcp.tool(annotations=RO)
def list_agents() -> dict:
    """List every agent with its granted scopes and the agents it delegates to."""
    return T.list_agents(graph())


@mcp.tool(annotations=RO)
def scan_paths(agent: str | None = None) -> dict:
    """Find lethal-trifecta paths (untrusted input -> private data -> external sink),
    including paths that cross agents via delegation. Optionally filter to one agent."""
    return T.scan_paths(graph(), agent)


@mcp.tool(annotations=RO)
def explain_tool(tool: str) -> dict:
    """Show why a tool is classified as ingesting untrusted input, reading private data,
    or sending externally, with the rule that matched."""
    return T.explain_tool(graph(), tool)


@mcp.tool(annotations=RO)
def propose_fix(mode: str = "zero_break") -> dict:
    """Propose the cheapest permission changes that close trifecta paths.
    mode=zero_break closes everything possible without breaking a workflow and lists
    the residual; mode=close_all closes everything and reports which workflows break.
    Proposal only; a human must approve."""
    return T.propose_fix(graph(), mode)


@mcp.tool(annotations=RO)
def guard_check(agent: str, history: list[str], next_tool: str) -> dict:
    """Runtime guard: given the tools already called in this task (across delegations),
    decide whether next_tool would complete the trifecta and must be blocked."""
    return T.guard_check(graph(), agent, history, next_tool)


@mcp.tool(annotations=RO)
def chokepoints(limit: int = 8) -> dict:
    """Rank the agents and per-agent tools most attack paths and information flow pass
    through (algo.betweenness over a taint-flow projection, plus trifecta path counts).
    Use to decide where one change removes the most risk."""
    from reach.algos import chokepoints as cp

    return cp(graph(), limit)


@mcp.tool(annotations=RO)
def explain_reach(src: str, dst: str, k: int = 1) -> dict:
    """Shortest route by which information can flow from src to dst (algo.SPpaths over the
    taint-flow projection). Names: agents, sources, data stores, sinks, or 'agent/tool'.
    Use to answer 'how could X ever reach Y?'."""
    from reach.algos import explain_reach as er

    return er(graph(), src, dst, k)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
def record_scan() -> dict:
    """Scan now and remember it: diff against open findings and attribute each newly
    opened or closed path to the estate changes since the last scan. Writes only
    Scan/Finding memory nodes, never the estate."""
    from reach.history import record_scan as rs

    return rs(graph())


@mcp.tool(annotations=RO)
def scan_timeline() -> dict:
    """Every recorded scan (open path count) and every recorded estate change."""
    from reach.history import timeline

    return timeline(graph())


@mcp.tool(annotations=RO)
def finding_history(key: str) -> dict:
    """When a path (key 'entry|untrusted|private|sink') was first seen, whether it is
    open, and which recorded changes opened or closed it."""
    from reach.history import finding_history as fh

    return fh(graph(), key)


@mcp.tool(annotations=RO)
def open_at(at_ms: int) -> dict:
    """Which paths were open as of the latest scan at or before at_ms (epoch ms)."""
    from reach.history import open_at as oa

    return oa(graph(), at_ms)


if __name__ == "__main__":
    mcp.run()
