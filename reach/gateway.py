"""Reach Gateway: an MCP proxy that enforces the trifecta guard on live tool calls.

Point any MCP client (Claude Desktop, Cursor, Kiro, your own agent) at the gateway
instead of at its servers. The gateway starts the real upstream servers, re-exposes
their tools as `<server>__<tool>`, and on every call:

  1. registers the upstream tools in the graph (reach.estate) the first time it sees them
  2. reads this task's earlier calls from the graph -- including calls made by OTHER
     agents on the same task id (taint follows the handoff)
  3. blocks the call if it would complete the lethal trifecta: untrusted input already
     ingested + private data already read + this call sends data out
  4. writes the call and its verdict back as (:Call)-[:IN_TASK]->(:Task)

The task ledger lives in FalkorDB, not in the process, so two gateways on one shared
FalkorDB (FALKORDB_HOST) see each other's calls and the cross-agent handoff is learned
as an observed DELEGATES_TO edge. With the embedded backend, share one process.

  uv run python -m reach.gateway --config gateway.json --agent support-bot [--task T] [--audit]

Config is the usual MCP client format: {"mcpServers": {"name": {"command", "args", "env"} | {"url"}}}.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from contextlib import AsyncExitStack, asynccontextmanager

import mcp_types as types
from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters
from mcp.server import Server
from mcp.server.stdio import stdio_server

from reach import estate
from reach import queries as Q

SEP = "__"

TASK_LEGS = """
MATCH (:Task {id: $task})<-[:IN_TASK]-(c:Call {verdict: 'allowed'})-[:CALLED]->(t:Tool)-[e:INGESTS|READS|SENDS_TO]->(n)
RETURN c.seq AS seq, c.agent AS agent, t.name AS tool, type(e) AS leg, n.name AS target
ORDER BY seq
"""
TASK_AGENTS = """
MATCH (:Task {id: $task})<-[:IN_TASK]-(c:Call)
RETURN c.agent AS agent, max(c.seq) AS last ORDER BY last DESC
"""
TOOL_LEGS = "MATCH (t:Tool {name: $tool})-[e:INGESTS|READS|SENDS_TO]->(n) RETURN type(e) AS leg, n.name AS target"
RECORD = """
MERGE (k:Task {id: $task})
WITH k MATCH (t:Tool {name: $tool})
CREATE (c:Call {seq: $seq, agent: $agent, at: $at, verdict: $verdict, reason: $reason, args: $args})
CREATE (c)-[:IN_TASK]->(k)
CREATE (c)-[:CALLED]->(t)
"""
NEXT_SEQ = "OPTIONAL MATCH (:Task {id: $task})<-[:IN_TASK]-(c:Call) RETURN coalesce(max(c.seq), 0) + 1 AS seq"


def load_config(path: str) -> dict:
    with open(path) as f:
        cfg = json.load(f)
    return cfg.get("mcpServers", cfg.get("servers", cfg))


def target(spec: dict):
    if spec.get("url"):
        return spec["url"]
    env = {**{k: os.environ[k] for k in ("PATH", "HOME", "REACH_OUTBOX") if k in os.environ}, **(spec.get("env") or {})}
    return StdioServerParameters(command=spec["command"], args=spec.get("args", []), env=env, cwd=spec.get("cwd"))


def verdict(prior: list[dict], next_legs: list[dict], tool: str) -> dict:
    """Pure decision. prior = legs of allowed calls earlier in this task."""
    ing = [p for p in prior if p["leg"] == "INGESTS"] + [{"tool": tool, **l} for l in next_legs if l["leg"] == "INGESTS"]
    rd = [p for p in prior if p["leg"] == "READS"] + [{"tool": tool, **l} for l in next_legs if l["leg"] == "READS"]
    out = [{"tool": tool, **l} for l in next_legs if l["leg"] == "SENDS_TO"]
    if ing and rd and out:
        return {"verdict": "blocked", "reason": "would complete the lethal trifecta in this task",
                "path": {"untrusted": [ing[0]["target"], ing[0]["tool"], ing[0].get("agent", "")],
                         "private": [rd[0]["target"], rd[0]["tool"], rd[0].get("agent", "")],
                         "sink": [out[0]["target"], tool]}}
    return {"verdict": "allowed", "tainted": bool(ing), "holds_private": bool(rd)}


class Gateway:
    def __init__(self, g, agent: str, upstreams: dict, task: str | None = None, mode: str = "block"):
        self.g, self.agent, self.upstreams, self.mode = g, agent, upstreams, mode
        self.task = task or os.environ.get("REACH_TASK") or f"task-{uuid.uuid4().hex[:8]}"
        self.clients: dict[str, Client] = {}
        self.tools: dict[str, tuple[str, types.Tool]] = {}  # exposed name -> (server, upstream tool)

    async def open(self, stack: AsyncExitStack) -> None:
        for name, spec in self.upstreams.items():
            c = await stack.enter_async_context(Client(spec if not isinstance(spec, dict) else target(spec)))
            self.clients[name] = c
            listed = (await c.list_tools()).tools
            for t in listed:
                self.tools[f"{name}{SEP}{t.name}"] = (name, t)
            estate.register(self.g, self.agent, name,
                            [{"name": t.name, "description": t.description or ""} for t in listed],
                            source="gateway")

    def list_tools(self) -> list[types.Tool]:
        out = []
        for exposed, (server, t) in self.tools.items():
            out.append(types.Tool(name=exposed, description=f"[{server} via Reach] {t.description or ''}",
                                  input_schema=t.input_schema, annotations=t.annotations))
        return out

    def check(self, exposed: str) -> dict:
        server, t = self.tools[exposed]
        tool = estate.qualified(server, t.name)
        prior = Q.ro(self.g, TASK_LEGS, {"task": self.task})
        nxt = Q.ro(self.g, TOOL_LEGS, {"tool": tool})
        v = verdict(prior, nxt, tool)
        v["tool"] = tool
        return v

    def _record(self, tool: str, v: str, reason: str, args: dict) -> None:
        # learn the handoff: if another agent made the latest call on this task, it handed off to us
        agents = Q.ro(self.g, TASK_AGENTS, {"task": self.task})
        if agents and agents[0]["agent"] != self.agent:
            estate.delegate(self.g, agents[0]["agent"], self.agent, observed=True)
        seq = Q.ro(self.g, NEXT_SEQ, {"task": self.task})[0]["seq"]
        self.g.query(RECORD, {"task": self.task, "tool": tool, "seq": seq, "agent": self.agent,
                              "at": int(time.time() * 1000), "verdict": v, "reason": reason,
                              "args": json.dumps(args)[:500]})

    async def call(self, exposed: str, args: dict) -> types.CallToolResult:
        if exposed not in self.tools:
            return types.CallToolResult(content=[types.TextContent(text=f"Reach: unknown tool {exposed}")], is_error=True)
        v = self.check(exposed)
        if v["verdict"] == "blocked" and self.mode == "block":
            self._record(v["tool"], "blocked", v["reason"], args)
            p = v["path"]
            msg = (f"BLOCKED by Reach: {v['reason']}. Earlier in task {self.task}, untrusted "
                   f"{p['untrusted'][0]} entered via {p['untrusted'][1]} and private {p['private'][0]} "
                   f"was read via {p['private'][1]}; {p['sink'][1]} would send to {p['sink'][0]}. "
                   "Do not retry. Ask the user to review the task.")
            return types.CallToolResult(content=[types.TextContent(text=msg)], is_error=True,
                                        structured_content={"reach": v})
        server, t = self.tools[exposed]
        res = await self.clients[server].call_tool(t.name, args)
        self._record(v["tool"], "allowed" if v["verdict"] == "allowed" else "audit-would-block",
                     v.get("reason", ""), args)
        return res


def build_server(gw: Gateway, stack_owner: bool = True) -> Server:
    @asynccontextmanager
    async def lifespan(_server):
        async with AsyncExitStack() as stack:
            if stack_owner:
                await gw.open(stack)
            yield gw

    async def on_list_tools(ctx, params):
        return types.ListToolsResult(tools=gw.list_tools())

    async def on_call_tool(ctx, params):
        return await gw.call(params.name, params.arguments or {})

    return Server("reach-gateway", instructions=f"Reach gateway for agent {gw.agent}; task {gw.task}.",
                  lifespan=lifespan, on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--agent", required=True)
    ap.add_argument("--task")
    ap.add_argument("--audit", action="store_true", help="log would-block calls but let them through")
    a = ap.parse_args()
    from reach.db import connect

    gw = Gateway(connect(), a.agent, load_config(a.config), a.task, "audit" if a.audit else "block")
    server = build_server(gw)

    import anyio

    async def run():
        async with stdio_server() as (r, w):
            await server.run(r, w, server.create_initialization_options())

    anyio.run(run)


if __name__ == "__main__":
    main()
