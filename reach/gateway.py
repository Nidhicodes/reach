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
from reach import schema

SEP = "__"

# Legs of every call earlier in this task that did (or may still) run. 'pending' calls
# are in flight in another gateway right now; counting them is the conservative choice.
TASK_LEGS = """
MATCH (:Task {id: $task})<-[:IN_TASK]-(c:Call)-[:CALLED]->(t:Tool)-[e:INGESTS|READS|SENDS_TO]->(n)
WHERE c.seq < $seq AND c.verdict IN ['allowed', 'pending', 'audit-would-block', 'approved']
RETURN c.seq AS seq, c.agent AS agent, t.name AS tool, type(e) AS leg, n.name AS target
ORDER BY seq
"""
TOOL_LEGS = "MATCH (t:Tool {name: $tool})-[e:INGESTS|READS|SENDS_TO]->(n) RETURN type(e) AS leg, n.name AS target"
# Reserve a sequence number and record the call as 'pending' in ONE write query.
# FalkorDB runs write queries on a graph one at a time, so two gateway processes can
# never take the same seq, and whichever call reserves second sees the first one. That
# closes the check-then-act race a per-process guard has.
RESERVE = """
MERGE (k:Task {id: $task})
WITH k
OPTIONAL MATCH (k)<-[:IN_TASK]-(p:Call)
WITH k, coalesce(max(p.seq), 0) + 1 AS seq
OPTIONAL MATCH (k)<-[:IN_TASK]-(prev:Call {seq: seq - 1})
WITH k, seq, prev.agent AS prev_agent
MATCH (t:Tool {name: $tool})
CREATE (c:Call {task: $task, seq: seq, agent: $agent, at: $at, verdict: 'pending', reason: '', args: $args})
CREATE (c)-[:IN_TASK]->(k)
CREATE (c)-[:CALLED]->(t)
RETURN seq, prev_agent
"""
FINALISE = """
MATCH (:Task {id: $task})<-[:IN_TASK]-(c:Call {seq: $seq})
SET c.verdict = $verdict, c.reason = $reason
"""
# Human-in-the-loop: an Approval node the UI (or `reach approve`) decides, from any process.
ASK = """
MATCH (:Task {id: $task})<-[:IN_TASK]-(c:Call {seq: $seq})
CREATE (a:Approval {id: $id, status: 'pending', at: $at, task: $task, agent: $agent, tool: $tool, why: $why})
CREATE (a)-[:FOR]->(c)
"""
APPROVAL = "MATCH (a:Approval {id: $id}) RETURN a.status AS status, a.by AS by"
DECIDE = """
MATCH (a:Approval {id: $id}) WHERE a.status = 'pending'
SET a.status = $status, a.by = $by, a.decided_at = $at
RETURN a.id AS id, a.status AS status
"""
PENDING = """
MATCH (a:Approval {status: 'pending'})
RETURN a.id AS id, a.task AS task, a.agent AS agent, a.tool AS tool, a.why AS why, a.at AS at
ORDER BY at
"""


def decide(g, approval_id: str, approve: bool, by: str = "human") -> dict | None:
    rows = Q.rows(g.query(DECIDE, {"id": approval_id, "status": "approved" if approve else "denied",
                                   "by": by, "at": int(time.time() * 1000)}))
    return rows[0] if rows else None


def pending_approvals(g) -> list[dict]:
    return Q.ro(g, PENDING)


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
    """mode: 'block' (default), 'audit' (log only) or 'ask' (hold the call for a human)."""

    def __init__(self, g, agent: str, upstreams: dict, task: str | None = None, mode: str = "block",
                 ask_timeout: float = 120.0, poll: float = 0.5):
        self.g, self.agent, self.upstreams, self.mode = g, agent, upstreams, mode
        self.ask_timeout, self.poll = ask_timeout, poll
        self.task = task or os.environ.get("REACH_TASK") or f"task-{uuid.uuid4().hex[:8]}"
        self.clients: dict[str, Client] = {}
        self.tools: dict[str, tuple[str, types.Tool]] = {}  # exposed name -> (server, upstream tool)
        schema.ensure(g)

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

    def check(self, exposed: str, args: dict | None = None) -> dict:
        """Reserve this call in the task ledger, then decide it against every earlier call."""
        server, t = self.tools[exposed]
        tool = estate.qualified(server, t.name)
        r = schema.write(self.g, RESERVE, {"task": self.task, "tool": tool, "agent": self.agent,
                                          "at": int(time.time() * 1000),
                                           "args": json.dumps(args or {})[:500]})[0]
        seq = r["seq"]
        # learn the handoff: if another agent made the previous call on this task, it handed off to us
        if r["prev_agent"] and r["prev_agent"] != self.agent:
            estate.delegate(self.g, r["prev_agent"], self.agent, observed=True)
        prior = Q.ro(self.g, TASK_LEGS, {"task": self.task, "seq": seq})
        nxt = Q.ro(self.g, TOOL_LEGS, {"tool": tool})
        v = verdict(prior, nxt, tool)
        v.update(tool=tool, seq=seq)
        return v

    def _finalise(self, seq: int, v: str, reason: str = "") -> None:
        self.g.query(FINALISE, {"task": self.task, "seq": seq, "verdict": v, "reason": reason})

    async def _ask(self, v: dict) -> str:
        """Hold the call until a human decides it (UI / `reach approve`), from any process."""
        import anyio

        aid = f"ap-{uuid.uuid4().hex[:8]}"
        p = v["path"]
        why = (f"untrusted {p['untrusted'][0]} via {p['untrusted'][1]}, private {p['private'][0]} via "
               f"{p['private'][1]}, now {p['sink'][1]} -> {p['sink'][0]}")
        self.g.query(ASK, {"task": self.task, "seq": v["seq"], "id": aid, "at": int(time.time() * 1000),
                           "agent": self.agent, "tool": v["tool"], "why": why})
        v["approval"] = aid
        deadline = time.monotonic() + self.ask_timeout
        while time.monotonic() < deadline:
            st = Q.ro(self.g, APPROVAL, {"id": aid})
            if st and st[0]["status"] != "pending":
                return st[0]["status"]
            await anyio.sleep(self.poll)
        decide(self.g, aid, False, by="timeout")
        return "timeout"

    def _blocked(self, v: dict, reason: str) -> types.CallToolResult:
        p = v["path"]
        msg = (f"BLOCKED by Reach: {reason}. Earlier in task {self.task}, untrusted "
               f"{p['untrusted'][0]} entered via {p['untrusted'][1]} and private {p['private'][0]} "
               f"was read via {p['private'][1]}; {p['sink'][1]} would send to {p['sink'][0]}. "
               "Do not retry. Ask the user to review the task.")
        return types.CallToolResult(content=[types.TextContent(text=msg)], is_error=True,
                                    structured_content={"reach": v})

    async def call(self, exposed: str, args: dict) -> types.CallToolResult:
        if exposed not in self.tools:
            return types.CallToolResult(content=[types.TextContent(text=f"Reach: unknown tool {exposed}")], is_error=True)
        v = self.check(exposed, args)
        if v["verdict"] == "blocked":
            if self.mode == "block":
                self._finalise(v["seq"], "blocked", v["reason"])
                return self._blocked(v, v["reason"])
            if self.mode == "ask":
                decision = await self._ask(v)
                if decision != "approved":
                    self._finalise(v["seq"], "denied", f"{v['reason']}; human said {decision}")
                    return self._blocked(v, f"{v['reason']} (held for approval: {decision})")
                self._finalise(v["seq"], "approved", v["reason"])
            else:
                self._finalise(v["seq"], "audit-would-block", v["reason"])
        server, t = self.tools[exposed]
        try:
            res = await self.clients[server].call_tool(t.name, args)
        except Exception as e:
            self._finalise(v["seq"], "error", str(e)[:200])
            raise
        if v["verdict"] == "allowed":
            self._finalise(v["seq"], "allowed")
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
    ap.add_argument("--ask", action="store_true", help="hold would-block calls for a human decision")
    ap.add_argument("--ask-timeout", type=float, default=120.0)
    ap.add_argument("--only", help="comma-separated servers from --config to proxy (default: all)")
    a = ap.parse_args()
    from reach.db import connect

    mode = "audit" if a.audit else "ask" if a.ask else "block"
    ups = load_config(a.config)
    if a.only:
        keep = set(a.only.split(","))
        ups = {k: v for k, v in ups.items() if k in keep}
    gw = Gateway(connect(), a.agent, ups, a.task, mode, ask_timeout=a.ask_timeout)
    server = build_server(gw)

    import anyio

    async def run():
        async with stdio_server() as (r, w):
            await server.run(r, w, server.create_initialization_options())

    anyio.run(run)


if __name__ == "__main__":
    main()
