import asyncio
import json

import pytest
from mcp.client.client import Client


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("REACH_ESTATE", "demo")
    monkeypatch.setenv("REACH_GRAPH", "reach_mcp_test")
    monkeypatch.setenv("REACH_DB_PATH", str(tmp_path / "m.db"))
    from reach import mcp_server

    mcp_server.graph.cache_clear()
    yield mcp_server.mcp
    mcp_server.graph().delete()
    mcp_server.graph.cache_clear()


def _payload(res) -> dict:
    if getattr(res, "structured_content", None):
        sc = res.structured_content
        return sc.get("result", sc)
    return json.loads(res.content[0].text)


def test_mcp_exposes_catalogue_and_guard(server):
    async def run():
        async with Client(server) as c:
            names = {t.name for t in (await c.list_tools()).tools}
            assert names == {"list_agents", "scan_paths", "explain_tool", "propose_fix", "guard_check",
                             "record_scan", "scan_timeline", "finding_history", "open_at",
                             "chokepoints", "explain_reach", "propose_hardening"}
            scan = _payload(await c.call_tool("scan_paths", {"agent": "support-bot"}))
            assert scan["outcome"] == "answered_with_path"
            g = _payload(await c.call_tool("guard_check", {
                "agent": "support-bot",
                "history": ["zendesk.read_ticket", "postgres.query"],
                "next_tool": "gmail.send",
            }))
            assert g["outcome"] == "blocked"

    asyncio.run(run())
