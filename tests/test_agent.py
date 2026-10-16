import asyncio

import pytest

from reach import agent as A


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("REACH_ESTATE", "demo")
    monkeypatch.setenv("REACH_GRAPH", "reach_agent_test")
    monkeypatch.setenv("REACH_DB_PATH", str(tmp_path / "a.db"))
    monkeypatch.delenv("REACH_LLM_BASE_URL", raising=False)
    from reach import mcp_server

    mcp_server.graph.cache_clear()
    yield mcp_server.mcp
    mcp_server.graph().delete()
    mcp_server.graph.cache_clear()


def test_checker_rejects_invented_names():
    res = [{"outcome": "answered_with_path", "paths": [{"handoff": ["support-bot"], "sink": "outbound-email"}]}]
    assert A.accepts("support-bot can leak via outbound-email.", res)[0]
    ok, why = A.accepts("support-bot can leak via auth-gateway.", res)
    assert not ok and "auth-gateway" in why


def test_checker_rejects_safe_on_empty():
    assert not A.accepts("ops-bot is safe.", [{"outcome": "not_in_graph"}])[0]


def test_checker_sees_through_unicode_hyphens():
    res = [{"outcome": "answered_with_path", "paths": [{"handoff": ["support-bot"]}]}]
    ok, why = A.accepts("support\u2011bot leaks via billing\u2011api.", res)
    assert not ok and "billing-api" in why
    assert A.accepts("support\u2011bot leaks.", res)[0]


def test_offline_answers_with_path(server):
    a = asyncio.run(A.ask("what can support-bot reach?", server))
    assert a.planner == "offline-router" and a.outcome == "answered_with_path"
    assert "customer-tickets -> support-bot -> customer-db -> outbound-email" in a.text
    assert [s.tool for s in a.trace] == ["scan_paths"]


def test_offline_unknown_agent_runs_nothing_else(server):
    a = asyncio.run(A.ask("what can payment-agent reach?", server))
    assert a.outcome == "unknown_agent" and "not in the graph" in a.text


def test_llm_hallucination_degrades_to_rows(server, monkeypatch):
    monkeypatch.setenv("REACH_LLM_BASE_URL", "http://fake")
    script = iter([
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": "1", "type": "function", "function": {"name": "scan_paths", "arguments": '{"agent": "support-bot"}'}}]},
        {"role": "assistant", "content": "support-bot can exfiltrate via billing-api."},
    ])
    monkeypatch.setattr(A.LLM, "chat", lambda self, m, t: next(script))
    a = asyncio.run(A.ask("what can support-bot reach?", server))
    assert "billing-api" in a.checked
    assert "billing-api" not in a.text and "outbound-email" in a.text
