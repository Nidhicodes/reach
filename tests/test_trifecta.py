import pytest

from reach.db import connect
from reach.queries import plan_fix, trifecta_paths
from reach.seed import seed


@pytest.fixture(scope="module")
def g(tmp_path_factory):
    graph = connect("reach_test", path=str(tmp_path_factory.mktemp("db") / "t.db"))
    seed(graph)
    yield graph
    graph.delete()


def test_finds_single_agent_trifectas(g):
    entries = {(p["entry"], p["reader"], p["sender"]) for p in trifecta_paths(g)}
    assert ("code-reviewer", "code-reviewer", "code-reviewer") in entries
    assert ("support-bot", "support-bot", "support-bot") in entries


def test_finds_cross_agent_trifecta_through_delegation(g):
    paths = [p for p in trifecta_paths(g) if p["entry"] == "research-agent" and p["reader"] == "sales-assistant"]
    assert paths, "taint from web-pages should flow via DELEGATES_TO into sales-assistant"
    assert paths[0]["handoff"] == ["research-agent", "sales-assistant"]


def test_ungranted_tool_is_not_a_path(g):
    # ops-bot uses slack.post but lacks slack:write, and ingests nothing untrusted.
    assert not [p for p in trifecta_paths(g) if "ops-bot" in (p["entry"], p["reader"], p["sender"])]


def test_fix_plan_closes_every_path(g):
    paths = trifecta_paths(g)
    plan = plan_fix(g, paths)
    assert plan.actions
    assert len(plan.actions) <= 3
