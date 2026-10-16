import pytest

from reach import tools as T
from reach.db import connect
from reach.seed import seed


@pytest.fixture(scope="module")
def g(tmp_path_factory):
    graph = connect("reach_tools_test", path=str(tmp_path_factory.mktemp("db") / "t.db"))
    seed(graph)
    yield graph
    graph.delete()


def test_unknown_names_run_nothing(g):
    assert T.scan_paths(g, "payment-agent")["outcome"] == "unknown_agent"
    assert T.explain_tool(g, "github.delete_repo")["outcome"] == "unknown_tool"
    assert T.guard_check(g, "support-bot", ["nope"], "gmail.send")["outcome"] == "unknown_tool"


def test_clean_agent_is_not_in_graph_not_safe(g):
    r = T.scan_paths(g, "ops-bot")
    assert r["outcome"] == "not_in_graph" and "Unmodelled" in r["note"]


def test_guard_blocks_third_leg(g):
    r = T.guard_check(g, "support-bot", ["zendesk.read_ticket", "postgres.query"], "gmail.send")
    assert r["outcome"] == "blocked"
    assert r["path"]["sink"] == ("gmail.send", "outbound-email")


def test_guard_allows_send_without_taint(g):
    assert T.guard_check(g, "support-bot", ["postgres.query"], "gmail.send")["outcome"] == "allowed"


def test_guard_taint_follows_delegation(g):
    # research-agent fetched a web page, handed off; sales-assistant read CRM, now emails.
    r = T.guard_check(g, "sales-assistant", ["browser.fetch", "crm.lookup"], "gmail.send")
    assert r["outcome"] == "blocked"


def test_guard_refuses_ungranted_tool(g):
    assert T.guard_check(g, "ops-bot", [], "slack.post")["outcome"] == "blocked"


def test_fix_requires_human_approval(g):
    r = T.propose_fix(g)
    assert r["requires_human_approval"] and r["paths_total"] >= 4
