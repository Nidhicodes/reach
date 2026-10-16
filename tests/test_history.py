import pytest

from reach import history as H
from reach.db import connect
from reach.seed import seed

K_SUPPORT = "support-bot|customer-tickets|customer-db|outbound-email"
K_CODE = "code-reviewer|public-github-issues|private-repos|public-gist"


@pytest.fixture
def g(tmp_path):
    graph = connect("hist_test", path=str(tmp_path / "h.db"))
    seed(graph)
    yield graph
    graph.delete()


def test_baseline_then_attributed_close_and_reopen(g):
    s0 = H.record_scan(g, at=1000)
    assert s0["baseline"] and s0["open"] >= 4 and not s0["opened"]

    H.apply_change(g, "revoke", "support-bot", "mail:send", actor="alice", at=2000)
    s1 = H.record_scan(g, at=3000)
    assert [c["key"] for c in s1["closed"]] == [K_SUPPORT]
    assert s1["closed"][0]["closed_by"][0]["target"] == "mail:send"

    H.apply_change(g, "grant", "support-bot", "mail:send", actor="bob", at=4000)
    s2 = H.record_scan(g, at=5000)
    assert [o["key"] for o in s2["opened"]] == [K_SUPPORT]
    assert s2["opened"][0]["opened_by"][0]["at"] == 4000

    h = H.finding_history(g, K_SUPPORT)
    assert h["status"] == "open" and h["first_seen"] == 1000
    assert {c["at"] for c in h["opened_by"]} == {4000}


def test_unrelated_change_is_not_blamed(g):
    H.record_scan(g, at=1000)
    H.apply_change(g, "revoke", "support-bot", "mail:send", at=2000)
    H.apply_change(g, "revoke", "code-reviewer", "gist:write", at=2100)
    s = H.record_scan(g, at=3000)
    by_key = {c["key"]: [x["agent"] for x in c["closed_by"]] for c in s["closed"]}
    assert by_key[K_SUPPORT] == ["support-bot"] and by_key[K_CODE] == ["code-reviewer"]


def test_open_at_answers_the_past(g):
    H.record_scan(g, at=1000)
    H.apply_change(g, "revoke", "support-bot", "mail:send", at=2000)
    H.record_scan(g, at=3000)
    then = {f["key"] for f in H.open_at(g, 1500)["findings"]}
    now = {f["key"] for f in H.open_at(g, 3500)["findings"]}
    assert K_SUPPORT in then and K_SUPPORT not in now
    assert H.open_at(g, 10)["outcome"] == "not_in_graph"


def test_unknown_names_change_nothing(g):
    assert H.apply_change(g, "grant", "ghost-agent", "mail:send")["outcome"] == "unknown_agent"
    assert H.apply_change(g, "grant", "support-bot", "root:*")["outcome"] == "unknown_scope"
