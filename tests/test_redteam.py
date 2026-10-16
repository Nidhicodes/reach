import pytest

from reach.db import connect
from reach.redteam import replay
from reach.seed import seed


@pytest.fixture(scope="module")
def g(tmp_path_factory):
    graph = connect("redteam_test", path=str(tmp_path_factory.mktemp("db") / "r.db"))
    seed(graph)
    yield graph
    graph.delete()


@pytest.mark.parametrize("scenario", ["support", "cross-agent"])
def test_injection_succeeds_without_guard_and_fails_with_it(g, scenario):
    assert replay(g, scenario, guard=False).exfiltrated
    run = replay(g, scenario, guard=True)
    assert not run.exfiltrated
    blocked = [e for e in run.events if e.verdict == "BLOCKED"]
    assert len(blocked) == 1 and blocked[0].tool == "gmail.send" and blocked[0].path


def test_cross_agent_block_happens_on_the_clean_agent(g):
    # sales-assistant never ingested untrusted input itself; taint came via delegation.
    run = replay(g, "cross-agent", guard=True)
    assert [e.agent for e in run.events if e.verdict == "BLOCKED"] == ["sales-assistant"]
