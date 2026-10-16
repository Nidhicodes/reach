import pytest

from reach.algos import chokepoints, explain_reach, flow_graph
from reach.db import connect
from reach.seed import seed


@pytest.fixture
def g(tmp_path):
    g = connect("algo_test", path=str(tmp_path / "a.db"))
    seed(g)
    yield g
    g.delete()
    flow_graph(g).delete()


def test_chokepoints_rank_cross_agent_hub_first(g):
    r = chokepoints(g)
    assert r["outcome"] == "answered_with_path"
    top = r["chokepoints"][0]
    # the two agents on the cross-agent handoff carry the most paths and flow
    assert top["name"] in ("sales-assistant", "research-agent")
    assert top["paths_through"] == 2 and top["score"] > 0
    assert chokepoints(g)["chokepoints"] == r["chokepoints"]  # reproducible
    # per-agent tool nodes, never a bare shared tool
    assert all("/" in c["name"] for c in r["chokepoints"] if c["kind"] == "Tool")


def test_explain_reach_crosses_the_handoff(g):
    r = explain_reach(g, "web-pages", "outbound-email")
    assert r["outcome"] == "answered_with_path"
    hops = r["routes"][0]["hops"]
    assert hops[0] == "web-pages" and hops[-1] == "outbound-email"
    assert "research-agent" in hops and "sales-assistant" in hops
    assert "DELEGATES" in r["routes"][0]["via"]


def test_explain_reach_outcomes(g):
    assert explain_reach(g, "web-pages", "no-such-thing")["outcome"] == "unknown_name"
    # sinks do not flow back into sources: exists, but no route
    assert explain_reach(g, "public-gist", "web-pages")["outcome"] == "not_in_graph"


def test_projection_respects_grants(g):
    # revoke the scope gmail.send needs from sales-assistant: the route must vanish
    g.query("MATCH (:Agent {name:'sales-assistant'})-[r:GRANTED]->(s:Scope)<-[:NEEDS]-(:Tool {name:'gmail.send'}) DELETE r")
    r = explain_reach(g, "crm-records", "outbound-email")
    assert all("sales-assistant/gmail.send" not in rt["hops"] for rt in r.get("routes", []))
