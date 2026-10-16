import pytest

from reach import web


@pytest.fixture(autouse=True)
def fresh(tmp_path, monkeypatch):
    monkeypatch.setenv("REACH_DB_PATH", str(tmp_path / "ui.db"))
    monkeypatch.setenv("KIROCREW_SCRATCH", str(tmp_path))
    monkeypatch.delenv("REACH_PUBLIC", raising=False)
    monkeypatch.delenv("REACH_LLM_BASE_URL", raising=False)
    web._graphs.clear()
    yield
    for g in web._graphs.values():
        try:
            g.delete()
        except Exception:
            pass
    web._graphs.clear()


def call(path, q=None, body=None, method=None):
    return web.api(method or ("POST" if body is not None else "GET"), path, q or {}, body or {})


def test_chokepoints_and_reach_endpoints():
    c = call("/api/chokepoints", {"estate": "demo"})
    assert c["outcome"] == "answered_with_path" and c["chokepoints"]
    r = call("/api/reach", {"estate": "demo", "src": "web-pages", "dst": "outbound-email"})
    assert r["routes"][0]["hops"][0] == "web-pages"


def test_gateway_run_blocks_when_enforcing_and_fills_ledger_and_estate():
    for scn in ("support", "cross-agent"):
        r = call("/api/gateway/run", body={"scenario": scn})
        audit, block = r["runs"]
        assert audit["mode"] == "audit" and audit["exfiltrated"]
        assert block["mode"] == "block" and not block["exfiltrated"]
        assert block["events"][-1]["blocked"]
    led = call("/api/gateway/ledger")["calls"]
    assert {c["verdict"] for c in led} >= {"allowed", "blocked", "audit-would-block"}
    est = call("/api/estate", {"estate": "gateway"})
    assert {"research-agent", "sales-assistant"} <= {n["id"] for n in est["nodes"]}
    assert {"src": "research-agent", "dst": "sales-assistant"} in est["delegations"]  # learned from the task


def test_sample_setup_scan_and_severity_on_paths():
    rep = call("/api/setup", body={"which": "sample"})
    assert rep["paths"] > 0 and rep["severity"].get("all-legs-auto-approved", 0) >= 1
    p = call("/api/paths", {"estate": "sample"})
    assert all("severity" in x for x in p["paths"])


def test_public_mode_refuses_this_machine(monkeypatch):
    monkeypatch.setenv("REACH_PUBLIC", "1")
    assert call("/api/config")["public"] is True
    with pytest.raises(ValueError):
        call("/api/setup", body={"which": "mine"})
    with pytest.raises(ValueError):
        call("/api/paths", {"estate": "mine"})


def test_empty_gateway_estate_reads_cleanly():
    assert call("/api/estate", {"estate": "gateway"})["nodes"] == []
    assert call("/api/paths", {"estate": "gateway"})["outcome"] == "not_in_graph"
