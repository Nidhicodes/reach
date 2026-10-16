from reach.eval import report, run


def test_reach_matches_oracle_and_baselines_miss_cross_agent(tmp_path):
    r = run(n=8, seed_value=7, db_path=str(tmp_path / "e.db"))
    t = r["totals"]
    assert t["reach"]["fp"] == 0 and t["reach"]["fn"] == 0
    assert t["b_agent"]["fn"] == r["cross_agent_truth"]  # grants-aware scanner misses exactly the cross-agent paths
    g = r["guard"]
    assert g[("attack", "allowed")] == 0 and g[("benign", "blocked")] == 0
    assert "Reach (FalkorDB traversal)" in report(r)
