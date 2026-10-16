"""Ablation eval: does the graph find what scanners without one miss, and is it right?

1. Path detection on N random estates (fixed RNG seed, reproducible):
   - ORACLE   independent brute force in plain Python (no Cypher): ground truth
   - REACH    the TRIFECTA Cypher on FalkorDB
   - B_MANIFEST  per-agent scan of tool manifests, ignores grants and delegation
                 (what single-server / single-agent MCP scanners report)
   - B_AGENT     per-agent scan that respects grants, still no delegation
   Unit = (entry agent, untrusted source, private data, sink) tuple.

2. Runtime guard on traces derived from the oracle:
   - attack traces: ingest -> (handoffs) -> read -> send ; must be blocked at send
   - benign traces: read->send (no taint) and ingest->send (no private data); must pass
   Baseline = static permission check (allows any granted tool): blocks no attacks.

Usage: uv run python -m reach.eval [n_estates]
"""

from __future__ import annotations

import os
import random
import sys
import time
from collections import Counter

from reach import tools as T
from reach.queries import trifecta_paths
from reach.seed import seed

LEGS = ("INGESTS", "READS", "SENDS_TO")


def random_estate(rng: random.Random, i: int) -> dict:
    sources = [f"src{j}" for j in range(3)]
    data = [f"data{j}" for j in range(3)]
    sinks = [f"sink{j}" for j in range(3)]
    servers = [f"e{i}-srv{j}" for j in range(4)]
    tools = {}
    for j in range(rng.randint(10, 18)):
        legs = rng.sample(LEGS, 2 if rng.random() < 0.15 else 1)
        tools[f"e{i}-tool{j}"] = (
            rng.choice(servers), [f"scope{j}"],
            [rng.choice(sources)] if "INGESTS" in legs else [],
            [rng.choice(data)] if "READS" in legs else [],
            [rng.choice(sinks)] if "SENDS_TO" in legs else [],
        )
    agents = [f"e{i}-agent{j}" for j in range(rng.randint(4, 8))]
    usage = {}
    for a in agents:
        used = rng.sample(sorted(tools), rng.randint(2, 4))
        granted = [tools[t][1][0] for t in used if rng.random() < 0.8]
        usage[a] = (used, granted)
    dels = [(a, b) for a in agents for b in agents if a != b and rng.random() < 0.12]
    return {
        "AGENTS": [{"name": a, "owner": "eval"} for a in agents], "SERVERS": servers,
        "SOURCES": sources, "DATA": data, "SINKS": sinks, "TOOLS": tools,
        "USAGE": usage, "DELEGATIONS": dels,
    }


# ------------------------------------------------------------------ oracle + baselines


def _legs(est: dict, agent: str, respect_grants: bool) -> dict[str, set[tuple[str, str]]]:
    used, granted = est["USAGE"][agent]
    out = {leg: set() for leg in LEGS}
    for t in used:
        _, needs, ing, rd, snd = est["TOOLS"][t]
        if respect_grants and not set(needs) <= set(granted):
            continue
        for leg, names in zip(LEGS, (ing, rd, snd)):
            out[leg] |= {(t, n) for n in names}
    return out


def oracle(est: dict, max_hops: int = 3) -> set[tuple]:
    agents = [a["name"] for a in est["AGENTS"]]
    legs = {a: _legs(est, a, True) for a in agents}
    edges = est["DELEGATIONS"]
    found = set()

    def walk(chain: list[str], used_edges: set):
        entry, r = chain[0], chain[-1]
        for _, s in legs[entry]["INGESTS"]:
            for _, d in legs[r]["READS"]:
                for x in chain:
                    for _, k in legs[x]["SENDS_TO"]:
                        found.add((entry, s, d, k))
        if len(chain) - 1 < max_hops:
            for e in edges:
                if e[0] == r and e not in used_edges:
                    walk(chain + [e[1]], used_edges | {e})

    for a in agents:
        walk([a], set())
    return found


def per_agent(est: dict, respect_grants: bool) -> set[tuple]:
    found = set()
    for a in (x["name"] for x in est["AGENTS"]):
        l = _legs(est, a, respect_grants)
        found |= {(a, s, d, k) for _, s in l["INGESTS"] for _, d in l["READS"] for _, k in l["SENDS_TO"]}
    return found


def reach(g) -> set[tuple]:
    return {(p["entry"], p["untrusted"], p["private"], p["sink"]) for p in trifecta_paths(g)}


# ------------------------------------------------------------------ guard traces


def traces(est: dict, rng: random.Random, n: int = 6):
    """(agent_at_send, history, send_tool, expect_block) built from oracle facts."""
    agents = [a["name"] for a in est["AGENTS"]]
    legs = {a: _legs(est, a, True) for a in agents}
    out = []
    # attacks: single-agent and via one delegation edge
    for a in agents:
        for b in [a] + [y for x, y in est["DELEGATIONS"] if x == a]:
            if legs[a]["INGESTS"] and legs[b]["READS"] and legs[b]["SENDS_TO"]:
                out.append((b, [rng.choice(sorted(legs[a]["INGESTS"]))[0], rng.choice(sorted(legs[b]["READS"]))[0]],
                            rng.choice(sorted(legs[b]["SENDS_TO"]))[0], True))
    # benign: read->send without taint, ingest->send without private data
    for a in agents:
        L = legs[a]
        if L["READS"] and L["SENDS_TO"]:
            r, s = rng.choice(sorted(L["READS"]))[0], rng.choice(sorted(L["SENDS_TO"]))[0]
            if not (_tool_legs(est, r) & {"INGESTS"}) and not (_tool_legs(est, s) & {"INGESTS"}):
                out.append((a, [r], s, False))
        if L["INGESTS"] and L["SENDS_TO"]:
            i, s = rng.choice(sorted(L["INGESTS"]))[0], rng.choice(sorted(L["SENDS_TO"]))[0]
            if not (_tool_legs(est, i) & {"READS"}) and not (_tool_legs(est, s) & {"READS"}):
                out.append((a, [i], s, False))
    rng.shuffle(out)
    return out[: n * 2]


def _tool_legs(est: dict, tool: str) -> set[str]:
    _, _, ing, rd, snd = est["TOOLS"][tool]
    return {leg for leg, names in zip(LEGS, (ing, rd, snd)) if names}


# ------------------------------------------------------------------ run


def score(pred: set, truth: set) -> Counter:
    return Counter(tp=len(pred & truth), fp=len(pred - truth), fn=len(truth - pred))


def run(n: int = 30, seed_value: int = 7, db_path: str | None = None) -> dict:
    from reach.db import connect

    rng = random.Random(seed_value)
    g = connect("eval", path=db_path or os.environ.get("REACH_DB_PATH", "eval.db"))
    totals = {k: Counter() for k in ("reach", "b_manifest", "b_agent")}
    missed_estates = Counter()
    guard = Counter()
    ms = []
    cross_agent_truth = 0
    for i in range(n):
        est = random_estate(rng, i)
        seed(g, est)
        truth = oracle(est)
        cross_agent_truth += len(truth - per_agent(est, True))
        t = time.time()
        preds = {"reach": reach(g), "b_manifest": per_agent(est, False), "b_agent": per_agent(est, True)}
        ms.append((time.time() - t) * 1000)
        for k, p in preds.items():
            s = score(p, truth)
            totals[k] += s
            if s["fn"]:
                missed_estates[k] += 1
        for agent, hist, send, expect in traces(est, rng):
            v = T.guard_check(g, agent, hist, send)["outcome"]
            blocked = v == "blocked"
            guard[("attack" if expect else "benign", "blocked" if blocked else "allowed")] += 1
    g.delete()
    return {
        "n_estates": n, "truth_paths": sum(totals["reach"][x] for x in ("tp", "fn")),
        "cross_agent_truth": cross_agent_truth, "totals": totals, "missed_estates": missed_estates,
        "guard": guard, "reach_ms_median": sorted(ms)[len(ms) // 2],
    }


def report(r: dict) -> str:
    L = [f"{r['n_estates']} random estates, {r['truth_paths']} ground-truth trifecta paths "
         f"({r['cross_agent_truth']} only exist across agents). Median Reach query {r['reach_ms_median']:.0f} ms.",
         "", "| scanner | TP | FP | FN | estates with a miss |", "|---|---|---|---|---|"]
    names = {"b_manifest": "per-agent manifest scan (no grants, no graph)",
             "b_agent": "per-agent scan with grants (no graph)", "reach": "Reach (FalkorDB traversal)"}
    for k in ("b_manifest", "b_agent", "reach"):
        t = r["totals"][k]
        L.append(f"| {names[k]} | {t['tp']} | {t['fp']} | {t['fn']} | {r['missed_estates'][k]}/{r['n_estates']} |")
    gd = r["guard"]
    L += ["", "| runtime | attacks blocked | benign allowed |", "|---|---|---|",
          f"| static permission check | 0/{gd[('attack','blocked')] + gd[('attack','allowed')]} | "
          f"{gd[('benign','blocked')] + gd[('benign','allowed')]}/{gd[('benign','blocked')] + gd[('benign','allowed')]} |",
          f"| Reach guard | {gd[('attack','blocked')]}/{gd[('attack','blocked')] + gd[('attack','allowed')]} | "
          f"{gd[('benign','allowed')]}/{gd[('benign','blocked')] + gd[('benign','allowed')]} |"]
    return "\n".join(L)


if __name__ == "__main__":
    print(report(run(int(sys.argv[1]) if len(sys.argv) > 1 else 30)))
