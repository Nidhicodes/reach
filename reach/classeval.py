"""How good is the tool classifier? Measured, not asserted.

Ground truth: 557 real MCP tools, each labelled by TWO different LLMs (gpt-oss-120b and
gpt-oss-20b) that never saw Reach's rules (scripts/label_tools.py). Per leg we report
their agreement (Cohen's kappa) and score classifiers only on the tools where both
labelers agree. These are model labels, not human ones.

Classifiers, per leg:
  curated         the audited per-server regex rules Reach uses for known servers
  generic         the name-only fallback rules, as if every server were new to Reach
  vector          FalkorDB vector index: 7 nearest tools from OTHER servers vote
  generic+vector  union, which is what Reach does for an unknown server

Leave-one-server-out: when scoring a `stripe` tool, no stripe tool is a neighbour, and
neighbour labels are labeler A's. So vector measures a server Reach has never seen.

  uv run --extra vector python -m reach.classeval
"""

from __future__ import annotations

import json
import re

from reach import vector as V
from reach.classify import GENERIC_RULES, classify, normalise
from reach.paths import DATA

LABELS = DATA / "labels/tools.jsonl"
LABELS_B = DATA / "labels/tools_b.jsonl"
LEG = {"INGESTS": "untrusted", "READS": "private", "SENDS_TO": "external"}
LEGS = ("untrusted", "private", "external", "acts")


def _legs(rules) -> dict:
    s = {LEG[r.leg] for r in rules}
    return {k: k in s for k in LEGS}


def generic(tool: str) -> dict:
    t = normalise(tool)
    return _legs([r for r in GENERIC_RULES if re.search(r.tool, t)])


def kappa(a: list[bool], b: list[bool]) -> float | None:
    n = len(a)
    if not n:
        return None
    po = sum(x == y for x, y in zip(a, b)) / n
    pa, pb = sum(a) / n, sum(b) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    return round((po - pe) / (1 - pe), 2) if pe < 1 else None


def score(rows: list[dict], pred_key: str, leg: str) -> dict:
    tp = sum(r[leg] and r[pred_key][leg] for r in rows)
    fp = sum(not r[leg] and r[pred_key][leg] for r in rows)
    fn = sum(r[leg] and not r[pred_key][leg] for r in rows)
    return {"n": len(rows), "tp": tp, "fp": fp, "fn": fn,
            "precision": round(tp / (tp + fp), 2) if tp + fp else None,
            "recall": round(tp / (tp + fn), 2) if tp + fn else None}


def load(path) -> dict:
    return {(r["server"], r["tool"]): r for r in map(json.loads, path.read_text().splitlines())}


def run(k: int = 7, graph: str = "classeval") -> dict:
    from reach.db import connect

    a, b = load(LABELS), load(LABELS_B) if LABELS_B.exists() else {}
    rows = list(a.values())
    g = connect(graph)
    try:
        g.delete()
    except Exception:
        pass
    g = connect(graph)
    for r in rows:
        r["name"], r["text"] = f"{r['server']}.{r['tool']}", V.text(r["server"], r["tool"], r["description"])
    V.index_tools(g, rows)
    vecs = V.embed([r["text"] for r in rows])
    for r, v in zip(rows, vecs):
        r["curated"] = _legs(classify(r["server"], r["tool"]))
        r["generic"] = generic(r["tool"])
        r["vector"] = {leg: x for leg, x in V.vote(V.neighbours(g, r["server"], v, k)).items() if leg in LEGS}
        r["generic+vector"] = {leg: r["generic"][leg] or r["vector"][leg] for leg in LEGS}
    g.delete()
    both = [(r, b[(r["server"], r["tool"])]) for r in rows if (r["server"], r["tool"]) in b]
    report = {"tools": len(rows), "double_labelled": len(both), "servers": len({r["server"] for r in rows}),
              "labelers": [rows[0]["labeler"], next(iter(b.values()))["labeler"] if b else None], "k": k,
              "kappa": {}, "agreed": {}, "results": {}}
    for leg in LEGS:
        report["kappa"][leg] = kappa([x[leg] for x, _ in both], [y[leg] for _, y in both])
        agreed = [x for x, y in both if x[leg] == y[leg]] if both else rows
        report["agreed"][leg] = {"n": len(agreed), "positives": sum(x[leg] for x in agreed)}
        for c in ("curated", "generic", "vector", "generic+vector"):
            if leg == "acts" and c in ("curated", "generic"):
                continue  # the regex rules have no state-change leg
            report["results"].setdefault(c, {})[leg] = score(agreed, c, leg)
    return report


def table(rep: dict) -> str:
    lines = ["| classifier | leg | precision | recall | tp | fp | fn |", "|---|---|---|---|---|---|---|"]
    for c, res in rep["results"].items():
        for leg, x in res.items():
            lines.append(f"| {c} | {leg} | {x['precision']} | {x['recall']} | {x['tp']} | {x['fp']} | {x['fn']} |")
    return "\n".join(lines)


if __name__ == "__main__":
    rep = run()
    print(table(rep))
    print(json.dumps({k: v for k, v in rep.items() if k != "results"}, indent=1))
