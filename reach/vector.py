"""Vector + graph classification for tools nobody has written a rule for.

Every Tool gets an embedding of "server tool-name: description" (BAAI/bge-small-en-v1.5,
384 dims, via fastembed -- the `vector` extra) stored on the node, with a FalkorDB
vector index over it. A tool from an UNKNOWN server is classified by its nearest
labelled neighbours: the vector index finds where to start, the graph supplies what
those neighbours are known to do (their INGESTS / READS / SENDS_TO edges), and the
legs win by similarity-weighted vote. The answer cites the neighbours it used.

  uv run --extra vector python -m reach.vector "acme-mail" "dispatch_message" "Send a message to any address"
"""

from __future__ import annotations

import os
import pathlib

from reach import queries as Q
from reach.classify import normalise

MODEL = "BAAI/bge-small-en-v1.5"
DIM = 384
_model = None

KNN = """
CALL db.idx.vector.queryNodes('Tool', 'emb', $k, vecf32($v)) YIELD node, score
WHERE node.server <> $server
RETURN node.name AS name, node.server AS server, score,
       node.l_untrusted AS untrusted, node.l_private AS private, node.l_external AS external,
       node.l_acts AS acts
ORDER BY score ASC
"""


def text(server: str, tool: str, description: str) -> str:
    return f"{server} {normalise(tool)}: {(description or '')[:400]}"


def embed(texts: list[str]) -> list[list[float]]:
    global _model
    if _model is None:
        from fastembed import TextEmbedding  # optional extra: `uv sync --extra vector`

        cache = os.environ.get("FASTEMBED_CACHE_PATH") or str(pathlib.Path(__file__).resolve().parents[1] / ".cache/fastembed")
        _model = TextEmbedding(MODEL, cache_dir=cache)
    return [list(map(float, v)) for v in _model.embed(texts)]


def index_tools(g, rows: list[dict]) -> int:
    """rows: [{name, server, text, untrusted?, private?, external?}] -> Tool nodes with emb + labels."""
    vecs = embed([r["text"] for r in rows])
    batch = [{"n": r["name"], "s": r["server"], "v": v, "u": r.get("untrusted"), "p": r.get("private"),
              "e": r.get("external"), "a": r.get("acts")} for r, v in zip(rows, vecs)]
    for i in range(0, len(batch), 100):
        g.query("UNWIND $rows AS r MERGE (t:Tool {name: r.n}) SET t.server = r.s, t.emb = vecf32(r.v), "
                "t.l_untrusted = r.u, t.l_private = r.p, t.l_external = r.e, t.l_acts = r.a", {"rows": batch[i:i + 100]})
    try:
        g.create_node_vector_index("Tool", "emb", dim=DIM, similarity_function="cosine")
    except Exception as e:
        if "already" not in str(e).lower():
            raise
    return len(batch)


def neighbours(g, server: str, vec: list[float], k: int = 7, pool: int = 60) -> list[dict]:
    rows = Q.ro(g, KNN, {"k": pool, "v": vec, "server": server})
    return rows[:k]


def vote(nb: list[dict], threshold: float = 0.5) -> dict:
    """Cosine *distance* comes back (0 = identical); weight = 1 - distance."""
    out = {}
    w = [max(0.0, 1 - n["score"]) for n in nb]
    tot = sum(w) or 1.0
    for leg in ("untrusted", "private", "external", "acts"):
        share = sum(wi for wi, n in zip(w, nb) if n.get(leg)) / tot
        out[leg] = share >= threshold
        out[f"{leg}_share"] = round(share, 2)
    return out


def classify(g, server: str, tool: str, description: str, k: int = 7) -> dict:
    v = embed([text(server, tool, description)])[0]
    nb = neighbours(g, server, v, k)
    return {**vote(nb), "neighbours": [{"name": n["name"], "similarity": round(1 - n["score"], 3)} for n in nb]}


if __name__ == "__main__":
    import json
    import sys

    from reach.db import connect

    print(json.dumps(classify(connect("classeval"), *sys.argv[1:4]), indent=1))
