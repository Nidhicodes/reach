"""Graph connection.

Two backends, same Cypher:
- FALKORDB_HOST set  -> real FalkorDB server (Docker / self-hosted / FalkorDB Cloud).
- otherwise          -> embedded FalkorDBLite (no Docker needed for local dev).
"""

from __future__ import annotations

import os

DEFAULT_GRAPH = "reach"


def connect(graph: str | None = None, path: str | None = None):
    """Return a FalkorDB Graph handle.

    `graph` names the graph; one instance holds one graph per tenant.
    `path` is only used by the embedded backend (file the data lives in).
    """
    name = graph or os.environ.get("REACH_GRAPH", DEFAULT_GRAPH)
    host = os.environ.get("FALKORDB_HOST")
    if host:
        from falkordb import FalkorDB

        db = FalkorDB(
            host=host,
            port=int(os.environ.get("FALKORDB_PORT", "6379")),
            username=os.environ.get("FALKORDB_USERNAME"),
            password=os.environ.get("FALKORDB_PASSWORD"),
        )
    else:
        from redislite.falkordb_client import FalkorDB  # provided by falkordblite

        db = FalkorDB(path or os.environ.get("REACH_DB_PATH", "reach.db"))
    return db.select_graph(name)
