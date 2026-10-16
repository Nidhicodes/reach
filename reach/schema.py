"""Uniqueness for concurrent writers.

FalkorDB's MERGE is not atomic across clients: two gateways that MERGE the same
(:Task {id}) at the same moment can both miss it and both create it (we measured 3
Task nodes from 4 processes). Unique constraints make the second CREATE fail instead,
and `write()` retries it, at which point the MERGE matches the node the winner made.
The same constraint on (:Call {task, seq}) is what makes sequence numbers unique.
"""

from __future__ import annotations

import random
import time

from reach import queries as Q

UNIQUE = [("Task", ("id",)), ("Call", ("task", "seq")), ("Agent", ("name",)), ("Tool", ("name",)),
          ("Server", ("name",)), ("Scope", ("name",)), ("Source", ("name",)), ("Data", ("name",)),
          ("Sink", ("name",)), ("Approval", ("id",))]

_done: set[str] = set()


def ensure(g) -> None:
    """Idempotent; once per graph per process."""
    key = getattr(g, "name", "") or str(id(g))
    if key in _done:
        return
    try:
        g.query("RETURN 1")  # a graph must exist before constraints can attach to it
        for label, props in UNIQUE:
            try:
                g.create_node_unique_constraint(label, *props)
            except Exception as e:  # already exists / still building
                if "already" not in str(e).lower() and "exists" not in str(e).lower():
                    raise
        _wait(g)
    except AttributeError:  # client without the constraint API: best effort
        pass
    _done.add(key)


def _wait(g, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        cs = g.list_constraints()
        if all(str(c.get("status", "")).upper() == "OPERATIONAL" for c in cs):
            return
        time.sleep(0.05)


def is_conflict(e: Exception) -> bool:
    s = str(e).lower()
    return "unique constraint" in s or "constraint violation" in s


def write(g, q: str, params: dict | None = None, retries: int = 30) -> list[dict]:
    """Run a write query, retrying when a concurrent writer won a unique-constraint race."""
    for i in range(retries):
        try:
            return Q.rows(g.query(q, params or {}))
        except Exception as e:
            if not is_conflict(e) or i == retries - 1:
                raise
            time.sleep(random.uniform(0.001, 0.004) * (i + 1))
    return []
