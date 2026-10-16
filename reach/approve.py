"""Decide calls a gateway in ask mode is holding, from any terminal.

  uv run python -m reach.approve                 # list pending
  uv run python -m reach.approve yes ap-1234abcd
  uv run python -m reach.approve no  ap-1234abcd

Uses the same FalkorDB as the gateways (FALKORDB_HOST or the embedded file).
"""

from __future__ import annotations

import getpass
import sys

from reach.db import connect
from reach.gateway import decide, pending_approvals


def main(argv: list[str]) -> int:
    g = connect()
    if not argv:
        rows = pending_approvals(g)
        for p in rows:
            print(f"{p['id']}  task={p['task']}  {p['agent']} -> {p['tool']}\n    {p['why']}")
        print(f"{len(rows)} pending")
        return 0
    if len(argv) != 2 or argv[0] not in ("yes", "no"):
        print(__doc__)
        return 2
    r = decide(g, argv[1], argv[0] == "yes", by=getpass.getuser())
    print(r or f"no pending approval {argv[1]}")
    return 0 if r else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
