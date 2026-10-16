"""Run the real-tool estate end to end and print paths + fix plans.

Usage: uv run python scripts/demo_real.py [db_path]
"""

import sys
import time

from reach.db import connect
from reach.queries import plan_fix, trifecta_paths, zero_break_plan
from reach.real_estate import seed_real

db_path = sys.argv[1] if len(sys.argv) > 1 else "reach_demo.db"
g = connect("real", path=db_path)
print(seed_real(g))

t = time.time()
paths = trifecta_paths(g)
print(f"{len(paths)} trifecta paths in {round((time.time() - t) * 1000)} ms")
for p in paths:
    print(f"  {p['entry']:16} {p['untrusted']:18} -> {p['handoff']} -> {p['private']:16} -> {p['sink']:18}"
          f" legs(tools) {len(p['in_tools'])}/{len(p['read_tools'])}/{len(p['out_tools'])}")

plan, residual = zero_break_plan(g, paths)
print(f"\nZERO-BREAK plan: cost {plan.cost}, closes {plan.closes} paths")
for a in plan.actions:
    print("  -", a.describe())
print(f"RESIDUAL (cannot close without breaking a workflow): {len(residual)}")
for p in residual:
    print(f"  {p['entry']} {p['untrusted']} -> {p['private']} -> {p['sink']}")

full = plan_fix(g, paths)
print(f"\nCLOSE-EVERYTHING plan: cost {full.cost}, breaks {full.broken}")
for a in full.actions:
    print("  -", a.describe())
g.delete()
