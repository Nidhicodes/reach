"""Label every cached real MCP tool with an LLM that never sees Reach's rules.

Output (JSONL, resumable): {server, tool, description, untrusted, private, external,
acts, labeler}. Run twice with two different models; `reach.classeval` scores against
the tools where both agree and reports their agreement (Cohen's kappa). Model labels,
not human ones -- said wherever the numbers appear.

  uv run python scripts/label_tools.py                                   # gpt-oss-120b -> data/labels/tools.jsonl
  REACH_LABEL_MODEL=openai/gpt-oss-20b REACH_LABEL_OUT=data/labels/tools_b.jsonl uv run python scripts/label_tools.py
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

from reach.onboard import LEGS, label
from reach.paths import DATA

OUT = pathlib.Path(os.environ.get("REACH_LABEL_OUT") or DATA / "labels/tools.jsonl")


def corpus() -> list[dict]:
    rows = []
    for f in sorted((DATA / "mcp").glob("*.json")):
        d = json.loads(f.read_text())
        for t in d["tools"]:
            rows.append({"server": d["server"], "tool": t["name"], "description": (t.get("description") or "")[:400]})
    return rows


def main() -> None:
    model = os.environ.get("REACH_LABEL_MODEL", "openai/gpt-oss-120b")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if OUT.exists():
        done = {(r["server"], r["tool"]) for r in map(json.loads, OUT.read_text().splitlines())}
    todo = [r for r in corpus() if (r["server"], r["tool"]) not in done]
    print(f"{model}: {len(done)} labelled, {len(todo)} to go", file=sys.stderr)
    for i in range(0, len(todo), 20):
        chunk = todo[i:i + 20]
        with OUT.open("a") as f:
            for r, legs in zip(chunk, label(chunk, model)):
                if legs:
                    f.write(json.dumps({**r, **{k: legs[k] for k in LEGS}, "labeler": model}) + "\n")
        print(f"  {min(i + 20, len(todo))}/{len(todo)}", file=sys.stderr)


if __name__ == "__main__":
    main()
