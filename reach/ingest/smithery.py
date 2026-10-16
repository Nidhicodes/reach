"""Fetch real, public MCP server tool lists from the Smithery registry.

Only public listing metadata (server name, tool names, tool descriptions) is used.
Responses are cached under data/mcp/ so the demo is reproducible offline, and every
record keeps its source URL for attribution.

Usage:  uv run python -m reach.ingest.smithery
"""

from __future__ import annotations

import json
import pathlib
import time
import urllib.request

REGISTRY = "https://registry.smithery.ai/servers"
from reach.paths import DATA

CACHE = DATA / "mcp"

# Widely used, verified servers that cover all three legs of the trifecta.
CURATED = [
    "gmail", "slack", "github", "googledrive", "googlesheets", "googlecalendar",
    "brave", "exa", "notion", "linear", "jira", "hubspot", "salesforce",
    "stripe", "postgres", "supabase", "discord", "outlook", "dropbox", "zendesk",
]


def fetch(name: str, refresh: bool = False) -> dict | None:
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / f"{name.replace('/', '__')}.json"
    if path.exists() and not refresh:
        return json.loads(path.read_text())
    url = f"{REGISTRY}/{name}"
    req = urllib.request.Request(url, headers={"User-Agent": "reach-hackathon/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = json.load(r)
    except Exception as e:  # noqa: BLE001 - a missing server is skipped, not fatal
        print(f"skip {name}: {e}")
        return None
    record = {
        "server": raw.get("qualifiedName", name),
        "display_name": raw.get("displayName"),
        "description": raw.get("description"),
        "source_url": f"https://smithery.ai/servers/{name}",
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tools": [
            {"name": t.get("name"), "description": (t.get("description") or "")[:600]}
            for t in raw.get("tools") or []
        ],
    }
    path.write_text(json.dumps(record, indent=1))
    return record


def load_cached() -> list[dict]:
    """Every cached server record, no network. Used at seed time and in deploys."""
    out = []
    for p in sorted(CACHE.glob("*.json")):
        rec = json.loads(p.read_text())
        if rec.get("tools"):
            out.append(rec)
    return out


def load_all(names: list[str] | None = None, refresh: bool = False) -> list[dict]:
    out = []
    for n in names or CURATED:
        rec = fetch(n, refresh=refresh)
        if rec and rec["tools"]:
            out.append(rec)
        time.sleep(0.2 if refresh or not (CACHE / f"{n}.json").exists() else 0)
    return out


if __name__ == "__main__":
    recs = load_all(refresh=False)
    print(f"{len(recs)} servers, {sum(len(r['tools']) for r in recs)} tools cached in {CACHE}")
