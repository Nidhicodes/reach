"""Scan my setup: find the MCP clients configured on this machine and map what each can reach.

  uv run python -m reach.setup                # static: known tool lists, runs nothing
  uv run python -m reach.setup --live         # start each configured server and ask it (tools/list)
  uv run python -m reach.setup --json out.json

Every MCP client config found (Claude Desktop, Claude Code, Cursor, Kiro, Windsurf,
VS Code, Gemini CLI, Codex) becomes one Agent in the graph, connected to its servers.
Then the same trifecta query, fix planner and chokepoint algorithm run on it.

Privacy: config files often hold API keys in `env` or args. This module keeps only
server names, the command's basename, the package name and env KEY names. Values are
never stored, printed or written to the graph. --live passes the configured env to the
server process it starts, exactly as the client itself would, and nothing else.

Static mode only knows the tool lists below and the cached Smithery servers; anything
else is reported as UNMODELLED (not as safe). --live is the accurate mode.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import pathlib
import re
import sys
import tomllib

from reach import estate
from reach import queries as Q

HOME = pathlib.Path.home()

# (client label, path, key holding the servers). Project-level files are resolved
# against the current directory.
LOCATIONS = [
    ("claude-desktop", HOME / "Library/Application Support/Claude/claude_desktop_config.json", "mcpServers"),
    ("claude-desktop", HOME / ".config/Claude/claude_desktop_config.json", "mcpServers"),
    ("claude-code", HOME / ".claude.json", "mcpServers"),
    ("claude-code-project", pathlib.Path(".mcp.json"), "mcpServers"),
    ("cursor", HOME / ".cursor/mcp.json", "mcpServers"),
    ("cursor-project", pathlib.Path(".cursor/mcp.json"), "mcpServers"),
    ("kiro", HOME / ".kiro/settings/mcp.json", "mcpServers"),
    ("kiro-project", pathlib.Path(".kiro/settings/mcp.json"), "mcpServers"),
    ("windsurf", HOME / ".codeium/windsurf/mcp_config.json", "mcpServers"),
    ("vscode", HOME / "Library/Application Support/Code/User/mcp.json", "servers"),
    ("vscode", HOME / ".config/Code/User/mcp.json", "servers"),
    ("vscode-project", pathlib.Path(".vscode/mcp.json"), "servers"),
    ("gemini-cli", HOME / ".gemini/settings.json", "mcpServers"),
    ("codex", HOME / ".codex/config.toml", "mcp_servers"),
]
KIRO_AGENTS = HOME / ".kiro/agents"

# Tool lists of widely used servers, as their READMEs document them. Static mode only.
REFERENCE = {
    "filesystem": ["read_file", "read_text_file", "read_media_file", "read_multiple_files", "write_file", "edit_file",
                   "create_directory", "list_directory", "list_directory_with_sizes", "directory_tree", "move_file",
                   "search_files", "get_file_info", "list_allowed_directories"],
    "fetch": ["fetch"],
    "git": ["git_status", "git_diff_unstaged", "git_diff_staged", "git_diff", "git_commit", "git_add", "git_reset",
            "git_log", "git_create_branch", "git_checkout", "git_show", "git_branch"],
    "memory": ["create_entities", "create_relations", "add_observations", "delete_entities", "read_graph",
               "search_nodes", "open_nodes"],
    "puppeteer": ["puppeteer_navigate", "puppeteer_screenshot", "puppeteer_click", "puppeteer_fill",
                  "puppeteer_select", "puppeteer_hover", "puppeteer_evaluate"],
    "playwright": ["browser_navigate", "browser_snapshot", "browser_click", "browser_type", "browser_evaluate",
                   "browser_take_screenshot", "browser_network_requests", "browser_tabs", "browser_file_upload"],
    "postgres": ["query"],
    "sqlite": ["read_query", "write_query", "create_table", "list_tables", "describe_table"],
    "slack": ["slack_list_channels", "slack_post_message", "slack_reply_to_thread", "slack_add_reaction",
              "slack_get_channel_history", "slack_get_thread_replies", "slack_get_users", "slack_get_user_profile"],
    "brave-search": ["brave_web_search", "brave_local_search"],
    "github": ["get_issue", "list_issues", "search_issues", "get_pull_request", "list_pull_requests",
               "get_file_contents", "search_code", "create_issue", "add_issue_comment", "create_pull_request",
               "create_or_update_file", "push_files", "create_repository", "fork_repository"],
    "gmail": ["search_emails", "read_email", "send_email", "draft_email"],
    "time": ["get_current_time", "convert_time"],
    "sequential-thinking": ["sequentialthinking"],
    "shell": ["run_command"],
}
ALIASES = {"brave": "brave-search", "server-brave-search": "brave-search", "mcp-server-fetch": "fetch",
           "mcp-server-git": "git", "desktop-commander": "shell", "shell-mcp": "shell", "terminal": "shell"}

# Built-in tools some clients declare per agent (Kiro agent JSON `tools`), mapped to a
# name the generic classifier understands. These are reachable without any MCP server.
BUILTINS = {
    "web_fetch": "fetch url", "web_search": "web search", "fs_read": "read file",
    "execute_bash": "execute command", "execute_cmd": "execute command", "shell": "execute command",
    "use_aws": "use aws",
}
SECRETISH = re.compile(r"(key|token|secret|pass|auth|bearer|sk-|ghp_|xox)", re.I)


def _read(path: pathlib.Path) -> dict | None:
    try:
        if path.suffix == ".toml":
            return tomllib.loads(path.read_text())
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _with_builtins(data: dict) -> dict:
    """Servers of a Kiro-agent-style config, plus its declared built-in tools as one pseudo-server."""
    tools = data.get("tools") or []
    builtins = list(BUILTINS) if "*" in tools else [t for t in tools if isinstance(t, str) and t in BUILTINS]
    allowed = set(data.get("allowedTools") or [])
    servers = dict(data.get("mcpServers") or data.get("servers") or data.get("mcp_servers") or {})
    if builtins:
        servers["builtin"] = {"_builtins": builtins, "_allowed": sorted(allowed & set(builtins))}
    return servers


def discover(extra: list[str] = (), include_home: bool = True) -> list[dict]:
    """[{client, path, servers: {name: spec}}]. Specs are kept in memory only."""
    found, seen = [], set()

    def add(client, path, servers):
        if servers and isinstance(servers, dict):
            key = (client, str(path.resolve()))
            if key not in seen:
                seen.add(key)
                found.append({"client": client, "path": str(path), "servers": servers})

    for client, path, key in LOCATIONS if include_home else []:
        data = _read(path)
        if not data:
            continue
        add(client, path, data.get(key))
        if client == "claude-code":  # per-project servers live under projects.<dir>.mcpServers
            for proj, cfg in (data.get("projects") or {}).items():
                add(f"claude-code:{pathlib.Path(proj).name}", path, (cfg or {}).get("mcpServers"))
    if include_home and KIRO_AGENTS.is_dir():
        for p in sorted(KIRO_AGENTS.glob("*.json")):
            data = _read(p)
            if data:
                add(f"kiro-agent:{p.stem}", p, _with_builtins(data))
    for x in extra:
        p = pathlib.Path(x)
        data = _read(p)
        if data:
            add(data.get("name") or f"file:{p.stem}", p, _with_builtins(data))
    return found


def describe(name: str, spec: dict) -> dict:
    """Redacted view of one server spec: never values that look like secrets."""
    args = [a for a in spec.get("args", []) if isinstance(a, str)]
    pkg = next((a for a in args if not a.startswith("-") and ("mcp" in a.lower() or a.startswith("@"))), "")
    return {
        "name": name,
        "transport": "http" if spec.get("url") or spec.get("type") in ("http", "sse") else "stdio",
        "command": os.path.basename(spec.get("command", "")) if spec.get("command") else "",
        "package": "" if SECRETISH.search(pkg) else pkg,
        "env_keys": sorted((spec.get("env") or {}).keys()),
        "disabled": bool(spec.get("disabled")),
    }


def identify(name: str, d: dict) -> str | None:
    """Which REFERENCE list (or cached Smithery server) a configured server is."""
    hay = f"{name} {d['package']}".lower()
    for alias, ref in ALIASES.items():
        if alias in hay:
            return ref
    for ref in REFERENCE:
        if re.search(rf"(^|[^a-z]){re.escape(ref)}([^a-z]|$)", hay):
            return ref
    return None


def static_tools(name: str, d: dict) -> tuple[list[dict], str]:
    ref = identify(name, d)
    if ref:
        return [{"name": t} for t in REFERENCE[ref]], f"reference:{ref}"
    from reach.ingest.smithery import CACHE

    for p in CACHE.glob("*.json"):
        if p.stem in name.lower():
            rec = json.loads(p.read_text())
            return rec["tools"], f"smithery:{p.stem}"
    return [], "unmodelled"


async def live_tools(spec: dict, timeout: float = 25.0) -> tuple[list[dict], str]:
    from mcp.client.client import Client

    from reach.gateway import target

    try:
        async with asyncio.timeout(timeout):
            async with Client(target(spec)) as c:
                listed = (await c.list_tools()).tools
        return [{"name": t.name, "description": t.description or ""} for t in listed], "live"
    except Exception as e:  # noqa: BLE001 - a server that will not start is reported, not fatal
        return [], f"live-failed:{type(e).__name__}"


def scan(g, clients: list[dict], live: bool = False) -> dict:
    g.query("MATCH (n) DETACH DELETE n")
    report = {"clients": [], "unmodelled": []}
    for c in clients:
        entry = {"client": c["client"], "path": c["path"], "servers": []}
        for name, spec in c["servers"].items():
            if not isinstance(spec, dict):
                continue
            d = describe(name, spec)
            if "_builtins" in spec:
                tools = [{"name": b, "classify_as": BUILTINS[b], "auto_approved": b in spec["_allowed"]}
                         for b in spec["_builtins"]]
                d.update(source="client-builtin", tools=len(tools), auto_approved=spec["_allowed"])
                estate.register(g, c["client"], "builtin", tools, source="client-builtin")
                entry["servers"].append(d)
                continue
            if d["disabled"]:
                d["source"] = "disabled"
                entry["servers"].append(d)
                continue
            tools, src = asyncio.run(live_tools(spec)) if live else static_tools(name, d)
            if live and not tools:  # fall back to the static list rather than show nothing
                st, ssrc = static_tools(name, d)
                if st:
                    tools, src = st, f"{ssrc} ({src})"
            d["source"], d["tools"] = src, len(tools)
            if tools:
                estate.register(g, c["client"], name, tools, source=src)
            else:
                report["unmodelled"].append(f"{c['client']}:{name}")
            entry["servers"].append(d)
        report["clients"].append(entry)
    return report


def annotate_severity(g, paths: list[dict]) -> list[dict]:
    """A path whose three legs are all auto-approved runs with no human in the loop."""
    auto = {(r["a"], r["t"]) for r in Q.ro(g, "MATCH (a:Agent)-[u:USES]->(t:Tool) WHERE u.auto_approved = true "
                                              "RETURN a.name AS a, t.name AS t")}
    for p in paths:
        legs = [any((p["entry"], t) in auto for t in p["in_tools"]),
                any((p["reader"], t) in auto for t in p["read_tools"]),
                any((p["sender"], t) in auto for t in p["out_tools"])]
        p["auto_legs"] = sum(legs)
        p["severity"] = "all-legs-auto-approved" if all(legs) else "needs-approval" if not any(legs) else "partly-auto-approved"
    paths.sort(key=lambda p: -p["auto_legs"])
    return paths


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--live", action="store_true", help="start each configured server to list its real tools")
    ap.add_argument("--config", action="append", default=[], help="extra MCP config file(s) to include")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("--graph", default="mine")
    ap.add_argument("--no-home", action="store_true", help="scan only --config files, not this machine's configs")
    a = ap.parse_args()
    from reach.algos import chokepoints
    from reach.db import connect

    clients = discover(a.config, include_home=not a.no_home)
    if not clients:
        print("No MCP client configs found. Pass one with --config path/to/mcp.json.")
        return
    g = connect(a.graph)
    report = scan(g, clients, a.live)
    paths = annotate_severity(g, Q.trifecta_paths(g))
    report["paths"] = paths
    report["chokepoints"] = chokepoints(g, 5).get("chokepoints", []) if paths else []

    print(f"Found {len(clients)} MCP client config(s):")
    for c in report["clients"][: 12 if len(report["clients"]) > 15 else None]:
        print(f"  {c['client']:<28} {len(c['servers'])} server(s)  [{c['path']}]")
        for s in c["servers"]:
            print(f"      {s['name']:<24} {s['source']:<28} tools={s.get('tools', 0)}")
    if len(report["clients"]) > 15:
        print(f"  ... {len(report['clients']) - 12} more (see --json)")
    agents_hit = sorted({p["entry"] for p in paths})
    print(f"\n{len(paths)} lethal-trifecta path(s) across {len(agents_hit)} agent(s); "
          f"{sum(p["severity"] == "all-legs-auto-approved" for p in paths)} have every leg auto-approved in the client config:")
    for p in paths[:20]:
        print(f"  [{p['severity']}] [{p['entry']}] {p['untrusted']} -> {p['private']} -> {p['sink']}"
              f"   via {p['in_tools'][0]} / {p['read_tools'][0]} / {p['out_tools'][0]}")
    if len(paths) > 20:
        print(f"  ... {len(paths) - 20} more (see --json)")
    if report["chokepoints"]:
        print("\nChokepoints (paths through, betweenness):")
        for cp in report["chokepoints"]:
            print(f"  {cp['name']:<48} {cp['paths_through']:>3}  {cp['score']}")
    if report["unmodelled"]:
        from collections import Counter

        by_server = Counter(u.rsplit(":", 1)[1] for u in report["unmodelled"])
        print(f"\nUnmodelled -- not scanned, NOT safe ({len(by_server)} server(s) across "
              f"{len({u.rsplit(':', 1)[0] for u in report['unmodelled']})} client(s)):")
        print("  " + ", ".join(f"{s} (x{n})" if n > 1 else s for s, n in by_server.most_common()))
        if not a.live:
            print("  -> rerun with --live to ask each server for its real tool list")
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(report, indent=1, default=str))
    print(f"\nGraph '{a.graph}' written. Open it in the UI with estate=mine.", file=sys.stderr)


if __name__ == "__main__":
    main()
