"""Harden an MCP client config: the agent ACTS on what the graph shows, with a human's OK.

For one config file, Reach scans it into the graph, finds its trifecta paths, and
proposes edits that close or guard every path WITHOUT removing a capability:

  1. require-approval  the send leg of a path is auto-approved in the client
                       (Kiro `allowedTools`, Cline/Roo `autoApprove` / `alwaysAllow`):
                       take it off, so a person confirms each outbound send.
  2. route-via-gateway every MCP server on a path is moved behind ONE Reach Gateway
                       entry, so the remaining paths are enforced at runtime. One
                       gateway per client, because the guard needs to see every call
                       the client makes in a task.

Dry run by default: prints the plan and a unified diff, writes nothing. With --apply
it first copies the original to `<file>.pre-reach.json` (the gateway reads the real
server specs, env included, from that copy, so secrets are never re-written anywhere
new), then writes the patched config in place, rescans, and records the change in the
graph as (:Remediation)-[:ON]->(:Agent).

  uv run python -m reach.harden path/to/mcp.json [--apply] [--gateway-cmd reach-gateway]
"""

from __future__ import annotations

import argparse
import copy
import difflib
import json
import pathlib
import shlex
import shutil
import time

from reach import queries as Q
from reach import setup as S

APPROVE_KEYS = ("autoApprove", "alwaysAllow")  # per-server lists (Cline, Roo)


def _client_paths(g, cfg_path: pathlib.Path) -> tuple[dict, list[dict]]:
    clients = S.discover([str(cfg_path)], include_home=False)
    if not clients:
        raise ValueError(f"{cfg_path}: not an MCP config this scanner can read")
    S.scan(g, clients, live=False)
    return clients[0], S.annotate_severity(g, Q.trifecta_paths(g))


def plan(g, cfg_path: str, gateway_cmd: str = "reach-gateway") -> dict:
    p = pathlib.Path(cfg_path)
    original = json.loads(p.read_text())
    client, paths = _client_paths(g, p)
    agent = client["client"]
    key = "mcpServers" if "mcpServers" in original else "servers" if "servers" in original else None
    servers = original.get(key) or {} if key else {}

    def server_of(tool: str) -> str:
        return tool.split(".", 1)[0]

    send_tools = sorted({t for x in paths for t in x["out_tools"]})
    on_path = sorted({server_of(t) for x in paths for t in x["in_tools"] + x["read_tools"] + x["out_tools"]}
                     - {"builtin"})
    edits, patched = [], copy.deepcopy(original)

    # 1. require approval on auto-approved send tools
    allowed = patched.get("allowedTools")
    if isinstance(allowed, list):
        drop = [t.split(".", 1)[1] for t in send_tools if t.startswith("builtin.") and t.split(".", 1)[1] in allowed]
        if drop:
            patched["allowedTools"] = [t for t in allowed if t not in drop]
            edits.append({"kind": "require-approval", "tools": drop,
                          "why": "these tools complete a trifecta path and ran with no confirmation"})
    for name in on_path:
        spec = (patched.get(key) or {}).get(name) or {}
        for ak in APPROVE_KEYS:
            lst = spec.get(ak)
            if isinstance(lst, list):
                drop = [t for t in lst if f"{name}.{t}" in send_tools]
                if drop:
                    spec[ak] = [t for t in lst if t not in drop]
                    edits.append({"kind": "require-approval", "server": name, "tools": drop,
                                  "why": "auto-approved send leg of a trifecta path"})

    # 2. route every on-path stdio/http server through one gateway
    wrap = [n for n in on_path if n in servers and not servers[n].get("disabled")]
    if wrap:
        backup = p.with_name(p.stem + ".pre-reach.json")
        for n in wrap:
            patched[key].pop(n)
        cmd = shlex.split(gateway_cmd)
        patched[key]["reach-gateway"] = {
            "command": cmd[0],
            "args": cmd[1:] + ["--config", str(backup.resolve()), "--only", ",".join(wrap), "--agent", agent],
        }
        edits.append({"kind": "route-via-gateway", "servers": wrap,
                      "why": "the gateway blocks the third leg at runtime; tools stay available as <server>__<tool>"})

    # after the edits, a path is guarded when its send leg either goes through the
    # gateway (runtime block) or is no longer auto-approved (a person confirms it)
    still_auto = set()
    if isinstance(patched.get("allowedTools"), list):
        still_auto |= {f"builtin.{t}" for t in patched["allowedTools"]}
    for n, spec in (patched.get(key) or {}).items():
        for ak in APPROVE_KEYS:
            still_auto |= {f"{n}.{t}" for t in spec.get(ak) or [] if isinstance(t, str)}
    guarded = 0
    for x in paths:
        enforced = any(server_of(t) in wrap for t in x["out_tools"])
        confirmed = all(t not in still_auto for t in x["out_tools"])
        x["after"] = "gateway-enforced" if enforced else "human-confirms-send" if confirmed else "unguarded"
        guarded += x["after"] != "unguarded"
    before = json.dumps(original, indent=2).splitlines(keepends=True)
    after = json.dumps(patched, indent=2).splitlines(keepends=True)
    return {
        "file": str(p), "agent": agent, "paths": len(paths),
        "severity_before": _count(paths), "edits": edits, "paths_guarded_after": guarded,
        "after": dict(__import__("collections").Counter(x["after"] for x in paths)),
        "capabilities_removed": 0,
        "diff": "".join(difflib.unified_diff(before, after, str(p), str(p))),
        "_patched": patched,
    }


def _count(paths: list[dict]) -> dict:
    from collections import Counter

    return dict(Counter(x["severity"] for x in paths))


RECORD = """
MERGE (a:Agent {name: $agent})
CREATE (r:Remediation {at: $at, file: $file, edits: $edits, actor: $actor})-[:ON]->(a)
"""


def apply(g, report: dict, actor: str = "human") -> dict:
    p = pathlib.Path(report["file"])
    if not report["edits"]:
        return {**_public(report), "applied": False, "note": "nothing to change"}
    backup = p.with_name(p.stem + ".pre-reach.json")
    if not backup.exists():
        shutil.copy2(p, backup)
    p.write_text(json.dumps(report["_patched"], indent=2) + "\n")
    g.query(RECORD, {"agent": report["agent"], "at": int(time.time() * 1000), "file": str(p),
                     "edits": json.dumps(report["edits"]), "actor": actor})
    return {**_public(report), "applied": True, "backup": str(backup)}


def _public(report: dict) -> dict:
    return {k: v for k, v in report.items() if not k.startswith("_")}


def main() -> None:
    ap = argparse.ArgumentParser(description="Propose (and with --apply, make) edits that guard every trifecta path.")
    ap.add_argument("config")
    ap.add_argument("--apply", action="store_true", help="write the patched config (backs up the original first)")
    ap.add_argument("--gateway-cmd", default="reach-gateway")
    ap.add_argument("--graph", default="harden")
    a = ap.parse_args()
    from reach.db import connect

    g = connect(a.graph)
    rep = plan(g, a.config, a.gateway_cmd)
    print(f"{rep['agent']}: {rep['paths']} trifecta path(s) {rep['severity_before']}")
    for e in rep["edits"]:
        print(f"  - {e['kind']}: {e.get('tools') or e.get('servers')}  ({e['why']})")
    print(f"After: {rep["paths_guarded_after"]}/{rep["paths"]} paths guarded {rep["after"]}; "
          f"{rep['capabilities_removed']} tools removed.\n")
    print(rep["diff"] or "(no changes)")
    if a.apply:
        r = apply(g, rep, actor="cli")
        print(f"\nApplied. Original kept at {r.get('backup')}." if r["applied"] else r["note"])
    elif rep["edits"]:
        print("\nDry run. Re-run with --apply to write it (the original is backed up first).")


if __name__ == "__main__":
    main()
