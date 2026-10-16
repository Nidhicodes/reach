import json

import pytest

from reach import queries as Q
from reach.db import connect
from reach.setup import describe, discover, identify, scan


@pytest.fixture
def g(tmp_path):
    g = connect("setup_test", path=str(tmp_path / "s.db"))
    yield g
    g.delete()


CFG = {"mcpServers": {
    "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/work"]},
    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
               "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_supersecretvalue"}},
    "weird-internal": {"command": "/opt/bin/thing", "args": ["--token", "sk-live-123"]},
}}


def test_describe_never_keeps_secret_values():
    d = describe("github", CFG["mcpServers"]["github"])
    assert d["env_keys"] == ["GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert "ghp_" not in json.dumps(d)
    w = describe("weird-internal", CFG["mcpServers"]["weird-internal"])
    assert "sk-live" not in json.dumps(w)


def test_identify_reference_servers():
    assert identify("fetch", describe("fetch", CFG["mcpServers"]["fetch"])) == "fetch"
    assert identify("fs", describe("fs", CFG["mcpServers"]["filesystem"])) == "filesystem"
    assert identify("weird-internal", describe("weird-internal", CFG["mcpServers"]["weird-internal"])) is None


def test_scan_finds_trifecta_in_a_typical_desktop_setup(g, tmp_path):
    p = tmp_path / "claude_desktop_config.json"
    p.write_text(json.dumps(CFG))
    clients = [c for c in discover([str(p)]) if c["path"] == str(p)]
    rep = scan(g, clients)
    assert rep["unmodelled"] == [f"file:claude_desktop_config:weird-internal"]
    paths = Q.trifecta_paths(g)
    # fetch alone ingests the web AND can send (URL exfil); filesystem holds the private data
    combos = {(x["untrusted"], x["private"], x["sink"]) for x in paths}
    assert ("web-content", "local-files", "http-request") in combos
    assert ("public-issues-prs", "source-code", "public-github") in combos
    # nothing secret reached the graph
    blob = json.dumps(Q.ro(g, "MATCH (n) RETURN properties(n) AS p"))
    assert "ghp_" not in blob and "sk-live" not in blob


def test_client_builtins_and_auto_approval_severity(g):
    from reach.setup import annotate_severity

    clients = [
        {"client": "yolo-agent", "path": "x", "servers": {"builtin": {
            "_builtins": ["web_fetch", "fs_read"], "_allowed": ["web_fetch", "fs_read"]}}},
        {"client": "careful-agent", "path": "y", "servers": {"builtin": {
            "_builtins": ["web_fetch", "fs_read"], "_allowed": []}}},
    ]
    scan(g, clients)
    paths = annotate_severity(g, Q.trifecta_paths(g))
    sev = {p["entry"]: p["severity"] for p in paths}
    assert sev == {"yolo-agent": "all-legs-auto-approved", "careful-agent": "needs-approval"}
