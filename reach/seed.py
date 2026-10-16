"""Synthetic agent estate for "Acme Corp" (synthetic data only, per hackathon rule 6).

Graph model
-----------
(:Agent  {name, owner})
(:Tool   {name})-[:PROVIDED_BY]->(:Server {name})
(:Agent)-[:USES]->(:Tool)
(:Tool)-[:NEEDS]->(:Scope {name})
(:Agent)-[:GRANTED]->(:Scope)
(:Tool)-[:INGESTS]->(:Source {name, trust:'untrusted'})   leg 1: untrusted input
(:Tool)-[:READS]->(:Data {name, sensitivity:'private'})     leg 2: private data
(:Tool)-[:SENDS_TO]->(:Sink {name, external:true})          leg 3: exfil channel
(:Agent)-[:DELEGATES_TO]->(:Agent)                          handoff: taint propagates

A tool is *usable* by an agent only if the agent holds every scope the tool needs.
"""

from __future__ import annotations

AGENTS = [
    {"name": "code-reviewer", "owner": "platform"},
    {"name": "support-bot", "owner": "cx"},
    {"name": "research-agent", "owner": "growth"},
    {"name": "sales-assistant", "owner": "sales"},
    {"name": "ops-bot", "owner": "infra"},
]

SERVERS = ["github-mcp", "zendesk-mcp", "postgres-mcp", "gmail-mcp", "browser-mcp", "crm-mcp", "slack-mcp"]

SOURCES = ["public-github-issues", "customer-tickets", "web-pages", "inbound-email"]
DATA = ["private-repos", "customer-db", "crm-records", "internal-runbooks"]
SINKS = ["public-gist", "outbound-email", "external-slack-connect", "http-fetch"]

# tool -> (server, scopes, ingests, reads, sends_to)
TOOLS = {
    "github.read_issues":   ("github-mcp",   ["repo:read"],        ["public-github-issues"], [], []),
    "github.read_code":     ("github-mcp",   ["repo:read"],        [], ["private-repos"], []),
    "github.create_gist":   ("github-mcp",   ["gist:write"],       [], [], ["public-gist"]),
    "zendesk.read_ticket":  ("zendesk-mcp",  ["tickets:read"],     ["customer-tickets"], [], []),
    "postgres.query":       ("postgres-mcp", ["db:read"],          [], ["customer-db"], []),
    "gmail.send":           ("gmail-mcp",    ["mail:send"],        [], [], ["outbound-email"]),
    "gmail.read":           ("gmail-mcp",    ["mail:read"],        ["inbound-email"], [], []),
    "browser.fetch":        ("browser-mcp",  ["net:egress"],       ["web-pages"], [], ["http-fetch"]),
    "crm.lookup":           ("crm-mcp",      ["crm:read"],         [], ["crm-records"], []),
    "slack.post":           ("slack-mcp",    ["slack:write"],      [], [], ["external-slack-connect"]),
    "runbooks.read":        ("github-mcp",   ["repo:read"],        [], ["internal-runbooks"], []),
}

# agent -> (tools used, scopes granted)
USAGE = {
    "code-reviewer":   (["github.read_issues", "github.read_code", "github.create_gist"],
                        ["repo:read", "gist:write"]),
    "support-bot":     (["zendesk.read_ticket", "postgres.query", "gmail.send"],
                        ["tickets:read", "db:read", "mail:send"]),
    "research-agent":  (["browser.fetch"], ["net:egress"]),
    "sales-assistant": (["crm.lookup", "gmail.send"], ["crm:read", "mail:send"]),
    # ops-bot USES slack.post but was never granted slack:write -> tool is not usable.
    "ops-bot":         (["runbooks.read", "slack.post"], ["repo:read"]),
}

DELEGATIONS = [("research-agent", "sales-assistant")]


def seed(g, estate: dict | None = None) -> None:
    """Wipe and load an estate (default: the synthetic Acme one). Idempotent.

    `estate` may override any of AGENTS, SERVERS, SOURCES, DATA, SINKS, TOOLS, USAGE,
    DELEGATIONS (same shapes as the module constants).
    """
    e = estate or {}
    AGENTS = e.get("AGENTS", globals()["AGENTS"])
    SERVERS = e.get("SERVERS", globals()["SERVERS"])
    SOURCES = e.get("SOURCES", globals()["SOURCES"])
    DATA = e.get("DATA", globals()["DATA"])
    SINKS = e.get("SINKS", globals()["SINKS"])
    TOOLS = e.get("TOOLS", globals()["TOOLS"])
    USAGE = e.get("USAGE", globals()["USAGE"])
    DELEGATIONS = e.get("DELEGATIONS", globals()["DELEGATIONS"])
    g.query("MATCH (n) DETACH DELETE n")
    g.query("UNWIND $rows AS r CREATE (:Agent {name: r.name, owner: r.owner})", {"rows": AGENTS})
    g.query("UNWIND $names AS n CREATE (:Server {name: n})", {"names": SERVERS})
    g.query("UNWIND $names AS n CREATE (:Source {name: n, trust: 'untrusted'})", {"names": SOURCES})
    g.query("UNWIND $names AS n CREATE (:Data {name: n, sensitivity: 'private'})", {"names": DATA})
    g.query("UNWIND $names AS n CREATE (:Sink {name: n, external: true})", {"names": SINKS})

    scopes = sorted({s for _, scopes, *_ in TOOLS.values() for s in scopes})
    g.query("UNWIND $names AS n CREATE (:Scope {name: n})", {"names": scopes})

    for tool, (server, needs, ingests, reads, sends) in TOOLS.items():
        g.query(
            """
            MATCH (srv:Server {name: $server})
            CREATE (t:Tool {name: $tool})-[:PROVIDED_BY]->(srv)
            WITH t
            UNWIND $needs AS s MATCH (sc:Scope {name: s}) CREATE (t)-[:NEEDS]->(sc)
            """,
            {"tool": tool, "server": server, "needs": needs},
        )
        for rel, label, names in (("INGESTS", "Source", ingests), ("READS", "Data", reads), ("SENDS_TO", "Sink", sends)):
            if names:
                g.query(
                    f"MATCH (t:Tool {{name: $tool}}) UNWIND $names AS n "
                    f"MATCH (x:{label} {{name: n}}) CREATE (t)-[:{rel}]->(x)",
                    {"tool": tool, "names": names},
                )

    for agent, (tools, granted) in USAGE.items():
        g.query(
            "MATCH (a:Agent {name: $a}) UNWIND $tools AS tn MATCH (t:Tool {name: tn}) CREATE (a)-[:USES]->(t)",
            {"a": agent, "tools": tools},
        )
        g.query(
            "MATCH (a:Agent {name: $a}) UNWIND $scopes AS sn MATCH (s:Scope {name: sn}) CREATE (a)-[:GRANTED]->(s)",
            {"a": agent, "scopes": granted},
        )

    g.query(
        "UNWIND $pairs AS p MATCH (a:Agent {name: p[0]}), (b:Agent {name: p[1]}) CREATE (a)-[:DELEGATES_TO]->(b)",
        {"pairs": [list(p) for p in DELEGATIONS]},
    )


if __name__ == "__main__":
    from reach.db import connect

    g = connect()
    seed(g)
    print(g.ro_query("MATCH (n) RETURN labels(n)[0] AS label, count(*) ORDER BY label").result_set)
