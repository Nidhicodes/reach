"""Real-tool estate: 557 public MCP tools from 18 real servers, wired to a synthetic org.

The servers and tools are real (Smithery registry, cached in data/mcp/). The org,
its agents, which servers each agent is connected to, its delegations, and its
workflows are synthetic (hackathon rule 6).

Extra graph model on top of reach.seed:
  (:Tool)-[:INGESTS|READS|SENDS_TO {rule, why}]->(...)   classifier evidence on the edge
  (:Tool)-[:NEEDS]->(:Scope {name:'conn:<server>'})       connecting a server grants all its tools
  (:Workflow {name})-[:RUN_BY]->(:Agent)
  (:Workflow)-[:REQUIRES]->(:Tool)                       what the agent legitimately needs
"""

from __future__ import annotations

from reach.classify import RULES, classify
from reach.ingest.smithery import load_cached

# agent -> (owner team, servers connected)
AGENTS = {
    "inbox-assistant":  ("exec-office", ["gmail", "googlecalendar"]),
    "support-copilot":  ("cx",          ["zendesk", "stripe", "slack"]),
    "dev-agent":        ("platform",    ["github", "supabase"]),
    "research-scout":   ("growth",      ["brave", "exa"]),
    "sales-copilot":    ("sales",       ["hubspot", "salesforce", "outlook"]),
    "docs-bot":         ("people-ops",  ["notion", "googledrive"]),
}
DELEGATIONS = [("research-scout", "sales-copilot"), ("support-copilot", "dev-agent")]

# workflow -> (agent, tools it genuinely needs). These are what a fix must not break.
WORKFLOWS = {
    "triage-inbox":        ("inbox-assistant", ["Gmail_ListEmails", "Gmail_GetEmail", "Gmail_ChangeEmailLabels", "Gmail_WriteDraftReplyEmail"]),
    "schedule-meetings":   ("inbox-assistant", ["GoogleCalendar_ListEvents", "GoogleCalendar_CreateEvent"]),
    "answer-tickets":      ("support-copilot", ["ZENDESK_GET_ZENDESK_TICKET_BY_ID", "ZENDESK_REPLY_ZENDESK_TICKET", "list_customers"]),
    "escalate-to-eng":     ("support-copilot", ["Slack_SendMessage"]),
    "fix-bugs":            ("dev-agent",       ["issue_read", "get_file_contents", "create_pull_request", "execute_sql"]),
    "market-research":     ("research-scout",  ["brave_web_search", "web_search_exa"]),
    "account-briefs":      ("sales-copilot",   ["search_crm_objects", "SALESFORCE_GET_ACCOUNT", "MicrosoftOutlookMail_CreateAndSendEmail"]),
    "onboarding-docs":     ("docs-bot",        ["notion-search", "notion-fetch", "GoogleDrive_SearchFiles"]),
}


def seed_real(g) -> dict:
    servers = {r["server"].lower(): r for r in load_cached()}
    g.query("MATCH (n) DETACH DELETE n")

    targets = {(r.leg, r.target) for r in RULES}
    label = {"INGESTS": "Source", "READS": "Data", "SENDS_TO": "Sink"}
    for leg, name in sorted(targets):
        props = {"Source": "trust: 'untrusted'", "Data": "sensitivity: 'private'", "Sink": "external: true"}[label[leg]]
        g.query(f"MERGE (:{label[leg]} {{name: $n, {props}}})", {"n": name})

    n_tools = n_edges = 0
    for key, rec in servers.items():
        g.query(
            "CREATE (:Server {name: $s, display: $d, source_url: $u})-[:GATED_BY]->(:Scope {name: $scope})",
            {"s": key, "d": rec["display_name"], "u": rec["source_url"], "scope": f"conn:{key}"},
        )
        tools, legs = [], []
        for t in rec["tools"]:
            tools.append({"name": t["name"], "description": t["description"]})
            for r in classify(key, t["name"]):
                legs.append({"tool": t["name"], "leg": r.leg, "target": r.target, "rule": r.id, "why": r.why})
        g.query(
            """
            MATCH (srv:Server {name: $s})-[:GATED_BY]->(sc:Scope)
            UNWIND $tools AS t
            CREATE (tool:Tool {name: t.name, description: t.description, server: $s})-[:PROVIDED_BY]->(srv)
            CREATE (tool)-[:NEEDS]->(sc)
            """,
            {"s": key, "tools": tools},
        )
        for leg in ("INGESTS", "READS", "SENDS_TO"):
            rows = [x for x in legs if x["leg"] == leg]
            if rows:
                g.query(
                    f"UNWIND $rows AS x MATCH (t:Tool {{name: x.tool, server: $s}}), (n:{label[leg]} {{name: x.target}}) "
                    f"CREATE (t)-[:{leg} {{rule: x.rule, why: x.why}}]->(n)",
                    {"rows": rows, "s": key},
                )
        n_tools += len(tools)
        n_edges += len(legs)

    for agent, (owner, srvs) in AGENTS.items():
        g.query(
            """
            CREATE (a:Agent {name: $a, owner: $o})
            WITH a UNWIND $srvs AS s
            MATCH (srv:Server {name: s})-[:GATED_BY]->(sc:Scope)
            CREATE (a)-[:GRANTED]->(sc)
            WITH a, srv
            MATCH (t:Tool)-[:PROVIDED_BY]->(srv)
            CREATE (a)-[:USES]->(t)
            """,
            {"a": agent, "o": owner, "srvs": srvs},
        )
    g.query(
        "UNWIND $p AS p MATCH (a:Agent {name: p[0]}), (b:Agent {name: p[1]}) CREATE (a)-[:DELEGATES_TO]->(b)",
        {"p": [list(x) for x in DELEGATIONS]},
    )
    for wf, (agent, req) in WORKFLOWS.items():
        g.query(
            """
            MATCH (a:Agent {name: $a})
            CREATE (w:Workflow {name: $w})-[:RUN_BY]->(a)
            WITH w, a UNWIND $req AS tn
            MATCH (a)-[:USES]->(t:Tool {name: tn})
            CREATE (w)-[:REQUIRES]->(t)
            """,
            {"a": agent, "w": wf, "req": req},
        )
    return {"servers": len(servers), "tools": n_tools, "leg_edges": n_edges}


if __name__ == "__main__":
    from reach.db import connect

    print(seed_real(connect()))
