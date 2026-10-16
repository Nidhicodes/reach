# How Reach compares

Checked on 16 Oct 2026 against public docs. Where a claim about another tool could
not be verified from its docs, it says so.

## Snyk Agent Scan (formerly Invariant Labs mcp-scan)

The closest tool. It scans MCP configs on a machine, flags prompt injection in tool
descriptions, and coined "toxic flows" for the lethal trifecta.

| | Snyk Agent Scan | Reach |
|---|---|---|
| Discover client configs on a machine | Yes, more clients than Reach | Yes (8 clients + Kiro agents) |
| Prompt injection inside tool descriptions | Yes (E001) | No |
| Toxic flow / trifecta | Per component: "our analysis focuses on each component individually" ([issue codes](https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md)). Outbound-send is not flagged separately ("most agents include network access tools by default") | Whole path: untrusted source -> agent(s) -> private data -> sink, as one Cypher traversal |
| Paths that cross agents (A reads, hands off, B sends) | Not described in the docs | Yes: up to 3 `DELEGATES_TO` hops, statically and at runtime |
| Runtime enforcement | `mcp-scan proxy` with guardrails (v0.2.1, [changelog](https://github.com/snyk/agent-scan/blob/main/CHANGELOG.md)); now Agent Guard hooks per client that call Snyk's cloud | Reach Gateway: local MCP proxy; the task ledger is in FalkorDB, shared by every gateway on it |
| Shared state across agents/processes | Not described | Yes: one graph, unique-constraint-safe writes, measured with 9 processes |
| Human approval instead of a hard block | Not described | `--ask`: an Approval node any process can decide |
| Fix plan | Reports risks | Minimum hitting set that closes paths without breaking workflows; `reach-harden` patches the config |
| History ("which change opened this path?") | Not described | Scans and changes stored in the graph, paths linked to likely causes |
| Where analysis runs | Snyk API (tool descriptions sent, secrets redacted; Snyk token required) | Locally; nothing leaves the machine |
| Independent benchmark | Not published for toxic flows | AgentDojo v1.2.2, see `bench/` |

Not tested hands-on: running Agent Scan needs a Snyk account and sends tool
descriptions to Snyk's API, so this comparison is from its documentation only.

## Others

- **BloodHound Enterprise** (SpecterOps) added attack paths for Entra agents in July
  2026: identity paths in Azure, not MCP tool calls, and no runtime guard.
- **AgentHound**, **AIHound**: open-source static mapping of agent credentials and
  permissions. No runtime enforcement.
- **Firewall-style defenses** at the agent-tool boundary score well on AgentDojo
  ([arXiv 2510.05244](https://arxiv.org/abs/2510.05244)). Reach is one of these; its
  difference is that every block cites the cross-agent path in the graph that caused it.
