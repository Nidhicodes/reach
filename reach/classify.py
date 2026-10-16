"""Classify real MCP tools into the three legs of the lethal trifecta.

Deterministic regex rules over (server, normalised tool name). No LLM: every edge the
classifier writes carries the rule id that produced it, so an analyst can audit why a
tool counts as untrusted input, private data, or an exfiltration channel.

Legs
  INGESTS  -> Source  content authored by people outside the org (prompt-injection entry)
  READS    -> Data    private org / customer data
  SENDS_TO -> Sink    a channel where data leaves the org or becomes visible outside it
"""

from __future__ import annotations

import re
from dataclasses import dataclass


def normalise(name: str) -> str:
    """`Gmail_SendEmail` / `channels.messages.create` / `DROPBOX_READ_FILE` -> 'gmail send email' etc."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    s = re.sub(r"[_.\-/]+", " ", s)
    return re.sub(r"\s+", " ", s).strip().lower()


@dataclass(frozen=True)
class Rule:
    id: str
    leg: str  # INGESTS | READS | SENDS_TO
    server: str  # regex on server name
    tool: str  # regex on normalised tool name
    target: str  # Source / Data / Sink node name
    why: str


MAIL = r"(gmail|outlook)"
R = Rule
RULES: list[Rule] = [
    # ---- untrusted input -------------------------------------------------------
    R("web-read", "INGESTS", r"(brave|exa)", r"(search|fetch|context|summari[sz]er)", "web-content",
      "Returns arbitrary web pages written by anyone"),
    R("mail-read-untrusted", "INGESTS", MAIL, r"^(?!.*draft).*\b(get|list|search|triage)\b.*\b(email|emails|thread|threads)\b", "inbound-email",
      "Anyone on the internet can email you"),
    R("chat-read-untrusted", "INGESTS", r"(slack|discord)", r"(get (thread )?messages|messages (list|get))", "chat-messages",
      "Shared/Connect channels carry messages from outside the org"),
    R("gh-issues", "INGESTS", r"github", r"(issue read|list issues|search issues|get discussion|discussion comments|pull request read|list pull requests|get notification)", "public-issues-prs",
      "Public issues and PR comments are writable by any GitHub user"),
    R("tickets-untrusted", "INGESTS", r"zendesk", r"(get .*ticket|list .*tickets)", "support-tickets",
      "Ticket bodies are written by customers"),
    R("cal-invites", "INGESTS", r"googlecalendar", r"list events", "calendar-invites",
      "Anyone can send a calendar invite with arbitrary text"),
    # ---- private data -----------------------------------------------------------
    R("mail-read-private", "READS", MAIL, r"\b(get|list|search)\b.*\b(email|emails|thread|threads|attachments?)\b", "mailbox",
      "The user's mailbox"),
    R("chat-read-private", "READS", r"slack", r"get (thread )?messages", "workspace-chat", "Internal Slack history"),
    R("gh-code", "READS", r"github", r"(get file contents|get repository tree|get commit|get secret scanning alert|get job logs)", "source-code",
      "Repository contents (including private repos)"),
    R("drive", "READS", r"(googledrive|dropbox)", r"(download|read file|search|list files)", "cloud-files", "Private documents"),
    R("sheets", "READS", r"googlesheets", r"(inspect|search spreadsheets|edit history)", "spreadsheets", "Private spreadsheets"),
    R("notion", "READS", r"notion", r"(notion search|notion fetch)", "notion-workspace", "Internal wiki"),
    R("crm", "READS", r"(hubspot|salesforce)", r"(search|\bget\b|execute soql|fetch|list)", "crm-records", "Customer and deal records"),
    R("payments", "READS", r"stripe", r"(list customers|list invoices|payment intents|subscriptions|retrieve balance|fetch stripe resources|search stripe resources)", "payments",
      "Customers, invoices, balances"),
    R("database", "READS", r"supabase", r"(execute sql|list tables)", "database", "Production database rows"),
    R("customer-records", "READS", r"zendesk", r"(get .*ticket|list .*tickets|search .*users)", "customer-records", "Customer PII in tickets"),
    # ---- exfiltration channels --------------------------------------------------
    R("mail-send", "SENDS_TO", MAIL, r"(\bsend\b|\bforward\b|reply to email)", "outbound-email", "Sends mail to any address"),
    R("chat-send", "SENDS_TO", r"slack", r"send message", "chat-post", "Posts can reach Slack Connect / external guests"),
    R("discord-send", "SENDS_TO", r"discord", r"(messages create|webhooks .*execute)", "chat-post", "Posts to Discord channels"),
    R("gh-public-write", "SENDS_TO", r"github", r"(create gist|create issue|issue write|add issue comment|create or update file|create pull request|create repository|fork repository)", "public-github",
      "Writes text that can be public on GitHub"),
    R("share-link", "SENDS_TO", r"(googledrive|dropbox)", r"(share file|set general access|temporary link)", "public-share-link",
      "Creates a link anyone can open"),
    R("cal-invite-out", "SENDS_TO", r"googlecalendar", r"(create event|update event)", "calendar-invite",
      "Invites carry text to external attendees"),
    R("ticket-reply", "SENDS_TO", r"zendesk", r"(reply .*ticket|create .*ticket)", "ticket-reply", "Replies go to the customer"),
    R("url-fetch", "SENDS_TO", r"exa", r"fetch", "http-request", "Fetching an attacker URL leaks data in the query string"),
]

IGNORE = re.compile(r"(who am i|list apps|^arcade )")

# Fallback for servers none of the RULES above know (a user's own setup: filesystem,
# fetch, puppeteer, postgres, sqlite, shell ...). Matched on the tool name only, and
# only when the server is unknown, so curated servers keep their audited rules.
ANY = r".*"
GENERIC_RULES: list[Rule] = [
    R("g-web-read", "INGESTS", ANY, r"\b(fetch|browse|navigate|scrape|crawl|web search|search (the )?web|get page|read url|open url|goto)\b", "web-content",
      "Returns pages written by anyone on the internet"),
    R("g-mail-read", "INGESTS", ANY, r"\b(get|list|read|search)\b.*\b(emails?|mail|inbox)\b", "inbound-email", "Anyone can email you"),
    R("g-chat-read", "INGESTS", ANY, r"\b(get|list|read|search)\b.*\b(channel history|messages?|thread replies|conversations?)\b", "chat-messages",
      "Shared channels carry messages from outside the org"),
    R("g-chat-private", "READS", ANY, r"\b(get|list|read|search)\b.*\b(channel history|messages?|thread replies|conversations?)\b", "workspace-chat",
      "Internal chat history"),
    R("g-issues", "INGESTS", ANY, r"\b(get|list|search|read)\b.*\b(issues?|pull requests?|comments?|tickets?)\b", "public-issues-prs",
      "Issue, PR and ticket text is written by outsiders"),
    R("g-files", "READS", ANY, r"\b(read (text |media |multiple )?files?|read file|list directory|directory tree|search files|get file( info| contents)?)\b", "local-files",
      "Files on the machine the agent runs on"),
    R("g-db", "READS", ANY, r"\b(query|sql|read query|list tables|describe table)\b", "database", "Database rows"),
    R("g-code", "READS", ANY, r"\b(git (log|show|diff|status)|search code)\b", "source-code", "Repository contents"),
    R("g-shell-read", "READS", ANY, r"\b(run|execute|exec)\b.*\b(command|shell|terminal|bash|script)\b|^(shell|bash|terminal)\b", "local-files",
      "A shell can read anything the user can"),
    R("g-http-out", "SENDS_TO", ANY, r"\b(fetch|navigate|http|request url|post url|webhook|curl|goto)\b", "http-request",
      "Requesting an attacker URL leaks data in the URL"),
    R("g-shell-out", "SENDS_TO", ANY, r"\b(run|execute|exec)\b.*\b(command|shell|terminal|bash|script)\b|^(shell|bash|terminal)\b", "http-request",
      "A shell can curl data anywhere"),
    R("g-mail-send", "SENDS_TO", ANY, r"\bsend\b.*\b(emails?|mail)\b", "outbound-email", "Sends mail to any address"),
    R("g-chat-send", "SENDS_TO", ANY, r"\b(send|post)\b.*\b(message|chat)\b", "chat-post", "Posts outside the agent"),
    R("g-cloud", "READS", ANY, r"\b(use aws|aws cli|gcloud|az cli|kubectl)\b", "cloud-resources",
      "Whatever the agent's cloud credentials can read"),
]


def is_known_server(server: str) -> bool:
    s = server.lower()
    return any(re.search(r.server, s) for r in RULES)


def classify(server: str, tool: str, fallback: bool = False) -> list[Rule]:
    """fallback=True (live setups, the gateway): a known server's tool that no curated
    rule matches is also tried against GENERIC_RULES, since real servers' tool names
    drift from the registry listing the curated rules were written against."""
    s, t = server.lower(), normalise(tool)
    if IGNORE.search(t):
        return []
    if not is_known_server(s):
        return [r for r in GENERIC_RULES if re.search(r.tool, t)]
    hits = [r for r in RULES if re.search(r.server, s) and re.search(r.tool, t)]
    if fallback and not hits:
        hits = [r for r in GENERIC_RULES if re.search(r.tool, t)]
    return hits
