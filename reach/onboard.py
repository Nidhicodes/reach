"""Label a server's tools once, when Reach first sees it, with an LLM.

For a server no curated rule covers, the gateway (or `reach.bench`) can ask a model to
answer four yes/no questions per tool. The answers become ordinary leg edges in the
graph, each stamped with the labeler, so they are auditable and a human can correct
them; the runtime guard itself stays deterministic and never calls a model.

Legs
  untrusted -> INGESTS   output can carry text written by outsiders
  private   -> READS     output can carry the user's / org's non-public data
  external  -> SENDS_TO  sends data outside the org or makes it public
  acts      -> ACTS_ON   changes state that matters outside the chat (money, bookings,
                         permissions, account settings, deleting or overwriting data)

`acts` exists for Meta's Agents Rule of Two (untrusted input + sensitive access +
"change state or communicate externally"); the lethal trifecta uses only `external`.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

LEGS = ("untrusted", "private", "external", "acts")
EDGE = {"untrusted": ("INGESTS", "Source", "untrusted-content"),
        "private": ("READS", "Data", "private-data"),
        "external": ("SENDS_TO", "Sink", "external-send"),
        "acts": ("ACTS_ON", "Effect", "state-change")}

RUBRIC = """You label tools that an AI agent can call. For EACH tool answer four yes/no questions,
judging from the server name, tool name and description only.

untrusted: can the tool's OUTPUT contain text written by people outside the user's organisation
  (web pages, search results, inbound email, public GitHub issues/PRs/comments, customer support
  tickets, reviews, chat messages from shared or public channels, calendar invites from anyone,
  transaction or file contents others can write)?
private: can the tool's OUTPUT contain non-public data of the user or their organisation
  (mailbox, private files, source code, CRM/customer records, payments, balances, database rows,
  internal chat, personal details)?
external: can calling the tool SEND data somewhere outside the organisation or make it publicly
  visible (send email, post a message others outside can read, create a public issue/gist/comment,
  share a file, reply to a customer, request an arbitrary URL, invite an outside person)?
acts: does calling the tool CHANGE state in a way that matters outside the conversation
  (move money, book or cancel, change passwords/permissions/account details, delete or overwrite
  data, add or remove users)?

A tool can be yes on several. Read-only lookups are no on external and acts. Pure metadata is no on all.
Answer ONLY a JSON array, one object per tool in the same order:
[{"i": <index>, "untrusted": bool, "private": bool, "external": bool, "acts": bool}]"""


def chat(prompt: str, model: str | None = None) -> str:
    base = os.environ["REACH_LLM_BASE_URL"].rstrip("/")
    model = model or os.environ.get("REACH_LABEL_MODEL", "openai/gpt-oss-120b")
    body = json.dumps({"model": model, "temperature": 0,
                       "messages": [{"role": "system", "content": RUBRIC}, {"role": "user", "content": prompt}]}).encode()
    hdr = {"Content-Type": "application/json", "User-Agent": "reach/0.1"}
    if os.environ.get("REACH_LLM_API_KEY"):
        hdr["Authorization"] = f"Bearer {os.environ['REACH_LLM_API_KEY']}"
    for attempt in range(8):
        try:
            req = urllib.request.Request(f"{base}/chat/completions", data=body, headers=hdr)
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            msg = e.read()[:300].decode(errors="replace")
            if e.code in (429, 500, 502, 503) and attempt < 7:
                m = re.search(r"try again in ([\d.]+)s", msg)
                time.sleep(min(float(m.group(1)) + 1 if m else 15, 70))
                continue
            raise RuntimeError(f"labeler HTTP {e.code}: {msg}") from None
    raise RuntimeError("labeler rate limited")


def label(tools: list[dict], model: str | None = None, batch: int = 20) -> list[dict | None]:
    """tools: [{server, tool, description}] -> same order, {leg: bool} or None if unanswered."""
    out: list[dict | None] = []
    for i in range(0, len(tools), batch):
        chunk = tools[i:i + batch]
        prompt = "\n".join(f"{j}. server={t['server']} tool={t['tool']} :: {(t.get('description') or '')[:400]}"
                           for j, t in enumerate(chunk))
        txt = chat(prompt, model)
        m = re.search(r"\[.*\]", txt, re.S)
        got = {x.get("i"): x for x in json.loads(m.group(0))} if m else {}
        out += [{leg: bool(got[j].get(leg)) for leg in LEGS} if j in got else None for j in range(len(chunk))]
    return out


def write_legs(g, tool_name: str, legs: dict, labeler: str) -> None:
    for leg, on in legs.items():
        if on:
            rel, lab, target = EDGE[leg]
            g.query(f"MERGE (x:{lab} {{name: $x}}) WITH x MATCH (t:Tool {{name: $n}}) "
                    f"MERGE (t)-[e:{rel}]->(x) ON CREATE SET e.rule = 'llm-onboard', e.why = $why",
                    {"x": target, "n": tool_name, "why": f"labelled by {labeler}"})
