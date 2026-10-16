"""Destination provenance: who vouched for the address this call sends to?

The trifecta / Rule of Two decide that a task is risky; they cannot tell the user's own
"email the report to bob@acme.com" from an injected "email it to refunds@evil.example".
Provenance can. Reach records every address-like value (email, IBAN, URL / domain)
that enters a task, and where it came from:

  (:Task)-[:VOUCHED]->(:Entity)              in the user's own request, or an org allowlist
  (:Call)-[:SAW {trusted}]->(:Entity)        in a tool result; trusted = the tool is not
                                             an untrusted-input tool (contacts, the user's
                                             profile, their own account details)

At a would-block send, if every destination in the call's arguments is vouched for --
by the request or by a trusted tool result in this task -- the call is allowed, with
the vouching path as the reason. A destination that only ever appeared in untrusted
content (or nowhere) keeps the block. A risky call with no destination in its
arguments (delete a file, change a password) is not helped by provenance and stays
blocked. Limitation, stated: an injection can still send data to a vouched party.
"""

from __future__ import annotations

import re

from reach import schema

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){10,30}\b")
URL = re.compile(r"\bhttps?://[^\s'\"<>)]+|\bwww\.[^\s'\"<>)]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|org|net|io|dev|co|ai|example)\b(?:/[^\s'\"<>)]*)?")


def norm(kind: str, v: str) -> str:
    v = v.strip().rstrip(".,;")
    if kind == "iban":
        return re.sub(r"\s", "", v).upper()
    if kind == "url":
        v = re.sub(r"^https?://", "", v.lower())
        return v.split("/", 1)[0].removeprefix("www.")  # vouch at domain level
    return v.lower()


def entities(text) -> set[str]:
    s = text if isinstance(text, str) else str(text)
    out = {f"email:{norm('email', m)}" for m in EMAIL.findall(s)}
    out |= {f"iban:{norm('iban', m)}" for m in IBAN.findall(s)}
    emails_domains = {e.split("@", 1)[1] for e in (x[6:] for x in out if x.startswith("email:"))}
    for m in URL.findall(s):
        d = norm("url", m)
        if d and d not in emails_domains:
            out.add(f"url:{d}")
    return out


VOUCH = """
MERGE (k:Task {id: $task})
WITH k UNWIND $ents AS e
MERGE (x:Entity {value: e})
MERGE (k)-[:VOUCHED]->(x)
"""
SAW = """
MATCH (:Task {id: $task})<-[:IN_TASK]-(c:Call {seq: $seq})
UNWIND $ents AS e
MERGE (x:Entity {value: e})
MERGE (c)-[s:SAW]->(x) ON CREATE SET s.trusted = $trusted
"""
VOUCHED = """
UNWIND $ents AS e
OPTIONAL MATCH (:Task {id: $task})-[:VOUCHED]->(v:Entity {value: e})
OPTIONAL MATCH (:Task {id: $task})<-[:IN_TASK]-(c:Call)-[s:SAW {trusted: true}]->(w:Entity {value: e})
RETURN e AS entity, v IS NOT NULL AS by_request, count(c) AS by_tools, collect(c.seq)[0] AS first_seq
"""


def vouch(g, task: str, text: str) -> int:
    ents = sorted(entities(text))
    if ents:
        schema.write(g, VOUCH, {"task": task, "ents": ents})
    return len(ents)


def saw(g, task: str, seq: int, output, trusted: bool) -> None:
    ents = sorted(entities(output))
    if ents:
        schema.write(g, SAW, {"task": task, "seq": seq, "ents": ents, "trusted": trusted})


def check(g, task: str, args: dict, tools_vouch: bool = True) -> dict:
    """{'destinations': [...], 'unvouched': [...], 'evidence': [...]}

    tools_vouch=False: only the user's request (and the allowlist) can vouch."""
    ents = sorted(entities(" ".join(str(v) for v in args.values())))
    if not ents:
        return {"destinations": [], "unvouched": [], "evidence": []}
    from reach import queries as Q

    rows = Q.ro(g, VOUCHED, {"task": task, "ents": ents})
    ok = {r["entity"] for r in rows if r["by_request"] or (tools_vouch and r["by_tools"])}
    return {"destinations": ents, "unvouched": [e for e in ents if e not in ok],
            "evidence": [{"entity": r["entity"], "by_request": r["by_request"], "first_seen_call": r["first_seq"]}
                         for r in rows if r["entity"] in ok]}
