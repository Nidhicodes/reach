"""Reach agent: an LLM that picks tools from the Reach MCP server and writes one answer.

The model never sees Cypher and never composes a query. It chooses MCP tools, and its
final sentence is checked against the tool results: any agent/tool/data name it
mentions that no tool returned rejects the sentence, and a flat answer assembled from
the rows goes out instead (degrade to flatter, never to wrong).

LLM: any OpenAI-compatible chat endpoint (OpenAI, Groq, OpenRouter, Ollama, vLLM):
  REACH_LLM_BASE_URL  e.g. https://api.groq.com/openai/v1  or http://127.0.0.1:11434/v1
  REACH_LLM_API_KEY   (optional for local endpoints)
  REACH_LLM_MODEL
Without REACH_LLM_BASE_URL a small offline router picks the tools instead, and the
answer says so -- useful for tests and a no-key demo, never passed off as the model.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from mcp.client.client import Client

MAX_STEPS = 6
SYSTEM = (
    "You are Reach, a security analyst for AI-agent estates. Answer ONLY from tool results. "
    "Always call scan_paths before claiming a risk. Every path you mention must show its hops "
    "(untrusted source -> agents -> private data -> sink). 'not_in_graph' means not modelled, "
    "never 'safe'. Fixes are proposals for human approval. Copy every agent, tool, data and "
    "sink name exactly as a tool returned it; never paraphrase a name. Answer in at most 4 sentences."
)

# a "name" = identifier containing a separator: code-reviewer, github.read_issues, Gmail_GetEmail
NAME = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:[-._:][A-Za-z0-9]+)+\b")
# Models emit typographic hyphens (U+2010..U+2015, U+2212) and zero-width chars inside
# names; normalise them or `research\u2011agent` slips past the name check unseen.
_HYPHENS = re.compile("[\u2010-\u2015\u2212\ufe63\uff0d]")
_INVISIBLE = re.compile("[\u200b-\u200d\u2060\ufeff]")


def normalise(text: str) -> str:
    return _INVISIBLE.sub("", _HYPHENS.sub("-", text))


# Domain vocabulary that looks like a name but is not an entity claim.
TERMS = {
    "lethal-trifecta", "prompt-injected", "prompt-injection", "least-privilege", "zero-break",
    "close-all", "close_all", "zero_break", "multi-hop", "cross-agent", "read-only", "e.g", "i.e",
    "not_in_graph", "answered_with_path", "answered_from_memory", "unknown_agent", "unknown_tool",
    "follow-up", "built-in", "third-party", "high-risk", "long-term", "real-time", "end-to-end",
}


@dataclass
class Step:
    tool: str
    args: dict
    ms: int
    outcome: str


@dataclass
class Answer:
    text: str
    outcome: str
    trace: list[Step] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)
    checked: str = ""  # "ok" | reason the model sentence was rejected
    planner: str = ""  # "llm:<model>" | "offline-router"


# ------------------------------------------------------------------ checking


def _strings(x: Any, out: set[str]) -> set[str]:
    if isinstance(x, str):
        out.add(x)
        out.update(NAME.findall(x))
    elif isinstance(x, dict):
        for k, v in x.items():
            _strings(k, out)
            _strings(v, out)
    elif isinstance(x, (list, tuple)):
        for v in x:
            _strings(v, out)
    return out


def accepts(sentence: str, results: list[dict], question: str = "") -> tuple[bool, str]:
    sentence = normalise(sentence)
    known = _strings(results, set()) | set(NAME.findall(normalise(question)))
    invented = sorted(n for n in set(NAME.findall(sentence)) - known if n.lower() not in TERMS)
    if invented:
        return False, f"named things not in any tool result: {invented}"
    empty = all(r.get("outcome") in ("not_in_graph", "unknown_agent", "unknown_tool", "unknown_name") for r in results)
    if results and empty and re.search(r"\bsafe\b", sentence, re.I):
        return False, "called an unmodelled/empty result safe"
    return True, "ok"


def fallback_text(results: list[dict]) -> str:
    """A flat answer built only from rows."""
    parts = []
    for r in results:
        o = r.get("outcome")
        if o in ("unknown_agent", "unknown_tool", "unknown_name"):
            parts.append(f"{o.replace('_', ' ')}: {r.get('agent') or r.get('tool') or r.get('name')} is not in the graph; nothing was run.")
        elif o == "not_in_graph":
            parts.append(r.get("note", "Nothing in the graph connects this the way the question assumed."))
        elif "paths" in r:
            for p in r["paths"][:5]:
                parts.append(f"{p['untrusted']} -> {' -> '.join(p['handoff'])} -> {p['private']} -> {p['sink']}")
            if len(r["paths"]) > 5:
                parts.append(f"(+{len(r['paths']) - 5} more paths)")
        elif "actions" in r:
            parts.append("Proposed (needs human approval): " + "; ".join(r["actions"]) +
                         (f". {len(r['residual_paths'])} path(s) need the runtime guard." if r["residual_paths"] else ""))
        elif o in ("blocked", "allowed"):
            parts.append(f"{o}: {r.get('reason', '')}".strip(": "))
        elif "chokepoints" in r:
            parts.append("Chokepoints (paths through / betweenness): " + ", ".join(
                f"{c['name']} ({c['paths_through']}/{c['score']})" for c in r["chokepoints"][:5]))
        elif "routes" in r:
            for rt in r["routes"][:3]:
                parts.append(" -> ".join(rt["hops"]))
        elif "agents" in r:
            parts.append("Agents: " + ", ".join(a["agent"] for a in r["agents"]))
    return "; ".join(parts) or "No tool returned anything to answer from."


# ------------------------------------------------------------------ planners


def _openai_tools(mcp_tools) -> list[dict]:
    return [{"type": "function", "function": {
        "name": t.name, "description": t.description or "", "parameters": t.input_schema or t.inputSchema,
    }} for t in mcp_tools]


class LLM:
    def __init__(self):
        self.base = os.environ["REACH_LLM_BASE_URL"].rstrip("/")
        self.model = os.environ.get("REACH_LLM_MODEL", "gpt-4o-mini")
        key = os.environ.get("REACH_LLM_API_KEY")
        self.headers = {"Content-Type": "application/json", "User-Agent": "reach/0.1",
                        **({"Authorization": f"Bearer {key}"} if key else {})}

    def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        body = json.dumps({"model": self.model, "messages": messages, "tools": tools, "temperature": 0}).encode()
        for attempt in range(5):
            req = urllib.request.Request(f"{self.base}/chat/completions", data=body, headers=self.headers)
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return json.load(r)["choices"][0]["message"]
            except urllib.error.HTTPError as e:
                msg = e.read()[:300].decode(errors="replace")
                if e.code == 429 and attempt < 4:  # free tiers rate-limit per minute; honour "try again in Ns"
                    m = re.search(r"try again in ([\d.]+)s", msg)
                    time.sleep(min(float(m.group(1)) + 1 if m else 10, 65))
                    continue
                raise RuntimeError(f"LLM HTTP {e.code}: {msg}") from None
        raise RuntimeError("LLM rate limited")


def offline_plan(question: str, agents: list[str]) -> list[tuple[str, dict]]:
    """Keyword router for no-key runs. Deliberately dumb and labelled as such."""
    q = question.lower()
    named = [a for a in agents if a.lower() in q]
    unknown = [w for w in NAME.findall(question) if w not in agents and "-" in w]
    if unknown and not named:
        return [("scan_paths", {"agent": unknown[0]})]
    m = re.search(r"how (?:does|can|could) (\S+) (?:reach|get to|flow to|leak to) (\S+?)[?.]?$", q)
    if m:
        return [("explain_reach", {"src": m.group(1), "dst": m.group(2)})]
    if re.search(r"\b(chokepoint|bottleneck|central|single point)", q):
        return [("chokepoints", {})]
    plan = [("scan_paths", {"agent": named[0]} if named else {})]
    if re.search(r"\b(fix|close|remediat|least.privilege|cut)", q):
        plan.append(("propose_fix", {"mode": "close_all" if "everything" in q or "all" in q.split() else "zero_break"}))
    return plan


# ------------------------------------------------------------------ loop


def _payload(res) -> dict:
    sc = getattr(res, "structured_content", None)
    if sc:
        return sc.get("result", sc)
    return json.loads(res.content[0].text)


async def ask(question: str, server) -> Answer:
    """`server` is anything mcp Client accepts: the in-process MCPServer, a URL, or stdio params."""
    trace: list[Step] = []
    results: list[dict] = []
    async with Client(server) as c:

        async def call(name: str, args: dict) -> dict:
            t = time.time()
            res = _payload(await c.call_tool(name, args))
            trace.append(Step(name, args, round((time.time() - t) * 1000), res.get("outcome", "")))
            results.append(res)
            return res

        if not os.environ.get("REACH_LLM_BASE_URL"):
            agents = [a["agent"] for a in (await call("list_agents", {}))["agents"]]
            results.pop(), trace.pop()  # roster lookup is routing, not evidence
            for name, args in offline_plan(question, agents):
                await call(name, args)
            text = fallback_text(results)
            return Answer(text, results[-1].get("outcome", ""), trace, results, "ok", "offline-router")

        llm = LLM()
        tools = _openai_tools((await c.list_tools()).tools)
        msgs: list[dict] = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": question}]
        text = ""
        for _ in range(MAX_STEPS):
            m = llm.chat(msgs, tools)
            msgs.append({k: v for k, v in m.items() if v is not None})
            if not m.get("tool_calls"):
                text = m.get("content") or ""
                break
            for tc in m["tool_calls"]:
                try:
                    args = json.loads(tc["function"]["arguments"] or "{}")
                    res = await call(tc["function"]["name"], args)
                except Exception as e:  # bad args / unknown tool: tell the model, keep going
                    res = {"outcome": "tool_error", "error": str(e)[:300]}
                msgs.append({"role": "tool", "tool_call_id": tc["id"], "content": json.dumps(res, default=str)[:12000]})

    ok, why = accepts(text, results, question) if text else (False, "model gave no final answer")
    if not results:
        ok, why = False, "model answered without calling any tool"
    final = normalise(text) if ok else fallback_text(results)
    outcome = results[-1].get("outcome", "") if results else "no_tool_called"
    return Answer(final, outcome, trace, results, why, f"llm:{llm.model}")


def main():
    import asyncio
    import sys

    from reach.mcp_server import mcp

    a = asyncio.run(ask(" ".join(sys.argv[1:]) or "What can our agents reach if injected?", mcp))
    for s in a.trace:
        print(f"  {s.tool:13} {json.dumps(s.args):60} {s.ms:4} ms  {s.outcome}")
    print(f"[{a.planner}] [check: {a.checked}]\n{a.text}")


if __name__ == "__main__":
    main()
