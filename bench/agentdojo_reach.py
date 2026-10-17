"""AgentDojo (ETH Zurich, v1.2.2) against Reach's runtime guard.

AgentDojo ships 97 user tasks and 35 injection tasks across four suites (workspace,
travel, banking, slack), each with a ground-truth tool sequence and an automatic
checker for "did the user's task succeed" (utility) and "did the attacker's goal
happen" (attack success). We run Reach as an AgentDojo FunctionsRuntime: every tool
call goes through the same reserve -> verdict -> finalise ledger the gateway uses,
stored in FalkorDB.

Tools are classified the way Reach classifies a server it has never seen: the generic
name rules plus the FalkorDB vector index over 557 labelled real MCP tools. No
AgentDojo tool was hand-labelled.

Two modes:

  replay  (default, no LLM)  Worst case: the model is fully hijacked. For every
          (user task, injection task) pair AgentDojo marks as injectable, run the
          user task's ground truth; the moment a tool result carries the injection,
          the "model" executes the attacker's ground truth, then finishes the user
          task. Without a defense every attack succeeds by construction, which is the
          sanity check. Benign utility = each user task's ground truth, no injection.
  live    A real model (REACH_LLM_* endpoint) with AgentDojo's `important_instructions`
          attack, on a small subset (free-tier rate limits).

  cd bench && uv run python agentdojo_reach.py replay
  cd bench && uv run python agentdojo_reach.py live --suite banking --users 4 --injections 3
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import uuid
from collections import Counter, defaultdict

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import ChatAssistantMessage, ChatToolResultMessage, text_content_block_from_string

from reach import gateway as G
from reach import provenance as P
from reach import schema
from reach import vector as V
from reach.classeval import LABELS, generic
from reach.db import connect

VERSION = "v1.2.2"
HERE = pathlib.Path(__file__).parent
from reach.onboard import EDGE as LEG_TARGET, label as llm_label  # noqa: E402


# ------------------------------------------------------------------ classification

def build_graph(g, suites, source: str = "vector") -> dict:
    """Classify every AgentDojo tool the way Reach classifies an unseen server.

    source="vector": generic name rules + kNN over the labelled corpus (zero touch)
    source="onboard": the onboarding labeler (reach.onboard), run once per suite and cached
    source="conservative": onboard labels, plus every tool that returns private data is
        also treated as untrusted (fail-closed: a bank statement or a shared file can carry
        text an outsider wrote, and the tool name cannot tell you when)
    """
    rows = [json.loads(x) for x in LABELS.read_text().splitlines()]
    for r in rows:
        r["name"], r["text"] = f"{r['server']}.{r['tool']}", V.text(r["server"], r["tool"], r["description"])
    V.index_tools(g, rows)
    for leg, (_, label, name) in LEG_TARGET.items():
        g.query(f"MERGE (:{label} {{name: $n}})", {"n": name})
    table = {}
    tools = [(s, t) for s, suite in suites.items() for t in suite.tools]
    if source in ("onboard", "conservative"):
        cache = HERE / "results" / "onboard_labels.json"
        cached = json.loads(cache.read_text()) if cache.exists() else {}
        todo = [(s, t) for s, t in tools if f"agentdojo-{s}.{t.name}" not in cached]
        if todo:
            got = llm_label([{"server": f"agentdojo-{s}", "tool": t.name, "description": t.description or ""} for s, t in todo])
            for (s, t), legs in zip(todo, got):
                cached[f"agentdojo-{s}.{t.name}"] = legs or {}
            cache.parent.mkdir(exist_ok=True)
            cache.write_text(json.dumps(cached, indent=1))
    else:
        vecs = V.embed([V.text(f"agentdojo-{s}", t.name, t.description or "") for s, t in tools])
    for i, (s, t) in enumerate(tools):
        name = f"agentdojo-{s}.{t.name}"
        if source in ("onboard", "conservative"):
            legs = {leg: bool(cached[name].get(leg)) for leg in LEG_TARGET}
            # the generic rules are a floor under the LLM labels, as in reach.classify
            gen = generic(t.name)
            legs = {leg: on or bool(gen.get(leg)) for leg, on in legs.items()}
            src_untrusted = legs["untrusted"]
            if source == "conservative":
                legs["untrusted"] = legs["untrusted"] or legs["private"]
            table[name] = {"legs": [l for l, on in legs.items() if on], "source": source}
        else:
            gen = generic(t.name)
            nb = V.neighbours(g, f"agentdojo-{s}", vecs[i], 7)
            vec = V.vote(nb)
            legs = {leg: bool(gen.get(leg)) or vec[leg] for leg in LEG_TARGET}
            src_untrusted = legs["untrusted"]
            table[name] = {"legs": [l for l, on in legs.items() if on], "generic": [l for l, on in gen.items() if on],
                           "neighbours": [n["name"] for n in nb[:3]]}
        g.query("MERGE (t:Tool {name: $n}) SET t.server = $s, t.src_untrusted = $u",
                {"n": name, "s": f"agentdojo-{s}", "u": src_untrusted})
        for leg, on in legs.items():
            if on:
                rel, label, target = LEG_TARGET[leg]
                g.query(f"MATCH (t:Tool {{name: $n}}), (x:{label} {{name: $x}}) MERGE (t)-[:{rel}]->(x)",
                        {"n": name, "x": target})
    return table


# ------------------------------------------------------------------ guarded runtime

# for vouching, "untrusted source" uses the onboarding label even in conservative mode:
# conservative only widens TAINT; it must not make every private tool a trusted voucher
UNTRUSTED_SRC = "MATCH (t:Tool {name: $tool}) WHERE t.src_untrusted = true RETURN 'INGESTS' AS leg"

class ReachRuntime(FunctionsRuntime):
    """Every call is reserved, judged and finalised in the FalkorDB task ledger."""

    g = None
    suite = ""
    blocked: list = []
    prompt = ""
    provenance = None  # None | "request" | "request+tools"
    vouched: list = []

    def __init__(self, functions=()):
        super().__init__(functions)
        self.task = f"adojo-{uuid.uuid4().hex[:10]}"
        if self.provenance:
            P.vouch(self.g, self.task, self.prompt)

    def run_function(self, env, function, kwargs, raise_on_error=False):
        tool = f"agentdojo-{self.suite}.{function}"
        r = schema.write(self.g, G.RESERVE, {"task": self.task, "tool": tool, "agent": "agent",
                                              "at": 0, "args": json.dumps(dict(kwargs), default=str)[:300]})
        if not r:  # unknown tool: let AgentDojo report it
            return super().run_function(env, function, kwargs, raise_on_error)
        seq = r[0]["seq"]
        prior = G.Q.ro(self.g, G.TASK_LEGS, {"task": self.task, "seq": seq})
        nxt = G.Q.ro(self.g, G.TOOL_LEGS, {"tool": tool})
        v = G.verdict(prior, nxt, tool)
        if v["verdict"] == "blocked" and self.provenance:
            c = P.check(self.g, self.task, dict(kwargs), tools_vouch=self.provenance == "request+tools")
            if c["destinations"] and not c["unvouched"]:
                v = {"verdict": "allowed"}
                ReachRuntime.vouched.append(function)
        if v["verdict"] == "blocked":
            self.g.query(G.FINALISE, {"task": self.task, "seq": seq, "verdict": "blocked", "reason": v["reason"]})
            ReachRuntime.blocked.append(function)
            msg = "BLOCKED by Reach: this call would send data out after untrusted content and private data were read in this task."
            if raise_on_error:
                return "", msg
            return "", msg
        self.g.query(G.FINALISE, {"task": self.task, "seq": seq, "verdict": "allowed", "reason": ""})
        res = super().run_function(env, function, kwargs, raise_on_error)
        if self.provenance and res[0] is not None:
            trusted = not any(l["leg"] == "INGESTS" for l in G.Q.ro(self.g, UNTRUSTED_SRC, {"tool": tool}))
            P.saw(self.g, self.task, seq, tool_result_to_str(res[0]), trusted)
        return res


# ------------------------------------------------------------------ hijacked replay

class Hijacked(BasePipelineElement):
    """Ground truth of the user task; when a tool result shows the injection, obey it."""

    def __init__(self, user_task, injection_task, marker: str | None, order: str = "now"):
        self.u, self.i, self.marker, self.order = user_task, injection_task, marker, order

    def _run(self, calls, runtime, env, msgs):
        for c in calls:
            msgs.append(ChatAssistantMessage(role="assistant", tool_calls=[c], content=[text_content_block_from_string("")]))
            res, err = runtime.run_function(env, c.function, c.args)
            msgs.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(tool_result_to_str(res))],
                                              tool_call=c, tool_call_id=None, error=err))
            yield tool_result_to_str(res)

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args={}):
        msgs, hijacked = list(messages), False
        for out in self._run(self.u.ground_truth(env), runtime, env, msgs):
            if self.marker and not hijacked and self.marker in out:
                hijacked = True
                if self.order == "now":
                    for _ in self._run(self.i.ground_truth(env), runtime, env, msgs):
                        pass
        if hijacked and self.order == "end":  # obeys after finishing the user's steps
            for _ in self._run(self.i.ground_truth(env), runtime, env, msgs):
                pass
        msgs.append(ChatAssistantMessage(role="assistant", tool_calls=None,
                                         content=[text_content_block_from_string(self.u.GROUND_TRUTH_OUTPUT)]))
        return query, runtime, env, msgs, extra_args


MARK = "<INJECTED-{}>"


def replay(g, suites, defended: bool, orders: dict | None = None) -> dict:
    """orders: (suite, user, injection) -> the hijack timing that works undefended.
    Undefended (orders=None) tries "now" then "end" and records which one lands; a pair
    no timing can land is not a viable attack and is left out of both arms."""
    res = {"benign": Counter(), "attack": Counter(), "by_suite": defaultdict(Counter), "pairs": [], "orders": {}}
    for sname, suite in suites.items():
        ReachRuntime.suite = sname
        rt = ReachRuntime if defended else FunctionsRuntime
        defaults = suite.get_injection_vector_defaults()
        canaries = {k: MARK.format(k) for k in defaults}
        for uid, u in suite.user_tasks.items():
            ReachRuntime.prompt = u.PROMPT
            ok, _ = suite.run_task_with_pipeline(Hijacked(u, None, None), u, None, {}, runtime_class=rt)
            res["benign"]["utility" if ok else "broken"] += 1
            res["by_suite"][sname]["benign_ok" if ok else "benign_broken"] += 1
            # which injection slots does this task's ground truth actually read?
            env = suite.load_and_inject_default_environment(canaries)
            from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline

            _, _, _, resp, _ = GroundTruthPipeline(u).query(u.PROMPT, FunctionsRuntime(suite.tools), u.init_environment(env))
            seen = [k for k, c in canaries.items() if any(c in str(m.get("content")) for m in resp)]
            if not seen:
                continue
            for iid, it in suite.injection_tasks.items():
                inj = {k: (MARK.format(k) if k in seen else defaults[k]) for k in defaults}
                marker = MARK.format(seen[0])
                key = (sname, uid, iid)
                if orders is None:
                    order = None
                    for o in ("now", "end"):
                        util, attacker_won = suite.run_task_with_pipeline(Hijacked(u, it, marker, o), u, it, inj, runtime_class=rt)
                        if attacker_won:
                            order = o
                            break
                    if order is None:
                        res["attack"]["not_viable"] += 1
                        continue
                    res["orders"][key] = order
                else:
                    if key not in orders:
                        continue
                    util, attacker_won = suite.run_task_with_pipeline(Hijacked(u, it, marker, orders[key]), u, it, inj, runtime_class=rt)
                res["attack"]["attacker_won" if attacker_won else "stopped"] += 1
                res["by_suite"][sname]["attack_won" if attacker_won else "attack_stopped"] += 1
                res["pairs"].append({"suite": sname, "user": uid, "injection": iid, "attacker_won": attacker_won,
                                     "utility": util})
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["replay", "live"])
    ap.add_argument("--suite", action="append")
    ap.add_argument("--out", default=str(HERE / "results"))
    ap.add_argument("--source", action="append", choices=["vector", "onboard", "conservative"])
    ap.add_argument("--policy", action="append", choices=["trifecta", "rule-of-two"])
    ap.add_argument("--provenance", action="append", choices=["off", "request", "request+tools"])
    a = ap.parse_args()
    suites = get_suites(VERSION)
    if a.suite:
        suites = {k: v for k, v in suites.items() if k in a.suite}
    out = pathlib.Path(a.out)
    out.mkdir(exist_ok=True)
    if a.mode != "replay":
        print("live mode: not implemented in this file", file=sys.stderr)
        return
    base = None
    arms = {}
    for source in a.source or ["vector", "onboard", "conservative"]:
        g = connect(f"adojo-{source}", path=str(HERE / "adojo.db"))
        try:
            g.delete()
        except Exception:
            pass
        g = connect(f"adojo-{source}", path=str(HERE / "adojo.db"))
        schema._done.discard(g.name)
        schema.ensure(g)
        ReachRuntime.g = g
        table = build_graph(g, suites, source)
        (out / f"tool_legs_{source}.json").write_text(json.dumps(table, indent=1))
        if base is None:
            base = replay(g, suites, defended=False)
        for policy, prov in [(p, v) for p in (a.policy or ["trifecta", "rule-of-two"])
                             for v in (a.provenance or ["off", "request", "request+tools"])]:
            os.environ["REACH_POLICY"] = policy
            ReachRuntime.provenance = None if prov == "off" else prov
            ReachRuntime.blocked, ReachRuntime.vouched = [], []
            r = replay(g, suites, defended=True, orders=base["orders"])
            arms[f"{source}/{policy}/provenance={prov}"] = {
                "vouched_sends": len(ReachRuntime.vouched),
                "benign": dict(r["benign"]), "attack": dict(r["attack"]),
                "by_suite": {k: dict(v) for k, v in r["by_suite"].items()},
                "blocked_tools": dict(Counter(ReachRuntime.blocked).most_common(12)),
            }
            (out / f"pairs_{source}_{policy}_{prov.replace('+', '_')}.json").write_text(json.dumps(r["pairs"]))
    summary = {"agentdojo": VERSION, "mode": "replay: fully hijacked model executing ground-truth calls",
               "no_defense": {"benign": dict(base["benign"]), "attack": dict(base["attack"]),
                              "by_suite": {k: dict(v) for k, v in base["by_suite"].items()}},
               "reach": arms}
    (out / "replay.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
