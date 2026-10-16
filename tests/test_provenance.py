import asyncio
import json
from contextlib import AsyncExitStack

from reach import provenance as P
from reach.db import connect
from reach.gateway import Gateway
from reach.mock_servers import build
from reach.redteam import ATTACKER


def test_entities_normalise_emails_ibans_and_domains():
    e = P.entities("Mail Bob@Acme.example or pay GB29 NWBK 6016 1331 9268 19, see https://www.acme.example/x")
    assert {"email:bob@acme.example", "iban:GB29NWBK60161331926819"} <= e
    assert "url:acme.example" not in e  # domain of an email already listed is not a separate URL


def test_vouched_destination_passes_and_injected_one_stays_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("REACH_OUTBOX", str(tmp_path / "outbox.jsonl"))
    g = connect("prov_t", path=str(tmp_path / "p.db"))

    async def run(to: str, task: str):
        gw = Gateway(g, "support-bot", {k: build(k) for k in ("zendesk", "postgres", "gmail")}, task=task,
                     provenance=True, trusted="finance@acme.example")
        async with AsyncExitStack() as s:
            await gw.open(s)
            await gw.call("zendesk__get_ticket", {"id": 4522})
            await gw.call("postgres__query", {"sql": "select *"})
            return await gw.call("gmail__send_email", {"to": to, "subject": "s", "body": "b"})

    ok = asyncio.run(run("finance@acme.example", "p1"))
    bad = asyncio.run(run(ATTACKER, "p2"))
    assert not ok.is_error
    assert bad.is_error and bad.structured_content["reach"]["provenance"]["unvouched"] == [f"email:{ATTACKER}"]
    sent = [json.loads(x)["to"] for x in (tmp_path / "outbox.jsonl").read_text().splitlines()]
    assert sent == ["finance@acme.example"]
    # the attacker address entered via the untrusted ticket: recorded, but not as a trusted sighting
    r = g.ro_query("MATCH (c:Call)-[s:SAW]->(:Entity {value: $e}) RETURN s.trusted", {"e": f"email:{ATTACKER}"}).result_set
    assert r and all(x[0] is False for x in r)
    g.delete()
