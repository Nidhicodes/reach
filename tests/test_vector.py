import pytest

pytest.importorskip("fastembed")

from reach import vector as V  # noqa: E402
from reach.db import connect  # noqa: E402


def test_unknown_tool_inherits_legs_from_nearest_labelled_tools(tmp_path):
    g = connect("vec_t", path=str(tmp_path / "v.db"))
    rows = [
        {"name": "mail.send_email", "server": "mail", "text": V.text("mail", "send_email", "Send an email to any address"),
         "untrusted": False, "private": False, "external": True, "acts": False},
        {"name": "mail.forward", "server": "mail", "text": V.text("mail", "forward_email", "Forward an email to a recipient"),
         "untrusted": False, "private": False, "external": True, "acts": False},
        {"name": "docs.read", "server": "docs", "text": V.text("docs", "read_document", "Read a private document"),
         "untrusted": False, "private": True, "external": False, "acts": False},
    ]
    V.index_tools(g, rows)
    r = V.classify(g, "acme-mailer", "dispatch_message", "Send a message by email to a recipient", k=2)
    assert r["external"] and not r["private"]
    assert r["neighbours"][0]["name"].startswith("mail.")
    g.delete()
