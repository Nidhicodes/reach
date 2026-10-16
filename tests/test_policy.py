from reach.gateway import verdict

PRIOR = [{"seq": 1, "agent": "a", "tool": "web.fetch", "leg": "INGESTS", "target": "web"},
         {"seq": 2, "agent": "a", "tool": "bank.balance", "leg": "READS", "target": "balance"}]
PAY = [{"leg": "ACTS_ON", "target": "state-change"}]
SEND = [{"leg": "SENDS_TO", "target": "email"}]


def test_trifecta_ignores_state_change_but_rule_of_two_blocks_it():
    assert verdict(PRIOR, PAY, "bank.send_money", "trifecta")["verdict"] == "allowed"
    v = verdict(PRIOR, PAY, "bank.send_money", "rule-of-two")
    assert v["verdict"] == "blocked" and "Rule of Two" in v["reason"]


def test_both_policies_block_exfiltration():
    for p in ("trifecta", "rule-of-two"):
        assert verdict(PRIOR, SEND, "mail.send", p)["verdict"] == "blocked"


def test_no_untrusted_input_means_no_block():
    assert verdict(PRIOR[1:], SEND + PAY, "mail.send", "rule-of-two")["verdict"] == "allowed"
