# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
import copy

import pytest

from demo.__main__ import POLICY
from demo.world import ATTACKER, World
from taskvault import AuditLog, Blocked, Policy, PolicyError, Vault
from taskvault.crypto import Cipher, LocalKeyProvider
from taskvault.planner import Planner


def _vault(world, policy=None, **kw):
    return Vault(policy or Policy.load(POLICY),
                 {"crm.customer": world.get_customer, "docs": world.get_doc, "inbox.ticket": world.get_ticket},
                 {"email.send": world.send_email, "payments.refund": world.refund}, **kw)


@pytest.fixture
def cipher(tmp_path):
    return Cipher(LocalKeyProvider(tmp_path / "k.key"))


# ---- pseudonymisation ---------------------------------------------------------

def _pseudo_policy():
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["sources"]["crm.customer"]["pseudonymize"] = ["name", "email"]
    return Policy.from_dict(raw)


def test_model_sees_stable_pseudonyms_not_real_values(cipher):
    world = World()
    vault = _vault(world, _pseudo_policy(), cipher=cipher)
    c1 = vault.start_task("support_reply", customer_id=12).read("crm.customer")
    c2 = vault.start_task("support_reply", customer_id=12).read("crm.customer")
    assert c1["name"].startswith("Name-") and c1["email"].endswith("@pseudonym.invalid")
    assert "Priya" not in str(c1) and "priya" not in str(c1)
    assert c1["name"] == c2["name"] and c1["email"] == c2["email"]     # consistent across tasks


def test_pseudonyms_are_swapped_back_only_at_the_sink():
    world = World()
    t = _vault(world, _pseudo_policy()).start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    t.act("email.send", to=c["email"], subject="Hi", body=f"Hi {c['name']}, sorted!")
    assert world.outbox == [{"to": "priya.shah@example.com", "subject": "Hi", "body": "Hi Priya Shah, sorted!"}]


def test_pseudonymised_data_still_cant_go_to_an_attacker():
    world = World()
    t = _vault(world, _pseudo_policy()).start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    with pytest.raises(Blocked):
        t.act("email.send", to=ATTACKER, subject="x", body=c["name"])
    assert world.outbox == []


def test_planner_mode_resolves_pseudonymous_recipients():
    world = World()
    t = _vault(world, _pseudo_policy()).start_task("support_reply_planned", customer_id=12, ticket_id="T-100")
    Planner(t).run([{"id": "c", "read": "crm.customer"},
                    {"id": "m", "format": "Hi {c.name}"},
                    {"act": "email.send", "args": {"to": "$c.email", "subject": "Hi", "body": "$m"}}])
    assert world.outbox[0]["to"] == "priya.shah@example.com" and world.outbox[0]["body"] == "Hi Priya Shah"


def test_secret_fields_cannot_be_pseudonymised():
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["sources"]["crm.customer"]["pseudonymize"] = ["card_number"]
    with pytest.raises(PolicyError, match="placeholders"):
        Policy.from_dict(raw)


# ---- imported labels ------------------------------------------------------------

def test_existing_labels_raise_the_level_of_a_document():
    world = World()
    world.docs["refund_policy"]["sensitivity"] = "Highly Confidential"
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["sources"]["docs"].update({"label_field": "sensitivity",
                                   "label_map": {"Public": "normal", "Highly Confidential": "protected"}})
    t = _vault(world, Policy.from_dict(raw)).start_task("support_reply", customer_id=12)
    body = t.read("docs", "refund_policy")["body"]
    with pytest.raises(Blocked, match="owner company"):
        t.act("email.send", to="priya.shah@example.com", subject="policy", body=body)


# ---- risk tiers, outbound detection -----------------------------------------------

def test_medium_risk_actions_are_allowed_but_flagged():
    world, flags = World(), []
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["tasks"]["support_reply"]["sinks"]["email.send"]["risk"] = "medium"
    audit = AuditLog()
    t = _vault(world, Policy.from_dict(raw), audit=audit, on_flag=flags.append).start_task("support_reply",
                                                                                            customer_id=12)
    t.act("email.send", to="priya.shah@example.com", subject="Hi", body="Hello")
    assert world.outbox and flags[0].reasons == ["medium-risk action"]
    assert audit.decisions("flag")


def test_high_risk_means_human_approval():
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["tasks"]["support_reply"]["sinks"]["email.send"]["risk"] = "high"
    policy = Policy.from_dict(raw)
    assert policy.tasks["support_reply"].sinks["email.send"].approval == "always"
    raw["tasks"]["support_reply"]["sinks"]["email.send"]["approval"] = "never"
    with pytest.raises(PolicyError):
        Policy.from_dict(raw)


def test_outbound_detection_catches_secrets_the_vault_never_saw():
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["detect_outbound"] = True
    world = World()
    t = _vault(world, Policy.from_dict(raw)).start_task("support_reply", customer_id=12)
    with pytest.raises(Blocked, match="payment card number"):
        t.act("email.send", to="priya.shah@example.com", subject="x", body="Tom's card is 5555 5555 5555 4444")
    t.act("email.send", to="priya.shah@example.com", subject="x", body="Your order 12345 has shipped")
    assert len(world.outbox) == 1


# ---- CLI --------------------------------------------------------------------------------

def test_cli_review_lists_flagged_actions(tmp_path, capsys):
    from taskvault.cli import main
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("flag", task=1, sink="email.send", reasons=["medium-risk action"], decision="flag")
    assert main(["review", "--audit", str(path)]) == 0
    assert "medium-risk action" in capsys.readouterr().out
