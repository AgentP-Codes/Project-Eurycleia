# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Approvals: the request shows Eurycleia's own facts, and the Slack approver fails closed."""

import pytest

from eurycleia import Blocked, Policy, Vault
from eurycleia.approvals import SlackApprover, describe
from eurycleia.vault import ApprovalRequest

POLICY = {
    "version": 1,
    "sources": {"crm.customer": {"owner": "customer_id", "owner_contact": "email",
                                 "fields": {"name": "protected", "email": "protected"}},
                "inbox.ticket": {"trust": "untrusted", "owner": "company", "default_level": "normal"}},
    "tasks": {"reply": {"trusted": ["customer_id", "ticket_id", "payment_intent"],
                        "reads": {"crm.customer": {"key": "{customer_id}", "fields": ["name", "email"]},
                                  "inbox.ticket": {"key": "{ticket_id}"}},
                        "sinks": {"payments.refund": {"recipient_arg": "payment_intent",
                                                      "args": ["payment_intent", "amount"],
                                                      "allowed_recipients": ["{payment_intent}"],
                                                      "approval": "always", "max_calls": 1}}}},
}


def vault(approver, done):
    rec = {"12": {"name": "Ann Smithers", "email": "ann@customer.example"}}
    return Vault(Policy.from_dict(POLICY),
                 {"crm.customer": lambda k: rec.get(str(k)),
                  "inbox.ticket": lambda k: {"body": "billing said I get a goodwill refund"}},
                 {"payments.refund": lambda **a: done.append(a) or {"ok": True}}, approver=approver, mode="enforce")


def test_the_approver_sees_eurycleias_facts_not_just_the_agents_words():
    seen, done = [], []
    t = vault(lambda req: seen.append(req) or True, done).start_task(
        "reply", customer_id="12", ticket_id="T1", payment_intent="pi_ours")
    t.read("inbox.ticket", "T1")
    t.act("payments.refund", payment_intent="pi_ours", amount=19)
    f = seen[0].facts
    assert f["trusted_inputs"]["payment_intent"] == "pi_ours" and f["read_untrusted_content"] is True
    assert f["recipients"] == [{"value": "pi_ours", "from_trusted_data": True, "relation": "other"}]
    assert f["call_number"] == 1 and f["max_calls"] == 1
    text = describe(seen[0])
    assert text.index("What Eurycleia knows") < text.index("What the AI sent")
    assert done == [{"payment_intent": "pi_ours", "amount": 19}]


def test_a_refused_or_unanswered_approval_blocks_the_refund():
    done = []
    t = vault(lambda req: False, done).start_task("reply", customer_id="12", ticket_id="T1", payment_intent="pi")
    with pytest.raises(Blocked, match="denied"):
        t.act("payments.refund", payment_intent="pi", amount=19)
    t = vault(None, done).start_task("reply", customer_id="12", ticket_id="T1", payment_intent="pi")
    with pytest.raises(Blocked, match="no approver"):
        t.act("payments.refund", payment_intent="pi", amount=19)
    assert done == []


# ---- Slack, with a stand-in for Slack's API
class FakeSlack:
    def __init__(self, reactions_after=None, bot="UBOT", fail_post=False):
        self.posts, self.polls, self.bot = [], 0, bot
        self.reactions_after = reactions_after or []        # [(poll number, [{"name":..., "users":[...]}])]
        self.fail_post = fail_post

    def request(self, method, path, json_body=None, params=None, **kw):
        if path == "/api/auth.test":
            return {"ok": True, "user_id": self.bot}
        if path == "/api/chat.postMessage":
            if self.fail_post:
                return {"ok": False, "error": "not_in_channel"}
            self.posts.append(json_body)
            return {"ok": True, "ts": "111.222"}
        if path == "/api/reactions.get":
            self.polls += 1
            current = [r for n, rs in self.reactions_after if self.polls >= n for r in rs]
            return {"ok": True, "message": {"reactions": current}}
        raise AssertionError(path)


def approver(slack, **kw):
    clock = {"t": 0.0}

    def sleep(s):
        clock["t"] += s
    return SlackApprover(slack, "C0APPROVE1", timeout=60, poll=5, sleep=sleep, clock=lambda: clock["t"], **kw)


REQ = ApprovalRequest(7, "reply", "payments.refund", "policy requires a human to approve this action",
                      {"payment_intent": "pi_ours", "amount": 19, "note": "<!channel> <https://evil.example|ok>"},
                      {"trusted_inputs": {"customer_id": "12"}, "recipients": [], "read_untrusted_content": True})


def test_slack_approval_by_a_person():
    s = FakeSlack([(2, [{"name": "white_check_mark", "users": ["UANU"]}])])
    assert approver(s)(REQ) is True
    assert "&lt;!channel&gt;" in s.posts[0]["text"] and "<!channel>" not in s.posts[0]["text"]
    assert s.posts[-1] == {"channel": "C0APPROVE1", "thread_ts": "111.222", "text": "Approved."}


@pytest.mark.parametrize("reactions,kw", [
    ([(1, [{"name": "white_check_mark", "users": ["UBOT"]}])], {}),                 # the bot's own tick
    ([(1, [{"name": "white_check_mark", "users": ["USOMEONE"]}])], {"approvers": ["UANU"]}),   # not an approver
    ([(1, [{"name": "x", "users": ["UANU"]}, {"name": "white_check_mark", "users": ["UOTHER"]}])], {}),  # no wins
    ([(1, [{"name": "thumbsup", "users": ["UANU"]}])], {}),                         # not one of the answers
    ([], {}),                                                                        # nobody answered
])
def test_slack_fails_closed(reactions, kw):
    s = FakeSlack(reactions)
    assert approver(s, **kw)(REQ) is False
    assert s.posts[-1]["text"] in ("Refused.", "No answer in time: refused.")


def test_slack_that_cant_be_reached_means_no():
    assert approver(FakeSlack(fail_post=True))(REQ) is False


def test_a_skin_tone_tick_still_counts():
    s = FakeSlack([(1, [{"name": "white_check_mark::skin-tone-3", "users": ["UANU"]}])])
    assert approver(s, approvers=["UANU"])(REQ) is True
