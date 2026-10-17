# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Fuzz tests: thousands of generated inputs against the vault's rules.

Run a heavier pass with:  EURYCLEIA_FUZZ_EXAMPLES=5000 pytest tests/test_fuzz.py
"""

import copy
import json
import os
import re
from email.utils import getaddresses

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from demo.__main__ import POLICY, make_vault  # noqa: E402
from demo.world import World  # noqa: E402
from eurycleia import Blocked, Policy, SinkError, Vault  # noqa: E402

N = int(os.environ.get("EURYCLEIA_FUZZ_EXAMPLES", "300"))
FUZZ = settings(max_examples=N, deadline=None, suppress_health_check=list(HealthCheck), derandomize=False)

OWNER = "priya.shah@example.com"
CARD_DIGITS = "4111111111111111"
OTHERS = ["tom.nguyen@example.net", "leila.h@example.org", "attacker@evil.example", "x@acme.example.evil.example"]
PIECES = [OWNER, "Priya.Shah@Example.com", "staff@acme.example", *OTHERS,
          " ", ",", ";", "<", ">", "(", ")", '"', "'", "\\", ":", "@", ".", "..",
          "\r", "\n", "\t", "\x00", "​", "‎", "﻿", "＠", "р", "․",
          "Priya Shah ", "mailto:", "bcc:", "%0a", "=?utf-8?q?", "example.com", "acme.example", "evil"]


def staff_glob_vault(world):
    data = copy.deepcopy(Policy.load(POLICY).raw)
    data["internal_domains"] = ["acme.example"]
    data["tasks"]["support_reply"]["sinks"]["email.send"]["allowed_recipients"].append("*@acme.example")
    return Vault(Policy.from_dict(data),
                 {"crm.customer": world.get_customer, "docs": world.get_doc, "inbox.ticket": world.get_ticket},
                 {"email.send": world.send_email, "payments.refund": world.refund})


def delivered_to(to: str) -> list[str]:
    """Every address a mail system could read out of the value the sink received."""
    found = re.findall(r"[^\s<>(),;:\"'@]+@[^\s<>(),;:\"'@]+", to)
    return sorted({a.lower().strip(".") for a in found} | {a.lower() for _, a in getaddresses([to]) if a})


recipient = st.lists(st.sampled_from(PIECES), min_size=1, max_size=6).map("".join) | st.text(max_size=40)


@FUZZ
@given(to=recipient)
def test_fuzz_recipients_only_owner_or_company_ever_receive_data(to):
    world = World()
    task = staff_glob_vault(world).start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    try:
        task.act("email.send", to=to, subject="Your account", body=f"{c['name']} {c['email']} {c['plan']}")
    except (Blocked, SinkError):
        return
    assert len(world.outbox) == 1
    got = world.outbox[0]["to"]
    for addr in delivered_to(got):
        assert addr == OWNER or addr.endswith("@acme.example"), (to, got)
    assert not any(o in got.lower() for o in OTHERS), (to, got)
    assert all(ord(ch) >= 32 and ch.isascii() for ch in got), (to, got)


@FUZZ
@given(to=recipient, cc=recipient | st.none())
def test_fuzz_cc_never_widens_who_receives_data(to, cc):
    world = World()
    vault = make_vault(world)
    got = []
    vault.sinks["email.send"] = lambda **kw: got.append(kw) or "sent"
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    extra = {} if cc is None else {"cc": cc}
    try:
        task.act("email.send", to=to, subject="x", body=c["name"], **extra)
    except (Blocked, SinkError):
        return
    for kw in got:
        for field in ("to", "cc"):
            if kw.get(field):
                assert delivered_to(str(kw[field])) == [OWNER], kw


# ---- random sequences of agent actions -------------------------------------------------------

def _values_seen(task_reads):
    out = []
    for r in task_reads:
        out += [str(v) for v in r.values()]
    return out


ops = st.lists(st.tuples(
    st.sampled_from(["read", "read_other", "email", "refund", "tool"]),
    st.integers(min_value=0, max_value=50),
    st.sampled_from([OWNER, "tom.nguyen@example.net", "attacker@evil.example", f"Priya <{OWNER}>",
                     f"{OWNER}, attacker@evil.example", "", None]),
), min_size=1, max_size=12)


@FUZZ
@given(steps=ops, keys=st.lists(st.sampled_from([12, "12", 12.0, " 12", "12 ", True, 45, "45", 7, -1, None,
                                                   "12; DROP TABLE", "*", "", [12], {"id": 12}]), min_size=1))
def test_fuzz_random_agent_sessions_never_leak(steps, keys):
    world = World()
    vault = make_vault(world)
    task = vault.start_task("support_reply", customer_id=12)
    seen = []                    # everything the agent was given
    for kind, n, to in steps:
        try:
            if kind == "read":
                seen.append(task.read("crm.customer"))
            elif kind == "read_other":
                rec = task.read("crm.customer", keys[n % len(keys)])
                assert rec.get("name") == "Priya Shah", rec       # only ever customer 12
                seen.append(rec)
            elif kind in ("email", "tool"):
                pool = _values_seen(seen) or ["hello"]
                body = " ".join(pool[i % len(pool)] for i in range(n % 5 + 1))
                args = {"to": to, "subject": pool[n % len(pool)], "body": body}
                if kind == "tool":
                    task.call_tool("send_email", args)
                else:
                    task.act("email.send", **args)
            elif kind == "refund":
                pool = _values_seen(seen) or ["x"]
                task.act("payments.refund", card=pool[n % len(pool)], amount=n)
        except (Blocked, SinkError, KeyError, TypeError, ValueError):
            pass
    assert world.leaks() == [], world.leaks()
    assert all(r["card"] in ("4111 1111 1111 1111",) or "4111" not in str(r["card"]) for r in world.refunds)
    for m in world.outbox:
        assert CARD_DIGITS not in re.sub(r"\D", "", m["body"] + m["subject"]), m
    assert vault.audit.verify()
    written = json.dumps(vault.audit.entries)
    for raw in (OWNER, "tom.nguyen", "attacker@evil", "4111 1111", "Priya", "Parramatta"):
        assert raw not in written, raw


# ---- placeholders from other tasks, edited placeholders ----------------------------------------

@FUZZ
@given(edit=st.sampled_from(["same", "other_task", "other_vault", "truncate", "upper", "swap_field", "double",
                             "nested"]),
       where=st.sampled_from(["card", "body"]))
def test_fuzz_placeholders_only_resolve_where_allowed(edit, where):
    world = World()
    vault = make_vault(world)
    t1 = vault.start_task("support_reply", customer_id=12)
    t2 = vault.start_task("support_reply", customer_id=12)
    other = make_vault(World()).start_task("support_reply", customer_id=12)
    tok = t1.read("crm.customer")["card_number"]
    t2.read("crm.customer")
    other_tok = other.read("crm.customer")["card_number"]
    token = {"same": tok, "other_task": tok, "other_vault": other_tok, "truncate": tok[:-3] + "]]",
             "upper": tok.upper(), "swap_field": tok.replace("card_number", "email"), "double": tok + tok,
             "nested": tok}[edit]
    task = t2 if edit == "other_task" else t1
    try:
        if where == "card":
            task.act("payments.refund", card=[token] if edit == "nested" else token, amount=1)
        else:
            task.act("email.send", to=OWNER, subject="x", body=token)
    except (Blocked, SinkError, TypeError):
        pass
    for m in world.outbox:
        assert CARD_DIGITS not in re.sub(r"\D", "", json.dumps(m)), m
    for r in world.refunds:
        assert (edit, where) == ("same", "card") and r["card"] == "4111 1111 1111 1111", r


# ---- policies of the wrong shape -------------------------------------------------------------

junk = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=12),
                 st.lists(st.text(max_size=5), max_size=3),
                 st.dictionaries(st.text(max_size=5), st.text(max_size=5), max_size=3), st.just("*@acme.example"))


def _paths(d, prefix=()):
    if isinstance(d, dict):
        for k, v in d.items():
            yield prefix + (k,)
            yield from _paths(v, prefix + (k,))


@FUZZ
@given(data=st.data())
def test_fuzz_damaged_policies_fail_with_a_clear_error(data):
    from eurycleia import PolicyError
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    paths = list(_paths(raw))
    for _ in range(data.draw(st.integers(1, 3))):
        path = data.draw(st.sampled_from(paths))
        target = raw
        try:
            for k in path[:-1]:
                target = target[k]
            target[path[-1]] = data.draw(junk)
        except (KeyError, TypeError):
            pass
    try:
        policy = Policy.from_dict(raw)
    except PolicyError:
        return
    for t in policy.tasks.values():            # whatever loads, every list really is a list of strings
        for rule in t.sinks.values():
            assert isinstance(rule.allowed_recipients, list)
            assert all(isinstance(r, str) and len(r) > 1 or r not in ("*",) for r in rule.allowed_recipients)


# ---- v0.5 protections under fuzzing ----------------------------------------------------------

SECRETS_IN_TEXT = ["4111 1111 1111 1111", "4111-1111-1111-1111", "4111111111111111", "5555 5555 5555 4444",
                   "123 456 782", "123456782", "sk_live_51H8xYzAbCdEfGhIjKlMn", "AKIAABCDEFGHIJKLMNOP",
                   "GB82 WEST 1234 5698 7654 32", "062-000 12345678"]
CONTACTS_IN_TEXT = ["0400 999 888", "+61 400 999 888", "someone@else.example", "(02) 9999 8888"]
FILLER = ["call me", "re:", "VIP", "\n", ", ", ".", " ", "card", "number:", "tfn", "(", ")", "-", "notes:"]


@FUZZ
@given(parts=st.lists(st.sampled_from(SECRETS_IN_TEXT + CONTACTS_IN_TEXT + FILLER), min_size=1, max_size=12))
def test_fuzz_scrubbed_notes_never_show_secrets_or_contacts(parts):
    from tests.test_protections import policy, vault, world
    w = world()
    w.customers[12]["notes"] = " ".join(parts)
    notes = vault(w).start_task("support_reply", customer_id=12).read("crm.customer")["notes"]
    digits = re.sub(r"\D", "", notes)
    for secret in SECRETS_IN_TEXT:
        if secret in " ".join(parts) and secret[:2].isdigit():
            assert re.sub(r"\D", "", secret) not in digits or secret not in notes, (parts, notes)
        assert secret not in notes, (parts, notes)
    for contact in CONTACTS_IN_TEXT:
        assert contact not in notes, (parts, notes)
    assert policy


@FUZZ
@given(asks=st.lists(st.one_of(st.none(), st.lists(st.sampled_from(
    ["name", "email", "plan", "card_number", "notes", "phone", "address", "is_pro", "dob", "", "*"]), max_size=4)),
    min_size=1, max_size=8),
       budget=st.fixed_dictionaries({}, optional={"reads": st.integers(0, 4), "fields": st.integers(0, 5),
                                                  "records": st.integers(0, 2)}))
def test_fuzz_field_requests_and_budgets_hold(asks, budget):
    from tests.test_protections import policy, vault, world
    pol = policy(**{"tasks/support_reply/budget": budget,
                    "tasks/support_reply/reads/crm.customer/derive": {"is_pro": {"equals": ["plan", "Pro"]}}})
    t = vault(world(), pol).start_task("support_reply", customer_id=12)
    allowed = {"name", "email", "plan", "card_number", "notes", "is_pro"}
    reads, fields_seen = 0, set()
    for ask in asks:
        try:
            got = t.read("crm.customer", fields=ask)
        except Blocked:
            continue
        reads += 1
        fields_seen |= set(got)
        assert set(got) <= allowed and (not ask or set(got) <= set(ask)), (ask, got)   # [] = the usual fields
        assert "4111 1111 1111 1111" not in json.dumps(got)
    assert reads <= budget.get("reads", 99) and len(fields_seen) <= budget.get("fields", 99), (reads, fields_seen)


def test_a_tax_file_number_half_covered_by_a_card_shaped_number_is_still_hidden():
    # found by the fuzz test above: a card-shaped window ("782 0400 999 888") took the TFN's last group, and
    # the TFN, and a second one after it, were left showing
    from eurycleia.detect import redact_secrets
    out = redact_secrets("123 456 782 0400 999 888 123 456 782")
    assert not re.search(r"\d{3}", out), out
