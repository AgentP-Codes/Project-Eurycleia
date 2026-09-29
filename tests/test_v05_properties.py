# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression properties for the v0.5 protections (simulated data only).

Written by an independent review agent; three of them failed before the fixes in 0.5 (domain summary,
reformatted values in sink results, and secrets echoed from outside the current call)."""

import copy
import json

import pytest

from demo.__main__ import POLICY
from demo.world import World
from taskvault import Blocked, Policy, SinkError, Vault
from taskvault.derive import compute

CARD = "4111 1111 1111 1111"
EMAIL = "priya.shah@example.com"
NOTES = "Call 0400 999 888 or priya.personal@gmail.example; card 5555 5555 5555 4444. Again 0400 999 888."


def _bare(value) -> str:
    """Text with placeholders removed: their 8 random hex characters can contain "4111" by chance."""
    from taskvault.vault import TOKEN_RE
    return TOKEN_RE.sub("[[placeholder]]", value if isinstance(value, str) else json.dumps(value, default=str))


def raw_policy():
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    src = raw["sources"]["crm.customer"]
    src["fields"]["notes"] = "protected"
    src["pseudonymize"] = ["name", "email"]
    src["scrub"] = ["notes"]
    raw["tasks"]["support_reply"]["reads"]["crm.customer"]["fields"] = ["name", "email", "plan", "card_number", "notes"]
    return raw


def make(raw=None, w=None, sinks=None, **kw):
    w = w or World()
    w.customers[12]["notes"] = NOTES
    v = Vault(Policy.from_dict(raw or raw_policy()),
              {"crm.customer": w.get_customer, "docs": w.get_doc, "inbox.ticket": w.get_ticket},
              sinks or {"email.send": w.send_email, "payments.refund": w.refund}, **kw)
    return v, w


# ---- 1. derive -------------------------------------------------------------------------------

SPECS = [{"last4": "v"}, {"present": "v"}, {"domain": "v"}, {"equals": ["v", "x"]},
         {"one_of": ["v", ["x", "y"]]}, {"at_least": ["v", 5]}, {"at_most": ["v", 5]},
         {"age_at_least": ["v", 18]}]
VALUES = [CARD, EMAIL, "+61 400 111 222", "14 Wattle St, Parramatta NSW", ["a", CARD], 123456789, None,
          "", "@@@", "x" * 50]


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: next(iter(s)))
@pytest.mark.parametrize("value", VALUES, ids=repr)
def test_derived_result_never_contains_source_value(spec, value):
    out = compute(spec, {"v": value})
    if value in (None, ""):
        return
    text = str(value).lower()
    if len(text) >= 4:
        assert text not in str(out).lower(), (spec, value, out)


def test_derived_reads_count_against_budget():
    raw = raw_policy()
    rule = raw["tasks"]["support_reply"]["reads"]["crm.customer"]
    rule["derive"] = {"is_pro": {"equals": ["plan", "Pro"]}}
    raw["tasks"]["support_reply"]["budget"] = {"reads": 2}
    t = make(raw)[0].start_task("support_reply", customer_id=12)
    t.read("crm.customer", fields=["is_pro"])
    t.read("crm.customer", fields=["is_pro"])
    with pytest.raises(Blocked):
        t.read("crm.customer", fields=["is_pro"])


# ---- 2. budgets ------------------------------------------------------------------------------

def budget_task(budget):
    raw = raw_policy()
    raw["tasks"]["support_reply"]["budget"] = budget
    raw["tasks"]["support_reply"]["reads"]["crm.customer"]["derive"] = {"is_pro": {"equals": ["plan", "Pro"]}}
    return make(raw)[0].start_task("support_reply", customer_id=12)


def test_budget_reads_across_read_and_call_tool():
    t = budget_task({"reads": 2})
    t.read("crm.customer", fields=["plan"])
    t.call_tool("get_customer", {"fields": ["plan"]})
    with pytest.raises(Blocked):
        t.call_tool("get_customer", {"customer_id": "12", "fields": ["plan"]})


def test_budget_records_int_vs_str_key_same_record():
    t = budget_task({"records": 1})
    t.read("crm.customer", key=12, fields=["plan"])
    t.read("crm.customer", key="12", fields=["plan"])      # same record: must not count twice


def test_budget_fields_with_derived_and_duplicates():
    t = budget_task({"fields": 2})
    t.read("crm.customer", fields=["plan", "plan"])
    t.read("crm.customer", fields=["is_pro"])
    with pytest.raises(Blocked):
        t.read("crm.customer", fields=["name"])
    with pytest.raises(Blocked):
        t.read("crm.customer", fields=["Name"])


# ---- 3. fields -------------------------------------------------------------------------------

@pytest.mark.parametrize("fields", [["address"], ["Plan"], ["plan", "PHONE"], [1], [None], ["plan", ["x"]],
                                    "plan", {"plan": 1}, ["plan "], ["card_number\x00"]])
def test_bad_field_names_are_refused(fields):
    t = make()[0].start_task("support_reply", customer_id=12)
    try:
        out = t.read("crm.customer", fields=fields)
    except Blocked:
        return
    allowed = {"name", "email", "plan", "card_number", "notes"}
    assert set(out) <= allowed, out


def test_duplicate_fields_return_once():
    t = make()[0].start_task("support_reply", customer_id=12)
    assert t.read("crm.customer", fields=["plan", "plan"]) == {"plan": "Pro"}


# ---- 4. trust levels & state isolation -------------------------------------------------------

def test_external_model_never_sees_internal_may_see_values():
    raw = raw_policy()
    raw["sources"]["crm.customer"]["internal_may_see"] = ["name", "email", "notes"]
    v, _ = make(raw)
    c = v.start_task("support_reply", customer_id=12).read("crm.customer")
    flat = json.dumps(c)
    for real in ("Priya Shah", EMAIL, "0400 999 888", "priya.personal@gmail.example"):
        assert real not in flat


def test_internal_vault_does_not_affect_external_vault():
    raw = raw_policy()
    raw["sources"]["crm.customer"]["internal_may_see"] = ["name"]
    w = World()
    make(raw, w, model="internal")[0].start_task("support_reply", customer_id=12).read("crm.customer")
    c = make(raw, w)[0].start_task("support_reply", customer_id=12).read("crm.customer")
    assert c["name"] != "Priya Shah"


def test_placeholder_from_task_a_refused_in_task_b():
    v, w = make()
    a = v.start_task("support_reply", customer_id=12)
    card = a.read("crm.customer")["card_number"]
    b = v.start_task("support_reply", customer_id=12)
    b.read("crm.customer")
    with pytest.raises(Blocked):
        b.act("payments.refund", card=card, amount=1)
    v2, w2 = make(w=World())
    c = v2.start_task("support_reply", customer_id=12)
    c.read("crm.customer")
    with pytest.raises(Blocked):
        c.act("payments.refund", card=card, amount=1)
    assert w.refunds == [] and w2.refunds == []


def test_pseudonym_from_task_a_is_not_resolved_in_task_b():
    v, w = make()
    a = v.start_task("support_reply", customer_id=12)
    pseudo_email = a.read("crm.customer")["email"]
    b = v.start_task("support_reply", customer_id=45)
    b.read("crm.customer")
    with pytest.raises(Blocked):
        b.act("email.send", to=pseudo_email, subject="x", body="y")
    assert w.outbox == []


# ---- 5. scrub --------------------------------------------------------------------------------

def test_scrub_removes_contacts_and_cards_including_repeats():
    c = make()[0].start_task("support_reply", customer_id=12).read("crm.customer")
    flat = json.dumps(c)
    for real in ("0400 999 888", "priya.personal@gmail.example", "5555 5555 5555 4444", "5555555555554444"):
        assert real not in flat


def test_scrub_value_split_across_lines():
    w = World()
    v, _ = make(w=w)
    w.customers[12]["notes"] = "email priya.personal@gmail.example\nphone 0400 999 888\ncard 5555555555554444"
    c = v.start_task("support_reply", customer_id=12).read("crm.customer")
    for real in ("0400 999 888", "priya.personal@gmail.example", "5555555555554444"):
        assert real not in c["notes"]


# ---- 6. masking of sink results --------------------------------------------------------------

def _variants(real):
    compact = real.replace(" ", "")
    return {
        "as_is": real,
        "upper": real.upper(),
        "lower": real.lower(),
        "compact": compact,
        "dashed": "-".join(real.split(" ")) if " " in real else real,
        "spaced_4": " ".join(compact[i:i + 4] for i in range(0, len(compact), 4)),
        "in_longer_string": f"ok ref={real}; done",
        "dict_key": {real: 1},
        "int": int(compact) if compact.isdigit() else real,
        "nested": [{"a": [real]}],
    }


@pytest.mark.parametrize("variant", list(_variants(CARD)))
def test_sink_result_card_variants_are_masked(variant):
    w = World()
    echo = lambda **a: _variants(CARD)[variant]   # noqa: E731
    v, _ = make(w=w, sinks={"email.send": w.send_email, "payments.refund": echo})
    t = v.start_task("support_reply", customer_id=12)
    card = t.read("crm.customer")["card_number"]
    out = json.dumps(t.act("payments.refund", card=card, amount=1), default=str)
    assert "1111" not in _bare(out), (variant, out)


@pytest.mark.parametrize("variant", ["as_is", "upper", "in_longer_string", "dict_key", "nested"])
def test_sink_result_email_variants_are_masked(variant):
    w = World()
    val = {"as_is": EMAIL, "upper": EMAIL.upper(), "in_longer_string": f"sent to {EMAIL}!",
           "dict_key": {EMAIL: "ok"}, "nested": [{"to": [EMAIL]}]}[variant]
    v, _ = make(w=w, sinks={"email.send": lambda **a: val, "payments.refund": w.refund})
    t = v.start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    out = json.dumps(t.act("email.send", to=c["email"], subject="s", body="b"))
    assert "priya.shah" not in out.lower(), (variant, out)


def test_sink_error_is_masked():
    w = World()

    def boom(**a):
        raise RuntimeError(f"bad card {a['card']}")
    v, _ = make(w=w, sinks={"email.send": w.send_email, "payments.refund": boom})
    t = v.start_task("support_reply", customer_id=12)
    card = t.read("crm.customer")["card_number"]
    with pytest.raises(SinkError) as e:
        t.act("payments.refund", card=card, amount=1)
    assert "4111" not in str(e.value)


def test_sink_result_masks_task_secrets_not_passed_in_this_call():
    """A sink that returns a secret this task holds, but that wasn't an argument of this call."""
    w = World()
    v, _ = make(w=w, sinks={"email.send": lambda **a: {"card_on_file": CARD}, "payments.refund": w.refund})
    t = v.start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    out = json.dumps(t.act("email.send", to=c["email"], subject="s", body="b"))
    assert "4111" not in _bare(out), out


# ---- 7. bound secrets ------------------------------------------------------------------------

def test_bound_secret_argument_rules():
    v, w = make()
    t = v.start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    card = c["card_number"]
    text_card = next(x for x in c["notes"].split() if x.startswith("[[vault:text_card_number:")).rstrip(".,;")
    for bad in (text_card, f"x {card}", f"{card} ", CARD, "4111111111111111", [card], {"c": card}):
        with pytest.raises(Blocked):
            t.act("payments.refund", card=bad, amount=1)
    with pytest.raises(Blocked):
        t.act("payments.refund", card=card, amount=card)
    assert w.refunds == []
    t.act("payments.refund", card=card, amount=1)
    assert w.refunds == [{"card": CARD, "amount": 1}]


# ---- 8. local API ----------------------------------------------------------------------------

from tests.test_api import api, call, start  # noqa: E402,F401


def test_api_blocked_actions_produce_no_execute(api):  # noqa: F811
    tid, _ = start(api)
    rec = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "get_customer", "arguments": {}})[1]["result"]
    for sink, args in [("email.send", {"to": "attacker@evil.example", "subject": "x", "body": "y"}),
                       ("email.send", {"to": rec["email"], "subject": "x", "body": rec["card_number"]}),
                       ("payments.refund", {"card": CARD, "amount": 1}),
                       ("payments.refund", {"card": rec["card_number"] + " ", "amount": 1}),
                       ("nope.sink", {})]:
        st, out = call(api, "POST", f"/v1/tasks/{tid}/act", {"sink": sink, "args": args})
        assert out.get("status") != "execute", (sink, out)
    assert api.pending == {}


def test_api_exec_error_is_masked(api):  # noqa: F811
    tid, _ = start(api)
    got = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "get_customer", "arguments": {}})[1]
    card = got["result"]["card_number"]
    out = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "refund", "arguments": {"card": card, "amount": 1}})[1]
    assert out["status"] == "execute"
    done = call(api, "POST", f"/v1/exec/{out['exec']}", {"error": f"declined {CARD} / 4111111111111111"})[1]
    assert "4111" not in _bare(done), done


def test_api_exec_result_variants_masked(api):  # noqa: F811
    tid, _ = start(api)
    got = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "get_customer", "arguments": {}})[1]
    card = got["result"]["card_number"]
    out = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "refund", "arguments": {"card": card, "amount": 1}})[1]
    done = call(api, "POST", f"/v1/exec/{out['exec']}",
                {"result": {"a": CARD, "b": "4111111111111111", "c": [{"d": CARD}], CARD: 1}})[1]
    assert "4111" not in _bare(done), done


def test_box_secret_opened_earlier_is_masked_in_later_results(tmp_path):
    """A card from a deposit box, opened for an approved refund, is masked if a later action echoes it."""
    from taskvault.crypto import LocalKeyProvider
    from tests.test_boxes import _vault_on_boxes
    vault, world = _vault_on_boxes(str(tmp_path / "b.db"), LocalKeyProvider(tmp_path / "v.key"))
    vault.sinks["email.send"] = lambda **a: {"note": "card on file 4111-1111-1111-1111"}
    t = vault.start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    t.act("payments.refund", card=c["card_number"], amount=5)
    out = json.dumps(t.act("email.send", to=c["email"], subject="s", body="b"))
    assert "4111" not in _bare(out) and c["card_number"] in out


def test_secrets_the_task_never_saw_are_removed_from_results():
    """Found by fuzzing: a sink returning ANOTHER customer's card (which this task never handed out) was
    passed to the model as-is. The detector now removes secret-looking data from results as a second net."""
    w = World()
    v, _ = make(w=w, sinks={"email.send": lambda **a: {"other": "4000-0566-5566-5556", "n": 4000056655665556,
                                                         "text": "acct 062-000 12345678, ok"},
                            "payments.refund": w.refund})
    t = v.start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    out = json.dumps(t.act("email.send", to=c["email"], subject="s", body="b"))
    assert "5566" not in _bare(out) and "12345678" not in _bare(out) and "card_number removed by taskvault" in out
    assert v.audit.entries[-1]["event"] == "sink.result_redacted" or \
        any(e["event"] == "sink.result_redacted" for e in v.audit.entries)
    assert not any(c in json.dumps(v.audit.entries) for c in ("4000 0566", "4000056655665556", "4000-0566"))


def test_api_refuses_invalid_unicode(api):  # noqa: F811
    tid, _ = start(api)
    st, out = call(api, "POST", f"/v1/tasks/{tid}/read", raw='{"source": "crm.customer", "key": "\\ud800"}')
    assert st == 400 and "Unicode" in out["error"]


from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

_WORDS = st.text(alphabet="abcdefghij XYZ,:;", max_size=20)
_SEPS = st.sampled_from(["", " ", "-", ".", "  ", " - ", "/"])


@st.composite
def _card_variant(draw):
    groups = ["4111", "1111", "1111", "1111"]
    out = groups[0]
    for g in groups[1:]:
        out += draw(_SEPS) + g
    return out


@st.composite
def _nested(draw, leaf):
    kind = draw(st.integers(0, 3))
    if kind == 0:
        return draw(_WORDS) + leaf + draw(_WORDS)
    if kind == 1:
        return [draw(_WORDS), leaf]
    if kind == 2:
        return {leaf: draw(st.integers())}
    return {"a": [{"b": leaf}]}


@settings(max_examples=300, deadline=None)
@given(data=st.data())
def test_masking_catches_reformatted_cards_anywhere(data):
    card_text = data.draw(_card_variant())
    result = data.draw(_nested(card_text))
    w = World()
    v, _ = make(w=w, sinks={"email.send": w.send_email, "payments.refund": lambda **a: result})
    t = v.start_task("support_reply", customer_id=12)
    placeholder = t.read("crm.customer")["card_number"]
    out = json.dumps(t.act("payments.refund", card=placeholder, amount=1), default=str)
    assert "4111" not in _bare(out), (card_text, out)


def test_the_second_net_never_touches_placeholders():
    """Found in the final load test: a placeholder whose 8 random characters were all digits passing the
    tax-file-number checksum was partly "removed", breaking it for the model's next step."""
    from taskvault.detect import redact_secrets
    from taskvault.vault import TOKEN_RE
    found = set()
    for hexpart in ("00000021", "00000042", "00000063", "12345678", "87654321", "abcdef01"):   # first 3 look like TFNs
        token = f"[[vault:card_number:{hexpart}]]"
        text = f"refunded to {token} ok"
        assert redact_secrets(text, found) == text and TOKEN_RE.search(redact_secrets({"card": token}, found)["card"])
    assert not found
    assert "removed by taskvault" in redact_secrets("tfn 123 456 782 and [[vault:x:12345678]]")
