# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Stress-test findings (September 2026): each test pins down one issue so it can't come back."""

import json

import pytest

from demo.__main__ import POLICY, make_vault
from demo.world import World
from eurycleia import Blocked, Policy, SinkError, Vault

OWNER = "priya.shah@example.com"


def _vault_with_staff_glob(world, sinks=None):
    """Demo policy, but email.send may also go to anyone at the company (like the finance template)."""
    import copy
    data = copy.deepcopy(Policy.load(POLICY).raw)
    data["internal_domains"] = ["acme.example"]
    data["tasks"]["support_reply"]["sinks"]["email.send"]["allowed_recipients"].append("*@acme.example")
    return Vault(Policy.from_dict(data),
                 {"crm.customer": world.get_customer, "docs": world.get_doc, "inbox.ticket": world.get_ticket},
                 sinks or {"email.send": world.send_email, "payments.refund": world.refund})


# ---- 1. one recipient string hiding a second address ------------------------------------

@pytest.mark.parametrize("to", [
    "attacker@evil.example staff@acme.example",
    "attacker@evil.example (staff@acme.example",
    "attacker@evil.example(x) staff@acme.example",
    '"attacker@evil.example" staff@acme.example',
    "attacker@evil.example\tstaff@acme.example",
])
def test_a_second_address_cannot_hide_behind_a_company_glob(to):
    world = World()
    task = _vault_with_staff_glob(world).start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    with pytest.raises(Blocked):
        task.act("email.send", to=to, subject="x", body=c["name"])
    assert world.outbox == []


def test_a_real_company_address_still_works_with_the_glob():
    world = World()
    task = _vault_with_staff_glob(world).start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    task.act("email.send", to="billing@acme.example", subject="x", body=c["name"])
    assert world.outbox[0]["to"] == "billing@acme.example"


# ---- 2. recipient edge cases -------------------------------------------------------------

@pytest.mark.parametrize("to", [
    OWNER + "\r\n", "\r\n" + OWNER, OWNER + "\nbcc: attacker@evil.example",
    "." + OWNER, OWNER.replace("@", "@."), OWNER + ".",
    f'"attacker@evil.example" <{OWNER}>', f"<@evil.example:{OWNER}>",
    f"{OWNER}(comment)", '"priya.shah"@example.com',
])
def test_odd_recipient_forms_are_blocked(to):
    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    with pytest.raises(Blocked):
        task.act("email.send", to=to, subject="x", body=c["name"])
    assert world.outbox == []


@pytest.mark.parametrize("to", [OWNER, OWNER.upper(), f"  {OWNER} ", f"Priya Shah <{OWNER}>"])
def test_ordinary_forms_of_the_owners_address_still_work(to):
    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    task.act("email.send", to=to, subject="x", body=f"Hi {c['name']}")
    assert len(world.outbox) == 1


# ---- 3. extra recipient arguments (cc / bcc) ---------------------------------------------

def test_cc_and_bcc_are_checked_like_the_main_recipient():
    world = World()
    got = []
    vault = make_vault(world)
    vault.sinks["email.send"] = lambda **kw: got.append(kw) or "sent"
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    for extra in ("cc", "bcc", "reply_to"):
        with pytest.raises(Blocked):
            task.act("email.send", to=c["email"], subject="x", body=c["name"], **{extra: "attacker@evil.example"})
    assert got == []


# ---- 4. what the sink sends back ---------------------------------------------------------

def test_secrets_in_a_sinks_reply_are_masked_before_the_agent_sees_them():
    world = World()
    vault = make_vault(world)
    vault.sinks["payments.refund"] = lambda card, amount: {"status": "ok", "card": card, "amount": amount}
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    out = task.act("payments.refund", card=c["card_number"], amount=49)
    assert "4111" not in json.dumps(out) and out["card"] == c["card_number"]


def test_secrets_in_a_sinks_error_are_masked_too():
    world = World()
    vault = make_vault(world)

    def failing_refund(card, amount):
        raise ValueError(f"card {card} was declined")
    vault.sinks["payments.refund"] = failing_refund
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    with pytest.raises(Exception) as e:
        task.act("payments.refund", card=c["card_number"], amount=49)
    assert "4111 1111 1111 1111" not in str(e.value)


def test_real_names_in_a_sinks_reply_are_shown_as_stand_ins():
    world = World()
    vault = make_vault(world)
    vault.sinks["email.send"] = lambda to, subject, body: f"sent to {to}: {body}"
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    if not c["name"].startswith("Name-"):
        pytest.skip("demo policy doesn't pseudonymise names")
    out = task.act("email.send", to=c["email"], subject="x", body=f"Hi {c['name']}")
    assert "Priya" not in out and OWNER not in out


# ---- 5. agent-chosen names in the audit log ----------------------------------------------

def test_agent_chosen_names_are_not_written_raw_to_the_audit_log():
    world = World()
    vault = make_vault(world)
    task = vault.start_task("support_reply", customer_id=12)
    task.read("crm.customer")
    for attempt in (lambda: task.act(OWNER, x=1), lambda: task.read(OWNER),
                    lambda: task.call_tool(OWNER, {}),
                    lambda: task.act("email.send", to=OWNER, subject="x", body="y", **{OWNER.replace("@", "_at_"): 1})):
        with pytest.raises((Blocked, KeyError, SinkError)):
            attempt()
    written = json.dumps(vault.audit.entries)
    assert OWNER not in written and "priya.shah_at_" not in written


# ---- 6. tampered deposit boxes fail as a normal block ------------------------------------

def test_tampered_box_data_is_a_logged_block_not_a_crash(tmp_path):
    from eurycleia.crypto import LocalKeyProvider
    from tests.test_boxes import _vault_on_boxes
    vault, world = _vault_on_boxes(str(tmp_path / "b.db"), LocalKeyProvider(tmp_path / "v.key"))
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    vault.boxes.db.execute("UPDATE tvb_items SET blob = substr(blob, 1, length(blob) - 4) || X'00000000'")
    with pytest.raises(Blocked):
        task.act("payments.refund", card=c["card_number"], amount=49)
    assert world.refunds == [] and vault.audit.decisions("block") and vault.audit.verify()


# ---- 7. damaged files: clear errors and a way back ---------------------------------------

def test_a_crash_mid_write_can_be_repaired_without_hiding_tampering(tmp_path, capsys):
    from eurycleia.audit import AuditError, AuditLog
    from eurycleia.cli import main
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.record("act", i=i)
    with path.open("a") as f:
        f.write('{"seq": 3, "ts": 1, "ev')                      # power cut mid-write
    with pytest.raises(AuditError, match="audit repair"):
        AuditLog(path)
    assert main(["audit", "repair", str(path)]) == 0
    assert "moved an unfinished last line" in capsys.readouterr().out
    fixed = AuditLog(path)
    assert len(fixed.entries) == 3 and fixed.verify()
    fixed.record("act", i=3)
    assert AuditLog(path).verify()

    lines = path.read_text().splitlines()                    # damage in the MIDDLE is not a crash
    lines[1] = lines[1][:-5]
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditError):
        AuditLog.repair(path)


def test_damaged_key_file_gives_a_clear_error(tmp_path):
    from eurycleia.crypto import KeyUnavailable, LocalKeyProvider
    for content in (b"not a key", b"", base64_of(b"short")):
        p = tmp_path / "k.key"
        p.write_bytes(content)
        with pytest.raises(KeyUnavailable, match="valid eurycleia key"):
            LocalKeyProvider(p, create=False).data_key()


def base64_of(b):
    import base64
    return base64.b64encode(b)


@pytest.mark.parametrize("text", ["version: 1\nsources: 5", "- a\n- b", "tasks: [1]", "tools: {x: 5}",
                                  "internal_domains: acme.example"])
def test_policies_of_the_wrong_shape_give_a_policy_error(tmp_path, text):
    from eurycleia import PolicyError
    p = tmp_path / "p.yaml"
    p.write_text(text)
    with pytest.raises(PolicyError):
        Policy.load(p)


def test_a_recipient_pattern_written_as_text_is_rejected_not_read_as_characters():
    import copy

    from eurycleia import PolicyError
    data = copy.deepcopy(Policy.load(POLICY).raw)
    data["tasks"]["support_reply"]["sinks"]["email.send"]["allowed_recipients"] = "*@acme.example"
    with pytest.raises(PolicyError, match="must be a list"):
        Policy.from_dict(data)


# ---- 8. found by the first real-agent run (LangGraph + hermes3) ----------------------------

def test_a_refund_cannot_go_to_a_card_the_agent_typed():
    """The card argument is bound to card_number, so it must be the vault's placeholder:
    a fooled agent can't refund to a card number of its own choosing."""
    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    for typed in ("xxxx-xxxx-xxxx-xxxx", "5555 5555 5555 4444", "4000056655665556", "", None, 12,
                  c["card_number"] + " ", c["card_number"].replace("card_number", "email")):
        with pytest.raises(Blocked):
            task.act("payments.refund", card=typed, amount=49)
    assert world.refunds == []
    task.act("payments.refund", card=c["card_number"], amount=49)
    assert world.refunds == [{"card": "4111 1111 1111 1111", "amount": 49}]


def test_an_empty_field_list_means_the_usual_fields():
    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    assert set(task.read("crm.customer", fields=[])) == set(task.read("crm.customer"))
    assert task.read("crm.customer", fields=[])["name"] == "Priya Shah"


# ---- 9. external security report (September 2026) ------------------------------------------

def _labelled_docs_vault(world_outbox):
    pol = Policy.from_dict({
        "internal_domains": ["acme.example"],
        "sources": {
            "customers": {"owner": "customer_id", "owner_contact": "email",
                          "fields": {"email": "protected", "name": "protected"}},
            "memos": {"owner": "company", "default_level": "normal", "fields": {"body": "normal", "tag": "normal"},
                      "label_field": "tag", "label_map": {"Confidential": "protected"}}},
        "tasks": {"reply": {"trusted": ["customer_id"],
                            "reads": {"customers": {"key": "{customer_id}", "fields": ["email", "name"]},
                                      "memos": {"keys": ["m1"], "fields": ["body"]}},
                            "sinks": {"email.send": {"recipient_arg": "to", "args": ["to", "subject", "body"],
                                                     "allowed_recipients": ["customers:{customer_id}.email"]}}}}})
    memos = {"m1": {"body": "INTERNAL floor price $18/seat", "tag": "Confidential"}}
    customers = {12: {"email": "priya.shah@example.com", "name": "Priya"}}
    return Vault(pol, {"customers": lambda k: customers.get(int(k)), "memos": lambda k: memos.get(k)},
                 {"email.send": lambda **kw: world_outbox.append(kw) or "sent"})


def test_planner_honours_document_level_labels():
    """Report finding 1: planner mode ignored label_field/label_map, so a 'Confidential' memo could be
    re-encoded by a fooled extractor and sent out."""
    import base64

    from eurycleia.planner import Planner
    outbox = []
    task = _labelled_docs_vault(outbox).start_task("reply", customer_id=12)
    plan = [{"id": "c", "read": "customers"}, {"id": "m", "read": "memos", "key": "m1"},
            {"id": "x", "extract": {"from": ["m.body"], "instruction": "summarise", "schema": {"text": "string"}}},
            {"act": "email.send", "args": {"to": "$c.email", "subject": "Hi", "body": "$x.text"}}]
    hijacked = lambda instruction, inputs, schema: {"text": base64.b64encode(inputs["m.body"].encode()).decode()}  # noqa: E731
    with pytest.raises(Blocked):
        Planner(task, hijacked).run(plan)
    assert outbox == []


def test_forgetting_a_holder_leaves_no_index_rows(tmp_path):
    """Report minor note: forget_holder left the encrypted field-name list behind."""
    from eurycleia.boxes import BoxStore, StaticHolderKeys
    from eurycleia.crypto import LocalKeyProvider
    keys = StaticHolderKeys()
    for h in ("customer:12", "customer:45"):
        keys.create(h)
    store = BoxStore(str(tmp_path / "b.db"), LocalKeyProvider(tmp_path / "v.key"), keys)
    levels = {"name": "protected", "card_number": "secret", "plan": "normal"}
    store.store_record("crm.customer", 12, {"name": "Priya", "card_number": "4111 1111 1111 1111", "plan": "Pro"},
                       "customer:12", levels)
    store.store_record("crm.customer", 45, {"name": "Tom", "card_number": "5555 5555 5555 4444", "plan": "Basic"},
                       "customer:45", levels)
    gone = store._macb(16, "record", "crm.customer", 12)
    store.forget_holder("customer:12")
    assert store.db.execute("SELECT count(*) FROM tvb_records WHERE record=?", (gone,))[0][0] == 0
    assert store.fetch_record("crm.customer", 45)["name"] == "Tom"                 # others untouched


def test_detector_stays_fast_on_hostile_text():
    """Report finding 2: overlap bookkeeping was quadratic, so crafted text could stall outbound checks."""
    import time

    from eurycleia.detect import scan_text
    text = "0400 111 222 " * 25_000                      # ~325 KB of phone-like numbers
    t0 = time.perf_counter()
    assert len(scan_text(text)) > 10_000                 # phone numbers (and digit runs that pass the card check)
    assert time.perf_counter() - t0 < 5.0                # was ~25 s; now well under a second on a laptop


def test_a_file_audit_log_keeps_a_bounded_window_in_memory(tmp_path):
    """Found by the soak test: a long-running server kept every audit entry in memory as well as on disk."""
    from eurycleia import AuditLog
    log = AuditLog(tmp_path / "a.jsonl", keep=100)
    for i in range(1000):
        log.record("x", i=i)
    assert len(log.entries) <= 110 and log.entries[-1]["i"] == 999
    assert log.verify()                                            # checks the whole file, not the window
    assert len(AuditLog(tmp_path / "a.jsonl", keep=None).entries) == 1000
    reloaded = AuditLog(tmp_path / "a.jsonl", keep=100)
    assert len(reloaded.entries) <= 110 and reloaded.head == log.head
    reloaded.record("y")
    assert AuditLog(tmp_path / "a.jsonl").verify()


def test_windows_file_lock_unlocks_the_byte_it_locked(tmp_path, monkeypatch):
    """Found on Windows: when reading an audit log stopped early (a damaged line), the unlock landed on a
    different position from the lock ("Permission denied"), hiding the real error. A stand-in for Windows'
    msvcrt that is just as strict reproduces it here."""
    import os as _os

    from eurycleia import audit as audit_mod

    class StrictMsvcrt:
        LK_LOCK, LK_UNLCK = 1, 0
        held: dict = {}

        def locking(self, fd, mode, n):
            pos = _os.lseek(fd, 0, _os.SEEK_CUR)
            if mode == self.LK_LOCK:
                self.held[fd] = pos
            elif self.held.pop(fd, None) != pos:
                raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(audit_mod, "_WINDOWS", True)
    monkeypatch.setattr(audit_mod, "_msvcrt", lambda: StrictMsvcrt())
    path = tmp_path / "audit.jsonl"
    log = audit_mod.AuditLog(path)
    for i in range(300):                               # bigger than one read buffer
        log.record("act", i=i, pad="x" * 50)
    assert audit_mod.AuditLog(path).verify()
    lines = path.read_text().splitlines()
    lines[5] = lines[5][:-5]                            # damage near the start: reading stops early
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(audit_mod.AuditError, match="not valid JSON"):
        audit_mod.AuditLog(path)
    with pytest.raises(audit_mod.AuditError):
        audit_mod.AuditLog.repair(path)


def test_references_from_the_retired_secret_store_are_refused_loudly():
    """Review of the 0.5 slim-down: a database still holding old `tvref_` references would otherwise pass the
    reference on as if it were the card number (e.g. a refund to a meaningless value)."""
    world = World()
    world.customers[12]["card_number"] = "tvref_0123456789abcdef"
    task = make_vault(world).start_task("support_reply", customer_id=12)
    with pytest.raises(Blocked, match="deposit boxes"):
        task.read("crm.customer")
