# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""0.7.1 hardening: the second batch of privately reported issues."""

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from eurycleia.connect import _state_path, connect

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from test_connect import POLICY, claude_config  # noqa: E402

from tests.test_findings_051 import customer  # noqa: E402

posix = pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")


@pytest.fixture(autouse=True)
def tv_home(tmp_path, monkeypatch):
    monkeypatch.setenv("EURYCLEIA_HOME", str(tmp_path / "tvhome"))


# ---- connections.json holds copies of agents' settings (API keys): private to this user
@posix
def test_connections_file_is_private(tmp_path):
    os.umask(0o022)
    cfg = claude_config(tmp_path)
    connect("claude-desktop", POLICY, "support_reply", ["customer_id=12"], config=str(cfg), servers=["crm"])
    assert stat.S_IMODE(_state_path().stat().st_mode) == 0o600


@posix
def test_an_old_readable_connections_file_is_locked_when_next_used(tmp_path):
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({}))
    os.chmod(p, 0o644)
    from eurycleia.connect import ConnectError, report
    with pytest.raises(ConnectError):                      # nothing connected, but the file was read
        report()
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


# ---- one holder approval covers one item in one task, not every reveal for open_ttl seconds
def test_each_approval_covers_one_item_in_one_task(tmp_path):
    from eurycleia.boxes import BoxLocked, BoxStore, StaticHolderKeys
    from eurycleia.crypto import LocalKeyProvider
    asked = []
    keys = StaticHolderKeys(approver=lambda r: asked.append((r.task, r.item)) or True)
    keys.create("customer:12")
    store = BoxStore(str(tmp_path / "boxes.db"), LocalKeyProvider(tmp_path / "vault.key"), keys)
    store.store_record("crm.customer", 12, {"card": "4111 1111 1111 1111", "tfn": "123 456 782"},
                       "customer:12", {"card": "secret", "tfn": "secret"})
    rec = store.fetch_record("crm.customer", 12)
    store.reveal(rec["card"], task=1)
    store.reveal(rec["card"], task=1)                    # the same item again in the same task: no new question
    assert len(asked) == 1
    store.reveal(rec["tfn"], task=1)                     # another item: asks
    store.reveal(rec["card"], task=2)                    # another task: asks
    store.reveal(rec["card"])                            # no task: always asks
    assert len(asked) == 4 and all(item for _t, item in asked)
    keys.approver = lambda r: False
    with pytest.raises(BoxLocked):
        store.reveal(rec["card"], task=3)


# ---- what an app sends back: secrets also hidden backwards, in parts, or split across fields
@pytest.mark.parametrize("echo", [
    "1111 1111 1111 1114",                     # backwards
    "1111111111111114",                        # backwards, no spaces
    "card 4111 1111 1111 on file",             # the first 12 digits
    {"first": "4111 1111", "last": "1111 1111"},   # split across two fields
    {"a": "41111111", "b": "11111111"},
    "ends ...1111 1111 1114 reversed",         # part of it, backwards
])
def test_app_results_hide_reversed_partial_and_split_card_numbers(echo):
    from tests.test_findings_051 import customer
    task, c, _world = customer(pseudo=False)
    task.vault.sinks["payments.refund"] = lambda card, amount: {"note": echo}
    out = json.dumps(task.act("payments.refund", card=c["card_number"], amount=5))
    digits_left = "".join(ch for ch in out if ch.isdigit())
    assert "41111111" not in digits_left and "11111111" not in digits_left, out


def test_a_cards_last_four_digits_can_still_be_shown():
    from tests.test_findings_051 import customer
    task, c, _world = customer(pseudo=False)
    task.vault.sinks["payments.refund"] = lambda card, amount: {"note": "refunded to the card ending 1111"}
    out = task.act("payments.refund", card=c["card_number"], amount=5)
    assert "ending 1111" in json.dumps(out)


@pytest.mark.parametrize("wakes_reader", [True, False], ids=["shutdown-wakes-reader", "windows-style"])
def test_idle_and_trickling_connections_cant_lock_agents_out(monkeypatch, wakes_reader):
    """#7: filling every slot with connections that never finish their request doesn't block a real call, whether
    or not dropping a connection wakes the thread reading it (on Windows it doesn't: the read times out instead)."""
    import socket
    import time as _t

    from eurycleia import api as api_mod
    from eurycleia.api import ApiServer
    from eurycleia.policy import Policy
    from tests.test_api import POLICY as API_POLICY
    from tests.test_api import build_vault, call, remote_sinks

    monkeypatch.setattr(api_mod._Server, "max_connections", 4)
    monkeypatch.setattr(api_mod._Server, "read_deadline", 1.5)
    monkeypatch.setattr(api_mod._Handler, "timeout", 2)
    if not wakes_reader:
        monkeypatch.setattr(api_mod, "_hang_up", lambda request: request.settimeout(0.05))
    srv = ApiServer(build_vault(remote_sinks(Policy.load(API_POLICY))), port=0).start()
    try:
        hogs = [socket.create_connection(("127.0.0.1", srv.port)) for _ in range(4)]
        for h in hogs:
            h.sendall(b"GET /v1/health HTTP/1.1\r\n")      # never finishes the headers
        _t.sleep(0.3)
        t0 = _t.monotonic()
        assert call(srv, "GET", "/v1/health")[0] == 200     # at the cap, the slowest hog is dropped instead
        assert _t.monotonic() - t0 < 4
        drip = socket.create_connection(("127.0.0.1", srv.port))
        drip.sendall(b"GET /v1/health HTTP/1.1\r\n")
        drip.settimeout(0.5)
        t0 = _t.monotonic()
        while _t.monotonic() - t0 < 6:                      # a byte every half second still hits the deadline
            try:
                drip.sendall(b"x")
                if drip.recv(1024) == b"":
                    break                                   # the server hung up
            except TimeoutError:
                continue                                    # still connected: drip another byte
            except OSError:
                break
        assert _t.monotonic() - t0 < 4
        assert call(srv, "GET", "/v1/health")[0] == 200     # and the server is still fine
        for h in [*hogs, drip]:
            h.close()
    finally:
        srv.shutdown()


def test_more_free_mail_services_are_never_a_company_domain():
    """#3: a business record naming a free or throwaway mail service doesn't open data to all its users."""
    from eurycleia.vault import company_domain
    for d in ("startmail.com", "simplelogin.co", "mozmail.com", "privaterelay.appleid.com", "tempmailo.com"):
        assert company_domain(d) is None, d
    assert company_domain("acme-corp.example") == "acme-corp.example"


def test_strict_company_domains_only_accept_listed_domains():
    from eurycleia.policy import Policy
    from eurycleia.vault import company_domain
    allowed = ["acme-corp.example"]
    assert company_domain("acme-corp.example", (), allowed) == "acme-corp.example"
    assert company_domain("some-new-mail.example", (), allowed) is None     # not on the list: refused
    assert company_domain("sub.acme-corp.example", (), allowed) is None
    p = Policy.from_dict({"sources": {}, "tasks": {}, "company_domains": ["ACME-corp.example."]})
    assert p.company_domains == ["acme-corp.example"]


def test_strict_company_domains_apply_to_real_sends():
    import yaml

    from eurycleia.policy import Policy
    from eurycleia.vault import Blocked, Vault
    from tests.test_owners import ACCOUNTS
    from tests.test_owners import POLICY as OWNERS_POLICY
    raw = yaml.safe_load(OWNERS_POLICY.read_text())
    raw["company_domains"] = ["harbourfreight.example"]
    sent = []
    v = Vault(Policy.from_dict(raw), {"crm.account": ACCOUNTS.get, "hr.employee": {}.get},
              {"email.send": lambda to, subject, body: sent.append(to) or "sent"})
    t = v.start_task("account_support", account_id=7)
    t.read("crm.account")
    t.act("email.send", to="ap@harbourfreight.example", subject="s", body="hi")
    t2 = v.start_task("account_support", account_id=8)        # wattlebakery.example isn't on the list
    t2.read("crm.account")
    with pytest.raises(Blocked):
        t2.act("email.send", to="ap@wattlebakery.example", subject="s", body="hi")
    assert sent == ["ap@harbourfreight.example"]


def _guarded_store(tmp_path, db="boxes.db"):
    from eurycleia.boxes import BoxStore, StaticHolderKeys
    from eurycleia.crypto import LocalKeyProvider
    return BoxStore(tmp_path / db, LocalKeyProvider(tmp_path / "vault.key"), StaticHolderKeys(),
                    rollback_guard=tmp_path / "other-disk" / "guard.db")


def test_restoring_an_old_copy_of_the_box_database_is_caught(tmp_path):
    """#6: the log chain alone can't tell an old copy from the real thing; the guard (kept elsewhere) can."""
    import shutil

    from eurycleia.boxes import BoxRollback
    (tmp_path / "other-disk").mkdir()
    store = _guarded_store(tmp_path)
    store.deposit("customer:12", "normal", "email", "ann@example.test")
    box = store.box_id("customer:12", "normal")
    store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    shutil.copy(tmp_path / "boxes.db", tmp_path / "old-copy.db")         # a backup taken now
    store.forget_holder("customer:12")                                   # later: the customer is forgotten
    assert store.check_rollback() == []
    store.db.close()

    old = _guarded_store(tmp_path, "old-copy.db")                       # someone restores the old backup
    assert old.check_rollback() == [box], "the old copy is behind the guard"
    with pytest.raises(BoxRollback):
        old.deposit("customer:12", "normal", "phone", "0400 000 000")     # writes are refused too


def test_the_guard_never_gets_in_the_way_of_normal_use(tmp_path):
    (tmp_path / "other-disk").mkdir()
    store = _guarded_store(tmp_path)
    for i in range(5):
        store.deposit(f"customer:{i}", "normal", "email", f"c{i}@example.test")
    store.forget_holder("customer:3")
    store.unforget_holder("customer:3")
    store.deposit("customer:3", "normal", "email", "back@example.test")
    assert store.check_rollback() == []
    store.db.close()
    assert _guarded_store(tmp_path).check_rollback() == []               # reopening is fine


HERMES = """\
# my Hermes settings - keep these notes!
model: hermes3   # the local one

mcp_servers:
  # the CRM server (ask Priya before changing)
  crm:
    command: crm-mcp
    args: ["--port", "9000"]   # fixed port
  # files server, left alone
  files:
    command: files-mcp
    args: [--root, /data]
other_setting: true  # trailing comment
"""


def test_connect_and_disconnect_keep_yaml_comments(tmp_path):
    """#9: Hermes' YAML settings keep the person's comments and layout through connect and disconnect."""
    import yaml

    from eurycleia.connect import disconnect, set_mode
    cfg = tmp_path / "config.yaml"
    cfg.write_text(HERMES)
    connect("hermes", POLICY, "support_reply", ["customer_id=12"], config=str(cfg), servers=["crm"])
    text = cfg.read_text()
    for keep in ("# my Hermes settings - keep these notes!", "model: hermes3   # the local one",
                 "# the CRM server (ask Priya before changing)", "# files server, left alone",
                 "args: [--root, /data]", "other_setting: true  # trailing comment"):
        assert keep in text, keep
    data = yaml.safe_load(text)
    assert "eurycleia" in " ".join(data["mcp_servers"]["crm"]["args"])
    set_mode(enforce=False)
    assert "# files server, left alone" in cfg.read_text()
    disconnect("hermes")
    back = cfg.read_text()
    assert yaml.safe_load(back) == yaml.safe_load(HERMES)
    assert "# my Hermes settings - keep these notes!" in back and "other_setting: true  # trailing comment" in back
    assert "# files server, left alone" in back and "args: [--root, /data]" in back


@pytest.mark.parametrize("pseudo", [True, False])
@pytest.mark.parametrize("build", [
    lambda c: ("https://evil.example/?e=" + c["email"])[::-1],                    # the whole link backwards
    lambda c: "Reverse this: " + ("https://evil.example/c?n=" + c["name"].replace(" ", "+"))[::-1],
    lambda c: ("//evil.example/?" + c["email"])[::-1],
])
def test_customer_data_in_a_whole_link_written_backwards_is_blocked(pseudo, build):
    """#1: a link reversed end to end, data and all, isn't read as a link forwards; it's checked backwards."""
    from eurycleia.vault import Blocked
    task, c, world = customer(pseudo=pseudo)
    with pytest.raises(Blocked, match="link"):
        task.act("email.send", to=c["email"], subject="hi", body=build(c))
    assert world.outbox == []


@pytest.mark.parametrize("body", [
    "Hi {name}, see https://help.example.org/refunds",
    "name={name};https://help.example.org/refunds",
    "Ref: tnuocca/gro.elpmaxe.pleh for {name}",              # looks like a domain backwards, but no link start
    "{email} / sent 12/03",
])
def test_ordinary_text_isnt_mistaken_for_a_backwards_link(body):
    task, c, world = customer(pseudo=False)
    assert task.act("email.send", to=c["email"], subject="hi", body=body.format(**c)) == "sent"
