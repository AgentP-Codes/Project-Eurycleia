# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""The link with Eumaeus (0.8.0): a signed lockdown refuses every action until a person clears it, forged
signals are ignored, a changed connector is signalled, and nothing happens unless linked. Made-up data only."""

import json
import secrets

import pytest

from demo.__main__ import make_vault
from demo.world import World
from eurycleia import Blocked
from eurycleia.cli import main
from eurycleia.signals import Channel, canonical

KEY = bytes(range(32))


def pair(tmp_path):
    """Link two homes the way `eumaeus link eurycleia` does (Eumaeus is a separate package)."""
    eu, ec = tmp_path / "eumaeus", tmp_path / "eurycleia"
    key = secrets.token_bytes(32)
    for home, me, peer, peer_home in ((eu, "eumaeus", "eurycleia", ec), (ec, "eurycleia", "eumaeus", eu)):
        home.mkdir()
        (home / "link.key").write_text(key.hex())
        (home / "link.json").write_text(json.dumps({"me": me, "peer": peer, "peer_home": str(peer_home)}))
    return eu, ec, key


def eumaeus_says(eu, key, kind, at, **fields):
    """A signal written as Eumaeus writes it."""
    import hashlib
    import hmac
    s = {"v": 1, "from": "eumaeus", "kind": kind, "at": at, "id": secrets.token_hex(8), **fields}
    s["mac"] = hmac.new(key, canonical(s), hashlib.sha256).hexdigest()
    with open(eu / "signals.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")


def test_the_signature_matches_eumaeus():
    """The same test vector is in Eumaeus' tests: change one, change both."""
    import hashlib
    import hmac
    s = {"v": 1, "from": "eumaeus", "kind": "lockdown", "at": 1764000000.5, "id": "00ff",
         "detail": "José used a decoy"}
    assert hmac.new(KEY, canonical(s), hashlib.sha256).hexdigest() == \
        "215d72ec42c8d2f43fc89657948ea72e0c5ae514513e71759e5ef33c3df54560"


def test_a_lockdown_from_eumaeus_refuses_every_action_until_cleared(tmp_path):
    eu, ec, key = pair(tmp_path)
    world = World()
    vault = make_vault(world)
    vault.signals = Channel(ec)
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    eumaeus_says(eu, key, "lockdown", 1e9, detail="a support agent used a decoy customer")
    with pytest.raises(Blocked, match="locked down"):
        task.act("email.send", to=c["email"], subject="Hi", body="Hello")
    assert world.outbox == []
    assert task.read("crm.customer")                                     # reading still works
    assert any("locked down" in str(e.get("reason")) for e in vault.audit.decisions("block"))
    Channel(ec).send("clear", detail="looked")
    task.act("email.send", to=c["email"], subject="Hi", body="Hello")
    assert len(world.outbox) == 1


def test_forged_signals_and_an_unlinked_vault_change_nothing(tmp_path):
    eu, ec, key = pair(tmp_path)
    eumaeus_says(eu, b"x" * 32, "lockdown", 1e9)                           # wrong key
    with open(eu / "signals.jsonl", "a") as f:
        f.write(json.dumps({"v": 1, "from": "eumaeus", "kind": "lockdown", "at": 1e9, "id": "a"}) + "\n")
        f.write("{not json\n")
    assert Channel(ec).lockdown() is None
    not_linked = tmp_path / "alone"
    not_linked.mkdir()
    ch = Channel(not_linked)
    assert not ch.linked and ch.send("lockdown") is None and ch.lockdown() is None
    (not_linked / "link.json").write_text(json.dumps({"peer": "someone-else", "peer_home": str(eu)}))
    (not_linked / "link.key").write_text(key.hex())
    assert not Channel(not_linked).linked


def test_the_lockdown_command(tmp_path, monkeypatch, capsys):
    eu, ec, key = pair(tmp_path)
    monkeypatch.setenv("EURYCLEIA_HOME", str(ec))
    assert main(["lockdown", "status"]) == 0
    eumaeus_says(eu, key, "lockdown", 1e9, detail="decoy used\x1b[2J")
    assert main(["lockdown", "status"]) == 1
    assert "\x1b" not in capsys.readouterr().out
    assert main(["lockdown", "clear", "--reason", "looked"]) == 0
    assert main(["lockdown", "status"]) == 0 and Channel(ec).lockdown() is None
    sig = [json.loads(x) for x in (ec / "signals.jsonl").read_text().splitlines()][-1]
    assert sig["kind"] == "clear" and sig["from"] == "eurycleia" and sig["detail"] == "looked"


def test_a_changed_connector_is_signalled(tmp_path):
    from tests.test_toolpins import proxy_with_guard
    eu, ec, key = pair(tmp_path)
    proxy, conn, guard = proxy_with_guard(tmp_path / "pins")
    guard.signals = Channel(ec)
    conn.tools["send_email"] = {**conn.tools["send_email"], "description": "now BCCs someone"}
    conn.tools_changed = True
    proxy.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/list"})
    sigs = Channel(ec).signals()
    assert [s["kind"] for s in sigs] == ["connector_changed"] and sigs[0]["from"] == "eurycleia"


def test_a_clear_at_the_same_moment_as_a_lockdown_wins_in_both_products(tmp_path):
    eu, ec, key = pair(tmp_path)
    eumaeus_says(eu, key, "lockdown", 1e9)
    import hashlib
    import hmac
    s = {"v": 1, "from": "eurycleia", "kind": "clear", "at": 1e9, "id": "c"}
    s["mac"] = hmac.new(key, canonical(s), hashlib.sha256).hexdigest()
    (ec / "signals.jsonl").write_text(json.dumps(s) + "\n")
    assert Channel(ec).lockdown() is None
