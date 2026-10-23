# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""0.6 hardening: keyed audit logs with an end-of-log record, owner-only files on Windows, and tombstones for
forgotten box holders. Simulated data only."""

import json
import os

import pytest

from eurycleia.audit import AuditError, AuditLog, audit_key
from eurycleia.crypto import LocalKeyProvider

KEY = b"k" * 32


def _log(tmp_path, key=KEY):
    return AuditLog(tmp_path / "audit.jsonl", key=key)


def _write(tmp_path, n=5, key=KEY):
    log = _log(tmp_path, key)
    for i in range(n):
        log.record("act", task=1, n=i, decision="allow")
    return tmp_path / "audit.jsonl"


def _lines(path):
    return path.read_text().splitlines()


def test_a_keyed_log_verifies_and_marks_every_entry(tmp_path):
    path = _write(tmp_path)
    assert all("mac" in json.loads(x) for x in _lines(path))
    assert _log(tmp_path).problem() is None
    assert (tmp_path / "audit.jsonl.head").exists()


def test_cutting_entries_off_the_end_is_detected(tmp_path):
    path = _write(tmp_path)
    path.write_text("\n".join(_lines(path)[:3]) + "\n")
    assert AuditLog(path).verify()                     # the plain chain can't tell...
    assert "cut off" in _log(tmp_path).problem()       # ...the keyed end-of-log record can


def test_deleting_the_end_of_log_record_is_detected(tmp_path):
    _write(tmp_path)
    (tmp_path / "audit.jsonl.head").unlink()
    assert "missing" in _log(tmp_path).problem()


def test_rewriting_the_whole_log_without_the_key_is_detected(tmp_path):
    path = _write(tmp_path)
    # an attacker rebuilds a consistent plain chain with an entry changed (they can't compute the MACs)
    forged, prev = [], "0" * 64
    for line in _lines(path):
        e = json.loads(line)
        e.pop("mac")
        e["decision"] = "block" if e["n"] == 2 else e["decision"]
        e["prev"] = prev
        body = {k: v for k, v in e.items() if k != "hash"}
        import hashlib
        e["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        prev = e["hash"]
        forged.append(json.dumps(e, sort_keys=True))
    path.write_text("\n".join(forged) + "\n")
    assert AuditLog(path).verify()                     # a forged plain chain passes the plain check
    assert _log(tmp_path).problem() is not None


def test_a_forged_end_of_log_record_is_detected(tmp_path):
    path = _write(tmp_path)
    path.write_text("\n".join(_lines(path)[:3]) + "\n")
    head = json.loads((tmp_path / "audit.jsonl.head").read_text())
    last = json.loads(_lines(path)[-1])
    head.update(seq=last["seq"], hash=last["hash"])     # can't recompute its MAC without the key
    (tmp_path / "audit.jsonl.head").write_text(json.dumps(head))
    assert "doesn't match the audit key" in _log(tmp_path).problem()


def test_the_wrong_key_is_detected(tmp_path):
    _write(tmp_path)
    assert _log(tmp_path, key=b"x" * 32).problem() is not None


def test_writing_after_entries_were_cut_off_is_refused(tmp_path):
    path = _write(tmp_path)
    path.write_text("\n".join(_lines(path)[:3]) + "\n")
    with pytest.raises(AuditError, match="cut off"):
        _log(tmp_path).record("act", task=2)


def test_turning_the_key_on_for_an_existing_log_needs_an_explicit_seal(tmp_path):
    _write(tmp_path, n=3, key=None)                    # an older, unkeyed log
    with pytest.raises(AuditError, match="audit seal"):
        _log(tmp_path).record("act", task=9)           # never starts keying by itself
    head = _log(tmp_path).seal()
    assert head["keyed_from"] == 3 and head["seq"] == 2
    log = _log(tmp_path)
    log.record("act", task=9)
    assert log.problem() is None
    with pytest.raises(AuditError, match="already protected"):
        _log(tmp_path).seal()


def test_stripping_macs_and_deleting_the_head_is_never_accepted(tmp_path):
    """Review finding: a rebuilt chain without MACs plus a deleted head used to be accepted as 'key just
    turned on' once the vault wrote one more entry."""
    import hashlib
    path = _write(tmp_path, n=5)
    forged, prev = [], "0" * 64
    for line in _lines(path):
        e = json.loads(line)
        if e["n"] == 2:
            continue                                   # drop the entry the attacker wants gone
        e.pop("mac")
        e["seq"], e["prev"] = len(forged), prev
        body = {k: v for k, v in e.items() if k != "hash"}
        e["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        prev = e["hash"]
        forged.append(json.dumps(e, sort_keys=True))
    path.write_text("\n".join(forged) + "\n")
    (tmp_path / "audit.jsonl.head").unlink()
    assert "missing" in _log(tmp_path).problem()
    with pytest.raises(AuditError):
        _log(tmp_path).record("act", n=99)            # the vault refuses to carry on writing to it
    assert "missing" in _log(tmp_path).problem()
    path.write_text("")                                # emptied completely: nothing left to check, but...
    assert _log(tmp_path).problem() is None            # ...an empty log with no head is just a new log


def test_seal_refuses_a_damaged_log(tmp_path):
    path = _write(tmp_path, n=3, key=None)
    lines = _lines(path)
    e = json.loads(lines[1])
    e["decision"] = "block"
    lines[1] = json.dumps(e, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditError, match="breaks the chain"):
        _log(tmp_path).seal()


def test_verifying_while_others_write_gives_no_false_alarms(tmp_path):
    import threading
    _log(tmp_path).record("act", n=0)
    stop, alarms = threading.Event(), []

    def writer():
        log = _log(tmp_path)
        while not stop.is_set():
            log.record("act", n=1)

    threads = [threading.Thread(target=writer) for _ in range(3)]
    for t in threads:
        t.start()
    for _ in range(30):
        if (p := _log(tmp_path).problem()) is not None:
            alarms.append(p)
    stop.set()
    for t in threads:
        t.join()
    assert alarms == [] and _log(tmp_path).problem() is None


def test_several_writers_share_a_keyed_log(tmp_path):
    a, b = _log(tmp_path), _log(tmp_path)
    for i in range(20):
        (a if i % 2 else b).record("act", n=i)
    assert _log(tmp_path).problem() is None


def test_in_memory_keyed_log():
    log = AuditLog(key=KEY)
    log.record("act", n=1)
    log.record("act", n=2)
    assert log.problem() is None
    log.entries[0]["n"] = 5
    assert log.problem() is not None


def test_audit_key_comes_from_the_vault_key(tmp_path):
    p = LocalKeyProvider(tmp_path / "k.key")
    assert audit_key(p) == audit_key(p) and audit_key(p) != p.data_key() and len(audit_key(p)) == 32
    with pytest.raises(ValueError):
        AuditLog(key=b"short")


def test_cli_verify_with_the_key(tmp_path, capsys):
    from eurycleia.cli import main
    p = LocalKeyProvider(tmp_path / "k.key")
    log = AuditLog(tmp_path / "audit.jsonl", key=audit_key(p))
    for i in range(4):
        log.record("act", n=i)
    assert main(["audit", "verify", str(tmp_path / "audit.jsonl"), "--key", str(tmp_path / "k.key")]) == 0
    lines = _lines(tmp_path / "audit.jsonl")
    (tmp_path / "audit.jsonl").write_text("\n".join(lines[:2]) + "\n")
    assert main(["audit", "verify", str(tmp_path / "audit.jsonl"), "--key", str(tmp_path / "k.key")]) == 1
    assert "cut off" in capsys.readouterr().out


# ------------------------------------------------------------------ tombstones for forgotten holders
LEVELS = {"name": "protected", "email": "protected", "card": "secret"}


def _boxes(tmp_path):
    from eurycleia.boxes import BoxStore, LocalHolderKeys
    keys = LocalHolderKeys(tmp_path / "holder-keys")
    store = BoxStore(tmp_path / "boxes.db", LocalKeyProvider(tmp_path / "vault.key"), keys)
    keys.create("customer:5")
    return store


def _record(n=5):
    return {"name": f"Customer {n}", "email": f"c{n}@example.com", "card": "4111 1111 1111 1111"}


def test_a_forgotten_holder_is_not_quietly_brought_back(tmp_path):
    from eurycleia.boxes import HolderForgotten
    store = _boxes(tmp_path)
    store.store_record("crm.customer", 5, _record(), "customer:5", LEVELS)
    store.forget_holder("customer:5")
    assert store.is_forgotten("customer:5") and store.fetch_record("crm.customer", 5) is None
    with pytest.raises(HolderForgotten):             # e.g. a nightly import still has them
        store.store_record("crm.customer", 5, _record(), "customer:5", LEVELS)
    with pytest.raises(HolderForgotten):
        store.deposit("customer:5", "normal", "note", "hello")
    assert store.fetch_record("crm.customer", 5) is None and store.boxes() == []


def test_unforget_lets_a_returning_holder_start_again(tmp_path):
    store = _boxes(tmp_path)
    store.store_record("crm.customer", 5, _record(), "customer:5", LEVELS)
    store.forget_holder("customer:5")
    assert store.unforget_holder("customer:5") and not store.unforget_holder("customer:5")
    assert store.fetch_record("crm.customer", 5) is None          # the old data stays gone
    store.store_record("crm.customer", 5, _record(), "customer:5", LEVELS)
    assert store.fetch_record("crm.customer", 5)["email"] == "c5@example.com"


def test_tombstones_hold_no_names(tmp_path):
    import sqlite3
    store = _boxes(tmp_path)
    store.store_record("crm.customer", 5, _record(), "customer:5", LEVELS)
    store.forget_holder("customer:5")
    rows = sqlite3.connect(tmp_path / "boxes.db").execute("SELECT holder FROM tvb_forgotten").fetchall()
    assert len(rows) == 1 and b"customer" not in bytes(rows[0][0]) and len(bytes(rows[0][0])) == 16


def test_a_forget_during_a_save_leaves_nothing_behind(tmp_path):
    from eurycleia.boxes import BoxLocked, HolderForgotten
    store = _boxes(tmp_path)
    store.store_record("crm.customer", 5, _record(), "customer:5", LEVELS)
    real_seal, fired = store._seal, []

    def seal_then_forget(*a):
        out = real_seal(*a)
        if not fired:
            fired.append(1)
            store.forget_holder("customer:5")
        return out

    store._seal = seal_then_forget
    with pytest.raises((HolderForgotten, BoxLocked)):
        store.store_record("crm.customer", 5, _record(), "customer:5", LEVELS)
    store._seal = real_seal
    assert store.fetch_record("crm.customer", 5) is None and store.boxes() == []


# ------------------------------------------------------------------ owner-only files on Windows
def test_windows_files_get_an_owner_only_access_list(tmp_path, monkeypatch):
    import eurycleia.audit as audit
    calls = []

    class Done:
        def __init__(self, out="", code=0):
            self.stdout, self.returncode = out, code

    def fake_run(cmd):
        calls.append(cmd)
        return Done('"PC\\\\someone","S-1-5-21-1-2-3-1001"') if cmd[0] == "whoami" else Done()

    monkeypatch.setattr(audit, "_WINDOWS", True)
    monkeypatch.setattr(audit, "_run", fake_run)
    monkeypatch.setattr(audit, "_msvcrt", lambda: _FakeMsvcrt())
    audit.private_file(tmp_path / "new.jsonl")
    audit.owner_only(tmp_path)
    icacls = [c for c in calls if c[0] == "icacls"]
    assert icacls[0][1:] == [str(tmp_path / "new.jsonl"), "/inheritance:r", "/grant:r", "*S-1-5-21-1-2-3-1001:F"]
    assert icacls[1][-1] == "*S-1-5-21-1-2-3-1001:(OI)(CI)F"


def test_windows_permission_failure_is_logged_not_fatal(tmp_path, monkeypatch, caplog):
    import eurycleia.audit as audit

    class Done:
        stdout, returncode = "Access is denied.", 5

    monkeypatch.setattr(audit, "_WINDOWS", True)
    monkeypatch.setattr(audit, "_run", lambda cmd: type("W", (), {"stdout": '"a","S-1-5-1"', "returncode": 0})()
                        if cmd[0] == "whoami" else Done())
    (tmp_path / "f").write_text("x")
    audit.owner_only(tmp_path / "f")
    assert "couldn't make f private" in caplog.text


def test_posix_files_are_owner_only(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX permissions")
    from eurycleia.audit import owner_only
    (tmp_path / "f").write_text("x")
    os.chmod(tmp_path / "f", 0o644)
    owner_only(tmp_path / "f")
    assert os.stat(tmp_path / "f").st_mode & 0o777 == 0o600
    assert os.stat(LocalKeyProvider(tmp_path / "k.key").path).st_mode & 0o777 == 0o600



def test_a_share_without_file_permissions_still_works(tmp_path, monkeypatch, caplog):
    """Azure Files and other SMB shares refuse chmod: the audit log still opens (with a warning), but a key
    file, which must be private, is still refused."""
    if os.name == "nt":
        pytest.skip("POSIX permissions")
    from eurycleia import audit

    def refuse(path, mode):
        raise PermissionError(1, "Operation not permitted")
    monkeypatch.setattr(audit.os, "chmod", refuse)
    log = audit.AuditLog(tmp_path / "audit.jsonl")
    assert log.path.exists() and "couldn't make" in caplog.text
    with pytest.raises(OSError):
        LocalKeyProvider(tmp_path / "k.key")
    assert not (tmp_path / "k.key").exists()

class _FakeMsvcrt:
    LK_LOCK, LK_UNLCK = 1, 0

    def locking(self, fd, mode, n):
        pass


def test_a_crash_between_an_entry_and_its_head_record_is_recovered(tmp_path, monkeypatch):
    log = _log(tmp_path)
    log.record("act", n=1)
    monkeypatch.setattr(AuditLog, "_write_head", lambda self, head: None)   # the head update never happens
    log.record("act", n=2)
    monkeypatch.undo()
    assert _log(tmp_path).problem() is None                  # the extra keyed entry is the vault's own
    _log(tmp_path).record("act", n=3)                         # and writing carries on
    assert _log(tmp_path).problem() is None


def test_an_extra_entry_without_the_key_is_still_caught(tmp_path):
    import hashlib
    path = _write(tmp_path, n=3)
    last = json.loads(_lines(path)[-1])
    forged = {"seq": last["seq"] + 1, "ts": last["ts"], "event": "act", "decision": "allow", "prev": last["hash"]}
    body = json.dumps(forged, sort_keys=True, separators=(",", ":"))
    forged["hash"] = hashlib.sha256(body.encode()).hexdigest()
    forged["mac"] = "0" * 64
    with path.open("a") as f:
        f.write(json.dumps(forged, sort_keys=True) + "\n")
    assert _log(tmp_path).problem() is not None


def test_a_deposit_racing_a_forget_saves_nothing(tmp_path):
    """Review finding: a deposit landing between sealing and saving left an orphaned item that came back after
    unforget."""
    import threading

    from eurycleia.boxes import BoxStore, HolderForgotten, LocalHolderKeys
    store = _boxes(tmp_path)
    store.deposit("customer:5", "high", "card", "4111 1111 1111 1111")
    other = BoxStore(tmp_path / "boxes.db", LocalKeyProvider(tmp_path / "vault.key"),
                     LocalHolderKeys(tmp_path / "holder-keys"))
    real_seal = store._seal

    def seal_then_forget(*a):
        out = real_seal(*a)
        t = threading.Thread(target=other.forget_holder, args=("customer:5",))
        t.start()
        t.join()
        return out

    store._seal = seal_then_forget
    with pytest.raises(HolderForgotten):
        store.deposit("customer:5", "high", "card", "5555 5555 5555 4444")
    store._seal = real_seal
    assert store.db.execute("SELECT COUNT(*) FROM tvb_items")[0][0] == 0
    store.unforget_holder("customer:5")
    box = store.ensure_box("customer:5", "high")
    with pytest.raises(KeyError):
        store.reveal(f"tvbox:{box}:{store._mac('item', box, 'card')[:24]}")


@pytest.mark.parametrize("variant", ["customer:012", "customer:12 ", "customer:12.0", "Customer:12", "customer: 12"])
def test_tombstones_cover_the_usual_spellings_of_an_id(tmp_path, variant):
    from eurycleia.boxes import HolderForgotten
    store = _boxes(tmp_path)
    store.forget_holder("customer:12")
    with pytest.raises((HolderForgotten, ValueError)):
        store.deposit(variant, "normal", "note", "hello")
    assert store.is_forgotten(variant.replace("Customer", "customer"))


def test_a_key_file_is_never_left_readable_when_windows_permissions_fail(tmp_path, monkeypatch):
    import eurycleia.audit as audit

    class Denied:
        stdout, returncode = "Access is denied.", 5

    monkeypatch.setattr(audit, "_WINDOWS", True)
    monkeypatch.setattr(audit, "_run", lambda cmd: type("W", (), {"stdout": '"a","S-1-5-1"', "returncode": 0})()
                        if cmd[0] == "whoami" else Denied())
    with pytest.raises(OSError, match="private"):
        LocalKeyProvider(tmp_path / "k.key")
    assert not (tmp_path / "k.key").exists()


def test_seal_refuses_a_keyed_log_whose_head_was_deleted(tmp_path):
    """Review finding: cut the end off a keyed log, delete its head, and `seal` used to accept it."""
    path = _write(tmp_path, n=5)
    path.write_text("\n".join(_lines(path)[:4]) + "\n")
    (tmp_path / "audit.jsonl.head").unlink()
    with pytest.raises(AuditError, match="written with a key"):
        _log(tmp_path).seal()


def test_connect_with_a_key_never_seals_by_itself(tmp_path, capsys):
    from eurycleia.cli import main
    p = LocalKeyProvider(tmp_path / "k.key")
    AuditLog(tmp_path / "audit.jsonl").record("act", n=1)          # an older, unkeyed log
    rc = main(["connect", "mcp-json", "--config", str(tmp_path / "none.json"), "--audit",
               str(tmp_path / "audit.jsonl"), "--key", str(p.path), "--task", "x"])
    assert rc == 1 and "audit seal" in capsys.readouterr().err
    assert not (tmp_path / "audit.jsonl.head").exists()
