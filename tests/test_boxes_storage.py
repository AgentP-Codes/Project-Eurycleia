# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Compact box storage (0.5): smaller rows, keyed log chain, log compaction and archives, migration from 0.4."""

import os
import shutil
import sqlite3
from pathlib import Path

import pytest

from demo.world import World
from eurycleia.boxes import BoxFormatError, BoxStore, LocalHolderKeys, StaticHolderKeys, holder_name, read_archive
from eurycleia.crypto import KeyUnavailable, LocalKeyProvider

LEVELS = {"name": "protected", "email": "protected", "phone": "protected", "address": "protected",
          "plan": "normal", "card_number": "secret", "customer_id": "normal"}
OLD = Path(__file__).parent / "data" / "boxes04"     # a box database written by taskvault 0.4 (test keys only)


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


def _store(tmp_path, clock=None):
    keys = StaticHolderKeys()
    store = BoxStore(str(tmp_path / "b.db"), LocalKeyProvider(tmp_path / "v.key"), keys, clock=clock or Clock())
    return store, keys


def _customer(i):
    return {"customer_id": i, "name": f"Customer {i}", "email": f"c{i}@example.com", "phone": f"04{i:08d}",
            "address": f"{i} Long Street, Sydney NSW 2000", "plan": "Pro", "card_number": f"4111 1111 1111 {i:04d}"}


def _load(store, keys, n):
    for i in range(1, n + 1):
        h = holder_name("customer", i)
        keys.create(h)
        store.store_record("crm.customer", i, _customer(i), h, LEVELS)


def _db_bytes(path):
    c = sqlite3.connect(path)
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    c.close()
    return sum(p.stat().st_size for p in path.parent.glob(path.name + "*"))


def _box(store, holder, tier):
    return bytes.fromhex(store.box_id(holder, tier)[4:])


# ---- size ------------------------------------------------------------------------------------

def test_a_customer_costs_about_2kb_and_a_read_one_small_log_entry(tmp_path):
    store, keys = _store(tmp_path)
    _load(store, keys, 400)
    per_customer = _db_bytes(tmp_path / "b.db") / 400
    assert per_customer < 2600, per_customer                 # was about 7,300 bytes in 0.4
    before = store.db.execute("SELECT COUNT(*) FROM tvb_log")[0][0]
    for i in range(1, 401):
        store.fetch_record("crm.customer", i, task=1)
    assert store.db.execute("SELECT COUNT(*) FROM tvb_log")[0][0] - before == 400   # one per read, not one per field


def test_record_index_hides_field_names_and_removed_fields_are_deleted(tmp_path):
    store, keys = _store(tmp_path)
    keys.create("customer:12")
    store.store_record("crm.customer", 12, _customer(12), "customer:12", LEVELS)
    raw = (tmp_path / "b.db").read_bytes()
    for word in (b"email", b"card_number", b"Customer 12", b"c12@example.com"):
        assert word not in raw
    items = store.db.execute("SELECT COUNT(*) FROM tvb_items")[0][0]
    store.store_record("crm.customer", 12, {"name": "Customer 12", "plan": "Pro"}, "customer:12", LEVELS)
    assert store.db.execute("SELECT COUNT(*) FROM tvb_items")[0][0] == items - 5
    assert store.fetch_record("crm.customer", 12) == {"name": "Customer 12", "plan": "Pro"}


# ---- keyed log chain --------------------------------------------------------------------------

def test_log_cannot_be_rewritten_without_the_vault_key(tmp_path):
    store, keys = _store(tmp_path)
    _load(store, keys, 2)
    store.fetch_record("crm.customer", 1, task=7)
    box = store.box_id("customer:1", "normal")
    assert store.verify_log(box)
    db = store.db
    # change a detail
    db.execute("UPDATE tvb_log SET detail='{\"task\":9}' WHERE box=? AND event='read'",
               (_box(store, "customer:1", "normal"),))
    assert not store.verify_log(box)


def test_log_detects_deleted_or_dropped_entries(tmp_path):
    store, keys = _store(tmp_path)
    _load(store, keys, 1)
    for _ in range(3):
        store.fetch_record("crm.customer", 1, task=1)
    box, b = store.box_id("customer:1", "normal"), _box(store, "customer:1", "normal")
    store.db.execute("DELETE FROM tvb_log WHERE box=? AND seq=2", (b,))        # a middle entry
    assert not store.verify_log(box)

    store2, keys2 = _store(tmp_path / "two")
    _load(store2, keys2, 1)
    store2.fetch_record("crm.customer", 1, task=1)
    b2 = _box(store2, "customer:1", "normal")
    store2.db.execute("DELETE FROM tvb_log WHERE box=? AND seq=0", (b2,))       # the start, with no compaction
    assert not store2.verify_log(store2.box_id("customer:1", "normal"))


def test_a_log_copied_from_another_vault_does_not_verify(tmp_path):
    a, ka = _store(tmp_path / "a")
    b, kb = _store(tmp_path / "b")
    _load(a, ka, 1)
    _load(b, kb, 1)
    mine = _box(b, "customer:1", "normal")
    rows = a.db.execute("SELECT seq, ts, event, detail, mac FROM tvb_log WHERE box=?",
                        (_box(a, "customer:1", "normal"),))
    b.db.execute("DELETE FROM tvb_log WHERE box=?", (mine,))
    for r in rows:        # the other vault's genuine entries, relabelled as this box's
        b.db.execute("INSERT INTO tvb_log (box, seq, ts, event, detail, mac) VALUES (?,?,?,?,?,?)", (mine, *r))
    assert not b.verify_log(b.box_id("customer:1", "normal"))
    b.db.execute("DELETE FROM tvb_log WHERE box=?", (mine,))
    assert not b.verify_log(b.box_id("customer:1", "normal"))           # an emptied log is caught too


# ---- compaction and archives ------------------------------------------------------------------

def test_compaction_keeps_the_chain_verifiable_and_the_archive_restores_the_detail(tmp_path):
    clock = Clock()
    store, keys = _store(tmp_path, clock)
    _load(store, keys, 3)
    for _ in range(5):
        store.fetch_record("crm.customer", 1, task=1)
    clock.t += 100 * 86400                                        # 100 days later
    store.fetch_record("crm.customer", 1, task=2)
    box = store.box_id("customer:1", "normal")
    before = store.log(box)

    n = store.compact_logs(90, tmp_path / "archive-1.tvlog", min_entries=1)
    assert n["entries"] >= 7 and store.verify_log(box)
    after = store.log(box)
    assert [e["event"] for e in after] == ["read", "compacted"]       # the recent read, then the summary
    summary = after[-1]["detail"]
    assert summary["events"]["read"] == 5 and summary["through"] == len(before) - 2

    archived = read_archive(store, tmp_path / "archive-1.tvlog")
    mine = [e for e in archived if e["box"] == box]
    assert [e["seq"] for e in mine] == list(range(len(before) - 1))
    assert (tmp_path / "archive-1.tvlog").stat().st_size < 3000
    assert b"read" not in (tmp_path / "archive-1.tvlog").read_bytes()   # encrypted

    # a second round, much later, compacts the summary too and still verifies
    clock.t += 100 * 86400
    store.fetch_record("crm.customer", 1, task=3)
    store.compact_logs(90, min_entries=1)
    assert store.verify_log(box) and store.log(box)[-1]["event"] == "compacted"

    # all three customers' boxes still verify, and their data is untouched
    for i in (1, 2, 3):
        for tier in ("normal", "high"):
            assert store.verify_log(store.box_id(f"customer:{i}", tier))
        assert store.fetch_record("crm.customer", i)["email"] == f"c{i}@example.com"


def test_archives_are_tamper_proof_and_never_overwritten(tmp_path):
    clock = Clock()
    store, keys = _store(tmp_path, clock)
    _load(store, keys, 1)
    clock.t += 100 * 86400
    arch = tmp_path / "a.tvlog"
    store.compact_logs(90, arch, min_entries=1)
    data = bytearray(arch.read_bytes())
    data[-5] ^= 1
    arch.write_bytes(bytes(data))
    with pytest.raises(KeyUnavailable):
        read_archive(store, arch)
    other, _ = _store(tmp_path / "other")
    arch.write_bytes(bytes(data[:-5]) + bytes([data[-5] ^ 1]) + bytes(data[-4:]))
    with pytest.raises(KeyUnavailable):
        read_archive(other, arch)                                     # wrong vault key
    store.fetch_record("crm.customer", 1, task=1)
    clock.t += 100 * 86400
    with pytest.raises(FileExistsError):
        store.compact_logs(90, arch, min_entries=1)
    assert store.verify_log(store.box_id("customer:1", "normal"))     # nothing removed when the archive failed
    assert store.compact_logs(90) == {"boxes": 0, "entries": 0}       # a handful of entries isn't worth compacting


def test_removing_the_start_of_a_log_and_faking_a_summary_is_detected(tmp_path):
    clock = Clock()
    store, keys = _store(tmp_path, clock)
    _load(store, keys, 1)
    for _ in range(3):
        store.fetch_record("crm.customer", 1, task=1)
    box, b = store.box_id("customer:1", "normal"), _box(store, "customer:1", "normal")
    store.db.execute("DELETE FROM tvb_log WHERE box=? AND seq<=1", (b,))
    last = store.db.execute("SELECT MAX(seq) FROM tvb_log WHERE box=?", (b,))[0][0]
    store.db.execute("INSERT INTO tvb_log (box, seq, ts, event, detail, mac) VALUES (?,?,?,?,?,?)",
                     (b, last + 1, clock.t, "compacted", '{"anchor":"' + "00" * 32 + '","through":1}', b"\x00" * 32))
    assert not store.verify_log(box)


def test_compaction_never_removes_newer_entries_after_the_clock_went_backwards(tmp_path):
    """Review finding: an old-looking entry after newer ones used to take the newer ones with it."""
    clock = Clock()
    store, keys = _store(tmp_path, clock)
    _load(store, keys, 1)
    box, b = store.box_id("customer:1", "normal"), _box(store, "customer:1", "normal")
    clock.t += 100 * 86400
    for _ in range(3):
        store.fetch_record("crm.customer", 1, task="recent")
    clock.t -= 60 * 86400                                          # the clock jumps back two months
    store.fetch_record("crm.customer", 1, task="skewed")
    clock.t += 60 * 86400
    before = [e["seq"] for e in store.log(box) if e["detail"].get("task") == "recent"]
    store.compact_logs(30, min_entries=1)
    after = [e["seq"] for e in store.log(box) if e["detail"].get("task") == "recent"]
    assert after == before and store.verify_log(box)
    assert store.db.execute("SELECT COUNT(*) FROM tvb_log WHERE box=? AND detail LIKE '%skewed%'", (b,))[0][0] == 1


def test_an_archive_from_another_database_is_rejected(tmp_path):
    clock = Clock()
    key = tmp_path / "shared.key"
    stores = []
    for name in ("a", "b"):
        keys = StaticHolderKeys()
        st = BoxStore(str(tmp_path / f"{name}.db"), LocalKeyProvider(key), keys, clock=clock)
        _load(st, keys, 1)
        for _ in range(2 if name == "a" else 4):
            st.fetch_record("crm.customer", 1, task=name)
        stores.append(st)
    clock.t += 100 * 86400
    stores[0].compact_logs(90, tmp_path / "a.tvlog", min_entries=1)
    stores[1].compact_logs(90, tmp_path / "b.tvlog", min_entries=1)
    assert read_archive(stores[0], tmp_path / "a.tvlog")
    with pytest.raises(KeyUnavailable, match="another box database"):
        read_archive(stores[1], tmp_path / "a.tvlog")


def test_removed_fields_are_logged(tmp_path):
    store, keys = _store(tmp_path)
    keys.create("customer:3")
    store.store_record("crm.customer", 3, _customer(3), "customer:3", LEVELS)
    store.store_record("crm.customer", 3, {"name": "Customer 3"}, "customer:3", LEVELS)
    removed = [e for e in store.log(store.box_id("customer:3", "normal")) if e["event"] == "removed"]
    assert removed and removed[0]["detail"]["fields"] == 5
    assert [e["event"] for e in store.log(store.box_id("customer:3", "high"))][-1] == "removed"


@pytest.mark.parametrize("backend", ["sqlite", "postgres"])
def test_concurrent_record_writes_in_opposite_field_orders_do_not_deadlock(tmp_path, backend, request):
    """Review finding: on Postgres, two records locking the same boxes in opposite orders could deadlock."""
    from concurrent.futures import ThreadPoolExecutor

    from eurycleia.boxes import BoxDB
    if backend == "postgres":
        url = request.getfixturevalue("pg_url")
    else:
        url = str(tmp_path / "c.db")
    vk = LocalKeyProvider(tmp_path / "v.key")
    keys = StaticHolderKeys()
    keys.create("client:acme")
    errors = []

    def worker(w):
        try:
            st = BoxStore(BoxDB(url), vk, keys)
            for i in range(15):
                rec = {"card_number": f"4111 {w} {i}", "name": f"n{w}-{i}"}
                if (w + i) % 2:
                    rec = dict(reversed(list(rec.items())))
                st.store_record("crm.contact", f"{w}-{i % 3}", rec, "client:acme",
                                {"card_number": "secret", "name": "protected"})
        except Exception as e:  # noqa: BLE001
            errors.append(repr(e))

    with ThreadPoolExecutor(6) as ex:
        list(ex.map(worker, range(6)))
    assert errors == []
    st = BoxStore(BoxDB(url), vk, keys)
    assert st.verify_log(st.box_id("client:acme", "normal")) and st.verify_log(st.box_id("client:acme", "high"))


# ---- migration from 0.4 ----------------------------------------------------------------------

def _old_copy(tmp_path):
    d = tmp_path / "old"
    shutil.copytree(OLD, d)
    return d, LocalKeyProvider(d / "vault.key", create=False), LocalHolderKeys(d / "holder-keys")


def test_old_databases_are_refused_until_migrated_then_everything_still_opens(tmp_path):
    d, vk, hk = _old_copy(tmp_path)
    with pytest.raises(BoxFormatError, match="boxes migrate"):
        BoxStore(str(d / "boxes.db"), vk, hk)
    store = BoxStore(str(d / "boxes.db"), vk, hk, _allow_legacy=True)
    counts = store.migrate()
    assert counts["boxes"] >= 7 and counts["records"] == 3
    store = BoxStore(str(d / "boxes.db"), vk, hk)
    for cid, rec in World().customers.items():
        got = store.fetch_record("crm.customer", cid, task=1)
        assert {k: v for k, v in got.items() if k != "card_number"} == \
               {k: v for k, v in rec.items() if k != "card_number"}
        assert store.reveal(got["card_number"], task=1, reason="check") == rec["card_number"]
    assert store._read_normal(store.box_id("department:hr", "normal"),
                              store._mac("item", store.box_id("department:hr", "normal"), "policy")[:24],
                              None) == "HR handbook v3"
    for b in store.boxes():
        assert store.verify_log(b.box_id)
        assert "migrated" in [e["event"] for e in store.log(b.box_id)]
    assert store.migrate()["boxes"] == 0                              # running it again is harmless


def test_migration_stops_if_an_old_log_was_tampered_with(tmp_path):
    d, vk, hk = _old_copy(tmp_path)
    c = sqlite3.connect(d / "boxes.db")
    c.execute("UPDATE tv_box_log SET event='deposit' WHERE seq=0 AND rowid=(SELECT MIN(rowid) FROM tv_box_log)")
    c.commit()
    c.close()
    store = BoxStore(str(d / "boxes.db"), vk, hk, _allow_legacy=True)
    with pytest.raises(BoxFormatError, match="tamper check"):
        store.migrate()
    c = sqlite3.connect(d / "boxes.db")                               # nothing changed
    assert c.execute("SELECT COUNT(*) FROM tvb_boxes").fetchone()[0] == 0
    assert c.execute("SELECT COUNT(*) FROM tv_boxes").fetchone()[0] >= 7


def test_migration_refuses_the_wrong_vault_key_even_without_records(tmp_path):
    """Review finding: with no record index to decrypt, a wrong key used to 'succeed' and wreck the logs."""
    d, _, hk = _old_copy(tmp_path)
    c = sqlite3.connect(d / "boxes.db")
    c.execute("DELETE FROM tv_index")
    c.commit()
    c.close()
    wrong = LocalKeyProvider(tmp_path / "wrong.key")
    with pytest.raises(BoxFormatError, match="doesn't belong"):
        BoxStore(str(d / "boxes.db"), wrong, hk, _allow_legacy=True).migrate()
    c = sqlite3.connect(d / "boxes.db")
    assert c.execute("SELECT COUNT(*) FROM tv_box_log").fetchone()[0] > 0      # old logs untouched
    right = LocalKeyProvider(d / "vault.key", create=False)
    counts = BoxStore(str(d / "boxes.db"), right, hk, _allow_legacy=True).migrate()
    assert counts["boxes"] >= 7 and counts["skipped_records"] == 0


def test_cli_migrate_compact_and_archive(tmp_path, capsys):
    from eurycleia.cli import main
    d, _, _ = _old_copy(tmp_path)
    common = ["--key", str(d / "vault.key"), "--db", str(d / "boxes.db"), "--holder-keys", str(d / "holder-keys")]
    assert main(["boxes", "migrate", *common]) == 0
    assert "vault key matched" in capsys.readouterr().out
    compact = ["boxes", "compact", *common, "--older-than", "0", "--min-entries", "1",
               "--archive", str(tmp_path / "a.tvlog")]
    assert main(compact) == 0
    assert "archived to" in capsys.readouterr().out
    assert main(["boxes", "archive", *common, str(tmp_path / "a.tvlog")]) == 0
    assert "archive intact" in capsys.readouterr().out
    assert main(compact) == 1
    assert os.path.exists(tmp_path / "a.tvlog")


def test_a_holder_forgotten_mid_save_never_leaves_unreadable_items(tmp_path):
    """Found by the mixed-load stress test (Postgres): a forget landing between sealing a record and saving it
    failed the save; worse, a box recreated in between would have got items sealed with its old key."""
    store, keys = _store(tmp_path)
    keys.create("customer:5")
    store.store_record("crm.customer", 5, _customer(5), "customer:5", LEVELS)
    real_seal, fired = store._seal, []

    def seal_then_forget(holder, tier, box, item_id, value):
        out = real_seal(holder, tier, box, item_id, value)
        if not fired:
            fired.append(1)
            store.forget_holder("customer:5")        # someone forgets the customer right now...
            store.unforget_holder("customer:5")      # ...they come straight back (0.6: tombstones)...
            store.ensure_box("customer:5", "normal")  # ...and the box is recreated with a NEW key
        return out

    store._seal = seal_then_forget
    store.store_record("crm.customer", 5, _customer(5), "customer:5", LEVELS)
    store._seal = real_seal
    assert fired and store.fetch_record("crm.customer", 5)["email"] == "c5@example.com"
    for tier in ("normal", "high"):
        assert store.verify_log(store.box_id("customer:5", tier))
