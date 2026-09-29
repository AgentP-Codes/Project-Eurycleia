# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""One-time upgrade of a taskvault 0.4 box database (`taskvault boxes migrate`). Loaded only when used."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import TYPE_CHECKING

from .boxes import TIERS, ZERO, BoxFormatError, _b, _jd
from .crypto import KeyUnavailable

if TYPE_CHECKING:
    from .boxes import BoxDB, BoxStore


def migrate(store: BoxStore) -> dict[str, int]:
    """Upgrade a taskvault 0.4 box database in place, in one transaction. Encrypted values are copied
    unchanged. First it proves the vault key belongs to this database, and checks every old log is
    internally consistent; it stops if either fails. (0.4 logs used an unkeyed hash chain, so someone
    with write access to the database could have rewritten one consistently; that can't be detected
    now. From 0.5 on, rewriting a log needs the vault key.)"""
    db = store.db
    empty = {"boxes": 0, "items": 0, "records": 0, "log_entries": 0, "skipped_records": 0}
    if not db.legacy:
        return empty
    counts = dict(empty)
    key = store._subkey(b"box-log")
    with db.transaction() as tx:
        boxes = tx.execute("SELECT box_id, holder_fp, holder_label, tier, wrapped_dek, created FROM tv_boxes")
        for box, _, label, tier, *_ in boxes:
            try:
                holder = store._unlock_vault(label, f"{box}|label").decode()
            except KeyUnavailable:
                holder = None
            if holder is None or store.box_id(holder, tier) != box:
                raise BoxFormatError("this vault key doesn't belong to this box database; nothing was changed")
        broken = [b for b, *_ in boxes if not _legacy_log_ok(tx, b)]
        if broken:
            raise BoxFormatError(f"{len(broken)} box log(s) fail their tamper check, so nothing was migrated: "
                                 f"{', '.join(broken[:5])}. Investigate before upgrading.")
        holder_of = {b: h for b, h, *_ in boxes}
        counts["boxes"] = len(boxes)
        for box, holder_fp, label, tier, dek, created in boxes:
            tx.execute("INSERT INTO tvb_boxes (box, holder, label, tier, dek, created) VALUES (?,?,?,?,?,?)",
                       (_b(box), bytes.fromhex(holder_fp)[:16], label, TIERS.index(tier), dek, created))
        for box, item, blob, recovery in tx.execute("SELECT box_id, item, blob, recovery FROM tv_items"):
            tx.execute("INSERT INTO tvb_items (box, item, blob, recovery) VALUES (?,?,?,?)",
                       (_b(box), bytes.fromhex(item), blob, recovery))
            counts["items"] += 1
        index: dict[str, dict[str, tuple[str, str]]] = {}
        for record_fp, field_fp, box, item in tx.execute("SELECT record_fp, field_fp, box_id, item FROM tv_index"):
            index.setdefault(record_fp, {})[field_fp] = (box, item)
        for record_fp, rows in index.items():
            names_row = rows.get("__fields__")
            if not names_row:
                counts["skipped_records"] += 1
                continue
            names = json.loads(store._unlock_vault(base64.b64decode(names_row[1]), f"{record_fp}|fields"))
            fmap = {}
            for f in names:
                hit = rows.get(store._mac("field", f))
                if hit and hit[0] in holder_of:        # skip leftovers pointing at a box that no longer exists
                    fmap[f] = [hit[0][4:], hit[1]]
            if not fmap:
                counts["skipped_records"] += 1
                continue
            rid = bytes.fromhex(record_fp)[:16]
            holder = bytes.fromhex(holder_of["box_" + next(iter(fmap.values()))[0]])[:16]
            tx.execute("INSERT INTO tvb_records (record, holder, map) VALUES (?,?,?)",
                       (rid, holder, store._lock_vault(_jd(fmap).encode(), f"rec|{rid.hex()}")))
            counts["records"] += 1
        for box, *_ in boxes:
            prev = ZERO
            seq = -1
            for seq, ts, event, detail in tx.execute(
                    "SELECT seq, ts, event, detail FROM tv_box_log WHERE box_id=? ORDER BY seq", (box,)):
                d = _jd(json.loads(detail))
                prev = store._chain(key, box, seq, ts, event, d, prev)
                tx.execute("INSERT INTO tvb_log (box, seq, ts, event, detail, mac) VALUES (?,?,?,?,?,?)",
                           (_b(box), seq, ts, event, d, prev))
                counts["log_entries"] += 1
        for table in ("tv_box_log", "tv_index", "tv_items", "tv_boxes"):
            tx.execute(f"DROP TABLE {table}")
    for box, *_ in boxes:
        store._log(box, "migrated", {"from": "0.4"})
    db.legacy = False
    if db.dialect == "sqlite":
        db.execute("VACUUM")                                     # hand the freed space back
    return counts


def _legacy_log_ok(db: BoxDB, box: str) -> bool:
    prev = "0" * 64
    for seq, ts, event, detail, p, h in db.execute(
            "SELECT seq, ts, event, detail, prev, hash FROM tv_box_log WHERE box_id=? ORDER BY seq", (box,)):
        body = json.dumps({"box": box, "seq": seq, "ts": ts, "event": event, "detail": json.loads(detail),
                           "prev": prev}, sort_keys=True, default=str)
        if p != prev or hashlib.sha256(body.encode()).hexdigest() != h:
            return False
        prev = h
    return True
