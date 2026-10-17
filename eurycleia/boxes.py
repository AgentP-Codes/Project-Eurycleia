# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Deposit boxes: each holder's data in its own encrypted box, like a bank's safe deposit boxes.

Holders are departments (``department:hr``), individual customers
(``customer:12``) or client companies (``client:acme``). Each holder has its
own boxes, stored as rows in SQLite or Postgres.

Two tiers:

  normal   basic information. The box has its own data key, locked by the
           vault's key, so the vault can open it whenever the policy allows.
  high     higher-tier information (secrets by default). Every item is sealed
           to the holder's *public* key and then locked again with the vault's
           key. Opening needs BOTH keys: the vault's and the holder's. Like a
           deposit slot, anyone can put something in; only the holder's key
           (plus the bank's) gets it out.

Opening a high box asks the holder's key service for the private key. That
service can require a person to approve, and the key is kept in memory only
for a short window (`open_ttl`), then wiped. Every deposit, opening and
withdrawal is written to a per-box log, each entry chained to the last with a
keyed MAC (so rewriting it needs the vault key). `compact_logs` archives old entries. `forget_holder` deletes a
holder's boxes; an optional company recovery key lets you restore access if a
holder loses theirs.

Performance: crypto is microseconds per item; boxes are rows, so millions of
boxes cost what millions of rows cost. The slow part is fetching a holder's
private key (a network call or a human approval), which is cached per open.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .audit import owner_only, private_file
from .crypto import KeyProvider, KeyUnavailable
from .errors import EurycleiaError

HOLDER_TYPES = ("department", "customer", "client")
TIERS = ("normal", "high")
FORMAT = 2                       # box database format (0.4 used 1: tv_* tables)
REF_RE = re.compile(r"^tvbox:(box_[0-9a-f]{24}):([0-9a-f]{24})$")


class BoxFormatError(EurycleiaError):
    """The box database is in a format this version can't use directly (see `eurycleia boxes migrate`)."""


class _BoxChanged(Exception):
    """Internal: a box vanished or changed key between sealing and saving; the save is retried."""


class HolderForgotten(EurycleiaError):
    """The holder was forgotten (forget_holder). New boxes for them are refused until unforget_holder()."""


class BoxLocked(EurycleiaError):
    """A high-tier box couldn't be opened: the holder's key was unavailable or access was denied."""


def is_box_ref(value: Any) -> bool:
    return isinstance(value, str) and bool(REF_RE.match(value))


def holder_name(kind: str, ident: Any) -> str:
    if kind not in HOLDER_TYPES:
        raise ValueError(f"holder type must be one of {HOLDER_TYPES}")
    ident = str(ident)
    if not ident or ":" in ident:
        raise ValueError("holder id must be non-empty and contain no ':'")
    return f"{kind}:{ident}"


# ------------------------------------------------------------------ holder keys
@dataclass
class OpenRequest:
    holder: str
    box_id: str
    task: Any
    reason: str


class HolderKeys(Protocol):
    def public_key(self, holder: str) -> bytes: ...

    def private_key(self, request: OpenRequest) -> bytes | None: ...


class LocalHolderKeys:
    """Holder key pairs as files in a folder (one per holder, owner-only permissions).

    Suitable for departments and testing. For customers or client companies,
    implement `HolderKeys` against their own key service, so the private key
    never sits with you. `approver` can require a person to allow each opening.
    """

    def __init__(self, folder: str | Path, approver: Callable[[OpenRequest], bool] | None = None):
        self.folder, self.approver = Path(folder), approver
        self.folder.mkdir(parents=True, exist_ok=True)

    def _path(self, holder: str) -> Path:
        return self.folder / (holder.replace(":", "__") + ".key")

    def create(self, holder: str) -> Path:
        path = self._path(holder)
        if path.exists():
            raise FileExistsError(f"{holder} already has a key")
        raw = X25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        private_file(path).write_bytes(base64.b64encode(raw))
        return path

    def public_key(self, holder: str) -> bytes:
        return _public_of(self._private(holder))

    def private_key(self, request: OpenRequest) -> bytes | None:
        if self.approver is not None and not self.approver(request):
            return None
        return self._private(request.holder)

    def _private(self, holder: str) -> bytes:
        path = self._path(holder)
        if not path.exists():
            raise KeyUnavailable(f"no key for {holder}")
        return base64.b64decode(path.read_bytes())


class StaticHolderKeys:
    """In-memory holder keys (tests, or wrapping keys fetched elsewhere)."""

    def __init__(self, private_keys: dict[str, bytes] | None = None,
                 approver: Callable[[OpenRequest], bool] | None = None):
        self.keys = dict(private_keys or {})
        self.approver = approver

    def create(self, holder: str) -> bytes:
        raw = X25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        self.keys[holder] = raw
        return raw

    def public_key(self, holder: str) -> bytes:
        if holder not in self.keys:
            raise KeyUnavailable(f"no key for {holder}")
        return _public_of(self.keys[holder])

    def private_key(self, request: OpenRequest) -> bytes | None:
        if self.approver is not None and not self.approver(request):
            return None
        return self.keys.get(request.holder)


def _public_of(private_raw: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _seal_to(public_raw: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Anonymous public-key encryption: X25519 + HKDF + AES-GCM. Output: eph_pub(32) | nonce(12) | ct."""
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(public_raw))
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = HKDF(SHA256(), 32, salt=eph_pub + public_raw, info=b"taskvault-box" + aad).derive(shared)
    nonce = os.urandom(12)
    return eph_pub + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def _open_from(private_raw: bytes, blob: bytes, aad: bytes) -> bytes:
    eph_pub, nonce, ct = blob[:32], blob[32:44], blob[44:]
    priv = X25519PrivateKey.from_private_bytes(private_raw)
    my_pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = HKDF(SHA256(), 32, salt=eph_pub + my_pub, info=b"taskvault-box" + aad).derive(shared)
    return AESGCM(key).decrypt(nonce, ct, aad)


# ------------------------------------------------------------------- database
class BoxDB:
    """Minimal SQLite / Postgres adapter. Statements use `?`; converted for Postgres."""

    def __init__(self, url: str | Path):
        self._lock = threading.RLock()
        url = str(url)
        if url.startswith(("postgresql://", "postgres://")):
            import psycopg  # optional: pip install "eurycleia[postgres]"
            self.dialect = "postgres"
            self.conn = psycopg.connect(url, autocommit=True)
            self.conn.execute("SELECT pg_advisory_lock(7428101)")   # one connection creates the tables at a time
        else:
            path = url[len("sqlite:///"):] if url.startswith("sqlite:///") else url
            self.dialect = "sqlite"
            target = ":memory:" if path == ":memory:" else str(private_file(Path(path).resolve()))
            self.conn = sqlite3.connect(target, check_same_thread=False, isolation_level=None, timeout=30)
            self.conn.execute("PRAGMA busy_timeout=30000")            # wait for other writers, don't fail
            if target != ":memory:":
                # readers don't block writers. Switching a brand-new file to WAL needs an exclusive
                # lock that SQLite won't wait for, so retry briefly if another connection is doing it too.
                _retry_locked(lambda: self.conn.execute("PRAGMA journal_mode=WAL"))
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA secure_delete=ON")       # deleted rows are overwritten, not left in free space
        pg = self.dialect == "postgres"
        blob, real = ("BYTEA", "DOUBLE PRECISION") if pg else ("BLOB", "REAL")
        compact = "" if pg else " WITHOUT ROWID"       # SQLite: store rows in the key's own tree, not twice
        for ddl in [
            "CREATE TABLE IF NOT EXISTS tvb_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
            f"CREATE TABLE IF NOT EXISTS tvb_boxes (box {blob} PRIMARY KEY, holder {blob} NOT NULL, "
            f"label {blob} NOT NULL, tier SMALLINT NOT NULL, dek {blob}, created {real} NOT NULL){compact}",
            "CREATE INDEX IF NOT EXISTS tvb_boxes_holder ON tvb_boxes (holder)",
            f"CREATE TABLE IF NOT EXISTS tvb_items (box {blob} NOT NULL, item {blob} NOT NULL, "
            f"blob {blob} NOT NULL, recovery {blob}, PRIMARY KEY (box, item)){compact}",
            f"CREATE TABLE IF NOT EXISTS tvb_records (record {blob} PRIMARY KEY, holder {blob} NOT NULL, "
            f"map {blob} NOT NULL){compact}",
            "CREATE INDEX IF NOT EXISTS tvb_records_holder ON tvb_records (holder)",
            # tombstones: keyed fingerprints of forgotten holders (no names), so a later import can't quietly
            # bring their data back
            f"CREATE TABLE IF NOT EXISTS tvb_forgotten (holder {blob} PRIMARY KEY, ts {real} NOT NULL){compact}",
            f"CREATE TABLE IF NOT EXISTS tvb_log (box {blob} NOT NULL, seq INTEGER NOT NULL, ts {real} NOT NULL, "
            f"event TEXT NOT NULL, detail TEXT NOT NULL, mac {blob} NOT NULL, PRIMARY KEY (box, seq)){compact}",
        ]:
            _retry_locked(lambda ddl=ddl: self.execute(ddl))
        found = self.execute("SELECT v FROM tvb_meta WHERE k='format'")
        if not found:
            _retry_locked(lambda: self.upsert("tvb_meta", ["k", "v"], ("format", str(FORMAT)), ["k"]))
        elif int(found[0][0]) > FORMAT:
            raise BoxFormatError("this box database was written by a newer eurycleia; upgrade eurycleia")
        if not self.execute("SELECT v FROM tvb_meta WHERE k='id'"):       # this database's own identity
            new_id = os.urandom(16).hex()
            ins = ("INSERT INTO tvb_meta (k, v) VALUES ('id', ?) ON CONFLICT (k) DO NOTHING" if pg
                   else "INSERT OR IGNORE INTO tvb_meta (k, v) VALUES ('id', ?)")
            _retry_locked(lambda: self.execute(ins, (new_id,)))
        self.db_id = self.execute("SELECT v FROM tvb_meta WHERE k='id'")[0][0]
        if pg:
            self.legacy = bool(self.execute("SELECT to_regclass('tv_boxes')")[0][0])
            self.conn.execute("SELECT pg_advisory_unlock(7428101)")
        else:
            self.legacy = bool(self.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='tv_boxes'"))

    def lock(self, key: str) -> None:
        """Inside a transaction: serialise writers working on the same key (e.g. one box).
        SQLite transactions already take the write lock up front, so only Postgres needs this."""
        if self.dialect == "postgres":
            self.execute("SELECT pg_advisory_xact_lock(hashtext(?))", (key,))

    def execute(self, sql: str, params: tuple = ()) -> list[tuple]:
        if self.dialect == "postgres":
            sql = sql.replace("?", "%s")
        with self._lock:
            cur = self.conn.execute(sql, params)
            try:
                rows = cur.fetchall()
            except Exception:  # noqa: BLE001 - statements without results
                rows = []
        return [tuple(bytes(v) if isinstance(v, memoryview) else v for v in r) for r in rows]

    def upsert(self, table: str, cols: list[str], values: tuple, key: list[str]) -> None:
        ph = ", ".join("?" for _ in cols)
        if self.dialect == "postgres":
            updates = ", ".join(f"{c}=EXCLUDED.{c}" for c in cols if c not in key)
            sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({ph}) ON CONFLICT ({', '.join(key)}) " + \
                  (f"DO UPDATE SET {updates}" if updates else "DO NOTHING")
        else:
            sql = f"INSERT OR REPLACE INTO {table} ({', '.join(cols)}) VALUES ({ph})"
        self.execute(sql, values)

    def transaction(self):
        return _Tx(self)

    def close(self) -> None:
        self.conn.close()


def _retry_locked(fn: Any, seconds: float = 30.0) -> Any:
    """Run fn, retrying while SQLite reports the database as locked (setup steps only)."""
    deadline = time.monotonic() + seconds
    delay = 0.01
    while True:
        try:
            return fn()
        except sqlite3.OperationalError as e:
            if "locked" not in str(e) or time.monotonic() > deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.5)


class _Tx:
    def __init__(self, db: BoxDB):
        self.db = db

    def __enter__(self):
        self.db._lock.acquire()
        # SQLite: take the write lock at the start, so two writers can't deadlock upgrading later.
        self.db.conn.execute("BEGIN IMMEDIATE" if self.db.dialect == "sqlite" else "BEGIN")
        return self.db

    def __exit__(self, exc_type, exc, tb):
        try:
            self.db.conn.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self.db._lock.release()
        return False


# ------------------------------------------------------------------ box store
@dataclass
class BoxInfo:
    box_id: str
    holder: str
    tier: str
    items: int
    created: float


def _jd(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _b(box: str) -> bytes:
    """'box_<24 hex>' -> the 12 bytes stored in the database."""
    return bytes.fromhex(box[4:])


def _s(box: bytes) -> str:
    return "box_" + bytes(box).hex()


ZERO = b"\x00" * 32
ARCHIVE_MAGIC = b"TVLOGARCHIVE1"


class BoxStore:
    def __init__(self, db: BoxDB | str | Path, vault_keys: KeyProvider, holder_keys: HolderKeys | None = None,
                 recovery_public_key: bytes | None = None, open_ttl: float = 300,
                 tiers: dict[str, str] | None = None, clock: Callable[[], float] = time.time,
                 _allow_legacy: bool = False):
        self.db = db if isinstance(db, BoxDB) else BoxDB(db)
        if self.db.legacy and not _allow_legacy:
            raise BoxFormatError("this box database uses the taskvault 0.4 format. Upgrade it once with:\n"
                                 "  eurycleia boxes migrate --db <database> --key <vault key>")
        self.vault_keys, self.holder_keys = vault_keys, holder_keys
        self.recovery_public_key = recovery_public_key
        self.open_ttl, self.clock = open_ttl, clock
        self.tiers = {"secret": "high", "protected": "normal", "normal": "normal", **(tiers or {})}
        self._open: dict[str, tuple[bytes, float]] = {}      # holder -> (private key, expires)
        self._lock = threading.Lock()

    # --------------------------------------------------------------- helpers
    def _mac(self, *parts: Any) -> str:
        msg = "\x00".join(str(p) for p in parts).encode()
        return hmac.new(self.vault_keys.data_key(), msg, hashlib.sha256).hexdigest()

    def _macb(self, n: int, *parts: Any) -> bytes:
        """Short keyed fingerprint (16 bytes for lookups, 12 for ids): reveals nothing without the vault key."""
        return bytes.fromhex(self._mac(*parts))[:n]

    def _subkey(self, purpose: bytes) -> bytes:
        # separate keys for separate jobs, all derived from the vault key
        return HKDF(SHA256(), 32, salt=None, info=b"taskvault-" + purpose).derive(self.vault_keys.data_key())

    def _vault(self) -> AESGCM:
        return AESGCM(self.vault_keys.data_key())

    def box_id(self, holder: str, tier: str) -> str:
        return "box_" + self._mac("box", holder, tier)[:24]

    def _lock_vault(self, data: bytes, aad: str) -> bytes:
        n = os.urandom(12)
        return n + self._vault().encrypt(n, data, aad.encode())

    def _unlock_vault(self, blob: bytes, aad: str) -> bytes:
        try:
            return self._vault().decrypt(blob[:12], blob[12:], aad.encode())
        except Exception as e:  # noqa: BLE001 - InvalidTag
            raise KeyUnavailable("vault key can't open this box (wrong key or tampered data)") from e

    # ------------------------------------------------------------------ boxes
    def ensure_box(self, holder: str, tier: str) -> str:
        if tier not in TIERS:
            raise ValueError(f"tier must be one of {TIERS}")
        kind = holder.split(":", 1)[0]
        if kind not in HOLDER_TYPES and holder != "company":
            raise ValueError("holder must look like department:x, customer:x, client:x or 'company'")
        box = self.box_id(holder, tier)
        if self.db.execute("SELECT 1 FROM tvb_boxes WHERE box=?", (_b(box),)):
            return box
        if tier == "high":
            if self.holder_keys is None:
                raise BoxLocked("high-tier boxes need holder keys (holder_keys=...)")
            self.holder_keys.public_key(holder)            # fail early if the holder has no key
            dek = None
        else:
            dek = self._lock_vault(AESGCM.generate_key(bit_length=256), f"{box}|dek")
        label = self._lock_vault(holder.encode(), f"{box}|label")
        fp = self._macb(16, "holder", holder)
        with self.db.transaction() as db:
            db.lock(box)
            if db.execute("SELECT 1 FROM tvb_forgotten WHERE holder=?", (self._tomb(holder),)):
                raise HolderForgotten("this holder was forgotten; if they have come back (a new account or "
                                      "consent), call unforget_holder() first")
            if db.execute("SELECT 1 FROM tvb_boxes WHERE box=?", (_b(box),)):
                return box                # another writer created it first: keep ITS key, never replace it
            db.execute("INSERT INTO tvb_boxes (box, holder, label, tier, dek, created) VALUES (?,?,?,?,?,?)",
                       (_b(box), fp, label, TIERS.index(tier), dek, self.clock()))
            self._log(box, "created", {"tier": tier}, db=db)
        return box

    def _box_row(self, box: str) -> tuple[str, bytes | None]:
        rows = self.db.execute("SELECT tier, dek FROM tvb_boxes WHERE box=?", (_b(box),))
        if not rows:
            raise KeyError("no such box (it may have been forgotten)")
        return TIERS[rows[0][0]], rows[0][1]

    def _box_dek(self, box: str) -> bytes:
        _, dek = self._box_row(box)
        return self._unlock_vault(dek, f"{box}|dek")

    def _holder_of(self, box: str) -> tuple[str, str]:
        rows = self.db.execute("SELECT label, tier FROM tvb_boxes WHERE box=?", (_b(box),))
        if not rows:
            raise KeyError("no such box (it may have been forgotten)")
        return self._unlock_vault(rows[0][0], f"{box}|label").decode(), TIERS[rows[0][1]]

    # ------------------------------------------------------------- deposit
    def _seal(self, holder: str, tier: str, box: str, item_id: str, value: Any) -> tuple[bytes, bytes | None]:
        plain = json.dumps(value).encode()
        aad = f"{box}|{item_id}"
        if tier == "high":
            if self.holder_keys is None:
                raise BoxLocked("high-tier boxes need holder keys (holder_keys=...)")
            inner = _seal_to(self.holder_keys.public_key(holder), plain, aad.encode())
            recovery = None
            if self.recovery_public_key:
                recovery = self._lock_vault(_seal_to(self.recovery_public_key, plain, aad.encode()), aad + "|rec")
            return self._lock_vault(inner, aad), recovery
        n = os.urandom(12)
        return n + AESGCM(self._box_dek(box)).encrypt(n, plain, aad.encode()), None

    def deposit(self, holder: str, tier: str, item: str, value: Any) -> str:
        """Put one value in a box. Returns the item id. High tier needs only the holder's PUBLIC key.
        If the holder is forgotten meanwhile, nothing is saved (HolderForgotten); if their box was recreated
        meanwhile, the value is sealed again with the new box's key."""
        for _ in range(3):
            box = self.ensure_box(holder, tier)
            item_id = self._mac("item", box, item)[:24]
            try:
                wrapped = self._box_row(box)[1]
                blob, recovery = self._seal(holder, tier, box, item_id, value)
            except KeyError:                               # the box was forgotten a moment ago
                continue
            with self.db.transaction() as db:
                db.lock(box)
                row = db.execute("SELECT dek FROM tvb_boxes WHERE box=?", (_b(box),))
                same = row and (bytes(row[0][0]) if row[0][0] is not None else None) == \
                    (bytes(wrapped) if wrapped is not None else None)
                if not same:                               # forgotten (and perhaps recreated) since we sealed
                    continue
                db.upsert("tvb_items", ["box", "item", "blob", "recovery"],
                          (_b(box), bytes.fromhex(item_id), blob, recovery), ["box", "item"])
                self._log(box, "deposit", {"item": item_id}, db=db)
            return item_id
        if self.is_forgotten(holder):
            raise HolderForgotten("this holder was forgotten while the value was being saved; nothing was saved")
        raise BoxLocked("the holder's box kept changing while saving; nothing was saved")

    def store_record(self, source: str, key: Any, record: dict[str, Any], holder: str,
                     levels: dict[str, str]) -> dict[str, str]:
        """Split a record into the holder's normal and high boxes by each field's level.

        One encrypted row per record says which box and item hold each field (the field names are
        inside the encryption, so the database reveals no schema), and each box's log gets one entry.

        If the holder is forgotten while this runs, it retries (recreating the boxes); it never saves items
        sealed with a box key that no longer exists."""
        for attempt in range(3):
            try:
                return self._store_record_once(source, key, record, holder, levels)
            except _BoxChanged:
                if attempt == 2:
                    raise BoxLocked("the holder's boxes kept changing while saving (forgotten meanwhile?)") from None
        raise AssertionError("unreachable")

    def _store_record_once(self, source: str, key: Any, record: dict[str, Any], holder: str,
                           levels: dict[str, str]) -> dict[str, str]:
        rid = self._macb(16, "record", source, key)
        placed: dict[str, str] = {}
        fmap: dict[str, list[str]] = {}
        sealed = []
        used: dict[str, bytes | None] = {}               # box -> the wrapped key its items were sealed with
        for f, v in record.items():
            tier = self.tiers.get(levels.get(f, "protected"), "normal")
            box = self.ensure_box(holder, tier)
            if box not in used:
                try:
                    used[box] = self._box_row(box)[1]
                except KeyError:
                    raise _BoxChanged() from None
            item_id = self._mac("item", box, f"rec\x00{source}\x00{key}\x00{f}")[:24]   # never clashes with deposit()
            try:
                sealed.append((box, item_id, *self._seal(holder, tier, box, item_id, v)))
            except KeyError:                       # the box was forgotten a moment ago
                raise _BoxChanged() from None
            fmap[f] = [box[4:], item_id]
            placed[f] = tier
        new_map = self._lock_vault(_jd(fmap).encode(), f"rec|{rid.hex()}")
        before = self.db.execute("SELECT map FROM tvb_records WHERE record=?", (rid,))
        old_map = self._read_map(rid, before[0][0]) if before else {}
        with self.db.transaction() as db:
            db.lock("rec" + rid.hex())
            locked = sorted({b for b, *_ in sealed} | {"box_" + bx for bx, _ in old_map.values()})
            for box in locked:                     # always the same order, so two writers can't deadlock
                db.lock(box)
            for box, wrapped in used.items():      # forgotten (and perhaps recreated) since we sealed? start over
                row = db.execute("SELECT dek FROM tvb_boxes WHERE box=?", (_b(box),))
                if not row or (bytes(row[0][0]) if row[0][0] is not None else None) != \
                        (bytes(wrapped) if wrapped is not None else None):
                    raise _BoxChanged()
            old = db.execute("SELECT map FROM tvb_records WHERE record=?", (rid,))
            if old:           # a field that is gone from the record is deleted, not left behind
                keep = {tuple(v) for v in fmap.values()}
                gone: dict[str, int] = {}
                for bx, it in self._read_map(rid, old[0][0]).values():
                    if (bx, it) not in keep:
                        db.execute("DELETE FROM tvb_items WHERE box=? AND item=?",
                                   (bytes.fromhex(bx), bytes.fromhex(it)))
                        gone["box_" + bx] = gone.get("box_" + bx, 0) + 1
                for box, n in sorted(gone.items()):
                    self._log(box, "removed", {"record": rid.hex()[:16], "fields": n}, db=db)
            for box, item_id, blob, recovery in sealed:
                db.upsert("tvb_items", ["box", "item", "blob", "recovery"],
                          (_b(box), bytes.fromhex(item_id), blob, recovery), ["box", "item"])
            db.upsert("tvb_records", ["record", "holder", "map"], (rid, self._macb(16, "holder", holder), new_map),
                      ["record"])
            for box in dict.fromkeys(b for b, *_ in sealed):
                n = sum(1 for b, *_ in sealed if b == box)
                self._log(box, "deposit", {"record": rid.hex()[:16], "fields": n}, db=db)
        return placed

    def _read_map(self, rid: bytes, blob: bytes) -> dict[str, list[str]]:
        return json.loads(self._unlock_vault(blob, f"rec|{rid.hex()}"))

    # ---------------------------------------------------------- withdraw
    def fetch_record(self, source: str, key: Any, task: Any = None) -> dict[str, Any] | None:
        """Normal-tier fields come back as values; high-tier fields as `tvbox:` references
        that can only be revealed later, with the holder's key."""
        rid = self._macb(16, "record", source, key)
        rows = self.db.execute("SELECT map FROM tvb_records WHERE record=?", (rid,))
        if not rows:
            return None
        fmap = self._read_map(rid, rows[0][0])
        by_box: dict[str, list[tuple[str, str]]] = {}
        for f, (bx, it) in fmap.items():
            by_box.setdefault("box_" + bx, []).append((f, it))
        values: dict[str, Any] = {}
        for box, fields in by_box.items():
            try:
                tier, dek = self._box_row(box)
            except KeyError:
                continue                                              # forgotten
            if tier == "high":
                values.update({f: f"tvbox:{box}:{it}" for f, it in fields})
                continue
            marks = ",".join("?" for _ in fields)
            found = {bytes(i).hex(): blob for i, blob in self.db.execute(
                f"SELECT item, blob FROM tvb_items WHERE box=? AND item IN ({marks})",
                (_b(box), *[bytes.fromhex(it) for _, it in fields]))}
            aes = AESGCM(self._unlock_vault(dek, f"{box}|dek"))
            got = 0
            for f, it in fields:
                blob = found.get(it)
                if blob is not None:
                    values[f] = json.loads(aes.decrypt(blob[:12], blob[12:], f"{box}|{it}".encode()))
                    got += 1
            self._log(box, "read", {"record": rid.hex()[:16], "fields": got, "task": task})
        out = {f: values[f] for f in fmap if f in values}              # the record's own field order
        return out or None

    def _read_normal(self, box: str, item: str, task: Any) -> Any:
        rows = self.db.execute("SELECT blob FROM tvb_items WHERE box=? AND item=?", (_b(box), bytes.fromhex(item)))
        if not rows:
            raise KeyError("item not found")
        blob = rows[0][0]
        plain = AESGCM(self._box_dek(box)).decrypt(blob[:12], blob[12:], f"{box}|{item}".encode())
        self._log(box, "read", {"item": item, "task": task})
        return json.loads(plain)

    def reveal(self, ref: str, task: Any = None, reason: str = "") -> Any:
        """Open a high-tier item. Needs the vault key AND the holder's private key (maybe with approval)."""
        m = REF_RE.match(ref) if isinstance(ref, str) else None
        if not m:
            raise ValueError("not a box reference")
        box, item = m.groups()
        holder, tier = self._holder_of(box)
        rows = self.db.execute("SELECT blob FROM tvb_items WHERE box=? AND item=?", (_b(box), bytes.fromhex(item)))
        if not rows:
            raise KeyError("item not found (it may have been forgotten)")
        aad = f"{box}|{item}"
        inner = self._unlock_vault(rows[0][0], aad)                  # key 1: the vault's
        private = self._holder_private(holder, box, task, reason)    # key 2: the holder's
        try:
            plain = _open_from(private, inner, aad.encode())
        except Exception as e:  # noqa: BLE001
            self._log(box, "open_failed", {"item": item, "task": task})
            raise BoxLocked("the holder's key didn't open this box") from e
        self._log(box, "reveal", {"item": item, "task": task, "reason": reason})
        return json.loads(plain)

    def _holder_private(self, holder: str, box: str, task: Any, reason: str) -> bytes:
        now = self.clock()
        with self._lock:
            cached = self._open.get(holder)
            if cached and cached[1] > now:
                return cached[0]
            self._open.pop(holder, None)
        if self.holder_keys is None:
            raise BoxLocked("no holder key service configured")
        try:
            key = self.holder_keys.private_key(OpenRequest(holder, box, task, reason))
        except KeyUnavailable as e:
            raise BoxLocked(str(e)) from e
        if not key:
            self._log(box, "open_denied", {"task": task, "reason": reason})
            raise BoxLocked(f"{holder.split(':')[0]} key holder did not allow this box to be opened")
        with self._lock:
            self._open[holder] = (key, now + self.open_ttl)
        self._log(box, "opened", {"task": task, "for_seconds": self.open_ttl})
        return key

    def close_all(self) -> None:
        """Forget every holder key held in memory (call at the end of a task or on shutdown)."""
        with self._lock:
            self._open.clear()

    def recover(self, ref: str, recovery_private_key: bytes) -> Any:
        """Company break-glass: read a high-tier item with the recovery key instead of the holder's."""
        m = REF_RE.match(ref) if isinstance(ref, str) else None
        if not m:
            raise ValueError("not a box reference")
        box, item = m.groups()
        rows = self.db.execute("SELECT recovery FROM tvb_items WHERE box=? AND item=?", (_b(box), bytes.fromhex(item)))
        if not rows or rows[0][0] is None:
            raise BoxLocked("no recovery copy for this item")
        aad = f"{box}|{item}"
        plain = _open_from(recovery_private_key, self._unlock_vault(rows[0][0], aad + "|rec"), aad.encode())
        self._log(box, "recovered", {"item": item})
        return json.loads(plain)

    # ------------------------------------------------------------- admin
    def forget_holder(self, holder: str) -> int:
        """Delete all of one holder's boxes, contents and record index. The per-box logs keep a
        'forgotten' entry (logs hold no values), and a tombstone (a keyed fingerprint, no name) stops new
        boxes being made for them, so a later import or sync can't quietly bring their data back. Call
        unforget_holder() if they genuinely return."""
        fp = self._macb(16, "holder", holder)
        with self._lock:
            self._open.pop(holder, None)
        n = 0
        with self.db.transaction() as db:
            boxes = sorted(bytes(r[0]) for r in db.execute("SELECT box FROM tvb_boxes WHERE holder=?", (fp,)))
            # lock every box id this holder could have (not just existing ones), so nobody creates one meanwhile
            every = sorted({_s(b) for b in boxes} | {self.box_id(holder, t) for t in TIERS})
            for box in every:
                db.lock(box)
            db.upsert("tvb_forgotten", ["holder", "ts"], (self._tomb(holder), self.clock()), ["holder"])
            for box in every:                     # items left behind without a box (e.g. by an older version)
                if not db.execute("SELECT 1 FROM tvb_boxes WHERE box=?", (_b(box),)):
                    n += db.execute("SELECT COUNT(*) FROM tvb_items WHERE box=?", (_b(box),))[0][0]
                    db.execute("DELETE FROM tvb_items WHERE box=?", (_b(box),))
            for box in boxes:
                n += db.execute("SELECT COUNT(*) FROM tvb_items WHERE box=?", (box,))[0][0]
                db.execute("DELETE FROM tvb_items WHERE box=?", (box,))
                db.execute("DELETE FROM tvb_boxes WHERE box=?", (box,))
            db.execute("DELETE FROM tvb_records WHERE holder=?", (fp,))
            for box in boxes:
                self._log(_s(box), "forgotten", {}, db=db)
        if self.db.dialect == "sqlite":
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")      # don't leave deleted pages in the WAL file
        return n

    def _tomb(self, holder: str) -> bytes:
        """The tombstone key: the holder in a standard form, so 'customer:012', 'customer:12 ' and 'customer:12.0'
        (as ids often come out of spreadsheets) are the same forgotten customer."""
        kind, _, ident = holder.partition(":")
        ident = ident.strip()
        if (m := re.fullmatch(r"([+-]?)0*(\d+)(?:\.0*)?", ident)) is not None:
            ident = m.group(1).replace("+", "") + (m.group(2) or "0")
        return self._macb(16, "forgotten", kind.strip().lower(), ident.lower())

    def unforget_holder(self, holder: str) -> bool:
        """Remove a forgotten holder's tombstone so new boxes can be made for them. Their old data stays gone.
        Returns whether there was a tombstone."""
        fp = self._tomb(holder)
        with self.db.transaction() as db:
            found = bool(db.execute("SELECT 1 FROM tvb_forgotten WHERE holder=?", (fp,)))
            db.execute("DELETE FROM tvb_forgotten WHERE holder=?", (fp,))
        return found

    def is_forgotten(self, holder: str) -> bool:
        return bool(self.db.execute("SELECT 1 FROM tvb_forgotten WHERE holder=?", (self._tomb(holder),)))

    def boxes(self) -> list[BoxInfo]:
        rows = self.db.execute("SELECT b.box, b.label, b.tier, b.created, COUNT(i.item) FROM tvb_boxes b "
                               "LEFT JOIN tvb_items i ON i.box = b.box GROUP BY b.box, b.label, b.tier, b.created "
                               "ORDER BY b.created")
        return [BoxInfo(_s(box), self._unlock_vault(label, f"{_s(box)}|label").decode(), TIERS[tier], n, created)
                for box, label, tier, created, n in rows]

    # --------------------------------------------------------------- logs
    def _chain(self, key: bytes, box: str, seq: int, ts: float, event: str, detail: str, prev: bytes) -> bytes:
        body = json.dumps([box, seq, ts, event, detail], separators=(",", ":")).encode()
        return hmac.new(key, prev + body, hashlib.sha256).digest()

    def _log(self, box: str, event: str, detail: dict[str, Any], db: BoxDB | None = None) -> None:
        """Append to the box's log. Each entry is chained to the one before with a keyed MAC, so changing,
        reordering or inserting entries is detectable, and forging them needs the vault key."""
        if db is None:
            with self.db.transaction() as tx:
                self._log(box, event, detail, db=tx)
            return
        db.lock(box)
        last = db.execute("SELECT seq, mac FROM tvb_log WHERE box=? ORDER BY seq DESC LIMIT 1", (_b(box),))
        seq, prev = (last[0][0] + 1, bytes(last[0][1])) if last else (0, ZERO)
        ts, d = round(self.clock(), 3), _jd(detail)
        mac = self._chain(self._subkey(b"box-log"), box, seq, ts, event, d, prev)
        db.execute("INSERT INTO tvb_log (box, seq, ts, event, detail, mac) VALUES (?,?,?,?,?,?)",
                   (_b(box), seq, ts, event, d, mac))

    def log(self, box: str) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT seq, ts, event, detail, mac FROM tvb_log WHERE box=? ORDER BY seq", (_b(box),))
        return [{"seq": s, "ts": t, "event": e, "detail": json.loads(d), "mac": bytes(m).hex()}
                for s, t, e, d, m in rows]

    def verify_log(self, box: str) -> bool:
        """True if the box's log is intact. After `compact_logs`, the chain resumes from the anchor
        recorded (under the MAC) in the 'compacted' entry."""
        rows = self.db.execute("SELECT seq, ts, event, detail, mac FROM tvb_log WHERE box=? ORDER BY seq", (_b(box),))
        if not rows:     # every box starts with a 'created' entry and compaction always leaves one behind
            return not self.db.execute("SELECT 1 FROM tvb_boxes WHERE box=?", (_b(box),))
        key = self._subkey(b"box-log")
        first = rows[0][0]
        prev = ZERO
        if first != 0:
            anchors = [json.loads(d) for _, _, e, d, _ in rows if e == "compacted"]
            match = [a for a in anchors if a.get("through") == first - 1]
            if not match:
                return False
            prev = bytes.fromhex(match[-1]["anchor"])
        for i, (seq, ts, event, detail, mac) in enumerate(rows):
            if seq != first + i:
                return False
            if not hmac.compare_digest(self._chain(key, box, seq, ts, event, detail, prev), bytes(mac)):
                return False
            prev = bytes(mac)
        return True

    def compact_logs(self, older_than_days: float, archive: str | Path | None = None,
                     min_entries: int = 10) -> dict[str, int]:
        """Remove log entries older than N days from every box's log, leaving a 'compacted' entry with
        counts and the chain anchor, so what remains still verifies. If `archive` is given, the removed
        entries are first written there, compressed and encrypted with a key derived from the vault key
        (logs hold no customer values, so compressing them leaks nothing). Boxes with fewer than
        `min_entries` old entries are left alone: the summary would take more room than it saves. Returns counts."""
        cutoff = self.clock() - older_than_days * 86400
        # Only an unbroken run of old entries from the start of each log is removed: if the clock ever
        # went backwards, an old-looking entry after newer ones must not take the newer ones with it.
        plan = {}
        for box, first, last, newer in self.db.execute(
                "SELECT l.box, MIN(l.seq), MAX(l.seq), (SELECT MIN(n.seq) FROM tvb_log n "
                "WHERE n.box = l.box AND n.ts >= ?) FROM tvb_log l GROUP BY l.box", (cutoff,)):
            through = last if newer is None else newer - 1
            if through - first + 1 >= max(1, min_entries):
                plan[bytes(box)] = through
        if not plan:
            return {"boxes": 0, "entries": 0}
        if archive is not None:
            entries = []
            for box, through in plan.items():
                for seq, ts, event, detail, mac in self.db.execute(
                        "SELECT seq, ts, event, detail, mac FROM tvb_log WHERE box=? AND seq<=? ORDER BY seq",
                        (box, through)):
                    entries.append({"box": _s(box), "seq": seq, "ts": ts, "event": event, "detail": detail,
                                    "mac": bytes(mac).hex()})
            write_archive(self, Path(archive), entries)
        removed = 0
        for box, through in plan.items():
            name = _s(box)
            with self.db.transaction() as db:
                db.lock(name)
                rows = db.execute("SELECT seq, ts, event, mac FROM tvb_log WHERE box=? AND seq<=? ORDER BY seq",
                                  (box, through))
                if not rows or any(ts >= cutoff for _, ts, _, _ in rows):
                    continue
                counts: dict[str, int] = {}
                for _, _, event, _ in rows:
                    counts[event] = counts.get(event, 0) + 1
                self._log(name, "compacted", {"through": through, "anchor": bytes(rows[-1][3]).hex(),
                                              "entries": len(rows), "from": rows[0][1], "to": rows[-1][1],
                                              "events": counts}, db=db)
                db.execute("DELETE FROM tvb_log WHERE box=? AND seq<=?", (box, through))
                removed += len(rows)
        if removed and self.db.dialect == "sqlite":
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return {"boxes": len(plan), "entries": removed}

    def migrate(self) -> dict[str, int]:
        """Upgrade a taskvault 0.4 box database in place (see boxes_migrate.py)."""
        from .boxes_migrate import migrate
        return migrate(self)


def _archive_key(store: BoxStore) -> AESGCM:
    return AESGCM(store._subkey(b"log-archive"))


def write_archive(store: BoxStore, path: Path, entries: list[dict[str, Any]]) -> None:
    """Compressed, encrypted archive of log entries. Never overwrites an existing file."""
    data = zlib.compress("\n".join(_jd(e) for e in entries).encode(), 9)
    nonce = os.urandom(12)
    aad = ARCHIVE_MAGIC + store.db.db_id.encode()          # opens only against the database it came from
    blob = ARCHIVE_MAGIC + nonce + _archive_key(store).encrypt(nonce, data, aad)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    owner_only(path)
    with os.fdopen(fd, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())                   # on disk before any log entry is deleted
    if os.name != "nt":
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def read_archive(store: BoxStore, path: str | Path) -> list[dict[str, Any]]:
    """Open an archive written by `compact_logs` and check each box's entries still chain together."""
    raw = Path(path).read_bytes()
    if not raw.startswith(ARCHIVE_MAGIC):
        raise BoxFormatError("not a eurycleia log archive")
    body = raw[len(ARCHIVE_MAGIC):]
    try:
        data = _archive_key(store).decrypt(body[:12], body[12:], ARCHIVE_MAGIC + store.db.db_id.encode())
    except Exception as e:  # noqa: BLE001
        raise KeyUnavailable("this archive can't be opened: it belongs to another box database or vault key, "
                             "or it was modified") from e
    entries = [json.loads(line) for line in zlib.decompress(data).decode().splitlines() if line]
    key = store._subkey(b"box-log")
    last: dict[str, tuple[int, bytes]] = {}
    for e in entries:
        mac = bytes.fromhex(e["mac"])
        prior = last.get(e["box"])
        if prior is not None or e["seq"] == 0:
            prev = prior[1] if prior else ZERO
            if prior and e["seq"] != prior[0] + 1:
                raise BoxFormatError(f"archive entries for {e['box']} are not continuous")
            if not hmac.compare_digest(store._chain(key, e["box"], e["seq"], e["ts"], e["event"], e["detail"], prev),
                                       mac):
                raise BoxFormatError(f"archive entry {e['box']} #{e['seq']} fails its tamper check")
        last[e["box"]] = (e["seq"], mac)
    # the last archived entry of each box must be the anchor the database's 'compacted' entry names
    for box, (seq, mac) in last.items():
        for (detail,) in store.db.execute("SELECT detail FROM tvb_log WHERE box=? AND event='compacted'", (_b(box),)):
            d = json.loads(detail)
            if d.get("through") == seq and d.get("anchor") != mac.hex():
                raise BoxFormatError(f"archive doesn't match this database's log for {box}")
    return entries


class BoxSource:
    """A vault source backed by deposit boxes: `Vault(sources={"crm.customer": BoxSource(store, "crm.customer")})`."""

    def __init__(self, store: BoxStore, source: str):
        self.store, self.source = store, source

    def __call__(self, key: Any) -> dict | None:
        return self.store.fetch_record(self.source, key)


def box_sources(policy: Any, store: BoxStore) -> dict[str, BoxSource]:
    """Sources for every policy source marked `storage: boxes`."""
    return {name: BoxSource(store, name) for name, src in policy.sources.items() if src.storage == "boxes"}
