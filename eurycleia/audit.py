# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Tamper-evident, hash-chained audit log.

Each entry stores the SHA-256 of the previous entry, so editing, reordering or
deleting any line breaks the chain and `verify()` fails. Raw sensitive values
are never written: only field names, keyed fingerprints and decisions.

The file is created with owner-only permissions and appended to under a lock. The lock is an
operating-system file lock, so several processes (e.g. web-server workers) can share one file:
each entry chains from whatever entry is really last in the file.
Set `fsync=True` to force each entry to disk before the action runs (slower,
but nothing is lost if the machine crashes).

With a `key` (derive one from the vault key with `audit_key`), every entry also carries a keyed MAC, so
rewriting the log needs the key, and a small `<file>.head` record, also keyed, notes the last entry. Cutting
entries off the end, or deleting the head, is then detected too. Someone with file access who kept an old
copy of both files could still roll them back together: ship the log (or the head) to your SIEM or
write-once storage if that matters.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .errors import EurycleiaError

GENESIS = "0" * 64


class AuditError(EurycleiaError):
    pass


def _digest(entry: dict[str, Any]) -> str:
    body = json.dumps({k: v for k, v in entry.items() if k not in ("hash", "mac")}, sort_keys=True,
                      separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def audit_key(provider: Any) -> bytes:
    """The audit log's own key, derived from the vault's key provider (LocalKeyProvider, KMSKeyProvider)."""
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(SHA256(), 32, salt=None, info=b"taskvault-audit-log").derive(provider.data_key())


def _mac(key: bytes, *parts: Any) -> str:
    return hmac.new(key, "\x00".join(str(p) for p in parts).encode(), hashlib.sha256).hexdigest()


def private_file(path: str | Path) -> Path:
    """Create `path` (and its folder) with owner-only permissions if it doesn't exist."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))
        owner_only(path)
    return path


def owner_only(path: str | Path, required: bool = False) -> None:
    """Make a file (or folder) readable and writable by the current user only.

    POSIX: mode 0600 (0700 for a folder). Windows ignores those modes, so there the file's access list is
    replaced with one entry for the current user (icacls: inherited entries removed, full control granted),
    which keeps other accounts on the same computer out. If that fails, a warning is logged, or, with
    `required` (key files), the error is raised."""
    path = Path(path)
    if not _WINDOWS:
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
        return
    import logging
    try:
        sid = _current_sid()
        grant = f"*{sid}:(OI)(CI)F" if path.is_dir() else f"*{sid}:F"
        done = _run(["icacls", str(path), "/inheritance:r", "/grant:r", grant])
        if done.returncode != 0:
            raise OSError(done.stdout.strip() or f"icacls exited with {done.returncode}")
    except (OSError, ValueError) as e:
        if required:
            raise OSError(f"couldn't make {path.name} private to this user: {e}") from e
        logging.getLogger("eurycleia").warning("couldn't make %s private to this user: %s", path.name, e)


def _current_sid() -> str:
    """The Windows security id of the current user (from `whoami /user`)."""
    out = _run(["whoami", "/user", "/fo", "csv", "/nh"]).stdout.strip()
    sid = out.rsplit(",", 1)[-1].strip().strip('"')
    if not sid.startswith("S-1-"):
        raise ValueError("couldn't find the current user's security id")
    return sid


def _run(cmd: list[str]):  # pragma: no cover - Windows only (tests substitute a stand-in)
    import subprocess
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)


class AuditLog:
    """Hash-chained, append-only log.

    With a file, the file is the record and `entries` holds only the most recent `keep` entries (10,000 by
    default), so a long-running server doesn't grow without end; pass `keep=None` to load everything
    (e.g. to read or report on a whole log). Without a file, everything stays in memory.
    """

    def __init__(self, path: str | Path | None = None, fsync: bool = False, keep: int | None = 10_000,
                 key: bytes | None = None):
        existed = bool(path) and Path(path).exists()
        self.path = private_file(Path(path).resolve()) if path else None   # absolute: survives chdir
        if existed and _WINDOWS:
            owner_only(self.path)          # a log from before 0.6 was created without an access list on Windows
        self.fsync = fsync
        if key is not None and len(key) < 16:
            raise ValueError("the audit key must be at least 16 bytes (use audit_key(provider))")
        self.key = key
        self._head_mem: dict[str, Any] | None = None
        self.keep = keep if self.path else None
        self._lock = threading.Lock()
        self.entries: list[dict[str, Any]] = []
        if self.path:
            for _, entry in _read_entries(self.path):
                self.entries.append(entry)
                self._trim()

    def _trim(self) -> None:
        if self.keep is not None and len(self.entries) > self.keep + self.keep // 10:
            del self.entries[:len(self.entries) - self.keep]

    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            fields.pop("mac", None)
            if not self.path:
                entry = {"seq": len(self.entries), "ts": round(time.time(), 3), "event": event,
                         **fields, "prev": self.head}
                entry["hash"] = _digest(entry)
                if self.key:
                    entry["mac"] = _mac(self.key, "entry", entry["hash"])
                    keyed_from = self._head_mem["keyed_from"] if self._head_mem else entry["seq"]
                    self._head_mem = self._head(entry, keyed_from)
                self.entries.append(entry)
                return entry
            with self.path.open("a+b") as f, _file_lock(f):
                last = _last_line(f)                      # another process may have written since
                seq, prev = (last["seq"] + 1, last["hash"]) if last else (0, GENESIS)
                keyed_from = self._keyed_from(last) if self.key else None
                entry = {"seq": seq, "ts": round(time.time(), 3), "event": event, **fields, "prev": prev}
                entry["hash"] = _digest(entry)
                if self.key:
                    entry["mac"] = _mac(self.key, "entry", entry["hash"])
                f.seek(0, os.SEEK_END)
                f.write((json.dumps(entry, sort_keys=True, default=str) + "\n").encode())
                f.flush()
                if self.fsync:
                    os.fsync(f.fileno())
                if self.key:
                    self._write_head(self._head(entry, keyed_from))
            self.entries.append(entry)
            self._trim()
            return entry

    # ------------------------------------------------------------ keyed end-of-log record
    @property
    def head_path(self) -> Path | None:
        return self.path.with_name(self.path.name + ".head") if self.path else None

    def _head(self, entry: dict[str, Any], keyed_from: int) -> dict[str, Any]:
        head = {"seq": entry["seq"], "hash": entry["hash"], "keyed_from": keyed_from}
        head["mac"] = _mac(self.key, "head", head["seq"], head["hash"], keyed_from)
        return head

    def _read_head(self) -> dict[str, Any] | None:
        """The end-of-log record, checked against the key; None if there isn't one. Raises if it was altered."""
        if not self.path:
            return self._head_mem
        try:
            head = json.loads(self.head_path.read_text())
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as e:
            raise AuditError(f"{self.head_path} is damaged") from e
        ok = isinstance(head, dict) and all(k in head for k in ("seq", "hash", "keyed_from", "mac")) and \
            hmac.compare_digest(str(head["mac"]), _mac(self.key, "head", head["seq"], head["hash"], head["keyed_from"]))
        if not ok:
            raise AuditError(f"{self.head_path} doesn't match the audit key: it was altered, or this is a "
                             "different key")
        return head

    def _ends_at_head(self, last: dict[str, Any] | None, head: dict[str, Any]) -> bool:
        """The log ends where the head says, or one keyed entry later: a crash between writing an entry and
        updating the head. That entry's MAC proves the vault wrote it, so it's accepted."""
        if last is None:
            return False
        if last.get("seq") == head["seq"] and last.get("hash") == head["hash"]:
            return True
        return (last.get("seq") == head["seq"] + 1 and last.get("prev") == head["hash"]
                and hmac.compare_digest(str(last.get("mac", "")), _mac(self.key, "entry", last.get("hash"))))

    def _keyed_from(self, last: dict[str, Any] | None) -> int:
        head = self._read_head()
        if head is None:
            if last is None:
                return 0                                 # a new log: keyed from its first entry
            # Never start keying by itself on a log that already has entries: that is also exactly what a log
            # looks like after someone stripped the MACs and deleted the head record.
            raise AuditError(f"{self.path} has entries but no end-of-log record ({self.head_path.name}). If this "
                             "is an older log written without a key, check it and protect it from here on with "
                             "`eurycleia audit verify FILE` then `eurycleia audit seal FILE --key KEYFILE`. "
                             "Otherwise the record was deleted: keep the file for investigation and start a new log")
        if not self._ends_at_head(last, head):
            raise AuditError(f"{self.path}: the log doesn't end where {self.head_path.name} says it does: entries "
                             "were cut off, or added without the key (for example by a eurycleia started without "
                             "--key). Not writing to it; keep it for investigation and start a new log")
        return head["keyed_from"]

    def _write_head(self, head: dict[str, Any]) -> None:
        tmp = self.head_path.with_name(self.head_path.name + ".tmp")
        # the head holds only a position, a hash and a MAC: nothing secret, so no access list is needed
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(head))
            f.flush()
            if self.fsync:
                os.fsync(f.fileno())
        os.replace(tmp, self.head_path)

    def verify(self) -> bool:
        """True if the whole chain is intact (for a file: the whole file, whoever wrote to it), and, with a key,
        every keyed entry's MAC and the end-of-log record check out."""
        return self.problem() is None

    def problem(self) -> str | None:
        """What's wrong with the log, in words, or None if it checks out. With a file, the log and its
        end-of-log record are read under the same lock, so writers don't cause false alarms."""
        return self._check()[1]

    def first_bad_entry(self) -> int | None:
        """Index of the first entry that breaks the chain (or, with a key, has a missing or wrong MAC from where
        keying started), or None if it's intact."""
        return self._check()[0]

    def _check(self) -> tuple[int | None, str | None]:
        if not self.path:
            with self._lock:
                return self._check_entries(iter(list(self.entries)), lambda: self._head_mem)
        with self.path.open("a+b") as f, _file_lock(f):
            return self._check_entries((e for _, e in _entries_in(f, self.path)), self._read_head)

    def _check_entries(self, entries, read_head) -> tuple[int | None, str | None]:
        head = None
        head_problem = None
        if self.key:
            try:
                head = read_head()
            except AuditError as e:
                head_problem = str(e)
        keyed_from = head["keyed_from"] if head else None
        prev, last, i = GENESIS, None, -1
        for i, entry in enumerate(entries):
            if entry.get("seq") != i or entry.get("prev") != prev or _digest(entry) != entry.get("hash"):
                return i, f"entry {i} was changed, removed or added without the key"
            # with a key: from where keying started, every entry needs a valid MAC; any MAC present must be valid
            must = self.key is not None and keyed_from is not None and i >= keyed_from
            if self.key and (must or "mac" in entry) and \
                    not hmac.compare_digest(str(entry.get("mac", "")), _mac(self.key, "entry", entry["hash"])):
                return i, f"entry {i} was changed, removed or added without the key"
            prev, last = entry["hash"], entry
        if not self.key:
            return None, None
        if head_problem:
            return None, head_problem
        if head is None:
            return None, (None if last is None else "the end-of-log record is missing (entries may have been cut "
                                                    "off; an older log needs `eurycleia audit seal` once)")
        if not self._ends_at_head(last, head):
            return None, "the log doesn't end where the end-of-log record says (entries were cut off or added)"
        return None, None

    def seal(self) -> dict[str, Any] | None:
        """Start protecting an existing log that was written without a key (never one that has held a keyed
        entry). Only seal a log you know was never keyed: someone who removed every MAC and the end-of-log record
        could make a keyed log look like an old unkeyed one. After checking its chain, write the
        keyed end-of-log record for its current last entry. From then on every entry needs the key, and the
        older entries can't be cut off or rewritten either without it being detected (their content was only
        protected by the plain chain before this). Returns the record written, or None for an empty log."""
        if not (self.key and self.path):
            raise ValueError("seal needs a file and a key")
        with self.path.open("a+b") as f, _file_lock(f):
            if self._read_head() is not None:
                raise AuditError(f"{self.path} is already protected by a key")
            prev, last = GENESIS, None
            for i, (_, entry) in enumerate(_entries_in(f, self.path)):
                if entry.get("seq") != i or entry.get("prev") != prev or _digest(entry) != entry.get("hash"):
                    raise AuditError(f"entry {i} breaks the chain; not sealing a damaged log")
                if "mac" in entry:
                    # it was written with a key, so its end-of-log record was removed: sealing it again would
                    # hide entries cut off the end
                    raise AuditError(f"entry {i} was written with a key, so this log's end-of-log record was "
                                     "deleted; not sealing it. Keep it for investigation and start a new log")
                prev, last = entry["hash"], entry
            if last is None:
                return None
            head = self._head(last, last["seq"] + 1)
            self._write_head(head)
            return head

    @staticmethod
    def repair(path: str | Path) -> Path | None:
        """Set aside an unfinished LAST line (left by a crash mid-write) so the log can be used again.

        Only the final line is ever moved, into `<file>.torn-<time>`; damage anywhere else is left
        alone, because that isn't what a crash looks like. Returns the side file, or None.
        """
        path = Path(path)
        data = path.read_bytes()
        body, sep, tail = data.rstrip(b"\n").rpartition(b"\n")
        last = tail if sep else data.rstrip(b"\n")
        try:
            json.loads(last)
            AuditLog(path)                                # raises if the damage is anywhere else
            return None                                   # last line is fine: nothing to repair
        except json.JSONDecodeError:
            pass
        side = path.with_name(f"{path.name}.torn-{int(time.time())}")
        side.write_bytes(last)
        with path.open("r+b") as f:
            f.truncate(len(body) + len(sep) if sep else 0)
        AuditLog(path)                                    # the rest must now load cleanly
        return side

    def decisions(self, decision: str) -> list[dict[str, Any]]:
        return [e for e in self.entries if e.get("decision") == decision]


def _last_line(f) -> dict[str, Any] | None:
    """The last complete entry in an open binary file, reading backwards from the end."""
    f.seek(0, os.SEEK_END)
    end = f.tell()
    if end == 0:
        return None
    chunk, pos, data = 65536, end, b""
    while pos > 0:
        step = min(chunk, pos)
        pos -= step
        f.seek(pos)
        data = f.read(step) + data
        lines = data.rstrip(b"\n").split(b"\n")
        if len(lines) > 1 or pos == 0:
            try:
                return json.loads(lines[-1])
            except json.JSONDecodeError as e:
                raise AuditError(f"the last line of {f.name} is not valid JSON; the log may be damaged") from e
    return None


def _read_entries(path: Path):
    """Every entry in an audit file, streamed line by line under the file lock (never a half-written line,
    and never the whole file in memory at once)."""
    with path.open("a+b") as f, _file_lock(f):
        yield from _entries_in(f, path)


def _entries_in(f, path: Path):
    """Every entry in an open (and locked) audit file."""
    f.seek(0)
    n, pending = 0, None
    for raw in f:
        n += 1
        if pending is not None:
            yield _parse(path, *pending, last=False)
            pending = None
        if raw.strip():
            pending = (n, raw)
    if pending is not None:
        yield _parse(path, *pending, last=True)


def _parse(path: Path, n: int, raw: bytes, last: bool) -> tuple[int, dict[str, Any]]:
    try:
        return n, json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        hint = (" If the machine crashed while writing, run `eurycleia audit repair` to set the "
                "unfinished last line aside." if last else "")
        raise AuditError(f"{path}:{n} is not valid JSON; the log may be damaged.{hint}") from e


_WINDOWS = os.name == "nt"


def _msvcrt():  # pragma: no cover - Windows only (tests substitute a stand-in)
    import msvcrt
    return msvcrt


def _rewind(f) -> None:
    """Put the OS file position at 0. `f.seek(0)` alone isn't enough: when position 0 is still in its read
    buffer, Python skips the real seek, and Windows locks and unlocks at the OS position."""
    if f.writable():
        f.flush()
    f.seek(0)
    os.lseek(f.fileno(), 0, os.SEEK_SET)


class _file_lock:
    """Exclusive OS-level lock on an open file, across processes (POSIX flock / Windows byte-range locking)."""

    def __init__(self, f):
        self.f = f

    def __enter__(self):
        if _WINDOWS:
            ms = _msvcrt()
            _rewind(self.f)
            while True:
                try:
                    ms.locking(self.f.fileno(), ms.LK_LOCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
        else:
            import fcntl
            fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if _WINDOWS:
                ms = _msvcrt()
                _rewind(self.f)                 # unlock exactly the byte we locked
                ms.locking(self.f.fileno(), ms.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        except OSError:
            if exc_type is None:
                raise
            # an error is already on its way (e.g. a damaged log): report that one, not the unlock;
            # closing the file releases the lock anyway
        return False
