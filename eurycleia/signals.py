# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Signals with Eumaeus (decoys for AI agents) on the same computer.

Once linked (`eumaeus link eurycleia`), the two share a secret key and each writes what the other should know to
its own signals.jsonl, one signed line per signal, and reads the other's:

  lockdown            (Eumaeus) a decoy was used: an agent here has been tricked. Every outgoing action, in every
                      task, is refused until a person clears it (`eurycleia lockdown clear`, or `eumaeus clear`)
  clear               a person has looked, and lifted the lockdown
  connector_changed   (Eurycleia) a connector's tools changed since they were approved, and the change is held
  untrusted_read      (Eurycleia) a task read outside content (reserved; not sent yet)

A signal with a wrong or missing signature is ignored, so a connector or an agent can't start or lift a
lockdown without the key. Not linked, none of this does anything.

The format (version 1) is fixed and shared with Eumaeus, which implements it separately:

  {"v": 1, "from": "eurycleia", "kind": "...", "at": <unix time>, "id": "<random>", ...text fields...,
   "mac": "<hex HMAC-SHA256, with the shared key, of the JSON of every other field: sorted keys, no spaces, UTF-8>"}
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

VERSION = 1
KINDS = {"lockdown", "clear", "untrusted_read", "connector_changed"}
MAX_FILE = 5_000_000


def canonical(signal: dict[str, Any]) -> bytes:
    return json.dumps({k: v for k, v in signal.items() if k != "mac"}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def valid(signal: Any, key: bytes) -> bool:
    if not isinstance(signal, dict) or signal.get("v") != VERSION or signal.get("kind") not in KINDS:
        return False
    mac = signal.get("mac")
    if not isinstance(mac, str) or not isinstance(signal.get("at"), (int, float)):
        return False
    return hmac.compare_digest(mac, hmac.new(key, canonical(signal), hashlib.sha256).hexdigest())


class Channel:
    """Eurycleia's side of the link with Eumaeus. Does nothing unless linked."""

    def __init__(self, home: str | Path | None = None):
        if home is None:
            from ._names import home_dir
            home = home_dir()
        self.home = Path(home)
        self.key: bytes | None = None
        self.peer_home: Path | None = None
        self._lock = threading.Lock()
        self._cache: dict[Path, tuple[int, int, list[dict[str, Any]]]] = {}
        try:
            info = json.loads((self.home / "link.json").read_text(encoding="utf-8"))
            key = bytes.fromhex((self.home / "link.key").read_text(encoding="utf-8").strip())
            if info.get("peer") == "eumaeus" and len(key) == 32:
                self.key, self.peer_home = key, Path(info["peer_home"])
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            pass

    @property
    def linked(self) -> bool:
        return self.key is not None and self.peer_home is not None

    def send(self, kind: str, **fields: Any) -> dict[str, Any] | None:
        if not self.linked or kind not in KINDS:
            return None
        body = {"v": VERSION, "from": "eurycleia", "kind": kind, "at": round(time.time(), 6),
                "id": secrets.token_hex(8), **{k: str(v)[:300] for k, v in fields.items()}}
        signal = {**body, "mac": hmac.new(self.key, canonical(body), hashlib.sha256).hexdigest()}
        path = self.home / "signals.jsonl"
        with self._lock:
            try:
                if path.exists() and path.stat().st_size > MAX_FILE:
                    keep = path.read_text(encoding="utf-8").splitlines()[-2000:]
                    path.write_text("\n".join(keep) + "\n", encoding="utf-8")
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps(signal, ensure_ascii=False) + "\n")
            except OSError:
                return None
        return signal

    def _read(self, path: Path) -> list[dict[str, Any]]:
        try:
            st = path.stat()
        except OSError:
            return []
        cached = self._cache.get(path)
        if cached and cached[:2] == (st.st_mtime_ns, st.st_size):
            return cached[2]
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-5000:]
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                s = json.loads(line)
            except ValueError:
                continue
            if self.key is not None and valid(s, self.key):
                out.append(s)
        self._cache[path] = (st.st_mtime_ns, st.st_size, out)
        return out

    def signals(self) -> list[dict[str, Any]]:
        if not self.linked:
            return []
        return sorted(self._read(self.home / "signals.jsonl") + self._read(self.peer_home / "signals.jsonl"),
                      key=lambda s: (s["at"], s["kind"] == "clear"))       # a clear wins a tie

    def lockdown(self) -> dict[str, Any] | None:
        """The lockdown in force (the newest lockdown-or-clear is a lockdown), or None."""
        last = None
        for s in self.signals():
            if s["kind"] in ("lockdown", "clear"):
                last = s
        return last if last is not None and last["kind"] == "lockdown" else None
