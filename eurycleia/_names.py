# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Eurycleia was called taskvault before 0.6. Settings, folders and files under the old name keep working:
the new name is used when it's there, the old one otherwise."""

from __future__ import annotations

import os
from pathlib import Path

OLD = "taskvault"
MARKS = ("--eurycleia-connected", "--taskvault-connected")      # set by `connect` in a wrapped server's arguments


def setting(name: str, default: str | None = None) -> str | None:
    """EURYCLEIA_<name>, else the old TASKVAULT_<name>, else `default`."""
    return os.environ.get(f"EURYCLEIA_{name}") or os.environ.get(f"TASKVAULT_{name}") or default


def _pick(new: Path, old: Path) -> Path:
    return old if old.exists() and not new.exists() else new


def home_dir() -> Path:
    """Where `connect`, `api` and the audit log keep their files: ~/.eurycleia (or ~/.taskvault if only that exists)."""
    explicit = setting("HOME")
    if explicit:
        return Path(explicit)
    return _pick(Path.home() / ".eurycleia", Path.home() / ".taskvault")


def local(new: str, old: str) -> str:
    """A file or folder in the current directory: `new`, unless only the old name exists."""
    return str(_pick(Path(new), Path(old)))
