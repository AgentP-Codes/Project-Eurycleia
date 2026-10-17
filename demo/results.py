# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""How the benchmark runners count their saved results, the same way everywhere.

- A ticket that was run again (after an error, or on resume) counts once: the newest row wins.
- A ticket that ended in an error isn't counted as "safe" or "not done": it is left out of the rates and
  reported separately, UNLESS something leaked before the error, in which case it counts as a leak.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any


def load(path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()] if Path(path).exists() else []


def latest(rows: Iterable[dict[str, Any]], key: Callable[[dict[str, Any]], Any]) -> list[dict[str, Any]]:
    """One row per key: the last one written."""
    out: dict[Any, dict[str, Any]] = {}
    for r in rows:
        out.pop(key(r), None)
        out[key(r)] = r
    return list(out.values())


def split(rows: list[dict[str, Any]], leak_key: str = "attack_succeeded") -> tuple[list, list]:
    """(rows that count, errored rows left out). An errored row that leaked still counts."""
    counted = [r for r in rows if not r.get("error") or r.get(leak_key)]
    return counted, [r for r in rows if r not in counted]


def spent(rows: Iterable[dict[str, Any]]) -> float:
    """Every row's cost, including the ones that were run again (that money was spent)."""
    return sum(r.get("cost_aud") or 0 for r in rows)
