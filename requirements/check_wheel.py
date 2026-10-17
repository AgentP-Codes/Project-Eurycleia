# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Check a built wheel contains every module and data file in eurycleia/ and taskvault/ (0.5.x shipped
without its integrations package, and nothing noticed). Usage: python requirements/check_wheel.py dist/*.whl"""

import sys
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
wanted = {p.relative_to(root).as_posix() for d in ("eurycleia", "taskvault") for p in (root / d).rglob("*")
          if p.is_file() and p.suffix in (".py", ".yaml", ".typed") and "__pycache__" not in p.parts}
bad = 0
for whl in sys.argv[1:]:
    if not whl.endswith(".whl"):
        continue
    names = set(zipfile.ZipFile(whl).namelist())
    missing = sorted(wanted - names)
    note = f", MISSING {missing}" if missing else ""
    print(f"{Path(whl).name}: {len(wanted) - len(missing)}/{len(wanted)} files{note}")
    bad += bool(missing)
sys.exit(1 if bad else 0)
