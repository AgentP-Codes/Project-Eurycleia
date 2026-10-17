# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Write a CycloneDX software bill of materials (SBOM) for a eurycleia release, using only the standard library.

    python requirements/sbom.py requirements/runtime.lock dist/eurycleia-sbom.cdx.json

It lists eurycleia and every library it installs, with exact versions and the checksums from the lock file,
so anyone can see precisely what is inside a release and check it against vulnerability databases.
"""

from __future__ import annotations

import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def parse_lock(text: str) -> list[dict]:
    comps = []
    for block in re.split(r"\n(?=[a-z0-9])", text, flags=re.I):
        m = re.match(r"([A-Za-z0-9_.-]+)==([^\s;\\]+)\s*(?:;\s*([^\\\n]+))?", block)
        if not m:
            continue
        name, version, marker = m.group(1).lower(), m.group(2), (m.group(3) or "").strip()
        hashes = sorted(set(re.findall(r"--hash=sha256:([0-9a-f]{64})", block)))
        comp = {"type": "library", "name": name, "version": version, "purl": f"pkg:pypi/{name}@{version}",
                "bom-ref": f"pkg:pypi/{name}@{version}",
                "hashes": [{"alg": "SHA-256", "content": h} for h in hashes]}
        if marker:
            comp["properties"] = [{"name": "python:environment-marker", "value": marker}]
        comps.append(comp)
    return comps


def build(lock: Path) -> dict:
    sys.path.insert(0, str(ROOT))
    from eurycleia import __version__
    me = f"pkg:pypi/eurycleia@{__version__}"
    comps = parse_lock(lock.read_text())
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "eurycleia requirements/sbom.py"}]},
            "component": {"type": "library", "name": "eurycleia", "version": __version__, "purl": me,
                          "bom-ref": me, "licenses": [{"license": {"id": "AGPL-3.0-only"}}],
                          "supplier": {"name": "AgentP-Codes"}},
        },
        "components": comps,
        "dependencies": [{"ref": me, "dependsOn": [c["bom-ref"] for c in comps]}],
    }


if __name__ == "__main__":
    lock, out = Path(sys.argv[1]), Path(sys.argv[2])
    bom = build(lock)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bom, indent=2) + "\n")
    print(f"SBOM: eurycleia {bom['metadata']['component']['version']} + {len(bom['components'])} libraries -> {out}")
