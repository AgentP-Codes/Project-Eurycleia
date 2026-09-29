# Locked libraries

taskvault needs only two libraries: `cryptography` (the encryption) and `pyyaml` (reading the policy file),
plus what they bring with them. The `.lock` files pin every one to an exact version **and** the SHA-256
checksum of every published file, so `pip install --require-hashes` refuses anything that was swapped or
tampered with, even if the package index were compromised.

| File | What it is |
| --- | --- |
| `runtime.in` / `runtime.lock` | What taskvault installs |
| `ci.in` / `ci.lock` | What the tests and release build install |
| `sbom.py` | Writes the software bill of materials attached to each release |

Install exactly the locked versions:

```bash
pip install --require-hashes -r requirements/runtime.lock
pip install --no-deps taskvault
```

Update the locks (after changing a `.in` file, or to pick up fixes); Dependabot also proposes updates weekly:

```bash
cd requirements
uv pip compile runtime.in --universal --generate-hashes --python-version 3.10 -o runtime.lock
uv pip compile ci.in --universal --generate-hashes --python-version 3.10 -o ci.lock
pip-audit -r runtime.lock --require-hashes --disable-pip --strict
```
