# Contributing

Thanks for helping. Issues, bug reports and pull requests are all welcome.

## Setup

```bash
pip install -e ".[dev]"
pytest
ruff check .
python -m demo && python -m demo.bench
```

## Guidelines

- **Every security rule needs a test that tries to break it.** Add attacks to `tests/` or to the attack suite in `taskvault/attacks.py`.
- **Fail closed.** When unsure, block and log.
- **Never log raw sensitive values.** Use `vault.fp(value)` for correlation.
- **Keep the core dependency-light.** No vendor SDKs: AI providers use the built-in client (`taskvault/webclient.py`); anything else goes behind an optional extra.
- **New connectors** take an injectable transport and ship with tests against fake responses. Validate every identifier and escape every key.
- If a change affects a guarantee, update [docs/threat-model.md](docs/threat-model.md) in the same PR.

## Licence of contributions

The taskvault core is licensed under AGPL-3.0-only and the adapters in `adapters/` under Apache-2.0 (see [NOTICE](NOTICE)). By opening a pull request, you agree that your contribution is licensed under the licence of the part of the project it changes, and that AgentP-Codes may also license it under other terms. If you can't agree to that, please open an issue to discuss the change instead.
