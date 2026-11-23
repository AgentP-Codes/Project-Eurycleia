# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""AgentDojo as an Azure job: the same run as run_live.py, set by environment variables instead of a command line,
so it runs in the cloud with nothing left on your computer (./setup.sh bench in deploy/azure).

    BENCH_MODEL       the Azure OpenAI deployment (default: EURYCLEIA_MODEL, the live test's model)
    BENCH_ATTACK      important_instructions (default), tool_knowledge, ...
    BENCH_SAMPLE      share of attack pairs, e.g. 0.25 (default); 1 = all
    BENCH_BUDGET_AUD  stop when the model has cost this much (default 10)
    BENCH_SUITES      e.g. "banking slack" (default: all four)
    BENCH_MODES       e.g. "none strict" (default)
    BENCH_PRICE_IN / BENCH_PRICE_OUT   US$ per million tokens, for a model demo/pricing.py doesn't list

It signs in to Azure OpenAI as the job's own identity (no key). Results go to /data/bench/, the live test's file
share: a run that stops (timeout, budget) carries on where it stopped when started again with the same settings.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_live  # noqa: E402


def settings(env: dict[str, str]) -> tuple[list[str], Path]:
    model = env.get("BENCH_MODEL") or env.get("EURYCLEIA_MODEL") or "gpt-5-mini"
    attack = env.get("BENCH_ATTACK") or "important_instructions"
    sample = env.get("BENCH_SAMPLE") or "0.25"
    budget = env.get("BENCH_BUDGET_AUD") or "10"
    for name, value, rx in (("BENCH_MODEL", model, r"[A-Za-z0-9._-]{1,64}"),
                            ("BENCH_ATTACK", attack, r"[a-z_]{1,64}"),
                            ("BENCH_SAMPLE", sample, r"(?:0?\.\d+|1(?:\.0+)?)"),
                            ("BENCH_BUDGET_AUD", budget, r"\d{1,3}(?:\.\d+)?")):
        if not re.fullmatch(rx, value):
            raise SystemExit(f"{name} has an unexpected value: {value!r}")
    folder = Path(env.get("EURYCLEIA_DATA") or "/data") / "bench"
    folder.mkdir(parents=True, exist_ok=True)
    out = folder / f"{model}-{attack}-{sample}.jsonl"
    argv = ["--provider", "azure", "--model", model, "--attack", attack, "--sample", sample,
            "--budget-aud", budget, "--out", str(out)]
    for suite in (env.get("BENCH_SUITES") or "").split():
        argv += ["--suite", suite]
    for mode in (env.get("BENCH_MODES") or "").split():
        argv += ["--mode", mode]
    if env.get("BENCH_PRICE_IN") and env.get("BENCH_PRICE_OUT"):
        argv += ["--price-in", env["BENCH_PRICE_IN"], "--price-out", env["BENCH_PRICE_OUT"]]
    return argv, out


def main() -> int:
    argv, out = settings(dict(os.environ))
    print(f"AgentDojo: {' '.join(argv)}", flush=True)
    sys.argv = ["run_live.py", *argv]
    code = run_live.main()
    import contextlib
    import io
    summary = io.StringIO()
    with contextlib.redirect_stdout(summary):
        run_live.summarize(out)
    out.with_suffix(".summary.txt").write_text(summary.getvalue(), encoding="utf-8")
    print(f"\nresults: {out}\nsummary: {out.with_suffix('.summary.txt')}", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
