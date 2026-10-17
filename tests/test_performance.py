# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Performance budget: eurycleia must stay light. Generous limits so slow CI machines pass;
typical figures are far lower (about 0.2 ms per task on a laptop)."""

import time

from demo.__main__ import make_vault
from demo.world import World

BUDGET_MS_PER_TASK = 5.0        # read + email + refund, all checks included


def test_overhead_per_task_stays_within_budget():
    world = World()
    vault = make_vault(world)
    n = 300
    t0 = time.perf_counter()
    for _ in range(n):
        task = vault.start_task("support_reply", customer_id=12)
        c = task.read("crm.customer")
        task.act("email.send", to=c["email"], subject="Re", body=f"Hi {c['name']}")
        task.act("payments.refund", card=c["card_number"], amount=1)
    per_task_ms = (time.perf_counter() - t0) / n * 1000
    assert per_task_ms < BUDGET_MS_PER_TASK, f"{per_task_ms:.2f} ms per task"


def test_core_import_is_light():
    import subprocess
    import sys
    code = ("import sys, time; t=time.perf_counter(); import eurycleia; "
            "print(time.perf_counter()-t); print(','.join(sorted(m for m in sys.modules if m.split('.')[0] in "
            "{'anthropic','openai','google','boto3','psycopg','pymongo','crewai'})))")
    root = str(__import__("pathlib").Path(__file__).resolve().parent.parent)     # works from any folder
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                         cwd=root).stdout.split("\n")
    assert float(out[0]) < 2.0, out[0]
    assert out[1] == "", f"optional libraries loaded by 'import eurycleia': {out[1]}"
