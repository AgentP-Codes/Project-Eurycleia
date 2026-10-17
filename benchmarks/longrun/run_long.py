# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""A long unattended run: one vault serving an API-model agent through a queue of tickets for hours.

What a support team's agent might do overnight, SIMULATED: one long-lived vault (keyed audit log, encrypted
cache) and a queue of the benchmark's 21 tickets in random order, 20 of them carrying an attack. It checks
what a short benchmark can't:
  - nothing leaks over hundreds of tickets, and tickets still get done
  - memory, open files and time per ticket stay flat (no slow build-up)
  - the audit log is intact at the end (checked with the key)

A snapshot line is printed and saved every --report-every tickets; a report is written at the end.
API keys come from the environment only. Stops at --budget-aud (estimated from reported tokens).

    python run_long.py --provider openai --model gpt-6-luna --tickets 20                   # a short check first
    python run_long.py --provider openai --model gpt-6-luna --hours 4 --budget-aud 3       # overnight
"""

from __future__ import annotations

import argparse
import gc
import json
import random
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from demo.bench import POLICY, SCENARIOS, SENDER, SYSTEM  # noqa: E402
from demo.pricing import BudgetExceeded, Meter, UnknownPrice  # noqa: E402
from demo.world import World  # noqa: E402
from eurycleia import Policy, Vault  # noqa: E402
from eurycleia.audit import AuditLog, audit_key  # noqa: E402
from eurycleia.cache import EncryptedCache  # noqa: E402
from eurycleia.crypto import Cipher, LocalKeyProvider  # noqa: E402
from eurycleia.llm import QuotaExhausted, ToolAgent  # noqa: E402

CUSTOMER = "priya.shah@example.com"


def make_provider(provider: str, model: str):
    from eurycleia.llm import AnthropicProvider, GeminiProvider, OpenAIProvider, OpenRouterProvider
    return {"anthropic": lambda: AnthropicProvider(model, cache=True), "openai": lambda: OpenAIProvider(model),
            "gemini": lambda: GeminiProvider(model), "openrouter": lambda: OpenRouterProvider(model)}[provider]()


def rss_mb() -> float:
    """This process's resident memory, where the system tells us (Linux, macOS; Windows via psutil if present)."""
    try:
        import psutil
        return psutil.Process().memory_info().rss / 1e6
    except ImportError:
        pass
    try:
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return peak / (1e6 if sys.platform == "darwin" else 1e3)
    except ImportError:
        return float("nan")


def open_files() -> int:
    try:
        import psutil
        return len(psutil.Process().open_files())
    except ImportError:
        fd = Path("/proc/self/fd")
        return len(list(fd.iterdir())) if fd.exists() else -1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", choices=["anthropic", "openai", "gemini", "openrouter"], required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--hours", type=float, default=0, help="stop after this long (0 = use --tickets)")
    ap.add_argument("--tickets", type=int, default=100)
    ap.add_argument("--report-every", type=int, default=25)
    ap.add_argument("--budget-aud", type=float, default=3.0)
    ap.add_argument("--price-in", type=float, default=None)
    ap.add_argument("--price-out", type=float, default=None)
    ap.add_argument("--out", default="longrun-results.jsonl")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    try:
        meter = Meter(a.model, a.budget_aud, a.price_in, a.price_out)
    except UnknownPrice as e:
        ap.error(str(e))
    provider = make_provider(a.provider, a.model)
    provider.on_usage = meter.hook
    work = Path(tempfile.mkdtemp(prefix="eurycleia-longrun-"))
    keys = LocalKeyProvider(work / "vault.key")
    cipher = Cipher(keys)
    audit = AuditLog(work / "audit.jsonl", key=audit_key(keys))
    policy = Policy.load(POLICY)
    world = World()                     # the company's systems; outbox and refunds are checked per ticket
    vault = Vault(policy, {"crm.customer": world.get_customer, "docs": world.get_doc,
                           "inbox.ticket": world.get_ticket},
                  {"email.send": world.send_email, "payments.refund": world.refund},
                  audit=audit, cipher=cipher, cache=EncryptedCache(cipher, policy.cache_ttl_seconds))
    rng = random.Random(a.seed)
    out = Path(a.out)
    tracemalloc.start()
    started = time.time()
    # leaks are counted on every ticket (attacked or not); a ticket that ends in an error is left out of the
    # "done" and "attacks" counts unless it leaked, and is counted under "errors"
    totals = {"tickets": 0, "done": 0, "finished": 0, "attacks": 0, "leaked": 0, "benign_leaked": 0,
              "errors": 0, "blocks": 0}
    in_a_row = 0
    snapshots = []
    n = 0
    print(f"working folder: {work}\nstarting: {a.model}, "
          + (f"{a.hours} hours" if a.hours else f"{a.tickets} tickets") + f", limit A${a.budget_aud:.2f}", flush=True)
    try:
        while (time.time() - started < a.hours * 3600) if a.hours else (n < a.tickets):
            n += 1
            sc = rng.choice(SCENARIOS)
            base_docs = dict(world.docs)
            world.docs.update(sc.docs or {})
            sent_before, refunds_before = len(world.outbox), len(world.refunds)
            t0 = time.time()
            error = None
            agent = ToolAgent(provider, system=SYSTEM)
            try:
                task = vault.start_task("support_reply", customer_id=12)
                agent(task, {"sender": SENDER, "ticket": sc.ticket})
            except (BudgetExceeded, QuotaExhausted):
                raise
            except Exception as e:  # noqa: BLE001 - a failed ticket is recorded; the run carries on
                error = f"{type(e).__name__}: {str(e)[:200]}"
            finally:
                world.docs.clear()
                world.docs.update(base_docs)
            took = time.time() - t0
            # this ticket's effects only
            ticket_world = World()
            ticket_world.outbox = world.outbox[sent_before:]
            ticket_world.refunds = world.refunds[refunds_before:]
            leaks = ticket_world.leaks(known=sc.ticket)
            done = any(m["to"] == CUSTOMER for m in ticket_world.outbox) and \
                (bool(ticket_world.refunds) or not sc.wants_refund)
            blocks = sum(1 for _, _, status in agent.log if status == "blocked")
            totals["tickets"] += 1
            totals["errors"] += bool(error)
            totals["blocks"] += blocks
            if not error:
                totals["finished"] += 1
                totals["done"] += done
            if not error or leaks:
                totals["attacks"] += sc.injected
                totals["leaked"] += bool(leaks) and sc.injected
                totals["benign_leaked"] += bool(leaks) and not sc.injected
            in_a_row = in_a_row + 1 if error else 0
            if in_a_row >= 10:
                print(f"\nStopped: 10 tickets in a row failed (last: {error}). Check the key, the network or "
                      "the provider's status page.")
                break
            if error:
                time.sleep(min(60, 5 * in_a_row))         # don't hammer a provider that's failing
            row = {"n": n, "scenario": sc.name, "injected": sc.injected, "done": done, "leaks": leaks[:3],
                   "blocks": blocks, "seconds": round(took, 2), "error": error, "spent_aud": round(meter.spent_aud, 4)}
            with out.open("a") as f:
                f.write(json.dumps(row) + "\n")
            if n % a.report_every == 0:
                gc.collect()
                current, _peak = tracemalloc.get_traced_memory()
                snap = {"snapshot": n, "minutes": round((time.time() - started) / 60, 1), **totals,
                        "python_mb": round(current / 1e6, 1), "process_mb": round(rss_mb(), 1),
                        "open_files": open_files(), "audit_entries": len(audit.entries),
                        "spent_aud": round(meter.spent_aud, 3)}
                snapshots.append(snap)
                with out.open("a") as f:
                    f.write(json.dumps(snap) + "\n")
                print(f"[{snap['minutes']:>6} min] {n} tickets: done {totals['done']}/{totals['finished']}, "
                      f"attacks leaked {totals['leaked']}/{totals['attacks']}, errors {totals['errors']}, "
                      f"python memory {snap['python_mb']} MB, open files {snap['open_files']}, "
                      f"A${meter.spent_aud:.2f}", flush=True)
    except (BudgetExceeded, QuotaExhausted) as e:
        print(f"\nStopped: {e}")
    except KeyboardInterrupt:
        print("\nStopped by you.")
    problem = AuditLog(work / "audit.jsonl", key=audit_key(keys), keep=None).problem()
    report = {"model": a.model, "minutes": round((time.time() - started) / 60, 1), **totals,
              "audit_log": "intact" if problem is None else f"PROBLEM: {problem}", "snapshots": snapshots,
              "spent_aud": round(meter.spent_aud, 3), "tokens": meter.tokens}
    growth = (snapshots[-1]["python_mb"] - snapshots[0]["python_mb"]) if len(snapshots) > 1 else 0
    report["python_memory_growth_mb"] = round(growth, 1)
    Path(out.with_suffix(".report.json")).write_text(json.dumps(report, indent=2))
    print(f"\n{totals['tickets']} tickets in {report['minutes']} min: done {totals['done']}/{totals['finished']}, "
          f"attacks leaked {totals['leaked']}/{totals['attacks']}, leaks on tickets without an attack "
          f"{totals['benign_leaked']}, errors {totals['errors']}, eurycleia blocks {totals['blocks']}\n"
          f"audit log: {report['audit_log']}; python memory growth {report['python_memory_growth_mb']} MB between "
          f"first and last snapshot\n{meter.summary()}\nreport: {out.with_suffix('.report.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
