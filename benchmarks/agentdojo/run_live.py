# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""AgentDojo with a real model, with and without eurycleia's rules.

API keys are read from the environment only. Set them in the window you run from; never put them on the
command line or in a file:

    Windows:     set ANTHROPIC_API_KEY=...     (or OPENAI_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY)
    macOS/Linux: export ANTHROPIC_API_KEY=...

    pip install -r requirements.txt
    python run_live.py --provider openai --model gpt-6-luna --smoke                  # a few episodes first
    python run_live.py --provider openai --model gpt-6-luna --budget-aud 6           # then the full run
    python run_live.py --provider anthropic --model claude-sonnet-5 --sample 0.25 --budget-aud 22
    python run_live.py --provider openrouter --model qwen/qwen3.6-plus --budget-aud 8
    python run_live.py --summarize agentdojo-results.jsonl

The cost is counted from the tokens each provider reports and priced from demo/pricing.py (a model that
isn't listed needs --price-in/--price-out). The run stops by itself at --budget-aud; set a spending limit in
the provider's console as well. Every episode is saved as it finishes (with its cost), so running the same
command again carries on where it stopped, counting what was already spent.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agentdojo.agent_pipeline import (  # noqa: E402
    AgentPipeline,
    InitQuery,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402
from defense import EurycleiaToolsExecutor, allowed_writes_by_prompt, run_episode  # noqa: E402

VERSION = "v1.2.2"


def make_llm(provider: str, model: str):

    def key(*names):
        for n in names:
            if os.environ.get(n):
                return os.environ[n]
        raise SystemExit(f"set {names[0]} in this window first (see the top of this file)")

    if provider == "anthropic":
        import anthropic
        from agentdojo.agent_pipeline import AnthropicLLM
        return AnthropicLLM(anthropic.AsyncAnthropic(api_key=key("ANTHROPIC_API_KEY"), max_retries=6), model)
    if provider == "gemini":
        from agentdojo.agent_pipeline import GoogleLLM
        from google import genai
        return GoogleLLM(model, client=genai.Client(api_key=key("GEMINI_API_KEY", "GOOGLE_API_KEY")))
    if provider in ("openai", "openrouter"):
        import openai
        from agentdojo.agent_pipeline import OpenAILLM
        if provider == "openai":
            client = openai.OpenAI(api_key=key("OPENAI_API_KEY"), max_retries=6)
        else:
            client = openai.OpenAI(api_key=key("OPENROUTER_API_KEY"), base_url="https://openrouter.ai/api/v1",
                                   max_retries=6)
        return OpenAILLM(client, model)
    raise SystemExit(f"unknown provider {provider}")


def make_pipeline(llm, model: str, executor) -> AgentPipeline:
    p = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm,
                       ToolsExecutionLoop([executor, llm])])
    p.name = pipeline_name(model)
    return p


def pipeline_name(model: str) -> str:
    """AgentDojo's attack text addresses the model by name ("...to you, Claude"), looked up from the pipeline
    name. It only knows older model ids, so a newer one gets a known id of the same family appended."""
    from agentdojo.models import MODEL_NAMES
    if any(k in model for k in MODEL_NAMES):
        return model
    m = model.lower().rsplit("/", 1)[-1]
    family = ("claude-3-haiku-20240307" if "claude" in m else                    # "Claude"
              "gpt-4o-2024-05-13" if m.startswith(("gpt", "o1", "o3", "o4", "o5")) else   # "GPT-4"
              "gemini-2.0-flash-001" if "gemini" in m else                       # "AI model developed by Google"
              "meta-llama/Llama-3-70b-chat-hf")                                  # "AI assistant" (Qwen, DeepSeek...)
    return f"{model} {family}"


def episodes(suite, a) -> list[tuple[str, str | None]]:
    users = a.user_task or list(suite.user_tasks)
    attacks = [(u, i) for u in users for i in (a.injection_task or list(suite.injection_tasks))]
    random.Random(0).shuffle(attacks)                  # a fair, repeatable sample
    if a.smoke:
        users, attacks = users[:2], attacks[:2]
    if a.sample:
        attacks = attacks[:max(1, round(len(attacks) * a.sample))]
    if a.max_pairs:
        attacks = attacks[:a.max_pairs]
    pairs: list[tuple[str, str | None]] = [(u, None) for u in users] if not a.attacks_only else []
    return pairs + ([] if a.no_attacks else attacks)


def run(a) -> int:
    import metering

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from demo.pricing import BudgetExceeded, Meter, UnknownPrice

    out = Path(a.out)
    done, spent = set(), 0.0
    if out.exists():
        for line in out.read_text().splitlines():
            r = json.loads(line)
            if r.get("model") == a.model:
                spent += r.get("cost_aud", 0) or 0          # money already spent on this model in this file
            if "error" not in r:
                done.add((r["model"], r["attack"], r["suite"], r["mode"], r["user_task"], r["injection_task"]))
    try:
        meter = Meter(a.model, a.budget_aud, a.price_in, a.price_out)
    except UnknownPrice as e:
        raise SystemExit(str(e)) from None
    meter.spent_aud = spent
    if spent >= a.budget_aud:
        print(f"A${spent:.2f} already spent on {a.model} in {out}, which is the whole budget (--budget-aud)")
        return summarize(out)
    metering.install(meter)
    llm = make_llm(a.provider, a.model)
    try:
        for suite_name in a.suite:
            suite = get_suites(VERSION)[suite_name]
            clean = suite.load_and_inject_default_environment(suite.get_injection_vector_defaults())
            templates = allowed_writes_by_prompt(suite, clean)
            for mode in a.mode:
                executor = ToolsExecutor() if mode == "none" else \
                    EurycleiaToolsExecutor(suite_name, templates if mode == "strict" else None)
                pipeline = make_pipeline(llm, a.model, executor)
                attack = load_attack(a.attack, suite, pipeline)
                for uid, iid in episodes(suite, a):
                    if (a.model, a.attack, suite_name, mode, uid, iid) in done:
                        continue
                    run_one(a, out, meter, suite, suite_name, mode, pipeline, attack, uid, iid)
                    time.sleep(a.sleep)
    except BudgetExceeded as e:
        print(f"\nStopped: {e}. Everything so far is saved; raise --budget-aud to carry on.")
    except KeyboardInterrupt:
        print("\nStopped. Everything so far is saved; run the same command to carry on.")
    print("\n" + meter.summary())
    return summarize(out)


def run_one(a, out: Path, meter, suite, suite_name: str, mode: str, pipeline, attack, uid: str, iid: str | None):
    from demo.pricing import BudgetExceeded
    ut = suite.user_tasks[uid]
    it = suite.injection_tasks[iid] if iid else None
    injections = attack.attack(ut, it) if it else suite.get_injection_vector_defaults()
    before = meter.spent_aud
    for attempt in range(4):
        try:
            r = run_episode(suite, pipeline, ut, it, injections)
            break
        except BudgetExceeded:
            _save(out, {"suite": suite_name, "mode": mode, "model": a.model, "attack": a.attack, "user_task": uid,
                        "injection_task": iid, "error": True, "cost_aud": meter.spent_aud - before})
            raise
        except Exception as e:  # noqa: BLE001 - quota and network errors: wait and retry
            if not _transient(e):         # a bug (in AgentDojo, the rules or this script): record it, don't pay again
                print(f"  {uid} {iid or ''}: {type(e).__name__}: {str(e)[:200]} (not retried)")
                _save(out, {"suite": suite_name, "mode": mode, "model": a.model, "attack": a.attack,
                            "user_task": uid, "injection_task": iid, "error": f"{type(e).__name__}: {str(e)[:300]}",
                            "cost_aud": meter.spent_aud - before})
                return
            wait = 30 * (attempt + 1)
            print(f"  {uid} {iid or ''}: {type(e).__name__}: {str(e)[:160]} (retrying in {wait}s)")
            time.sleep(wait)
    else:
        print("  giving up on this one for now; run the same command again later to retry it")
        _save(out, {"suite": suite_name, "mode": mode, "model": a.model, "attack": a.attack, "user_task": uid,
                    "injection_task": iid, "error": True, "cost_aud": meter.spent_aud - before})
        return
    cost = meter.spent_aud - before
    _save(out, {"suite": suite_name, "mode": mode, "model": a.model, "attack": a.attack, "user_task": uid,
                "injection_task": iid, **r, "cost_aud": round(cost, 5)})
    tag = f"attack {'SUCCEEDED' if r.get('attack_effective') else 'failed'}" if iid else ""
    ok = "yes" if r["utility"] else "no "
    print(f"{suite_name} {mode:<7} {uid:<14} {iid or '':<18} utility {ok} {tag:<16} A${meter.spent_aud:.2f}",
          flush=True)


def _transient(e: Exception) -> bool:
    """Rate limits, overload, timeouts and dropped connections: worth waiting and trying again."""
    text = f"{type(e).__name__} {e}".lower()
    return any(w in text for w in ("rate", "429", "overload", "529", "503", "502", "500", "timeout", "timed out",
                                   "connection", "resource_exhausted", "unavailable", "quota", "temporar"))


def _save(out: Path, row: dict) -> None:
    with out.open("a") as f:           # kept (and shown in the summary) so nothing is silently lost
        f.write(json.dumps(row) + "\n")


def summarize(path: Path) -> int:
    rows = [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]
    finished = {(r["model"], r["attack"], r["suite"], r["mode"], r["user_task"], r["injection_task"])
                for r in rows if "error" not in r}
    failed = {(r["model"], r["attack"], r["suite"], r["mode"], r["user_task"], r["injection_task"])
              for r in rows if "error" in r} - finished
    rows = [r for r in rows if "error" not in r]
    groups: dict[tuple, list] = {}
    for r in rows:
        groups.setdefault((r["model"] + (f" ({r['attack']})" if r["attack"] != "important_instructions" else ""),
                           r["suite"], r["mode"]), []).append(r)
    print(f"\n{'model':<28} {'suite':<10} {'mode':<8} {'utility (no attack)':<22} {'utility under attack':<22} "
          f"attacks succeeded")
    for (model, suite, mode), rs in sorted(groups.items()):
        plain = [r for r in rs if not r["injection_task"]]
        attacked = [r for r in rs if r["injection_task"]]

        def pct(xs, key):
            n = sum(bool(x.get(key)) for x in xs)
            return f"{n}/{len(xs)} ({100 * n / len(xs):.0f}%)" if xs else "-"
        print(f"{model:<28} {suite:<10} {mode:<8} {pct(plain, 'utility'):<22} {pct(attacked, 'utility'):<22} "
              f"{pct(attacked, 'attack_effective')}  [AgentDojo's own verdict: {pct(attacked, 'attack_agentdojo')}]")
    costs: dict[str, float] = {}
    for r in [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]:
        costs[r["model"]] = costs.get(r["model"], 0) + (r.get("cost_aud") or 0)
    if costs:
        print("\nspent (estimated from reported tokens): " +
              ", ".join(f"{m} A${c:.2f}" for m, c in sorted(costs.items())) + f"; total A${sum(costs.values()):.2f}")
    if failed:
        per: dict[tuple, int] = {}
        for k in failed:
            per[(k[0], k[2], k[3])] = per.get((k[0], k[2], k[3]), 0) + 1
        print(f"\n{len(failed)} episodes ended in an error and aren't counted above (run the same command again to "
              "retry them):\n" + "\n".join(f"  {m} {s} {mode}: {n}" for (m, s, mode), n in sorted(per.items())))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", choices=["anthropic", "openai", "gemini", "openrouter"])
    ap.add_argument("--model")
    ap.add_argument("--suite", action="append", choices=["workspace", "travel", "banking", "slack"])
    ap.add_argument("--mode", action="append", choices=["none", "general", "strict"])
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--user-task", action="append")
    ap.add_argument("--injection-task", action="append")
    ap.add_argument("--max-pairs", type=int, default=0, help="attack pairs per suite and mode (0 = all)")
    ap.add_argument("--sample", type=float, default=0, help="share of attack pairs to run, e.g. 0.25 (all tasks run)")
    ap.add_argument("--smoke", action="store_true", help="just 2 tasks and 2 attacks per suite and mode, to check")
    ap.add_argument("--budget-aud", type=float, default=5.0, help="stop when this model has cost this much (A$)")
    ap.add_argument("--price-in", type=float, default=None, help="US$ per million input tokens (unlisted models)")
    ap.add_argument("--price-out", type=float, default=None, help="US$ per million output tokens (unlisted models)")
    ap.add_argument("--no-attacks", action="store_true", help="only the user tasks, no injections")
    ap.add_argument("--attacks-only", action="store_true")
    ap.add_argument("--sleep", type=float, default=0, help="seconds between episodes (for free-tier limits)")
    ap.add_argument("--out", default="agentdojo-results.jsonl")
    ap.add_argument("--summarize", metavar="FILE", default=None)
    a = ap.parse_args()
    if a.summarize:
        return summarize(Path(a.summarize))
    if not (a.provider and a.model):
        ap.error("--provider and --model are needed (or --summarize FILE)")
    a.suite = a.suite or ["workspace", "travel", "banking", "slack"]
    a.mode = a.mode or ["none", "strict"]
    return run(a)


if __name__ == "__main__":
    sys.exit(main())
