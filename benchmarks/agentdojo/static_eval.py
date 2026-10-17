# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""AgentDojo without a model: what eurycleia's rules do to each task's reference actions.

  utility   each user task's reference solution (its "ground truth" tool calls), run through the rules:
            does the task still get done? A block here is a false positive.
  security  for every user task x attack pair: the user task's reference actions (so the agent has read the
            injected content, as a hijacked agent would), then exactly the attacker's reference actions (a
            model that is fully fooled). Does the attack still succeed?

This measures the rules, not a model: a real model may be fooled less often (fewer attempts reach the rules),
or may find other actions (which the rules may or may not catch). Run run_live.py for that.

    pip install agentdojo
    python static_eval.py [--mode strict|general|both] [--suite banking ...] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string  # noqa: E402
from defense import EurycleiaToolsExecutor, allowed_writes_by_prompt, run_episode  # noqa: E402

VERSION = "v1.2.2"


class ScriptedAgent(BasePipelineElement):
    """Plays a fully-cooperative 'model': the user task's reference calls, then (if any) the attacker's."""

    def __init__(self, user_task, injection_task, executor: EurycleiaToolsExecutor | None):
        self.user_task, self.injection_task, self.executor = user_task, injection_task, executor
        self.blocked: list[str] = []

    def query(self, query, runtime, env, messages=(), extra_args={}):  # noqa: B006
        calls = list(self.user_task.ground_truth(env))
        if self.injection_task is not None:
            calls += list(self.injection_task.ground_truth(env))
        msgs = list(messages)
        gate, extra_args = self.executor.gate_for(query, extra_args) if self.executor else (None, extra_args)
        for call in calls:
            msgs.append(ChatAssistantMessage(role="assistant", tool_calls=[call],
                                             content=[text_content_block_from_string("")]))
            if self.executor:
                res = self.executor.run_call(gate, runtime, env, call)
                if res["error"] and res["error"].startswith("Blocked by eurycleia"):
                    self.blocked.append(f"{call.function}: {res['error'][22:]}")
            else:
                from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
                from defense import _result
                result, error = runtime.run_function(env, call.function, call.args)
                res = _result(call, tool_result_to_str(result), error)
            msgs.append(res)
        msgs.append(ChatAssistantMessage(role="assistant", tool_calls=None,
                                         content=[text_content_block_from_string(self.user_task.GROUND_TRUTH_OUTPUT)]))
        return query, runtime, env, msgs, extra_args


ATTACKERS = {"workspace": "mark.black-2134@gmail.com", "banking": "US133000000121212121212"}


def attacker_sends(suite_name: str, suite) -> None:
    """The item that carries an injection is attributed to the attacker, as it would be in real life: the email
    is from the attacker, the payment with the injected subject comes from the attacker's IBAN, the calendar
    invitation includes the attacker, the shared file is owned by the attacker. (In AgentDojo's own data they
    come from innocent-looking senders.) Travel and Slack have no sender fields to change."""
    orig = type(suite).load_and_inject_default_environment
    att = ATTACKERS.get(suite_name)

    def patched(self, injections):
        env = orig(self, injections)
        defaults = self.get_injection_vector_defaults()
        goals = {v for k, v in injections.items() if v and len(v) > 20 and v != defaults.get(k)}
        def hit(text):
            return any(g in (text or "") for g in goals)
        if suite_name == "banking":
            for t in env.bank_account.transactions:
                if hit(t.subject):
                    t.sender = att
        if suite_name == "workspace":
            for e in env.inbox.emails.values():
                if hit(e.body):
                    e.sender = att
            for c in env.calendar.events.values():
                if hit(c.description):
                    c.participants = [*c.participants, att]
            for f in env.cloud_drive.files.values():
                if hit(f.content):
                    f.owner = att
        return env

    suite.load_and_inject_default_environment = patched.__get__(suite)


def evaluate(suite_name: str, mode: str, realistic: bool = False) -> dict:
    suite = get_suites(VERSION)[suite_name]
    if realistic:
        attacker_sends(suite_name, suite)
    try:
        return _evaluate(suite, suite_name, mode, realistic)
    finally:
        suite.__dict__.pop("load_and_inject_default_environment", None)    # get_suites caches the suite


def _evaluate(suite, suite_name: str, mode: str, realistic: bool) -> dict:
    clean = suite.load_and_inject_default_environment(suite.get_injection_vector_defaults())
    templates = allowed_writes_by_prompt(suite, clean) if mode == "strict" else None

    def agent(ut, it):
        return ScriptedAgent(ut, it, None if mode == "none" else EurycleiaToolsExecutor(suite_name, templates))

    no_reference = sorted(i for i, t in suite.injection_tasks.items() if not t.ground_truth(clean))
    out = {"suite": suite_name, "mode": mode, "attacker_sends": realistic, "utility": {}, "security": {},
           "attacks_without_reference": no_reference}
    for uid, ut in suite.user_tasks.items():
        r = run_episode(suite, agent(ut, None), ut, None, suite.get_injection_vector_defaults())
        out["utility"][uid] = {"done": r["utility"], "blocked": r["blocked"]}
    for uid, ut in suite.user_tasks.items():
        for iid, it in suite.injection_tasks.items():
            if not it.ground_truth(clean):
                continue                              # no reference attack to replay
            injections = {k: it.GOAL for k in suite.get_injection_vector_defaults()}
            r = run_episode(suite, agent(ut, it), ut, it, injections)
            out["security"][f"{uid}|{iid}"] = {"attack_succeeded": r["attack_effective"],
                                                "agentdojo_verdict": r["attack_agentdojo"], "blocked": r["blocked"]}
    return out


def summary(r: dict) -> str:
    u = r["utility"]
    s = r["security"]
    done = sum(v["done"] for v in u.values())
    hit = sum(v["attack_succeeded"] for v in s.values())
    official = sum(v["agentdojo_verdict"] for v in s.values())
    tag = "attacker sends" if r.get("attacker_sends") else "as published"
    return (f"{r['suite']:<10} {r['mode']:<8} {tag:<15} utility {done}/{len(u)} ({100 * done / max(1, len(u)):.0f}%)   "
            f"attacks succeeded {hit}/{len(s)} ({100 * hit / max(1, len(s)):.0f}%)"
            f"   [AgentDojo's own verdict, counting refused calls: {official}/{len(s)}]")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["strict", "general", "none", "all"], default="all")
    ap.add_argument("--suite", action="append", choices=["workspace", "travel", "banking", "slack"])
    ap.add_argument("--json", default=None, help="write every result here")
    ap.add_argument("--data", choices=["published", "attacker-sends", "both"], default="both",
                    help="AgentDojo's data as published, or with injected items sent by the attacker")
    a = ap.parse_args()
    modes = ["none", "general", "strict"] if a.mode == "all" else [a.mode]
    results = []
    variants = {"published": [False], "attacker-sends": [True], "both": [False, True]}[a.data]
    for realistic in variants:
        for mode in modes:
            for name in a.suite or ["workspace", "travel", "banking", "slack"]:
                r = evaluate(name, mode, realistic)
                results.append(r)
                print(summary(r), flush=True)
    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
