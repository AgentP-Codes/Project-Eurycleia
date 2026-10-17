# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""`eurycleia learn`: draft a policy from what the agent did while eurycleia watched.

Connect in watch mode (`eurycleia connect`, or `Vault(mode="shadow")`), use the agent as normal for a while,
then run `eurycleia learn`. It reads the audit log and the current policy and writes:

  eurycleia.learned.yaml   the policy with the changes below (your own policy file is never touched)
  learn-report.md          every change and why, what it left for you to decide, and what still looked wrong

What it changes, and what it never does:
  - It widens the policy only for patterns seen in many separate tasks (--min-tasks, default 5, and at least
    --min-share of that task's runs, default 20%), and only in the narrowest form that explains them: "the
    contact on this task's own customer record", never "anyone at gmail.com". Even the company's own domain is
    left for a person to add.
  - It never learns anything that could be an attack: an address that appeared in untrusted content (a
    ticket, a web page), another customer's records or contact, secrets going anywhere, customer data to
    someone who doesn't own it, links carrying data. Those are listed under "looked wrong" instead.
  - Nothing at all is learned from a task where something looked wrong.
  - It sets call limits that were missing; it raises limits by at most double and never reopens a switched-off
    action. Personal-data fields and bigger jumps are left for you to decide.
  - It never learns an outside address (the log holds fingerprints, not addresses) or an extra argument (any of
    them could send data somewhere): the report lists them for you to decide.
  - It then replays the watched tasks against the draft and says what the draft would still block.

The audit log never holds data values, so neither does anything this writes.
"""

from __future__ import annotations

import copy
import math
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .audit import AuditLog
from .policy import Policy

RECIPIENT_ARGS = {"to", "cc", "bcc", "reply_to", "replyto", "reply-to", "recipient", "recipients"}


@dataclass
class Watched:
    """One task as the log shows it."""
    id: str
    template: str
    reads: list[dict] = field(default_factory=list)            # allowed reads
    acts: list[dict] = field(default_factory=list)             # actions that ran (all of them, in watch mode)
    problems: list[dict] = field(default_factory=list)         # would_block / block entries


@dataclass
class Change:
    task: str
    what: str                         # plain words, for the report
    why: str
    resolves: set[tuple[str, int]] = field(default_factory=set)   # (task id, index into its problems)


@dataclass
class Learned:
    policy: dict[str, Any]
    tasks_seen: dict[str, int]
    changes: list[Change]
    needs_you: list[str]
    looked_wrong: list[str]
    suggestions: list[str]
    still_blocked: dict[str, Counter]       # template -> reason -> count, under the draft
    still_blocked_tasks: dict[str, int]
    total_problems: int


# ------------------------------------------------------------------ reading the log
def watched_tasks(entries: list[Any]) -> list[Watched]:
    tasks: dict[Any, Watched] = {}
    for e in entries:
        if not isinstance(e, dict):
            continue                                  # a damaged or hand-edited line
        tid = e.get("task")
        if e.get("event") == "task.start":
            tasks[tid] = Watched(str(tid), str(e.get("template")))
            continue
        t = tasks.get(tid)
        if t is None:
            continue
        decision = e.get("decision")
        if decision in ("would_block", "block"):
            t.problems.append(e)
        elif e.get("event") == "read" and decision == "allow":
            t.reads.append(e)
        elif e.get("event") == "act" and decision == "allow":
            t.acts.append(e)
    return list(tasks.values())


def _category(e: dict) -> str:
    r = str(e.get("reason", ""))
    if r == "recipient did not come from trusted data":
        return "recipient"
    if re.search(r"called more than \d+ times in one task", r):
        return "max_calls"
    if "does not accept some of the arguments" in r:
        return "args"
    if "is not allowed for this task" in r:
        return "sink_not_allowed"
    if "field(s) this task can't see" in r:
        return "fields"
    if r.startswith("data budget exceeded"):
        return "budget"
    return "never"            # secrets, owners, scope, links, placeholders, unknown tools: never learned


def _learnable_relation(rel: Any) -> bool:
    return bool(_contact_spec(rel)) or str(rel or "").startswith("internal:")


def _tainted(t: Watched) -> bool:
    """A task where something looked wrong (an attack, or the agent off track). Nothing is learned from it."""
    for p in t.problems:
        cat = _category(p)
        if cat == "never":
            return True
        if cat == "recipient" and not _learnable_relation(p.get("relation")):
            return True                       # an outside address, one from untrusted content, another record's
            #                                   contact, or one the log can't place
        if cat == "fields" and (p.get("unknown_other") or "unknown_fields" not in p):
            return True                       # asked for something that isn't a field of the source
    for a in t.acts:
        if "untrusted" in (a.get("recipient_relations") or []):
            return True                       # the policy let it through, but the address came from a ticket
    return False


def _calls(a: dict) -> int:
    c = a.get("call")
    return c if isinstance(c, int) and not isinstance(c, bool) and c > 0 else 1


def _p95(values: list[int]) -> int:
    v = sorted(values)
    return v[max(0, math.ceil(0.95 * len(v)) - 1)] if v else 0


def _contact_spec(relation: Any) -> tuple[str, str, str] | None:
    """"contact:crm.customer.email:{customer_id}" -> ("crm.customer", "email", "customer_id")."""
    m = re.fullmatch(r"contact:(.+)\.([A-Za-z0-9_]+):\{([A-Za-z_][A-Za-z0-9_]*)\}", str(relation or ""))
    return (m.group(1), m.group(2), m.group(3)) if m else None


# ------------------------------------------------------------------ learning
def learn(policy_path: str | Path, entries: list[Any], min_tasks: int = 5, min_share: float = 0.2) -> Learned:
    base = Policy.load(policy_path)
    raw = copy.deepcopy(base.raw)
    watched = watched_tasks(entries)
    by_template: dict[str, list[Watched]] = defaultdict(list)
    for t in watched:
        by_template[t.template].append(t)

    changes: list[Change] = []
    new_limits: dict[tuple[str, str], int] = {}       # limits set where there were none: checked in the replay
    needs_you: list[str] = []
    looked_wrong: list[str] = []
    suggestions: list[str] = []

    for tname, runs in sorted(by_template.items()):
        template = base.tasks.get(tname)
        if template is None:
            needs_you.append(f"task `{tname}` was run {len(runs)} times but isn't in the policy any more")
            continue
        traw = raw["tasks"][tname]
        sinks_raw = traw.get("sinks") or {}
        for name in list(sinks_raw):
            if sinks_raw[name] is None:
                sinks_raw[name] = {}                          # an empty entry is valid: no settings
        total = len(runs)
        clean = [t for t in runs if not _tainted(t)]           # everything below is learned from these only
        if len(clean) < total:
            looked_wrong.append(f"`{tname}`: something looked wrong in {total - len(clean)} of {total} tasks; "
                                "nothing was learned from them (details below)")

        def enough(n: int) -> bool:
            return n >= min_tasks and n >= min_share * total

        def problems(pred, among: list[Watched]) -> set[tuple[str, int]]:
            return {(t.id, i) for t in among for i, p in enumerate(t.problems) if pred(p)}

        def tasks_in(hits: set[tuple[str, int]]) -> int:
            return len({tid for tid, _ in hits})

        # ---- recipients: per sink, the narrowest rule that explains them
        pairs = Counter()
        for t in clean:
            pairs.update({(p.get("relation"), p.get("sink")) for p in t.problems if _category(p) == "recipient"})
        for (rel, sink), _n in sorted(pairs.items(), key=lambda x: (-x[1], str(x[0]))):
            pred = lambda p, rel=rel, sink=sink: (_category(p) == "recipient" and p.get("relation") == rel  # noqa: E731
                                                  and p.get("sink") == sink)
            n = tasks_in(problems(pred, clean))
            rule = sinks_raw.get(sink)
            if rule is None:
                continue
            spec = None
            if parts := _contact_spec(rel):
                src_name, fld, trusted_name = parts
                src = base.sources.get(src_name)
                read_key = (template.reads.get(src_name) or {}).get("key")
                if not (src and src.trust == "trusted" and trusted_name in template.trusted
                        and read_key == f"{{{trusted_name}}}"):
                    continue
                spec = f"{src_name}:{{{trusted_name}}}.{fld}"
                what = f"`{sink}` may send to `{spec}` (the {fld} on this task's own {src_name} record)"
            elif str(rel).startswith("internal:"):
                # never learned: an address can reach the agent in a form eurycleia can't spot ("ops at acme dot
                # example"), so a person decides whether the whole company domain is right
                if enough(n):
                    needs_you.append(f"`{tname}`: `{sink}` sent to people at `{str(rel)[9:]}` (your own company) in "
                                     f"{n} of {total} tasks. If that's normal, add `*@{str(rel)[9:]}` (or the exact "
                                     "addresses) to its `allowed_recipients` by hand")
                continue
            if spec is None:
                continue
            if not enough(n):
                needs_you.append(f"`{tname}`: {what[0].lower() + what[1:]}? Seen in only {n} of {total} tasks, too "
                                 "few to learn from; add it by hand if that's normal")
                continue
            lst = rule.setdefault("allowed_recipients", [])
            if spec not in lst:
                lst.append(spec)
            changes.append(Change(tname, what, f"seen in {n} of {total} tasks", problems(pred, runs)))

        outside = defaultdict(set)    # (sink, fingerprint) -> tasks
        for t in runs:      # what was never learned, from any task
            for p in t.problems:
                if _category(p) != "recipient":
                    continue
                rel = p.get("relation")
                if rel == "other":
                    outside[(p.get("sink"), p.get("recipient"))].add(t.id)
                elif rel == "untrusted":
                    looked_wrong.append(f"`{tname}`: `{p.get('sink')}` sent to an address that came from a ticket, "
                                        "email or web page. This is what an attack looks like; not learned")
                elif str(rel or "").startswith("contact:") and not _contact_spec(rel):
                    looked_wrong.append(f"`{tname}`: `{p.get('sink')}` sent to the contact on a record this task "
                                        "isn't for (another customer); not learned")
                elif rel is None:
                    looked_wrong.append(f"`{tname}`: a recipient the log can't place (written by an older "
                                        "eurycleia); not learned")
        for sink in sorted({k[0] for k in outside}, key=str):
            tids = set().union(*(v for k, v in outside.items() if k[0] == sink))
            same = [(fp, len(v)) for (sk, fp), v in outside.items() if sk == sink and len(v) > 1]
            looked_wrong.append(
                f"`{tname}`: `{sink}` sent to outside addresses the policy doesn't list in {len(tids)} task(s)"
                + "".join(f"; the same one (fingerprint `{fp}`) in {n}" for fp, n in sorted(same, key=lambda x: -x[1]))
                + ". eurycleia never learns outside addresses: if one is a real partner, add it by hand; if you "
                "don't recognise it, treat it as an attack")

        # ---- call limits
        for sink, rule in sinks_raw.items():
            used = [max([_calls(a) for a in t.acts if a.get("sink") == sink], default=0) for t in clean]
            used = [x for x in used if x]
            if not any(a.get("sink") == sink for t in runs for a in t.acts):
                suggestions.append(f"`{tname}`: never used `{sink}` in {total} watched tasks. If it's never "
                                   "needed, removing it makes the task safer")
                continue
            current = rule.get("max_calls")
            if current == 0:
                continue                                   # switched off on purpose: never turned back on
            if not used:
                continue
            if current is None:
                if len(used) < min_tasks:          # too few to tell normal from one odd task: leave it to a person
                    needs_you.append(f"`{tname}`: `{sink}` has no call limit and was used in only {len(used)} "
                                     f"task(s) where nothing looked wrong (up to {max(used)} calls). Set one by hand")
                    continue
                # the highest count enough tasks reached: one task (an attack that looked normal) can't set it
                new = max(x for x in range(1, max(used) + 1) if sum(u >= x for u in used) >= min_tasks)
                rule["max_calls"] = new
                new_limits[(tname, sink)] = new
                above = sum(u > new for u in used)
                changes.append(Change(tname, f"`{sink}`: at most {new} call(s) per task (there was no limit)",
                                      f"reached in {sum(u >= new for u in used)} of the {len(used)} tasks that used "
                                      "it where nothing looked wrong"))
                if above:
                    needs_you.append(f"`{tname}`: {above} task(s) used `{sink}` more than {new} times (up to "
                                     f"{max(used)}). Too few to learn from; raise the limit by hand if that's normal")
                continue
            pred = lambda p, sink=sink: _category(p) == "max_calls" and p.get("sink") == sink  # noqa: E731
            n = tasks_in(problems(pred, clean))
            if not (n and enough(n)):
                continue
            new = max(current, _p95(used))
            if new > 2 * current:
                needs_you.append(f"`{tname}`: `{sink}` needed up to {new} calls in a task (limit {current}). That's "
                                 "a big jump; raise it by hand if it's right")
            elif new > current:
                rule["max_calls"] = new
                fixed = {(t.id, i) for t in runs for i, p in enumerate(t.problems) if pred(p)
                         and max([_calls(a) for a in t.acts if a.get("sink") == sink], default=0) <= new}
                changes.append(Change(tname, f"`{sink}`: at most {new} calls per task (was {current})",
                                      f"{n} of {total} tasks needed more than {current}", fixed))

        # ---- extra arguments: never learned (any argument can carry an address or a link)
        for sink, rule in sinks_raw.items():
            if rule.get("args") is None:
                continue
            extra = Counter()
            for t in runs:
                extra.update({a for x in t.acts if x.get("sink") == sink for a in x.get("args") or []}
                             - set(rule["args"]))
            for arg, n in extra.most_common():
                if arg.lower() in RECIPIENT_ARGS:
                    looked_wrong.append(f"`{tname}`: `{sink}` was given a `{arg}` in {n} task(s). Extra "
                                        "recipients are how data gets copied out; not learned")
                else:
                    needs_you.append(f"`{tname}`: `{sink}` was given a `{arg}` argument in {n} of {total} tasks. "
                                     "Arguments are never learned, because any of them could send data somewhere "
                                     "(a forwarding address, a webhook). Add it by hand only if it can't")

        # ---- fields the task couldn't see: normal ones are learned, protected ones are yours to decide
        for src_name, rule in (traw.get("reads") or {}).items():
            src = base.sources.get(src_name)
            if src is None or not isinstance(rule, dict) or not isinstance(rule.get("fields"), list):
                continue
            def asked(among: list[Watched], src_name=src_name) -> Counter:
                c = Counter()
                for t in among:
                    c.update({f for p in t.problems if _category(p) == "fields" and p.get("source") == src_name
                              for f in p.get("unknown_fields") or [] if isinstance(f, str)})
                return c
            for fld, n in asked(runs).most_common():
                level = src.fields.get(fld, src.default_level)
                if level == "secret":
                    looked_wrong.append(f"`{tname}`: asked for the secret field `{src_name}.{fld}` in {n} "
                                        "task(s); not learned")
            added = []
            for fld, n in asked(clean).most_common():
                level = src.fields.get(fld, src.default_level)
                if level == "secret" or fld in rule["fields"]:
                    continue
                if level == "protected":
                    needs_you.append(f"`{tname}`: asked for `{src_name}.{fld}` (personal data) in {n} of {total} "
                                     "tasks. Add it by hand if the task really needs it")
                elif enough(n):
                    rule["fields"].append(fld)
                    added.append((fld, n))
            if added:
                fixed = {(t.id, i) for t in runs for i, p in enumerate(t.problems)
                         if _category(p) == "fields" and p.get("source") == src_name and not p.get("unknown_other")
                         and "unknown_fields" in p and set(p["unknown_fields"]) <= set(rule["fields"])}
                changes.append(Change(tname, f"reads {', '.join(f'`{f}`' for f, _ in added)} from `{src_name}` too",
                                      "; ".join(f"`{f}` asked for in {n} of {total} tasks" for f, n in added), fixed))

        # ---- data budgets
        budget = traw.get("budget") or {}
        for k, limit in list(budget.items()):
            pred = lambda p, k=k: _category(p) == "budget" and f" {k} per task" in str(p.get("reason"))  # noqa: E731
            n = tasks_in(problems(pred, clean))
            if not (n and enough(n)):
                continue
            new = max(limit, _p95([_usage(t)[k] for t in clean]))
            if new > 2 * limit:
                needs_you.append(f"`{tname}`: tasks needed up to {new} {k} (budget {limit}). That's a big jump; "
                                 "raise it by hand if it's right")
            elif new > limit:
                budget[k] = new
                fixed = {(t.id, i) for t in runs for i, p in enumerate(t.problems)
                         if pred(p) and _usage(t)[k] <= new}
                changes.append(Change(tname, f"data budget: up to {new} {k} per task (was {limit})",
                                      f"{n} of {total} tasks needed more", fixed))

        # ---- the rest
        for t in runs:
            looked_wrong += [f"`{tname}`: {p.get('reason')}" for p in t.problems if _category(p) == "never"]
        not_allowed = Counter(p.get("sink") for t in runs for p in t.problems if _category(p) == "sink_not_allowed")
        for sink, n in not_allowed.items():
            needs_you.append(f"`{tname}`: used `{sink}` in {n} of {total} tasks, but the task doesn't allow it. "
                             "If that's normal, add it to the task by hand (who it may send to can't be guessed)")
        for src_name in (traw.get("reads") or {}):
            if not any(r.get("source") == src_name for t in runs for r in t.reads):
                suggestions.append(f"`{tname}`: never read `{src_name}` in {total} watched tasks")

    Policy.from_dict(raw)       # the draft must load

    # ---- replay: what the draft would still block in the watched tasks
    resolved = set().union(*(c.resolves for c in changes)) if changes else set()
    still: dict[str, Counter] = defaultdict(Counter)
    still_tasks: dict[str, set] = defaultdict(set)
    for t in watched:
        for i, p in enumerate(t.problems):
            if (t.id, i) not in resolved:
                still[t.template][str(p.get("reason"))] += 1
                still_tasks[t.template].add(t.id)
        for (tname, sink), limit in new_limits.items():   # calls the new limits would stop (none were logged)
            over = sum(1 for a in t.acts if t.template == tname and a.get("sink") == sink and _calls(a) > limit)
            if over:
                still[t.template][f"{sink!r} called more than {limit} times in one task (new limit)"] += over
                still_tasks[t.template].add(t.id)
    return Learned(raw, {k: len(v) for k, v in by_template.items()}, changes, _dedupe(needs_you),
                   _summarise(looked_wrong), suggestions, dict(still), {k: len(v) for k, v in still_tasks.items()},
                   sum(len(t.problems) for t in watched))


def _usage(t: Watched) -> dict[str, int]:
    records = {(r.get("source"), r.get("key")) for r in t.reads}
    fields = {(r.get("source"), r.get("key"), f) for r in t.reads for f in r.get("fields") or []}
    return {"reads": len(t.reads), "records": len(records), "fields": len(fields)}


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _summarise(items: list[str]) -> list[str]:
    return [f"{text} ({n} times)" if n > 1 else text for text, n in Counter(items).most_common()]


# ------------------------------------------------------------------ writing
def write(result: Learned, out_policy: Path, out_report: Path, policy_path: str | Path, audit_paths: list[str]) -> None:
    head = (f"# Drafted by `eurycleia learn` on {time.strftime('%Y-%m-%d')} from "
            f"{sum(result.tasks_seen.values())} watched tasks, starting from {Path(policy_path).name}.\n"
            f"# Review {out_report.name} first. To use it, copy it over your policy file (keep the old one) and run "
            "`eurycleia enforce`.\n# (Comments from the original policy aren't carried over; it is unchanged.)\n\n")
    out_policy.write_text(head + yaml.safe_dump(result.policy, sort_keys=False, allow_unicode=True))
    out_report.write_text(report_text(result, out_policy, audit_paths))


def report_text(r: Learned, out_policy: Path, audit_paths: list[str]) -> str:
    lines = ["# What eurycleia learned", "",
             f"From {sum(r.tasks_seen.values())} watched tasks ("
             + ", ".join(f"`{k}` {v}" for k, v in sorted(r.tasks_seen.items())) + f") in {', '.join(audit_paths)}.",
             f"The draft is `{out_policy.name}`. Your policy is unchanged. To use the draft, copy it over your "
             "policy file (keep the old one), then run `eurycleia enforce`.", "", "## Changes in the draft", ""]
    lines += [f"- {c.what}. Why: {c.why}." for c in r.changes] or ["- none"]
    lines += ["", "## Decide these yourself", ""]
    lines += [f"- {x}" for x in r.needs_you] or ["- nothing"]
    lines += ["", "## Looked wrong (never learned)", "",
              "These are what an attack, or an agent going off track, looks like. Check them; if one was really "
              "fine, change the policy by hand.", ""]
    lines += [f"- {x}" for x in r.looked_wrong] or ["- nothing"]
    lines += ["", "## Could be tighter", ""]
    lines += [f"- {x}" for x in r.suggestions] or ["- nothing"]
    lines += ["", "## Replayed against the draft", ""]
    remaining = sum(sum(c.values()) for c in r.still_blocked.values())
    lines.append(f"While watching, the old policy would have blocked {r.total_problems} action(s). With the draft "
                 f"it would block {remaining}"
                 + (":" if remaining else ". Everything seen while watching would have gone through."))
    for tname, reasons in sorted(r.still_blocked.items()):
        lines.append(f"- `{tname}` ({r.still_blocked_tasks[tname]} task(s)):")
        lines += [f"  - {n} x {reason}" for reason, n in reasons.most_common()]
    lines += ["", "This replay uses the audit log, so it covers what the agent did while watched, not everything "
              "it might do later."]
    return "\n".join(lines) + "\n"


def load_entries(paths: list[str], key: str | None = None) -> list[dict]:
    """Every entry of the logs, after checking each one hasn't been edited (with the key, if given)."""
    entries: list[dict] = []
    for p in paths:
        if not Path(p).is_file():
            raise FileNotFoundError(2, "no such audit log", p)
        if key:
            from .audit import audit_key
            from .crypto import LocalKeyProvider
            log = AuditLog(p, keep=None, key=audit_key(LocalKeyProvider(key, create=False)))
            if (problem := log.problem()) is not None:
                raise ValueError(f"{p}: the audit log doesn't check out ({problem}); not learning from it")
        else:
            log = AuditLog(p, keep=None)
            if (problem := log.problem()) is not None:
                raise ValueError(f"{p}: the audit log doesn't check out ({problem}); not learning from it")
        entries += log.entries
    return entries
