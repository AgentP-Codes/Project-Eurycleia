# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Ready-made approvers: who says yes or no when the policy wants a person to approve an action.

    from eurycleia.approvals import SlackApprover
    vault = Vault(policy, sources, sinks, approver=SlackApprover(HttpClient("https://slack.com", token), "C0123"))

Every approver fails closed: no answer in time, an error, or anything unclear means no. Each shows the person
what Eurycleia itself knows about the action first (ApprovalRequest.facts), and what the agent sent second and
marked as such, because a fooled agent can make a bad action sound reasonable (OWASP ASI09).
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterable
from typing import Any

from .vault import ApprovalRequest

log = logging.getLogger("eurycleia")

APPROVE = {"white_check_mark", "heavy_check_mark"}       # ✅ ✔️
REFUSE = {"x", "no_entry", "no_entry_sign"}               # ❌ ⛔ 🚫


def describe(req: ApprovalRequest, limit: int = 1500) -> str:
    """The request as plain text, facts first. The agent's part is quoted and cut short; it may be misleading."""
    f = req.facts or {}
    lines = [f"Approval needed: {req.sink} (task {req.template}, #{req.task_id})", f"Why: {req.reason}", "",
             "What Eurycleia knows:"]
    for k, v in (f.get("trusted_inputs") or {}).items():
        lines.append(f"  - {k}: {v}  (from your app, not the AI)")
    for r in f.get("recipients") or []:
        where = "from trusted data" if r.get("from_trusted_data") else "NOT from trusted data"
        lines.append(f"  - goes to: {r.get('value')}  ({where}; {r.get('relation')})")
    if "read_untrusted_content" in f:
        lines.append(f"  - the task read outside content (an email, a web page): "
                     f"{'yes' if f['read_untrusted_content'] else 'no'}")
    if f.get("call_number"):
        lines.append(f"  - this action, time {f['call_number']}" +
                     (f" of at most {f['max_calls']}" if f.get("max_calls") else "") + " in this task")
    sent = json.dumps(req.args, default=str, ensure_ascii=False)
    if len(sent) > limit:
        sent = sent[:limit] + " ...(cut)"
    lines += ["", "What the AI sent (it may have been fooled; judge by the facts above):", f"  {sent}"]
    return "\n".join(lines)


def _slack_safe(text: str) -> str:
    """Slack reads <...> as links and mentions (<!channel>, <https://...|click here>): show them as text."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class SlackApprover:
    """Posts each request in a Slack channel and waits for a person to react ✅ (approve) or ❌ (refuse).

    Only reactions from people count, never the bot's own; with `approvers` (Slack user ids), only theirs.
    A refusal from any of them wins. No answer within `timeout` seconds, or any error, means no; the bot then
    says so in the thread. Needs a bot token with chat:write and reactions:read."""

    def __init__(self, client: Any, channel: str, timeout: float = 120, poll: float = 5,
                 approvers: Iterable[str] | None = None, sleep: Callable[[float], None] | None = None,
                 clock: Callable[[], float] | None = None):
        self.client, self.channel = client, channel
        self.timeout, self.poll = float(timeout), float(poll)
        self.approvers = {a.strip() for a in approvers or [] if a and a.strip()}
        self.sleep, self.clock = sleep or time.sleep, clock or time.monotonic
        self._bot: str | None = None

    def _call(self, method: str, path: str, **kw: Any) -> dict:
        r = self.client.request(method, path, **kw) or {}
        if not r.get("ok"):
            raise RuntimeError(f"Slack {path}: {r.get('error', 'unknown error')}")
        return r

    def _bot_id(self) -> str:
        if self._bot is None:
            self._bot = str(self._call("POST", "/api/auth.test", json_body={}).get("user_id") or "")
        return self._bot

    def _decision(self, ts: str) -> bool | None:
        r = self._call("GET", "/api/reactions.get", params={"channel": self.channel, "timestamp": ts, "full": "true"})
        approved = refused = False
        for reaction in (r.get("message") or {}).get("reactions") or []:
            people = [u for u in reaction.get("users") or [] if u != self._bot_id()]
            if self.approvers:
                people = [u for u in people if u in self.approvers]
            if not people:
                continue
            name = str(reaction.get("name", "")).split("::")[0]       # ignore skin tones
            approved |= name in APPROVE
            refused |= name in REFUSE
        return False if refused else (True if approved else None)

    def __call__(self, req: ApprovalRequest) -> bool:
        minutes = max(1, round(self.timeout / 60))
        text = (_slack_safe(describe(req)) + f"\n\nReact :white_check_mark: to approve or :x: to refuse. "
                f"No answer in {minutes} minute{'s' if minutes != 1 else ''} means refused.")
        try:
            ts = self._call("POST", "/api/chat.postMessage", json_body={"channel": self.channel, "text": text})["ts"]
        except Exception as e:  # noqa: BLE001 - can't ask, so the answer is no
            log.warning("couldn't ask for approval in Slack (%s); refused", e)
            return False
        end = self.clock() + self.timeout
        answer: bool | None = None
        try:
            while answer is None and self.clock() < end:
                self.sleep(self.poll)
                answer = self._decision(ts)
        except Exception as e:  # noqa: BLE001
            log.warning("couldn't read the Slack approval (%s); refused", e)
            answer = None
        try:
            note = {True: "Approved.", False: "Refused.", None: "No answer in time: refused."}[answer]
            self.client.request("POST", "/api/chat.postMessage",
                                json_body={"channel": self.channel, "thread_ts": ts, "text": note})
        except Exception:  # noqa: BLE001 - the decision stands either way
            pass
        return answer is True
