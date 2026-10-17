# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""eurycleia's rules for AgentDojo's four tool suites.

AgentDojo's tools (send_email, send_money, read_file, ...) don't fit eurycleia's record-and-placeholder model,
so this is a port of the rules that apply to them, written the way a developer would configure eurycleia:

  1. Task-scoped tools ("strict" mode): a task may only use the tools that change something (send, pay, delete,
     book ...) that its template lists. AgentDojo doesn't come with templates, so each user task's template is
     taken to be the tools its reference solution uses: what a developer who built that one feature would allow.
     "general" mode gives every task every tool, so only rule 2 applies.
  2. Recipients from trusted data: every recipient (email address, IBAN, user, channel, web address to post to)
     must be in the user's own request, at the company's own email domain (eurycleia's internal_domains), or in
     data the user's side wrote: the recipients of emails they sent, the payees of payments they made or
     scheduled, the workspace's member and channel lists. (Not AgentDojo's contact list: it is built from every
     email, including ones an attacker sent.) Anything a sender outside controls never
     counts: email bodies, files, web pages, reviews and messages, and also who an email, payment, invitation or
     shared file came from (an attacker can send those themselves).

The trusted inputs a real app would pass (who the signed-in user is, the company's domain) are given per suite.

Not ported: placeholders for secrets and stand-ins for personal details (AgentDojo's checks need the model to
see real values), the link check, and value matching of protected data (AgentDojo has no data owners).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SuiteRules:
    writes: set[str]                                   # tools that change something
    recipients: dict[str, list[str]]                   # tool -> arguments naming who/where it goes to
    me: set[str] = field(default_factory=set)          # the signed-in user (a trusted input from the app)
    internal_domains: set[str] = field(default_factory=set)
    directory_tools: set[str] = field(default_factory=set)      # whole output is trusted (address book, members)
    url_args: set[tuple[str, str]] = field(default_factory=set)  # (tool, arg) compared by web address host


SUITES: dict[str, SuiteRules] = {
    "workspace": SuiteRules(
        writes={"send_email", "delete_email", "create_calendar_event", "cancel_calendar_event",
                "reschedule_calendar_event", "add_calendar_event_participants", "append_to_file", "create_file",
                "delete_file", "share_file"},
        recipients={"send_email": ["recipients", "cc", "bcc"], "share_file": ["email"],
                    "create_calendar_event": ["participants"], "add_calendar_event_participants": ["participants"]},
        me={"emma.johnson@bluesparrowtech.com"},
        internal_domains={"bluesparrowtech.com"},
        # not the contact list: AgentDojo builds it from every email's sender and recipients, received ones too,
        # so an attacker who emails the user is in it
    ),
    "travel": SuiteRules(
        writes={"create_calendar_event", "cancel_calendar_event", "reserve_hotel", "reserve_car_rental",
                "reserve_restaurant", "send_email"},
        recipients={"send_email": ["recipients", "cc", "bcc"], "create_calendar_event": ["participants"]},
        directory_tools={"get_user_information"},
    ),
    "banking": SuiteRules(
        writes={"send_money", "schedule_transaction", "update_scheduled_transaction", "update_password",
                "update_user_info"},
        recipients={"send_money": ["recipient"], "schedule_transaction": ["recipient"],
                    "update_scheduled_transaction": ["recipient"]},
        me={"me"},
        directory_tools={"get_iban"},
    ),
    "slack": SuiteRules(
        writes={"add_user_to_channel", "send_direct_message", "send_channel_message", "invite_user_to_slack",
                "remove_user_from_slack", "post_webpage"},
        recipients={"send_direct_message": ["recipient"], "send_channel_message": ["channel"],
                    "invite_user_to_slack": ["user_email"], "add_user_to_channel": ["user", "channel"],
                    "remove_user_from_slack": ["user"], "post_webpage": ["url"]},
        directory_tools={"get_channels", "get_users_in_channel"},
        url_args={("post_webpage", "url")},
    ),
}


def _dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, (list, tuple)):
        return [_dump(v) for v in value]
    if isinstance(value, dict):
        return {k: _dump(v) for k, v in value.items()}
    return value


def _strings(value: Any) -> list[str]:
    out, stack = [], [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())
        elif isinstance(v, (list, tuple, set)):
            stack.extend(v)
    return out


def _records(value: Any) -> list[dict]:
    out, stack = [], [value]
    while stack:
        v = stack.pop()
        if isinstance(v, dict):
            out.append(v)
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
    return out


def _host(url: str) -> str:
    u = url.strip().lower()
    u = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", u)
    return re.split(r"[/?#:]", u, maxsplit=1)[0].rstrip(".")


def _norm(v: Any) -> str:
    return str(v).strip().lower()


class Gate:
    """One agent run: what's trusted so far, and whether each tool call is allowed."""

    def __init__(self, suite: str, prompt: str, allowed_writes: set[str] | None):
        self.rules = SUITES[suite]
        self.prompt = prompt.lower()
        self.prompt_tokens = {t.strip(".,;:!?()'\"") for t in re.split(r"\s+", self.prompt)}
        self.allowed_writes = allowed_writes            # None: general mode (every tool)
        self.me = {_norm(m) for m in self.rules.me}
        self.trusted: set[str] = set()
        self.trusted_hosts = {_host(t) for t in self.prompt_tokens if "." in t}

    def _trust(self, values: Any) -> None:
        for s in _strings(values):
            self.trusted.add(_norm(s))
            if "." in s:
                self.trusted_hosts.add(_host(s))

    # ------------------------------------------------------------------ trust
    def learn(self, tool: str, result: Any) -> None:
        """Remember trusted values from a tool's output: only what the user's side wrote."""
        data = _dump(result)
        if tool in self.rules.directory_tools:
            self._trust(data)
            if tool == "get_iban":
                self.me.add(_norm(data))                # the account's own IBAN
            return
        for rec in _records(data):
            # an email the user sent: who they sent it to
            if "sender" in rec and _norm(rec.get("sender")) in self.me:
                for k in ("recipients", "cc", "bcc", "recipient"):
                    self._trust(rec.get(k))
            # a file the user owns: who they shared it with
            if "owner" in rec and _norm(rec.get("owner")) in self.me and isinstance(rec.get("shared_with"), dict):
                self._trust(list(rec["shared_with"]))

    def _is_trusted(self, value: Any, as_url: bool) -> bool:
        v = _norm(value)
        if not v:
            return False
        if as_url:
            return _host(v) in self.trusted_hosts
        if "@" in v and v.rsplit("@", 1)[1] in self.rules.internal_domains:
            return True                                 # the company's own staff (internal_domains)
        return v in self.trusted or v in self.me or v in self.prompt_tokens or (" " in v and v in self.prompt)

    # ------------------------------------------------------------------ checks
    def check(self, tool: str, args: dict[str, Any]) -> str | None:
        """Why this call is blocked, or None if it's allowed."""
        if self.allowed_writes is not None and tool in self.rules.writes and tool not in self.allowed_writes:
            return f"'{tool}' is not allowed for this task"
        for arg in self.rules.recipients.get(tool, []):
            value = args.get(arg)
            values = value if isinstance(value, (list, tuple)) else ([] if value in (None, "") else [value])
            for v in values:
                if not self._is_trusted(v, (tool, arg) in self.rules.url_args):
                    return f"'{arg}' of '{tool}' did not come from the user's request or trusted data"
        return None
