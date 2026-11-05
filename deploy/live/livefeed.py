# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""The live demo's feed: what the agent is doing right now, safe to show anyone.

Every email the agent handles, each step it takes (with and without Eurycleia), what Eurycleia blocked and why,
refunds waiting for a person, and the result. It's saved next to the other results (live-feed.json) and, when
EURYCLEIA_DEMO_URL is set, published to a public web page (Azure Storage's static website) for demo.html.

The page is public, so nothing personal or secret goes in it, even made-up: email addresses become the customer's
id ("C024") or "an outside address", payment ids "a payment", phone and card numbers "a phone number" and
"a card number", chat channels "the team channel", canary codes "[canary]". Tool results (what the agent read)
are never published, only what it did.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from datetime import datetime, timezone
from email.utils import formatdate
from pathlib import Path
from typing import Any

MAX_EMAILS = 30            # how many recent emails the page shows
MAX_STEPS = 40             # per run
PUBLISH_EVERY = 2.0        # seconds between uploads while busy

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.I)
PAYMENT_RE = re.compile(r"\b(?:pi|ch|re|cus|pm|in)_[A-Za-z0-9]{6,}\b")
CHANNEL_RE = re.compile(r"\b[CGD][A-Z0-9]{8,12}\b")
CANARY_RE = re.compile(r"CANARY[-_ ]?[A-Z0-9]{6,}", re.I)
MAIL_ID_RE = re.compile(r"\bM\d{10,}[\w-]*")
PHONE_RE = re.compile(r"(?<![\w])(?:\+?61[ -]?|0)\d(?:[ -]?\d){7,8}(?![\w])")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


class Feed:
    def __init__(self, data: Path, company: dict, inbox: str, publish_url: str | None = None,
                 token: Callable[[], str] | None = None, transport: Any = None,
                 clock: Callable[[], float] = time.monotonic):
        self.path = Path(data) / "live-feed.json"
        self.company, self.inbox = company, inbox.lower()
        self.publish_url = (publish_url or "").rstrip("/") or None
        self.token, self.transport, self.clock = token, transport, clock
        self._last_publish = -1e9
        self._warned = False
        self._customers = {c["email"].lower(): c["customer_id"] for c in company.get("customers", [])}
        try:
            self.state: dict = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.state = {}
        self.state.setdefault("emails", [])
        self.state.setdefault("totals", {})
        self._current: dict | None = None
        self._config = ""

    # ---------------------------------------------------------------- what's safe to show
    def public(self, text: Any, limit: int = 200) -> str:
        t = str(text or "")
        t = CANARY_RE.sub("[canary]", t)

        def addr(m: re.Match) -> str:
            a = m.group(0).lower()
            if a in self._customers:
                return self._customers[a]
            domain = (self.company.get("company") or {}).get("domain", "")
            if domain and a.endswith("@" + domain):
                return "a staff address"
            return "an outside address"
        t = EMAIL_RE.sub(addr, t)
        t = PAYMENT_RE.sub("a payment", t)
        t = CARD_RE.sub("a card number", t)
        t = PHONE_RE.sub("a phone number", t)
        t = CHANNEL_RE.sub("the team channel", t)
        t = MAIL_ID_RE.sub("this email", t)
        t = re.sub(r"\s+", " ", t).strip()
        return t if len(t) <= limit else t[: limit - 1].rstrip() + "…"

    # ---------------------------------------------------------------- recording
    def start(self, settings: Any, model: str) -> None:
        self.state.update({"running": True, "model": model, "mode": settings.mode,
                           "approver": getattr(settings, "approver", "")})
        self.publish(force=True)

    def stop(self) -> None:
        self.state["running"] = False
        self.publish(force=True)

    def email(self, ticket: dict | None, subject: str, body: str, customer_id: str | None, round_: int,
              configs: list[str]) -> None:
        if self.state.get("round") != round_:              # a new round starts with fresh totals
            self.state["round"], self.state["totals"] = round_, {}
        entry = {"id": f"{round_}-{(ticket or {}).get('ticket_id') or 'outside'}-{len(self.state['emails'])}",
                 "at": _now(), "ticket": (ticket or {}).get("ticket_id"),
                 "kind": (ticket or {}).get("kind", "outside email"), "tier": (ticket or {}).get("tier", "basic"),
                 "probes": (ticket or {}).get("probes", ""), "customer": customer_id,
                 "subject": self.public(subject, 90), "snippet": self.public(body, 220),
                 "runs": {c: {"status": "waiting", "steps": [], "result": None} for c in configs}}
        self.state["emails"] = [entry, *self.state["emails"]][:MAX_EMAILS]
        self._current = entry
        self.publish()

    def run(self, config: str) -> None:
        self._config = config
        if self._current and config in self._current["runs"]:
            self._current["runs"][config]["status"] = "running"
            self.publish()

    def step(self, tool: str, args: dict, outcome: str, why: str = "") -> None:
        if not self._current or self._config not in self._current["runs"]:
            return
        steps = self._current["runs"][self._config]["steps"]
        if len(steps) < MAX_STEPS:
            steps.append({"t": _now(), "tool": tool, "what": self.describe(tool, args), "outcome": outcome,
                          "why": self.public(why, 160)})
        self.publish(force=outcome in ("approval", "blocked"))

    def end(self, row: dict) -> None:
        if not self._current or row["config"] not in self._current["runs"]:
            return
        run = self._current["runs"][row["config"]]
        run["status"] = "done"
        run["result"] = {"leaked": bool(row["leaked"]), "leaks": [self.public(x, 120) for x in row["leaks"][:4]],
                         "done": bool(row["done"]), "blocked": row["blocked"],
                         "unwanted_refund": bool(row.get("unwanted_refund")),
                         "approvals": row.get("approvals") or {}}
        t = self.state["totals"].setdefault(row["config"], {
            "emails": 0, "leaked": 0, "attacks": 0, "attacks_leaked": 0, "normal": 0, "normal_done": 0,
            "blocked": 0, "unwanted_refunds": 0, "approvals_asked": 0, "approvals_given": 0})
        t["emails"] += 1
        t["leaked"] += bool(row["leaked"])
        t["blocked"] += row["blocked"]
        t["unwanted_refunds"] += bool(row.get("unwanted_refund"))
        t["approvals_asked"] += (row.get("approvals") or {}).get("asked", 0)
        t["approvals_given"] += (row.get("approvals") or {}).get("approved", 0)
        if row["kind"] == "attack":
            t["attacks"] += 1
            t["attacks_leaked"] += bool(row["leaked"])
        elif row["kind"] == "normal":
            t["normal"] += 1
            t["normal_done"] += bool(row["done"])
        self.publish(force=True)

    def describe(self, tool: str, args: dict) -> str:
        a = args or {}
        if tool == "get_ticket":
            return "Read the email"
        if tool == "get_customer":
            return f"Looked up customer {self.public(a.get('customer_id'), 20)}"
        if tool == "get_doc":
            return f"Read the help document '{self.public(a.get('name'), 40)}'"
        if tool == "send_email":
            return f"Email to {self.public(a.get('to'), 60)}: {self.public(a.get('subject'), 70)}"
        if tool == "refund":
            amount = a.get("amount")
            return f"Refund {self.public(a.get('payment_intent'), 30)}" + (f" of ${amount}" if amount else "")
        if tool == "post_slack":
            return f"Team chat: {self.public(a.get('text'), 110)}"
        return self.public(f"{tool}", 40)

    # ---------------------------------------------------------------- saving and publishing
    def publish(self, force: bool = False) -> None:
        self.state["updated"] = _now()
        body = json.dumps(self.state, ensure_ascii=False).encode()
        try:
            self.path.write_bytes(body)
        except OSError:
            pass
        if not self.publish_url or (not force and self.clock() - self._last_publish < PUBLISH_EVERY):
            return
        self._last_publish = self.clock()
        try:
            put_blob(f"{self.publish_url}/live/feed.json", body, self.token, self.transport)
        except Exception as e:  # noqa: BLE001 - the demo page is a nice-to-have; the test carries on
            if not self._warned:
                print(f"live demo: couldn't publish ({str(e)[:160]})", flush=True)
                self._warned = True


def put_blob(url: str, body: bytes, token: Callable[[], str] | None, transport: Any = None) -> None:
    """Upload one file to Azure Blob Storage, signed in as the job's own identity (no storage key)."""
    if not url.startswith("https://"):
        raise ValueError("the demo URL must use https")
    if transport is None:
        from eurycleia.connectors.base import urllib_transport
        transport = urllib_transport(timeout=15)
    headers = {"x-ms-version": "2023-11-03", "x-ms-date": formatdate(usegmt=True), "x-ms-blob-type": "BlockBlob",
               "Content-Type": "application/json", "x-ms-blob-content-type": "application/json",
               "x-ms-blob-cache-control": "no-cache, max-age=0"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token()}"
    r = transport("PUT", url, headers, body)
    if r.status >= 300:
        raise RuntimeError(f"HTTP {r.status}")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
