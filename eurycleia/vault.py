# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""The vault: task-scoped reads, placeholders for secrets, owner-bound outbound checks.

The agent never talks to source systems. It asks the vault for data inside a
Task, and every outbound action goes back through the same Task:

    vault = Vault(policy, sources={...}, sinks={...})
    task = vault.start_task("support_reply", customer_id=12)   # trusted input only
    customer = task.read("crm.customer")                          # scoped to customer 12
    task.act("email.send", to=customer["email"], body="...")     # checked before it runs

Guarantees enforced here (see docs/threat-model.md):
  1. A task can only read records and fields its template allows, keyed from
     trusted inputs - never from what the model asks for.
  2. Secret fields never reach the model: they are swapped for placeholders and
     only turned back into real values for sinks allowed to receive them.
  3. Protected values only flow to their owner (customer 12's data only to
     customer 12's verified address) or, for company data, internal domains.
  4. Recipients must come from trusted data, never from untrusted content.
  5. Every read and action is recorded in a hash-chained audit log.

Guarantee 3 is enforced here by matching values in outbound arguments. For
guarantees that survive rewording and encoding, use `eurycleia.planner`, which
tracks labels through the data flow instead of matching strings.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import itertools
import json
import logging
import os
import re
import secrets
import threading
import unicodedata
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .boxes import BoxLocked, is_box_ref
from .cache import EncryptedCache
from .crypto import Cipher
from .derive import compute as derive_value
from .detect import redact_secrets
from .errors import EurycleiaError
from .policy import Policy, SinkRule, TaskTemplate

log = logging.getLogger("eurycleia")

TOKEN_RE = re.compile(r"\[\[vault:([a-z0-9_]+):([a-f0-9]{8})\]\]")
LOOSE_TOKEN_RE = re.compile(r"\[\[\s{0,8}vault\s{0,8}:[^\]]{0,200}\]\]?", re.I)   # anything like a placeholder
MIN_MATCH_LEN = 4  # shorter values produce too many false matches
_NO_RULE = SinkRule()


class Blocked(EurycleiaError):
    """Raised when the vault refuses a read or an action. `reason` is safe to show the model."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class SinkError(EurycleiaError):
    """A sink (your own code) raised an error. The message has real values masked, as the model may see it."""


@dataclass(frozen=True)
class Label:
    level: str          # secret | protected | normal
    owner: str          # "company" or e.g. "customer_id:12"
    source: str
    field: str
    trust: str = "trusted"


@dataclass
class ApprovalRequest:
    task_id: int
    template: str
    sink: str
    reason: str
    args: dict[str, Any]   # as the agent sent them: placeholders, not real secrets


Approver = Callable[[ApprovalRequest], bool]


@dataclass
class FlagEvent:
    """An allowed action worth a human look (medium risk, or unusual for this task)."""
    task_id: int
    template: str
    sink: str
    reasons: list[str]


class Vault:
    def __init__(self, policy: Policy,
                 sources: dict[str, Callable[[Any], dict | None]],
                 sinks: dict[str, Callable[..., Any]],
                 audit: AuditLog | None = None,
                 mode: str = "enforce",
                 cipher: Cipher | None = None,
                 cache: EncryptedCache | None = None,
                 approver: Approver | None = None,
                 boxes: Any = None,
                 on_flag: Callable[[FlagEvent], None] | None = None,
                 model: str = "external"):
        if mode not in ("enforce", "shadow"):
            raise ValueError("mode must be 'enforce' or 'shadow'")
        if model not in ("external", "internal"):
            raise ValueError("model must be 'external' (a hosted AI service) or 'internal' (self-hosted)")
        self.model = model
        for name in policy.sources:
            if name not in sources:
                raise ValueError(f"policy source {name!r} has no connector")
        self.policy, self.sources, self.sinks = policy, sources, sinks
        self.audit = audit if audit is not None else AuditLog()
        self.mode, self.cipher, self.cache = mode, cipher, cache
        self.approver, self.on_flag, self.boxes = approver, on_flag, boxes
        self._fp_key = os.urandom(32)
        self._task_ids = itertools.count(1)
        # task ids are unique across processes (several MCP servers, restarts) writing to one audit log
        self._run = secrets.token_hex(4)

    # ---------------------------------------------------------------- helpers
    def fp(self, value: Any) -> str:
        """Keyed fingerprint so logs can correlate values without storing them."""
        if self.cipher:
            return self.cipher.fingerprint(value)
        return hmac.new(self._fp_key, str(value).encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:16]

    def pseudonym(self, value: Any, source: str, field: str) -> str:
        """A stable, readable stand-in for a real value. Same input -> same pseudonym."""
        pid = self.fp(f"pseudo\x00{source}\x00{field}\x00{value}")[:6]
        text = str(value)
        if "@" in text and " " not in text.strip():
            return f"{field.replace('_', '-')}-{pid}@pseudonym.invalid"
        return f"{field.replace('_', ' ').title().replace(' ', '')}-{pid.upper()}"

    def start_task(self, template: str, **trusted: Any) -> Task:
        if template not in self.policy.tasks:
            raise KeyError(f"no task template {template!r}")
        t = self.policy.tasks[template]
        missing = [k for k in t.trusted if trusted.get(k) in (None, "")]
        if missing:
            raise ValueError(f"task {template!r} needs trusted inputs: {missing}")
        task = Task(self, t, f"{self._run}-{next(self._task_ids)}", trusted)
        self.audit.record("task.start", task=task.id, template=template,
                          trusted={k: self.fp(v) for k, v in trusted.items()})
        return task

    def _fetch(self, source: str, key: Any) -> dict | None:
        """Read-through: short-lived encrypted cache first, then the source system."""
        if self.cache is not None:
            hit = self.cache.get(source, key)
            if hit is not None:
                return hit
        record = self.sources[source](key)
        if record is not None and self.cache is not None:
            self.cache.put(source, key, record)
        return record

    def _owner_contact(self, owner: str) -> str | None:
        """The verified destination for a data owner, e.g. customer 12's email on file."""
        if owner == "company" or ":" not in owner:
            return None
        key_name, key = owner.split(":", 1)
        for src in self.policy.sources.values():
            if src.owner == key_name and src.owner_contact and src.trust == "trusted":
                rec = self._fetch(src.name, _coerce(key))
                if rec and rec.get(src.owner_contact):
                    return rec[src.owner_contact]
        return None

    def _owner_domain(self, owner: str) -> str | None:
        """A business customer's own email domain on file (owner_domain), e.g. account 7's acme-corp.example.
        None if there isn't one, or if it isn't a usable company domain (see company_domain)."""
        if owner == "company" or ":" not in owner:
            return None
        key_name, key = owner.split(":", 1)
        for src in self.policy.sources.values():
            if src.owner == key_name and src.owner_domain and src.trust == "trusted":
                rec = self._fetch(src.name, _coerce(key))
                if rec and (domain := company_domain(rec.get(src.owner_domain), self.policy.shared_email_domains)):
                    return domain
        return None


class Task:
    def __init__(self, vault: Vault, template: TaskTemplate, task_id: int | str, trusted: dict[str, Any]):
        self.vault, self.template, self.id, self.trusted = vault, template, task_id, trusted
        self._tokens: dict[str, tuple[Any, Label]] = {}   # placeholder -> (sealed value, label)
        self._seen: dict[str, Label] = {}                   # protected/secret value -> label
        self._calls: dict[str, int] = {}
        self._reported: set[str] = set()
        self._pseudo: dict[str, Any] = {}                   # pseudonym -> real value
        self._revealed: dict[str, Any] = {}                 # placeholder -> value opened from a deposit box
        self._used = {"reads": 0, "records": set(), "fields": set()}   # for the task's data budget
        # For the audit log's recipient relations (see _relation): whose contact each address is, and which
        # addresses appeared in untrusted content. Kept in memory for this task only; the log gets labels.
        self._contacts: dict[str, set[str]] = {}
        self._untrusted_addresses: set[str] = set()
        self._unscanned = False                 # some untrusted text was too long to scan in full
        self._mentioned_domains: set[str] = set()   # domains written after an "@" in untrusted text
        # One read or action at a time per task, so call limits and data budgets hold when an agent framework
        # runs tool calls in parallel. The sink itself runs outside the lock (see act).
        self._lock = threading.RLock()
        self._flags: list[FlagEvent] = []                   # flags waiting for on_flag, called outside the lock

    # ------------------------------------------------------------------ reads
    def read(self, source: str, key: Any = None, fields: list[str] | None = None) -> dict[str, Any]:
        """Return one record for the model: only allowed fields (or just the ones asked for),
        secrets as placeholders, personal details as stand-ins, free text scrubbed, plus any
        safe summaries the policy defines."""
        try:
            with self._lock:
                return self._read(source, key, fields)
        finally:
            self._fire_flags()

    def _read(self, source: str, key: Any, fields: list[str] | None) -> dict[str, Any]:
        self._reported = set()
        if source not in self.vault.policy.sources:
            self._decide("read", "unknown source", shown=f"unknown source {source!r}",
                         source=self.vault.fp(source))
            raise KeyError(f"unknown source {source!r}")
        rule = self.template.reads.get(source)
        allowed_keys = self.allowed_keys(source)
        if key is None and len(allowed_keys) == 1:
            key = allowed_keys[0]
        in_scope = rule is not None and str(key) in {str(k) for k in allowed_keys}
        if not in_scope:
            self._decide("read", f"{source} record is outside this task's scope",
                         shown=f"{source}:{key} is outside this task's scope",
                         source=source, key=self.vault.fp(key))
            rule = {"fields": None}   # shadow mode only: observe what an unscoped read returns
        derive = rule.get("derive") or {}
        record = self.vault._fetch(source, key)
        if record is None:
            raise KeyError(f"{source}:{key} not found")
        src = self.vault.policy.sources[source]
        allowed = list(rule.get("fields") or [f for f in record if f not in derive])

        # Fields on request: the model names what it needs; nothing else is returned.
        if isinstance(fields, (list, tuple)) and not fields:
            fields = None                    # an empty list means "no preference", not "nothing"
        if fields is None and rule.get("on_request"):
            self.vault.audit.record("read", task=self.id, source=source, key=self.vault.fp(key), fields=[],
                                    decision="allow", note="listed available fields")
            return {"available_fields": sorted([*allowed, *derive]),
                    "note": "ask again with fields=[...] for just the ones you need"}
        if fields is not None:
            if not isinstance(fields, (list, tuple)) or not all(isinstance(f, str) for f in fields):
                self._decide("read", "fields must be a list of names", source=source)
                fields = []
            unknown = sorted(set(fields) - set(allowed) - set(derive))
            if unknown:
                known = [f for f in unknown if f in src.fields]   # names from the policy only, never the agent's text
                self._decide("read", f"asked for {len(unknown)} field(s) this task can't see",
                             shown=f"this task can't see {unknown} in {source}", source=source,
                             unknown_fields=known, unknown_other=len(unknown) - len(known))
            wanted = [f for f in dict.fromkeys(fields) if f in allowed or f in derive]
        else:
            wanted = [*allowed, *derive]

        if self.vault.mode == "shadow":       # only watch mode's log is learned from (eurycleia learn)
            self._note_addresses(source, src, key, record, wanted, in_scope)
        self._spend(source, key, wanted)
        owner = owner_of(src, key, record)
        internal = self.vault.model == "internal"
        out: dict[str, Any] = {}
        for f in wanted:
            if f in derive:                                    # a safe summary, never the value itself
                out[f] = derive_value(derive[f], record)
                continue
            if f not in record:
                continue
            label = Label(src.level(key, f, record), owner, source, f, src.trust)
            value = record[f]
            if isinstance(value, str) and value.startswith("tvref_"):
                # a reference from the secret store retired in 0.5: never pass it on as if it were the value
                self._decide("read", "record holds a reference from the retired secret store",
                             shown=f"{source}.{f} holds an old eurycleia secret-store reference; move the "
                                   "secrets into deposit boxes (eurycleia boxes put)", source=source)
                continue
            if label.level == "secret" or is_box_ref(value):
                # high-tier box items stay locked: only a reference is sealed, opened at the sink
                out[f] = self._seal(value, label)
                continue
            if label.level == "protected":
                self._remember(value, label)
            as_is = internal and f in src.internal_may_see
            if f in src.pseudonymize and value not in (None, "") and not as_is:
                p = self.vault.pseudonym(value, source, f)
                self._pseudo[p] = value
                value = p
            elif isinstance(value, str) and ("*" in src.scrub or f in src.scrub):
                value = self._scrub(value, label, record, src, keep_personal=as_is)
            out[f] = value
        self.vault.audit.record("read", task=self.id, source=source, key=self.vault.fp(key),
                                fields=sorted(out), decision="allow")
        return out

    def _spend(self, source: str, key: Any, fields: list[str]) -> None:
        """Count this read against the task's data budget (reads, distinct records, distinct fields)."""
        budget = self.template.budget
        used = self._used
        rec = (source, self.vault.fp(key))
        new_fields = {(rec, f) for f in fields}
        after = {"reads": used["reads"] + 1, "records": len(used["records"] | {rec}),
                 "fields": len(used["fields"] | new_fields)}
        for k, limit in budget.items():
            if after[k] > limit:
                self._flag("read", [f"data budget: more than {limit} {k} in one task"])
                self._decide("read", f"data budget exceeded: at most {limit} {k} per task", source=source)
        used["reads"] += 1
        used["records"].add(rec)
        used["fields"] |= new_fields

    def _scrub(self, text: str, label: Label, record: dict[str, Any], src: Any, keep_personal: bool) -> str:
        """Free text: secrets found inside become placeholders; emails and phone numbers become
        stand-ins; this record's own pseudonymised values (e.g. the customer's name) too."""
        from .detect import KINDS, scan_text
        out, last = [], 0
        for kind, s, e in scan_text(text):
            piece = text[s:e]
            level = KINDS[kind].level
            if level == "secret":
                repl = self._seal(piece, Label("secret", label.owner, label.source, f"text_{kind}", label.trust))
            elif level == "protected" and kind in ("email", "phone") and not keep_personal:
                repl = self.vault.pseudonym(piece, label.source, kind)
                self._pseudo[repl] = piece
                self._remember(piece, label)
            else:
                continue
            out += [text[last:s], repl]
            last = e
        text = "".join(out + [text[last:]])
        if not keep_personal:
            for f in src.pseudonymize:
                v = record.get(f)
                if isinstance(v, str) and len(v) >= MIN_MATCH_LEN and v in text:
                    p = self.vault.pseudonym(v, label.source, f)
                    self._pseudo[p] = v
                    text = text.replace(v, p)
        return text

    def allowed_keys(self, source: str) -> list[Any]:
        rule = self.template.reads.get(source) or {}
        keys = rule.get("keys", [rule["key"]] if "key" in rule else [])
        out = []
        for k in keys:
            m = re.fullmatch(r"\{(\w+)\}", k) if isinstance(k, str) else None
            out.append(self.trusted[m.group(1)] if m else (k.format(**self.trusted) if isinstance(k, str) else k))
        return out

    def _seal(self, value: Any, label: Label) -> str:
        token = f"[[vault:{label.field}:{secrets.token_hex(4)}]]"
        sealed = self.vault.cipher.encrypt(value, aad=token) if self.vault.cipher else value
        self._tokens[token] = (sealed, label)
        self._seen[str(value)] = label
        return token

    def _unseal(self, token: str, sink: str = "?") -> Any:
        sealed, _ = self._tokens[token]
        value = self.vault.cipher.decrypt(sealed, aad=token) if self.vault.cipher else sealed
        if is_box_ref(value):
            if self.vault.boxes is None:
                raise BoxLocked("this value is in a deposit box but no box store is configured")
            # second key: the holder's (may ask a person to approve)
            value = self.vault.boxes.reveal(value, task=self.id, reason=f"{self.template.name} -> {sink}")
            self._revealed[token] = value                   # so this task's sink results can be masked
        return value

    def _remember(self, value: Any, label: Label) -> None:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            value = str(value)
        if isinstance(value, str):
            for piece in [value, *[l.strip() for l in value.splitlines()]]:
                if len(piece) >= MIN_MATCH_LEN:
                    self._seen[piece] = label
        elif isinstance(value, (list, dict)):
            for v in (value.values() if isinstance(value, dict) else value):
                self._remember(v, label)

    # ---------------------------------------------------------------- actions
    def act(self, sink: str, **args: Any) -> Any:
        """Check an outbound action, swap placeholders back to real values, then run it.

        Every check below runs in order; in enforce mode the first failure raises Blocked, in shadow mode
        each failure is only recorded as "would block"."""
        # The checks and the call count run under the task's lock, so limits hold when tool calls run in
        # parallel. A human approval, opening a deposit box and the sink itself run outside it, so a slow
        # person or sink doesn't hold up the task's other calls (the call is already counted).
        try:
            with self._lock:
                rule, args, recipient_args, recipients, n, shown = self._prepare(sink, args)
        finally:
            self._fire_flags()
        if rule.approval == "always":
            try:
                self._approve(sink, "policy requires a human to approve this action", shown)
            except Blocked:
                with self._lock:                            # a refused call doesn't use up the limit
                    self._calls[sink] = max(0, self._calls.get(sink, 1) - 1)
                raise
        return self._run_sink(sink, rule, args, recipient_args, recipients, n)

    def _prepare(self, sink: str, args: dict[str, Any]) -> tuple:
        """Every check; then the call is counted. Runs under the task's lock."""
        self._reported = set()
        self._check_shape(sink, args)
        shown = args                                        # what the agent sent (shown in approvals)
        args = {k: self._unpseudo(v) for k, v in args.items()}   # checks run on real values
        if sink not in self.vault.sinks:
            self._decide("act", "unknown sink", shown=f"unknown sink {sink!r}", sink=self.vault.fp(sink))
            raise KeyError(f"unknown sink {sink!r}")   # shadow mode: nothing to run
        rule = self.template.sinks.get(sink)
        if rule is None:
            self._decide("act", f"sink {sink!r} is not allowed for this task", sink=sink)
            rule = _NO_RULE
        n = self._check_arguments_and_limits(sink, rule, args)
        recipient_args, recipients = self._check_recipients(sink, rule, args)
        text = _flatten(args)
        self._check_placeholders(sink, rule, args, text, recipients)
        self._check_raw_values(sink, text, recipients)
        self._check_links(sink, rule, shown, args)
        if self.vault.policy.detect_outbound and recipients:
            from .detect import KINDS, scan_text
            for kind, _s, _e in scan_text(TOKEN_RE.sub(" ", text)):
                if KINDS[kind].level == "secret":
                    self._decide("act", f"outbound message contains what looks like a {KINDS[kind].label}",
                                 sink=sink)
        self._calls[sink] = n
        return rule, args, recipient_args, recipients, n, shown

    def _check_shape(self, sink: str, args: dict[str, Any]) -> None:
        """Arguments nested absurdly deep, or numbers too long to turn into text, can't be checked: refuse them
        (in shadow mode too, since the checks after this couldn't run)."""
        problem = _shape_problem(args)
        if problem:
            self.vault.audit.record("act", task=self.id, sink=self._safe_name(sink), decision="block", reason=problem)
            raise Blocked(problem)

    def _check_arguments_and_limits(self, sink: str, rule: SinkRule, args: dict[str, Any]) -> int:
        if rule.args is not None and (extra := sorted(set(args) - set(rule.args))):
            self._decide("act", f"{sink!r} does not accept some of the arguments given",
                         shown=f"{sink!r} does not accept arguments {extra}", sink=sink)
        n = self._calls.get(sink, 0) + 1
        if rule.max_calls is not None and n > rule.max_calls:
            self._decide("act", f"{sink!r} called more than {rule.max_calls} times in one task", sink=sink)
        return n

    def _check_recipients(self, sink: str, rule: SinkRule, args: dict[str, Any]) -> tuple[list[str], list[Any]]:
        """Every recipient (to, cc, bcc, reply_to, ...) must come from trusted data or the policy."""
        recipient_args = [rule.recipient_arg] if rule.recipient_arg else []
        if rule.recipient_arg:
            recipient_args += [a for a in args if a != rule.recipient_arg and a.lower() in _RECIPIENT_ARGS]
        recipients = [r for a in recipient_args for r in _as_list(args.get(a))]
        if rule.recipient_arg:
            trusted = self._trusted_recipients(rule.allowed_recipients)
            for r in recipients or [None]:
                if not _matches(r, trusted):
                    self._decide("act", "recipient did not come from trusted data",
                                 shown=f"recipient {r!r} did not come from trusted data",
                                 sink=sink, recipient=self.vault.fp(r), relation=self._relation(r))
        return recipient_args, recipients

    def _check_placeholders(self, sink: str, rule: SinkRule, args: dict[str, Any], text: str,
                            recipients: list[Any]) -> None:
        """Placeholders: genuine, from this task, allowed for this sink, and only for their owner."""
        if any(not TOKEN_RE.fullmatch(m.group(0)) for m in LOOSE_TOKEN_RE.finditer(text)):
            self._decide("act", "damaged or forged placeholder", sink=sink)
        for token in sorted(set(m.group(0) for m in TOKEN_RE.finditer(text))):
            field = TOKEN_RE.fullmatch(token).group(1)
            if token not in self._tokens:
                self._decide("act", "unknown or foreign placeholder", sink=sink)
                continue
            if field not in rule.secrets_allowed:
                self._decide("act", f"secret field {field!r} may not be sent to {sink!r}", sink=sink)
            elif isinstance(rule.secrets_allowed, dict):
                want = rule.secrets_allowed[field]
                where = [k for k, v in args.items() if token in _flatten({k: v})]
                if where != [want] or args.get(want) != token:
                    self._decide("act", f"secret field {field!r} may only be passed as {want!r} to {sink!r}",
                                 sink=sink)
            for r in recipients:
                if not self._owner_ok(self._tokens[token][1], r):
                    self._decide("act", "secret would go to someone other than its owner", sink=sink)
        # An argument bound to a secret (secrets_allowed: {card_number: card}) must BE that secret's
        # placeholder, never a value the agent typed: otherwise a fooled agent could refund to, or pay,
        # an account of its own choosing.
        if isinstance(rule.secrets_allowed, dict):
            for field, arg in rule.secrets_allowed.items():
                if arg not in args:
                    continue
                value = args[arg]
                ok = isinstance(value, str) and value in self._tokens and self._tokens[value][1].field == field
                if not ok:
                    self._decide("act", f"{arg!r} must be the vault's placeholder for {field!r}",
                                 shown=f"{arg!r} must be the [[vault:{field}:...]] placeholder from the record, "
                                       f"not a typed value", sink=sink)

    def _check_raw_values(self, sink: str, text: str, recipients: list[Any]) -> None:
        """Raw protected/secret values seen in this task: only to their owner (or internal domains)."""
        lowered = text.lower()
        for value, label in self._seen.items():
            if value.lower() not in lowered:
                continue
            if label.level == "secret":
                self._decide("act", f"raw secret {label.field!r} in outbound action", sink=sink)
            for r in recipients:
                if not self._owner_ok(label, r):
                    self._decide("act", f"{label.source}.{label.field} may not be sent to anyone but its owner",
                                 shown=f"{label.source}.{label.field} (owner {label.owner}) "
                                       f"may not be sent to this recipient", sink=sink,
                                 recipient=self.vault.fp(r))

    def _check_links(self, sink: str, rule: SinkRule, shown: dict[str, Any], args: dict[str, Any]) -> None:
        """Customer data inside a link to someone else's website leaves the company as soon as the link is
        opened (or an image in an email loads), whoever the message is addressed to. So a link to a site
        outside internal_domains / link_domains may not carry any protected or secret value this task has
        seen, a placeholder, or a stand-in (which the vault would otherwise turn back into the real value)."""
        allowed = [*self.vault.policy.internal_domains, *self.vault.policy.link_domains]
        values = [v for v in self._seen if len(v) >= MIN_MATCH_LEN]
        stand_ins = list(self._pseudo)
        for which, strings in (("shown", _strings(shown)), ("real", _strings(args))):
            for text in strings:
                for url in _urls(text):
                    if _host_allowed(url, allowed):
                        continue
                    forms = [(f, re.sub(r"[\W_]", "", f)) for f in _url_forms(url)]
                    hit = any(TOKEN_RE.search(f) for f, _ in forms)
                    if which == "shown":
                        hit = hit or any(p.lower() in f for p in stand_ins for f, _ in forms)
                    else:
                        hit = hit or any(_in_link(v, f, sq) for v in values for f, sq in forms)
                    if hit:
                        self._decide("act", "customer data inside a link to an outside website",
                                     shown="a link in this action points to a website outside the company and "
                                           "carries customer data; links may only carry customer data to the "
                                           "company's own sites", sink=sink)
                        return

    def _secret_values(self) -> list[str]:
        """The real values of every secret this task has handed out as a placeholder and could unlock (a box
        item only once opened), for masking encoded copies of them in sink results."""
        return [real for real, token in self._mask_map({}, {}).items() if TOKEN_RE.fullmatch(token)]

    def _run_sink(self, sink: str, rule: SinkRule, args: dict[str, Any], recipient_args: list[str],
                  recipients: list[Any], n: int) -> Any:
        """All checks passed (or shadow mode) and the call is counted: unlock placeholders, run the sink and
        mask what comes back. Runs outside the task's lock."""
        classes = [self._recipient_class(r, rule) for r in recipients]
        relations = [self._relation(r) for r in recipients]
        sizes = {k: len(str(v)) for k, v in args.items()}
        if self.vault.mode == "enforce":
            for a in recipient_args:     # the sink gets the checked address, not the text the agent wrote
                v = args.get(a)
                if isinstance(v, str) and v.strip():
                    args[a] = ", ".join(_canonical(x) for x in _as_list(v))
                elif isinstance(v, (list, tuple)):
                    args[a] = [_canonical(x) for x in v]
        try:
            resolved = {k: self._resolve(v, sink) for k, v in args.items()}
        except BoxLocked as e:
            self.vault.audit.record("act", task=self.id, sink=sink, decision="block", reason=f"box locked: {e}")
            raise Blocked(f"box locked: {e}") from e
        except Exception as e:  # noqa: BLE001 - damaged or missing stored secret: fail closed, and log it
            self.vault.audit.record("act", task=self.id, sink=sink, decision="block",
                                    reason=f"a stored secret couldn't be unlocked ({type(e).__name__})")
            raise Blocked("a stored secret couldn't be unlocked; the action was not run") from None
        self.vault.audit.record("act", task=self.id, sink=sink, args=[self._safe_name(a) for a in sorted(args)],
                                recipients=[self.vault.fp(r) for r in recipients], recipient_classes=classes,
                                recipient_relations=relations,
                                arg_sizes={self._safe_name(k): v for k, v in sizes.items()}, call=n,
                                decision="allow")
        if rule.risk == "medium":
            self._flag(sink, ["medium-risk action"])
            self._fire_flags()
        with self._lock:                                    # a consistent view of what this task handed out
            mask = self._mask_map(args, resolved)
            secrets_out = self._secret_values()
        try:
            result = self.vault.sinks[sink](**resolved)
        except Exception as e:  # noqa: BLE001 - the error text may quote real values; mask them
            text = redact_secrets(_mask(str(e), mask, secrets_out))
            raise SinkError(f"{sink} failed: {type(e).__name__}: {text}") from None
        result = _mask(result, mask, secrets_out)
        if self.vault.mode == "shadow":            # what an action returns (a web page, search results) is outside
            with self._lock:                       # content too: remember its addresses for the audit log's labels
                self._note_untrusted(result)
        # second net: secret-looking data this task never handed out (e.g. another customer's card that the
        # sink's own code looked up) is removed too, so it can't reach the model through a result
        caught: set[str] = set()
        result = redact_secrets(result, caught)
        if caught:
            self.vault.audit.record("sink.result_redacted", task=self.id, sink=sink, kinds=sorted(caught))
        if self.vault.cache is not None:
            for src in rule.invalidates:
                self.vault.cache.invalidate_source(src)
        return result

    # ------------------------------------------------------------- tool layer
    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Dispatch an agent-facing tool name using the policy's `tools` map."""
        with self._lock:
            tm = self._tool_for(name, arguments)
        if tm.read:
            key = arguments.get(tm.key_arg) if tm.key_arg and arguments else None
            return self.read(tm.read, key, fields=(arguments or {}).get("fields"))
        return self.act(tm.act, **dict(arguments or {}))

    def _tool_for(self, name: str, arguments: dict[str, Any] | None) -> Any:
        arguments = dict(arguments or {})
        tm = self.vault.policy.tools.get(name)
        if tm is None:
            self._decide("act", "tool is not exposed", shown=f"tool {name!r} is not exposed",
                         tool=self.vault.fp(name))
            raise Blocked(f"tool {name!r} is not exposed")
        for arg, kind in (tm.params or {}).items():     # the declared JSON types, checked before anything runs
            if arg in arguments and not _json_type_ok(arguments[arg], kind):
                self._decide("act", f"tool argument has the wrong type (expected {kind})",
                             shown=f"argument {arg!r} of {name!r} must be a {kind}", tool=name)
        return tm

    def tool_specs(self) -> list[dict[str, Any]]:
        """Tool definitions (name, description, JSON schema) for this task, for LLM adapters."""
        specs = []
        for tm in self.vault.policy.tools.values():
            if tm.read and tm.read not in self.template.reads:
                continue
            if tm.act and tm.act not in self.template.sinks:
                continue
            props: dict[str, Any] = {k: {"type": v} for k, v in tm.params.items()}
            required = list(tm.params)
            if tm.read and tm.key_arg and tm.key_arg not in props:
                props[tm.key_arg] = {"type": "string", "description": RECORD_ID}
            if tm.read:
                rule = self.template.reads.get(tm.read) or {}
                names = sorted([*(rule.get("fields") or []), *(rule.get("derive") or {})])
                if names:
                    props["fields"] = {"type": "array", "items": {"type": "string", "enum": names},
                                       "description": "only the fields you need" +
                                                      (" (required)" if rule.get("on_request") else " (optional)")}
            specs.append({"name": tm.name, "description": tm.description or (tm.read or tm.act),
                          "input_schema": {"type": "object", "properties": props, "required": required}})
        return specs

    # ---------------------------------------------------------------- checks
    def _trusted_recipients(self, specs: list[str]) -> list[str]:
        out = []
        for spec in specs:
            spec = spec.format(**self.trusted)
            if spec.startswith("*@") and (d := _source_ref(spec[2:])) and d[0] in self.vault.policy.sources:
                # e.g. *@crm.account:7.domain -> anyone at that business customer's own domain, looked up by
                # the vault from trusted data
                src = self.vault.policy.sources[d[0]]
                rec = self.vault._fetch(d[0], _coerce(d[1])) if src.trust == "trusted" else None
                if rec and (domain := company_domain(rec.get(d[2]), self.vault.policy.shared_email_domains)):
                    out.append("*@" + domain)
                continue
            m = re.fullmatch(r"([\w.]+):([^.]+)\.(\w+)", spec)
            if m and m.group(1) in self.vault.policy.sources:
                # e.g. crm.customer:12.email -> looked up by the vault itself, not by the model
                src = self.vault.policy.sources[m.group(1)]
                if src.trust != "trusted":
                    continue
                rec = self.vault._fetch(m.group(1), _coerce(m.group(2)))
                if rec and rec.get(m.group(3)):
                    # values from records are addresses, never patterns ('*' and '?' are legal in an address)
                    out.extend(LITERAL + _norm(v, unicode_ok=True) for v in _as_list(rec[m.group(3)]))
            else:
                out.append(_norm_pattern(spec))   # literal address or glob like *@acme.example
        return out

    def _owner_ok(self, label: Label, recipient: Any) -> bool:
        """Protected data may go to its owner, or to the company's own domains (it already holds it)."""
        r = _norm(recipient, unicode_ok=True)
        if r in ("", _INVALID):
            return False
        src = self.vault.policy.sources.get(label.source)
        shareable = src is None or src.share_internally or label.owner == "company"
        if shareable and "@" in r and r.rsplit("@", 1)[-1] in self.vault.policy.internal_domains:
            return True
        if label.owner == "company":
            return False
        contact = self.vault._owner_contact(label.owner)
        if contact is not None and _norm(contact, unicode_ok=True) == r:
            return True
        domain = self.vault._owner_domain(label.owner)
        return domain is not None and r.isascii() and "@" in r and r.rsplit("@", 1)[1] == domain

    def _approve(self, sink: str, reason: str, args: dict[str, Any]) -> None:
        req = ApprovalRequest(self.id, self.template.name, sink, reason, dict(args))
        ok = bool(self.vault.approver and self.vault.approver(req))
        self.vault.audit.record("approval", task=self.id, sink=sink, reason=reason,
                                decision="approved" if ok else "denied")
        if not ok:
            raise Blocked(f"{reason}: {'denied' if self.vault.approver else 'no approver configured'}")

    def _resolve(self, value: Any, sink: str = "?") -> Any:
        if isinstance(value, str):
            return TOKEN_RE.sub(lambda m: str(self._unseal(m.group(0), sink)) if m.group(0) in self._tokens
                                else m.group(0), value)
        if isinstance(value, list):
            return [self._resolve(v, sink) for v in value]
        if isinstance(value, dict):
            return {k: self._resolve(v, sink) for k, v in value.items()}
        return value

    def _unpseudo(self, value: Any) -> Any:
        """Swap pseudonyms back to real values (the agent only ever saw the pseudonyms)."""
        if not self._pseudo:
            return value
        if isinstance(value, str):
            for p, real in self._pseudo.items():
                if p in value:
                    value = value.replace(p, str(real))
            return value
        if isinstance(value, list):
            return [self._unpseudo(v) for v in value]
        if isinstance(value, dict):
            return {k: self._unpseudo(v) for k, v in value.items()}
        return value

    def _safe_name(self, name: str) -> str:
        """Argument names chosen by the agent: kept if they look like names, else fingerprinted."""
        return name if _NAME_RE.fullmatch(str(name)) else "fp:" + self.vault.fp(name)

    def _mask_map(self, shown: dict[str, Any], resolved: dict[str, Any]) -> dict[str, str]:
        """Real value -> what the agent saw (placeholder or pseudonym), for masking sink output: every secret
        this task has handed out as a placeholder (not just this call's), and every pseudonym. A secret still
        locked in a deposit box is only included once the task has opened it, so masking never opens a box."""
        out: dict[str, str] = {}
        for token, (sealed, _) in self._tokens.items():
            if token in self._revealed:
                real = str(self._revealed[token])
            else:
                value = self.vault.cipher.decrypt(sealed, aad=token) if self.vault.cipher else sealed
                if is_box_ref(value):
                    continue
                real = str(value)
            if real and real != token:
                out[real] = token
        for pseudo, real in self._pseudo.items():
            if str(real):
                out.setdefault(str(real), pseudo)
        return out

    def _recipient_class(self, recipient: Any, rule: SinkRule) -> str:
        r = _norm(recipient, unicode_ok=True)
        if "@" in r and r.rsplit("@", 1)[-1] in self.vault.policy.internal_domains:
            return "internal"
        for spec in rule.allowed_recipients:
            s = spec.format(**self.trusted)
            if (_source_ref(s) or (s.startswith("*@") and _source_ref(s[2:]))) and \
                    _matches(recipient, self._trusted_recipients([spec])):
                return "owner"
        return "listed"

    def _note_addresses(self, source: str, src: Any, key: Any, record: dict[str, Any], wanted: list[str],
                        in_scope: bool) -> None:
        """Remember, for this task, whose contact address is whose, and which addresses arrived in untrusted
        content, so the audit log can say how a recipient relates to the task without storing it. Watch mode
        only. A contact counts as "this task's own" only when the read was in scope and the task's read rule
        picks the record by that trusted input."""
        if src.trust == "untrusted":
            for f in wanted:
                self._note_untrusted(record.get(f))
        elif src.owner_contact and record.get(src.owner_contact):
            rule_key = (self.template.reads.get(source) or {}).get("key")
            by = [t for t in self.trusted if in_scope and rule_key == f"{{{t}}}"]
            label = f"{source}.{src.owner_contact}" + (f":{{{by[0]}}}" if by else "")
            for v in _as_list(record[src.owner_contact]):
                self._contacts.setdefault(_norm(v, unicode_ok=True), set()).add(label)

    def _note_untrusted(self, value: Any) -> None:
        """Addresses in content from outside (untrusted reads, and what actions return, such as a fetched web
        page). Watch mode only."""
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8", "replace")
        if not isinstance(value, str):             # what the agent receives: the text of the whole result
            try:
                value = json.dumps(value, default=lambda o: o.decode("utf-8", "replace")
                                   if isinstance(o, (bytes, bytearray)) else str(o), ensure_ascii=False)
            except (TypeError, ValueError, RecursionError):
                value = str(value)
        if len(value) > _SCAN_LIMIT:
            self._unscanned = True
        value = unicodedata.normalize("NFKC", value[:_SCAN_LIMIT])     # full-width ＠ and the like
        self._untrusted_addresses |= _addresses_in(value)
        self._mentioned_domains |= {d.lower() for d in _MENTIONED_DOMAIN_RE.findall(value)}
        # the company's own domain written any way at all ("ops at acme dot example", "acme[.]example"): any
        # address there that the task then uses counts as named by outside content
        low = value.lower()
        squashed = re.sub(r"[\W_]+", "", low)
        for d in self.vault.policy.internal_domains:
            d = d.lower()
            if d in low or re.sub(r"[\W_]+", "", d) in squashed or d.replace(".", "dot").replace("-", "") in squashed:
                self._mentioned_domains.add(d)

    def _relation(self, recipient: Any) -> str:
        """How a recipient relates to this task, in policy names only (never the value), for learning a policy
        from watch mode (eurycleia learn): "contact:crm.customer.email:{customer_id}" is the contact on the
        record this task was started for; "contact:crm.customer.email" another record's contact;
        "internal:acme.example" the company's own domain; "untrusted" an address that appeared in untrusted
        content such as a ticket or web page; "other" anything else."""
        r = _norm(recipient, unicode_ok=True)
        if r in ("", _INVALID):
            return "invalid"
        labels = sorted(self._contacts.get(r, ()), key=lambda x: (":" not in x, x))
        if labels and ":" in labels[0]:
            return "contact:" + labels[0]         # the verified contact of this task's own record, even if a
            #                                       ticket also mentions it (customers sign their emails)
        if r in self._untrusted_addresses or self._unscanned:
            return "untrusted"                    # before the rest: an attacker can name any other address
        if labels:
            return "contact:" + labels[0]
        if "@" in r and (d := r.rsplit("@", 1)[-1]) in self.vault.policy.internal_domains:
            # an address at the company that outside content named, in any form: treated as from that content
            return "untrusted" if d in self._mentioned_domains else "internal:" + d
        return "other"

    def _flag(self, sink: str, reasons: list[str]) -> None:
        """Record a flag now; your on_flag handler is called once the task's lock is released (see _fire_flags),
        so a slow handler can't hold up the task's other calls."""
        self.vault.audit.record("flag", task=self.id, sink=sink, reasons=reasons, decision="flag")
        if self.vault.on_flag:
            with self._lock:
                self._flags.append(FlagEvent(self.id, self.template.name, sink, reasons))

    def _fire_flags(self) -> None:
        if not self._flags:
            return
        with self._lock:
            events, self._flags = self._flags, []
        for event in events:
            self.vault.on_flag(event)

    def _decide(self, kind: str, reason: str, shown: str | None = None, **fields: Any) -> None:
        """Block (or, in shadow mode, record) an action.

        `reason` goes to the log and the audit file, so it must never contain data values
        (addresses, record keys, owners): only names from the policy. `shown` is the fuller
        message for the caller, who supplied those values in the first place.
        """
        # The log line stays generic; the reason (names only, never values) goes to the audit file.
        log.info("%s a %s (details in the audit log)", "would block" if self.vault.mode == "shadow" else "blocked",
                 kind)
        if self.vault.mode == "shadow":
            if (shown or reason) not in self._reported:
                self._reported.add(shown or reason)
                self.vault.audit.record(kind, task=self.id, decision="would_block", reason=reason, **fields)
            return
        self.vault.audit.record(kind, task=self.id, decision="block", reason=reason, **fields)
        raise Blocked(shown or reason)


def owner_of(src: Any, key: Any, record: dict) -> str:
    """'company', or '<owner>:<id>' where id is the record key or its owner_field."""
    if src.owner == "company":
        return "company"
    oid = record.get(src.owner_field) if src.owner_field else key
    return f"{src.owner}:{oid}"


_INVALID = "\x00invalid"
RECORD_ID = "record id (optional)"      # the description of a read tool's record-id argument (see tool_specs)
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_RECIPIENT_ARGS = {"to", "cc", "bcc", "reply_to", "replyto", "reply-to", "recipient", "recipients"}

_ATOM = r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_EMAIL_RE = re.compile(rf"{_ATOM}(?:\.{_ATOM})*@{_LABEL}(?:\.{_LABEL})+")
_PLAIN_ID_RE = re.compile(r"[a-z0-9+][a-z0-9+._:/-]*")          # phone numbers, account ids, URLs' paths...
_DISPLAY_RE = re.compile(r"([^<>@\"\\]*)<([^<>]+)>")


_SCAN_LIMIT = 200_000            # characters of untrusted text scanned for addresses (watch mode); longer text
#                                 makes every recipient but the task's own contact count as untrusted


def _addresses_in(text: str) -> set[str]:
    """Every address in free text, normalised, in the forms a reader could take from it: as matched, and with
    any wrapping punctuation (quotes, brackets, '?', '*', backticks...) trimmed from either end."""
    out = set()
    for m in _UNICODE_EMAIL_RE.finditer(text):
        raw = m.group(0)
        for form in (raw, raw.strip("'\"`*!?.,;:()[]{}<>~^|#$%&+=/-_"), raw.lstrip("'\"`*!?([{<~^|#$%&+=/-_")):
            n = _norm(form, unicode_ok=True)
            if n and n != _INVALID:
                out.add(n)
    for at in re.finditer("@", text):               # "ops@acme.example's", to=ops@..., “ops@...”, ops@...…
        i = at.start()
        left = _PLAIN_LOCAL_RE.search(text, max(0, i - 64), i)
        right = _PLAIN_DOMAIN_RE.match(text, i + 1, i + 1 + 520)
        if left and right:
            n = _norm((left.group(0) + "@" + right.group(0)).strip("._%+-"), unicode_ok=True)
            if n and n != _INVALID:
                out.add(n)
    return out


_PLAIN_LOCAL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}\Z")
_PLAIN_DOMAIN_RE = re.compile(r"[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}")
_MENTIONED_DOMAIN_RE = re.compile(r"@\s{0,3}([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8})")


_UNICODE_EMAIL_RE = re.compile(r"[^\s@<>\"(),;:\\\[\]]{1,64}@[^\s@<>\"(),;:\\\[\]./]{1,63}"
                               r"(?:\.[^\s@<>\"(),;:\\\[\]./]{1,63}){1,8}")


def _norm(v: Any, unicode_ok: bool = False) -> str:
    """Canonical form for comparing recipients.

    Accepts exactly one plain address ("a@b.com", any case, surrounding spaces) or
    "Display Name <a@b.com>" with no '@' in the name; or, for non-email recipients, one plain
    identifier (compared with its letters as written: a URL path or channel id can be case-sensitive;
    only a URL's scheme and host are lower-cased). Anything else (a second address, comments, quoted
    parts, stray dots, control or invisible characters, look-alike letters, non-text values) normalises
    to a value that never matches a trusted recipient, so it's blocked rather than guessed.

    `unicode_ok` lets through an address with non-ASCII letters (jos\u00e9@example.com) in its standard
    (NFC) form. Such an address is only ever compared for exact equality with one from trusted data,
    never matched against a pattern (see _matches), so a look-alike can't stand in for it.
    """
    if v is None:
        return ""
    if not isinstance(v, str):
        return _INVALID
    if any(c in v for c in "\r\n\t\x00") or any(unicodedata.category(c) in ("Cf", "Cc") for c in v):
        return _INVALID                      # header injection or invisible characters
    if not v.isascii():
        if not unicode_ok or unicodedata.normalize("NFC", v) != v:
            return _INVALID                  # look-alike characters
        s = v.strip()
        if "<" in s or ">" in s:
            m = _DISPLAY_RE.fullmatch(s)
            if not m:
                return _INVALID
            s = m.group(2).strip()
        s = s.lower()
        return s if _UNICODE_EMAIL_RE.fullmatch(s) else _INVALID
    s = v.strip()
    if "<" in s or ">" in s:
        m = _DISPLAY_RE.fullmatch(s)
        if not m:
            return _INVALID
        s = m.group(2).strip()
    if "@" in s:
        s = s.lower()
        return s if _EMAIL_RE.fullmatch(s) else _INVALID
    if not _PLAIN_ID_RE.fullmatch(s.lower()):
        return _INVALID
    m = re.match(r"([a-z][a-z0-9+.\-]*://[^/?#]*)(.*)", s, re.I | re.S)
    return m.group(1).lower() + m.group(2) if m else s


_MAX_DEPTH = 64


def _shape_problem(value: Any) -> str | None:
    """Why a value can't be checked safely, or None. Iterative, so it can't itself run out of stack."""
    stack = [(value, 0)]
    while stack:
        v, depth = stack.pop()
        if depth > _MAX_DEPTH:
            return f"arguments are nested more than {_MAX_DEPTH} levels deep"
        if isinstance(v, int) and not isinstance(v, bool) and v.bit_length() > 10_000:
            return "a number in the arguments is too long"
        if isinstance(v, dict):
            stack.extend((x, depth + 1) for x in v.keys())
            stack.extend((x, depth + 1) for x in v.values())
        elif isinstance(v, (list, tuple, set)):
            stack.extend((x, depth + 1) for x in v)
    return None


def _strings(value: Any) -> list[str]:
    """Every piece of text in a value (strings and dict keys), without recursion."""
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


# Links in text. A link starts at a web scheme (with or without slashes: browsers read "https:host" as
# "https://host"), any "scheme://", "//", "www.", or a bare domain or IP address followed by a path or query.
_LINK_START = re.compile(
    r"(?:https?|ftps?|wss?|file|javascript|vbscript):|[a-z][a-z0-9+.\-]{0,31}://|//|"
    r"(?<![\w.@-])www\.|(?<![\w.@-])(?:[a-z0-9-]{1,63}\.){1,8}[a-z]{2,24}(?=[/?#:\\])|"
    r"(?<![\w.@-])\d{1,3}(?:\.\d{1,3}){3}(?=[/?#:\\])", re.I)
# Where a link can run on past spaces and quotes of the other kind: a quoted HTML attribute or CSS value (the
# whole value, from the first link start to its closing quote), and a Markdown target.
_ATTR_VALUE = re.compile(r"""(?:=|url\()\s*(?:"([^"]{0,8192})"|'([^']{0,8192})')""", re.I)
_MD_TARGET = re.compile(r"\]\(\s*(<[^<>]{1,8192}>|[^)\s]{1,8192})", re.I)
_PLAIN_LINK_END = re.compile(r"[\s\"'<>`]")
_WEB_SCHEMES = {"http", "https", "ftp", "ftps", "ws", "wss"}
_NO_LOAD_SCHEMES = {"mailto", "tel", "sms", "data", "cid", "about"}      # nothing is fetched from a website


def _urls(text: str) -> list[str]:
    """Candidate links in one piece of text, read generously: as written and with HTML entities decoded,
    backslashes as slashes, and control characters, tabs and line breaks removed inside attribute values
    (as browsers do). A candidate may run on past the real end of a link; that only makes the check stricter."""
    if not re.search(r"[:/\\]|www\.|&", text, re.I):
        return []
    out = []
    for t in {text, html.unescape(text)}:
        t = t.replace("\\", "/")
        for m in _ATTR_VALUE.finditer(t):
            value = re.sub(r"[\x00-\x20\x7f]", "", m.group(1) if m.group(1) is not None else m.group(2))
            if (ls := _LINK_START.search(value)) is not None:
                out.append(value[ls.start():])
        for m in _MD_TARGET.finditer(t):
            out.append(m.group(1).strip("<>"))
        pos = 0
        while (ls := _LINK_START.search(t, pos)) is not None:
            stop = _PLAIN_LINK_END.search(t, ls.end())
            end = stop.start() if stop else len(t)
            end = min(end, ls.start() + 8192)
            out.append(t[ls.start():end])
            pos = max(end, ls.end())
    return [u for u in dict.fromkeys(x.strip() for x in out) if u]


def _url_host(url: str) -> str | None:
    """The website a link loads from, read the way browsers do (any number of slashes or backslashes after a
    web scheme, the part after the last '@' before the path, no port); "" if it can't be told; None for
    links that don't load anything from a website (mailto:, tel:, data: ...)."""
    u = url.strip().replace("\\", "/")
    m = re.match(r"([a-z][a-z0-9+.\-]*):", u, re.I)
    if m and not re.match(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+:\d", u, re.I):     # "host.com:8080/x" is not a scheme
        scheme, rest = m.group(1).lower(), u[m.end():]
        if scheme in _NO_LOAD_SCHEMES:
            return None
        if scheme in _WEB_SCHEMES:
            rest = rest.lstrip("/")
        elif rest.startswith("//"):
            rest = rest[2:]
        else:
            return ""                                    # javascript: and unknown schemes: never allowed
    else:
        rest = u.lstrip("/")
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    host = urllib.parse.unquote(authority.rpartition("@")[2])
    if host.startswith("["):
        return host.lower()
    host = host.split(":")[0].strip().rstrip(".").lower()
    return host if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", host) else ""


def _host_allowed(url: str, allowed: list[str]) -> bool:
    host = _url_host(url)
    if host is None:
        return True
    return bool(host) and any(host == d or host.endswith("." + d) for d in allowed)


def _url_forms(url: str) -> list[str]:
    """A link as written and decoded (percent-encoding, '+' for space, HTML entities), lower-cased."""
    forms, cur = [url], url
    for _ in range(3):
        nxt = html.unescape(urllib.parse.unquote_plus(cur))
        if nxt == cur:
            break
        forms.append(nxt)
        cur = nxt
    return [f.lower() for f in forms]


def _in_link(value: str, link: str, squeezed_link: str) -> bool:
    """A value in a (lower-cased) link: as written, with punctuation and spaces dropped, or, for a value of
    several words (a name, an address), two or more of its words of 4+ letters each standing on their own
    ("?first=Priya&last=Shah"). One common word alone ("Shah", "King") isn't enough: ordinary links contain
    them. So a plain-text link, which ends at the first space, can still carry one word of a value."""
    v = value.lower()
    if v in link:
        return True
    squeezed = re.sub(r"[\W_]", "", v)
    if len(squeezed) >= 6 and squeezed in squeezed_link:
        return True
    words = {w for w in re.split(r"[\s,]+", v) if len(w) >= 4 and re.search(r"[^\W\d_]", w)}
    if len(words) < 2:
        return False
    found = sum(1 for w in words if re.search(r"(?<![^\W_])" + re.escape(w) + r"(?![^\W_])", link))
    return found >= 2


def _source_ref(spec: str) -> tuple[str, str, str] | None:
    """'crm.account:7.domain' -> ('crm.account', '7', 'domain'), else None."""
    m = re.fullmatch(r"([\w.]+):([^.]+)\.(\w+)", spec)
    return (m.group(1), m.group(2), m.group(3)) if m else None


# Email services anyone can sign up to: a "company domain" at one of these would let data go to strangers. A list
# like this can never be complete, so any domain containing one of these provider names is refused (e.g.
# yahoo.com.au, hotmail.fr, mail.example.com); add others with the policy's shared_email_domains.
SHARED_EMAIL_PROVIDERS = frozenset("""
gmail googlemail yahoo ymail rocketmail hotmail outlook live msn passport aol aim icloud me mac proton protonmail
pm gmx zoho zohomail yandex mail email qq 163 126 yeah sina sohu aliyun fastmail hey tutanota tuta tutamail
posteo duck mailbox mailfence runbox disroot riseup comcast xfinity verizon att sbcglobal bellsouth cox charter
spectrum earthlink juno netzero optonline frontier windstream centurylink bigpond telstra optusnet tpg iinet
internode dodo westnet adam aussiebb btinternet btopenworld sky virginmedia talktalk ntlworld blueyonder orange
wanadoo free sfr laposte neuf web t-online freenet arcor libero tiscali alice virgilio rediffmail naver daum
hanmail nate seznam wp onet interia o2 abv rambler inbox bk list ukr shaw rogers sympatico telus videotron
mailinator yopmail guerrillamail sharklasers grr guerrillamailblock pokemail spam4 tempmail temp-mail 10minutemail
trashmail throwawaymail maildrop dispostable mintemail getnada mohmal emailondeck usa post hushmail lycos rediff
excite netscape inbox mail2world safe-mail
""".split())
PUBLIC_SUFFIXES = frozenset("""
co.uk org.uk ac.uk gov.uk me.uk com.au net.au org.au edu.au gov.au id.au co.nz net.nz org.nz com.br co.jp ne.jp
co.in co.za com.cn com.mx com.sg com.hk co.kr
""".split())


def company_domain(value: Any, shared: Any = ()) -> str | None:
    """A business customer's email domain from trusted data, lower-cased; None if it isn't a plain domain, is only
    a public suffix (co.uk), or looks like a shared email service (gmail.com, yahoo.com.au, anything in `shared`),
    where 'anyone at the domain' means anyone."""
    if not isinstance(value, str):
        return None
    d = value.strip().lower().lstrip("@").rstrip(".")
    if not d.isascii() or not re.fullmatch(rf"{_LABEL}(?:\.{_LABEL})+", d) or d in PUBLIC_SUFFIXES:
        return None
    extra = {str(x).strip().lower().lstrip("@").rstrip(".") for x in shared}
    if any(d == x or d.endswith("." + x) for x in extra):
        return None
    if any(label in SHARED_EMAIL_PROVIDERS for label in d.split(".")[:-1]):     # every label but the ending
        return None
    return d


def _json_type_ok(value: Any, kind: str) -> bool:
    checks = {"string": lambda v: isinstance(v, str),
              "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
              "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
              "boolean": lambda v: isinstance(v, bool),
              "array": lambda v: isinstance(v, list), "object": lambda v: isinstance(v, dict)}
    return checks.get(kind, lambda v: True)(value)


_SEP = r"[\W_]{0,3}"      # between the digits of a number: any punctuation or spaces (an em dash, a dot...)


def _mask_patterns(mask: dict[str, str]) -> list[tuple[re.Pattern[str], str]]:
    """One pattern per real value, forgiving about how a sink might have reformatted it: any upper/lower
    case, and for number-like values (cards, phones, account numbers) spaces, dots, dashes or nothing
    between the digits."""
    out = []
    for real in sorted(mask, key=len, reverse=True):
        if len(real) < 3:
            continue
        digits = re.sub(r"\D", "", real)
        alnum = re.sub(r"[\W_]", "", real)
        if len(digits) >= 6 and len(digits) >= 0.6 * len(alnum):
            core = re.sub(r"[\W_]", "", real)
            pattern = _SEP.join(re.escape(c) for c in core)
        else:
            pattern = re.escape(real)
        out.append((re.compile(pattern, re.IGNORECASE), mask[real]))
    return out


def _mask(value: Any, mask: dict[str, str], secrets_out: Any = ()) -> Any:
    """Replace real values with what the agent saw, anywhere in a sink's result: in text, in keys, as
    numbers, in any case, and reformatted (a card "4111 1111 1111 1111" also as 4111-1111-1111-1111).
    Secrets (`secrets_out`) are also caught written in base64 or hex."""
    if not mask:
        return value
    mask = dict(mask)
    for real in secrets_out:
        if real in mask:
            for enc in _encodings(real):
                mask.setdefault(enc, mask[real])
    return _mask_value(value, _mask_patterns(mask))


def _encodings(real: str) -> set[str]:
    """base64 (standard and URL-safe, with or without padding) and hex of a secret, as written and with
    spaces and punctuation removed."""
    out = set()
    for form in {real, re.sub(r"[\W_]", "", real)}:
        raw = form.encode("utf-8")
        if len(raw) < 4:
            continue
        for b in (base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()):
            out |= {b, b.rstrip("=")}
        out.add(raw.hex())
    return {e for e in out if len(e) >= 8}


def _mask_value(value: Any, patterns: list[tuple[re.Pattern[str], str]]) -> Any:
    if isinstance(value, str):
        for pattern, shown in patterns:
            value = pattern.sub(lambda _m, s=shown: s, value)
        return value
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        text = str(int(value)) if isinstance(value, int) or value.is_integer() else repr(value)
        masked = _mask_value(text, patterns)
        return masked if masked != text else value
    if isinstance(value, (list, tuple)):
        return type(value)(_mask_value(v, patterns) for v in value)
    if isinstance(value, dict):
        return {_mask_value(k, patterns): _mask_value(v, patterns) for k, v in value.items()}
    return value


def _canonical(v: Any) -> Any:
    """What the sink receives after the checks: the bare email address (lower-case), or a plain
    identifier with its original letters (channel ids and account numbers can be case-sensitive)."""
    n = _norm(v, unicode_ok=True)
    return n if "@" in n else (v.strip() if isinstance(v, str) else v)


def _norm_pattern(spec: str) -> str:
    """Allowed-recipient patterns from the policy (trusted): trimmed; email patterns and a URL's scheme and
    host lower-cased, the rest kept as written."""
    s = spec.strip()
    if "@" in s:
        return s.lower()
    m = re.match(r"([a-z*][a-z0-9+.\-*]*://[^/?#]*)(.*)", s, re.I | re.S)
    return m.group(1).lower() + m.group(2) if m else s


_GLOB_CACHE: dict[str, re.Pattern[str]] = {}


def _glob(pattern: str) -> re.Pattern[str]:
    """A recipient pattern as a regex. Wildcards stay inside one part of an address, so a pattern is never
    wider than it looks:
      email      '*' in the name part matches any name ('*@acme.example'); in the domain it matches one label
                 without dots ('*@*.acme.example' is one subdomain deep)
      URL        '*' in the host matches one label; in the path it matches within one segment (no '/');
                 '**' in the path matches across segments ('https://files.acme.example/upload/**')
      other ids  '*' matches anything except '/', '@' and '.'
    '?' is one such character; [abc] is a character class."""
    rx = _GLOB_CACHE.get(pattern)
    if rx is not None:
        return rx
    if "@" in pattern:
        local, _, domain = pattern.rpartition("@")
        parts = [(local, "[^@]"), ("@", None), (domain, "[^@./]")]
    elif m := re.match(r"([^:/]*://)([^/?#]*)(.*)", pattern, re.S):
        parts = [(m.group(1), None), (m.group(2), "[^@./:?#]"), (m.group(3), "[^/?#]")]
    else:
        parts = [(pattern, "[^/@.]")]
    out = []
    for text, cls in parts:
        if cls is None:
            out.append(re.escape(text))
            continue
        i = 0
        while i < len(text):
            c = text[i]
            if c == "*" and text[i:i + 2] == "**" and cls == "[^/?#]":
                out.append(".*")
                i += 2
                continue
            if c == "*":
                out.append(cls + "*")
            elif c == "?":
                out.append(cls)
            elif c == "[" and (j := text.find("]", i + 2)) != -1:
                inner = text[i + 1:j]
                negate = inner.startswith("!")
                inner = re.sub(r"([\\\[\]^&|~])", r"\\\1", inner[1:] if negate else inner).replace("--", "-\\-")
                # like '*' and '?', a class never matches the part's separators
                out.append(f"(?:(?!{cls[2:-1] and '[' + cls[2:-1] + ']'}){'[^' if negate else '['}{inner}])")
                i = j + 1
                continue
            else:
                out.append(re.escape(c))
            i += 1
    try:
        rx = re.compile("".join(out), re.S)
    except re.error:                          # e.g. a malformed [z-a] class in the policy: matches nothing
        rx = re.compile(r"(?!)")
    if len(_GLOB_CACHE) < 4096:
        _GLOB_CACHE[pattern] = rx
    return rx


LITERAL = "\x00="          # marks an allowed recipient taken from a record: compared exactly, never as a pattern


def _matches(recipient: Any, allowed: list[str]) -> bool:
    r = _norm(recipient, unicode_ok=True)
    if not r or r == _INVALID:
        return False
    for a in allowed:
        if a.startswith(LITERAL):
            if r == a[len(LITERAL):] and a[len(LITERAL):] != _INVALID:
                return True
        elif r == a or (r.isascii() and any(c in a for c in "*?[") and _glob(a).fullmatch(r) is not None):
            return True                      # an internationalised address only ever matches exactly
    return False


def _as_list(v: Any) -> list:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return list(v)
    if isinstance(v, str) and ("," in v or ";" in v):
        return [p.strip() for p in re.split(r"[,;]", v) if p.strip()]
    return [v]


def _flatten(args: dict[str, Any]) -> str:
    try:
        return json.dumps(args, default=str, ensure_ascii=False) + " " + " ".join(
            str(v) for v in args.values())
    except (TypeError, ValueError):
        return " ".join(str(v) for v in args.values())


def _coerce(key: Any) -> Any:
    return int(key) if isinstance(key, str) and key.isdigit() else key
