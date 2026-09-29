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
guarantees that survive rewording and encoding, use `taskvault.planner`, which
tracks labels through the data flow instead of matching strings.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import itertools
import json
import logging
import os
import re
import secrets
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .boxes import BoxLocked, is_box_ref
from .cache import EncryptedCache
from .crypto import Cipher
from .derive import compute as derive_value
from .detect import redact_secrets
from .errors import TaskvaultError
from .policy import Policy, SinkRule, TaskTemplate

log = logging.getLogger("taskvault")

TOKEN_RE = re.compile(r"\[\[vault:([a-z0-9_]+):([a-f0-9]{8})\]\]")
LOOSE_TOKEN_RE = re.compile(r"\[\[\s*vault\s*:[^\]]*\]\]?", re.I)   # anything that looks like a placeholder
MIN_MATCH_LEN = 4  # shorter values produce too many false matches
_NO_RULE = SinkRule()


class Blocked(TaskvaultError):
    """Raised when the vault refuses a read or an action. `reason` is safe to show the model."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class SinkError(TaskvaultError):
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
        task = Task(self, t, next(self._task_ids), trusted)
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


class Task:
    def __init__(self, vault: Vault, template: TaskTemplate, task_id: int, trusted: dict[str, Any]):
        self.vault, self.template, self.id, self.trusted = vault, template, task_id, trusted
        self._tokens: dict[str, tuple[Any, Label]] = {}   # placeholder -> (sealed value, label)
        self._seen: dict[str, Label] = {}                   # protected/secret value -> label
        self._calls: dict[str, int] = {}
        self._reported: set[str] = set()
        self._pseudo: dict[str, Any] = {}                   # pseudonym -> real value
        self._revealed: dict[str, Any] = {}                 # placeholder -> value opened from a deposit box
        self._used = {"reads": 0, "records": set(), "fields": set()}   # for the task's data budget

    # ------------------------------------------------------------------ reads
    def read(self, source: str, key: Any = None, fields: list[str] | None = None) -> dict[str, Any]:
        """Return one record for the model: only allowed fields (or just the ones asked for),
        secrets as placeholders, personal details as stand-ins, free text scrubbed, plus any
        safe summaries the policy defines."""
        self._reported = set()
        if source not in self.vault.policy.sources:
            self._decide("read", "unknown source", shown=f"unknown source {source!r}",
                         source=self.vault.fp(source))
            raise KeyError(f"unknown source {source!r}")
        rule = self.template.reads.get(source)
        allowed_keys = self.allowed_keys(source)
        if key is None and len(allowed_keys) == 1:
            key = allowed_keys[0]
        if rule is None or str(key) not in {str(k) for k in allowed_keys}:
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
                self._decide("read", f"asked for {len(unknown)} field(s) this task can't see",
                             shown=f"this task can't see {unknown} in {source}", source=source)
            wanted = [f for f in dict.fromkeys(fields) if f in allowed or f in derive]
        else:
            wanted = [*allowed, *derive]

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
                             shown=f"{source}.{f} holds an old taskvault secret-store reference; move the "
                                   "secrets into deposit boxes (taskvault boxes put)", source=source)
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

    def _unseal(self, token: str) -> Any:
        sealed, _ = self._tokens[token]
        value = self.vault.cipher.decrypt(sealed, aad=token) if self.vault.cipher else sealed
        if is_box_ref(value):
            if self.vault.boxes is None:
                raise BoxLocked("this value is in a deposit box but no box store is configured")
            # second key: the holder's (may ask a person to approve)
            value = self.vault.boxes.reveal(value, task=self.id, reason=f"{self.template.name} -> "
                                                                         f"{getattr(self, '_sink', '?')}")
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
        self._reported = set()
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
        if self.vault.policy.detect_outbound and recipients:
            from .detect import KINDS, scan_text
            for kind, _s, _e in scan_text(TOKEN_RE.sub(" ", text)):
                if KINDS[kind].level == "secret":
                    self._decide("act", f"outbound message contains what looks like a {KINDS[kind].label}",
                                 sink=sink)
        if rule.approval == "always":
            self._approve(sink, "policy requires a human to approve this action", shown)
        return self._run_sink(sink, rule, args, recipient_args, recipients, n)

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
                                 sink=sink, recipient=self.vault.fp(r))
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

    def _run_sink(self, sink: str, rule: SinkRule, args: dict[str, Any], recipient_args: list[str],
                  recipients: list[Any], n: int) -> Any:
        """All checks passed (or shadow mode): unlock placeholders, run the sink, mask what comes back."""
        classes = [self._recipient_class(r, rule) for r in recipients]
        sizes = {k: len(str(v)) for k, v in args.items()}
        self._calls[sink] = n
        self._sink = sink
        if self.vault.mode == "enforce":
            for a in recipient_args:     # the sink gets the checked address, not the text the agent wrote
                v = args.get(a)
                if isinstance(v, str) and v.strip():
                    args[a] = ", ".join(_canonical(x) for x in _as_list(v))
                elif isinstance(v, (list, tuple)):
                    args[a] = [_canonical(x) for x in v]
        try:
            resolved = {k: self._resolve(v) for k, v in args.items()}
        except BoxLocked as e:
            self.vault.audit.record("act", task=self.id, sink=sink, decision="block", reason=f"box locked: {e}")
            raise Blocked(f"box locked: {e}") from e
        except Exception as e:  # noqa: BLE001 - damaged or missing stored secret: fail closed, and log it
            self.vault.audit.record("act", task=self.id, sink=sink, decision="block",
                                    reason=f"a stored secret couldn't be unlocked ({type(e).__name__})")
            raise Blocked("a stored secret couldn't be unlocked; the action was not run") from None
        self.vault.audit.record("act", task=self.id, sink=sink, args=[self._safe_name(a) for a in sorted(args)],
                                recipients=[self.vault.fp(r) for r in recipients], recipient_classes=classes,
                                arg_sizes={self._safe_name(k): v for k, v in sizes.items()}, call=n,
                                decision="allow")
        if rule.risk == "medium":
            self._flag(sink, ["medium-risk action"])
        mask = self._mask_map(args, resolved)
        try:
            result = self.vault.sinks[sink](**resolved)
        except Exception as e:  # noqa: BLE001 - the error text may quote real values; mask them
            raise SinkError(f"{sink} failed: {type(e).__name__}: {redact_secrets(_mask(str(e), mask))}") from None
        result = _mask(result, mask)
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
        if tm.read:
            key = arguments.get(tm.key_arg) if tm.key_arg else None
            return self.read(tm.read, key, fields=arguments.get("fields"))
        return self.act(tm.act, **arguments)

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
                props[tm.key_arg] = {"type": "string", "description": "record id (optional)"}
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
            m = re.fullmatch(r"([\w.]+):([^.]+)\.(\w+)", spec)
            if m and m.group(1) in self.vault.policy.sources:
                # e.g. crm.customer:12.email -> looked up by the vault itself, not by the model
                src = self.vault.policy.sources[m.group(1)]
                if src.trust != "trusted":
                    continue
                rec = self.vault._fetch(m.group(1), _coerce(m.group(2)))
                if rec and rec.get(m.group(3)):
                    out.extend(_norm(v) for v in _as_list(rec[m.group(3)]))
            else:
                out.append(_norm_pattern(spec))   # literal address or glob like *@acme.example
        return out

    def _owner_ok(self, label: Label, recipient: Any) -> bool:
        """Protected data may go to its owner, or to the company's own domains (it already holds it)."""
        r = _norm(recipient)
        if r in ("", _INVALID):
            return False
        if "@" in r and r.rsplit("@", 1)[-1] in self.vault.policy.internal_domains:
            return True
        if label.owner == "company":
            return False
        contact = self.vault._owner_contact(label.owner)
        return contact is not None and _norm(contact) == r

    def _approve(self, sink: str, reason: str, args: dict[str, Any]) -> None:
        req = ApprovalRequest(self.id, self.template.name, sink, reason, dict(args))
        ok = bool(self.vault.approver and self.vault.approver(req))
        self.vault.audit.record("approval", task=self.id, sink=sink, reason=reason,
                                decision="approved" if ok else "denied")
        if not ok:
            raise Blocked(f"{reason}: {'denied' if self.vault.approver else 'no approver configured'}")

    def _resolve(self, value: Any) -> Any:
        if isinstance(value, str):
            return TOKEN_RE.sub(lambda m: str(self._unseal(m.group(0))) if m.group(0) in self._tokens
                                else m.group(0), value)
        if isinstance(value, list):
            return [self._resolve(v) for v in value]
        if isinstance(value, dict):
            return {k: self._resolve(v) for k, v in value.items()}
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
        r = _norm(recipient)
        if "@" in r and r.rsplit("@", 1)[-1] in self.vault.policy.internal_domains:
            return "internal"
        for spec in rule.allowed_recipients:
            if re.fullmatch(r"([\w.]+):([^.]+)\.(\w+)", spec.format(**self.trusted)) and \
                    r in self._trusted_recipients([spec]):
                return "owner"
        return "listed"

    def _flag(self, sink: str, reasons: list[str]) -> None:
        self.vault.audit.record("flag", task=self.id, sink=sink, reasons=reasons, decision="flag")
        if self.vault.on_flag:
            self.vault.on_flag(FlagEvent(self.id, self.template.name, sink, reasons))

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
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_RECIPIENT_ARGS = {"to", "cc", "bcc", "reply_to", "replyto", "reply-to", "recipient", "recipients"}

_ATOM = r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_EMAIL_RE = re.compile(rf"{_ATOM}(?:\.{_ATOM})*@{_LABEL}(?:\.{_LABEL})+")
_PLAIN_ID_RE = re.compile(r"[a-z0-9+][a-z0-9+._:/-]*")          # phone numbers, account ids, URLs' paths...
_DISPLAY_RE = re.compile(r"([^<>@\"\\]*)<([^<>]+)>")


def _norm(v: Any) -> str:
    """Canonical form for comparing recipients.

    Accepts exactly one plain address ("a@b.com", any case, surrounding spaces) or
    "Display Name <a@b.com>" with no '@' in the name; or, for non-email recipients, one plain
    identifier. Anything else (a second address, comments, quoted parts, stray dots, control or
    invisible characters, look-alike letters, non-text values) normalises to a value that never
    matches a trusted recipient, so it's blocked rather than guessed.
    """
    if v is None:
        return ""
    if not isinstance(v, str):
        return _INVALID
    if any(c in v for c in "\r\n\t\x00") or any(unicodedata.category(c) in ("Cf", "Cc") for c in v):
        return _INVALID                      # header injection or invisible characters
    if unicodedata.normalize("NFKC", v) != v or not v.isascii():
        return _INVALID                      # look-alike characters
    s = v.strip()
    if "<" in s or ">" in s:
        m = _DISPLAY_RE.fullmatch(s)
        if not m:
            return _INVALID
        s = m.group(2).strip()
    s = s.lower()
    if "@" in s:
        return s if _EMAIL_RE.fullmatch(s) else _INVALID
    return s if _PLAIN_ID_RE.fullmatch(s) else _INVALID


def _json_type_ok(value: Any, kind: str) -> bool:
    checks = {"string": lambda v: isinstance(v, str),
              "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
              "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
              "boolean": lambda v: isinstance(v, bool),
              "array": lambda v: isinstance(v, list), "object": lambda v: isinstance(v, dict)}
    return checks.get(kind, lambda v: True)(value)


_SEP = r"[\s.\-_/]*"


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
            core = re.sub(r"[\s.\-_/]", "", real)
            pattern = _SEP.join(re.escape(c) for c in core)
        else:
            pattern = re.escape(real)
        out.append((re.compile(pattern, re.IGNORECASE), mask[real]))
    return out


def _mask(value: Any, mask: dict[str, str]) -> Any:
    """Replace real values with what the agent saw, anywhere in a sink's result: in text, in keys, as
    numbers, in any case, and reformatted (a card "4111 1111 1111 1111" also as 4111-1111-1111-1111)."""
    if not mask:
        return value
    return _mask_value(value, _mask_patterns(mask))


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
    n = _norm(v)
    return n if "@" in n else (v.strip() if isinstance(v, str) else v)


def _norm_pattern(spec: str) -> str:
    """Allowed-recipient patterns from the policy (trusted): just trimmed and lower-cased."""
    return spec.strip().lower()


def _matches(recipient: Any, allowed: list[str]) -> bool:
    r = _norm(recipient)
    return bool(r) and r != _INVALID and any(r == a or (any(c in a for c in "*?[") and fnmatch.fnmatchcase(r, a))
                           for a in allowed)


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
