# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Safe summaries: facts about a record instead of the record's values.

A task's read rule can list derived fields. The model sees only the result (a yes/no, the last
four digits, an email's domain...), never the value it was computed from:

    reads:
      crm.customer:
        key: "{customer_id}"
        fields: [name, plan]
        derive:
          card_ending: {last4: card_number}          # "•••• 1111"
          is_pro:      {equals: [plan, Pro]}         # true / false
          adult:       {age_at_least: [dob, 18]}     # true / false
          has_phone:   {present: phone}              # true / false
          email_domain: {domain: email}              # "example.com"
          big_spender: {at_least: [lifetime_value, 10000]}

Only these operations exist; there is no expression language, so a policy can't be used to run code.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any

from .errors import EurycleiaError


class DeriveError(EurycleiaError):
    pass


def _digits(v: Any) -> str:
    return re.sub(r"\D", "", str(v or ""))


def _number(v: Any) -> float | None:
    try:
        return float(str(v).replace(",", "").replace("$", "").strip())
    except (TypeError, ValueError):
        return None


def _date(v: Any) -> _dt.date | None:
    if isinstance(v, _dt.datetime):
        return v.date()
    if isinstance(v, _dt.date):
        return v
    s = str(v or "").strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y/%m/%d", "%d-%m-%Y"):
        try:
            return _dt.datetime.strptime(s[:10], fmt).date()
        except ValueError:
            continue
    return None


def _age_at_least(value: Any, years: Any, today: _dt.date | None = None) -> bool | None:
    born = _date(value)
    if born is None:
        return None
    today = today or _dt.date.today()
    age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    return age >= int(years)


_EMAIL = re.compile(r"[^@\s,;<>\"']+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")


def _domain(value: Any) -> str | None:
    """The domain of ONE email address, or nothing: never the value itself (a card, a list, free text)."""
    m = _EMAIL.fullmatch(value.strip()) if isinstance(value, str) else None
    return m.group(1).lower() if m else None


# name -> (argument shape, function(record, args) -> value)
def _one(args: Any) -> str:
    if not isinstance(args, str):
        raise DeriveError("expects a field name")
    return args


def _pair(args: Any) -> tuple[str, Any]:
    if not (isinstance(args, list) and len(args) == 2 and isinstance(args[0], str)):
        raise DeriveError("expects [field, value]")
    return args[0], args[1]


OPS: dict[str, Any] = {
    "last4": (_one, lambda rec, f: ("•••• " + _digits(rec.get(f))[-4:]) if len(_digits(rec.get(f))) >= 8 else None),
    "present": (_one, lambda rec, f: rec.get(f) not in (None, "")),
    "domain": (_one, lambda rec, f: _domain(rec.get(f))),
    "equals": (_pair, lambda rec, a: None if rec.get(a[0]) is None
               else str(rec.get(a[0])).strip().lower() == str(a[1]).strip().lower()),
    "one_of": (_pair, lambda rec, a: None if rec.get(a[0]) is None
               else str(rec.get(a[0])).strip().lower() in {str(x).strip().lower() for x in a[1]}),
    "at_least": (_pair, lambda rec, a: None if _number(rec.get(a[0])) is None
                 else _number(rec.get(a[0])) >= float(a[1])),
    "at_most": (_pair, lambda rec, a: None if _number(rec.get(a[0])) is None
                else _number(rec.get(a[0])) <= float(a[1])),
    "age_at_least": (_pair, lambda rec, a: _age_at_least(rec.get(a[0]), a[1])),
}


def check_spec(name: str, spec: Any) -> tuple[str, Any]:
    """Validate one derived-field spec from a policy: {op: args}. Returns (op, parsed args)."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,40}", str(name)):
        raise DeriveError(f"derived field name {name!r} must be lower_case_with_underscores")
    if not (isinstance(spec, dict) and len(spec) == 1):
        raise DeriveError(f"{name}: write it as {{operation: arguments}}, e.g. {{last4: card_number}}")
    op, args = next(iter(spec.items()))
    if op not in OPS:
        raise DeriveError(f"{name}: unknown operation {op!r} (use {', '.join(sorted(OPS))})")
    shape, _ = OPS[op]
    try:
        parsed = shape(args)
    except DeriveError as e:
        raise DeriveError(f"{name}: {op} {e}") from None
    if op in ("at_least", "at_most", "age_at_least") and _number(parsed[1]) is None:
        raise DeriveError(f"{name}: {op} needs a number")
    if op == "one_of" and not isinstance(parsed[1], list):
        raise DeriveError(f"{name}: one_of expects [field, [values]]")
    return op, parsed


def compute(spec: dict[str, Any], record: dict[str, Any]) -> Any:
    op, parsed = check_spec("x", spec)
    try:
        return OPS[op][1](record, parsed)
    except (TypeError, ValueError, OverflowError):
        return None                      # can't tell: never guess
