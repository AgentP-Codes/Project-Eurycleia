# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Automatic detection of sensitive data.

Used by `eurycleia setup` to label fields without the developer doing it by
hand, by `eurycleia scan` to find secrets in text, and (optionally) by the vault
to block outbound values that look like secrets.

Detection is a *suggestion*: setup writes what it found, with its reasons and
confidence, into the policy as comments so a person can review it. Enforcement
always comes from the policy, never from detection alone.

Checksums are verified where the format has one (cards, TFN, ABN, Medicare,
IBAN), which keeps false positives low.
"""

from __future__ import annotations

import bisect
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

# ------------------------------------------------------------------ checksums


def _digits(s: str) -> str:
    return re.sub(r"[\s-]", "", s)


def luhn_ok(num: str) -> bool:
    d = _digits(num)
    if not d.isdigit() or not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0 and len(set(d)) > 1


def tfn_ok(num: str) -> bool:
    d = _digits(num)
    if not d.isdigit() or len(d) not in (8, 9):
        return False
    weights = [10, 7, 8, 4, 6, 3, 5, 1] if len(d) == 8 else [1, 4, 3, 7, 5, 8, 6, 9, 10]
    return sum(int(x) * w for x, w in zip(d, weights, strict=True)) % 11 == 0 and len(set(d)) > 1


def abn_ok(num: str) -> bool:
    d = _digits(num)
    if not d.isdigit() or len(d) != 11:
        return False
    nums = [int(x) for x in d]
    nums[0] -= 1
    weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
    return sum(n * w for n, w in zip(nums, weights, strict=True)) % 89 == 0


def medicare_ok(num: str) -> bool:
    d = _digits(num)
    if not d.isdigit() or len(d) not in (10, 11) or d[0] not in "23456":
        return False
    check = sum(int(x) * w for x, w in zip(d[:8], [1, 3, 7, 9, 1, 3, 7, 9], strict=True)) % 10
    return check == int(d[8])


def iban_ok(s: str) -> bool:
    s = re.sub(r"\s", "", s).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    moved = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1


# ------------------------------------------------------------------ detectors
@dataclass(frozen=True)
class Kind:
    name: str
    level: str          # secret | protected | normal
    label: str          # human description


KINDS = {k.name: k for k in [
    Kind("card_number", "secret", "payment card number"),
    Kind("au_tfn", "secret", "Australian tax file number"),
    Kind("au_medicare", "secret", "Medicare number"),
    Kind("bank_account", "secret", "bank account (BSB + account)"),
    Kind("iban", "secret", "IBAN"),
    Kind("api_key", "secret", "API key or token"),
    Kind("private_key", "secret", "private key"),
    Kind("password", "secret", "password or secret"),
    Kind("gov_id", "secret", "government ID (passport / licence)"),
    Kind("au_abn", "normal", "Australian Business Number (public)"),
    Kind("email", "protected", "email address"),
    Kind("phone", "protected", "phone number"),
    Kind("person_name", "protected", "person's name"),
    Kind("address", "protected", "street address"),
    Kind("dob", "protected", "date of birth"),
    Kind("ip_address", "protected", "IP address"),
    Kind("money", "protected", "financial amount"),
    Kind("free_text", "protected", "free text (may contain anything)"),
    Kind("identifier", "normal", "record identifier"),
    Kind("category", "normal", "status / category / type"),
    Kind("timestamp", "normal", "date or time"),
]}

VALUE_PATTERNS: list[tuple[str, re.Pattern[str], Any]] = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), None),
    ("api_key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|"
                           r"gh[pousr]_[A-Za-z0-9]{30,}|xox[abpr]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|"
                           r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), None),
    ("card_number", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), luhn_ok),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){10,30}\b"), iban_ok),
    ("bank_account", re.compile(r"\b\d{3}-?\d{3}[ ,/]{1,3}\d{6,10}\b"), None),
    ("au_medicare", re.compile(r"\b[2-6]\d{3} ?\d{5} ?\d{1,2}\b"), medicare_ok),
    ("au_abn", re.compile(r"\b\d{2} ?\d{3} ?\d{3} ?\d{3}\b"), abn_ok),
    ("au_tfn", re.compile(r"\b\d{3} ?\d{3} ?\d{2,3}\b"), tfn_ok),
    # lengths bounded as in the email standard, so a long run like a.a.a.a... is scanned in linear time
    ("email", re.compile(r"\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}\b"), None),
    ("phone", re.compile(r"(?:\+\d{1,3}[ -]?)?\(?0?[2-478]\)?[ -]?\d{2,4}[ -]?\d{3}[ -]?\d{3}\b"), None),
    ("phone", re.compile(r"(?:\+61[ -]?|\(0[2378]\)[ -]?|\b0[2378][ -]?)\d{4}[ -]?\d{4}\b"), None),   # AU landlines
    ("phone", re.compile(r"\+\d{1,3}(?:[ -]?\(?\d{1,4}\)?){2,5}\d\b"), None),                       # international
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), None),
]

NAME_HINTS: list[tuple[str, str]] = [
    (r"(^|_)(cvv|cvc|pan|card(_?num(ber)?)?|cc_?num)($|_)", "card_number"),
    (r"(^|_)tfn($|_)|tax_?file", "au_tfn"),
    (r"medicare", "au_medicare"),
    (r"(^|_)(bsb|account_?(no|num(ber)?)|bank_?account|acct)($|_)", "bank_account"),
    (r"iban", "iban"),
    (r"(passport|licen[cs]e|driver|national_?id|ssn|nin)", "gov_id"),
    (r"(password|passwd|secret|api_?key|token|private_?key|credential)", "password"),
    (r"(^|_)abn($|_)", "au_abn"),
    (r"e_?mail", "email"),
    (r"(phone|mobile|cell|fax|tel)($|_)", "phone"),
    (r"(^|_)(first|last|full|given|family|sur)?_?name($|_)|(^|_)(contact|customer|person)$", "person_name"),
    (r"(address|street|suburb|postcode|zip|city)", "address"),
    (r"(dob|birth)", "dob"),
    (r"(^|_)ip(_?addr(ess)?)?($|_)", "ip_address"),
    (r"(salary|income|wage|balance|credit_?limit|amount|price|total|cost)", "money"),
    (r"(note|comment|description|body|message|content|text)", "free_text"),
    (r"(^|_)(id|uuid|key|ref|number|no)$|_id$", "identifier"),
    (r"(status|type|category|plan|tier|state|kind|currency|country)$", "category"),
    (r"(_at|_on|date|time|created|updated)$", "timestamp"),
]


@dataclass
class Finding:
    kind: str
    level: str
    confidence: float           # 0..1
    reasons: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return KINDS[self.kind].label


def detect_value(value: Any) -> str | None:
    """The most sensitive kind found anywhere in one value, or None."""
    if value is None:
        return None
    text = str(value)
    for kind, pattern, check in VALUE_PATTERNS:
        for m in pattern.finditer(text):
            if check is None or check(m.group(0)):
                return kind
    return None


def scan_text(text: str) -> list[tuple[str, int, int]]:
    """All sensitive spans in free text: (kind, start, end). Overlaps keep the first (most sensitive).

    Runs in roughly linear time: accepted spans never overlap, so they're kept sorted and each new
    match is checked only against its neighbours (a binary search), not against every span found.
    """
    starts: list[int] = []                      # sorted starts of accepted spans
    spans: dict[int, tuple[str, int]] = {}      # start -> (kind, end)

    def clash(start: int, end: int) -> int | None:
        """End of an accepted span overlapping [start, end), or None."""
        i = bisect.bisect_right(starts, start) - 1
        worst = None
        for j in (i, i + 1):                     # only the neighbours can overlap
            if 0 <= j < len(starts):
                s = starts[j]
                e = spans[s][1]
                if s < end and start < e:
                    worst = e if worst is None else max(worst, e)
        # a longer candidate can cover several short accepted spans: check the next ones too
        j = i + 2
        while j < len(starts) and starts[j] < end:
            e = spans[starts[j]][1]
            worst = e if worst is None else max(worst, e)
            j += 1
        return worst

    def clashing(start: int, end: int) -> list[int]:
        """Starts of the accepted spans overlapping [start, end)."""
        i = max(0, bisect.bisect_right(starts, start) - 1)
        out = []
        for j in range(i, len(starts)):
            s = starts[j]
            if s >= end:
                break
            if start < spans[s][1]:
                out.append(s)
        return out

    for kind, pattern, check in VALUE_PATTERNS:
        pos = 0
        while (m := pattern.search(text, pos)) is not None:
            whole_run = check is not None
            if whole_run:
                # A run of digit groups can hold a real value next to other numbers ("card 4111 ... 1111 123"):
                # look at every piece of the whole run once (usual layouts first, then longest), then carry on
                # after the run. Even when the first match passes the check, it may not be the real value.
                found, nxt = _checked_run(text, m.start(), kind, pattern, check,
                                          lambda a, b: [(s, spans[s][1]) for s in clashing(a, b)])
            else:
                found, nxt = [(m.start(), m.end())], m.end()
            for start, end in found:
                over = clash(start, end)
                if over is not None:
                    if not whole_run:
                        nxt = min(nxt, over)     # overlaps something more sensitive: look again after it
                        continue
                    # a secret run sharing digits with a secret already found ("tfn 123 456 782 0400..." where a
                    # card-shaped window took the TFN's last group): hide both, as one value, so no part shows
                    hits = clashing(start, end)
                    if KINDS[kind].level != "secret" or any(KINDS[spans[h][0]].level != "secret" for h in hits):
                        continue
                    first_kind = spans[hits[0]][0]
                    start, end = min(start, hits[0]), max([end] + [spans[h][1] for h in hits])
                    for h in hits:
                        starts.remove(h)
                        del spans[h]
                    bisect.insort(starts, start)
                    spans[start] = (first_kind, end)
                    continue
                bisect.insort(starts, start)
                spans[start] = (kind, end)
            pos = max(nxt, m.start() + 1)
    return [(spans[s][0], s, spans[s][1]) for s in starts]


# For the checked kinds: how a run of groups looks, and how many letters/digits a real value has.
_RUNS = {"card_number": (re.compile(r"\d+(?:[ -]\d+)*"), 13, 19),
         "iban": (re.compile(r"[A-Z0-9]+(?: [A-Z0-9]+)*"), 14, 34),
         "au_medicare": (re.compile(r"\d+(?: \d+)*"), 10, 11),
         "au_abn": (re.compile(r"\d+(?: \d+)*"), 11, 11),
         "au_tfn": (re.compile(r"\d+(?: \d+)*"), 8, 9)}


def _checked_run(text: str, start: int, kind: str, pattern: re.Pattern[str], check: Any,
                 taken: Any = None) -> tuple[list, int]:
    """The valid values inside the run of groups starting at `start`, and where the run ends.

    Each piece of the run (a stretch of whole groups with the right number of letters and digits) is checked
    once, longest first, so the work grows linearly with the run's length. `taken` are spans already found
    (of other kinds): pieces clear of them are looked at first, then pieces that share groups with them
    (the caller merges those, so a value half-covered by another one is still hidden in full)."""
    run_re, lo, hi = _RUNS[kind]
    run = run_re.match(text, start)
    end = run.end() if run else start + 1
    groups = [(g.start() + start, g.end() + start) for g in re.finditer(r"[^ \-]+", text[start:end])]
    counts = [0]
    for s, e in groups:
        counts.append(counts[-1] + (e - s))
    candidates = []
    for i in range(len(groups)):
        for j in range(i, min(len(groups), i + hi)):
            n = counts[j + 1] - counts[i]
            if n > hi:
                break
            if n >= lo:
                candidates.append((n, i, j))
    if kind == "card_number":
        candidates = _luhn_candidates(text, groups, candidates)
    usual = _usual_card if kind == "card_number" else (lambda _groups, _c: False)
    foreign = [False] * len(groups)                     # groups inside a value found earlier (another kind)
    near = taken(start, end) if taken is not None and groups else []
    k = 0
    for g, (gs, ge) in enumerate(groups):          # both lists are in order: one pass
        while k < len(near) and near[k][1] <= gs:
            k += 1
        foreign[g] = k < len(near) and near[k][0] < ge
    touches = [0]
    for f in foreign:
        touches.append(touches[-1] + f)
    # a card written the usual way (4-4-4-4, 4-6-5, 4-6-4, 4-4-4-4-3, or unbroken) comes before other windows, so a
    # longer run that happens to pass the check can't take the card's digits and leave part of it visible
    candidates.sort(key=lambda c: (touches[c[2] + 1] > touches[c[1]], not usual(groups, c), -c[0], c[1]))
    owner = [-1] * len(groups)                          # which accepted value each group belongs to
    parent: list[int] = []                              # accepted values; overlapping usual-layout ones merge
    span: list[list[int]] = []
    is_usual: list[bool] = []

    def root(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for c in candidates:
        _n, i, j = c
        hit = {root(owner[g]) for g in range(i, j + 1) if owner[g] >= 0}
        if all(owner[g] >= 0 or foreign[g] for g in range(i, j + 1)):
            continue                                    # wholly inside values already found
        this_usual = usual(groups, c)
        if hit and not (this_usual and all(is_usual[x] for x in hit)):
            continue                                    # overlaps a value already found
        piece = text[groups[i][0]:groups[j][1]]
        if not (pattern.fullmatch(piece) and check(piece)):
            continue
        # Two overlapping card-shaped windows that both pass (a card next to other 4-digit numbers): there's no
        # telling which is the card, so both are hidden, as one value.
        k = len(parent)
        parent.append(k)
        span.append([i, j])
        is_usual.append(this_usual)
        for x in hit:
            parent[x] = k
            span[k] = [min(span[k][0], span[x][0]), max(span[k][1], span[x][1])]
        for g in range(i, j + 1):
            if owner[g] < 0:
                owner[g] = k
    out = [(groups[span[k][0]][0], groups[span[k][1]][1]) for k in range(len(parent)) if parent[k] == k]
    return sorted(out), end


_DOUBLE = [0, 2, 4, 6, 8, 1, 3, 5, 7, 9]
_USUAL_LAYOUTS = ([4, 4, 4, 4], [4, 6, 5], [4, 6, 4], [4, 4, 4, 4, 3])


def _usual_card(groups: list[tuple[int, int]], c: tuple[int, int, int]) -> bool:
    lens = [groups[g][1] - groups[g][0] for g in range(c[1], c[2] + 1)]
    return len(lens) == 1 or lens in _USUAL_LAYOUTS


def _luhn_candidates(text: str, groups: list[tuple[int, int]], candidates: list) -> list:
    """Keep only the windows whose Luhn sum works out, computed in constant time per window from running
    totals (the full check still runs on what's kept). Without this a long run of digits that never passes
    would cost a full check for every window."""
    digits: list[int] = []
    first: list[int] = []                 # index in `digits` of each group's first digit
    for s, e in groups:
        first.append(len(digits))
        digits += [int(c) for c in text[s:e]]           # int(): also full-width and other decimal digits
    # plain[k] / doubled[k]: running totals where the digits at even (resp. odd) indexes are doubled
    even_doubled, odd_doubled = [0], [0]
    for k, d in enumerate(digits):
        even_doubled.append(even_doubled[-1] + (_DOUBLE[d] if k % 2 == 0 else d))
        odd_doubled.append(odd_doubled[-1] + (d if k % 2 == 0 else _DOUBLE[d]))
    keep = []
    for c in candidates:
        _n, i, j = c
        a, b = first[i], first[j] + (groups[j][1] - groups[j][0])      # digit range [a, b)
        # Luhn doubles every second digit counting from the last one: indexes of the other parity to b-1
        totals = odd_doubled if (b - 1) % 2 == 0 else even_doubled
        if (totals[b] - totals[a]) % 10 == 0:
            keep.append(c)
    return keep


def redact(text: str) -> str:
    out, last = [], 0
    for kind, s, e in scan_text(text):
        out += [text[last:s], f"[{kind.upper()}]"]
        last = e
    return "".join(out + [text[last:]])


_PLACEHOLDER = re.compile(r"\[\[vault:[a-z0-9_]+:[a-f0-9]{8}\]\]")


def redact_secrets(value: Any, found: set[str] | None = None) -> Any:
    """Replace secret-looking data (cards, bank accounts, tax file numbers, keys, ...) anywhere in a value:
    in text, dict keys and numbers. `found` collects the kinds replaced. Emails and phone numbers are left
    alone: they're only protected, and replies often legitimately mention them."""
    found = found if found is not None else set()
    if isinstance(value, str):
        # the vault's own placeholders end in random hex, which can look like a tax file number by chance:
        # blank them out (same length, so positions line up) before looking
        masked = _PLACEHOLDER.sub(lambda m: "#" * len(m.group(0)), value)
        spans = [(k, s, e) for k, s, e in scan_text(masked) if KINDS[k].level == "secret"]
        if not spans:
            return value
        out, last = [], 0
        for kind, s, e in spans:
            out += [value[last:s], f"[{kind} removed by eurycleia]"]
            last = e
            found.add(kind)
        return "".join(out + [value[last:]])
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int) and abs(value) >= 10 ** 7:
        text = str(value)
        masked = redact_secrets(text, found)
        return masked if masked != text else value
    if isinstance(value, (list, tuple)):
        return type(value)(redact_secrets(v, found) for v in value)
    if isinstance(value, dict):
        return {redact_secrets(k, found): redact_secrets(v, found) for k, v in value.items()}
    return value


_RANK = {"secret": 3, "protected": 2, "normal": 1}


def classify_column(name: str, samples: list[Any]) -> Finding:
    """Label a column from its name and sample values. Picks the most sensitive credible signal."""
    lname = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    name_kind = next((k for pat, k in NAME_HINTS if re.search(pat, lname)), None)

    values = [v for v in samples if v not in (None, "")]
    value_kinds = Counter(k for k in (detect_value(v) for v in values) if k)
    top_kind, top_n = value_kinds.most_common(1)[0] if value_kinds else (None, 0)
    ratio = top_n / len(values) if values else 0.0

    candidates: list[Finding] = []
    if name_kind == "free_text" and top_kind:
        # a notes/description column that sometimes holds sensitive data: free text at that level
        lvl = max(KINDS[top_kind].level, "protected", key=lambda x: _RANK[x])
        return Finding("free_text", lvl, 0.8, [f"column name '{name}' suggests free text",
                                               f"{top_n}/{len(values)} values contain: {KINDS[top_kind].label}"])
    if top_kind and ratio > 0.6:
        candidates.append(Finding(top_kind, KINDS[top_kind].level, round(min(1.0, 0.5 + ratio / 2), 2),
                                  [f"{top_n}/{len(values)} sample values match: {KINDS[top_kind].label}"]))
    elif top_kind:
        # some values contain sensitive data: treat the column as free text holding it
        lvl = KINDS[top_kind].level
        candidates.append(Finding("free_text", lvl, 0.6,
                                  [f"{top_n}/{len(values)} values contain: {KINDS[top_kind].label}"]))
    if name_kind:
        candidates.append(Finding(name_kind, KINDS[name_kind].level, 0.6 if values else 0.5,
                                  [f"column name '{name}' suggests: {KINDS[name_kind].label}"]))
    if not candidates:
        long_text = values and sum(len(str(v)) > 60 for v in values) / len(values) > 0.3
        if long_text:
            return Finding("free_text", "protected", 0.5, ["long free text; could contain anything"])
        return Finding("category", "protected", 0.3, ["no signal found; defaulting to protected to be safe"])

    best = max(candidates, key=lambda f: (_RANK[f.level], f.confidence))
    agree = [c for c in candidates if c.kind == best.kind]
    if len(agree) > 1:
        best = Finding(best.kind, best.level, min(1.0, best.confidence + 0.2),
                       [r for c in agree for r in c.reasons])
    else:
        best.reasons = [r for c in candidates for r in c.reasons]
    return best


DOC_MARKERS = re.compile(r"\b(confidential|internal[ -]only|do not (?:distribute|share)|restricted|"
                         r"commercial[ -]in[ -]confidence|privileged)\b", re.I)


def classify_document(name: str, text: str) -> Finding:
    """Label a whole document: secrets inside -> secret; marked internal -> protected; else normal."""
    kinds = {k for k, _, _ in scan_text(text)}
    secrets = sorted(k for k in kinds if KINDS[k].level == "secret")
    if secrets:
        return Finding("free_text", "secret", 0.8, [f"contains {', '.join(KINDS[k].label for k in secrets)}"])
    if m := DOC_MARKERS.search(text[:4000]):
        return Finding("free_text", "protected", 0.8, [f"marked '{m.group(0)}'"])
    personal = sorted(k for k in kinds if KINDS[k].level == "protected")
    if personal:
        return Finding("free_text", "protected", 0.6, [f"contains {', '.join(KINDS[k].label for k in personal)}"])
    return Finding("free_text", "normal", 0.5, ["no sensitive markers or data found; review before sharing"])
