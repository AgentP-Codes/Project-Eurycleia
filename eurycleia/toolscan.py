# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Warnings about what a connector's tool definitions say (tool poisoning, shadowing).

A tool's description and its inputs' descriptions are written by whoever made the connector, and an AI model
reads them as instructions. Published attacks hide orders in them: read the user's private files and pass them
in, copy every email to an outside address, never tell the user. This scan looks for the signs, with fixed
patterns, no AI (a model asked to judge a poisoned description can be fooled by it).

Strong signs (instructions aimed at the AI, secrecy, hidden text, private files, "always copy to ...") hold a
tool; mild ones (a mention of passwords, a link, another tool's name) are only reported, since honest
descriptions have them too. Either way these are warnings, not verdicts: a clean result doesn't make a
connector safe, and a warning can be a false alarm. What actually protects you is elsewhere: the agent only
sees your policy's descriptions, only the inputs your policy lists, and every recipient is checked against
trusted data. Where the warnings are used:

  * `eurycleia setup` doesn't copy a flagged description into the policy it writes;
  * a tool flagged the first time a connector is recorded waits for approval instead of being approved;
  * `eurycleia tools review` shows the warnings for each changed tool.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

MAX_DESCRIPTION = 1500       # longer than any honest description we've seen; long ones hide things
MAX_TEXT = 6000              # one piece of text longer than this isn't checked past here, and is flagged as strong
MAX_PIECES = 3000            # pieces of text in one tool definition; more than this is flagged, not checked


def show(value: Any, limit: int = 120) -> str:
    """Anything a connector said, made safe to print: one line, every control or invisible character (colour
    codes, cursor moves, line breaks, right-to-left marks) shown as \\xNN, and cut to `limit`. A connector's
    names and descriptions are shown to the person deciding whether to approve it, so it mustn't be able to
    wipe or rewrite what's on their screen."""
    text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
    out = []
    for ch in text[: limit * 2]:
        if ch == " " or (ch.isprintable() and unicodedata.category(ch) not in ("Cf", "Co", "Cs", "Zl", "Zp")):
            out.append(ch)
        else:
            out.append(f"\\x{ord(ch):02x}" if ord(ch) < 256 else f"\\u{ord(ch):04x}")
    shown = "".join(out)
    return shown if len(shown) <= limit and len(text) <= limit * 2 else shown[:limit] + "…"


@dataclass(frozen=True)
class Finding:
    tool: str
    where: str               # "description", "input 'x'", "title"
    kind: str                # see KINDS
    excerpt: str

    @property
    def strong(self) -> bool:
        return self.kind in STRONG

    def line(self) -> str:
        return f"{show(self.tool, 64)}: {KINDS[self.kind]} in its {show(self.where, 80)} (\"{show(self.excerpt)}\")"


KINDS = {
    "instructions": "instructions aimed at the AI",
    "secrecy": "asks the AI to keep something from the user",
    "secret_files": "points the AI at private files",
    "send_elsewhere": "tells the AI to send or copy data somewhere",
    "hidden": "hidden or disguised text",
    "secret_words": "mentions keys or passwords",
    "address": "contains an address or link",
    "other_tools": "names another tool",
    "too_long": "an unusually long description",
    "unchecked": "too much text to check",
}
STRONG = frozenset({"instructions", "secrecy", "secret_files", "send_elsewhere", "hidden", "unchecked"})

_P = [
    ("instructions", r"<\s*/?\s*(?:important|system|instructions?|admin|secret)\s*>|\[\s*/?\s*inst\s*\]"),
    ("instructions", r"\b(?:ignore|disregard|forget|override)\b.{0,40}\b(?:instructions?|rules|guidelines|"
                     r"previous|prior|above|system)\b"),
    ("instructions", r"\b(?:before|after|instead of)\s+(?:using|calling|running|answering|"
                     r"you\s+(?:use|call|answer))\b"),
    ("instructions", r"\byou\s+(?:must|should|have\s+to|need\s+to)\s+(?:always|first|also|never)\b"),
    ("instructions", r"\bwhen\s+this\s+tool\s+is\s+(?:available|present|installed|loaded|enabled)\b|"
                     r"(?<![\w-])[\w-]{1,64}\s+tool\s+(?:must|should|has\s+to)\b"),
    ("instructions", r"\b(?:as\s+an?\s+ai|assistant\s+must|the\s+(?:ai|model|assistant|agent)\s+(?:must|should))\b"),
    ("secrecy", r"\b(?:do\s*n[o']?t|never|without|(?:must|should|shall)\s*(?:not|n't))\s+"
                r"(?:tell(?:ing)?|mention(?:ing)?|inform(?:ing)?|reveal(?:ing)?|notify(?:ing)?|alert(?:ing)?|"
                r"disclos(?:e|ing))\b"),
    ("secrecy", r"\b(?:secretly|covertly)\b|\b(?:silently|quietly)\s+(?:\w+\s+){0,2}?(?:send|copy|forward|upload|"
                r"include|read|access|add|attach|share|post)|\bthe\s+user\s+(?:must|should)\s*(?:not|n't)\s+know\b"),
    ("secret_files", r"(?:~|%userprofile%|\$home)[/\\]|\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.env\b|\.aws[/\\]|"
                r"\bmcp\.json\b|claude_desktop_config|\.npmrc\b|\.netrc\b|/etc/(?:passwd|shadow)\b"),
    ("secret_words", r"\b(?:api[\s_-]?keys?|access[\s_-]?tokens?|private[\s_-]?keys?|passwords?|credentials?|"
                r"secrets?|session\s+cookies?)\b"),
    ("send_elsewhere", r"\b(?:always|also|all|every|each|any)\b.{0,25}\b(?:b?cc|forward|copy|send|post|upload)"
                       r"\b.{0,40}(?:@|https?://|\bwww\.)"),
    ("send_elsewhere", r"\b(?:b?cc|forward|copy|send|post|upload)\b.{0,15}"
                       r"\b(?:every|all|each|any|a\s+copy|copies)\b.{0,40}(?:@|https?://|\bwww\.)"),
    ("send_elsewhere", r"\b(?:always|also)\s+(?:b?cc|copy|forward|include)\b"),
    ("address", r"(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+|https?://[^\s\"'<>]+"),
]
_COMPILED = [(k, re.compile(p, re.I | re.S)) for k, p in _P]
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")
_B64 = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_COMMENT = re.compile(r"<!--|-->|\x1b\[")          # HTML comments and terminal codes hide text from a person


def _excerpt(text: str, m: re.Match | None) -> str:
    if m is None:
        return text[:60]
    a, b = max(0, m.start() - 15), min(len(text), m.end() + 15)
    return re.sub(r"\s+", " ", text[a:b]).strip()[:90]


def scan_text(tool: str, where: str, text: Any, other_tools: set[str] | frozenset[str] = frozenset()) -> list[Finding]:
    if not isinstance(text, str) or not text.strip():
        return []
    out: list[Finding] = []
    if len(text) > MAX_TEXT:                    # never spend long on one text, and never wave a long one through
        out.append(Finding(tool, where, "unchecked", f"{len(text)} characters"))
        text = text[:MAX_TEXT]
    if _INVISIBLE.search(text) or _COMMENT.search(text) or any(unicodedata.category(c) == "Co" for c in text):
        out.append(Finding(tool, where, "hidden", "invisible characters or hidden text"))
    if (m := _B64.search(text)) is not None:
        out.append(Finding(tool, where, "hidden", _excerpt(text, m)[:40] + "…"))
    plain = unicodedata.normalize("NFKC", _INVISIBLE.sub("", text))
    seen: set[str] = set()
    for kind, rx in _COMPILED:
        if kind in seen:
            continue
        if (m := rx.search(plain)) is not None:
            out.append(Finding(tool, where, kind, _excerpt(plain, m)))
            seen.add(kind)
    for other in sorted(other_tools - {tool}):
        if 4 <= len(other) <= 64 and re.search(rf"(?<![\w-]){re.escape(other)}(?![\w-])", plain, re.I):
            out.append(Finding(tool, where, "other_tools", other))
            break
    if where == "description" and len(text) > MAX_DESCRIPTION:
        out.append(Finding(tool, where, "too_long", f"{len(text)} characters"))
    return out


_WORDS = re.compile(r"[_\-.]+|(?<=[a-z])(?=[A-Z])")


def _pieces(value: Any, where: str, out: list[tuple[str, str]], depth: int = 0) -> None:
    """Every piece of text anywhere in a definition, with where it was found: descriptions, titles, default
    values, examples, allowed values, hints, and the names of inputs themselves (published attacks hide
    instructions in all of them, not only in the description)."""
    if len(out) > MAX_PIECES or depth > 40:
        return
    if isinstance(value, str):
        out.append((where, value))
    elif isinstance(value, list):
        for v in value:
            _pieces(v, where, out, depth + 1)
    elif isinstance(value, dict):
        for k, v in value.items():
            k = str(k)
            if where.endswith("inputs") or len(k) > 24:      # an input's name, or any unusually long name
                label = f"input '{k[:40]}'" if where.endswith("inputs") else f"{where} name"
                out.append((f"{label} (its name)", k))
                out.append((f"{label} (its name)", _WORDS.sub(" ", k)))
            if where.endswith("inputs"):
                inner = f"input '{k[:40]}'"
            elif k == "properties":
                inner = f"{where} inputs" if where != "tool" else "inputs"
            elif where == "tool" and k in ("description", "title"):
                inner = k
            elif k in ("description", "title", "default", "examples", "enum", "const"):
                inner = where if where != "tool" else k
            else:
                inner = where if where != "tool" else {"inputSchema": "tool", "outputSchema": "what it returns",
                                                       "annotations": "hints"}.get(k, k)
            _pieces(v, inner, out, depth + 1)


def scan_tool(tool: Any, other_tools: set[str] | frozenset[str] = frozenset()) -> list[Finding]:
    """Warnings for one tool definition: every piece of text in it, wherever it is. Never raises, whatever
    shape the definition has."""
    if not isinstance(tool, dict):
        return []
    name = tool.get("name") if isinstance(tool.get("name"), str) else "?"
    pieces: list[tuple[str, str]] = []
    _pieces({k: v for k, v in tool.items() if k != "name"}, "tool", pieces)
    out: list[Finding] = []
    if len(pieces) > MAX_PIECES:
        out.append(Finding(name, "definition", "unchecked", f"more than {MAX_PIECES} pieces of text"))
    done: set[tuple[str, str]] = set()
    for where, text in pieces[:MAX_PIECES]:
        for f in scan_text(name, where, text, other_tools):
            if (f.where, f.kind) not in done:               # one warning of each kind per place
                done.add((f.where, f.kind))
                out.append(f)
    return out


def strong_findings(findings: list[Finding]) -> dict[str, list[str]]:
    """Tool -> the strong warnings about it (what holds a tool or keeps its description out of a policy)."""
    out: dict[str, list[str]] = {}
    for f in findings:
        if f.strong:
            out.setdefault(f.tool, []).append(f.line())
    return out


def scan_tools(tools: list[dict[str, Any]], known: set[str] | frozenset[str] = frozenset()) -> list[Finding]:
    """Warnings for every tool a connector offers. `known` adds tool names from other connectors, so a
    description that steers how another connector's tools are used (shadowing) is caught too."""
    names = {str(t.get("name")) for t in tools if isinstance(t, dict)} | set(known)
    return [f for t in tools if isinstance(t, dict) for f in scan_tool(t, names)]
