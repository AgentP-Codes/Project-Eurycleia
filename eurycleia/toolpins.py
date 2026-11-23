# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Tools that can't change behind your back (rug pulls, OWASP ASI04).

A connector (an MCP server) you approved can later change what its tools say or take, for example a new
description with instructions for the model, or a new input to carry data out. Eurycleia records each
connector's tool definitions the first time it starts, and every time it checks again it compares them:

  * a tool the policy uses that changed, or appeared, is **held**: hidden from the agent and refused, until
    a person looks at what changed and approves it (`eurycleia tools review`, `eurycleia tools approve`);
  * a changed tool the policy doesn't use, a removed tool, or a new server version is reported, not held.

The record is kept on this machine only (one private file per connector in ~/.eurycleia/tool-pins/), compared
exactly (no AI), and every change is written to the audit log.

Even before this check, the agent only ever sees the tools and descriptions in your policy, never the
connector's own, and can only pass the inputs the policy lists. This check is what tells you that the
connector behind those tools is no longer the one you approved.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import owner_only
from .toolscan import scan_tools, show, strong_findings

FORMAT = 1
_KEPT = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
MAX_TOOLS = 2000             # more tools than this from one connector isn't a connector we can check
MAX_TOOL_BYTES = 200_000     # one tool's whole definition
_ODD = "x-eurycleia"         # marks a definition eurycleia couldn't take as it came (always "not approved")


def canonical(tool: dict[str, Any]) -> dict[str, Any]:
    """The parts of a tool definition that matter, in a fixed form (field order never counts as a change)."""
    return json.loads(json.dumps({k: tool[k] for k in _KEPT if k in tool}, sort_keys=True))


def fingerprint(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def server_key(command: list[str]) -> str:
    """A short id for a connector, from the command that starts it."""
    return "srv-" + fingerprint(list(command))[:12]


def _inputs(tool: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    required = schema.get("required") if isinstance(schema, dict) else None
    return ((props if isinstance(props, dict) else {}),
            {r for r in (required if isinstance(required, list) else []) if isinstance(r, str)})


def _rest(schema: Any) -> Any:
    return {k: v for k, v in schema.items() if k not in ("properties", "required")} if isinstance(schema, dict) \
        else schema


def describe_change(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """What changed in one tool, in plain words. Names come from the connector, so they're shown made safe
    (`show`): a name can't hide or rewrite the line it's on. Never raises, whatever shape a definition has."""
    out = []
    if new.get(_ODD):
        out.append(str(new[_ODD]))
    if old.get("description") != new.get("description"):
        out.append("its description changed")
    if old.get("title") != new.get("title"):
        out.append("its title changed")
    (op, oreq), (np, nreq) = _inputs(old), _inputs(new)
    for name in sorted(set(np) - set(op)):
        out.append(f"new input '{show(name, 60)}'" + (" (required)" if name in nreq else ""))
    for name in sorted(set(op) - set(np)):
        out.append(f"input '{show(name, 60)}' removed")
    for name in sorted(set(op) & set(np)):
        a, b = op[name] if isinstance(op[name], dict) else {}, np[name] if isinstance(np[name], dict) else {}
        shown = show(name, 60)
        if a.get("type") != b.get("type"):
            out.append(f"input '{shown}' changed type ({show(a.get('type'), 20)} -> {show(b.get('type'), 20)})")
        if a.get("description") != b.get("description"):
            out.append(f"input '{shown}' has a new description")
        rest = {k: v for k, v in a.items() if k not in ("type", "description")}
        if rest != {k: v for k, v in b.items() if k not in ("type", "description")} or \
                (not isinstance(op[name], dict) or not isinstance(np[name], dict)) and op[name] != np[name]:
            out.append(f"input '{shown}' changed its allowed values or format")
        if (name in oreq) != (name in nreq):
            out.append(f"input '{shown}' is now {'required' if name in nreq else 'optional'}")
    if _rest(old.get("inputSchema") or {}) != _rest(new.get("inputSchema") or {}):
        out.append("its input rules changed")
    if old.get("outputSchema") != new.get("outputSchema"):
        out.append("what it returns changed")
    if old.get("annotations") != new.get("annotations"):
        out.append("its hints changed (for example whether it only reads, or can delete)")
    return out[:40] or (["its definition changed"] if old != new else [])


def index(tools: list[Any]) -> dict[str, Any]:
    """Tool name -> its definition in a fixed form. A tool listed twice with different definitions, or one too
    big to check, is kept with a mark that no approved definition has, so it always counts as not approved."""
    now: dict[str, Any] = {}
    for t in tools[:MAX_TOOLS]:
        if not isinstance(t, dict) or not isinstance(t.get("name"), str):
            continue
        name, c = t["name"], canonical(t)
        size = len(json.dumps(c, ensure_ascii=False))
        if size > MAX_TOOL_BYTES:
            c = {"name": name, _ODD: f"its definition is too big to check ({size} characters)"}
        if name in now and now[name] != c:
            c = {"name": name, _ODD: "it is listed more than once, with different definitions"}
        now[name] = c
    if len(tools) > MAX_TOOLS:
        now[f"({len(tools) - MAX_TOOLS} more tools)"] = {"name": "(more)", _ODD: "too many tools to check"}
    return now


@dataclass
class Review:
    """The result of comparing a connector's tools now with what was approved."""
    server: str
    label: str
    first_seen: bool = False
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: dict[str, list[str]] = field(default_factory=dict)
    server_changed: list[str] = field(default_factory=list)
    warnings: dict[str, list[str]] = field(default_factory=dict)     # tool -> what the scan found (new/changed)
    too_many: bool = False       # more tools than can be checked: nothing from this connector counts as approved

    @property
    def unapproved(self) -> set[str]:
        """Tools whose current definition hasn't been approved: changed or new."""
        return set(self.changed) | set(self.added)

    def empty(self) -> bool:
        return not (self.added or self.removed or self.changed or self.server_changed)

    def lines(self) -> list[str]:
        out = [f"{show(t, 64)}: {', '.join(why)}" for t, why in sorted(self.changed.items())]
        out += [f"{show(t, 64)}: new tool" for t in sorted(self.added)]
        out += [f"{show(t, 64)}: removed" for t in sorted(self.removed)]
        out += self.server_changed
        out += [f"  warning: {w}" for t in sorted(self.warnings) for w in self.warnings[t]]
        return out


def compare(key: str, label: str, approved: dict[str, Any], now: dict[str, Any], old_info: dict[str, Any],
            info: dict[str, Any]) -> Review:
    review = Review(key, label)
    review.added = sorted(set(now) - set(approved))
    review.removed = sorted(set(approved) - set(now))
    review.changed = {n: describe_change(approved[n], now[n]) for n in sorted(set(now) & set(approved))
                      if fingerprint(approved[n]) != fingerprint(now[n]) or now[n].get(_ODD)}
    if old_info.get("name") != info.get("name"):
        review.server_changed.append(f"the connector now calls itself '{show(info.get('name'), 60)}' "
                                     f"(was '{show(old_info.get('name'), 60)}')")
    if old_info.get("version") != info.get("version"):
        review.server_changed.append(f"connector version {show(old_info.get('version'), 40)} -> "
                                     f"{show(info.get('version'), 40)}")
    return review


def _warnings(now: dict[str, Any], review: Review) -> dict[str, list[str]]:
    """What the scan says about each new or changed tool (mild findings marked as such)."""
    names = set(now)
    out: dict[str, list[str]] = {}
    for n in sorted(review.unapproved):
        if now[n].get(_ODD):
            out.setdefault(n, []).append(f"{show(n, 64)}: {now[n][_ODD]}; this can't be approved as it is")
        for f in scan_tools([now[n]], names):
            out.setdefault(n, []).append(f.line() + ("" if f.strong else " (mild)"))
    return out


class ToolPins:
    """The approved tool definitions of each connector, one private file per connector."""

    def __init__(self, folder: str | Path | None = None, clock: Callable[[], float] = time.time):
        if folder is None:
            from ._names import home_dir
            folder = home_dir() / "tool-pins"
        self.folder, self.clock = Path(folder), clock

    def _path(self, key: str) -> Path:
        if not re.fullmatch(r"srv-[0-9a-f]{12}", key):
            raise ValueError(f"not a connector id: {key!r} (see `eurycleia tools status`)")
        return self.folder / f"{key}.json"

    def load(self, key: str) -> dict[str, Any] | None:
        try:
            data = json.loads(self._path(key).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as e:
            raise ValueError(f"the tool record for {key} can't be read ({type(e).__name__}); remove it with "
                             f"`eurycleia tools forget {key}` and approve the connector again") from None
        if not isinstance(data, dict) or data.get("format") != FORMAT:
            raise ValueError(f"the tool record for {key} is in a format this version doesn't know")
        return data

    def _save(self, key: str, data: dict[str, Any]) -> None:
        self.folder.mkdir(parents=True, exist_ok=True)
        owner_only(self.folder)
        path = self._path(key)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8"))
                f.flush()
                os.fsync(f.fileno())
            owner_only(tmp)
            os.replace(tmp, path)                     # all at once: never half a record
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def all(self) -> list[dict[str, Any]]:
        out = []
        for p in sorted(self.folder.glob("srv-*.json")) if self.folder.exists() else []:
            try:
                rec = self.load(p.stem)
            except ValueError:
                continue
            if rec:
                out.append(rec)
        return out

    def check(self, command: list[str], server_info: dict[str, Any] | None, tools: list[dict[str, Any]],
              label: str | None = None) -> Review:
        """Compare what the connector offers now with what was approved. The first time a connector is seen,
        what it offers is recorded as approved (you set it up just now). Anything different afterwards is kept
        as 'seen' until approved, so approving approves exactly what was looked at."""
        key = server_key(command)
        now = index(tools)
        info = {k: (v if isinstance(v := (server_info or {}).get(k), (str, int, float, type(None))) else str(v))
                for k in ("name", "version")}
        label = show(label or info.get("name") or " ".join(command), 80)
        rec = self.load(key)
        if rec is None:
            # first sight: what you just set up is approved, except tools whose definition has strong signs of
            # poisoning (instructions for the AI, secrecy, hidden text...): those wait for a person to look
            flagged = strong_findings(scan_tools(list(now.values())))
            for n, d in now.items():
                if d.get(_ODD):
                    flagged.setdefault(n, []).append(f"{show(n, 64)}: {d[_ODD]}")
            approved = {n: d for n, d in now.items() if n not in flagged}
            self._save(key, {"format": FORMAT, "server": key, "label": label, "command": list(command),
                             "info": info, "approved": approved, "approved_at": self.clock(),
                             "seen": {"tools": now, "info": info, "at": self.clock()} if flagged else None})
            return Review(key, label, first_seen=True, added=sorted(flagged), warnings=flagged,
                          too_many=len(tools) > MAX_TOOLS)
        review = compare(key, rec.get("label") or label, rec.get("approved") or {}, now, rec.get("info") or {}, info)
        review.warnings = _warnings(now, review)
        review.too_many = len(tools) > MAX_TOOLS
        if review.too_many:
            review.server_changed.append(f"the connector lists more than {MAX_TOOLS} tools: too many to check, "
                                         "so none of them can be used")
        seen = None if review.empty() else {"tools": now, "info": info}
        before = rec.get("seen")
        if (seen is None) != (before is None) or (seen and (fingerprint(seen["tools"]) != fingerprint(before["tools"])
                                                           or seen["info"] != before.get("info"))):
            rec["seen"] = None if seen is None else {**seen, "at": self.clock()}
            self._save(key, rec)
        return review

    def pending(self, key: str) -> Review | None:
        """What's waiting for approval on one connector (from the last check), or None."""
        rec = self.load(key)
        if not rec or not rec.get("seen"):
            return None
        seen = rec["seen"]
        review = compare(key, rec.get("label") or key, rec.get("approved") or {}, seen.get("tools") or {},
                         rec.get("info") or {}, seen.get("info") or {})
        review.warnings = _warnings(seen.get("tools") or {}, review)
        return review

    def approve(self, key: str, tools: list[str] | None = None) -> list[str]:
        """Approve what was last seen: every change on the connector, or just the named tools. Returns what
        was approved."""
        rec = self.load(key)
        if not rec or not rec.get("seen"):
            return []
        seen = rec["seen"]
        now, approved = seen.get("tools") or {}, dict(rec.get("approved") or {})
        names = sorted((set(now) | set(approved)) if tools is None else set(tools))
        done = []
        for n in names:
            if n in now and now[n].get(_ODD):
                continue                              # couldn't be checked, so it can't be approved
            if n in now and approved.get(n) != now[n]:
                approved[n] = now[n]
                done.append(n)
            elif n not in now and n in approved:
                del approved[n]                       # approving a removal forgets the old definition
                done.append(n)
        if tools is None:
            rec["info"] = seen.get("info") or rec.get("info")
        rec["approved"], rec["approved_at"] = approved, self.clock()
        rest = {n: d for n, d in now.items() if approved.get(n) != d}
        gone = set(approved) - set(now)
        rec["seen"] = seen if (rest or gone or rec["info"] != seen.get("info")) else None
        self._save(key, rec)
        return done

    def stamp(self, key: str) -> float:
        """When this connector's record last changed (an approval shows up here), 0 if there is none."""
        try:
            return self._path(key).stat().st_mtime_ns
        except FileNotFoundError:
            return 0

    def forget(self, key: str) -> bool:
        path = self._path(key)
        if path.exists():
            path.unlink()
            return True
        return False


class ToolGuard:
    """In `eurycleia serve`: checks the connector's tools when the session starts, whenever the connector says
    its tools changed, and every `recheck` seconds, and holds the policy's tools whose connector tool isn't
    approved. `uses` maps each policy tool to the connector tool it calls."""

    def __init__(self, client: Any, command: list[str], uses: dict[str, str], pins: ToolPins | None = None,
                 hold: bool = True, recheck: float = 300, audit: Any = None, signals: Any = None,
                 warn: Callable[[str], None] | None = None, clock: Callable[[], float] = time.monotonic):
        self.client, self.command, self.uses = client, list(command), dict(uses)
        self.pins = pins or ToolPins()
        self.hold, self.recheck, self.audit, self.clock = hold, recheck, audit, clock
        self.signals = signals
        self.warn = warn or (lambda msg: None)
        self.held: dict[str, list[str]] = {}         # policy tool -> why
        self.held_upstream: set[str] = set()         # connector tools not approved as they are now
        self.review: Review | None = None
        self._last = -1e18
        self._reported = ""
        self._stamp: float | None = None
        self._key = server_key(self.command)
        self._checking = threading.Lock()            # `eurycleia api` calls from several threads
        self.hold_all = False

    def check(self, force: bool = False) -> None:
        with self._checking:
            self._check(force)

    def _check(self, force: bool) -> None:
        stale = self.clock() - self._last >= self.recheck
        approved = self._stamp is not None and self.pins.stamp(self._key) != self._stamp   # someone approved
        if not (force or stale or approved or getattr(self.client, "tools_changed", False)):
            return
        self.client.tools_changed = False
        self._last = self.clock()
        tools = list_tools(self.client)
        review = self.pins.check(self.command, getattr(self.client, "server_info", None), tools)
        self._stamp = self.pins.stamp(self._key)
        self.review = review
        used = set(self.uses.values())
        held = {}
        for policy_tool, upstream in self.uses.items():
            if upstream in review.changed:
                held[policy_tool] = review.changed[upstream]
            elif upstream in review.added:
                held[policy_tool] = ["it wasn't offered when the connector was approved"]
            elif review.too_many:
                held[policy_tool] = [f"the connector lists more than {MAX_TOOLS} tools, too many to check"]
        self.held = held if self.hold else {}
        self.held_upstream = review.unapproved if self.hold else set()
        self.hold_all = self.hold and review.too_many
        report = fingerprint(review.lines())
        if review.first_seen:
            self._record("tools.recorded", review, sorted(used))
            if review.added:
                self.warn(f"eurycleia: connector {review.label} ({review.server}) recorded; "
                          f"{', '.join(show(t, 64) for t in review.added)} not approved yet because of what its "
                          f"definition says. "
                          f"Review: eurycleia tools review {review.server}")
        elif not review.empty() and report != self._reported:
            self._reported = report
            self._record("tools.changed", review, sorted(held))
            what = "held until approved" if self.hold and held else "not held (watch mode)" if held else "reported"
            self.warn(f"eurycleia: connector {review.label} ({review.server}) changed since it was approved; "
                      f"{len(held)} tool(s) the policy uses {what}. Review: eurycleia tools review "
                      f"{review.server}")

    def _record(self, event: str, review: Review, tools: list[str]) -> None:
        if self.audit is not None:
            self.audit.record(event, server=review.server, label=review.label, changes=review.lines()[:50],
                              held=sorted(self.held), tools=tools)
        if event == "tools.changed" and self.signals is not None:      # Eumaeus' page shows it too
            self.signals.send("connector_changed", server=review.server, label=review.label,
                              detail=f"{len(self.held)} tool(s) held until approved")

    def blocked(self, policy_tool: str) -> str | None:
        """Why this policy tool is held right now, or None."""
        why = self.held.get(policy_tool)
        if not why:
            return None
        return (f"the connector changed this tool since it was approved ({'; '.join(why)}). It stays "
                f"unavailable until someone runs `eurycleia tools review` and approves the change.")


    def blocked_upstream(self, tool: str) -> str | None:
        """Why the connector tool itself is held (however the vault came to call it), or None."""
        if tool not in self.held_upstream and not self.hold_all:
            return None
        return f"the connector's tool '{show(tool, 64)}' changed since it was approved and is held"


def list_tools(client: Any, limit: int = 50) -> list[dict[str, Any]]:
    """Every tool the connector offers, following its pages."""
    tools: list[dict[str, Any]] = []
    cursor = None
    for _ in range(limit):
        page = client.request("tools/list", {"cursor": cursor} if cursor else {})
        page = page if isinstance(page, dict) else {}
        listed = page.get("tools")
        tools += [t for t in (listed if isinstance(listed, list) else []) if isinstance(t, dict)]
        cursor = page.get("nextCursor")
        if not cursor or not isinstance(cursor, str) or len(tools) > MAX_TOOLS:
            break
    return tools


def policy_uses(policy_raw: dict[str, Any], policy_tools: dict[str, Any]) -> dict[str, str]:
    """Each policy tool name -> the connector tool it ends up calling (through `upstream:`)."""
    up = policy_raw.get("upstream") or {}
    by_source = {n: (s or {}).get("tool") for n, s in (up.get("sources") or {}).items()}
    by_sink = {n: (s or {}).get("tool") for n, s in (up.get("sinks") or {}).items()}
    out = {}
    for name, tm in policy_tools.items():
        target = by_source.get(tm.read) if tm.read else by_sink.get(tm.act) if tm.act else None
        if isinstance(target, str):
            out[name] = target
    return out
