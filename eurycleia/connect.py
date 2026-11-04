# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""`eurycleia connect`: put eurycleia in front of an agent's existing MCP tool servers.

    eurycleia connect claude-desktop --policy eurycleia.yaml --task support_reply --trusted customer_id=12
    eurycleia report                  # what eurycleia would have blocked so far
    eurycleia enforce                 # start blocking
    eurycleia disconnect claude-desktop

It edits the agent's own settings file: each chosen MCP server's command is wrapped in
`eurycleia serve ... -- <original command>`. New connections start in WATCH mode (shadow): eurycleia
records what it would block but blocks nothing, so nothing breaks on day one. A backup of the
settings file is made first, and the original commands are remembered so `disconnect` puts them
back exactly.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import sys
import time
from pathlib import Path
from typing import Any

from ._names import MARKS, home_dir
from .audit import owner_only
from .errors import EurycleiaError
from .policy import Policy

MARK = MARKS[0]          # appears in wrapped args, so we never wrap twice (0.5 used --taskvault-connected)


class ConnectError(EurycleiaError):
    pass


def home() -> Path:
    return home_dir()


def _wrapped(entry: dict[str, Any]) -> bool:
    """Is this server already wrapped by `connect` (by this version or by taskvault 0.5)?"""
    return any(m in (entry.get("args") or []) for m in MARKS)


def default_config(agent: str) -> Path:
    if agent == "claude-desktop":
        if sys.platform == "darwin":
            return Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"
        if os.name == "nt":
            appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
            return appdata / "Claude/claude_desktop_config.json"
        return Path.home() / ".config/Claude/claude_desktop_config.json"
    if agent == "hermes":
        return Path.home() / ".hermes/config.yaml"
    raise ConnectError(f"no default settings file for {agent!r}; give one with --config")


AGENTS = {  # agent -> (file format, key holding the MCP servers)
    "claude-desktop": ("json", "mcpServers"),
    "hermes": ("yaml", "mcp_servers"),
    "mcp-json": ("json", "mcpServers"),      # any other app using the common {"mcpServers": {...}} file
}

SNIPPETS = {
    "crewai": "from eurycleia.integrations.crewai import protect\n"
              "agent = Agent(..., tools=protect(task))          # task = vault.start_task(...)",
    "langgraph": "from eurycleia.integrations.langchain import protect\n"
                 "agent = create_agent(model, tools=protect(task))  # task = vault.start_task(...)",
}


# ------------------------------------------------------------------ settings files
def _load(path: Path, fmt: str) -> dict[str, Any]:
    if not path.exists():
        raise ConnectError(f"{path} doesn't exist. Is the agent installed, or is its settings file elsewhere? "
                           f"(use --config)")
    raw = path.read_bytes()
    text = raw.decode("utf-8-sig")               # Windows editors often add an invisible marker (BOM) at the start
    try:
        if fmt == "json":
            data = json.loads(text or "{}")
        else:
            import yaml
            data = yaml.safe_load(text) or {}
    except Exception as e:  # noqa: BLE001 - json/yaml parse errors
        where = f" (line {e.lineno})" if hasattr(e, "lineno") else ""
        raise ConnectError(f"{path} isn't valid {fmt.upper()}{where}; fix it (or restore a backup) and try again. "
                           "Nothing was changed.") from None
    if not isinstance(data, dict):
        raise ConnectError(f"{path} isn't a settings file eurycleia understands")
    return data


def _yaml_block(lines: list[str], start: int, indent: int) -> int:
    """The line after the block that starts at `start`: the next line indented `indent` or less that isn't
    blank or a comment (comments just above the next entry stay with it)."""
    end = start + 1
    last = start + 1
    while end < len(lines):
        stripped = lines[end].strip()
        if stripped and not stripped.startswith("#"):
            if len(lines[end]) - len(lines[end].lstrip()) <= indent:
                break
            last = end + 1
        end += 1
    return last


def _yaml_edit(text: str, data: dict[str, Any], section: str, names: list[str]) -> str | None:
    """Rewrite only the named servers' entries under `section`, leaving every other line (comments,
    other servers, other settings, blank lines) exactly as it was. None if the file's layout is one this
    can't edit safely (flow style, anchors, tabs...), in which case the caller writes the whole file."""
    import yaml
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    head = [i for i, ln in enumerate(lines) if re.match(rf"{re.escape(section)}\s*:\s*(#.*)?$", ln.rstrip("\r\n"))]
    if len(head) != 1:
        return None
    for name in names:
        start = head[0] + 1
        end = _yaml_block(lines, head[0], 0)
        child = [i for i in range(start, end) if lines[i].strip() and not lines[i].lstrip().startswith("#")]
        if not child:
            return None
        indent = len(lines[child[0]]) - len(lines[child[0]].lstrip(" "))
        if indent == 0 or "\t" in lines[child[0]][:indent]:
            return None
        at = [i for i in child if len(lines[i]) - len(lines[i].lstrip(" ")) == indent
              and re.match(rf"\s*['\"]?{re.escape(name)}['\"]?\s*:\s*(#.*)?$", lines[i].rstrip("\r\n"))]
        if len(at) != 1:
            return None
        stop = _yaml_block(lines, at[0], indent)
        dumped = yaml.safe_dump({name: data[section][name]}, sort_keys=False, allow_unicode=True,
                                default_flow_style=False, width=10**6)
        newline = "\r\n" if lines[at[0]].endswith("\r\n") else "\n"
        block = [" " * indent + ln + newline for ln in dumped.splitlines()]
        lines[at[0]:stop] = block
    out = "".join(lines)
    try:
        if yaml.safe_load(out) != data:          # anything unexpected: don't risk it
            return None
    except yaml.YAMLError:
        return None
    return out


def _save(path: Path, fmt: str, data: dict[str, Any], section: str = "", names: list[str] | None = None) -> None:
    """Replace the settings file all at once, keeping its permissions (it may hold API keys) and its
    start-of-file marker, and writing to the real file if the path is a symbolic link. In a YAML file only the
    changed servers' lines are rewritten, so the person's comments and layout are kept."""
    real = path.resolve()
    if fmt == "json":
        text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    else:
        import yaml
        old = real.read_bytes().decode("utf-8-sig") if real.exists() else ""
        edited = _yaml_edit(old, data, section, names or []) if old and section else None
        text = edited if edited is not None else yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    raw = text.encode("utf-8")
    if real.exists() and real.read_bytes().startswith(b"\xef\xbb\xbf"):
        raw = b"\xef\xbb\xbf" + raw
    mode = stat.S_IMODE(real.stat().st_mode) if real.exists() else 0o600
    tmp = real.with_name(f".{real.name}.eurycleia-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, real)                     # all or nothing: never a half-written settings file
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _state_path() -> Path:
    return home() / "connections.json"


def _state() -> dict[str, Any]:
    p = _state_path()
    if not p.exists():
        return {}
    if os.name != "nt" and stat.S_IMODE(p.stat().st_mode) & 0o077:   # made by an earlier version: lock it now
        owner_only(p)
    return json.loads(p.read_text())


def _save_state(state: dict[str, Any]) -> None:
    """connections.json keeps a copy of each agent's original server settings, which can hold API keys, so it's
    private to this user (0600, or an owner-only access list on Windows) from the moment it exists, and replaced
    all at once. Before 0.7.1 it was created with the default permissions, usually readable by everyone."""
    folder = home()
    folder.mkdir(parents=True, exist_ok=True)
    path = _state_path()
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(state, indent=2).encode())
            f.flush()
            os.fsync(f.fileno())
        owner_only(tmp)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


# ------------------------------------------------------------------ commands
def connect(agent: str, policy: str | os.PathLike[str], task: str, trusted: list[str], config: str | None = None,
            servers: list[str] | None = None, audit: str | None = None, key: str | None = None,
            enforce: bool = False) -> list[str]:
    """Wrap the agent's MCP servers with eurycleia. Returns the names of the servers now protected."""
    if agent in SNIPPETS:
        raise ConnectError(f"{agent} is set up in code, not a settings file. Add:\n\n{SNIPPETS[agent]}")
    if agent not in AGENTS:
        raise ConnectError(f"unknown agent {agent!r} (choose from {', '.join([*AGENTS, *SNIPPETS])})")
    fmt, section = AGENTS[agent]
    path = Path(config) if config else default_config(agent)
    pol = Policy.load(policy)                                        # fail early on a bad policy
    if task not in pol.tasks:
        raise ConnectError(f"task {task!r} isn't in {policy} (tasks: {', '.join(pol.tasks) or 'none'})")
    if not (pol.raw.get("upstream") or {}):
        raise ConnectError("the policy has no 'upstream' section mapping the server's tools. Generate one with:\n"
                           "  eurycleia setup -- <the MCP server's command>")
    for kv in trusted:
        if "=" not in kv:
            raise ConnectError(f"--trusted needs KEY=VALUE, got {kv!r}")
    missing = [t for t in pol.tasks[task].trusted if t not in {kv.split("=", 1)[0] for kv in trusted}]
    if missing:
        raise ConnectError(f"task {task!r} needs trusted inputs: {missing} (pass --trusted KEY=VALUE)")

    data = _load(path, fmt)
    entries = data.get(section) or {}
    if not isinstance(entries, dict) or not entries:
        raise ConnectError(f"{path} has no MCP servers under '{section}' to protect")
    chosen = servers or list(entries)
    unknown = [s for s in chosen if s not in entries]
    if unknown:
        raise ConnectError(f"no MCP server called {unknown} in {path} (found: {', '.join(entries)})")

    backup = path.resolve().with_name(path.resolve().name + ".eurycleia-backup")
    old_backup = path.resolve().with_name(path.resolve().name + ".taskvault-backup")
    if not backup.exists() and not old_backup.exists():       # a 0.5 backup already holds the original
        shutil.copy2(path.resolve(), backup)          # keeps the original's permissions
    audit_path = Path(audit) if audit else home() / "audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    state = _state()
    record = state.setdefault(str(path.resolve()), {"agent": agent, "servers": {}})
    done = []
    for name in chosen:
        entry = entries[name]
        if not isinstance(entry, dict) or not entry.get("command"):
            raise ConnectError(f"server {name!r} has no command (only local, command-based servers can be wrapped)")
        if _wrapped(entry):
            done.append(name)                                        # already connected
            continue
        record["servers"][name] = {"command": entry["command"], "args": list(entry.get("args") or [])}
        wrapped = ["-m", "eurycleia", "serve", MARK, "--policy", str(Path(policy).resolve()), "--task", task]
        for kv in trusted:
            wrapped += ["--trusted", kv]
        wrapped += ["--audit", str(audit_path.resolve())]
        if key:
            wrapped += ["--key", str(Path(key).resolve())]
        if not enforce:
            wrapped.append("--shadow")
        wrapped += ["--", entry["command"], *[str(a) for a in entry.get("args") or []]]
        entry["command"], entry["args"] = sys.executable, wrapped
        done.append(name)
    record.update(connected=record.get("connected") or time.time(), audit=str(audit_path.resolve()))
    _save(path, fmt, data, section, done)
    _save_state(state)
    return done


def _connected() -> list[tuple[Path, str, dict[str, Any]]]:
    out = []
    for path, rec in _state().items():
        fmt, _ = AGENTS.get(rec.get("agent", ""), ("json", "mcpServers"))
        out.append((Path(path), fmt, rec))
    if not out:
        raise ConnectError("nothing is connected yet (run `eurycleia connect` first)")
    return out


def set_mode(enforce: bool) -> list[str]:
    """Switch every connected server between watch (shadow) and enforce. Returns the servers changed."""
    state = _state()
    if not state:
        raise ConnectError("nothing is connected yet (run `eurycleia connect` first)")
    changed = []
    for p, rec in state.items():
        fmt, section = AGENTS.get(rec.get("agent", ""), ("json", "mcpServers"))
        path = Path(p)
        data = _load(path, fmt)
        before = len(changed)
        for name in rec["servers"]:
            entry = (data.get(section) or {}).get(name)
            if not entry or not _wrapped(entry):
                continue
            args = list(entry["args"])
            split = args.index("--")
            head, tail = [a for a in args[:split] if a != "--shadow"], args[split:]
            if not enforce:
                head.append("--shadow")
            if head + tail != args:
                entry["args"] = head + tail
                changed.append(name)
        _save(path, fmt, data, section, changed[before:])
        rec["mode"] = "enforce" if enforce else "watch"
    _save_state(state)
    return changed


def disconnect(agent: str | None = None, config: str | None = None) -> list[str]:
    """Put the original commands back. Returns the servers restored."""
    state = _state()
    targets = [str(Path(config).resolve())] if config else [p for p, r in state.items()
                                                              if agent is None or r.get("agent") == agent]
    restored = []
    for p in targets:
        rec = state.get(p)
        if not rec:
            continue
        fmt, section = AGENTS.get(rec["agent"], ("json", "mcpServers"))
        path = Path(p)
        data = _load(path, fmt)
        here = []
        for name, original in rec["servers"].items():
            entry = (data.get(section) or {}).get(name)
            if entry and _wrapped(entry):
                entry["command"], entry["args"] = original["command"], original["args"]
                here.append(name)
        restored += here
        _save(path, fmt, data, section, here)
        del state[p]
    _save_state(state)
    return restored


def report(policy: str | None = None) -> str:
    """Plain-English summary of what eurycleia saw while connected."""
    from collections import Counter

    from .audit import AuditLog
    lines = []
    for _path, _fmt, rec in _connected():
        audit = Path(rec.get("audit", home() / "audit.jsonl"))
        entries = AuditLog(audit, keep=None).entries if audit.exists() else []
        days = (time.time() - rec.get("connected", time.time())) / 86400
        tasks = sum(e.get("event") == "task.start" for e in entries)
        would = [e for e in entries if e.get("decision") == "would_block"]
        blocked = [e for e in entries if e.get("decision") == "block"]
        flags = [e for e in entries if e.get("decision") == "flag"]
        mode = rec.get("mode", "watch")
        lines += [f"{rec['agent']} ({', '.join(rec['servers'])}): {mode} mode, connected {days:.1f} days",
                  f"  {tasks} sessions, {len(would)} would have been blocked, {len(blocked)} blocked, "
                  f"{len(flags)} flagged for review"]
        for reason, n in Counter(e.get("reason", "?") for e in would + blocked).most_common(8):
            lines.append(f"    {n:>4}  {reason}")
        if mode == "watch":
            if not tasks:
                lines.append("  Nothing observed yet: use the agent as normal for a while, then check again.")
            elif would:
                lines.append("  If any of these were legitimate, run `eurycleia learn --policy <your policy>` to draft "
                             "a policy from what the agent did, or widen it by hand. When the list is only things "
                             "you'd want stopped, run `eurycleia enforce`.")
            else:
                lines.append("  Nothing would have been blocked. When you're comfortable, run `eurycleia enforce`.")
    return "\n".join(lines)
