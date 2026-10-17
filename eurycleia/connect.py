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
import shutil
import stat
import sys
import time
from pathlib import Path
from typing import Any

from ._names import MARKS, home_dir
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


def _save(path: Path, fmt: str, data: dict[str, Any]) -> None:
    """Replace the settings file all at once, keeping its permissions (it may hold API keys) and its
    start-of-file marker, and writing to the real file if the path is a symbolic link."""
    real = path.resolve()
    if fmt == "json":
        text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    else:
        import yaml
        text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
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
    return json.loads(p.read_text()) if p.exists() else {}


def _save_state(state: dict[str, Any]) -> None:
    home().mkdir(parents=True, exist_ok=True)
    _state_path().write_text(json.dumps(state, indent=2))


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
    _save(path, fmt, data)
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
        _save(path, fmt, data)
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
        for name, original in rec["servers"].items():
            entry = (data.get(section) or {}).get(name)
            if entry and _wrapped(entry):
                entry["command"], entry["args"] = original["command"], original["args"]
                restored.append(name)
        _save(path, fmt, data)
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
