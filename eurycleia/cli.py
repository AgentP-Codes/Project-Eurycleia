# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""eurycleia command line.

  eurycleia setup --sqlite DB --docs DIR ...     scan your data and write a policy for you
  eurycleia init [--template support|finance]    create eurycleia.yaml + fixtures.yaml from a template
  eurycleia check  [--policy P]                  validate and lint a policy
  eurycleia test   [--policy P] [--fixtures F]   run the worst-case attack suite (CI)
  eurycleia report [--audit FILE...]             what was (or would have been) blocked
  eurycleia serve  --task T --trusted k=v -- CMD run the MCP proxy in front of an MCP server
  eurycleia audit  verify|show|seal FILE         check, read or start protecting an audit log
  eurycleia keys   init|shred PATH               manage a local customer key
  eurycleia scan FILE...                         find secrets and personal data in text files
  eurycleia review --audit FILE                  list actions flagged for a human look
  eurycleia boxes holder|put|list|log|forget|unforget   deposit boxes for departments, customers, clients
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections import Counter
from importlib import resources
from pathlib import Path
from typing import Any

from . import __version__
from ._names import local, setting
from .audit import AuditLog
from .errors import EurycleiaError
from .policy import Policy, PolicyError

DEFAULT_POLICY = "eurycleia.yaml"
DEFAULT_STORE = ".eurycleia"


def main(argv: list[str] | None = None) -> int:
    POLICY, STORE = local(DEFAULT_POLICY, "taskvault.yaml"), local(DEFAULT_STORE, ".taskvault")  # 0.5's names
    p = argparse.ArgumentParser(prog="eurycleia", description="A task-scoped data vault for AI agents.")
    p.add_argument("--version", action="version", version=f"eurycleia {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("setup", help="scan your data and write a starter policy")
    s.add_argument("--sqlite", action="append", default=[], metavar="PATH", help="SQLite database file")
    s.add_argument("--postgres", action="append", default=[], metavar="DSN", help="Postgres DSN (needs psycopg)")
    s.add_argument("--file", action="append", default=[], metavar="PATH", help="CSV / JSON / JSONL table")
    s.add_argument("--docs", action="append", default=[], metavar="DIR", help="folder of text documents")
    s.add_argument("--domain", default="example.com", help="your company's email domain")
    s.add_argument("--no-pseudonyms", action="store_true", help="show real names/emails to the model")
    s.add_argument("--dir", default=".")
    s.add_argument("--force", action="store_true")
    s.add_argument("mcp", nargs=argparse.REMAINDER, help="-- command to start an MCP server to scan")

    s = sub.add_parser("scan", help="find secrets and personal data in text files")
    s.add_argument("files", nargs="+")

    s = sub.add_parser("review", help="list actions flagged for review")
    s.add_argument("--audit", nargs="+", required=True)

    s = sub.add_parser("boxes", help="deposit boxes: per-holder encrypted storage")
    bsub = s.add_subparsers(dest="boxes_cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", default=f"{STORE}/boxes.db", help="SQLite path or postgresql:// URL")
    common.add_argument("--key", required=True, help="the vault's key file")
    common.add_argument("--holder-keys", default=f"{STORE}/holder-keys", help="folder of holder keys")
    b = bsub.add_parser("holder", parents=[common], help="create a key for a department, customer or client")
    b.add_argument("--type", required=True, choices=["department", "customer", "client"])
    b.add_argument("--id", required=True)
    b = bsub.add_parser("put", parents=[common], help="store a CSV's rows in holders' boxes")
    b.add_argument("csv")
    b.add_argument("--source", required=True, help="source name, e.g. crm.customer")
    b.add_argument("--key-column", required=True)
    b.add_argument("--holder-type", required=True, choices=["department", "customer", "client"])
    b.add_argument("--holder-field", help="column holding each row's holder id (customers, clients)")
    b.add_argument("--holder-id", help="one holder for every row (e.g. a department)")
    b.add_argument("--policy", help="take field levels from this policy (otherwise detected)")
    bsub.add_parser("list", parents=[common], help="list boxes")
    b = bsub.add_parser("log", parents=[common], help="show and verify one box's log")
    b.add_argument("box")
    b = bsub.add_parser("forget", parents=[common], help="delete all of one holder's boxes (and keep them out)")
    b.add_argument("--holder", required=True, help="e.g. customer:12")
    b = bsub.add_parser("unforget", parents=[common], help="let a forgotten holder's boxes be made again")
    b.add_argument("--holder", required=True, help="e.g. customer:12")
    b = bsub.add_parser("compact", parents=[common], help="archive and remove old box log entries")
    b.add_argument("--older-than", type=float, required=True, metavar="DAYS")
    b.add_argument("--archive", default=None, help="write the removed entries here (compressed, encrypted)")
    b.add_argument("--min-entries", type=int, default=10, help="skip boxes with fewer old entries than this")
    b = bsub.add_parser("archive", parents=[common], help="open and check a log archive")
    b.add_argument("file")
    bsub.add_parser("migrate", parents=[common], help="upgrade a taskvault 0.4 box database")

    s = sub.add_parser("init", help="create a starter policy and fixtures from a template")
    s.add_argument("--template", choices=["support", "finance"], default="support")
    s.add_argument("--dir", default=".")
    s.add_argument("--force", action="store_true")

    s = sub.add_parser("check", help="validate and lint a policy")
    s.add_argument("--policy", default=POLICY)

    s = sub.add_parser("test", help="run the worst-case attack suite against a policy")
    s.add_argument("--policy", default=POLICY)
    s.add_argument("--fixtures", default="fixtures.yaml")
    s.add_argument("--task", action="append")
    s.add_argument("--no-assume-approved", action="store_true",
                   help="count 'needs approval' as blocked instead of testing the rule behind it")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("serve", help="run the MCP proxy (stdio)")
    s.add_argument("--policy", default=POLICY)
    s.add_argument("--task", required=True)
    s.add_argument("--trusted", action="append", default=[], metavar="KEY=VALUE")
    s.add_argument("--audit", default=None, help="append-only audit log file (JSONL)")
    s.add_argument("--shadow", action="store_true", help="log what would be blocked; block nothing")
    s.add_argument("--key", default=None, help="customer key file: enables the encrypted cache")
    s.add_argument("--eurycleia-connected", action="store_true", help=argparse.SUPPRESS)  # marker from `connect`
    s.add_argument("--boxes", default=None, help="deposit box database for sources with storage: boxes")
    s.add_argument("--holder-keys", default=f"{STORE}/holder-keys")
    s.add_argument("upstream", nargs=argparse.REMAINDER, help="-- command to start the upstream MCP server")

    s = sub.add_parser("audit", help="verify or read an audit log")
    s.add_argument("action", choices=["verify", "show", "repair", "seal"])
    s.add_argument("file")
    s.add_argument("--key", default=None, help="customer key file the log was written with (checks its MACs)")
    s.add_argument("--decision", default=None)

    s = sub.add_parser("api", help="local API for agents in other languages (TypeScript and JavaScript)")
    s.add_argument("--policy", default=POLICY)
    s.add_argument("--app", default=None, metavar="MODULE:FUNCTION",
                   help="your vault factory, e.g. eurycleia_app:build_vault (from `eurycleia setup`)")
    s.add_argument("--port", type=int, default=8765, help="port on 127.0.0.1 (0 = any free port)")
    s.add_argument("--audit", default="audit.jsonl", help="audit log (when not using --app)")
    s.add_argument("--key", default=None, help="customer key file: encrypted cache")
    s.add_argument("--shadow", action="store_true", help="watch mode: log what would be blocked, block nothing")
    s.add_argument("--connection-file", default=None,
                   help="where adapters find the URL and token (default: ~/.eurycleia/api.json)")
    s.add_argument("upstream", nargs=argparse.REMAINDER, help="optional: -- an MCP server providing the tools")

    s = sub.add_parser("connect", help="protect an agent's MCP servers (starts in watch mode)")
    s.add_argument("agent", help="claude-desktop, hermes, mcp-json (with --config), crewai, langgraph")
    s.add_argument("--policy", default=POLICY)
    s.add_argument("--task", required=False, help="the task template to run (default: the policy's only task)")
    s.add_argument("--trusted", action="append", default=[], metavar="KEY=VALUE")
    s.add_argument("--config", default=None, help="the agent's settings file (default: where the agent keeps it)")
    s.add_argument("--server", action="append", default=None, help="only this MCP server (repeatable)")
    s.add_argument("--audit", default=None, help="audit log (default: ~/.eurycleia/audit.jsonl)")
    s.add_argument("--key", default=None, help="customer key file")
    s.add_argument("--enforce", action="store_true", help="block from the start instead of watching first")

    s = sub.add_parser("disconnect", help="put an agent's original MCP servers back")
    s.add_argument("agent", nargs="?", default=None)
    s.add_argument("--config", default=None)

    s = sub.add_parser("report", aliases=["plan"],
                       help="what eurycleia blocked, or would have (connected agents, or --audit files)")
    s.add_argument("--audit", nargs="+", default=None, help="report on these audit logs instead")
    s.add_argument("--policy", default=None, help="with --audit: also list tasks, sources and actions never used")
    s = sub.add_parser("learn", help="draft a policy from what the agent did in watch mode")
    s.add_argument("--policy", required=True, help="the policy eurycleia was watching with")
    s.add_argument("--audit", nargs="+", default=None, help="audit logs to learn from (default: connected agents')")
    s.add_argument("--key", default=None, help="the customer key file, to check a keyed audit log first")
    s.add_argument("--out", default=None, help="draft policy file (default: <policy>.learned.yaml)")
    s.add_argument("--report", default="learn-report.md")
    s.add_argument("--min-tasks", type=int, default=5, help="learn a pattern only if seen in this many tasks")
    s.add_argument("--min-share", type=float, default=0.2, help="...and in at least this share of the task's runs")
    sub.add_parser("enforce", help="start blocking on every connected agent")
    sub.add_parser("watch", help="go back to watch mode (log, don't block)")

    s = sub.add_parser("keys", help="manage a local customer key")
    s.add_argument("action", choices=["init", "shred"])
    s.add_argument("path")

    args = p.parse_args(argv)
    try:
        return COMMANDS[args.cmd](args)
    except PolicyError as e:
        print(f"policy error: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"not found: {e.filename}", file=sys.stderr)
        return 2
    except EurycleiaError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


# ---------------------------------------------------------------- commands
def cmd_setup(a: argparse.Namespace) -> int:
    from .setup import run_setup
    mcp = [x for x in a.mcp if x != "--"]
    return run_setup(a.dir, sqlite=a.sqlite, postgres=a.postgres, files=a.file, docs=a.docs, mcp=mcp or None,
                     domain=a.domain, pseudonyms=not a.no_pseudonyms, force=a.force)


def cmd_scan(a: argparse.Namespace) -> int:
    from .detect import KINDS, scan_text
    found = 0
    for f in a.files:
        text = Path(f).read_text(errors="replace")
        for kind, s, _e in scan_text(text):
            line = text.count("\n", 0, s) + 1
            print(f"{f}:{line}: {KINDS[kind].label} ({KINDS[kind].level})")
            found += KINDS[kind].level == "secret"
    print(f"\n{found} secret value(s) found" if found else "no secrets found")
    return 1 if found else 0


def cmd_review(a: argparse.Namespace) -> int:
    entries = [e for f in a.audit for e in AuditLog(f, keep=None).entries]
    flags = [e for e in entries if e.get("decision") == "flag"]
    templates = {e.get("task"): e.get("template") for e in entries if e.get("event") == "task.start"}
    if not flags:
        print("nothing flagged")
    for e in flags:
        print(f"task {e.get('task')} ({templates.get(e.get('task'), '?')}) {e.get('sink')}:")
        for r in e.get("reasons", []):
            print(f"    - {r}")
    return 0


def _box_store(a: argparse.Namespace):
    from .boxes import BoxStore, LocalHolderKeys
    from .crypto import LocalKeyProvider
    return BoxStore(a.db, LocalKeyProvider(a.key, create=False), LocalHolderKeys(a.holder_keys),
                    _allow_legacy=getattr(a, "boxes_cmd", "") == "migrate")


def cmd_boxes(a: argparse.Namespace) -> int:
    import csv

    from .boxes import LocalHolderKeys, holder_name
    if a.boxes_cmd == "holder":
        h = holder_name(a.type, a.id)
        path = LocalHolderKeys(a.holder_keys).create(h)
        print(f"created key for {h}: {path}")
        print("Give this key to the holder (or keep it in their key service). Without it, their high-security")
        print("boxes can't be opened. Back it up, or set up a company recovery key.")
        return 0
    store = _box_store(a)
    if a.boxes_cmd == "put":
        with open(a.csv, newline="", encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
        if not rows:
            print("no rows")
            return 1
        if a.policy:
            src = Policy.load(a.policy).sources[a.source]
            levels = {c: src.level(None, c) for c in rows[0]}
        else:
            from .detect import classify_column
            levels = {c: classify_column(c, [r.get(c) for r in rows[:200]]).level for c in rows[0]}
        if not a.holder_field and not a.holder_id:
            print("give --holder-field (per row) or --holder-id (one holder)", file=sys.stderr)
            return 2
        from .boxes import HolderForgotten
        tiers: dict[str, int] = {}
        skipped = 0
        for r in rows:
            h = holder_name(a.holder_type, r[a.holder_field] if a.holder_field else a.holder_id)
            try:
                placed = store.store_record(a.source, r[a.key_column], r, h, levels)
            except HolderForgotten:
                skipped += 1                         # forgotten on request: their data isn't brought back
                continue
            for t in placed.values():
                tiers[t] = tiers.get(t, 0) + 1
        if skipped:
            print(f"skipped {skipped} rows for holders who were forgotten (see `eurycleia boxes unforget`)")
        print(f"stored {len(rows) - skipped} rows: {tiers.get('normal', 0)} values in normal boxes, "
              f"{tiers.get('high', 0)} in high-security boxes")
        print("fields in high-security boxes: " + (", ".join(c for c, lv in levels.items()
                                                                if store.tiers.get(lv) == "high") or "none"))
    elif a.boxes_cmd == "list":
        boxes = store.boxes()
        for b in boxes:
            print(f"{b.box_id}  {b.holder:<28} {b.tier:<7} {b.items} items")
        print(f"{len(boxes)} boxes")
    elif a.boxes_cmd == "log":
        for e in store.log(a.box):
            print(f"{e['seq']:>4}  {e['ts']:.0f}  {e['event']:<12} {json.dumps(e['detail'])}")
        ok = store.verify_log(a.box)
        print("log chain valid" if ok else "LOG CHAIN BROKEN - it was modified")
        return 0 if ok else 1
    elif a.boxes_cmd == "forget":
        if ":" not in a.holder:
            print("--holder looks like customer:12 (type:id)", file=sys.stderr)
            return 2
        had = any(b.holder == a.holder for b in store.boxes())
        n = store.forget_holder(a.holder)
        if not had and not n:
            print(f"no boxes found for {a.holder} (check the spelling); it is recorded as forgotten anyway")
        print(f"deleted {n} items from {a.holder}'s boxes; new boxes for them are refused until "
              f"`eurycleia boxes unforget --holder {a.holder}`")
    elif a.boxes_cmd == "unforget":
        found = store.unforget_holder(a.holder)
        print(f"{a.holder} can have boxes again (their old data stays deleted)" if found
              else f"{a.holder} wasn't forgotten")
    elif a.boxes_cmd == "compact":
        if a.archive and Path(a.archive).exists():
            print(f"{a.archive} already exists; choose a new archive file", file=sys.stderr)
            return 1
        n = store.compact_logs(a.older_than, a.archive, a.min_entries)
        where = f", archived to {a.archive}" if a.archive and n["entries"] else " (not archived)"
        print(f"compacted {n['entries']} log entries in {n['boxes']} boxes{where if n['entries'] else ''}")
    elif a.boxes_cmd == "archive":
        from .boxes import read_archive
        entries = read_archive(store, a.file)
        for e in entries:
            print(f"{e['box']}  {e['seq']:>4}  {e['ts']:.0f}  {e['event']:<12} {e['detail']}")
        print(f"{len(entries)} entries, archive intact")
    elif a.boxes_cmd == "migrate":
        n = store.migrate()
        if not n["boxes"]:
            print("already in the current format; nothing to do")
        else:
            print(f"upgraded {n['boxes']} boxes, {n['items']} items, {n['records']} records and "
                  f"{n['log_entries']} log entries; the vault key matched and every old log passed its tamper check")
            if n["skipped_records"]:
                print(f"{n['skipped_records']} damaged record index entries were left out (their items are kept)")
    return 0


def cmd_init(a: argparse.Namespace) -> int:
    out = Path(a.dir)
    out.mkdir(parents=True, exist_ok=True)
    files = {DEFAULT_POLICY: f"{a.template}.yaml", "fixtures.yaml": f"fixtures-{a.template}.yaml"}
    for dest, src in files.items():
        target = out / dest
        if target.exists() and not a.force:
            print(f"{target} already exists (use --force to overwrite)", file=sys.stderr)
            return 1
        target.write_text(resources.files("eurycleia.templates").joinpath(src).read_text())
        print(f"created {target}")
    print("\nNext: edit the policy for your data, then run `eurycleia check` and `eurycleia test`.\n"
          "Then `eurycleia connect <agent>` puts it in front of your agent in watch mode.")
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    from .attacks import lint
    policy = Policy.load(a.policy)
    print(f"{a.policy}: OK ({len(policy.sources)} sources, {len(policy.tasks)} tasks, {len(policy.tools)} tools)")
    for w in lint(policy):
        print(f"  warning: {w}")
    return 0


def cmd_test(a: argparse.Namespace) -> int:
    from .attacks import Fixtures, format_report, run_attack_suite
    policy = Policy.load(a.policy)
    report = run_attack_suite(policy, Fixtures.load(a.fixtures), a.task, assume_approved=not a.no_assume_approved)
    if a.json:
        print(json.dumps({"results": [r.__dict__ for r in report.results], "warnings": report.warnings}, indent=2))
    else:
        print(format_report(report))
    return 1 if report.leaks else 0


def _report_files(a: argparse.Namespace) -> int:
    entries = [e for f in a.audit for e in AuditLog(f, keep=None).entries]
    would = [e for e in entries if e.get("decision") == "would_block"]
    blocked = [e for e in entries if e.get("decision") == "block"]
    tasks = {e.get("task") for e in entries if e.get("event") == "task.start"}
    print(f"{len(tasks)} tasks observed, {len(would)} would-block decisions, {len(blocked)} blocks\n")
    if would:
        print("Would have been blocked (most common first):")
        for reason, n in Counter(e["reason"] for e in would).most_common():
            print(f"  {n:>5}  {reason}")
        print("\nIf any of these are legitimate, widen the policy for that task; otherwise they are what "
              "enforcement will stop.")
    if a.policy:
        policy = Policy.load(a.policy)
        used_sources = {e.get("source") for e in entries if e.get("event") == "read" and e.get("decision") == "allow"}
        used_sinks = {e.get("sink") for e in entries if e.get("event") == "act" and e.get("decision") == "allow"}
        started = Counter(e.get("template") for e in entries if e.get("event") == "task.start")
        print("\nCoverage (never exercised while observing - rare paths may get blocked later):")
        gaps = 0
        for tname, t in policy.tasks.items():
            if not started.get(tname):
                print(f"  task {tname}: never started")
                gaps += 1
                continue
            for s in t.reads:
                if s not in used_sources:
                    print(f"  task {tname}: never read {s}")
                    gaps += 1
            for s in t.sinks:
                if s not in used_sinks:
                    print(f"  task {tname}: never used {s}")
                    gaps += 1
        if not gaps:
            print("  none")
    return 0


def _cipher(key: str | None):
    if not key:
        return None
    from .crypto import Cipher, LocalKeyProvider
    return Cipher(LocalKeyProvider(key, create=False))


def _audit(path: str | None, key: str | None, keep: int | None = 10_000) -> AuditLog:
    """An audit log, keyed from the customer key file when there is one (see audit_key)."""
    if not key:
        return AuditLog(path, keep=keep)
    from .audit import audit_key
    from .crypto import LocalKeyProvider
    return AuditLog(path, keep=keep, key=audit_key(LocalKeyProvider(key, create=False)))


def cmd_serve(a: argparse.Namespace) -> int:
    from .cache import EncryptedCache
    from .mcp import ProxyServer, StdioMCPClient, upstream_bindings
    from .vault import Vault

    upstream = [x for x in a.upstream if x != "--"]
    if not upstream:
        print("give the upstream MCP server command after --", file=sys.stderr)
        return 2
    policy = Policy.load(a.policy)
    trusted = dict(kv.split("=", 1) for kv in a.trusted)
    trusted = {k: int(v) if v.isdigit() else v for k, v in trusted.items()}
    cipher = _cipher(a.key)
    client = StdioMCPClient(upstream)
    try:
        sources, sinks = upstream_bindings(policy.raw, client)
        boxes = None
        if a.boxes:
            from .boxes import BoxStore, LocalHolderKeys, box_sources
            from .crypto import LocalKeyProvider
            if not a.key:
                print("--boxes needs --key", file=sys.stderr)
                return 2
            boxes = BoxStore(a.boxes, LocalKeyProvider(a.key, create=False), LocalHolderKeys(a.holder_keys))
            sources.update(box_sources(policy, boxes))
        vault = Vault(policy, sources, sinks, audit=_audit(a.audit, a.key), mode="shadow" if a.shadow else "enforce",
                      cipher=cipher, cache=EncryptedCache(cipher, policy.cache_ttl_seconds) if cipher else None,
                      boxes=boxes)
        ProxyServer(vault, a.task, trusted).serve(sys.stdin, sys.stdout)
    finally:
        client.close()
    return 0


def _load_agent(spec: str):
    mod, _, fn = spec.partition(":")
    if not fn:
        raise SystemExit("--agent must look like module:function")
    sys.path.insert(0, str(Path.cwd()))
    return getattr(importlib.import_module(mod), fn)


def cmd_audit(a: argparse.Namespace) -> int:
    if a.action == "repair":
        side = AuditLog.repair(a.file)
        print(f"moved an unfinished last line to {side}; the log is usable again" if side
              else f"{a.file}: nothing to repair")
        return 0
    log = _audit(a.file, a.key, keep=None)
    if a.action == "seal":
        if not a.key:
            print("seal needs --key (the customer key file eurycleia will write this log with)", file=sys.stderr)
            return 2
        head = log.seal()
        print(f"{a.file}: nothing to seal (empty)" if head is None else
              f"{a.file}: protected from entry {head['keyed_from']} on; cutting off or rewriting any entry is now "
              "detected with the key")
        return 0
    if a.action == "verify":
        problem = log.problem()
        checked = "chain, keyed MACs and end-of-log record" if a.key else "chain"
        print(f"{a.file}: {len(log.entries)} entries, {checked} " +
              ("valid" if problem is None else f"BROKEN - {problem}"))
        if problem is None and not a.key:
            print("  (pass --key to also check it wasn't rewritten or cut short by someone without the key)")
        return 0 if problem is None else 1
    for e in log.entries:
        if a.decision and e.get("decision") != a.decision:
            continue
        print(json.dumps({k: v for k, v in e.items() if k not in ("hash", "prev")}, default=str))
    return 0


def cmd_api(a: argparse.Namespace) -> int:
    import signal

    from .api import ApiServer, remote_sinks
    from .connect import home
    from .vault import Vault

    policy = Policy.load(a.policy)
    sinks: dict = dict(remote_sinks(policy))         # actions your other-language app runs itself
    client = None
    if a.app:
        vault = _load_agent(a.app)(sinks=sinks)
        if not isinstance(vault, Vault):
            print(f"{a.app} must return a eurycleia Vault", file=sys.stderr)
            return 2
    else:
        sources: dict = {}
        upstream = [x for x in a.upstream if x != "--"]
        if upstream:
            from .mcp import StdioMCPClient, upstream_bindings
            client = StdioMCPClient(upstream)
            up_sources, up_sinks = upstream_bindings(policy.raw, client)
            sources.update(up_sources)
            sinks.update(up_sinks)
        cipher = _cipher(a.key)
        from .cache import EncryptedCache
        vault = Vault(policy, sources, sinks, audit=_audit(a.audit, a.key), mode="shadow" if a.shadow else "enforce",
                      cipher=cipher, cache=EncryptedCache(cipher, policy.cache_ttl_seconds) if cipher else None)
    server = ApiServer(vault, port=a.port, token=setting("API_TOKEN") or None)
    conn = server.write_connection_file(Path(a.connection_file) if a.connection_file else home() / "api.json")
    print(f"eurycleia api listening on {server.url} (this computer only)\n"
          f"adapters find the address and token in {conn}\n"
          f"mode: {'WATCH (logging only)' if vault.mode == 'shadow' else 'ENFORCE'}   stop with Ctrl+C", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.httpd.server_close()
        server.remove_connection_file()
        if client:
            client.close()
    return 0


def cmd_connect(a: argparse.Namespace) -> int:
    from .connect import connect
    task = a.task
    if not task and a.agent not in ("crewai", "langgraph"):
        tasks = list(Policy.load(a.policy).tasks)
        if len(tasks) != 1:
            print(f"choose a task with --task ({', '.join(tasks)})", file=sys.stderr)
            return 2
        task = tasks[0]
    if a.key:
        # the protected agent will write a keyed log; it won't start keying an older log by itself (see
        # `eurycleia audit seal`), so say so now rather than let the agent's tools fail later
        from .connect import home
        audit_file = Path(a.audit) if a.audit else home() / "audit.jsonl"
        if audit_file.exists() and audit_file.stat().st_size and \
                not audit_file.with_name(audit_file.name + ".head").exists():
            print(f"{audit_file} already has entries but isn't protected with a key yet. If it was written "
                  f"without one (taskvault 0.5, or without --key), check and seal it once:\n"
                  f"  eurycleia audit verify {audit_file}\n  eurycleia audit seal {audit_file} --key {a.key}\n"
                  f"or give this agent its own new log with --audit. Then run connect again.", file=sys.stderr)
            return 1
    names = connect(a.agent, a.policy, task or "", a.trusted, config=a.config, servers=a.server, audit=a.audit,
                    key=a.key, enforce=a.enforce)
    mode = "ENFORCE (blocking)" if a.enforce else "WATCH (logging only, nothing is blocked yet)"
    print(f"protected {len(names)} MCP server(s): {', '.join(names)}\nmode: {mode}\n"
          f"a backup of the settings file was saved next to it (.eurycleia-backup)\n"
          f"restart the agent app so it picks up the change")
    if not a.enforce:
        print("next: use the agent as normal, then run `eurycleia report`, then `eurycleia enforce`")
    return 0


def cmd_disconnect(a: argparse.Namespace) -> int:
    from .connect import disconnect
    names = disconnect(a.agent, a.config)
    print(f"restored {len(names)} MCP server(s): {', '.join(names) or 'none'} (restart the agent app)")
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    if a.audit:
        return _report_files(a)
    from .connect import report
    print(report())
    return 0


def cmd_learn(a: argparse.Namespace) -> int:
    from .learn import learn, load_entries, write
    paths = a.audit
    if not paths:
        from .connect import _connected, home
        paths = sorted({str(rec.get("audit", home() / "audit.jsonl")) for _p, _f, rec in _connected()})
    try:
        entries = load_entries(paths, a.key)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    result = learn(a.policy, entries, a.min_tasks, a.min_share)
    if not result.tasks_seen:
        print("no tasks in the audit log yet: use the agent for a while in watch mode, then try again")
        return 1
    policy = Path(a.policy)
    out = Path(a.out) if a.out else policy.with_name(policy.stem + ".learned.yaml")
    report = Path(a.report)
    write(result, out, report, a.policy, paths)
    remaining = sum(sum(c.values()) for c in result.still_blocked.values())
    print(f"learned from {sum(result.tasks_seen.values())} tasks: {len(result.changes)} change(s), "
          f"{len(result.needs_you)} for you to decide, {len(result.looked_wrong)} thing(s) that looked wrong")
    print(f"the old policy would have blocked {result.total_problems} action(s) while watching; the draft blocks "
          f"{remaining}")
    print(f"draft: {out}")
    print(f"report: {report} (read it before using the draft)")
    return 0


def cmd_enforce(a: argparse.Namespace) -> int:
    from .connect import set_mode
    names = set_mode(True)
    print(f"enforcing on {len(names)} server(s): {', '.join(names) or 'already enforcing'} (restart the agent app)")
    return 0


def cmd_watch(a: argparse.Namespace) -> int:
    from .connect import set_mode
    names = set_mode(False)
    print(f"watch mode on {len(names)} server(s): {', '.join(names) or 'already watching'} (restart the agent app)")
    return 0


def cmd_keys(a: argparse.Namespace) -> int:
    from .crypto import LocalKeyProvider
    if a.action == "init":
        if Path(a.path).exists():
            print(f"{a.path} already exists", file=sys.stderr)
            return 1
        LocalKeyProvider(a.path)
        print(f"created {a.path} (mode 600). Keep it out of version control and back it up.")
    else:
        LocalKeyProvider(a.path, create=False).shred()
        print(f"destroyed {a.path}: everything encrypted with it is now unreadable")
    return 0


COMMANDS: dict[str, Any] = {
    "setup": cmd_setup, "init": cmd_init, "check": cmd_check, "test": cmd_test, "plan": cmd_report,
    "serve": cmd_serve, "api": cmd_api, "connect": cmd_connect, "disconnect": cmd_disconnect, "report": cmd_report,
    "enforce": cmd_enforce, "watch": cmd_watch, "review": cmd_review, "audit": cmd_audit, "keys": cmd_keys,
    "scan": cmd_scan, "boxes": cmd_boxes, "learn": cmd_learn,
}

if __name__ == "__main__":
    sys.exit(main())
