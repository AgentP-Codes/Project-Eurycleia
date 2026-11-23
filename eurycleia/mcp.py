# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""MCP proxy: put the vault in front of an existing agent with no code changes.

    agent host  <--stdio MCP-->  eurycleia proxy  <--stdio MCP-->  your MCP server(s)

The agent sees only the tools named in the policy's `tools:` section. Each call
becomes a vault read or action; the vault calls the real (upstream) MCP tools
itself, per the policy's `upstream:` section:

    upstream:
      sources:
        crm.customer: {tool: get_customer, key_arg: customer_id}
      sinks:
        email.send: {tool: send_email}

Trusted inputs (e.g. which customer this session is for) come from the host,
never from the model: `--trusted customer_id=12` on the command line, or the
host's `initialize` request under `params._meta.eurycleia.trusted`.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from typing import IO, Any

from . import __version__
from .errors import EurycleiaError
from .vault import Blocked, Task, Vault

log = logging.getLogger("eurycleia.mcp")

PROTOCOL_VERSION = "2025-06-18"


class MCPError(Exception):
    pass


# --------------------------------------------------------------------- upstream
MAX_LINE = 32 * 1024 * 1024      # one message from a connector; a longer one ends the connection


class StdioMCPClient:
    """Minimal MCP client for an upstream server started as a subprocess. A connector that doesn't answer
    within `timeout` seconds, or sends a message longer than MAX_LINE, gets an error, not a proxy that hangs
    or runs out of memory."""

    def __init__(self, command: list[str], env: dict[str, str] | None = None, timeout: float = 120,
                 cwd: str | os.PathLike | None = None):
        try:
            err: Any = sys.stderr.fileno()
        except (AttributeError, OSError, ValueError):
            err = subprocess.DEVNULL     # e.g. under a test runner that captures stderr
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=err, text=True, encoding="utf-8", errors="replace", bufsize=1,
                                     env=env, cwd=cwd)          # MCP messages are UTF-8, whatever the system uses
        self._id, self._lock, self.timeout = 0, threading.Lock(), timeout
        self.tools_changed = False          # the server said its tools changed (checked by ToolGuard)
        self._lines: queue.Queue = queue.Queue(maxsize=1000)
        threading.Thread(target=self._read, daemon=True, name="eurycleia-mcp-reader").start()
        init = self.request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                           "clientInfo": {"name": "eurycleia", "version": __version__}})
        info = (init or {}).get("serverInfo") if isinstance(init, dict) else None
        self.server_info: dict[str, Any] = info if isinstance(info, dict) else {}
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _read(self) -> None:
        """Runs on its own thread: hands each line the connector prints to request(), which can then stop
        waiting after a time limit."""
        out = self.proc.stdout
        assert out
        try:
            while True:
                line = out.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE and not line.endswith("\n"):
                    self._lines.put(MCPError("upstream MCP server sent a message that is too long"))
                    self.proc.kill()
                    return
                self._lines.put(line)
        except (OSError, ValueError):
            pass
        self._lines.put(None)                                  # the connector exited

    def _send(self, msg: dict[str, Any]) -> None:
        assert self.proc.stdin
        try:
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()
        except (OSError, ValueError):
            raise MCPError("upstream MCP server exited") from None

    def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        with self._lock:
            self._id += 1
            rid = self._id
            self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    line = self._lines.get(timeout=max(0.0, deadline - time.monotonic()))
                except queue.Empty:
                    raise MCPError(f"upstream MCP server didn't answer within {self.timeout:.0f} seconds") from None
                if line is None:
                    self._lines.put(None)                      # stays exited for the next caller too
                    raise MCPError("upstream MCP server exited")
                if isinstance(line, MCPError):
                    self._lines.put(line)
                    raise line
                try:
                    msg = json.loads(line)
                except (ValueError, RecursionError):
                    raise MCPError("upstream MCP server sent a message that isn't valid JSON") from None
                if not isinstance(msg, dict):
                    continue
                if msg.get("id") == rid and ("result" in msg or "error" in msg):
                    if "error" in msg:
                        err = msg["error"]
                        raise MCPError(str(err.get("message", "upstream error")) if isinstance(err, dict)
                                       else "upstream error")
                    return msg["result"]
                if msg.get("method") == "notifications/tools/list_changed":
                    self.tools_changed = True
                    continue
                if "method" in msg and "id" in msg:   # server->client request we don't support
                    self._send({"jsonrpc": "2.0", "id": msg["id"],
                                "error": {"code": -32601, "message": "not supported by eurycleia proxy"}})

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def _tool_result_to_value(result: dict[str, Any]) -> Any:
    if result.get("isError"):
        raise MCPError(_text(result) or "upstream tool failed")
    if "structuredContent" in result:
        return result["structuredContent"]
    text = _text(result)
    try:
        return json.loads(text)
    except (TypeError, ValueError, RecursionError):
        return text


def _text(result: dict[str, Any]) -> str:
    return "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")


def upstream_bindings(policy_raw: dict[str, Any], client: Any,
                      guard: Any = None) -> tuple[dict[str, Callable], dict[str, Callable]]:
    """Build vault sources/sinks that call the upstream MCP server's tools. With a ToolGuard, a connector tool
    that changed since it was approved is refused, however the vault came to call it."""

    def held(tool: str) -> None:
        if guard is not None:
            guard.check()
            if why := guard.blocked_upstream(tool):
                raise MCPError(why)

    up = policy_raw.get("upstream") or {}
    sources: dict[str, Callable] = {}
    sinks: dict[str, Callable] = {}
    for name, spec in (up.get("sources") or {}).items():
        def read(key: Any, _s=spec) -> dict | None:
            args = {_s["key_arg"]: key} if _s.get("key_arg") else {}
            try:
                held(_s["tool"])
                value = _tool_result_to_value(client.call_tool(_s["tool"], args))
            except MCPError:
                return None
            return value if isinstance(value, dict) else ({"body": value} if value else None)
        sources[name] = read
    for name, spec in (up.get("sinks") or {}).items():
        def act(_s=spec, **args: Any) -> Any:
            held(_s["tool"])
            return _tool_result_to_value(client.call_tool(_s["tool"], args))
        sinks[name] = act
    return sources, sinks


# ----------------------------------------------------------------------- server
class ProxyServer:
    """Serves MCP to the agent host; every tool call goes through a vault Task."""

    def __init__(self, vault: Vault, template: str, trusted: dict[str, Any] | None = None, guard: Any = None):
        self.vault, self.template, self.trusted = vault, template, dict(trusted or {})
        self.task: Task | None = None
        self.guard = guard                   # a ToolGuard: tools whose connector changed are held
        self._held_before: frozenset[str] = frozenset()
        self.list_changed = False            # tell the host to fetch the tool list again

    def handle(self, msg: Any) -> dict[str, Any] | None:
        """Answer one JSON-RPC message. Never raises: bad input gets an error reply."""
        if not isinstance(msg, dict):
            return _error(None, -32600, "invalid request: expected a JSON object")
        method, rid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if not isinstance(rid, (str, int, type(None))) or isinstance(rid, bool):
            rid = None
        if method is None:
            return None                      # a response to something we never send
        if not isinstance(method, str) or not isinstance(params, dict):
            return _error(rid, -32600, "invalid request: 'method' must be a string and 'params' an object")
        try:
            return self._handle(method, rid, params)
        except Exception as e:  # noqa: BLE001 - the proxy must stay up; log the type, not the details
            log.warning("internal error handling %s: %s", method[:40], type(e).__name__)
            return _error(rid, -32603, f"internal error ({type(e).__name__})")

    def _handle(self, method: str, rid: Any, params: dict[str, Any]) -> dict[str, Any] | None:
        try:
            if method == "initialize":
                meta = params.get("_meta") or {}
                meta = (meta.get("eurycleia") or meta.get("taskvault")) if isinstance(meta, dict) else None  # 0.5 name
                meta = meta.get("trusted") if isinstance(meta, dict) else None
                if meta is not None and not isinstance(meta, dict):
                    raise ValueError("_meta.eurycleia.trusted must be an object")
                self.trusted.update(meta or {})
                self.task = self.vault.start_task(self.template, **self.trusted)
                self._check_tools(force=True)
                self.list_changed = False
                result: Any = {"protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
                               "capabilities": {"tools": {"listChanged": self.guard is not None}},
                               "serverInfo": {"name": "eurycleia", "version": __version__},
                               "instructions": "Tools are scoped to this task by eurycleia. Secret values "
                                               "appear as [[vault:...]] placeholders; pass them unchanged."}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                self._check_tools()
                held = set(self.guard.held) if self.guard is not None else set()
                result = {"tools": [{"name": s["name"], "description": s["description"],
                                     "inputSchema": s["input_schema"]} for s in self._task().tool_specs()
                                    if s["name"] not in held]}
            elif method == "tools/call":
                name, arguments = params.get("name", ""), params.get("arguments") or {}
                if not isinstance(name, str) or not isinstance(arguments, dict):
                    raise ValueError("tools/call needs a string 'name' and an object 'arguments'")
                result = self._call(name, arguments)
            elif method.startswith("notifications/"):
                return None
            elif method in ("resources/list", "prompts/list"):
                result = {method.split("/")[0]: []}
            else:
                return _error(rid, -32601, f"method {method!r} not supported")
        except ValueError as e:
            return _error(rid, -32602, str(e))
        except MCPError as e:
            return _error(rid, -32603, str(e))
        return None if rid is None else {"jsonrpc": "2.0", "id": rid, "result": result}

    def _task(self) -> Task:
        if self.task is None:
            raise ValueError("initialize first")
        return self.task

    def _check_tools(self, force: bool = False) -> None:
        if self.guard is None:
            return
        try:
            self.guard.check(force=force)
        except (MCPError, OSError, ValueError) as e:
            log.warning("couldn't check the connector's tools: %s", type(e).__name__)
            if force:
                raise MCPError("couldn't read the connector's tools to check them against what was approved") from e
        now = frozenset(self.guard.held)
        if now != self._held_before:
            self._held_before = now
            self.list_changed = True

    def _call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self._check_tools()
        if self.guard is not None and (why := self.guard.blocked(name)):
            return {"isError": True, "content": [{"type": "text", "text": f"Held by eurycleia: {why}"}]}
        try:
            value = self._task().call_tool(name, arguments)
        except Blocked as e:
            return {"isError": True, "content": [{"type": "text", "text": f"Blocked by eurycleia: {e.reason}"}]}
        except (KeyError, MCPError) as e:
            return {"isError": True, "content": [{"type": "text", "text": f"Not available: {e}"}]}
        except EurycleiaError as e:          # e.g. the tool itself failed (message already masked)
            return {"isError": True, "content": [{"type": "text", "text": str(e)}]}
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        return {"content": [{"type": "text", "text": text}]}

    def serve(self, instream: IO[str], outstream: IO[str]) -> None:
        for line in instream:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except (ValueError, RecursionError):     # ValueError also covers numbers too long to convert
                reply: dict[str, Any] | None = _error(None, -32700, "parse error")
            else:
                reply = self.handle(msg)
            if self.list_changed:                    # a tool was held or released: the host should look again
                self.list_changed = False
                outstream.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}) + "\n")
            if reply is not None:
                outstream.write(json.dumps(reply) + "\n")
                outstream.flush()


def _error(rid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}
