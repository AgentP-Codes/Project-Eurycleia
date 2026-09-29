# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""A local API so agents written in other languages (TypeScript, Go, Java, ...) can use taskvault.

    taskvault api --app taskvault_app:build_vault          # connectors from `taskvault setup`
    taskvault api --policy taskvault.yaml -- <MCP server>  # or tools from an MCP server

The language adapters (in `adapters/`) are thin clients: every check, placeholder, pseudonym, audit entry
and block happens here, in the same code the Python SDK uses. Nothing is re-implemented per language.

Actions ("sinks") such as sending an email can run on either side:

* in Python, if the app factory or MCP server provides them, or
* in the other language's app: the adapter registers a handler, and when the vault approves the action
  it asks the adapter to run it with the real values (like a Python sink function receives them), then
  masks whatever the handler returns before the model sees it.

Locked down by default: listens on 127.0.0.1 only; every request needs a random bearer token; requests
from web pages (an Origin header) and unexpected Host headers are refused, so a website you visit can't
reach it; bodies are size-limited; tasks expire when idle.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import queue
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import __version__
from .errors import TaskvaultError
from .vault import Blocked, SinkError, Task, Vault

log = logging.getLogger("taskvault.api")
MAX_BODY = 1024 * 1024
_current = threading.local()


class ApiError(TaskvaultError):
    """`taskvault api` can't start as asked."""


def _alive(pid: int) -> bool:
    if os.name == "nt":          # checking another process needs extra Windows calls; assume it has gone
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True              # exists, owned by someone else
    return True


class RemoteSink:
    """A sink whose code lives in the adapter's app (another language). See module docs."""

    def __init__(self, name: str):
        self.name = name

    def __call__(self, **args: Any) -> Any:
        ex = getattr(_current, "exchange", None)
        if ex is None:
            raise RuntimeError(f"{self.name} is run by the app connected through `taskvault api`, "
                               "and can only be used from there")
        return ex.run_remote(self.name, args)


def remote_sinks(vault_or_policy: Any) -> dict[str, RemoteSink]:
    """A RemoteSink for every action the policy names (in any task, or behind any tool)."""
    policy = getattr(vault_or_policy, "policy", vault_or_policy)
    names = {s for t in policy.tasks.values() for s in t.sinks}
    names |= {tm.act for tm in policy.tools.values() if tm.act}
    return {name: RemoteSink(name) for name in sorted(names)}


class _Exchange:
    """One API call running on a worker thread, able to pause while the adapter runs a sink."""

    def __init__(self, exec_timeout: float):
        self.id = secrets.token_urlsafe(16)
        self.outbox: queue.Queue = queue.Queue()
        self.inbox: queue.Queue = queue.Queue()
        self.exec_timeout = exec_timeout

    def run_remote(self, sink: str, args: dict[str, Any]) -> Any:
        self.outbox.put({"status": "execute", "exec": self.id, "sink": sink, "args": args})
        try:
            reply = self.inbox.get(timeout=self.exec_timeout)
        except queue.Empty:
            raise TimeoutError(f"the app didn't finish {sink} within {self.exec_timeout:.0f} seconds") from None
        if "error" in reply:
            raise RuntimeError(str(reply["error"]))   # masked by the vault; never cut first (cut values escape)
        return reply.get("result")


class _Session:
    def __init__(self, task: Task):
        self.task, self.lock, self.last = task, threading.Lock(), time.monotonic()


class ApiServer:
    def __init__(self, vault: Vault, port: int = 0, token: str | None = None, idle_minutes: float = 30,
                 exec_timeout: float = 120, max_tasks: int = 1000):
        self.vault = vault
        self.token = token or secrets.token_urlsafe(32)
        self.idle, self.exec_timeout, self.max_tasks = idle_minutes * 60, exec_timeout, max_tasks
        self.sessions: dict[str, _Session] = {}
        self.pending: dict[str, tuple[_Exchange, float]] = {}
        self._nonces: dict[str, float] = {}
        self._lock = threading.Lock()
        server = self

        class Handler(_Handler):
            api = server

        self.httpd = _Server(("127.0.0.1", port), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"

    # ------------------------------------------------------------ lifecycle
    def serve_forever(self) -> None:
        self.httpd.serve_forever(poll_interval=0.1)       # also how quickly shutdown() returns

    def start(self) -> ApiServer:
        threading.Thread(target=self.serve_forever, daemon=True, name="taskvault-api").start()
        return self

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def write_connection_file(self, path: Path) -> Path:
        """Where adapters find the URL and token. Written owner-only, all at once, never through a symbolic
        link, and never over the file of another `taskvault api` that is still running."""
        path = Path(path)
        if not path.parent.exists():
            path.parent.mkdir(parents=True, mode=0o700)
        if path.is_symlink():
            raise ApiError(f"{path} is a symbolic link; refusing to write the token through it")
        if path.exists():
            try:
                other = int(json.loads(path.read_text()).get("pid") or 0)
            except (ValueError, TypeError, AttributeError, OSError):
                other = 0
            if other and other != os.getpid() and _alive(other):
                raise ApiError(f"another taskvault api (process {other}) is using {path}; stop it, "
                               "or give this one its own --connection-file")
        tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(json.dumps({"url": self.url, "token": self.token, "pid": os.getpid()}).encode())
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)                  # replaces a link or loose file; never writes through it
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        self._conn_file = path
        return path

    def remove_connection_file(self) -> None:
        """Remove the connection file, but only if it's still ours (not a newer server's)."""
        path = getattr(self, "_conn_file", None)
        try:
            if path and json.loads(path.read_text()).get("token") == self.token:
                path.unlink()
        except (OSError, ValueError, AttributeError):
            pass

    def _fresh_nonce(self, nonce: str) -> bool:
        """Each signed request's random value is accepted once (replays are refused)."""
        now = time.monotonic()
        with self._lock:
            if len(self._nonces) > 10000:
                for k in [k for k, t in self._nonces.items() if now - t > 2 * AUTH_WINDOW + 5]:
                    del self._nonces[k]
                if len(self._nonces) > 400_000:
                    return False                               # flooded: refuse rather than grow without end
            if nonce in self._nonces:
                return False
            self._nonces[nonce] = now
            return True

    # -------------------------------------------------------------- actions
    def _expire(self) -> None:
        now = time.monotonic()
        with self._lock:
            for sid in [s for s, v in self.sessions.items() if now - v.last > self.idle]:
                del self.sessions[sid]
            for eid in [e for e, (_, t) in self.pending.items() if now - t > self.exec_timeout]:
                del self.pending[eid]

    def start_task(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self._expire()
        template, trusted = body.get("template"), body.get("trusted") or {}
        if not isinstance(template, str) or not isinstance(trusted, dict):
            return 400, {"error": "give 'template' (a task name) and 'trusted' (an object)"}
        with self._lock:
            if len(self.sessions) >= self.max_tasks:
                return 429, {"error": "too many open tasks; end some first"}
        if not all(isinstance(k, str) and k.isidentifier() for k in trusted):
            return 400, {"error": "trusted input names must be plain names"}
        try:
            task = self.vault.start_task(template, **trusted)
        except (KeyError, ValueError) as e:
            return 400, {"error": str(e).strip("'\"")}
        except TypeError:
            return 400, {"error": "a trusted input has a reserved name"}
        sid = secrets.token_urlsafe(16)
        with self._lock:
            self.sessions[sid] = _Session(task)
        return 200, {"task": sid, "tools": task.tool_specs()}

    def _session(self, sid: str) -> _Session | None:
        self._expire()
        with self._lock:
            s = self.sessions.get(sid)
            if s:
                s.last = time.monotonic()
            return s

    def run(self, sid: str, op: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        s = self._session(sid)
        if s is None:
            return 404, {"error": "no such task (it ended or expired)"}
        if op == "call":
            name, args = body.get("name"), body.get("arguments") or {}
            if not isinstance(name, str) or not isinstance(args, dict):
                return 400, {"error": "give 'name' (a tool) and 'arguments' (an object)"}
            fn = lambda: s.task.call_tool(name, args)  # noqa: E731
        elif op == "read":
            source, key, fields = body.get("source"), body.get("key"), body.get("fields")
            if not isinstance(source, str) or (fields is not None and not isinstance(fields, list)):
                return 400, {"error": "give 'source', and optionally 'key' and 'fields' (a list)"}
            fn = lambda: s.task.read(source, key, fields=fields)  # noqa: E731
        elif op == "act":
            sink, args = body.get("sink"), body.get("args") or {}
            if not isinstance(sink, str) or not isinstance(args, dict):
                return 400, {"error": "give 'sink' and 'args' (an object)"}
            fn = lambda: s.task.act(sink, **args)  # noqa: E731
        elif op == "end":
            with self._lock:
                self.sessions.pop(sid, None)
            return 200, {"status": "ended"}
        else:
            return 404, {"error": "unknown operation"}
        ex = _Exchange(self.exec_timeout)

        def worker() -> None:
            _current.exchange = ex
            # one call at a time per task (tasks keep state). If an earlier call is stuck, give up rather
            # than queue: a queued action could otherwise run after the app was told it timed out.
            # wait longer than an earlier call can take to time out, so a slow app never makes this one fail
            if not s.lock.acquire(timeout=self.exec_timeout + 30):
                ex.outbox.put({"status": "error", "message": "the task is still busy with an earlier call"})
                return
            try:
                out = {"status": "ok", "result": fn()}
            except Blocked as e:
                out = {"status": "blocked", "reason": e.reason}
            except SinkError as e:        # already masked by the vault
                out = {"status": "error", "message": str(e)}
            except KeyError as e:
                out = {"status": "error", "message": f"not available: {e}"}
            except TypeError as e:        # e.g. a sink called with arguments it doesn't take
                out = {"status": "error", "message": f"bad arguments: {type(e).__name__}"}
            except Exception as e:  # noqa: BLE001 - never echo internals, which may hold values
                log.warning("api %s failed: %s", op, type(e).__name__)
                out = {"status": "error", "message": "internal error (see the server log)"}
            finally:
                _current.exchange = None
                s.lock.release()
            ex.outbox.put(out)

        threading.Thread(target=worker, daemon=True, name="taskvault-api-call").start()
        return self._next(ex)

    def _next(self, ex: _Exchange) -> tuple[int, dict[str, Any]]:
        try:
            item = ex.outbox.get(timeout=self.exec_timeout * 2 + 60)
        except queue.Empty:
            return 504, {"error": "timed out"}
        if item.get("status") == "execute":
            with self._lock:
                self.pending[ex.id] = (ex, time.monotonic())
        return 200, item

    def finish(self, eid: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        with self._lock:
            entry = self.pending.pop(eid, None)
        if entry is None:
            return 404, {"error": "no such pending action (it finished or timed out)"}
        ex, _ = entry
        ex.inbox.put({"error": body["error"]} if "error" in body else {"result": body.get("result")})
        return self._next(ex)


class _Server(ThreadingHTTPServer):
    request_queue_size = 256         # many agents connecting at once (the default of 5 drops connections)
    daemon_threads = True
    max_connections = 256            # beyond this, new connections are closed straight away

    def __init__(self, *a: Any, **kw: Any):
        super().__init__(*a, **kw)
        self._slots = threading.BoundedSemaphore(self.max_connections)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)             # too many open connections (e.g. a slow-connection attack)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


# ------------------------------------------------------------------ request signing
# The token is a shared secret and never travels over the connection. Each request carries the time, a
# one-off random value and an HMAC over them, the method, the path and the body; each reply carries an
# HMAC over the same random value, the status and the reply body. So the server knows the request came
# from someone holding the token (and wasn't replayed), and the adapter knows the reply came from the
# real taskvault, not another program listening on the same port.
AUTH_WINDOW = 120


def request_mac(token: str, method: str, path: str, ts: str, nonce: str, body: bytes) -> str:
    msg = "\n".join(["TV1", method, path, ts, nonce, hashlib.sha256(body).hexdigest()])
    return hmac.new(token.encode(), msg.encode(), hashlib.sha256).hexdigest()


def response_mac(token: str, nonce: str, status: int, body: bytes) -> str:
    msg = "\n".join(["TV1-RESPONSE", nonce, str(status), hashlib.sha256(body).hexdigest()])
    return hmac.new(token.encode(), msg.encode(), hashlib.sha256).hexdigest()


def signed_headers(token: str, method: str, path: str, body: bytes) -> dict[str, str]:
    """Headers for a request to `taskvault api` (what the adapters do, in Python)."""
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    return {"x-taskvault-time": ts, "x-taskvault-nonce": nonce,
            "x-taskvault-auth": request_mac(token, method, path, ts, nonce, body)}


class _Handler(BaseHTTPRequestHandler):
    api: ApiServer
    server_version = "taskvault-api"
    sys_version = ""
    timeout = 30                         # a client that stops sending is dropped (no thread held forever)
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:     # no request details in logs
        pass

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        try:
            data = json.dumps(payload, default=str).encode()
        except (TypeError, ValueError, RecursionError):
            status, data = 500, b'{"error": "reply could not be encoded"}'
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.send_header("cache-control", "no-store")
        self.send_header("connection", "close")        # one request per connection: say so, so clients never reuse it
        nonce = self.headers.get("x-taskvault-nonce") or ""
        if getattr(self, "_signed", False) and nonce:
            self.send_header("x-taskvault-auth", response_mac(self.api.token, nonce, status, data))
        self.end_headers()
        self.wfile.write(data)

    def _check(self) -> bytes | None:
        """All the guards. Returns the request body, or None after sending a refusal."""
        self._signed = False
        host = (self.headers.get("host") or "").lower()
        if host not in (f"127.0.0.1:{self.api.port}", f"localhost:{self.api.port}"):
            self._send(421, {"error": "wrong Host header"})          # blocks DNS-rebinding tricks
            return None
        if self.headers.get("origin") is not None:
            self._send(403, {"error": "requests from web pages are refused"})
            return None
        try:
            n = int(self.headers.get("content-length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            if 0 < n <= 4 * MAX_BODY:        # read and drop it, so the refusal arrives (Windows otherwise resets
                left = n                     # the connection when unread data is left, and the reply is lost)
                while left > 0:
                    chunk = self.rfile.read(min(65536, left))
                    if not chunk:
                        break
                    left -= len(chunk)
            self._send(413, {"error": "request too large"})
            return None
        body = self.rfile.read(n) if n else b""
        ts, nonce = self.headers.get("x-taskvault-time") or "", self.headers.get("x-taskvault-nonce") or ""
        mac = self.headers.get("x-taskvault-auth") or ""
        good = request_mac(self.api.token, self.command, self.path, ts, nonce, body)
        if not (ts.isdigit() and 16 <= len(nonce) <= 64 and hmac.compare_digest(mac.encode(), good.encode())):
            self._send(401, {"error": "request not signed with this server's token"})
            return None
        if abs(time.time() - int(ts)) > AUTH_WINDOW or not self.api._fresh_nonce(nonce):
            self._send(401, {"error": "request expired or replayed"})
            return None
        self._signed = True                                       # from here on, replies are signed
        return body

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except (RecursionError, ValueError, TypeError) as e:     # never a dropped connection with no answer
            log.warning("api request failed: %s", type(e).__name__)
            try:
                self._send(400, {"error": "bad request"})
            except OSError:
                pass

    def do_GET(self) -> None:  # noqa: N802
        if self._check() is None:
            return
        if self.path == "/v1/health":
            self._send(200, {"ok": True, "version": __version__})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        raw = self._check()
        if raw is None:
            return
        if (self.headers.get("content-type") or "").split(";")[0].strip().lower() != "application/json":
            self._send(415, {"error": "send JSON (content-type: application/json)"})
            return
        try:
            body = json.loads(raw or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            self._send(400, {"error": "body isn't valid JSON"})
            return
        if not isinstance(body, dict):
            self._send(400, {"error": "body must be a JSON object"})
            return
        try:
            json.dumps(body, ensure_ascii=False).encode("utf-8")       # e.g. a lone "\ud800" can't be real text
        except UnicodeEncodeError:
            self._send(400, {"error": "body contains text that isn't valid Unicode"})
            return
        parts = self.path.strip("/").split("/")
        if parts == ["v1", "tasks"]:
            self._send(*self.api.start_task(body))
        elif len(parts) == 4 and parts[:2] == ["v1", "tasks"]:
            self._send(*self.api.run(parts[2], parts[3], body))
        elif len(parts) == 3 and parts[:2] == ["v1", "exec"]:
            self._send(*self.api.finish(parts[2], body))
        else:
            self._send(404, {"error": "not found"})
