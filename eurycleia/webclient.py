# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""A small, careful HTTPS client on Python's standard library, for talking to AI model APIs.

eurycleia calls Claude, OpenAI-compatible servers (including Ollama) and Gemini with this instead of each
vendor's SDK, so installing eurycleia pulls in no AI libraries at all. It is stricter than a default client:

* certificates are always verified (the system's trusted certificates, or SSL_CERT_FILE);
* an API key is never sent over plain http, except to this computer (localhost);
* redirects are refused, so a key can't be forwarded to another server;
* responses are size-limited, and error messages never include request headers (where keys live).
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import threading
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

MAX_RESPONSE = 16 * 1024 * 1024
RETRY_STATUS = {408, 429, 500, 502, 503, 504, 529}


class ProviderError(RuntimeError):
    """The model API returned an error or couldn't be reached. Never contains the API key."""

    def __init__(self, status: int, message: str, retry_after: float | None = None, body: str = ""):
        super().__init__(f"{status or 'network'}: {message}" if status else message)
        self.status, self.retry_after, self.body = status, retry_after, body

    @property
    def retryable(self) -> bool:
        return self.status in RETRY_STATUS or self.status == 0


class _Deadline:
    """Cuts the connection when the whole request has taken too long. A per-read timeout alone lets a server
    that sends one byte at a time hold a request (and the agent) open indefinitely."""

    def __init__(self, seconds: float):
        self.socks: list[socket.socket] = []
        self.fired = False
        self._lock = threading.Lock()
        self.timer = threading.Timer(seconds, self._fire)
        self.timer.daemon = True

    def _fire(self) -> None:
        with self._lock:
            self.fired = True
            for sock in self.socks:
                try:
                    sock.shutdown(socket.SHUT_RDWR)       # wakes any read blocked on it
                except OSError:
                    pass

    def wrap(self, cls: type) -> type:
        deadline = self

        class Conn(cls):  # type: ignore[misc, valid-type]
            def connect(self) -> None:
                super().connect()
                with deadline._lock:                      # urllib later hands this socket to the response
                    deadline.socks.append(self.sock)
                    if deadline.fired:
                        self.sock.shutdown(socket.SHUT_RDWR)

        return Conn


class _HTTP(urllib.request.HTTPHandler):
    def __init__(self, deadline: _Deadline):
        super().__init__()
        self.deadline = deadline

    def http_open(self, req: Any) -> Any:
        return self.do_open(self.deadline.wrap(http.client.HTTPConnection), req)


class _HTTPS(urllib.request.HTTPSHandler):
    def __init__(self, deadline: _Deadline):
        super().__init__(context=ssl.create_default_context())
        self.deadline = deadline

    def https_open(self, req: Any) -> Any:
        return self.do_open(self.deadline.wrap(http.client.HTTPSConnection), req, context=self._context)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None                     # urllib then raises HTTPError(3xx): handled as a refusal below


def is_local(host: str) -> bool:
    host = (host or "").strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_url(url: str, sends_secret: bool) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError("model API address must be an http(s) URL")
    if parts.username or parts.password:
        raise ValueError("don't put credentials in the model API address")
    if parts.scheme == "http" and sends_secret and not is_local(parts.hostname):
        raise ValueError(f"refusing to send an API key over plain http to {parts.hostname}; use https")


SECRET_HEADERS = ("authorization", "x-api-key", "x-goog-api-key", "api-key", "x-identity-header")


def post_json(url: str, body: dict[str, Any], headers: dict[str, str] | None = None, timeout: float = 120,
              secret_headers: tuple[str, ...] = SECRET_HEADERS) -> dict[str, Any]:
    """POST JSON, return the JSON reply. Raises ProviderError on HTTP or network errors."""
    return request_json("POST", url, body, headers, timeout, secret_headers)


def get_json(url: str, headers: dict[str, str] | None = None, timeout: float = 30,
             secret_headers: tuple[str, ...] = SECRET_HEADERS) -> dict[str, Any]:
    """GET, return the JSON reply (used for Azure sign-in tokens). Same rules as post_json."""
    return request_json("GET", url, None, headers, timeout, secret_headers)


def request_json(method: str, url: str, body: dict[str, Any] | None, headers: dict[str, str] | None = None,
                 timeout: float = 120, secret_headers: tuple[str, ...] = SECRET_HEADERS) -> dict[str, Any]:
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    sends_secret = any(headers.get(h) for h in secret_headers)
    check_url(url, sends_secret)
    host = urlsplit(url).hostname or ""
    from . import __version__
    base = {"accept": "application/json", "user-agent": f"eurycleia/{__version__}"}
    if body is not None:
        base["content-type"] = "application/json"
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method,
                                 headers={**base, **headers})
    deadline = _Deadline(timeout)
    handlers: list[Any] = [_NoRedirect(), _HTTP(deadline), _HTTPS(deadline)]
    if is_local(host):
        handlers.append(urllib.request.ProxyHandler({}))      # this computer: never through a proxy
    opener = urllib.request.build_opener(*handlers)
    deadline.timer.start()
    try:
        with opener.open(req, timeout=timeout) as r:
            chunks, size = [], 0
            while size <= MAX_RESPONSE:
                chunk = r.read(min(65536, MAX_RESPONSE + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            data = b"".join(chunks)
            if deadline.fired:
                raise TimeoutError
    except urllib.error.HTTPError as e:
        try:
            text = e.read(64 * 1024).decode("utf-8", "replace")
        except (OSError, http.client.HTTPException):
            text = ""                                     # cut off by the deadline, or the server hung up
        if 300 <= e.code < 400:
            raise ProviderError(e.code, f"{host} tried to redirect the request; refused so the key stays put",
                                body=text) from None
        retry = e.headers.get("retry-after") if e.headers else None
        try:
            retry_after = min(float(retry), 120.0) if retry else None
        except ValueError:
            retry_after = None
        raise ProviderError(e.code, _error_message(text) or e.reason, retry_after, text) from None
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as e:
        if deadline.fired or isinstance(e, TimeoutError) or isinstance(getattr(e, "reason", None), TimeoutError):
            raise ProviderError(0, f"{host} didn't finish answering within {timeout:.0f} seconds") from None
        reason = getattr(e, "reason", None) or type(e).__name__
        raise ProviderError(0, f"couldn't reach {host}: {reason}") from None
    finally:
        deadline.timer.cancel()
    if len(data) > MAX_RESPONSE:
        raise ProviderError(0, f"{host} sent more than {MAX_RESPONSE // (1024 * 1024)} MB; refused")
    try:
        out = json.loads(data)
    except json.JSONDecodeError:
        raise ProviderError(0, f"{host} didn't send JSON") from None
    if not isinstance(out, dict):
        raise ProviderError(0, f"{host} sent an unexpected reply")
    return out


def _error_message(text: str) -> str:
    try:
        err = json.loads(text).get("error")
    except (json.JSONDecodeError, AttributeError):
        return text[:300]
    if isinstance(err, dict):
        return str(err.get("message") or err.get("type") or err)[:300]
    return str(err)[:300]
