# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""The built-in HTTPS client used for AI model APIs: real local servers, no internet needed."""

import datetime
import http.server
import json
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from taskvault import webclient
from taskvault.webclient import ProviderError, check_url, post_json


class Server:
    """A tiny local HTTP(S) server whose replies each test scripts."""

    def __init__(self, handler, tls_files=None):
        seen = self.seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("content-length") or 0)
                seen.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                             "body": self.rfile.read(n)})
                status, headers, body = handler(self)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                seen.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                             "body": b""})
                self.send_response(200)
                self.send_header("content-length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        scheme = "http"
        if tls_files:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls_files)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
            scheme = "https"
        self.url = f"{scheme}://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def reply(status=200, body=None, headers=None):
    data = body if isinstance(body, bytes) else json.dumps(body if body is not None else {"ok": True}).encode()
    return lambda h: (status, {"content-type": "application/json", **(headers or {})}, data)


def test_plain_http_is_refused_for_keys_except_on_this_computer():
    with pytest.raises(ValueError, match="plain http"):
        check_url("http://api.example.com/v1", sends_secret=True)
    check_url("http://api.example.com/v1", sends_secret=False)          # no key: allowed (e.g. Ollama on the LAN)
    for local in ("http://localhost:11434", "http://127.0.0.1:1", "http://[::1]:1"):
        check_url(local, sends_secret=True)
    with pytest.raises(ValueError, match="credentials"):
        check_url("https://user:pw@api.example.com", sends_secret=False)
    with pytest.raises(ValueError):
        check_url("file:///etc/passwd", sends_secret=False)


def test_round_trip_and_errors_never_contain_the_key():
    srv = Server(reply(body={"answer": 42}))
    try:
        assert post_json(srv.url + "/v1/x", {"q": 1}, {"x-api-key": "SECRET-KEY-123"}) == {"answer": 42}
        assert srv.seen[0]["headers"]["x-api-key"] == "SECRET-KEY-123"
        assert json.loads(srv.seen[0]["body"]) == {"q": 1}
    finally:
        srv.close()
    srv = Server(reply(401, {"error": {"type": "authentication_error", "message": "invalid x-api-key"}}))
    try:
        with pytest.raises(ProviderError) as e:
            post_json(srv.url + "/v1/x", {}, {"x-api-key": "SECRET-KEY-123"})
        assert e.value.status == 401 and "invalid x-api-key" in str(e.value)
        assert "SECRET-KEY-123" not in str(e.value) + e.value.body + repr(e.value.__cause__)
    finally:
        srv.close()


def test_redirects_are_refused_so_the_key_is_never_forwarded():
    for code in (301, 302, 303, 307, 308):
        target = Server(reply())
        bouncer = Server(reply(code, {}, {"location": target.url + "/steal"}))
        try:
            with pytest.raises(ProviderError, match="redirect"):
                post_json(bouncer.url + "/v1/x", {}, {"authorization": "Bearer SECRET"})
            assert target.seen == [], code
        finally:
            target.close()
            bouncer.close()



def test_oversized_replies_are_refused(monkeypatch):
    monkeypatch.setattr(webclient, "MAX_RESPONSE", 1000)
    srv = Server(reply(body=b'{"x": "' + b"a" * 5000 + b'"}'))
    try:
        with pytest.raises(ProviderError, match="more than"):
            post_json(srv.url, {})
    finally:
        srv.close()


def test_rate_limit_hint_and_non_json_replies():
    srv = Server(reply(429, {"error": {"message": "slow down"}}, {"retry-after": "7"}))
    try:
        with pytest.raises(ProviderError) as e:
            post_json(srv.url, {})
        assert e.value.retryable and e.value.retry_after == 7
    finally:
        srv.close()
    srv = Server(reply(body=b"<html>captive portal</html>"))
    try:
        with pytest.raises(ProviderError, match="JSON"):
            post_json(srv.url, {})
    finally:
        srv.close()
    with pytest.raises(ProviderError, match="couldn't reach"):
        post_json("http://127.0.0.1:9/", {}, timeout=3)


def _self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    import ipaddress
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return str(cert_file), str(key_file)


def test_certificates_are_verified(tmp_path, monkeypatch):
    """A server with a certificate nobody vouches for (as in a man-in-the-middle attack) is refused."""
    cert, key = _self_signed(tmp_path)
    srv = Server(reply(), tls_files=(cert, key))
    try:
        with pytest.raises(ProviderError, match="CERTIFICATE_VERIFY_FAILED|certificate verify failed"):
            post_json(srv.url + "/v1/x", {}, {"x-api-key": "SECRET"})
        assert srv.seen == []                                          # the key was never sent
        monkeypatch.setenv("SSL_CERT_FILE", cert)                      # trusting it explicitly works
        assert post_json(srv.url + "/v1/x", {}, {"x-api-key": "SECRET"}) == {"ok": True}
    finally:
        srv.close()


def test_a_real_provider_through_a_local_server():
    """The whole path: provider -> built-in client -> a local server speaking the OpenAI-compatible API
    (like Ollama)."""
    from taskvault.llm import OllamaProvider
    srv = Server(reply(body={"choices": [{"message": {"role": "assistant", "content": "hello from local"}}]}))
    try:
        p = OllamaProvider("hermes3", host=srv.url)
        assert p.complete("sys", "hi") == "hello from local"
        sent = json.loads(srv.seen[0]["body"])
        assert srv.seen[0]["path"] == "/v1/chat/completions" and sent["model"] == "hermes3"
        assert "authorization" not in srv.seen[0]["headers"]
    finally:
        srv.close()


def test_a_server_dripping_bytes_is_cut_off_at_the_deadline():
    """Found by stress testing: a server sending one byte at a time kept a request open far past its timeout."""
    import socket
    import time

    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)

    def drip():
        c, _ = lsock.accept()
        c.recv(65536)
        c.sendall(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100000\r\n\r\n")
        try:
            for _ in range(200):
                c.sendall(b" ")
                time.sleep(0.2)
        except OSError:
            pass
        c.close()

    threading.Thread(target=drip, daemon=True).start()
    t0 = time.monotonic()
    with pytest.raises(ProviderError, match="didn't finish"):
        post_json(f"http://127.0.0.1:{lsock.getsockname()[1]}/v1", {}, timeout=2)
    assert time.monotonic() - t0 < 5
    lsock.close()
