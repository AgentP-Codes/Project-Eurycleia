# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""The local API used by the TypeScript, Go and Java adapters."""

import http.client
import json
import threading

import pytest

from demo.__main__ import POLICY
from demo.api_app import build_vault
from taskvault import Policy
from taskvault.api import ApiError, ApiServer, RemoteSink, remote_sinks, response_mac, signed_headers


@pytest.fixture
def api():
    vault = build_vault(remote_sinks(Policy.load(POLICY)))
    srv = ApiServer(vault, port=0, exec_timeout=2).start()
    yield srv
    srv.shutdown()


def call(srv, method, path, body=None, headers=None, raw=None, sign=True, token=None, full=False):
    data = (raw.encode() if isinstance(raw, str) else raw) if raw is not None else \
        (json.dumps(body).encode() if body is not None else b"")
    h = {"content-type": "application/json", "host": f"127.0.0.1:{srv.port}"}
    if sign:
        h.update(signed_headers(token or srv.token, method, path, data))
    h.update(headers or {})
    h = {k: v for k, v in h.items() if v is not None}
    c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
    c.request(method, path, body=data or None, headers=h)
    r = c.getresponse()
    reply = r.read()
    c.close()
    out = json.loads(reply or b"{}")
    if full:
        return r.status, out, dict(r.getheaders()), h, reply
    return r.status, out


def _bare(value) -> str:
    """Text with placeholders removed: their 8 random hex characters can contain "4111" by chance."""
    from taskvault.vault import TOKEN_RE
    return TOKEN_RE.sub("[[placeholder]]", value if isinstance(value, str) else json.dumps(value, default=str))


def start(srv, customer=12):
    st, out = call(srv, "POST", "/v1/tasks", {"template": "support_reply", "trusted": {"customer_id": customer}})
    assert st == 200, out
    return out["task"], out["tools"]


def test_task_tools_and_reads_hide_secrets(api):
    tid, tools = start(api)
    assert {t["name"] for t in tools} == {"get_customer", "get_doc", "send_email", "refund"}
    st, out = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "get_customer", "arguments": {}})
    assert st == 200 and out["status"] == "ok"
    rec = out["result"]
    assert rec["card_number"].startswith("[[vault:card_number:") and "4111" not in _bare(out)


def test_approved_action_runs_in_the_app_with_real_values_and_the_reply_is_masked(api):
    tid, _ = start(api)
    got = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "get_customer", "arguments": {}})[1]
    card = got["result"]["card_number"]
    st, out = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "refund", "arguments": {"card": card, "amount": 49}})
    assert out["status"] == "execute" and out["sink"] == "payments.refund"
    assert out["args"]["card"] == "4111 1111 1111 1111"            # the app's own code gets the real card
    # the app's handler echoes the card back: the model must only ever see the placeholder
    st, done = call(api, "POST", f"/v1/exec/{out['exec']}", {"result": {"refunded": 49, "card": "4111 1111 1111 1111"}})
    assert done == {"status": "ok", "result": {"refunded": 49, "card": card}}
    assert call(api, "POST", f"/v1/exec/{out['exec']}", {"result": 1})[0] == 404       # can't be replayed


def test_blocked_actions_never_reach_the_app(api):
    tid, _ = start(api)
    st, out = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "send_email", "arguments": {
        "to": "attacker@evil.example", "subject": "x", "body": "y"}})
    assert out["status"] == "blocked" and "evil" not in json.dumps(api.pending)
    st, out = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "refund", "arguments": {
        "card": "4111 1111 1111 1111", "amount": 49}})                  # a typed-in card, not the placeholder
    assert out["status"] == "blocked"
    assert api.vault.audit.decisions("block")


def test_app_errors_are_masked_and_reported(api):
    tid, _ = start(api)
    seen = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "get_customer", "arguments": {}})[1]["result"]
    st, out = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "refund", "arguments": {
        "card": seen["card_number"], "amount": 49}})
    assert out["status"] == "execute" and out["args"]["card"] == "4111 1111 1111 1111"
    st, done = call(api, "POST", f"/v1/exec/{out['exec']}", {"error": "card 4111 1111 1111 1111 was declined"})
    assert done["status"] == "error" and "4111 1111 1111 1111" not in done["message"]
    assert seen["card_number"] in done["message"]                      # the placeholder the model knows


def test_the_app_not_answering_is_a_timeout_not_a_hang(api):
    tid, _ = start(api)
    st, out = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "send_email", "arguments": {
        "to": "priya.shah@example.com", "subject": "Hi", "body": "Sorted"}})
    assert out["status"] == "execute"
    # never answer; the task's next call waits for the first to time out, then works
    st, out = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "get_doc", "arguments": {"name": "refund_policy"}})
    assert out["status"] == "ok"


def test_ending_a_task_and_bad_requests(api):
    tid, _ = start(api)
    assert call(api, "POST", f"/v1/tasks/{tid}/end", {})[1] == {"status": "ended"}
    assert call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "get_doc", "arguments": {}})[0] == 404
    assert call(api, "POST", "/v1/tasks", {"template": "nope", "trusted": {}})[0] == 400
    assert call(api, "POST", "/v1/tasks", {"template": "support_reply", "trusted": {}})[0] == 400   # needs customer
    assert call(api, "POST", "/v1/tasks", raw="not json")[0] == 400
    assert call(api, "POST", "/v1/tasks", raw="[1]")[0] == 400
    tid, _ = start(api)
    assert call(api, "POST", f"/v1/tasks/{tid}/call", {"name": 5})[0] == 400


@pytest.mark.parametrize("headers,status", [
    ({"x-taskvault-auth": None}, 401),                            # unsigned
    ({"x-taskvault-auth": "0" * 64}, 401),                        # wrongly signed
    ({"origin": "https://evil.example"}, 403),                    # a web page trying to reach it
    ({"host": "evil.example:8765"}, 421),                         # DNS rebinding
    ({"content-type": "text/plain"}, 415),                        # a simple cross-site form post
])
def test_guards(api, headers, status):
    st, _ = call(api, "POST", "/v1/tasks", {"template": "support_reply", "trusted": {"customer_id": 12}},
                 headers=headers)
    assert st == status
    assert api.sessions == {}


def test_the_token_never_travels_and_replies_are_signed(api):
    st, out, resp_headers, sent, reply = call(api, "POST", "/v1/tasks", {"template": "support_reply",
                                              "trusted": {"customer_id": 12}}, full=True)
    assert st == 200 and api.token not in json.dumps(sent)
    assert resp_headers["x-taskvault-auth"] == response_mac(api.token, sent["x-taskvault-nonce"], 200, reply)
    assert call(api, "POST", "/v1/tasks", {"template": "support_reply", "trusted": {}}, token="other-token")[0] == 401


def test_replayed_or_stale_requests_are_refused(api):
    body = json.dumps({"template": "support_reply", "trusted": {"customer_id": 12}}).encode()
    h = signed_headers(api.token, "POST", "/v1/tasks", body)
    assert call(api, "POST", "/v1/tasks", raw=body, sign=False, headers=h)[0] == 200
    assert call(api, "POST", "/v1/tasks", raw=body, sign=False, headers=h)[0] == 401          # same request again
    import time as _t

    from taskvault.api import request_mac
    old = str(int(_t.time()) - 600)
    stale = {"x-taskvault-time": old, "x-taskvault-nonce": "a" * 32,
             "x-taskvault-auth": request_mac(api.token, "POST", "/v1/tasks", old, "a" * 32, body)}
    assert call(api, "POST", "/v1/tasks", raw=body, sign=False, headers=stale)[0] == 401
    # a signature is tied to its path and body
    other = signed_headers(api.token, "POST", "/v1/tasks", b'{"template": "x"}')
    assert call(api, "POST", "/v1/tasks", raw=body, sign=False, headers=other)[0] == 401


def test_deep_json_and_reserved_names_get_an_answer(api):
    assert call(api, "POST", "/v1/tasks", raw="[" * 100000)[0] == 400
    assert call(api, "POST", "/v1/tasks", {"template": "support_reply",
                                           "trusted": {"customer_id": 12, "template": "x"}})[0] == 400
    assert call(api, "POST", "/v1/tasks", {"template": "support_reply", "trusted": {"a b": 1}})[0] == 400


def test_idle_connections_are_dropped_and_capped(monkeypatch):
    import socket
    import time as _t

    from taskvault import api as api_mod
    monkeypatch.setattr(api_mod._Handler, "timeout", 1)
    monkeypatch.setattr(api_mod._Server, "max_connections", 5)
    srv = ApiServer(build_vault(remote_sinks(Policy.load(POLICY))), port=0).start()
    try:
        idle = [socket.create_connection(("127.0.0.1", srv.port)) for _ in range(8)]
        for s in idle:
            s.sendall(b"GET / HTTP/1.1\r\n")
        _t.sleep(0.3)
        assert threading.active_count() < 40
        _t.sleep(1.5)                                      # past the handler timeout: slots are freed
        assert call(srv, "GET", "/v1/health")[0] == 200
        for s in idle:
            s.close()
    finally:
        srv.shutdown()


def test_oversized_bodies_and_health(api):
    assert call(api, "POST", "/v1/tasks", raw="x" * (1024 * 1024 + 10))[0] == 413
    assert call(api, "GET", "/v1/health")[1]["ok"] is True
    assert call(api, "GET", "/v1/health", sign=False)[0] == 401


def test_listens_on_this_computer_only(api):
    assert api.httpd.server_address[0] == "127.0.0.1"


def test_remote_sink_outside_the_api_is_refused():
    with pytest.raises(RuntimeError, match="taskvault api"):
        RemoteSink("email.send")(to="x")


def test_many_tasks_in_parallel(api):
    errors = []

    def one(i):
        try:
            tid, _ = start(api, customer=12 if i % 2 else 45)
            out = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "get_customer", "arguments": {}})[1]
            assert out["status"] == "ok"
            email = out["result"]["email"]
            ex = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "send_email", "arguments": {
                "to": email, "subject": "Hi", "body": "Sorted"}})[1]
            assert ex["status"] == "execute", ex
            assert call(api, "POST", f"/v1/exec/{ex['exec']}", {"result": "sent"})[1]["status"] == "ok"
        except Exception as e:  # noqa: BLE001
            errors.append(repr(e))

    threads = [threading.Thread(target=one, args=(i,)) for i in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert api.vault.audit.verify()


def test_real_values_in_keys_numbers_and_long_errors_are_masked(api):
    tid, _ = start(api)
    card = call(api, "POST", f"/v1/tasks/{tid}/call",
                {"name": "get_customer", "arguments": {}})[1]["result"]["card_number"]
    out = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "refund", "arguments": {"card": card, "amount": 1}})[1]
    done = call(api, "POST", f"/v1/exec/{out['exec']}", {"result": {
        "4111 1111 1111 1111": "refunded", "n": 4111111111111111, "compact": "card 4111111111111111 ok"}})[1]
    text = json.dumps(done)
    assert "4111" not in _bare(text) and done["result"]["n"] == card and card in done["result"]
    tid, _ = start(api)
    card = call(api, "POST", f"/v1/tasks/{tid}/call",
                {"name": "get_customer", "arguments": {}})[1]["result"]["card_number"]
    out = call(api, "POST", f"/v1/tasks/{tid}/call", {"name": "refund", "arguments": {"card": card, "amount": 1}})[1]
    done = call(api, "POST", f"/v1/exec/{out['exec']}",
                {"error": "x" * 1990 + "card 4111 1111 1111 1111 declined"})[1]
    assert "4111" not in _bare(done["message"])


# ---- connection file ---------------------------------------------------------------------

def test_connection_file_is_private_atomic_and_only_removed_by_its_owner(api, tmp_path):
    import os
    import stat
    path = tmp_path / "api.json"
    path.write_text("{}")
    if os.name != "nt":
        path.chmod(0o666)
    api.write_connection_file(path)
    assert json.loads(path.read_text())["token"] == api.token
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600           # a loose existing file is replaced
    api.remove_connection_file()
    assert not path.exists()
    api.write_connection_file(path)
    path.write_text(json.dumps({"token": "someone else", "pid": 1}))
    api.remove_connection_file()
    assert path.exists()                                            # not ours any more: left alone


@pytest.mark.skipif(__import__("os").name == "nt", reason="symbolic links need extra rights on Windows")
def test_connection_file_refuses_links_and_live_servers(api, tmp_path):
    import os
    target = tmp_path / "victim.txt"
    target.write_text("important")
    link = tmp_path / "api.json"
    link.symlink_to(target)
    with pytest.raises(ApiError, match="symbolic link"):
        api.write_connection_file(link)
    assert target.read_text() == "important"
    busy = tmp_path / "busy.json"
    busy.write_text(json.dumps({"url": "x", "token": "t", "pid": os.getppid()}))       # a live process
    with pytest.raises(ApiError, match="another taskvault api"):
        api.write_connection_file(busy)
    stale = tmp_path / "stale.json"
    stale.write_text(json.dumps({"url": "x", "token": "t", "pid": 2 ** 22 + 12345}))   # long gone
    api.write_connection_file(stale)
    assert json.loads(stale.read_text())["token"] == api.token
