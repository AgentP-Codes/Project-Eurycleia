# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Connector pack: HubSpot, Zendesk, Stripe, Xero, Slack, Outlook (Microsoft Graph), Gmail, MongoDB.

SIMULATED: every test answers from a fake HTTP transport (or a fake Mongo collection) shaped
like the real API's documented responses. They check what we send and what we accept back,
not live behaviour.
"""

import base64
import email
import json
import urllib.parse

import pytest

from eurycleia.connectors import HttpClient, HttpError
from eurycleia.connectors.base import Response
from eurycleia.connectors.saas import (
    GmailSink,
    HubSpotConnector,
    HubSpotSink,
    MongoConnector,
    OutlookMailSink,
    SlackMessageSink,
    StripeCustomerConnector,
    StripeRefundSink,
    XeroConnector,
    ZendeskConnector,
    ZendeskReplySink,
)

BAD_IDS = ["../admin", "12/../../x", "12?x=1", "12#x", "", " ", {"$gt": ""}, ["12"], None, True, "a" * 500]


class Fake:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, method, url, headers, body):
        u = urllib.parse.urlparse(url)
        self.calls.append({"method": method, "path": u.path, "query": urllib.parse.parse_qs(u.query),
                           "headers": headers, "body": body})
        for (m, path), (status, payload) in self.routes.items():
            if m == method and u.path == path:
                return Response(status, {}, json.dumps(payload).encode())
        return Response(404, {}, b'{"message":"not found"}')


def client(base, routes, **kw):
    fake = Fake(routes)
    return HttpClient(base, "tok", transport=fake, **kw), fake


# ---- HubSpot -----------------------------------------------------------------------------

def test_hubspot_reads_listed_properties_by_unique_property():
    c, fake = client("https://api.hubapi.com", {("GET", "/crm/v3/objects/contacts/12"): (200, {
        "id": "901", "properties": {"firstname": "Priya", "email": "priya@example.com", "hs_secret": "x"}})})
    rec = HubSpotConnector(c, "contacts", ["firstname", "email"], id_property="customer_id")(12)
    assert rec == {"firstname": "Priya", "email": "priya@example.com"}
    q = fake.calls[0]["query"]
    assert q["properties"] == ["firstname,email"] and q["idProperty"] == ["customer_id"]
    assert fake.calls[0]["headers"]["Authorization"] == "Bearer tok"


def test_hubspot_missing_record_and_bad_ids():
    c, _ = client("https://api.hubapi.com", {})
    conn = HubSpotConnector(c, "contacts", ["email"])
    assert conn(99) is None
    for bad in BAD_IDS:
        with pytest.raises(ValueError):
            conn(bad)


def test_hubspot_sink_only_writes_allowed_properties():
    c, fake = client("https://api.hubapi.com", {("PATCH", "/crm/v3/objects/tickets/5"): (200, {"id": "5"})})
    sink = HubSpotSink(c, "tickets", writable=["hs_pipeline_stage"])
    assert sink(record_id=5, hs_pipeline_stage="closed")["updated"] == ["hs_pipeline_stage"]
    assert json.loads(fake.calls[0]["body"]) == {"properties": {"hs_pipeline_stage": "closed"}}
    with pytest.raises(ValueError):
        sink(record_id=5, owner_email="attacker@evil.example")


# ---- Zendesk -----------------------------------------------------------------------------

def test_zendesk_ticket_and_reply():
    routes = {("GET", "/api/v2/tickets/100.json"): (200, {"ticket": {"id": 100, "subject": "Refund",
                                                                     "description": "charged twice"}}),
              ("PUT", "/api/v2/tickets/100.json"): (200, {"ticket": {"id": 100}})}
    c, fake = client("https://acme.zendesk.com", routes, auth_scheme="Basic")
    assert ZendeskConnector(c, "tickets", ["subject"])(100) == {"subject": "Refund"}
    out = ZendeskReplySink(c)(ticket_id=100, body="Refunded", public=True)
    assert out == {"ticket": "100", "commented": True, "public": True}
    assert json.loads(fake.calls[1]["body"]) == {"ticket": {"comment": {"body": "Refunded", "public": True}}}
    assert fake.calls[0]["headers"]["Authorization"] == "Basic tok"
    with pytest.raises(ValueError):
        ZendeskReplySink(c, allow_public=False)(ticket_id=100, body="x", public=True)
    for bad in [*BAD_IDS, "abc", "100.json"]:
        with pytest.raises(ValueError):
            ZendeskConnector(c)(bad)


# ---- Stripe ------------------------------------------------------------------------------

def test_stripe_customer_and_capped_refund():
    routes = {("GET", "/v1/customers/cus_ABC123xyz"): (200, {"id": "cus_ABC123xyz", "name": "Priya",
                                                             "email": "p@example.com", "metadata": {"x": 1}}),
              ("GET", "/v1/customers/cus_Deleted1"): (200, {"id": "cus_Deleted1", "deleted": True}),
              ("POST", "/v1/refunds"): (200, {"id": "re_1", "status": "succeeded"})}
    c, fake = client("https://api.stripe.com", routes)
    assert StripeCustomerConnector(c, ["id", "email"])("cus_ABC123xyz") == {"id": "cus_ABC123xyz",
                                                                             "email": "p@example.com"}
    assert StripeCustomerConnector(c)("cus_Deleted1") is None
    sink = StripeRefundSink(c, max_amount=100)
    assert sink(payment_intent="pi_3Nabcdef", amount=49.5) == {"refund": "re_1", "status": "succeeded"}
    form = urllib.parse.parse_qs(fake.calls[-1]["body"].decode())
    assert form == {"payment_intent": ["pi_3Nabcdef"], "amount": ["4950"], "reason": ["requested_by_customer"]}
    for amount in (0, -5, 100.01, "49", True, float("nan")):
        with pytest.raises(ValueError):
            sink(payment_intent="pi_3Nabcdef", amount=amount)
    for bad in ("ch_123456", "pi_x/../../v1/charges", "pi_12"):
        with pytest.raises(ValueError):
            sink(payment_intent=bad, amount=1)
    with pytest.raises(ValueError):
        StripeCustomerConnector(c)("12")


# ---- Xero --------------------------------------------------------------------------------

def test_xero_contact_needs_tenant_header():
    cid = "7f3a2c10-1111-2222-3333-444455556666"
    routes = {("GET", f"/api.xro/2.0/Contacts/{cid}"): (200, {"Contacts": [{"ContactID": cid, "Name": "Acme",
                                                                             "EmailAddress": "ap@acme.example"}]})}
    fake = Fake(routes)
    with pytest.raises(ValueError):
        XeroConnector(HttpClient("https://api.xero.com", "tok", transport=fake))
    c = HttpClient("https://api.xero.com", "tok", headers={"xero-tenant-id": "t1"}, transport=fake)
    assert XeroConnector(c, fields=["Name"])(cid) == {"Name": "Acme"}
    assert fake.calls[0]["headers"]["xero-tenant-id"] == "t1"
    for bad in ("12", cid + "/x", *BAD_IDS):
        with pytest.raises(ValueError):
            XeroConnector(c)(bad)


# ---- Slack -------------------------------------------------------------------------------

def test_slack_posts_and_reports_errors():
    c, fake = client("https://slack.com", {("POST", "/api/chat.postMessage"): (200, {"ok": True, "ts": "1.2"})})
    assert SlackMessageSink(c)(channel="C0123ABCD", text="Refund approved")["ok"]
    assert json.loads(fake.calls[0]["body"]) == {"channel": "C0123ABCD", "text": "Refund approved"}
    c2, _ = client("https://slack.com", {("POST", "/api/chat.postMessage"): (200, {"ok": False,
                                                                                    "error": "channel_not_found"})})
    with pytest.raises(HttpError, match="channel_not_found"):
        SlackMessageSink(c2)(channel="C0123ABCD", text="x")
    for bad in ("#general\n", "C01 23", "../x", ""):
        with pytest.raises(ValueError):
            SlackMessageSink(c)(channel=bad, text="x")


# ---- Outlook / Gmail ---------------------------------------------------------------------

def test_outlook_sends_plain_text_to_plain_addresses():
    c, fake = client("https://graph.microsoft.com", {("POST", "/v1.0/users/support%40acme.example/sendMail"):
                                                     (202, {})})
    out = OutlookMailSink(c, sender="support@acme.example")(to="priya@example.com", subject="Hi", body="Done")
    assert out == {"sent": True, "to": 1}
    msg = json.loads(fake.calls[0]["body"])["message"]
    assert msg["toRecipients"] == [{"emailAddress": {"address": "priya@example.com"}}]
    assert msg["body"] == {"contentType": "Text", "content": "Done"}
    for bad in ('"x" <a@b.com>', "a@b.com\r\nbcc: c@d.com", "not-an-address", ""):
        with pytest.raises(ValueError):
            OutlookMailSink(c, sender="support@acme.example")(to=bad, subject="x", body="y")


def test_gmail_builds_a_proper_message():
    c, fake = client("https://gmail.googleapis.com", {("POST", "/gmail/v1/users/me/messages/send"):
                                                      (200, {"id": "m1"})})
    assert GmailSink(c)(to=["priya@example.com"], subject="Hi", body="Refund done") == {"sent": True, "id": "m1"}
    raw = json.loads(fake.calls[0]["body"])["raw"]
    msg = email.message_from_bytes(base64.urlsafe_b64decode(raw))
    assert msg["To"] == "priya@example.com" and msg["Subject"] == "Hi"
    assert "Refund done" in msg.get_payload()
    with pytest.raises(ValueError):
        GmailSink(c)(to="priya@example.com", subject="Hi\r\nBcc: attacker@evil.example", body="x")


# ---- MongoDB -----------------------------------------------------------------------------

class FakeCollection:
    def __init__(self, docs):
        self.docs, self.queries = docs, []

    def find_one(self, query, projection=None):
        self.queries.append((query, projection))
        (field, cond), = query.items()
        want = cond["$eq"] if isinstance(cond, dict) and set(cond) == {"$eq"} else None
        for d in self.docs:
            if isinstance(cond, dict) and set(cond) != {"$eq"}:
                return d                         # a naive driver would match anything with $gt / $ne
            if d.get(field) == want:
                return {k: v for k, v in d.items() if projection is None or k in projection or k == "_id"}
        return None


def test_mongo_reads_one_document_and_cant_be_tricked_into_a_query():
    coll = FakeCollection([{"_id": "a", "customer_id": 45, "name": "Tom"},
                           {"_id": "b", "customer_id": 12, "name": "Priya", "card": "4111"}])
    conn = MongoConnector(coll, "customer_id", fields=["customer_id", "name"])
    assert conn(12) == {"customer_id": 12, "name": "Priya"}
    assert coll.queries[0] == ({"customer_id": {"$eq": 12}}, {"customer_id": 1, "name": 1})
    for bad in ({"$gt": 0}, {"$ne": None}, [12], None, True):
        with pytest.raises(ValueError):
            conn(bad)
    assert conn(999) is None


# ---- a connector behind the vault ----------------------------------------------------------

def test_slack_behind_the_vault_only_reaches_allowed_channels():
    from eurycleia import Blocked, Policy, Vault
    c, fake = client("https://slack.com", {("POST", "/api/chat.postMessage"): (200, {"ok": True})})
    pol = Policy.from_dict({
        "sources": {"notes": {"owner": "company", "fields": {"text": "normal"}}},
        "tasks": {"notify": {"reads": {"notes": {"key": "n1", "fields": ["text"]}},
                             "sinks": {"slack.post": {"recipient_arg": "channel", "args": ["channel", "text"],
                                                      "allowed_recipients": ["C0SUPPORT1"], "max_calls": 2}}}}})
    v = Vault(pol, {"notes": lambda k: {"text": "hello"}}, {"slack.post": SlackMessageSink(c)})
    t = v.start_task("notify")
    t.act("slack.post", channel="C0SUPPORT1", text="all good")
    assert json.loads(fake.calls[0]["body"])["channel"] == "C0SUPPORT1"          # original letters kept
    for bad in ("C0OTHER99", "C0SUPPORT1 C0OTHER99", "c0support1\n"):
        with pytest.raises(Blocked):
            t.act("slack.post", channel=bad, text="x")
    assert len(fake.calls) == 1
