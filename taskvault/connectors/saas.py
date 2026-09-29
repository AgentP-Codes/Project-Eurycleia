# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Connectors for common business apps: HubSpot, Zendesk, Stripe, Xero, Slack, Microsoft 365
(Outlook mail), Gmail and MongoDB.

Each is a thin, stdlib-only adapter over the app's public REST API with an injectable HTTP
transport, so it can be tested offline. Record ids from the agent are checked (no slashes,
queries or operators) and only the listed fields are returned. Bring your own OAuth token or
API key; taskvault never stores it.

These are TESTED AGAINST SIMULATED API RESPONSES (see tests/test_connectors_saas.py), not yet
against live accounts. Check them against your own account before relying on them.
"""

from __future__ import annotations

import base64
from email.message import EmailMessage
from typing import Any

from .base import HttpClient, HttpError, check_id, pick, quote


# ------------------------------------------------------------------ HubSpot
class HubSpotConnector:
    """A CRM record (contacts, companies, deals, tickets...) by record id or a unique property.

        HubSpotConnector(HttpClient("https://api.hubapi.com", token), "contacts",
                         fields=["firstname", "lastname", "email"], id_property="customer_id")
    """

    def __init__(self, client: HttpClient, object_type: str, fields: list[str], id_property: str | None = None):
        self.client, self.type = client, check_id(object_type, r"[a-z0-9_]{1,64}", "object type")
        self.fields = [check_id(f, r"[A-Za-z0-9_]{1,100}", "property") for f in fields]
        self.id_property = check_id(id_property, r"[A-Za-z0-9_]{1,100}", "property") if id_property else None

    def __call__(self, key: Any) -> dict | None:
        params = {"properties": ",".join(self.fields), "archived": "false"}
        if self.id_property:
            params["idProperty"] = self.id_property
        data = self.client.request("GET", f"/crm/v3/objects/{self.type}/{quote(check_id(key))}",
                                   params=params, allow_404=True)
        return pick((data or {}).get("properties"), self.fields) if data else None


class HubSpotSink:
    """Update allowed properties of one record: sink(record_id=..., **properties)."""

    def __init__(self, client: HttpClient, object_type: str, writable: list[str]):
        self.client, self.type, self.writable = client, check_id(object_type, r"[a-z0-9_]{1,64}"), set(writable)

    def __call__(self, record_id: Any, **properties: Any) -> dict:
        if bad := set(properties) - self.writable:
            raise ValueError(f"properties not writable: {sorted(bad)}")
        self.client.request("PATCH", f"/crm/v3/objects/{self.type}/{quote(check_id(record_id))}",
                            json_body={"properties": properties})
        return {"id": str(record_id), "updated": sorted(properties)}


# ------------------------------------------------------------------ Zendesk
class ZendeskConnector:
    """A ticket or user by id. Client: HttpClient("https://<sub>.zendesk.com", token)
    (OAuth token, or auth_scheme="Basic" with base64 of "email/token:<api token>")."""

    def __init__(self, client: HttpClient, kind: str = "tickets", fields: list[str] | None = None):
        if kind not in ("tickets", "users", "organizations"):
            raise ValueError("kind must be tickets, users or organizations")
        self.client, self.kind, self.fields = client, kind, fields

    def __call__(self, key: Any) -> dict | None:
        data = self.client.request("GET", f"/api/v2/{self.kind}/{quote(check_id(key, r'[0-9]{1,20}'))}.json",
                                   allow_404=True)
        return pick((data or {}).get(self.kind[:-1]), self.fields) if data else None


class ZendeskReplySink:
    """Add a comment to a ticket: sink(ticket_id=..., body=..., public=True)."""

    def __init__(self, client: HttpClient, allow_public: bool = True):
        self.client, self.allow_public = client, allow_public

    def __call__(self, ticket_id: Any, body: str, public: bool = True) -> dict:
        if public and not self.allow_public:
            raise ValueError("public replies are turned off for this sink")
        tid = check_id(ticket_id, r"[0-9]{1,20}", "ticket id")
        self.client.request("PUT", f"/api/v2/tickets/{quote(tid)}.json",
                            json_body={"ticket": {"comment": {"body": str(body), "public": bool(public)}}})
        return {"ticket": tid, "commented": True, "public": bool(public)}


# ------------------------------------------------------------------ Stripe
class StripeCustomerConnector:
    """A customer by id (cus_...). Client: HttpClient("https://api.stripe.com", secret_key)."""

    def __init__(self, client: HttpClient, fields: list[str] | None = None):
        self.client, self.fields = client, fields or ["id", "name", "email", "phone"]

    def __call__(self, key: Any) -> dict | None:
        data = self.client.request("GET", f"/v1/customers/{quote(check_id(key, r'cus_[A-Za-z0-9]{6,64}'))}",
                                   allow_404=True)
        if not data or data.get("deleted"):
            return None
        return pick(data, self.fields)


class StripeRefundSink:
    """Refund a payment: sink(payment_intent="pi_...", amount=<dollars>). Amounts over max_amount are refused."""

    def __init__(self, client: HttpClient, max_amount: float = 500, currency_minor_units: int = 100):
        self.client, self.max, self.units = client, max_amount, currency_minor_units

    def __call__(self, payment_intent: str, amount: float, reason: str = "requested_by_customer") -> dict:
        pi = check_id(payment_intent, r"pi_[A-Za-z0-9]{6,64}", "payment intent")
        if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not 0 < amount <= self.max:
            raise ValueError(f"amount must be a number between 0 and {self.max}")
        if reason not in ("duplicate", "fraudulent", "requested_by_customer"):
            raise ValueError("invalid refund reason")
        r = self.client.request("POST", "/v1/refunds", form_body={
            "payment_intent": pi, "amount": int(round(amount * self.units)), "reason": reason})
        return {"refund": r.get("id"), "status": r.get("status")}


# ------------------------------------------------------------------ Xero
class XeroConnector:
    """A contact or invoice by id. Client: HttpClient("https://api.xero.com", token,
    headers={"xero-tenant-id": "<tenant id>"})."""

    def __init__(self, client: HttpClient, kind: str = "Contacts", fields: list[str] | None = None):
        if kind not in ("Contacts", "Invoices"):
            raise ValueError("kind must be Contacts or Invoices")
        if "xero-tenant-id" not in {k.lower() for k in client.headers}:
            raise ValueError("Xero needs a xero-tenant-id header on the client")
        self.client, self.kind, self.fields = client, kind, fields

    def __call__(self, key: Any) -> dict | None:
        kid = check_id(key, r"[0-9a-fA-F-]{36}", "Xero id")
        data = self.client.request("GET", f"/api.xro/2.0/{self.kind}/{quote(kid)}", allow_404=True)
        items = (data or {}).get(self.kind) or []
        return pick(items[0], self.fields) if items else None


# ------------------------------------------------------------------ Slack
class SlackMessageSink:
    """Post a message: sink(channel=..., text=...). Put `channel` as the sink's recipient_arg and
    list allowed channel ids in the policy. Client: HttpClient("https://slack.com", bot_token)."""

    def __init__(self, client: HttpClient):
        self.client = client

    def __call__(self, channel: str, text: str) -> dict:
        ch = check_id(channel, r"[CDG][A-Z0-9]{6,20}|[a-z0-9._-]{1,80}", "channel")
        r = self.client.request("POST", "/api/chat.postMessage", json_body={"channel": ch, "text": str(text)})
        if not (r or {}).get("ok"):
            raise HttpError(200, f"Slack error: {(r or {}).get('error', 'unknown')}")
        return {"ok": True, "channel": ch, "ts": r.get("ts")}


# ------------------------------------------------------------------ email: Microsoft 365, Gmail
def _addresses(to: Any) -> list[str]:
    items = to if isinstance(to, (list, tuple)) else [p.strip() for p in str(to).split(",") if p.strip()]
    out = []
    for a in items:
        if not isinstance(a, str) or "@" not in a or any(c in a for c in "\r\n<>\"'(),;"):
            raise ValueError("each recipient must be a plain email address")
        out.append(a.strip())
    if not out:
        raise ValueError("no recipient")
    return out


class OutlookMailSink:
    """Send an email from a Microsoft 365 mailbox via Microsoft Graph: sink(to=..., subject=..., body=...).
    Client: HttpClient("https://graph.microsoft.com", token) with Mail.Send permission."""

    def __init__(self, client: HttpClient, sender: str, save_to_sent: bool = True):
        self.client, self.sender, self.save = client, _addresses(sender)[0], save_to_sent

    def __call__(self, to: Any, subject: str, body: str) -> dict:
        rcpt = _addresses(to)
        self.client.request("POST", f"/v1.0/users/{quote(self.sender)}/sendMail", json_body={
            "message": {"subject": str(subject), "body": {"contentType": "Text", "content": str(body)},
                        "toRecipients": [{"emailAddress": {"address": a}} for a in rcpt]},
            "saveToSentItems": self.save})
        return {"sent": True, "to": len(rcpt)}


class GmailSink:
    """Send an email via the Gmail API: sink(to=..., subject=..., body=...).
    Client: HttpClient("https://gmail.googleapis.com", token) with the gmail.send scope."""

    def __init__(self, client: HttpClient, sender: str = "me"):
        self.client, self.sender = client, sender

    def __call__(self, to: Any, subject: str, body: str) -> dict:
        msg = EmailMessage()
        msg["To"] = ", ".join(_addresses(to))
        if any(c in str(subject) for c in "\r\n"):
            raise ValueError("subject can't contain line breaks")
        msg["Subject"] = str(subject)
        msg.set_content(str(body))
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        r = self.client.request("POST", f"/gmail/v1/users/{quote(self.sender)}/messages/send", json_body={"raw": raw})
        return {"sent": True, "id": (r or {}).get("id")}


# ------------------------------------------------------------------ MongoDB
class MongoConnector:
    """One document by a key field: MongoConnector(db["customers"], "customer_id", fields=[...]).
    The key must be a plain value, never a query object, so "{'$gt': ''}"-style tricks can't match
    other documents. (pymongo: pip install pymongo)"""

    def __init__(self, collection: Any, key_field: str, fields: list[str] | None = None):
        self.coll = collection
        self.key = check_id(key_field, r"[A-Za-z_][A-Za-z0-9_.]{0,100}", "field")
        self.fields = [check_id(f, r"[A-Za-z_][A-Za-z0-9_.]{0,100}", "field") for f in fields] if fields else None

    def __call__(self, key: Any) -> dict | None:
        if isinstance(key, bool) or not isinstance(key, (str, int, float)):
            raise ValueError("key must be a plain value")
        projection = {f: 1 for f in self.fields} if self.fields else None
        doc = self.coll.find_one({self.key: {"$eq": key}}, projection)
        if doc is None:
            return None
        doc = {k: v for k, v in doc.items() if k != "_id" or (self.fields and "_id" in self.fields)}
        return pick(doc, self.fields)
