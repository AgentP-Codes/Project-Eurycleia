# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Put the MADE-UP company into the real apps: customers into HubSpot, their payments into Stripe TEST mode.

    python fake_company.py --inbox you.test@gmail.com --out live-data     # once: make the company
    python seed.py                                                         # load it into HubSpot and Stripe
    python seed.py --cleanup                                               # remove everything seed.py made

Uses the same settings and secrets as live.py (see its top). Safe to run again: existing contacts are updated,
and customers already in Stripe aren't charged twice. Stripe live keys are refused.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
sys.path.insert(0, str(HERE))

from live import Settings  # noqa: E402

from eurycleia.connectors.base import HttpClient  # noqa: E402

PROPERTIES = [("eurycleia_customer_id", "Customer id (made-up test data)"), ("plan", "Plan"),
              ("private_notes", "Private notes (made-up test data)")]


class Seeder:
    def __init__(self, settings: Settings, hubspot: HttpClient | None = None, stripe: HttpClient | None = None):
        self.settings = settings
        self.hubspot = hubspot or HttpClient("https://api.hubapi.com", settings.secret("hubspot-token"))
        if stripe is None:
            key = settings.secret("stripe-test-key")
            if not key.startswith(("sk_test_", "rk_test_")):
                raise SystemExit("stripe-test-key must be a TEST key (sk_test_ or rk_test_). Live keys are refused.")
            stripe = HttpClient("https://api.stripe.com", key)
        self.stripe = stripe
        self.state_path = settings.data / "state.json"
        self.state: dict[str, Any] = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        self.company = json.loads((settings.data / "company.json").read_text())

    def save(self) -> None:
        self.state_path.write_text(json.dumps(self.state, indent=2))

    def check_company(self) -> None:
        user, _, host = self.settings.inbox.partition("@")
        wrong = [c["email"] for c in self.company["customers"]
                 if not (c["email"].endswith("@" + host) and c["email"].startswith(user + "+"))]
        if wrong:
            raise SystemExit(f"company.json wasn't made for {self.settings.inbox} (e.g. {wrong[0]}). Make it with "
                             f"`python fake_company.py --inbox {self.settings.inbox} --out {self.settings.data}`")

    def properties(self) -> None:
        for name, label in PROPERTIES:
            try:
                self.hubspot.request("POST", "/crm/v3/properties/contacts", json_body={
                    "name": name, "label": label, "type": "string", "fieldType": "text",
                    "groupName": "contactinformation"})
            except Exception as e:  # noqa: BLE001 - 409: it's already there
                if "409" not in str(e) and "already exists" not in str(e).lower():
                    raise

    def contacts(self) -> int:
        made = self.state.setdefault("customers", {})
        for c in self.company["customers"]:
            props = {"firstname": c["first"], "lastname": c["last"], "email": c["email"], "phone": c["phone"],
                     "address": c["address"].split(",")[0], "city": c["address"].split(",")[1].strip(),
                     "plan": c["plan"], "private_notes": c["private_notes"], "eurycleia_customer_id": c["customer_id"]}
            rec = made.setdefault(c["customer_id"], {})
            if rec.get("hubspot_id"):
                self.hubspot.request("PATCH", f"/crm/v3/objects/contacts/{rec['hubspot_id']}",
                                     json_body={"properties": props})
            else:
                found = self.hubspot.request("POST", "/crm/v3/objects/contacts/search", json_body={
                    "filterGroups": [{"filters": [{"propertyName": "email", "operator": "EQ",
                                                   "value": c["email"]}]}], "limit": 1})
                hits = (found or {}).get("results") or []
                if hits:
                    rec["hubspot_id"] = str(hits[0]["id"])
                    self.hubspot.request("PATCH", f"/crm/v3/objects/contacts/{rec['hubspot_id']}",
                                         json_body={"properties": props})
                else:
                    rec["hubspot_id"] = str(self.hubspot.request("POST", "/crm/v3/objects/contacts",
                                                                 json_body={"properties": props})["id"])
            self.save()
        return len(made)

    def payments(self) -> int:
        made, n = self.state.setdefault("customers", {}), 0
        for c in self.company["customers"]:
            rec = made.setdefault(c["customer_id"], {})
            if rec.get("payments"):
                continue                                       # already charged on an earlier run
            if not rec.get("stripe_customer"):
                rec["stripe_customer"] = self.stripe.request("POST", "/v1/customers", form_body={
                    "email": c["email"], "name": c["name"], "description": "Eurycleia live test (made-up data)",
                    "metadata[eurycleia_customer_id]": c["customer_id"]})["id"]
                self.save()                                    # so a rerun reuses it, even if a payment fails
            pis = []
            for o in (o for o in self.company["orders"] if o["customer_id"] == c["customer_id"]):
                pis.append(self.stripe.request("POST", "/v1/payment_intents", form_body={
                    "amount": int(o["amount_aud"] * 100), "currency": "aud", "customer": rec["stripe_customer"],
                    "payment_method": c["stripe_test_payment_method"], "return_url": "https://example.com/stripe-test-return",
                    "confirm": "true", "description": f"Bramblecove order {o['order_id']} (made-up)",
                    "metadata[order_id]": o["order_id"]})["id"])
                n += 1
            rec["payments"] = pis
            self.save()
        return n

    def cleanup(self) -> list[str]:
        done = []
        for cid, rec in list(self.state.get("customers", {}).items()):
            if rec.get("hubspot_id"):
                self.hubspot.request("DELETE", f"/crm/v3/objects/contacts/{rec['hubspot_id']}", raw=True)
            if rec.get("stripe_customer"):
                self.stripe.request("DELETE", f"/v1/customers/{rec['stripe_customer']}")
            del self.state["customers"][cid]
            done.append(cid)
            self.save()
        return done


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cleanup", action="store_true", help="remove the made-up customers and their payments")
    a = ap.parse_args(argv)
    settings = Settings()
    settings.data.mkdir(parents=True, exist_ok=True)
    if not (settings.data / "company.json").exists():           # first run: make the made-up company
        import fake_company
        fake_company.write(fake_company.make(inbox=settings.inbox), settings.data)
        print(f"made a made-up company for {settings.inbox}")
    s = Seeder(settings)
    if a.cleanup:
        print(f"removed {len(s.cleanup())} made-up customers from HubSpot and Stripe")
        return 0
    s.check_company()
    s.properties()
    print(f"HubSpot: {s.contacts()} made-up customers")
    print(f"Stripe (test mode): {s.payments()} new test payments")
    return 0


if __name__ == "__main__":
    sys.exit(main())
