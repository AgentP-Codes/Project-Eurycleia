# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Demo vault for the language adapters (SIMULATED data).

    taskvault api --policy demo/policy.yaml --app demo.api_app:build_vault

Customer records, documents and tickets come from the simulated world. The actions (email.send,
payments.refund) are run by the connected app itself, in its own language, through the adapter.
"""

from taskvault import AuditLog, Policy, Vault

from .__main__ import POLICY
from .world import World


def build_vault(sinks: dict) -> Vault:
    world = World()
    return Vault(Policy.load(POLICY),
                 sources={"crm.customer": world.get_customer, "docs": world.get_doc, "inbox.ticket": world.get_ticket},
                 sinks=sinks, audit=AuditLog())
