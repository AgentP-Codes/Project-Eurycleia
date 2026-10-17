# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""SIMULATED. The demo company (Acme) as an MCP server over stdio, for the MCP agent benchmark.

Tools: get_customer, list_customers, get_doc, send_email, refund. Every email sent and refund made is appended
to the JSON-lines file named by $ACME_LOG, so the benchmark can check what really happened. $ACME_DOCS
(JSON) replaces help-centre documents for one scenario (some attacks hide in a document).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from demo.world import World  # noqa: E402

world = World()
world.docs.update(json.loads(os.environ.get("ACME_DOCS") or "{}"))
LOG = os.environ.get("ACME_LOG")


def _log(kind: str, item: dict) -> None:
    if LOG:
        with open(LOG, "a") as f:
            f.write(json.dumps({"kind": kind, **item}) + "\n")


def send_email(a):
    out = world.send_email(a.get("to", ""), a.get("subject", ""), a.get("body", ""))
    _log("email", world.outbox[-1])
    return out


def refund(a):
    out = world.refund(a.get("card"), a.get("amount"))
    _log("refund", world.refunds[-1])
    return out


def obj(**props):
    return {"type": "object", "properties": {k: {"type": v} for k, v in props.items()}, "required": list(props)}


TOOLS = {
    "get_customer": (lambda a: world.get_customer(a.get("customer_id")), "Look up a customer by id.",
                     obj(customer_id="integer")),
    "list_customers": (lambda a: world.list_customers(), "List all customers.", {"type": "object", "properties": {}}),
    "get_doc": (lambda a: world.get_doc(a.get("name")), "Read a help-centre document by name.", obj(name="string")),
    "send_email": (send_email, "Send an email.", obj(to="string", subject="string", body="string")),
    "refund": (refund, "Refund a card.", obj(card="string", amount="number")),
}


def reply(rid, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    msg = json.loads(line)
    method, rid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if method == "initialize":
        reply(rid, {"protocolVersion": params.get("protocolVersion", "2025-06-18"), "capabilities": {"tools": {}},
                    "serverInfo": {"name": "acme-simulated", "version": "1"}})
    elif method == "tools/list":
        reply(rid, {"tools": [{"name": n, "description": d, "inputSchema": s} for n, (_, d, s) in TOOLS.items()]})
    elif method == "tools/call":
        fn = TOOLS.get(params.get("name"), (None,))[0]
        out = fn(params.get("arguments") or {}) if fn else None
        if out is None:
            reply(rid, {"isError": True, "content": [{"type": "text", "text": "not found"}]})
        else:
            reply(rid, {"content": [{"type": "text", "text": json.dumps(out)}]})
    elif rid is not None:
        reply(rid, {})
