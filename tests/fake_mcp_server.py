# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""SIMULATED. A tiny stand-in MCP server with the demo company's data (used by the proxy tests).

Every email it "sends" is appended to the file named by $FAKE_MCP_OUTBOX. If $FAKE_MCP_DEFS names a JSON file,
its contents change what tools/list says ({"version": "2", "tools": {"send_email": {"description": ...}}}), read
each time, so a test can make the server change its tools (a "rug pull") between or during sessions.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from demo.world import World  # noqa: E402

for _stream in (sys.stdin, sys.stdout):       # MCP messages are UTF-8, like a real MCP server's
    _stream.reconfigure(encoding="utf-8")
world = World()
OUTBOX = os.environ.get("FAKE_MCP_OUTBOX")

TOOLS = {
    "get_customer": lambda a: world.get_customer(a.get("customer_id")),
    "list_customers": lambda a: world.list_customers(),
    "get_doc": lambda a: world.get_doc(a.get("name")),
    "get_ticket": lambda a: world.get_ticket(a.get("ticket_id")),
    "send_email": lambda a: world.send_email(a["to"], a.get("subject", ""), a.get("body", "")),
    "refund": lambda a: world.refund(a["card"], a["amount"]),
}


def reply(rid, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}, ensure_ascii=False) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    msg = json.loads(line)
    method, rid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    defs = {}
    if os.environ.get("FAKE_MCP_DEFS") and os.path.exists(os.environ["FAKE_MCP_DEFS"]):
        with open(os.environ["FAKE_MCP_DEFS"], encoding="utf-8") as f:
            defs = json.load(f)
    if method == "initialize":
        reply(rid, {"protocolVersion": params.get("protocolVersion"), "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake-acme", "version": defs.get("version", "0")}})
    elif method == "tools/list":
        listed = [{"name": n, "inputSchema": {"type": "object"}, **(defs.get("tools") or {}).get(n, {})}
                  for n in TOOLS]
        reply(rid, {"tools": listed + [t for n, t in (defs.get("tools") or {}).items() if n not in TOOLS]})
    elif method == "tools/call":
        out = TOOLS[params["name"]](params.get("arguments") or {})
        if params["name"] == "send_email" and OUTBOX:
            with open(OUTBOX, "a", encoding="utf-8") as f:
                f.write(json.dumps(world.outbox[-1], ensure_ascii=False) + "\n")
        if out is None:
            reply(rid, {"isError": True, "content": [{"type": "text", "text": "not found"}]})
        else:
            reply(rid, {"content": [{"type": "text", "text": json.dumps(out)}]})
    elif rid is not None:
        reply(rid, {})
