# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared by the framework add-ons: each eurycleia tool as (name, description, argument schema, runner).

The runner always goes through `task.call_tool`, so every call gets the vault's checks, and it
always returns text: a blocked call comes back as "Blocked by eurycleia: ..." for the agent to read.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

_TYPES = {"string": str, "number": float, "integer": int, "boolean": bool, "array": list, "object": dict}


@dataclass
class ToolEntry:
    name: str
    description: str
    schema: Any                     # a pydantic model class
    run: Callable[..., str]


def tool_entries(task: Any) -> list[ToolEntry]:
    from pydantic import Field, create_model  # every supported framework already depends on pydantic

    from ..errors import EurycleiaError
    from ..vault import RECORD_ID, Blocked

    out = []
    for spec in task.tool_specs():
        props = spec["input_schema"].get("properties", {})

        def kind(v: dict[str, Any]) -> Any:
            if v.get("description") == RECORD_ID:
                return str | int        # models often send a record id as a number (customer_id=12)
            return _TYPES.get(v.get("type"), Any)

        fields = {k: (kind(v) | None, Field(default=None, description=v.get("description", "")))
                  for k, v in props.items()}
        schema = create_model(f"{spec['name']}_args", **fields)

        def run(_name: str = spec["name"], **kwargs: Any) -> str:
            args = {k: v for k, v in kwargs.items() if v is not None}
            try:
                result = task.call_tool(_name, args)
            except Blocked as e:
                return f"Blocked by eurycleia: {e.reason}"
            except (KeyError, EurycleiaError) as e:
                return f"Not available: {e}"
            return result if isinstance(result, str) else json.dumps(result, default=str)

        out.append(ToolEntry(spec["name"], spec["description"], schema, run))
    return out
