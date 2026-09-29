# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared by the framework add-ons: each taskvault tool as (name, description, argument schema, runner).

The runner always goes through `task.call_tool`, so every call gets the vault's checks, and it
always returns text: a blocked call comes back as "Blocked by taskvault: ..." for the agent to read.
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

    from ..errors import TaskvaultError
    from ..vault import Blocked

    out = []
    for spec in task.tool_specs():
        props = spec["input_schema"].get("properties", {})
        fields = {k: (_TYPES.get(v.get("type"), Any) | None,
                      Field(default=None, description=v.get("description", ""))) for k, v in props.items()}
        schema = create_model(f"{spec['name']}_args", **fields)

        def run(_name: str = spec["name"], **kwargs: Any) -> str:
            args = {k: v for k, v in kwargs.items() if v is not None}
            try:
                result = task.call_tool(_name, args)
            except Blocked as e:
                return f"Blocked by taskvault: {e.reason}"
            except (KeyError, TaskvaultError) as e:
                return f"Not available: {e}"
            return result if isinstance(result, str) else json.dumps(result, default=str)

        out.append(ToolEntry(spec["name"], spec["description"], schema, run))
    return out
