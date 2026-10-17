# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""CrewAI add-on: give a CrewAI agent eurycleia-protected tools.

    from eurycleia.integrations.crewai import protect
    agent = Agent(role=..., goal=..., backstory=..., tools=protect(task), llm=...)

`task` is a eurycleia Task (from vault.start_task). The agent only gets the tools the task's
policy allows, and every call goes through the vault's checks. Needs CrewAI (pip install crewai);
eurycleia itself doesn't depend on it.
"""

from __future__ import annotations

from typing import Any

from ._common import tool_entries


def protect(task: Any) -> list[Any]:
    from crewai.tools import BaseTool

    tools = []
    for e in tool_entries(task):
        cls = type(f"Eurycleia_{e.name}", (BaseTool,),
                   {"__annotations__": {}, "_run": lambda self, _run=e.run, **kw: _run(**kw)})
        tools.append(cls(name=e.name, description=e.description, args_schema=e.schema))
    return tools
