# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""LangChain / LangGraph add-on: eurycleia-protected tools for any LangChain agent.

    from langchain.agents import create_agent
    from eurycleia.integrations.langchain import protect
    agent = create_agent(model, tools=protect(task), system_prompt=...)

Works with LangGraph agents and anything else that takes LangChain tools. Every call goes
through the vault's checks. Needs langchain-core; eurycleia itself doesn't depend on it.
"""

from __future__ import annotations

from typing import Any

from ._common import tool_entries


def protect(task: Any) -> list[Any]:
    from langchain_core.tools import StructuredTool

    return [StructuredTool.from_function(func=lambda _run=e.run, **kw: _run(**kw), name=e.name,
                                         description=e.description, args_schema=e.schema)
            for e in tool_entries(task)]
