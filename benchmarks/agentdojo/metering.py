# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Count what AgentDojo's model calls cost, stop at a budget, and turn on Claude's prompt caching.

AgentDojo's model classes call each provider's SDK through one module-level function per provider. These
replacements do the same call, then record the tokens the provider reports in a Meter (demo/pricing.py),
which raises BudgetExceeded once the run reaches its limit. For Claude they also mark the system prompt,
tool list and newest message as cacheable (OpenAI and Gemini cache repeated prompts by themselves).
"""

from __future__ import annotations

import time
from typing import Any


def _anthropic_cached(system: Any, tools: list, messages: list) -> tuple[Any, list, list]:
    mark = {"type": "ephemeral"}
    if isinstance(system, str) and system:
        system = [{"type": "text", "text": system, "cache_control": mark}]
    if tools:
        tools = [*tools[:-1], {**dict(tools[-1]), "cache_control": mark}]
    if messages:
        last = dict(messages[-1])
        content = last.get("content")
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        if isinstance(content, list) and content:
            block = content[-1] if isinstance(content[-1], dict) else content[-1].model_dump(exclude_none=True)
            block = {k: v for k, v in block.items() if v is not None}     # e.g. citations: None isn't accepted
            last["content"] = [*content[:-1], {**block, "cache_control": mark}]
            messages = [*messages[:-1], last]
    return system, tools, messages


def _accepts(fn, name: str) -> bool:
    import inspect
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return True
    return name in params or any(p.kind is p.VAR_KEYWORD for p in params.values())


# Models that refused a temperature setting in this run. Newer Claude models accept only the default.
_NO_TEMPERATURE: set[str] = set()


def _refuses_temperature(e: Exception) -> bool:
    return getattr(e, "status_code", None) == 400 and "temperature" in str(e).lower()


async def anthropic_call(meter, cache, client, model, messages, tools, max_tokens, system_prompt=None,
                         temperature=0.0, thinking_budget_tokens=None):
    """One Claude call, counted in `meter`. A model that refuses a temperature setting is asked again without
    one, and isn't sent one again in this run."""
    system, tools_, messages_ = (_anthropic_cached(system_prompt, list(tools or []), list(messages))
                                 if cache else (system_prompt, tools, messages))
    kwargs: dict[str, Any] = {"model": model, "messages": messages_, "max_tokens": max_tokens}
    if tools_:
        kwargs["tools"] = tools_
    if system:
        kwargs["system"] = system
    if thinking_budget_tokens:
        kwargs["thinking"] = {"type": "enabled", "budget_tokens": thinking_budget_tokens}
    elif (temperature is not None and model not in _NO_TEMPERATURE
          and _accepts(client.messages.create, "temperature")):
        kwargs["temperature"] = temperature      # newer Anthropic libraries no longer take a temperature
    try:
        msg = await client.messages.create(**kwargs)
    except Exception as e:  # noqa: BLE001 - only a refused temperature is retried; anything else is raised
        if "temperature" not in kwargs or not _refuses_temperature(e):
            raise
        _NO_TEMPERATURE.add(model)
        del kwargs["temperature"]
        msg = await client.messages.create(**kwargs)
    u = msg.usage
    meter.add(u.input_tokens or 0, getattr(u, "cache_read_input_tokens", 0) or 0,
              getattr(u, "cache_creation_input_tokens", 0) or 0, u.output_tokens or 0)
    return msg


def install(meter, cache: bool = True) -> None:
    """Route AgentDojo's Anthropic, OpenAI(-compatible) and Google calls through `meter`."""
    from agentdojo.agent_pipeline.llms import anthropic_llm, google_llm, openai_llm

    async def anthropic_request(client, model, messages, tools, max_tokens, system_prompt=None, temperature=0.0,
                                thinking_budget_tokens=None):
        return await anthropic_call(meter, cache, client, model, messages, tools, max_tokens, system_prompt,
                                    temperature, thinking_budget_tokens)

    original_openai = getattr(openai_llm.chat_completion_request, "__wrapped__", openai_llm.chat_completion_request)

    def openai_request(*args, **kwargs):
        for attempt in range(5):
            try:
                completion = original_openai(*args, **kwargs)
                break
            except Exception as e:  # noqa: BLE001 - rate limits: wait and retry, like AgentDojo's own wrapper
                if attempt == 4 or "rate" not in str(e).lower() and "429" not in str(e):
                    raise
                time.sleep(10 * (attempt + 1))
        u = getattr(completion, "usage", None)
        if u is not None:
            details = getattr(u, "prompt_tokens_details", None)
            cached = (getattr(details, "cached_tokens", 0) or 0) if details else 0
            meter.add((u.prompt_tokens or 0) - cached, cached, 0, u.completion_tokens or 0)
        return completion

    original_google = getattr(google_llm.chat_completion_request, "__wrapped__", google_llm.chat_completion_request)

    def google_request(*args, **kwargs):
        for attempt in range(5):
            try:
                response = original_google(*args, **kwargs)
                break
            except Exception as e:  # noqa: BLE001 - rate limits: wait and retry
                if attempt == 4 or "429" not in str(e) and "RESOURCE_EXHAUSTED" not in str(e):
                    raise
                time.sleep(15 * (attempt + 1))
        u = getattr(response, "usage_metadata", None)
        if u is not None:
            cached = getattr(u, "cached_content_token_count", 0) or 0
            meter.add((getattr(u, "prompt_token_count", 0) or 0) - cached, cached, 0,
                      (getattr(u, "candidates_token_count", 0) or 0) + (getattr(u, "thoughts_token_count", 0) or 0))
        return response

    anthropic_llm.chat_completion_request = anthropic_request
    openai_llm.chat_completion_request = openai_request
    google_llm.chat_completion_request = google_request
