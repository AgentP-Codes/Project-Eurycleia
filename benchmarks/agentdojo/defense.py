# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""An AgentDojo pipeline element: runs the model's tool calls through eurycleia's rules (see rules.py).

Drop-in replacement for AgentDojo's ToolsExecutor. A blocked call is not run; the model gets the reason
as the tool's error, just as eurycleia's MCP proxy and adapters report a block."""

from __future__ import annotations

from ast import literal_eval
from collections.abc import Sequence

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string
from rules import Gate


def allowed_writes_by_prompt(suite, env) -> dict[str, set[str]]:
    """Each user task's template for strict mode: the tools its reference solution uses."""
    return {t.PROMPT: {c.function for c in t.ground_truth(env)} for t in suite.user_tasks.values()}


class EurycleiaToolsExecutor(BasePipelineElement):
    def __init__(self, suite_name: str, templates: dict[str, set[str]] | None = None) -> None:
        self.suite_name = suite_name
        self.templates = templates                   # None: general mode

    def gate_for(self, query: str, extra_args: dict) -> tuple[Gate, dict]:
        gate = extra_args.get("eurycleia_gate")
        if gate is None:
            allowed = None if self.templates is None else self.templates.get(query, set())
            gate = Gate(self.suite_name, query, allowed)
            extra_args = {**extra_args, "eurycleia_gate": gate}
        return gate, extra_args

    def run_call(self, gate: Gate, runtime: FunctionsRuntime, env: Env, call: FunctionCall) -> ChatToolResultMessage:
        for k, v in call.args.items():                # AgentDojo's own fix-up: lists sent as strings
            if isinstance(v, str) and is_string_list(v):
                call.args[k] = literal_eval(v)
        if call.function not in runtime.functions:
            return _result(call, "", f"Invalid tool {call.function} provided.")
        reason = gate.check(call.function, dict(call.args))
        if reason:
            return _result(call, "", f"Blocked by eurycleia: {reason}")
        result, error = runtime.run_function(env, call.function, call.args)
        if error is None:
            gate.learn(call.function, result)
        return _result(call, tool_result_to_str(result), error)

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),  # noqa: B008 - AgentDojo's
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):  # noqa: B006 - signature
        gate, extra_args = self.gate_for(query, extra_args)
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        results = [self.run_call(gate, runtime, env, c) for c in messages[-1]["tool_calls"]]
        return query, runtime, env, [*messages, *results], extra_args


def run_episode(suite, pipeline, user_task, injection_task, injections: dict[str, str]) -> dict:
    """AgentDojo's run_task_with_pipeline, but also reporting whether an attack succeeded counting only the
    tool calls that actually ran. (AgentDojo judges some attacks from the calls the model *attempted*, so a
    call eurycleia refused would still count as a successful attack.)"""
    from agentdojo.agent_pipeline.errors import AbortAgentError
    from agentdojo.task_suite.task_suite import functions_stack_trace_from_messages, model_output_from_messages

    env = suite.load_and_inject_default_environment(injections)
    env = user_task.init_environment(env)
    pre = env.model_copy(deep=True)
    runtime = FunctionsRuntime(suite.tools)
    messages: list = []
    try:
        _, _, env, messages, _ = pipeline.query(user_task.PROMPT, runtime, env)
    except AbortAgentError as e:
        env, messages = e.task_environment, e.messages
    output = (model_output_from_messages(messages) if messages and messages[-1]["role"] == "assistant" else None) or []
    trace = functions_stack_trace_from_messages(messages)
    refused = {id(m["tool_call"]) for m in messages if m["role"] == "tool" and m.get("tool_call") is not None and
               (m.get("error") or "").startswith("Blocked by eurycleia")}
    ran = [c for c in trace if id(c) not in refused]
    out = {"utility": bool(suite._check_task_result(user_task, output, pre, env, ran)),
           "blocked": [f"{m['tool_call'].function}: {m['error'][22:]}" for m in messages
                       if m["role"] == "tool" and (m.get("error") or "").startswith("Blocked by eurycleia")]}
    if injection_task is not None:
        out["attack_agentdojo"] = bool(suite._check_task_result(injection_task, output, pre, env, trace))
        out["attack_effective"] = bool(suite._check_task_result(injection_task, output, pre, env, ran))
    return out


def _result(call: FunctionCall, text: str, error: str | None) -> ChatToolResultMessage:
    return ChatToolResultMessage(role="tool", content=[text_content_block_from_string(text)],
                                 tool_call_id=call.id, tool_call=call, error=error)
