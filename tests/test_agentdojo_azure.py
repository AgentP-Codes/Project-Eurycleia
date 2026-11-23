# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""AgentDojo on Azure OpenAI: the v1 address, and sign-in with a key or a renewed Azure token (no stored key)."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("agentdojo")
httpx = pytest.importorskip("httpx")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks" / "agentdojo"))
import run_live  # noqa: E402

REPLY = {"id": "x", "object": "chat.completion", "created": 0, "model": "gpt-5-mini",
         "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}],
         "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


def _ask(client, seen):
    client._client = httpx.Client(transport=httpx.MockTransport(
        lambda req: seen.append((str(req.url), req.headers.get("authorization"))) or httpx.Response(200, json=REPLY)))
    client.chat.completions.create(model="gpt-5-mini", messages=[{"role": "user", "content": "hi"}])


def test_azure_signs_in_with_a_renewed_token_when_there_is_no_key(monkeypatch):
    import eurycleia.azure as az
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://res.openai.azure.com/")
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
    n = {"calls": 0}

    class Token:
        def __init__(self, resource):
            assert resource == az.OPENAI_RESOURCE

        def __call__(self):
            n["calls"] += 1
            return f"t{n['calls']}"
    monkeypatch.setattr(az, "AzureToken", Token)
    seen = []
    client = run_live.azure_client()
    _ask(client, seen)
    _ask(client, seen)
    assert seen == [("https://res.openai.azure.com/openai/v1/chat/completions", "Bearer t1"),
                    ("https://res.openai.azure.com/openai/v1/chat/completions", "Bearer t2")]   # asked each call


def test_azure_uses_the_key_when_set_and_needs_https(monkeypatch):
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "k")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://res.openai.azure.com/openai/v1")
    seen = []
    _ask(run_live.azure_client(), seen)
    assert seen == [("https://res.openai.azure.com/openai/v1/chat/completions", "Bearer k")]
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "http://res.openai.azure.com")
    with pytest.raises(SystemExit):
        run_live.azure_client()


def test_the_azure_job_turns_its_settings_into_a_run_that_resumes(tmp_path):
    import bench_job
    argv, out = bench_job.settings({"EURYCLEIA_MODEL": "gpt-5-mini", "BENCH_ATTACK": "tool_knowledge",
                                    "EURYCLEIA_DATA": str(tmp_path), "BENCH_SUITES": "banking slack"})
    assert out == tmp_path / "bench" / "gpt-5-mini-tool_knowledge-0.25.jsonl"     # same settings, same file
    assert argv[:2] == ["--provider", "azure"] and "--budget-aud" in argv and argv.count("--suite") == 2
    for bad in ({"BENCH_MODEL": "x; rm -rf /"}, {"BENCH_SAMPLE": "2"}, {"BENCH_ATTACK": "../x"}):
        with pytest.raises(SystemExit):
            bench_job.settings({"EURYCLEIA_DATA": str(tmp_path), **bad})
