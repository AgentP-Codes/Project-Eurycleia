# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""AgentDojo's Claude calls: counted, and retried without a temperature when a model refuses one."""

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks" / "agentdojo"))
import metering  # noqa: E402


class Refused(Exception):
    status_code = 400


class Meter:
    def __init__(self):
        self.calls = []

    def add(self, *tokens):
        self.calls.append(tokens)


class Client:
    """A fake Claude client whose `create` takes a temperature, like older Anthropic libraries."""

    def __init__(self, refuse_temperature=False, error=None):
        self.sent, self.refuse, self.error = [], refuse_temperature, error
        self.messages = SimpleNamespace(create=self.create)

    async def create(self, model, messages, max_tokens, tools=None, system=None, temperature=None, thinking=None):
        self.sent.append({"temperature": temperature, "model": model})
        if self.error:
            raise self.error
        if self.refuse and temperature is not None:
            raise Refused("temperature: only the default value is supported for this model")
        return SimpleNamespace(usage=SimpleNamespace(input_tokens=10, cache_read_input_tokens=2,
                                                     cache_creation_input_tokens=3, output_tokens=4))


def call(client, meter, model="m"):
    return asyncio.run(metering.anthropic_call(meter, True, client, model, [{"role": "user", "content": "hi"}],
                                               [], 100, "system", 0.0))


@pytest.fixture(autouse=True)
def fresh():
    metering._NO_TEMPERATURE.clear()


def test_temperature_is_sent_when_accepted():
    c, m = Client(), Meter()
    call(c, m)
    assert [s["temperature"] for s in c.sent] == [0.0]
    assert m.calls == [(10, 2, 3, 4)]


def test_refused_temperature_is_retried_without_it_and_remembered():
    c, m = Client(refuse_temperature=True), Meter()
    call(c, m, "claude-sonnet-5-5")
    call(c, m, "claude-sonnet-5-5")
    assert [s["temperature"] for s in c.sent] == [0.0, None, None]   # asked once with it, never again
    assert len(m.calls) == 2                                         # both calls counted once


def test_other_errors_are_not_retried():
    c = Client(error=Refused("max_tokens: too large"))
    with pytest.raises(Refused):
        call(c, Meter())
    assert len(c.sent) == 1


def test_no_temperature_when_the_library_does_not_take_one():
    class NewClient(Client):
        async def create(self, model, messages, max_tokens, tools=None, system=None, thinking=None):
            self.sent.append({"temperature": None})
            return SimpleNamespace(usage=SimpleNamespace(input_tokens=1, output_tokens=1))

    c = NewClient()
    call(c, Meter())
    assert c.sent == [{"temperature": None}]
