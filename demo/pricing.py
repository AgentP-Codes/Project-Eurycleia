# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""What a benchmark run costs, and a hard stop when it reaches your limit.

Prices are US$ per million tokens, as listed on 2026-09-30 (check the provider's pricing page before you rely
on them: they change). Costs are shown in Australian dollars at EURYCLEIA_AUD_PER_USD (default 1.43).
A model that isn't listed needs --price-in and --price-out, so a run never spends without a known price.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

PRICES_CHECKED = "2026-10-17"

# model id (or prefix) -> (input, cached input, cache write, output), US$ per 1M tokens
PRICES: dict[str, tuple[float, float, float, float]] = {
    "claude-haiku-4-5": (1.00, 0.10, 1.25, 5.00),
    "claude-sonnet-5": (2.00, 0.20, 2.50, 10.00),
    "claude-sonnet-5-5": (2.00, 0.10, 2.50, 10.00),     # cache reads halved on 7 Oct 2026
    "claude-opus-5-5": (4.00, 0.40, 5.00, 20.00),
    "gpt-6-luna": (0.10, 0.01, 0.10, 0.50),
    "gpt-5.6-luna": (0.10, 0.01, 0.10, 0.50),
    "gpt-6.1-sol": (2.00, 0.10, 2.00, 10.00),
    "gemini-3.5-flash-lite": (0.30, 0.03, 0.30, 2.50),
    "gemini-2.5-flash-lite": (0.10, 0.01, 0.10, 0.40),
    "gemini-3.8-flash": (0.75, 0.075, 0.75, 3.75),
    "qwen/qwen3.6-plus": (0.325, 0.325, 0.325, 1.95),
}


class BudgetExceeded(RuntimeError):
    """The run reached its spending limit and stopped."""


class UnknownPrice(ValueError):
    """No price is known for this model: pass --price-in and --price-out."""


def aud_per_usd() -> float:
    return float(os.environ.get("EURYCLEIA_AUD_PER_USD") or os.environ.get("TASKVAULT_AUD_PER_USD") or "1.43")


def price_for(model: str, price_in: float | None = None, price_out: float | None = None):
    if price_in is not None and price_out is not None:
        return (price_in, price_in, price_in * 1.25, price_out)
    m = model.removeprefix("models/").lower()
    for key in sorted(PRICES, key=len, reverse=True):
        # the name itself, or the name plus a date or version (claude-haiku-4-5-20251001); never a different
        # model that happens to start the same way (gpt-6.1-sol-pro is not gpt-6.1-sol)
        if m == key or re.fullmatch(re.escape(key) + r"(?:-\d[\d.-]*|@[\w.-]+|:[\w.-]+)", m):
            return PRICES[key]
    raise UnknownPrice(f"no price is known for {model!r}: pass --price-in and --price-out (US$ per million "
                       f"tokens, from the provider's pricing page)")


@dataclass
class Meter:
    """Counts tokens and money for one model; raises BudgetExceeded once the limit is reached."""
    model: str
    budget_aud: float
    price_in: float | None = None
    price_out: float | None = None
    spent_aud: float = 0.0
    tokens: dict[str, int] = field(default_factory=lambda: {"input": 0, "cached": 0, "cache_write": 0,
                                                             "output": 0, "calls": 0})

    def __post_init__(self) -> None:
        self.price = price_for(self.model, self.price_in, self.price_out)

    def add(self, input_tokens: int = 0, cached: int = 0, cache_write: int = 0, output: int = 0) -> float:
        """Record one model call (input_tokens excludes cached and cache-write tokens). Returns its cost."""
        p_in, p_cached, p_write, p_out = self.price
        usd = (input_tokens * p_in + cached * p_cached + cache_write * p_write + output * p_out) / 1e6
        aud = usd * aud_per_usd()
        self.spent_aud += aud
        for k, v in (("input", input_tokens), ("cached", cached), ("cache_write", cache_write), ("output", output)):
            self.tokens[k] += int(v)
        self.tokens["calls"] += 1
        if self.spent_aud >= self.budget_aud:
            raise BudgetExceeded(f"spending limit reached: A${self.spent_aud:.2f} of A${self.budget_aud:.2f} "
                                 f"on {self.model}")
        return aud

    def hook(self, usage: dict[str, int]) -> None:
        """For eurycleia's providers (their `on_usage`)."""
        self.add(usage.get("input", 0), usage.get("cached", 0), usage.get("cache_write", 0), usage.get("output", 0))

    def summary(self) -> str:
        t = self.tokens
        return (f"{self.model}: A${self.spent_aud:.2f} of A${self.budget_aud:.2f} ({t['calls']} calls; tokens: "
                f"{t['input']:,} input, {t['cached']:,} cached, {t['cache_write']:,} cache writes, "
                f"{t['output']:,} output)")
