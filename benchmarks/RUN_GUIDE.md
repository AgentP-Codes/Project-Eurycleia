# Test round: running order (Windows, API models)

This guide runs every model and benchmark in the planned order, with a spending limit on each step. The
limits add up to **A$100**. They are ceilings: each run stops when its own estimate reaches the limit, and
most steps should come in under it.

## Before you start

**1. Set a spending limit with each provider as well.** The script's limits are estimates from reported
tokens. A limit at the provider is the real backstop.

- Anthropic: Console, then Settings, then Limits.
- OpenAI: Settings, then Limits.
- Google AI Studio: Billing, then Budget.
- OpenRouter: buy a small amount of credit, for example US$15.

**2. Set up Python once.** From the Eurycleia folder, open Command Prompt and make three separate
environments. AgentDojo and the frameworks each pin their own libraries, so they need their own.

```
py -3.12 -m venv .venv-tv
.venv-tv\Scripts\activate
pip install -e .
deactivate

py -3.12 -m venv .venv-dojo
.venv-dojo\Scripts\activate
pip install -e . -r benchmarks\agentdojo\requirements.txt
deactivate

py -3.12 -m venv .venv-fw
.venv-fw\Scripts\activate
pip install -e . -r benchmarks\frameworks\requirements.txt
deactivate
```

**3. Add keys in the window you run from.** A new window needs them set again. Never put a key in a file,
on the command line of a script, or in a chat.

```
set ANTHROPIC_API_KEY=...
set OPENAI_API_KEY=...
set GEMINI_API_KEY=...
set OPENROUTER_API_KEY=...
```

**4. Check the OpenRouter model names and prices.** Look up DeepSeek V4.1 Flash, GLM 5.3 Flash and Qwen3.6
Plus on openrouter.ai. The exact model id is on each page, for example `qwen/qwen3.6-plus`. For models
without a built-in price, pass `--price-in` and `--price-out` in US$ per million tokens, from the same page.

**5. Keep the results.** Every step saves its results as it goes. Running the same command again carries on
where it stopped, and the money already spent still counts toward that step's limit.

## Step 1: cheap models on AgentDojo, full runs (about A$29 at most)

```
.venv-dojo\Scripts\activate
cd benchmarks\agentdojo
python run_live.py --provider openai --model gpt-6-luna --smoke --budget-aud 0.5
python run_live.py --provider openai --model gpt-6-luna --budget-aud 8
python run_live.py --provider gemini --model gemini-3.5-flash-lite --smoke --budget-aud 0.5
python run_live.py --provider gemini --model gemini-3.5-flash-lite --budget-aud 14
python run_live.py --provider openrouter --model <deepseek id> --price-in <in> --price-out <out> --budget-aud 2
python run_live.py --provider openrouter --model <glm id> --price-in <in> --price-out <out> --budget-aud 2
python run_live.py --provider openrouter --model qwen/qwen3.6-plus --sample 0.1 --budget-aud 2
python run_live.py --summarize agentdojo-results.jsonl
cd ..\..
deactivate
```

Always run `--smoke` first on a new provider: 2 tasks and 2 attacks, a few cents. If the smoke run shows
errors, stop and send them to me before the full run. The Gemini 3.x smoke run matters most, because
AgentDojo's Gemini support hasn't been tried with this model yet.

## Step 2: the stronger models on AgentDojo, samples (about A$48 at most)

```
.venv-dojo\Scripts\activate
cd benchmarks\agentdojo
python run_live.py --provider anthropic --model claude-haiku-4-5 --smoke --budget-aud 0.5
python run_live.py --provider anthropic --model claude-haiku-4-5 --sample 0.5 --budget-aud 18
python run_live.py --provider anthropic --model claude-sonnet-5 --sample 0.25 --budget-aud 15
python run_live.py --provider openai --model gpt-6.1-sol --sample 0.25 --budget-aud 14
python run_live.py --summarize agentdojo-results.jsonl
cd ..\..
deactivate
```

## Step 3: Eurycleia's own benchmark, 3 runs each (about A$8 at most)

This uses 21 support tickets, 20 of them attacks, in three set-ups: no vault, vault, and planner.

```
.venv-tv\Scripts\activate
python -m demo.bench --provider openai --model gpt-6-luna --runs 3 --budget-aud 0.5 --out bench-luna.json
python -m demo.bench --provider gemini --model gemini-3.5-flash-lite --runs 3 --budget-aud 1 --out bench-gemini.json
python -m demo.bench --provider openrouter --model <deepseek id> --price-in <in> --price-out <out> --runs 3 --budget-aud 0.5 --out bench-deepseek.json
python -m demo.bench --provider anthropic --model claude-haiku-4-5 --runs 3 --budget-aud 2 --out bench-haiku.json
python -m demo.bench --provider anthropic --model claude-sonnet-5 --runs 3 --budget-aud 2.5 --out bench-sonnet.json
python -m demo.bench --provider openai --model gpt-6.1-sol --runs 3 --budget-aud 1.5 --out bench-sol.json
deactivate
```

Also run the same benchmark once with pseudonyms switched on. The model then sees stand-ins (`Name-1A2B3C`)
instead of customers' names and contact details. Comparing it with the run above shows whether stand-ins confuse
a real model:

```
.venv-tv\Scripts\activate
python -m demo.bench --provider openai --model gpt-6-luna --configs vault --runs 3 --pseudonyms --budget-aud 0.5 --out bench-luna-pseudonyms.json
deactivate
```

## Step 4: real agent frameworks and an MCP agent (about A$7 at most)

This runs LangGraph and CrewAI agents, and an API model using an MCP server both directly and after
`eurycleia connect`.

```
.venv-fw\Scripts\activate
cd benchmarks\frameworks
python run_frameworks.py --framework langgraph --framework crewai --provider openai --model gpt-6-luna --smoke --budget-aud 0.3
python run_frameworks.py --framework langgraph --framework crewai --provider openai --model gpt-6-luna --budget-aud 1
python run_frameworks.py --framework langgraph --framework crewai --provider anthropic --model claude-haiku-4-5 --budget-aud 1.5
python run_frameworks.py --framework langgraph --framework crewai --provider anthropic --model claude-sonnet-5 --budget-aud 1.5
python run_frameworks.py --framework langgraph --provider gemini --model gemini-3.5-flash-lite --budget-aud 1
cd ..\mcp_agent
python run_mcp.py --provider openai --model gpt-6-luna --budget-aud 0.5
python run_mcp.py --provider anthropic --model claude-sonnet-5 --budget-aud 1.5
cd ..\..
deactivate
```

## Step 5: real apps (about A$3 at most)

Set up the test accounts first, as described in `benchmarks\real_apps\REAL_APPS.md`. Use new test accounts
and made-up data only.

```
.venv-tv\Scripts\activate
cd benchmarks\real_apps
python run_real.py check
python run_real.py seed
python run_real.py run --smoke
python run_real.py run
python run_real.py run --provider openai --model gpt-6-luna --budget-aud 1
python run_real.py run --provider anthropic --model claude-haiku-4-5 --budget-aud 2
python run_real.py summarize
python run_real.py cleanup
cd ..\..
deactivate
```

## Step 6: overnight long run (about A$3 at most)

Before you start, set the laptop to not sleep while plugged in: Settings, then System, then Power.

```
.venv-tv\Scripts\activate
python benchmarks\longrun\run_long.py --provider openai --model gpt-6-luna --tickets 20 --budget-aud 0.2
python benchmarks\longrun\run_long.py --provider openai --model gpt-6-luna --hours 6 --budget-aud 3
deactivate
```

The first command is a quick check. The second runs until 6 hours pass or A$3 is spent, whichever comes
first. It prints a line every 25 tickets and stops by itself after 10 failures in a row.

## Step 7: `eurycleia learn` with a real model (about A$2 at most)

The model handles 40 tickets in watch mode, starting from a policy that's too tight, with about 1 in 5 tickets
carrying an attack. `eurycleia learn` then drafts a policy. Finally, 20 fresh tickets run with the draft
switched on: normal tickets should still get done, and no attack should leak.

```
.venv-tv\Scripts\activate
python benchmarks\learn\run_learn.py --provider openai --model gpt-6-luna --smoke --budget-aud 0.2
python benchmarks\learn\run_learn.py --provider openai --model gpt-6-luna --budget-aud 0.5 --out learn-luna
python benchmarks\learn\run_learn.py --provider anthropic --model claude-haiku-4-5 --budget-aud 1.5 --out learn-haiku
deactivate
```

Each run saves its draft policy, `learn-report.md` and `learn-results.json` in its `--out` folder.

## Afterwards

**1. Send me the results files.** They hold no keys:

- `benchmarks\agentdojo\agentdojo-results.jsonl`
- the `bench-*.json` files (including `bench-luna-pseudonyms.json`)
- `benchmarks\frameworks\framework-results.jsonl`
- `benchmarks\mcp_agent\mcp-results.jsonl`
- `benchmarks\real_apps\real-apps-results.jsonl`
- `longrun-results.jsonl` and `longrun-results.report.json`
- the `learn-luna` and `learn-haiku` folders

The real-app results include your test addresses. That's fine, since they are test accounts.

**2. Delete or roll every API key** in each provider's console, then close the Command Prompt window.

## The limits

| Step | Limit (A$) |
|---|---|
| 1. AgentDojo: gpt-6-luna 8, Gemini 3.5 Flash-Lite 14, DeepSeek 2, GLM 2, Qwen 2 (plus smoke runs 1) | 29 |
| 2. AgentDojo: Haiku 4.5 18, Sonnet 5 15, gpt-6.1-sol 14 (plus smoke run 0.5) | 47.5 |
| 3. Eurycleia benchmark: 6 models | 8 |
| 4. Frameworks 5.3, MCP agent 2 | 7.3 |
| 5. Real apps | 3 |
| 6. Long run (plus check 0.2) | 3.2 |
| 7. `eurycleia learn`: Luna 0.5, Haiku 1.5 (plus smoke run 0.2) | 2.2 |
| **Total** | **100** |

Each limit is a ceiling, so the real total is likely lower.
