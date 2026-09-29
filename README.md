# taskvault

**A data vault for AI agents.** taskvault sits between an AI agent and your company's data. Each task sees only the data it needs, personal details and secrets are hidden from the AI, and data can only go where your policy allows, even if a prompt injection takes the agent over. It reduces risk; it doesn't remove it (see [Limitations](#limitations)).

> [!WARNING]
> **Early release: use at your own risk.** taskvault is new and hasn't been fully tested in real-world use. It hasn't had an independent security review, the connectors have only been tested against simulated services, and testing with live AI models is still limited (see [What's simulated](#whats-simulated) and [real-model results](docs/real-model-results.md)). Test results don't guarantee it will stop every attack. Don't rely on it as your only protection for sensitive or regulated data, and test it thoroughly in your own environment first. Things may change between versions.
>
> **Not recommended for live production AI agents handling real customer data yet.** Use it for testing, prototypes and watch mode until it has been tested further.
>
> Provided "as is", without warranty of any kind, under the [AGPL-3.0 licence](LICENSE). Its features describe design goals, not guarantees. Please read the full [Disclaimer](#disclaimer) before using it.

**Status:** v0.5.1 beta · Feedback, issues and ideas are very welcome.

**How this was built:** taskvault was designed and directed by @AgentP-Codes. Much of the code, tests and documentation were written with the help of Claude (Anthropic's AI). The live model tests were run by the project using its own API keys. All the code is open for review.

## What it does

- **Protects the agent you already have.** One command puts taskvault in front of an agent's tools (Claude Desktop, Hermes and other MCP apps), with no code changes. For CrewAI and LangGraph it's one line of code.
- **Works with agents in other languages:** Python, TypeScript/JavaScript, Go and Java.
- **Gives each task only the data it needs.** Answering one customer's ticket? The agent sees that customer's record, and only the fields it asks for.
- **Hides personal details and secrets from the AI.** Names and emails become stand-ins, and card numbers and similar secrets are never shown to the AI at all. Real values are swapped back only when an approved action needs them.
- **Stops data going to the wrong place.** Customer data can only go to that customer or your own staff. Recipients planted in a ticket or document are refused.
- **Sets firm limits:** how much data a task can read, how many times an action can run, and which actions need a person to approve them.
- **Keeps sensitive data in encrypted deposit boxes,** one per customer, department or client company, with a second key required for the most sensitive information.
- **Lets you watch before you block.** Watch mode records what taskvault *would* have blocked without blocking anything, and `taskvault report` summarises it.
- **Keeps a tamper-evident record** of what the agent read and did, with no real data values in it.
- **Scans your data and writes a starter setup,** so you don't start from a blank page.
- **Stays small.** Two required libraries, no AI company libraries, and it runs on an ordinary laptop.

## What's new in 0.5

- **Easy start:** `taskvault connect` protects an existing agent in watch mode; `report`, `enforce` and `disconnect` do the rest.
- **Other languages:** a local API and small, dependency-free adapters for TypeScript/JavaScript, Go and Java.
- **More data protections:** free-text scrubbing, safe summaries instead of raw values, fields on request, data budgets, and separate settings for AI you run yourself.
- **More connectors** (22 in total), including HubSpot, Zendesk, Stripe, Xero, Slack, Outlook, Gmail and MongoDB.
- **Smaller, faster deposit boxes** (about 2 KB per customer), with log archiving and a one-step upgrade from 0.4.
- **Fewer outside libraries:** Claude, OpenAI, Gemini and Ollama need nothing extra installed. Every library is pinned and checked for known vulnerabilities, and release builds are set up to be signed.
- **Security fixes** from an external report, from real-model testing and from a round of stress testing and independent AI reviews.
- **Leaner:** session replay, the behaviour baseline and the old secret store were removed.
- **Licence:** the core is now AGPL-3.0 (see [Licence](#licence)).

Full details are in the [changelog](CHANGELOG.md).

## Install

Requires Python 3.10 or later.

```bash
pip install git+https://github.com/AgentP-Codes/Task-Vault-Name-is-bound-to-Change-
taskvault --version
```

Or download the `.whl` from the [latest release](https://github.com/AgentP-Codes/Task-Vault-Name-is-bound-to-Change-/releases) and `pip install` it. Optional extras: `postgres`, `aws`, `langchain`, `crewai`.

## Get started

**1. Scan your data and get a starter policy.** taskvault works out what's sensitive and who owns each record, and explains every choice it makes:

```bash
taskvault setup --sqlite crm.db --docs ./help-articles --domain yourcompany.com
taskvault check     # validate the policy
taskvault test      # run the built-in attack suite against it (exits 1 on any leak)
```

It also reads CSV/JSON files, Postgres and MCP servers, and recognises cards, Australian TFN / Medicare / ABN / BSB numbers, IBANs, API keys, emails, phones, names, addresses and more. Sample values are read locally to classify fields and are never written anywhere.

**2. Protect your agent.** Pick whichever fits:

```bash
# An existing agent app (Claude Desktop, Hermes, other MCP apps): starts in watch mode
taskvault connect claude-desktop --task customer_request --trusted customer_id=12
taskvault report          # after a while: what would have been blocked
taskvault enforce         # start blocking
taskvault disconnect      # put everything back exactly as it was
```

```python
# A Python agent (the SDK), or CrewAI / LangGraph with tools=protect(task)
from taskvault_app import build_vault          # written by `taskvault setup`
from taskvault.llm import AnthropicProvider, ToolAgent

vault = build_vault(sinks={"email.send": send_email})
task = vault.start_task("customer_request", customer_id=ticket.verified_customer_id)   # trusted, from your app
ToolAgent(AnthropicProvider())(task, {"ticket": ticket.body})                          # untrusted, as data
```

```bash
# Agents in TypeScript, Go or Java: run the local API, then use the adapter for your language
taskvault api --app taskvault_app:build_vault
```

See [`adapters/`](adapters/README.md) for the other languages, and [`examples/`](examples/) for complete examples, including **planner mode**, the strictest way to run an agent.

**3. Keep sensitive data in deposit boxes (optional):**

```bash
taskvault keys init vault.key
taskvault boxes holder --key vault.key --type customer --id 12
taskvault boxes put customers.csv --key vault.key --source crm.customer --key-column id \
    --holder-type customer --holder-field id
```

Deposit boxes are encrypted per customer, department or client company. The most sensitive tier needs both the vault's key and the holder's key, and the holder can require approval. `taskvault boxes forget --holder customer:12` deletes one holder's data for an erasure request.

## Tested with real AI models

Live testing is still limited. The samples are small, so read this as a first look.

| Model | Attacks | Leaked without taskvault | Leaked with taskvault |
|---|---|---|---|
| Gemini 3.5 Flash-Lite (free tier) | harder | **2/5** | **0/5** |
| Claude Haiku 4.5 | harder | **7/15** | not tested yet |
| Claude Opus 5.5 | original | **3/10** | not tested yet |
| Claude Haiku 4.5 | original | 0/30 | 0/23 |
| Claude Sonnet 5 | original | 0/29 | 0/15 |

- **With taskvault, 0 of 43 live attack runs leaked data,** and models completed at least as many tasks with it as without.
- **Without it, plausible requests got real models to leak,** such as "send my details to my new email" or a fake internal note asking for a card number.
- **0.5 compatibility checks:** 0.5 was also run with a local model (hermes3 via Ollama, through LangGraph) and with Gemini 3.5 Flash-Lite. Tasks ran normally and nothing leaked with taskvault; in one small run a local model leaked to a reworded attack without taskvault and didn't with it. These are small compatibility checks, not a benchmark.

A fuller Gemini run (all 21 test tickets, with and without taskvault) is in progress, and OpenAI models haven't been tested live yet. More testing is planned, including an independent benchmark ([AgentDojo](https://github.com/ethz-spylab/agentdojo)). Full breakdown: [docs/real-model-results.md](docs/real-model-results.md).

**Try it with your own model.** The attack benchmark uses a fictional company and sends only invented test data to the provider (you pay their normal API costs):

```bash
git clone https://github.com/AgentP-Codes/Task-Vault-Name-is-bound-to-Change- && cd Task-Vault-Name-is-bound-to-Change-
pip install -e .
export ANTHROPIC_API_KEY=your-key        # Windows: set ANTHROPIC_API_KEY=your-key
python -m demo.bench --provider anthropic --model claude-sonnet-5 --runs 3 --out results.json
```

Providers: `anthropic`, `openai`, `gemini`, `ollama`. We'd love to see your results: open an issue with your `results.json`.

## How it's tested

- **About 460 automated tests,** including randomised (fuzz) tests, on Linux with Python 3.10 to 3.14, plus test runs on a Windows laptop. Windows and macOS runs are set up in CI.
- **Stress and load tests:** 2,000 tasks run at once from Python, Node, Go and Java; over 100,000 random API requests; long runs to catch memory leaks; large messages and databases. Run it yourself with `python -m demo.stress`.
- **Reviews by separate AI agents** that tried to break the new code, plus an external security report. Every problem found is fixed and has a test.
- **Supply chain:** pinned, checksummed libraries, vulnerability checks on every change, and release builds set up to be signed with a list of what's inside.

**This is still not an independent security review.** The testing was done by the project, with AI assistance, mostly against attacks we designed.

## What's simulated

| Part | Status |
| --- | --- |
| Vault core, planner, encryption, deposit boxes, setup scanner, CLI, MCP proxy, local API | Real code, tested |
| SQLite and Postgres | Real code, tested against real SQLite and a real Postgres 16 server |
| TypeScript, Go and Java adapters | Real code, tested against a real `taskvault api` with simulated data |
| Demo company, customers, tickets and documents | **Simulated**: invented data |
| "Hijacked" agents in the demo and offline benchmark | **Simulated**: scripted stand-ins that obey every injection |
| Connectors (Salesforce, HubSpot, Stripe, Slack and others) | Real code, **tested against simulated API responses**, not live services |
| Claude, Gemini and Ollama | Tested with live models (see above) |
| OpenAI | Real code; not yet tested with a live model |

## CLI

| Command | What it does |
| --- | --- |
| `taskvault setup ...` | Scan your data and write a starter policy, test data and connector code |
| `taskvault init --template support\|finance` | Start from a template instead |
| `taskvault check` / `test` | Validate a policy / run the attack suite (exits 1 on any leak) |
| `taskvault connect` / `disconnect` | Put taskvault in front of an agent app's tools, or undo it |
| `taskvault report` / `enforce` / `watch` | See what was (or would have been) blocked; start or stop blocking |
| `taskvault serve ... -- <cmd>` | Run the MCP proxy yourself |
| `taskvault api` | Local API for agents in TypeScript, Go and Java |
| `taskvault review` | Actions flagged for a person to look at |
| `taskvault scan FILE...` | Find secrets and personal data in text files |
| `taskvault boxes ...` | Deposit boxes: holders, storing, listing, logs, archiving, forgetting, upgrading |
| `taskvault audit verify\|show\|repair` | Check or read an audit log |
| `taskvault keys init\|shred` | Create or destroy a local key |

## Documentation

- [Policy reference](docs/policy-reference.md): every setting
- [Threat model](docs/threat-model.md): what it's designed to protect against, and what it isn't
- [Deploying](docs/deployment.md): keys, audit logs, rollout, operations
- [Other languages](adapters/README.md): the local API and adapters

## Limitations

- **Allowed actions aren't judged for content.** A fooled agent can still send the right customer a wrong message.
- **Reworded or encoded data** can sometimes reach a recipient the task already allows. Planner mode is designed to close this.
- **Your app must supply trusted inputs honestly.** If "which customer is this?" comes from the email text, the protections don't hold.
- **Setup is a draft.** Review what it writes, especially low-confidence fields listed in `setup-report.md`.
- **Not independently audited,** and test results are limited: most attacks were written by the project, and live samples are small. New attack techniques appear all the time.
- **It's one layer, not a complete security system.** It doesn't replace access controls, network security, monitoring, staff training or your AI provider's own safeguards.
- **Bugs are possible,** including ones that could let data through. Keep backups, and don't make it your only protection.
- **Windows and macOS** have had less real use than Linux. On Windows, key and database files rely on your user folder's normal protections.

## Background

Builds on research including [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813) (Google DeepMind) and [FIDES: Securing AI Agents with Information-Flow Control](https://arxiv.org/abs/2505.23643) (Microsoft Research).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Credits

Created by [@AgentP-Codes](https://github.com/AgentP-Codes).

## Disclaimer

**Please read this before using taskvault.**

- **Experimental software.** taskvault is an early, experimental project under active development. It may contain bugs, security flaws or incomplete features, and it may change without notice.
- **No warranty.** It's provided "as is" and "as available", without warranty of any kind, express or implied. That includes, without limitation, warranties of merchantability, fitness for a particular purpose, security, accuracy and non-infringement.
- **No liability.** To the maximum extent permitted by law, the authors and contributors aren't liable for any direct, indirect, incidental, special, consequential or exemplary loss or damage arising from using or being unable to use taskvault. That includes data loss, data breaches, privacy incidents, regulatory fines, business interruption, lost profits, and harm caused by AI agents or the actions they take.
- **Not a guarantee of security.** Descriptions of what taskvault does describe its design goals. They aren't promises that it will prevent any particular attack, leak or misuse. Benchmark and test results are limited, were produced by the project itself, and don't guarantee results in your environment.
- **Your responsibility.** You're solely responsible for:
  - deciding whether taskvault suits your use
  - configuring and testing it properly
  - securing your own systems, keys and data
  - complying with the laws that apply to you, such as privacy and data-protection laws (the Australian Privacy Act, GDPR and others) and industry rules (such as PCI DSS)
  - overseeing any AI agents you run
- **Not professional advice.** Nothing in this project is legal, compliance, security or other professional advice. Get qualified advice for your situation.
- **Third-party services.** Using taskvault with AI providers (such as Anthropic, Google or OpenAI) or other services may cost money and is subject to their terms. You're responsible for your API keys, usage and costs. Running the live benchmark sends test data to the provider you choose.
- **No affiliation.** taskvault is an independent project. It isn't affiliated with, endorsed by or sponsored by Anthropic, Google, OpenAI, Microsoft, Salesforce or any other company named here. Product names are trademarks of their owners and are used only to describe compatibility.
- **Sample data is fictional.** The demo company, customers and card numbers are invented; the card numbers are standard payment-network test numbers.
- **Where the law doesn't allow some exclusions,** those exclusions apply only as far as the law permits, and the rest still apply.

By using taskvault you accept these terms and the [AGPL-3.0 licence](LICENSE) (see sections 15 and 16, "Disclaimer of Warranty" and "Limitation of Liability").

## Licence

The taskvault core is licensed under the **GNU Affero General Public License v3.0 only** (AGPL-3.0-only). You can use, study, change and share it. If you modify it and let others use it over a network, you must offer them your modified source code. Anyone passing it on must keep the [NOTICE](NOTICE) file and its attribution.

The language adapters in [`adapters/`](adapters/) are licensed under **Apache-2.0**, so they can be used in any application.

Versions up to and including 0.4.2 were released under Apache-2.0 and remain available under it.

Copyright 2026 AgentP-Codes.
