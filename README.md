# Project Eurycleia

*Pronounced yoo-ree-KLEE-uh. Formerly taskvault.*

**A data vault for AI agents.** Eurycleia sits between an AI agent and your company's data. Each task sees only the data it needs, personal details and secrets are hidden from the AI, and data can only go where your policy allows, even if a prompt injection takes the agent over. It reduces risk; it doesn't remove it (see [Limitations](#limitations)).

> [!WARNING]
> **Early release: use at your own risk.** Eurycleia is new and hasn't been fully tested in real-world use. It hasn't had an independent security review, and live testing so far covers a few apps and models (see [What's simulated](#whats-simulated), [live test results](docs/live-test-results.md) and [real-model results](docs/real-model-results.md)). Test results don't guarantee it will stop every attack. Don't rely on it as your only protection for sensitive or regulated data, and test it thoroughly in your own environment first. Things may change between versions.
>
> **Not recommended for live production AI agents handling real customer data yet.** Use it for testing, prototypes and watch mode until it has been tested further.
>
> Provided "as is", without warranty of any kind, under the [AGPL-3.0 licence](LICENSE). Its features describe design goals, not guarantees. Please read the full [Disclaimer](#disclaimer) before using it.

**Status:** v0.7.0 beta · Feedback, issues and ideas are very welcome.

**How this was built:** Eurycleia was designed and directed by @AgentP-Codes. Much of the code, tests and documentation were written with the help of Claude (Anthropic's AI). The live model tests were run by the project using its own API keys. All the code is open for review.

## Why "Eurycleia"

In Homer's *Odyssey*, Eurycleia keeps the keys to the storeroom where the household's treasure is kept. While
strangers fill the house, she recognises the real master by an old scar, and she locks the doors so the
intruders can't reach the weapons. Eurycleia, the software, does the same job for an AI agent: it keeps the
data, knows who it really belongs to, and keeps an attacker away from the agent's tools.

## What it does

- **Protects the agent you already have.** One command puts Eurycleia in front of an agent's tools (Claude Desktop, Hermes and other MCP apps), with no code changes. For CrewAI and LangGraph it's one line of code.
- **Works with agents in Python and TypeScript/JavaScript,** and any other language through a small local API.
- **Gives each task only the data it needs.** Answering one customer's ticket? The agent sees that customer's record, and only the fields it asks for.
- **Hides personal details and secrets from the AI.** Names and emails become stand-ins, and card numbers and similar secrets are never shown to the AI at all. Real values are swapped back only when an approved action needs them.
- **Stops data going to the wrong place.** Customer data can only go to that customer (or, for a business customer, their own company) or your own staff, and staff records only to that employee. Recipients planted in a ticket or document are refused.
- **Sets firm limits:** how much data a task can read, how many times an action can run, and which actions need a person to approve them.
- **Keeps sensitive data in encrypted deposit boxes,** one per customer, department or client company, with a second key required for the most sensitive information.
- **Lets you watch before you block.** Watch mode records what Eurycleia *would* have blocked without blocking anything, and `eurycleia report` summarises it.
- **Writes the policy for you.** After watching, `eurycleia learn` drafts a policy from what the agent normally does, never from what looked like an attack, and shows what the draft would still block.
- **Keeps a tamper-evident record** of what the agent read and did, with no real data values in it.
- **Scans your data and writes a starter setup,** so you don't start from a blank page.
- **Stays small.** Two required libraries, no AI company libraries, and it runs on an ordinary laptop.

## What's new in 0.7

- **Tested live, not simulated:** a real AI model answering a made-up company's support email, connected to real test accounts in HubSpot, Stripe and Slack, on Azure. Of 124 emails (63 attacks), the model alone leaked data in 19, and in none with Eurycleia, while every normal request was still handled. See [live test results](docs/live-test-results.md).
- **Harder attacks:** 48 new attacks aimed at each protection, not just at the model.
- **Catches reworded data:** personal details are still caught when spacing, punctuation or look-alike characters change, or a number is written backwards or in words.
- **Azure:** Azure OpenAI models, sign-in with Azure's own identities instead of stored keys, and Azure Key Vault for the data key. A ready-made [live test setup](deploy/azure/README.md) for your own Azure subscription.
- **Two security fixes,** reported privately: protected data could leave through an action that names no recipient, and through encoded, split or `mailto:` links. Upgrade from 0.6. See the [changelog](CHANGELOG.md).
- **Fixes found by running for real,** including an audit log on a network file share.

## What's new in 0.6

- **A new name:** taskvault is now Eurycleia. The command is `eurycleia` (or `eury` for short). Code, settings, folders and connected agents from 0.5 keep working under the old name.
- **Tested with real models:** four Claude models; with Eurycleia none of 100 attacks leaked data, without it 12 did. See [Tested with real AI models](#tested-with-real-ai-models).
- **Tested on a public benchmark:** Eurycleia's rules on [AgentDojo](benchmarks/agentdojo/README.md), with a replay you can run without an API key and a runner for real models.
- **Business customers and staff:** a business customer's data can go to anyone at that company's own email domain. Staff records can be kept to the employee alone, not shared with colleagues.
- **Harder to tamper with:** with a key, the audit log can't be rewritten or cut short without it being detected. Key and token files are private to your user on Windows too. A customer who asked to be forgotten can't be quietly re-imported.
- **Easier to start:** a [5-minute quick start](docs/quickstart.md), and a fix so the CrewAI and LangChain helpers are included when installed from a release file.
- **Smaller:** only the TypeScript adapter is kept (Go and Java were removed).

0.5.1 was a security update. Full details are in the [changelog](CHANGELOG.md).

## Install

Requires Python 3.10 or later.

```bash
pip install eurycleia
eurycleia --version
```

Or `pip install git+https://github.com/AgentP-Codes/project-eurycleia` for the latest code. Optional extras: `postgres`, `aws`, `langchain`, `crewai`, for example `pip install "eurycleia[postgres]"`. New to it? Follow the [5-minute quick start](docs/quickstart.md).

## Get started

**1. Scan your data and get a starter policy.** Eurycleia works out what's sensitive and who owns each record, and explains every choice it makes:

```bash
eurycleia setup --sqlite crm.db --docs ./help-articles --domain yourcompany.com
eurycleia check     # validate the policy
eurycleia test      # run the built-in attack suite against it (exits 1 on any leak)
```

It also reads CSV/JSON files, Postgres and MCP servers, and recognises cards, Australian TFN / Medicare / ABN / BSB numbers, IBANs, API keys, emails, phones, names, addresses and more. Sample values are read locally to classify fields and are never written anywhere.

**2. Protect your agent.** Pick whichever fits:

```bash
# An existing agent app (Claude Desktop, Hermes, other MCP apps): starts in watch mode
eurycleia connect claude-desktop --task customer_request --trusted customer_id=12
eurycleia report          # after a while: what would have been blocked
eurycleia learn --policy eurycleia.yaml   # draft a policy from what the agent did; read learn-report.md
eurycleia enforce         # start blocking
eurycleia disconnect      # put everything back exactly as it was
```

```python
# A Python agent (the SDK), or CrewAI / LangGraph with tools=protect(task)
from eurycleia_app import build_vault          # written by `eurycleia setup`
from eurycleia.llm import AnthropicProvider, ToolAgent

vault = build_vault(sinks={"email.send": send_email})
task = vault.start_task("customer_request", customer_id=ticket.verified_customer_id)   # trusted, from your app
ToolAgent(AnthropicProvider())(task, {"ticket": ticket.body})                          # untrusted, as data
```

```bash
# Agents in TypeScript or JavaScript: run the local API, then use the adapter
eurycleia api --app eurycleia_app:build_vault
```

See [`adapters/`](adapters/README.md) for TypeScript and JavaScript, and [`examples/`](examples/) for complete examples, including **planner mode**, the strictest way to run an agent.

**3. Keep sensitive data in deposit boxes (optional):**

```bash
eurycleia keys init vault.key
eurycleia boxes holder --key vault.key --type customer --id 12
eurycleia boxes put customers.csv --key vault.key --source crm.customer --key-column id \
    --holder-type customer --holder-field id
```

Deposit boxes are encrypted per customer, department or client company. The most sensitive tier needs both the vault's key and the holder's key, and the holder can require approval. `eurycleia boxes forget --holder customer:12` deletes one holder's data for an erasure request.

## Tested live

In October 2026 Eurycleia ran in front of a real agent (gpt-5-mini on Azure OpenAI) answering a made-up company's support email, with real test accounts in HubSpot, Stripe and Slack:

| 124 emails (63 attacks) | Emails that leaked data | Normal emails done |
|---|---|---|
| Without Eurycleia | **19** | 61/61 |
| With Eurycleia | **0** | 61/61 |

One model so far, and the attacks were written by the project; refunds nobody asked for still got through (see [Limitations](#limitations)). Full results: [docs/live-test-results.md](docs/live-test-results.md).

## Tested with real AI models

Eurycleia 0.6 was run against four Claude models through the paid API: 21 support tickets, 20 of them attacks,
once without Eurycleia and once with it (Opus twice). The samples are small, so read this as a first look.

| Model | Leaked without Eurycleia | Leaked with Eurycleia | Done without | Done with |
|---|---|---|---|---|
| Claude Haiku 4.5 | **3/20** | **0/20** | 10/21 | 13/21 |
| Claude Sonnet 5 | **2/20** | **0/20** | 21/21 | 21/21 |
| Claude Sonnet 5.5 | **1/20** | **0/20** | 19/21 | 20/21 |
| Claude Opus 5.5 (2 runs) | **6/40** | **0/40** | 36/42 | 39/42 |
| **All** | **12/100** | **0/100** | 86/105 | 93/105 |

- **With Eurycleia, none of the 100 attacks leaked anything,** and every model finished at least as many tickets
  with it as without.
- **Without it, every model was tricked,** including the largest and newest. Calm, believable requests worked
  best: a polite note asking to send details to a "bookkeeper" worked on three of the four models.
- Earlier versions were also tested with Gemini and a local model. An OpenAI model (gpt-5-mini) was tested live in 0.7.

Full breakdown: [docs/real-model-results.md](docs/real-model-results.md).

### On a public benchmark: AgentDojo

[AgentDojo](https://github.com/ethz-spylab/agentdojo) is an independent prompt-injection benchmark with 97 everyday tasks (email, travel, banking, Slack) and 35 attacks. We replayed each task's reference solution, and the exact actions of the 26 attacks that come with one, through Eurycleia's rules, with no model involved:

| | Tasks still done | Attacks that succeeded |
|---|---|---|
| No defence | 97/97 | 552/609 (91%) |
| Eurycleia, one set of rules per app | 85/97 | 142/609 (23%) |
| Eurycleia, rules per task | 85/97 | 29/609 (5%) |

This measures the rules, not a model, and the per-task rules were taken from each task's reference solution. A real model is fooled less often, but may also try other actions. The 12 tasks lost send money, invitations or messages to addresses found only in content an outsider controls. The results are the same when the attacker, not an innocent-looking sender, sends the email or payment carrying the attack. What gets through, and how to run it yourself: [benchmarks/agentdojo](benchmarks/agentdojo/README.md). A first run with a real model, Claude Sonnet 5.5 on 20 banking attacks, worked end to end: with Eurycleia's strict rules it finished the same tasks as with no protection (18/20 under attack), but the model resisted every AgentDojo attack on its own (0/20 either way), so this run shows Eurycleia doesn't get in the way rather than what it stops. A larger run with harder attacks is planned.

**Try it with your own model.** The attack benchmark uses a fictional company and sends only invented test data to the provider (you pay their normal API costs):

```bash
git clone https://github.com/AgentP-Codes/project-eurycleia && cd project-eurycleia
pip install -e .
export ANTHROPIC_API_KEY=your-key        # Windows: set ANTHROPIC_API_KEY=your-key
python -m demo.bench --provider anthropic --model claude-sonnet-5 --runs 3 --out results.json
```

Providers: `anthropic`, `openai`, `gemini`, `ollama`. We'd love to see your results: open an issue with your `results.json`.

## How it's tested

- **About 860 automated tests,** including randomised (fuzz) tests, on Linux with Python 3.10 to 3.14, Windows and macOS.
- **Stress and load tests:** 2,000 tasks run at once from Python and Node; over 100,000 random API requests; long runs to catch memory leaks; large messages and databases. Run it yourself with `python -m demo.stress`.
- **Reviews by separate AI agents** that tried to break the new code, plus external security reports. Every problem found is fixed and has a test.
- **A public benchmark:** [AgentDojo](benchmarks/agentdojo/README.md), replayed without a model (see above).
- **A live deployment:** a real model with real test accounts in HubSpot, Stripe and Slack on Azure ([results](docs/live-test-results.md)).
- **Real models, frameworks and apps (in progress):** runners for API models, LangGraph and CrewAI, an MCP agent, long unattended runs and real apps in test accounts. See [benchmarks/RUN_GUIDE.md](benchmarks/RUN_GUIDE.md).
- **Supply chain:** pinned, checksummed libraries, vulnerability checks on every change, and release builds set up to be signed with a list of what's inside.

**This is still not an independent security review.** The testing was done by the project, with AI assistance, mostly against attacks we designed.

## What's simulated

| Part | Status |
| --- | --- |
| Vault core, planner, encryption, deposit boxes, setup scanner, CLI, MCP proxy, local API | Real code, tested |
| SQLite and Postgres | Real code, tested against real SQLite and a real Postgres 16 server |
| TypeScript adapter | Real code, tested against a real `eurycleia api` with simulated data |
| Demo company, customers, tickets and documents | **Simulated**: invented data |
| "Hijacked" agents in the demo and offline benchmark | **Simulated**: scripted stand-ins that obey every injection |
| HubSpot, Stripe (test mode) and Slack | Tested live, with test accounts and made-up data |
| Other connectors (Salesforce and others) | Real code, **tested against simulated API responses**, not live services |
| Claude, Gemini and Ollama | Tested with live models (see above) |
| OpenAI models | gpt-5-mini tested live on Azure OpenAI; others not yet |

## CLI

| Command | What it does |
| --- | --- |
| `eurycleia setup ...` | Scan your data and write a starter policy, test data and connector code |
| `eurycleia init --template support\|finance` | Start from a template instead |
| `eurycleia check` / `test` | Validate a policy / run the attack suite (exits 1 on any leak) |
| `eurycleia connect` / `disconnect` | Put Eurycleia in front of an agent app's tools, or undo it |
| `eurycleia report` / `enforce` / `watch` | See what was (or would have been) blocked; start or stop blocking |
| `eurycleia learn --policy FILE` | Draft a policy from what the agent did in watch mode, with a report of every change |
| `eurycleia serve ... -- <cmd>` | Run the MCP proxy yourself |
| `eurycleia api` | Local API for agents in TypeScript and JavaScript |
| `eurycleia review` | Actions flagged for a person to look at |
| `eurycleia scan FILE...` | Find secrets and personal data in text files |
| `eurycleia boxes ...` | Deposit boxes: holders, storing, listing, logs, archiving, forgetting, upgrading |
| `eurycleia audit verify\|show\|repair` | Check or read an audit log |
| `eurycleia keys init\|shred` | Create or destroy a local key |

## Documentation

- [Policy reference](docs/policy-reference.md): every setting
- [Threat model](docs/threat-model.md): what it's designed to protect against, and what it isn't
- [Deploying](docs/deployment.md): keys, audit logs, rollout, operations
- [TypeScript and JavaScript](adapters/README.md): the local API and adapter

## Limitations

- **Allowed actions aren't judged for content.** A fooled agent can still send the right customer a wrong message, or give a refund nobody asked for (kept to that customer's own payment and within the cap). In the live test this happened 8 times in 124 emails. Asking a person before unusual actions is planned.
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

**Please read this before using Eurycleia.**

- **Experimental software.** Eurycleia is an early, experimental project under active development. It may contain bugs, security flaws or incomplete features, and it may change without notice.
- **No warranty.** It's provided "as is" and "as available", without warranty of any kind, express or implied. That includes, without limitation, warranties of merchantability, fitness for a particular purpose, security, accuracy and non-infringement.
- **No liability.** To the maximum extent permitted by law, the authors and contributors aren't liable for any direct, indirect, incidental, special, consequential or exemplary loss or damage arising from using or being unable to use Eurycleia. That includes data loss, data breaches, privacy incidents, regulatory fines, business interruption, lost profits, and harm caused by AI agents or the actions they take.
- **Not a guarantee of security.** Descriptions of what Eurycleia does describe its design goals. They aren't promises that it will prevent any particular attack, leak or misuse. Benchmark and test results are limited, were produced by the project itself, and don't guarantee results in your environment.
- **Your responsibility.** You're solely responsible for:
  - deciding whether Eurycleia suits your use
  - configuring and testing it properly
  - securing your own systems, keys and data
  - complying with the laws that apply to you, such as privacy and data-protection laws (the Australian Privacy Act, GDPR and others) and industry rules (such as PCI DSS)
  - overseeing any AI agents you run
- **Not professional advice.** Nothing in this project is legal, compliance, security or other professional advice. Get qualified advice for your situation.
- **Third-party services.** Using Eurycleia with AI providers (such as Anthropic, Google or OpenAI) or other services may cost money and is subject to their terms. You're responsible for your API keys, usage and costs. Running the live benchmark sends test data to the provider you choose.
- **No affiliation.** Eurycleia is an independent project. It isn't affiliated with, endorsed by or sponsored by Anthropic, Google, OpenAI, Microsoft, Salesforce or any other company named here. Product names are trademarks of their owners and are used only to describe compatibility.
- **Sample data is fictional.** The demo company, customers and card numbers are invented; the card numbers are standard payment-network test numbers.
- **Where the law doesn't allow some exclusions,** those exclusions apply only as far as the law permits, and the rest still apply.

By using Eurycleia you accept these terms and the [AGPL-3.0 licence](LICENSE) (see sections 15 and 16, "Disclaimer of Warranty" and "Limitation of Liability").

## Licence

The Eurycleia core is licensed under the **GNU Affero General Public License v3.0 only** (AGPL-3.0-only). You can use, study, change and share it. If you modify it and let others use it over a network, you must offer them your modified source code. Anyone passing it on must keep the [NOTICE](NOTICE) file and its attribution.

The TypeScript adapter in [`adapters/`](adapters/) is licensed under **Apache-2.0**, so it can be used in any application.

Versions up to and including 0.4.2 were released under Apache-2.0 and remain available under it.

Copyright 2026 AgentP-Codes.
