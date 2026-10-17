# Quick start (about 5 minutes)

You need Python 3.10 or newer.

## 1. Install

```bash
pip install https://github.com/AgentP-Codes/project-eurycleia/releases/download/v0.6.0/eurycleia-0.6.0-py3-none-any.whl
```

This installs the release file from GitHub; Eurycleia isn't on PyPI yet. It adds two small libraries, `pyyaml` and `cryptography`, and no AI company libraries.

## 2. Make a policy and attack it

```bash
mkdir my-vault && cd my-vault
eurycleia init --template support     # or: --template finance
eurycleia test
```

`eurycleia.yaml` is the policy: what each task may read, what the AI may see, and where data may go. Every choice has a comment. `eurycleia test` runs 19 made-up attacks against it and should end with `19 blocked, 0 leaked`.

## 3. Run your first task

Save [`examples/first_task.py`](../examples/first_task.py) next to `eurycleia.yaml` and run it:

```bash
python first_task.py
```

```text
the model sees: {'name': 'Priya Shah', 'email': 'priya@example.com', 'plan': 'Pro', 'card_number': '[[vault:card_number:681b45c2]]'}
blocked: recipient 'attacker@evil.example' did not come from trusted data
emails sent to: ['priya@example.com']
```

The model gets a placeholder instead of the card. Email to the customer goes out; email to anyone else is refused, however the model was talked into it.

## 4. Put it in front of your agent

If your agent uses MCP tools (Claude Desktop, Hermes, or any `mcpServers` settings file):

```bash
eurycleia connect claude-desktop --task support_reply --trusted customer_id=12
```

It starts in **watch mode**: nothing is blocked, and everything that *would* have been blocked is logged. After a while:

```bash
eurycleia report        # what would have been blocked
eurycleia learn --policy eurycleia.yaml   # draft a policy from what the agent did
eurycleia enforce       # start blocking
eurycleia disconnect    # put the original settings back exactly
```

For agents in Python code (LangChain, CrewAI, your own loop), see [`examples/support_agent.py`](../examples/support_agent.py). For TypeScript, see [`adapters/`](../adapters/README.md).

## Next

- Map your own data: `eurycleia setup` scans a database or CSV and writes a first policy for you to review.
- Read [what Eurycleia protects and what it doesn't](threat-model.md) before using real data.
- [Policy reference](policy-reference.md) and [deployment checklist](deployment.md).
