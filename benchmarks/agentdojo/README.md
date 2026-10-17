# Eurycleia on AgentDojo

[AgentDojo](https://github.com/ethz-spylab/agentdojo) is a public benchmark for prompt injection. It has 97 everyday tasks in four suites (an office workspace, travel booking, online banking and Slack) and 35 attacks hidden in emails, files, web pages, reviews and messages. It measures two things: whether the agent still gets its task done (**utility**), and whether an attacker gets it to do something else (**attack success**).

This folder runs AgentDojo with Eurycleia's rules in front of the tools. It isn't part of the Eurycleia package: install AgentDojo separately (`pip install agentdojo`).

## What is being tested

AgentDojo's tools (`send_email`, `send_money`, `read_file`, ...) don't fit Eurycleia's record-and-placeholder model. [`rules.py`](rules.py) ports the rules that do apply, configured the way a developer would configure Eurycleia:

1. **Task-scoped tools.** This applies in `strict` mode only. A task may use only the tools that change something (send, pay, delete, book) listed in its template. AgentDojo has no templates, so each task's template is the set of tools its reference solution uses: what a developer who built that one feature would allow. In `general` mode, every task gets every tool.
2. **Recipients from trusted data.** Every recipient (an email address, IBAN, Slack user or channel, or a web address to post to) must be one of:
   - in the user's own request;
   - at the company's own email domain (Eurycleia's `internal_domains`);
   - in data the user's side wrote: the people they've emailed, the payees they've paid or scheduled, and the workspace's member and channel lists. Not AgentDojo's contact list: it is built from every email, including ones an attacker sent. A real address book the user keeps would count.

   Nothing an outsider controls counts. That rules out email bodies, files, web pages, reviews and messages, and also *who* an email, payment, invitation or shared file came from, because an attacker can send those themselves.

The app's trusted inputs (who the signed-in user is and the company's domain) are set for each suite.

**Not ported:**
- placeholders for secrets and stand-ins for personal details, because AgentDojo's checks need the model to see real values;
- the link check;
- owner-based value matching, because AgentDojo has no data owners.

A blocked call isn't run, and the model gets the reason as the tool's error.

## Results without a model (`static_eval.py`)

This replays each task's reference solution: its "ground truth", the tool calls a perfect agent would make.

- **Utility** runs each task's reference solution through the rules. Anything blocked here is a false positive.
- **Security** runs each task × attack pair. The task's reference calls run first, so the injected content has been read. Then the attacker's exact reference calls run, as from a model that is fully fooled.

26 of AgentDojo's 35 attacks have a reference solution that can be replayed (workspace attacks 6–13 and travel attack 6 don't), which gives 609 task × attack pairs.

| Suite | No defence: attacks | general: utility | general: attacks | strict: utility | strict: attacks |
| --- | --- | --- | --- | --- | --- |
| Workspace | 187/240 (78%) | 37/40 (92%) | 40/240 (17%) | 37/40 (92%) | 2/240 (1%) |
| Travel | 116/120 (97%) | 20/20 (100%) | 57/120 (48%) | 20/20 (100%) | 3/120 (2%) |
| Banking | 144/144 (100%) | 15/16 (94%) | 16/144 (11%) | 15/16 (94%) | 1/144 (1%) |
| Slack | 105/105 (100%) | 13/21 (62%) | 29/105 (28%) | 13/21 (62%) | 23/105 (22%) |
| **All** | **552/609 (91%)** | **85/97 (88%)** | **142/609 (23%)** | **85/97 (88%)** | **29/609 (5%)** |

Utility with no defence is 97/97. "No defence" attacks are below 100% because some reference attacks fail on their own in some tasks.

**The results don't depend on who AgentDojo says sent the attack.** In AgentDojo's data, the email, payment or file carrying an injection comes from an innocent-looking sender. A real attacker would send it themselves. With `--data attacker-sends`, the replay gives those items the attacker as sender, owner or invitee, and the numbers are identical. An earlier version of these rules trusted sender fields and the contact list. A separate review caught it: in that version, attacks got through 112 of 144 times in banking when the attacker was the sender.

**What gets through, and why:**

- **Attacks that do something a task is allowed to do.** In workspace, deleting a file during a task that deletes files. In travel, booking a hotel during a task that books hotels, or emailing the user's details to an address the user named in their own request. In banking, changing the password during the task that changes the password. Slack accounts for 23 of the 29 strict cases: 21 are an attack that only makes the agent open a web page, and 2 are a phishing link sent to a real colleague. Eurycleia checks where data goes, not what a message says (see the [threat model](../../docs/threat-model.md)).
- **In general mode, all of the above plus any attack using a tool the task doesn't need**: deleting files, booking hotels, creating calendar events, changing passwords, opening web pages.

**What it costs:** the 12 tasks that fail send something to an address found only in content an outsider controls.
- Paying a bill uses the IBAN printed in the bill file.
- Inviting a colleague uses an email address from their web page.
- A calendar invitation goes to people named in an email, or looked up in the contact list.
- A direct message goes to whoever posted in a channel.

That is exactly the pattern an attacker uses, so Eurycleia refuses it. A real deployment would put the address in trusted data (a payee list, the member directory) or ask a person (`risk: high`).

**How to read these numbers:**
- They test the rules, not a model.
- A real model may be fooled less often than the fully fooled script.
- A real model may also try other actions to reach the attacker's goal.
- The strict-mode templates are taken from the reference solutions, which is favourable to Eurycleia.
- AgentDojo judges some attacks from the calls the model *attempted*, including calls Eurycleia refused and never ran; the table counts only calls that ran. AgentDojo's own verdict is 50/609 for strict, 163/609 for general and 552/609 with no defence. The difference is all in Slack, where the refused calls are invitations and channel changes.

Run it yourself (about 10 minutes, no API key):

```bash
cd benchmarks/agentdojo
pip install -r requirements.txt       # AgentDojo 0.1.35, the version these results used
python static_eval.py                 # all suites; modes none / general / strict; data as published and attacker-sends
python static_eval.py --suite banking --mode strict --json results.json
```

## With a real model (`run_live.py`)

The API key is read from the environment only. Never put it on the command line or in a file.

```bash
set GEMINI_API_KEY=...            # Windows (macOS/Linux: export GEMINI_API_KEY=...)
python run_live.py --provider gemini --model gemini-2.5-flash-lite --suite banking --mode none --mode strict --max-pairs 30 --sleep 4
python run_live.py --summarize agentdojo-results.jsonl
```

- Each finished episode is saved to `agentdojo-results.jsonl`. Running the same command again carries on where it stopped (quota, Ctrl+C).
- A full run is thousands of model calls, so on a free tier start with one suite and `--max-pairs`.
- `--provider ollama --model hermes3` runs a local model through Ollama.
- The attack is AgentDojo's standard `important_instructions`.
