# The live test on Azure

A real support agent for **Bramblecove Supply Co., a made-up company**, protected by Eurycleia. It answers real
emails in a test Gmail inbox, uses HubSpot, Stripe (test mode) and Slack, and runs on an AI model in your own
Azure subscription. Only the company and its data are made up. See [deploy/live](../live) for the agent itself.

## What runs where

| Part | Where |
|---|---|
| The agent | an Azure Container Apps job that starts every 5 minutes, handles new emails and stops (you pay only while it runs) |
| The AI model | your Foundry / Azure OpenAI deployment |
| Passwords and tokens | Azure Key Vault. The agent signs in with its own Azure identity: no password is stored in the app |
| Results, audit log, daily reports | an Azure file share |
| The code | the image `ghcr.io/agentp-codes/eurycleia-live`, built by GitHub from this repository (private if the repository is) |

## Safety limits (whatever the agent or Eurycleia does)

- Email goes only to addresses on your test inbox (`you.test+anything@gmail.com`); nothing else is sent.
- Slack posts go only to your two test channels. Refunds go only to the test's own payments in Stripe **test
  mode**, at most A$200; live Stripe keys are refused.
- A daily spending limit on the model (A$2 by default), and a kill switch: `./setup.sh pause`.

## Setting it up (Azure Cloud Shell, Bash)

You need: a HubSpot service key, a Stripe `sk_test_` key, a Slack bot token and two channel ids, a model
deployment in Foundry, and a test Gmail address. A Gmail app password is optional: without one the test runs in
**no-email mode**, where the made-up emails go to the agent through a folder on the storage share (`mail/new`) and
its replies are recorded in `mail/sent.jsonl` instead of being emailed. Everything else is the same, including the
leak check. Add the app password later with `./setup.sh secrets` and the next run uses Gmail.

Get this folder (`deploy/azure`) into Cloud Shell: `git clone` the repository, or, for a private repository,
zip the folder and use Cloud Shell's **Upload** button, then `unzip azure.zip`. For a private repository, also set
`IMAGE_TOKEN_USER` and make a GitHub token with only **read:packages** (setup.sh asks for it).

```bash
cd azure                     # or Project-Eurycleia/deploy/azure after a git clone
cp settings.example.env settings.env
nano settings.env            # fill it in, then Ctrl+O, Enter, Ctrl+X
chmod +x setup.sh
./setup.sh all               # asks for each secret (nothing shows as you type)
./setup.sh seed              # loads the made-up customers into HubSpot and Stripe
./setup.sh resume            # the agent starts PAUSED; this turns it on (watch mode: logs, doesn't block)
./setup.sh feed 5            # sends 5 made-up support emails
./setup.sh status
```

The first runs are in **watch mode**: Eurycleia records what it would block. When that looks right,
`./setup.sh enforce` switches blocking on. Each test email is also handled once without Eurycleia, so every
attack gets a with/without result. Results: the daily report in Slack, or `results.jsonl` in the file share.

When you're finished: `./setup.sh remove` deletes the resource group and everything in it, including the model.
Then delete the HubSpot key, the Stripe key, the Slack app and the Gmail app password.

## Other models

The agent uses the Azure OpenAI deployment by default. To test another provider's model, store its API key (it goes
straight into Key Vault) and switch the agent's model; results record which model handled each email.

    ./setup.sh key openai                          # asks for the key; nothing appears on screen
    ./setup.sh model openai MODEL-NAME             # add PRICE_IN PRICE_OUT (US$ per million tokens) if it's new
    ./setup.sh budget 5                            # daily model budget in A$
    ./setup.sh model azure gpt-5-mini              # back to the Azure deployment

That provider bills you directly; it isn't paid from your Azure credit.

## Approving refunds

Every refund waits for a person's yes. By default the agent posts each one in the report channel with what
Eurycleia knows about it (whose payment, how much, whether it came from trusted data) and waits for a reaction:
:white_check_mark: approves, :x: refuses, and no answer within two minutes refuses.

- Give the Slack app the **reactions:read** scope as well as chat:write (Slack app settings, OAuth & Permissions,
  then reinstall the app to the workspace).
- `./setup.sh approver slack 300 U0123ABC` waits five minutes and counts only that Slack user's reactions (your
  member id is in your Slack profile, under the three dots).
- For a long unattended round, `./setup.sh approver simulated` uses a stand-in reviewer that approves only genuine
  duplicate-charge refunds. Results record which approver was used, so simulated approvals are never mistaken
  for a person's.

## Live demo page

    ./setup.sh demo          # prints the page's address
    ./setup.sh demo off      # takes it down

A public web page that shows the test as it runs: each email as it arrives, what the AI did with and without
Eurycleia, what was blocked and why, refunds waiting for approval, and running totals. It's served from your
storage account's static website, and the agent updates it with its own identity, allowed to write that one
container only.

The page is public, so it only ever shows made-up data, and even then email addresses become the customer's id
or "an outside address", payment ids "a payment" and chat channels "the team channel". What the AI read is never
shown, only what it did.
