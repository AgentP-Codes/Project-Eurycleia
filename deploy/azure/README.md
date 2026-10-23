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
