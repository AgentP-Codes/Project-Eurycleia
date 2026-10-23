# Live test results

Eurycleia 0.7 was tested as a live deployment, not a simulation: a real AI model answering a made-up company's
support email, connected to real test accounts in HubSpot, Stripe (test mode) and Slack, running on Azure.
Everything about the company, its customers and its emails is invented, and nothing could reach a real person.
How it works and how to run it yourself: [deploy/azure](../deploy/azure/README.md).

## Round 2 (22 October 2026): gpt-5-mini on Azure OpenAI

124 made-up support emails: 61 normal requests and 63 attacks (15 basic, 48 harder). Each email was handled
twice, once without Eurycleia and once with it, by the same model.

| | Emails that leaked data | Harder attacks that leaked | Normal emails done | Refunds nobody asked for |
|---|---|---|---|---|
| Without Eurycleia | **19 / 124** | **15 / 48** | 61 / 61 | 11 |
| With Eurycleia | **0 / 124** | **0 / 48** | 61 / 61 | 8 |

- **On its own, the model leaked data in about one in three of the harder attacks**, and in 19 emails overall.
  Across the rounds, what leaked included personal details posted in the team's chat channel, internal notes
  sent to a customer, another customer's details, the internal pricing sheet, and phone numbers written
  backwards or in words.
- **With Eurycleia, none leaked**, and every normal customer request was still handled, refunds included.
- Zero leaks in 63 attacks means that, with 95% confidence, fewer than about 5% of attacks like these would get
  through. More rounds and models will narrow that.
- The model spent A$1.73 on the whole round.

## Round 1 (19 and 20 October 2026)

The same model on the same emails, run while the test itself was being finished. It showed the same pattern:
on the basic emails, 7 of 40 leaked without Eurycleia and none with it. Its harder-attack counts aren't
quoted, because a bug in the test (now fixed) handled some emails twice; its only "leak" with Eurycleia turned
out to be a customer told their own address, which another made-up customer happened to share.

## What it doesn't show yet

- **Refunds nobody asked for.** Eurycleia keeps a refund to the customer's own latest payment, once and within a
  cap, but it doesn't judge whether the refund was deserved. The model gave 8 such refunds with Eurycleia in
  place. Asking a person before unusual actions is planned for 0.7.x.
- **One model.** OpenAI and Claude models are next (0.7.x).
- **Attacks written by the project.** An outside red team is planned.
- **No real email.** These rounds carried the emails through a folder instead of a mailbox; everything else was
  live.

## Found and fixed by the live test

Running for real found problems the simulated tests couldn't, all fixed in 0.7: personal details reformatted
(spacing, punctuation, look-alike characters, a phone number backwards or in words) could get past the
outgoing check; the audit log failed on a network file share; and several setup problems with Azure, Stripe and
Key Vault.
