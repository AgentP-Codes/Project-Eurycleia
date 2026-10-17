# Threat model

Eurycleia assumes the model **will** be fooled sometimes. It doesn't try to detect prompt injection. It limits what a fooled agent can reach and where data can go, using deterministic checks outside the model.

> The properties below are what Eurycleia is **designed** to enforce. They aren't a warranty or a promise of security: the software is experimental, hasn't been independently audited, and may contain bugs. See the [Disclaimer](../README.md#disclaimer).

## What we protect

| Asset | Example |
| --- | --- |
| Customer data | Names, emails, phone numbers, addresses, account records |
| Secrets | Card numbers, bank account numbers, government IDs, credentials |
| Company data | Pricing, contracts, internal documents |
| Actions | Refunds, payments, emails, record updates |

## Attacker

Anyone who can put text in front of the agent: a customer email, a support ticket, a web page, a document, a tool description. We assume the attacker **fully controls the model's output** once their text is read. They know how Eurycleia works (open design). They do not control the host application, the policy file, the vault process, the customer's key, or the source systems.

## Trust boundaries

```
 trusted                                  untrusted
 ───────                                  ─────────
 your app (decides trusted inputs)        ticket / email / web text
 policy file (reviewed in PRs)            everything the model says
 vault process + customer key             tool descriptions from third parties
 source systems (CRM, ERP, drive)
```

Trusted inputs (e.g. "this task is for customer 12") must come from your app, typically from a verified sender or an authenticated session. **If your app derives trusted inputs from untrusted text, every guarantee below is void.**

## Designed protections

Assuming the vault and key store aren't compromised and the policy is correct:

| # | Protection | Tool mode (`Task`, MCP proxy) | Planner mode |
| --- | --- | --- | --- |
| 1 | A task reads only the records and fields its template allows, keyed from trusted inputs | ✅ | ✅ |
| 2 | Secret fields never enter the model's context (placeholders only) | ✅ | ✅ (including the quarantined extractor) |
| 3 | Secrets are only turned back into real values at sinks listed in `secrets_allowed` | ✅ | ✅ |
| 4 | Recipients must match `allowed_recipients`, resolved by the vault from trusted data | ✅ | ✅ |
| 5 | Protected data only reaches its owner (a person's address on file, or anyone at a business customer's own domain) or internal domains (unless the source sets `share_internally: false`) | ⚠️ value matching: exact values and document lines | ✅ by provenance: survives rewording and encoding |
| 6 | A recipient derived from untrusted content is rejected, even if it looks valid | ⚠️ only via rule 4 | ✅ |
| 7 | Sinks reject arguments not in their `args` list and calls beyond `max_calls`; limits and data budgets also hold when tool calls run in parallel | ✅ | ✅ |
| 8 | `approval: always` actions need a human yes; with no approver they fail closed | ✅ | ✅ |
| 9 | Every read, action, block and approval is in a hash-chained audit log with no raw sensitive values; with a key, rewriting it needs the key and cutting entries off the end is detected | ✅ | ✅ |
| 10 | Cached records and placeholder values are encrypted with the customer's key, and deposit boxes with the vault key (plus the holder's key for the high tier); destroying the key makes them unreadable | ✅ when a cipher is configured | ✅ |
| 11 | Fields listed in `pseudonymize` reach the model only as stand-ins; recipients and data checks run on the real values | ✅ | ✅ |
| 12 | Recipients are compared after normalisation; display-name tricks, header injection, hidden second recipients and look-alike characters are rejected (an address with non-ASCII letters only on an exact match with trusted data) | ✅ | ✅ |
| 13 | Deposit boxes: a high-tier box can't be opened without both the vault's key and the holder's key; one holder's key can't open another holder's box; every opening is in that box's own tamper-evident log | ✅ | ✅ |
| 14 | Customer data (protected or secret values the task has seen, placeholders, stand-ins) never leaves inside a link to a website outside `internal_domains` / `link_domains`, even in a message to the right person | ⚠️ value matching: exact and decoded values | ⚠️ same check (value matching) |

## Detection (helpful, never relied on)

These add oversight but aren't enforced protections: `detect_outbound` pattern matching, `risk: medium` flags, and the classifications `eurycleia setup` suggests.

## Not protected against (be honest with your users)

- **Content of allowed actions.** A fooled agent can still send the *right* customer a wrong, rude or misleading message. Review outbound content separately if that matters.
- **Tool mode, rule 5.** An agent that paraphrases, splits or encodes protected data can get it past value matching *to a recipient the task already allows*. Untrusted recipients are still blocked outright. Use planner mode where this matters.
- **Rule 14 is value matching too.** Links are checked for whole values (as written, decoded, or with spaces and punctuation dropped) and for two or more words of a multi-word value. One word on its own (a first name in a plain-text link, say) isn't caught, because ordinary links contain common words. Neither is data the agent has reworded or encoded in other ways.
- **Planner-mode conditions.** A `when:` condition derived from untrusted text lets that text decide *whether* a pre-approved action happens (one bit), not what it does. Conditions are logged.
- **Pseudonyms are consistent.** The same person gets the same stand-in across tasks, so a model (or its provider) can link activity to one pseudonymous person without learning who they are. Use a separate key per tenant to keep tenants unlinkable.
- **Deposit boxes while open.** Once a holder allows an opening, their key stays in the vault's memory for `open_ttl` seconds (default 300) so a task can finish. Keep it short, and call `close_all()` when a task ends.
- **Rolling the audit log back.** With a key, edits, rewrites and a shortened log are detected, but someone with file access who kept older copies of both the log and its `.head` file could restore them together. Someone who removes every MAC and the `.head` file can also make a keyed log look like an old one that was never keyed, so only `eurycleia audit seal` a log you know was never keyed. Ship the log elsewhere if that matters.
- **Box metadata.** Box ids, tiers, item counts and timings are visible to anyone with database access; holder names, field names and values are encrypted.
- **Side channels.** Timing, error messages and whether an action happened can leak small amounts of information.
- **Sinks without a recipient.** For sinks like webhooks the vault can't know who receives the data. `eurycleia check` warns about these; restrict them with `args` and don't send protected data to them.
- **Sinks that echo secrets in unusual ways.** Sink results are masked for real values in any case and spacing, as base64 and hex, and a second pass removes anything card- or account-shaped. A sink that returns a secret split across several fields, or otherwise transformed, can still get it to the model. Don't return secrets from sinks.
- **A compromised host, policy, vault or key.** Out of scope.
- **Availability.** A hostile ticket can make an agent do nothing useful. Scanning text takes time in proportion to its length (about a second per few hundred KB in the worst case), and the local API limits requests to 1 MB.

## Failure behaviour

| Situation | Behaviour |
| --- | --- |
| Rule violated (enforce mode) | Action blocked, `Blocked` raised, audit entry written |
| Rule violated (shadow mode) | Action allowed, `would_block` audit entry written |
| Approval needed, no approver | Blocked (fails closed) |
| Unknown source, sink or tool | Blocked |
| Key missing or revoked | Decryption fails; nothing is returned |
| Cache entry expired | Re-fetched from the source system |

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
