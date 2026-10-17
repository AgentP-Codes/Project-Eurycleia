# Changelog

## 0.6.0

**New name: Eurycleia**
- taskvault is now Eurycleia (`pip install` the `eurycleia` package, `import eurycleia`, command `eurycleia` or `eury` for short). The name is from the *Odyssey*: the keeper of the household's storeroom keys.
- Nothing set up with 0.5 breaks: `import taskvault`, `python -m taskvault` and the `taskvault` command still work, settings named `TASKVAULT_*`, the `~/.taskvault` folder, a `taskvault.yaml` policy and the `_meta.taskvault` MCP setting are still read when the new names aren't there, and agents connected by 0.5 are still recognised by `connect`, `enforce`, `watch` and `disconnect`. Encryption is unchanged, so existing deposit boxes and keyed audit logs open as before. The TypeScript adapter still exports `TaskVault`
- The local API's signature headers are now `x-eurycleia-*`: update the TypeScript adapter together with Eurycleia

**Tested with real models**
- Four Claude models through the paid API (Haiku 4.5, Sonnet 5, Sonnet 5.5, Opus 5.5 twice), 21 tickets with 20 attacks each: with Eurycleia 0 of 100 attacks leaked, without it 12 of 100. Every model finished at least as many tickets with Eurycleia as without. [docs/real-model-results.md](docs/real-model-results.md)
- AgentDojo ran end to end with a real model for the first time: Claude Sonnet 5.5 on 20 banking attacks finished the same tasks with Eurycleia's strict rules as without (18/20); the model resisted all 20 attacks on its own

**Benchmark**
- Eurycleia's rules on [AgentDojo](benchmarks/agentdojo/README.md), a public prompt-injection benchmark (97 tasks, 35 attacks, 4 suites). A replay of every task's and attack's reference actions needs no model or API key: with per-task rules 85/97 tasks still done and 29/609 attacks succeeded (552/609 with no defence); with one set of rules per suite, 85/97 and 142/609. Recipients are trusted only from data the user's side wrote, so the results are the same when the attacker is the sender of the email or payment carrying the attack (a review found an earlier version trusted sender fields and AgentDojo's contact list, which includes anyone who emailed the user). A runner for real models (Gemini, Ollama, OpenAI-compatible) saves as it goes and resumes after a quota stop. Not part of the package

**Policy from watch mode**
- `eurycleia learn --policy FILE [--audit LOG]`: drafts a policy from what the agent did while Eurycleia watched, into a new file with a report (`learn-report.md`) of every change and why. It widens only for patterns seen in many separate tasks, in the narrowest form (the contact on the task's own record); never for addresses from untrusted content, other customers' data, secrets, owner-only data, outside addresses or extra arguments, and nothing at all from a task where something looked wrong. Personal-data fields and big limit increases are left for you to decide. It sets missing call limits, and replays the watched tasks to show what the draft would still block. Your policy file is never changed
- To make this possible the audit log now records how each recipient relates to the task (for example "the contact on this task's own customer record", "an address from untrusted content"), in policy names only, never the address. Task ids in the log are unique across processes, so several MCP servers can share one log

**Business customers and staff**
- `owner_domain` on a source: a business customer's data may go to anyone at exactly that company's own email domain on file. Domains that look like shared email services are refused (any containing a known provider's name, such as yahoo.com.au or hotmail.fr, plus bare endings like co.uk); add others with the new top-level `shared_email_domains`. Recipients: `*@crm.account:{account_id}.domain`
- `share_internally: false` on a source: its protected data goes only to its owner, not to anyone at `internal_domains` (for staff records: a colleague doesn't get someone's salary)
- Example policy and tests for both: [`examples/business_and_staff.yaml`](examples/business_and_staff.yaml); "Who owns a record" in the policy reference

**Harder to tamper with**
- Audit logs with a key (`--key` on `serve`, `api`, `connect`; `AuditLog(..., key=audit_key(provider))`): each entry carries a keyed MAC and a keyed `.head` record notes where the log ends, so rewriting the log needs the key, and cutting entries off the end or deleting the `.head` record is detected. `eurycleia audit verify FILE --key KEYFILE`. Writing to a log that was cut short is refused. Eurycleia never starts keying a log that already has entries by itself: `eurycleia audit seal FILE --key KEYFILE` does it once, after checking the chain, and refuses a log that has held keyed entries (`connect --key` says when it's needed). A crash between writing an entry and its `.head` record is recovered. Verifying while other processes write gives no false alarms. Rolling both files back to older copies isn't detected (documented)
- Owner-only files on Windows: key files, the local API's token file, audit logs, box archives and holder keys get an access list with only the current user (0600 is ignored on Windows)
- Tombstones for forgotten box holders: after `forget_holder`, new boxes and deposits for them are refused (including a deposit already under way), so a later import can't quietly bring their data back; the usual spellings of an id (`customer:012`, `customer:12.0`) count as the same holder; `boxes put` skips their rows; `eurycleia boxes unforget` if they genuinely return. The tombstone is a keyed fingerprint, not a name

**Also fixed**
- A customer email address on file containing `*` or `?` (legal in an address) was treated as a pattern, so `*@gmail.com` on file allowed any gmail address as a recipient. Addresses from records are now always compared exactly (present in earlier versions too)
- `eurycleia check` warns when a task reads staff records (`share_internally: false`) and may send to a wildcard such as `*@yourcompany.com`
- Windows: a key file is never left in place if its access list can't be set; key files and audit logs from before 0.6 get one when next opened
- The source archive now includes the tests' data (demo, examples, docs)
- Secret scanning: a tax file number that shares digits with a card-shaped number next to it is now hidden in full (overlapping secret values are merged instead of one being dropped). Found by the fuzz tests
- LangChain and CrewAI tools accept a record id sent as a number (`customer_id=12`), as models often do; before, the framework rejected the call before it reached Eurycleia
- `SMTPSink` now checks the mail server's TLS certificate (Python's default for `starttls()` doesn't)

**Easier to start**
- A 5-minute [quick start](docs/quickstart.md), with its example run in the tests
- Ready for PyPI: the release workflow can publish with trusted publishing (no stored password), switched off until the project's final name is chosen
- Fixed: the CrewAI and LangChain helpers (`eurycleia.integrations`) were missing from the 0.5 release files, so they only worked from a source checkout. Every build is now checked to contain every module

**Smaller**
- Only the TypeScript/JavaScript adapter is kept; Go and Java were removed (the local API stays, so any language can sign requests the same way)

**Testing (not part of the package)**
- A spending meter in A$ with a hard limit, reported-token costs and Claude prompt caching for every benchmark runner; OpenRouter as a provider
- New benchmarks: LangGraph and CrewAI agents ([benchmarks/frameworks](benchmarks/frameworks/run_frameworks.py)), an API model using an MCP server before and after `eurycleia connect` ([benchmarks/mcp_agent](benchmarks/mcp_agent/run_mcp.py)), a long unattended run ([benchmarks/longrun](benchmarks/longrun/run_long.py)) and real apps in test accounts: HubSpot, Zendesk, Stripe test mode, Slack, Gmail/SMTP/Microsoft 365 ([benchmarks/real_apps](benchmarks/real_apps/REAL_APPS.md))
- The AgentDojo runner now meters cost, samples, and supports Claude and OpenRouter
- `eurycleia learn` with a real model: watch, learn a draft, then check it enforced on fresh tickets ([benchmarks/learn](benchmarks/learn/run_learn.py))
- Running order for the test round: [benchmarks/RUN_GUIDE.md](benchmarks/RUN_GUIDE.md)
- AgentDojo with newer Claude models: no temperature is sent when the Anthropic library doesn't take one, and a call a model refuses because of its temperature setting is sent again without it. Claude Sonnet 5.5 prices added

## 0.5.1

Security fixes from a private report on 0.5.0 (reproduced and fixed here; tested with simulated data and scripted calls, not live models).

**Fixed**
- **Customer data in links (high).** A fooled agent could put a customer's details, or their stand-ins, inside a link or image address in an email to that same customer; the vault then filled in the real values and, when the email was opened, they went to the linked website. Actions are now blocked when a link to a website outside `internal_domains` (or the new `link_domains`) carries a protected or secret value the task has seen (or two or more words of one), a placeholder or a stand-in. Links are read the way browsers read them: in HTML attributes (the whole value), Markdown, CSS and plain text, with or without `//` after the scheme, and decoded (percent-encoding, `+`, HTML entities, backslashes as slashes). A review of the first version of this fix found three ways around it (links without slashes, quotes inside a link, multi-word values in some attributes); all are fixed and tested
- **Slow scanning (high).** The email pattern took quadratic time on text like `a.a.a.a...`: one ~1 MB ticket could freeze the whole process for about an hour. Its lengths are now bounded. Our own wider timing tests found two more slow cases in the same scanner (long runs of short digit groups, and IBAN-like text, 8-50 s per 200 KB); runs of groups are now examined once each, with a constant-time Luhn pre-check. Every pattern is now tested on hostile input; the worst case is now about 1-2 s per MB
- **Cards next to other numbers.** The scanner could take a run of digits that happened to pass the card check instead of the real card beside it, leaving part of the card visible. Cards written the usual way (4-4-4-4, 4-6-5, 4-6-4, 4-4-4-4-3, or unbroken) now come first, and when two overlapping card-shaped runs both pass, both are hidden. In 40,000 random trials with a card among other numbers, dates and amounts, every card was hidden whole (0.5.0: about 14% were not). Tax file and Medicare numbers written right next to other numbers are found about as often as before, which is not always (a known limitation of pattern matching). Digits in other scripts (such as full-width) are handled; an early version of this change crashed on them
- **Parallel calls (medium).** `max_calls` and data budgets could be exceeded when an agent framework ran tool calls on one task in parallel (LangGraph does by default): 30 of 30 emails went out under `max_calls: 3`. Each task now checks and counts one call at a time (planner-mode checks too). Human approvals, opening a deposit box, `on_flag` handlers and the sink itself run outside that lock, so a slow person, handler or app doesn't hold up the task; a refused approval doesn't use up the limit
- **Echoed secrets (low-medium).** Sink results are now masked for a secret with any punctuation between its digits (such as an em dash), and in base64 and hex. A secret split across several fields can still get through (documented)
- **Recipient patterns (low).** `*` no longer reaches past one part of an address: `*acme.example` doesn't match `evil@notacme.example`, and `https://*.partner.com/*` doesn't match `https://evil.com/x.partner.com/y`. `**` matches across path segments; `?` and `[...]` stay within one part too, and `^` in a class is literal (as before). `taskvault check` warns about patterns that match look-alike or any domains (`*acme.example`, `*@*acme.example`, `https://*.com`)
- **Behaviour change:** recipients other than email addresses (URLs, channel ids) are now compared with their case as written, except a URL's scheme and host (a URL path can be case-sensitive). A policy entry `c0support1` no longer matches `C0SUPPORT1`
- **Crashes on unusual input (low).** A number over 4,300 digits ended the MCP proxy (and upstream replies or API requests with one got an unclear error); arguments nested thousands of levels deep raised an internal error instead of being blocked. Both are now refused cleanly
- **Non-ASCII owner addresses (low, usability).** A customer whose address on file has non-ASCII letters (`josé@example.com`) could never be emailed. Such an address is now accepted when it exactly equals the trusted one, and never through a pattern; look-alikes are still blocked

**New**
- `link_domains` policy setting: other websites whose links may carry customer data
- 180 regression tests for the above; every fix was reviewed by separate AI agents (not an independent security audit), and their findings on the first versions of these fixes are fixed too

## 0.5.0

**Licence**
- The taskvault core is now licensed under AGPL-3.0-only (versions up to 0.4.2 stay under Apache-2.0). The language adapters in `adapters/` stay under Apache-2.0 so they can be used in any application. See NOTICE.

**Leaner**
- Removed: session recording and replay (`--record`, `taskvault replay`, `taskvault traces`), the behaviour baseline ("pattern of life": `taskvault baseline`, `--baseline`) and the old secret store (`taskvault store tokenize`, `--store`). Recordings kept an extra copy of real data; firm per-task limits, budgets and approvals do the baseline's job more predictably; deposit boxes replace the secret store. Records still holding old `tvref_` references are refused with a clear message
- `taskvault plan` is now `taskvault report --audit FILE` (`plan` still works)
- The core action check is split into named steps (same checks, same order); the one-time 0.4 box upgrade loads only when used
- Core code about 7% smaller (6,273 to 5,826 lines); 21 commands down to 16; tests run in about 40 s instead of 63 s with nothing dropped but the removed features' own tests
- Reviewed by a separate AI agent: same behaviour in every path of the action check, no protection lost

**Stress testing before release** (load, fuzzing, soak, mixed workloads and a separate review agent; with Claude Opus 5.5, not an independent audit). Found and fixed:
- The `domain` summary returned the whole value when it wasn't an email (e.g. a card number)
- Masking of action results missed reformatted values (dashes instead of spaces, capitals) and secrets the task had seen but that weren't part of that action; it now catches any case and spacing, and every secret the task handed out
- A second net removes secret-looking data (cards, bank accounts, tax file numbers, keys) that the task never saw from action results, and logs that it did (found by fuzzing: an app returning another customer's card)
- A long-running server kept every audit entry in memory as well as on disk; now a recent window (10,000) is kept and checks stream the file
- A customer forgotten at the moment a record was being saved could fail the save, or leave items sealed with an old box key; saves now detect this and retry
- `taskvault connect`: a Windows BOM or broken JSON crashed it; a private settings file (which can hold API keys) became readable by others; a settings file that is a symbolic link was replaced by a copy
- The AI web client could be held open indefinitely by a server sending one byte at a time; there's now an overall deadline
- Java adapter reused closed connections under load; the API now says it closes each connection, and the Java client uses HTTP/1.1
- Invalid Unicode in an API request caused an internal error instead of a clean refusal
- First test run on Windows (451 passed, 2 failed), both fixed: the audit log's Windows file lock could be released at the wrong position when reading stopped early, hiding the real error; and a refused oversized API request reached the app as a dropped connection instead of "too large"
- The second net once mistook a placeholder ending in eight digits for a tax file number and cut it (twice in 2,000 tasks); placeholders are now skipped
- Second Windows run: tests now work from any folder, and a slow app no longer makes the next request on the same task fail; the agent demo reports crashed runs as ERROR instead of "safe"
- Measured: 2,000 tasks from Python, Node, Go and Java at once with no errors; 120,000 random API requests with no crashes or leaks; an 8-minute soak with flat threads, files and (after the fix) memory

**Easy start**
- `taskvault connect claude-desktop|hermes|mcp-json` puts taskvault in front of an agent's existing MCP servers by editing its settings file (backup saved first). Starts in watch mode: logs what it would block, blocks nothing
- `taskvault report` (what would have been blocked), `taskvault enforce` / `taskvault watch` (switch modes), `taskvault disconnect` (restores the original settings exactly)

**Other languages**
- `taskvault api`: a local API so agents in other languages get the same protection. Adapters with no dependencies for TypeScript/JavaScript (Node 18+, with helpers for OpenAI, Anthropic and Vercel AI SDK tool formats), Go and Java (17+). Tested against the simulated demo data, including a Vercel AI SDK agent with a scripted model
- Approved actions run in the app's own language with the real values; what they return (or the error they throw) is masked before the model sees it; blocked actions never reach the app's code
- The token never travels: every request and reply is signed (HMAC-SHA256, time-limited, no replays), so a program posing as taskvault on the same port gets nothing and can't trigger actions. Local only, web pages refused, connection and size limits
- A separate AI agent reviewed the local API and adapters; its findings were fixed before release (a long error could be cut before masking, an existing loose connection file could expose the token, an impostor server on the port, idle connections holding threads, and smaller issues)
- Masking also covers real values in result keys, as numbers, and written without spaces (for the Python SDK too)

**Data protections**
- Free-text scrub: personal data inside text fields (notes, ticket bodies) is replaced before the model sees it
- Derived answers: a task can get "card ends 4242" or "is over 18: yes" instead of the value itself
- Fields on request: the agent asks for the fields it needs; unrequested fields are never read
- Data budgets per task (reads, records, fields)
- Model trust levels: `model="external"` (default) or `"internal"` for a model you run yourself

**Smaller deposit boxes, stronger logs**
- New storage format: about 2.2 KB per customer (was about 7.2 KB) and about 150 bytes of log per read (was about 2.1 KB); reads about 3 times faster. Encryption unchanged
- Field names now sit inside one encrypted entry per record, so the database doesn't even show how many fields a record has
- Box logs are chained with a key derived from the vault key: rewriting a log now needs the key (0.4 used a plain hash chain)
- `taskvault boxes compact` archives old log entries (compressed, encrypted, tied to the database) and leaves a summary that keeps the chain verifiable
- `taskvault boxes migrate` upgrades 0.4 box databases in one step; it checks the key and every old log first
- Forgetting a holder overwrites the deleted data in SQLite; fields dropped from a record are deleted and logged
- A second review (by a separate AI agent) found and we fixed: compaction removing newer entries after a clock jump, migration accepting a wrong key, a Postgres deadlock between concurrent writers, archives not forced to disk before deleting, archives from another database being accepted
- Shared audit file: a process opening the log could read another's half-written line

**Fewer libraries (supply chain)**
- Claude, OpenAI-compatible APIs (including Ollama) and Gemini now use a small built-in HTTPS client instead of each company's library: installing taskvault adds no AI libraries (the `[anthropic]`, `[openai]`, `[gemini]`, `[ollama]` extras are now empty)
- The client always verifies certificates, refuses redirects (so a key can't be forwarded), never sends a key over plain http except to this computer, limits reply size, and keeps keys out of error messages
- Rate limits are waited out; a used-up quota or credit balance stops cleanly
- Every library is locked to an exact version and checksum (`requirements/*.lock`); CI installs with `--require-hashes` and checks for known vulnerabilities on every change and weekly (pip-audit)
- GitHub Actions are pinned to exact commits; Dependabot proposes updates weekly
- When a release is published, a workflow runs the tests and vulnerability check, builds the package, writes a software bill of materials (SBOM) and checksums, signs a record of how the files were built (GitHub build attestation), and attaches them to the release
- Tests also run on Windows and macOS

**Agent frameworks and connectors**
- `protect(task)` for CrewAI and LangChain / LangGraph; `OllamaProvider` for local models
- Connectors (tested against simulated responses): HubSpot, Zendesk, Stripe, Xero, Slack, Outlook, Gmail, MongoDB

**Security fixes** (from a reported review and real-model testing)
- Planner mode now applies document-level sensitivity labels (`label_field` / `label_map`)
- Personal-data detector runs in near-linear time on adversarial input (was quadratic)
- Recorded traces must be encrypted (`--record` needs `--key`) and are owner-only
- `forget_holder` removes every index row for the holder
- An empty `fields` list means the usual fields, not none
- A secret bound to an argument (such as a card for a refund) must be the vault's own placeholder; a typed-in card number is blocked
- CI runs with read-only permissions; block log lines carry no details

## 0.4.2

Security and reliability fixes from a round of stress testing (with Claude Opus 5.5). Not an independent review.

**Security**
- Recipients must be exactly one plain address or id: a hidden second address could get past a glob rule like `*@yourcompany.com`
- Sink replies and error messages are masked (real values replaced with the placeholder or stand-in the agent saw); sink errors are raised as `SinkError`
- `cc` / `bcc` / `reply_to` / `recipients` arguments are checked like the main recipient; sinks receive the checked address
- Damaged or forged placeholders are blocked; tool arguments are type-checked against the policy's `params`
- Block reasons written to logs and the audit file contain no data values; agent-chosen names are fingerprinted
- List settings in policies must be lists (a string like `"*@acme.example"` was read as characters, including `*`); wrong shapes raise `PolicyError`
- A failure unlocking a stored secret is a logged block
- Requires `cryptography>=49` (older versions have known vulnerabilities)
- REST connector: only http(s) URLs; keys can't be `.` or `..`

**Reliability**
- Deposit boxes: a race could replace a box's data key (making earlier items unreadable); SQLite waits instead of failing with "database is locked"; Postgres setup is serialised
- Audit log: an OS-level file lock and chaining from the file's real last entry, so several processes can share one file; `taskvault audit repair` sets aside a torn last line
- MCP proxy: malformed JSON-RPC gets an error reply instead of crashing the proxy
- Clear errors for damaged key files and policies of the wrong shape
- Linter warns when a sink with a recipient has no `args` list; templates and demo policy now list them

**Testing**
- Fuzz tests (`tests/test_fuzz.py`, needs `hypothesis`), hardening tests, MCP proxy fuzz tests, multi-process audit test, concurrent deposit-box test
- `python -m demo.stress`: throughput, 32-thread and multi-writer checks, 10 MB inputs, 100,000-row setup scan
- Fixed a test that failed at random (short digit strings matching random hex)
- 231 tests

## 0.4.1

- First tests with live models (Claude Sonnet 5, Haiku 4.5, Opus 5.5; Gemini 3.5 Flash-Lite and 2.5 Flash on the free tier): with the vault, 0 of 43 attack runs leaked; without it, realistic attacks leaked data on several models. Chart, table and raw data in `docs/real-model-results.md`
- Planner mode: plans are checked against the policy (sources, sinks, required arguments, field references) before they run, and the model gets the errors back with up to two retries
- Planner prompt lists each sink's arguments and each source's keys, with a worked example
- The extractor may answer "unknown" (null); a `when` on it skips the action
- Gemini: waits out free-tier per-minute rate limits; the benchmark stops cleanly and keeps its results if a daily quota runs out
- README: fuller disclaimer and limitations; security features described as design goals, not guarantees
- Five harder, realistic attacks in the benchmark (new email address, shared account, staff impersonation, full card for records, forwarded internal request); `--scenarios` to run a subset
- 166 tests

## 0.4.0

- Deposit boxes: per-holder encrypted boxes for departments, customers and client companies, stored in SQLite or Postgres
- Two tiers: normal boxes open with the vault's key; high-security boxes need the vault's key and the holder's key (X25519 sealed per item), optionally with the holder's approval, for a limited time
- High-security values stay locked until an approved action needs them
- Per-box tamper-evident logs, `forget_holder`, and an optional company recovery key
- `storage: boxes` for policy sources; `taskvault boxes holder|put|list|log|forget`; `taskvault serve --boxes`
- Postgres support tested against a real Postgres 16 server (deposit boxes, setup scanner, SQL connector)
- 156 tests

## 0.3.0

- `taskvault setup`: scans SQLite, Postgres, CSV/JSON files, document folders and MCP servers, then writes a commented policy, synthetic fixtures, connector code and a report, and runs the attack suite
- Automatic detection of sensitive data (cards, TFN, Medicare, ABN, BSB/account, IBAN, API keys, private keys, emails, phones, names, addresses...) with checksums; `taskvault scan`
- Pseudonymisation: the model sees stable stand-ins for names, emails and phones; real values only at sinks
- Long-term secret store: move secrets into the vault, keep `tvref_` references in your data; `taskvault store tokenize`; per-owner erasure
- Risk tiers on sinks (`low` / `medium` flags for review / `high` needs approval) and `taskvault review`
- Behaviour baseline learned from clean tasks; flags unusual actions; `taskvault baseline`
- Import existing sensitivity labels (`label_field`, `label_map`)
- `detect_outbound`: block outbound text that looks like a secret
- `secrets_allowed` can bind each secret to one argument
- Protected data may go to internal domains
- Hardening: recipient normalisation (display names, header injection, hidden recipients, look-alike characters), owner-only file permissions, thread-safe audit log with optional fsync, `taskvault` logger, error hierarchy (`TaskvaultError`), typed package
- File connectors (`FolderDocuments`, `TableFile`)
- Tested on Python 3.10-3.13; 131 tests

## 0.2.0

- Planner mode: provenance-tracked plans with a quarantined extractor and conditional actions
- Customer-held keys (local file or cloud KMS envelope), AES-256-GCM, crypto-shredding
- Encrypted read-through cache with TTL and invalidation
- Connectors: SQL, REST, Salesforce, Google Drive, SharePoint/OneDrive, SMTP
- MCP proxy (`taskvault serve`) with host-supplied trusted inputs
- CLI: `init`, `check`, `test`, `plan`, `serve`, `replay`, `traces`, `audit`, `keys`
- Worst-case attack suite with an independent leak oracle, and a policy linter
- Encrypted session traces and replay investigations, kept separate from the audit log
- Anthropic and OpenAI adapters; benchmark harness (`python -m demo.bench`)
- Policy: `owner_field`, sink `args`, `approval`, `max_calls`, `invalidates`, recipient globs, `tools`, `upstream`
- Support and finance policy templates

## 0.1.0

- Task-scoped reads, secret placeholders, owner-bound outbound checks, shadow mode, hash-chained audit log
- Offline demo of a hijacked support agent
