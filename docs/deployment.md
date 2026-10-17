# Deploying Eurycleia to production

A checklist for running Eurycleia in front of real agents and real data.

## 1. Install and pin

```bash
pip install "eurycleia[all] @ https://github.com/AgentP-Codes/project-eurycleia/releases/download/v0.6.0/eurycleia-0.6.0-py3-none-any.whl"
```

Eurycleia isn't on PyPI yet, so install from a release file. Pin the version. Read the changelog before upgrading, and rerun `eurycleia test` in CI on every upgrade.

## 2. Keys

The customer's key encrypts cached records and placeholders; deposit boxes use it as the vault key.

- **Cloud (recommended):** use `KMSKeyProvider` with the customer's own KMS key (e.g. AWS KMS). Only a wrapped data key is stored on disk; revoking the KMS key revokes access.
- **Local:** `eurycleia keys init /secure/volume/customer.key` creates a 256-bit key with owner-only permissions (on Windows, an access list with only your user account). Keep it out of version control, back it up separately from the data, and restrict who can read it.
- **Crypto-shredding:** `eurycleia keys shred PATH`, or revoking the KMS key, makes everything encrypted under it unreadable. Test this in staging before relying on it.
- Use a **separate key per customer or tenant**, so pseudonyms and stored data can't be linked across tenants.

## 3. Write and test the policy

1. `eurycleia setup ...` against a staging copy of your data (or `eurycleia init`).
2. Review every comment in `eurycleia.yaml`, especially low-confidence fields in `setup-report.md`.
3. Set `internal_domains` to your real domains.
4. Put `eurycleia check` and `eurycleia test` in CI; the build fails if any attack leaks.
5. Review policy changes in pull requests like any other code.

## 4. Trusted inputs

Everything depends on this: the values you pass to `start_task` (e.g. `customer_id`) must come from **your** system: an authenticated session, a verified email sender, a ticket's customer record. Never from text the model or the customer wrote.

## 5. Roll out in shadow mode first

1. Run with `mode="shadow"` (or `eurycleia serve --shadow`) for one to two weeks. Nothing is blocked.
2. `eurycleia report --audit audit.jsonl --policy eurycleia.yaml` shows what *would* have been blocked, and which paths were never exercised (month-end, refunds, rare cases).
3. Run `eurycleia learn --policy eurycleia.yaml --audit audit.jsonl`. It writes `eurycleia.learned.yaml` and
   `learn-report.md`:
   - It only widens the policy for patterns seen in many separate tasks (at least 5, and 20% of that task's runs;
     change with `--min-tasks` and `--min-share`), in the narrowest form that explains them, such as "the contact
     on this task's own customer record". Even your own company's domain is left for you to add.
   - It never learns anything an attack would look like: addresses that came from a ticket or web page, other
     customers' records, secrets, customer data to someone who doesn't own it, extra `cc`/`bcc` recipients.
     Those are listed under "Looked wrong".
   - Nothing is learned from a task where something looked wrong. Limits are raised by at most double; a bigger
     jump is left for you to decide, and a switched-off action (`max_calls: 0`) stays off.
   - It never learns outside addresses (the audit log holds fingerprints, not addresses), or extra arguments
     (any of them could send data somewhere). Add a real partner's address or a needed argument by hand.
   - Let the agent read tickets, emails and web pages through Eurycleia (a source with `trust: untrusted`), not
     pasted into its prompt. That's how Eurycleia knows an address came from outside content.
   - It replays the watched tasks against the draft and lists what would still be blocked.
   Read the report, then copy the draft over your policy (keep the old one). Declare rare paths up front.
4. Switch to enforce.

## 6. Audit log

- Use `AuditLog(path, fsync=True)` so each entry is on disk before the action runs.
- Ship the log to your SIEM or write-once storage (e.g. S3 Object Lock). The hash chain proves order and integrity; off-box copies protect against truncation.
- Check it regularly: `eurycleia audit verify audit.jsonl --key customer.key` (exits 1 if anything is wrong).
- To start protecting a log written without a key, check it and seal it once: `eurycleia audit verify audit.jsonl`, then `eurycleia audit seal audit.jsonl --key customer.key` (`connect --key` tells you when this is needed). Only seal a log you know was never keyed. Eurycleia never starts keying an existing log by itself, and `seal` refuses a log that has held keyed entries, because a log whose MACs and `.head` file were removed looks exactly like one that was never keyed. If a keyed log is refused ("doesn't end where...", "no end-of-log record"), keep the file for investigation and start a new one. Every process writing to the log needs the same `--key`.
- When `serve`, `api` or `connect` run with `--key`, every entry also gets a MAC keyed from that key, and `audit.jsonl.head` records where the log ends. Rewriting the log then needs the key, and cutting entries off the end (or deleting the `.head` file) is detected. Without `--key` the chain still catches edits, but someone with file access could rebuild it or trim the end. Someone who kept old copies of both files could roll them back together, so for the strongest record, also ship the log to your SIEM or write-once storage. In Python: `AuditLog("audit.jsonl", key=audit_key(key_provider))`.
- The log never contains raw sensitive values, only keyed fingerprints, field names and decisions.

## 7. Oversight

- Give high-risk sinks `risk: high` and pass an `approver` that asks a person (Slack, email, a queue). With no approver configured, high-risk actions fail closed.
- Use `risk: medium` and `on_flag` for actions worth a look but not worth blocking.
- Set per-task limits (`max_calls`) and data budgets so a hijacked agent can only do a bounded amount. Review flagged actions with `eurycleia review`.

## 8. Secrets

For the sharpest values (cards, bank accounts, IDs), keep them in deposit boxes instead of your own database: `eurycleia boxes put customers.csv ...` (next section). The high-security tier needs both the vault's key and the holder's key to open.

## 9. Deposit boxes

- **Database:** SQLite is fine for one server; use Postgres (`postgresql://...`) when several vault processes share boxes. Back it up like any database: its contents are encrypted.
- **Holder keys:** for departments, `eurycleia boxes holder` creates a key file; give it to the department and keep it off the vault server where possible. For customers or client companies, implement `HolderKeys` against *their* key service so their private key never sits with you.
- **Approvals:** pass an `approver` to the holder key service to require a person (e.g. an HR manager) to allow each opening of a high-security box.
- **Recovery:** create a company recovery key pair, keep the private half offline (e.g. in a safe), and pass its public key as `recovery_public_key`. It's the break-glass if a holder loses their key.
- **Erasure:** `eurycleia boxes forget --holder customer:12` for a deletion request. A tombstone (a keyed fingerprint, no name) then stops their boxes being made again, so a later import or sync can't quietly bring their data back; `boxes put` skips their rows. If they genuinely return, `eurycleia boxes unforget --holder customer:12`. A record the vault read just before may still be in its encrypted cache for up to `cache_ttl_seconds`; restart the vault, or call `vault.cache.invalidate_source(...)` for the box source, to drop it at once. The tombstone covers the usual spellings of an id (`customer:012`, `customer:12.0`).

## 10. Logging

Eurycleia logs decisions to the standard `logging` module under the `eurycleia` logger (blocks at INFO). It never logs raw sensitive values. Route it wherever your service logs go.

## 11. Incidents

1. `eurycleia audit show audit.jsonl --decision block` to see what was stopped.
2. `eurycleia audit verify audit.jsonl` to confirm the log wasn't changed; for deposit boxes, `eurycleia boxes log <box>`.
3. The audit entries show which task, template, action and (fingerprinted) recipient was involved; your agent framework's own logs show what the model was given.
