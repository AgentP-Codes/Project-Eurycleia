# Policy reference

A policy is one YAML file, kept in your repo and reviewed like code. `eurycleia init` creates a starter; `eurycleia check` validates and lints it. Unknown keys are errors.

```yaml
version: 1
internal_domains: [yourcompany.com]
link_domains: []    # optional: other websites whose links may carry customer data
shared_email_domains: []   # optional: more email services that are never a business customer's own domain
cache_ttl_seconds: 300
detect_outbound: true
sources:  {...}
tasks:    {...}
tools:    {...}     # optional: for the MCP proxy and LLM adapters
upstream: {...}     # optional: for the MCP proxy
```

## `internal_domains`

Your company's own email domains. Protected data (company-owned or a customer's) may be sent to these addresses, because the company already holds it. Secrets still only go where `secrets_allowed` says.

## Who owns a record

Every record belongs to someone, and that decides where its protected data may go.

| Records about | `owner` | Where the data may go | Example |
| --- | --- | --- | --- |
| Your company (documents, pricing) | `company` | `internal_domains` only | `docs` in the demo |
| One customer | `customer_id` + `owner_contact: email` | That customer's address on file, and `internal_domains` | `crm.customer` in the demo |
| A business customer | `account_id` + `owner_domain: domain` | Anyone at that company's own domain on file, and `internal_domains` | [`examples/business_and_staff.yaml`](../examples/business_and_staff.yaml) |
| One employee | `employee_id` + `owner_contact: work_email` + `share_internally: false` | That employee only, not their colleagues | same example |

The key (a customer id, account id or employee number) always comes from a trusted input your app passes to `start_task`, such as the signed-in user, never from the model or the text it reads. Allow recipients to match: `crm.customer:{customer_id}.email` for one address, or `*@crm.account:{account_id}.domain` for anyone at a business customer's domain.

## `link_domains`

Customer data inside a link leaves the company as soon as the link is opened, or as soon as an image in an email loads, whoever the message was sent to. So in any action, a link to a website outside `internal_domains` may not carry a protected or secret value the task has seen, a placeholder, or a stand-in. Links are found in HTML attributes, Markdown, CSS and plain text, and are checked as written and decoded (percent-encoding, `+` for spaces, HTML entities). The action is blocked, not edited.

List other sites here only if links to them may carry customer data, for example your booking provider: `link_domains: [bookings.example]`. Each entry also covers its subdomains. Links that carry no customer data (a help article, say) always work. Customer data is found in a link even when it's encoded (base64, hex), written backwards, or split across several links, and a `mailto:` link counts as going to its address's domain.

## `cache_ttl_seconds`

How long a fetched record stays in the encrypted read-through cache (when a cipher is configured). Default 300.

## `detect_outbound`

When `true`, any outbound action with a recipient is also scanned for things that look like secrets (card numbers, TFNs, Medicare numbers, bank accounts, IBANs, API keys, private keys), even if the vault never handed them out, and blocked. `eurycleia setup` turns this on.

## `sources`

What the vault may read. Each source maps to a connector you pass to `Vault(sources=...)`.

| Key | Meaning | Default |
| --- | --- | --- |
| `owner` | `company`, or the name of a trusted input that identifies the record's owner (e.g. `customer_id`) | `company` |
| `owner_contact` | Field holding the owner's verified destination (e.g. `email`). Each owner needs this or `owner_domain` on at least one source | – |
| `owner_domain` | For a business customer: field holding the company's own email domain (e.g. `domain`). Its data may go to anyone at exactly that domain. A domain that looks like a shared email service is refused: any domain containing a known provider's name (gmail, yahoo, hotmail, outlook, bigpond and about a hundred more, so also yahoo.com.au or hotmail.fr), bare endings like `co.uk`, and anything in `shared_email_domains`. No such list is complete: only fill this field from records you've checked, such as signed contracts. Some real companies share a provider's name (verizon.com, telstra.com); their data then goes only to their `owner_contact` address | – |
| `share_internally` | `false`: this source's protected data goes only to its owner, not to anyone at `internal_domains`. Use it for staff records | `true` |
| `owner_field` | Field holding the owner's id when it isn't the record key (e.g. an invoice's `supplier_id`) | record key |
| `fields` | `field: level` for each field | – |
| `key_levels` | `record-key: level`, for document stores where sensitivity is per document | – |
| `default_level` | Level for anything not listed | `protected` |
| `trust` | `trusted`, or `untrusted` for inboxes, tickets, web pages | `trusted` |
| `pseudonymize` | Fields the model sees as stable stand-ins (e.g. `Name-7F3A2C`, `email-7f3a2c@pseudonym.invalid`). Real values are swapped back only at sinks, after every check. Not for secret fields | – |
| `storage` | `external` (read from your systems through a connector) or `boxes` (Eurycleia deposit boxes) | `external` |
| `label_field` | Field holding an existing sensitivity label (e.g. from Microsoft Purview) | – |
| `label_map` | That label's value → level, e.g. `{Public: normal, Confidential: protected, "Highly Confidential": secret}`. The most sensitive of the field level and the label wins | – |

**Levels**

| Level | Model sees it? | Where it can go |
| --- | --- | --- |
| `secret` | No, only a `[[vault:field:xxxx]]` placeholder | Only sinks listing it in `secrets_allowed`, and only to its owner |
| `protected` | Yes (or as a pseudonym, if listed in `pseudonymize`) | Only its owner's contact, or `internal_domains` |
| `normal` | Yes | Anywhere the task may send |

## `tasks`

A task template scopes one unit of agent work.

```yaml
tasks:
  support_reply:
    description: Answer one ticket for the customer who sent it.
    trusted: [customer_id]
    reads:
      crm.customer: {key: "{customer_id}", fields: [name, email, plan, card_number]}
      docs: {keys: [refund_policy], fields: [name, body]}
    sinks:
      email.send:
        recipient_arg: to
        allowed_recipients: ["crm.customer:{customer_id}.email"]
        max_calls: 3
      payments.refund:
        args: [card, amount]
        secrets_allowed: {card_number: card}
        risk: high
        max_calls: 1
        invalidates: [crm.customer]
```

| Key | Meaning |
| --- | --- |
| `trusted` | Inputs your app must supply to `start_task`. Never derive these from untrusted text |
| `reads.<source>.key` / `keys` | Which record(s) the task may read. `{name}` is filled from trusted inputs |
| `reads.<source>.fields` | Which fields are returned. Omit to return all (linter warns) |
| `sinks.<sink>.recipient_arg` | Argument naming the recipient(s). A sink without one (a ticket comment, a record write, a webhook) can't carry protected data at all, since it can't be shown to reach the data's owner; secrets still go only where `secrets_allowed` says. Lists and comma-separated strings are each checked. Each must be exactly one plain address (`a@b.com` or `Name <a@b.com>`) or one plain id; anything else is blocked. Arguments named `cc`, `bcc`, `reply_to` or `recipients` get the same checks. The sink receives the checked address |
| `sinks.<sink>.allowed_recipients` | `source:key.field` (looked up by the vault), `*@source:key.field` (anyone at a domain looked up by the vault, see [Who owns a record](#who-owns-a-record)), a literal address, or a pattern like `*@yourcompany.com` (see [Recipient patterns](#recipient-patterns)) |
| `sinks.<sink>.secrets_allowed` | Secret fields whose placeholders are swapped for real values at this sink. As a mapping (`{card_number: card}`), each secret may only be passed as that one argument |
| `sinks.<sink>.args` | The only argument names this sink accepts. Recommended for every sink with a recipient (the linter warns otherwise) |
| `sinks.<sink>.risk` | `low` (default): allow. `medium`: allow, but flag for review (`on_flag` callback, `eurycleia review`). `high`: a human must approve |
| `sinks.<sink>.approval` | `always` sends every call to your `approver`; `never` (default). Set automatically by `risk: high` |
| `sinks.<sink>.max_calls` | Per-task limit |
| `sinks.<sink>.invalidates` | Sources to drop from the cache after this action |

Any source or sink not listed in the task is blocked.

### Recipient patterns

A `*` never reaches past one part of an address, so a pattern is never wider than it looks:

| Pattern | Matches | Doesn't match |
| --- | --- | --- |
| `*@acme.example` | any name at `acme.example` | `x@evil.acme.example`, `x@notacme.example` |
| `*@*.acme.example` | one subdomain: `x@eu.acme.example` | `x@a.b.acme.example`, `x@acme.example` |
| `https://*.partner.com/*` | `https://api.partner.com/in` (one path segment) | `https://evil.com/x.partner.com/y`, `https://api.partner.com/a/b` |
| `https://files.acme.example/upload/**` | anything under `/upload/` | other paths or hosts |
| `+614*` | ids starting `+614` (anything except `/`, `@`, `.`) | |

`?` is one character and `[abc]` a character class, within the same part. Email addresses are compared ignoring case; for other recipients only a URL's scheme and host ignore case, and the rest must match exactly (a URL path can be case-sensitive). An address with non-ASCII letters (`josé@example.com`) is accepted only when it exactly equals one from trusted data, never through a pattern. `eurycleia check` warns about patterns like `*acme.example` or `*@*acme.example` that match look-alike domains.

List settings (`allowed_recipients`, `args`, `fields`, `trusted`...) must be written as lists, e.g. `[a, b]`. A plain string is rejected, so a typo can't turn `"*@acme.example"` into "anyone".

## `tools`

Agent-facing tool names, used by the MCP proxy and `Task.call_tool` / `Task.tool_specs` (LLM adapters).

```yaml
tools:
  get_customer: {read: crm.customer, key_arg: customer_id, description: Look up the ticket's customer.}
  send_email:   {act: email.send, description: Email the customer., params: {to: string, subject: string, body: string}}
```

A tool is only offered to a task that can use its source or sink.

## `upstream`

For `eurycleia serve`: which tools on the upstream MCP server back each source and sink.

```yaml
upstream:
  sources:
    crm.customer: {tool: get_customer, key_arg: customer_id}
  sinks:
    email.send: {tool: send_email}
```

The agent never sees upstream tools directly; unmapped upstream tools are unreachable.
