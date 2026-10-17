# Eurycleia for TypeScript and JavaScript

Agents written in **TypeScript or JavaScript** can use Eurycleia through a local API.
The adapter is a thin client with **no dependencies**: every check, placeholder, pseudonym, audit entry and
block happens in Eurycleia itself, in the same code the Python SDK uses. Nothing security-related is
re-implemented per language.

| Language | File | Needs | Tested with |
| --- | --- | --- | --- |
| TypeScript / JavaScript | [`typescript/index.js`](typescript/index.js) (+ `index.d.ts`) | Node 18+ | Node 22, TypeScript 5 (types), Vercel AI SDK 5 (scripted model) |

It has been tested against the demo's simulated data only. Agents in other languages can use the same local
API: every request is plain JSON over HTTP, signed as described under [Security](#security). (Go and Java
adapters were included in 0.5 and removed in 0.6 to keep the project small.)

## 1. Start Eurycleia's local API

```bash
eurycleia api --app eurycleia_app:build_vault     # the connectors written by `eurycleia setup`
# or, with the tools of an existing MCP server:
eurycleia api --policy eurycleia.yaml -- python my_crm_mcp_server.py
```

It listens on `127.0.0.1` only and writes its address and a fresh secret token to `~/.eurycleia/api.json`
(owner-only). The adapter finds it there, or in `EURYCLEIA_URL` and `EURYCLEIA_TOKEN`.

## 2. Use it from your agent

**TypeScript**

```ts
import { Eurycleia } from "eurycleia-client";

const tv = (await Eurycleia.connect())
  .onAction("email.send", async ({ to, subject, body }) => mailer.send({ to, subject, body }))
  .onAction("payments.refund", async ({ card, amount }) => payments.refund(card, amount));

const task = await tv.startTask("customer_request", { customer_id: session.customerId });  // trusted: from your app
// give the model task.openAITools() / task.anthropicTools() / task.vercelTools({ tool, jsonSchema })
const text = await task.callForModel(toolCall.name, toolCall.args);   // what goes back to the model
await task.end();
```

## How actions work

When the model asks for an action (send an email, refund a card), Eurycleia checks it first. If it's
blocked, your handler never runs and the model is told why. If it's allowed, your handler runs **with the
real values** (the real card number, not the placeholder the model saw), exactly like a Python sink
function. Whatever the handler returns, or the error it throws, goes back through Eurycleia, which replaces
any real values with what the model saw before the model gets it.

Don't log the arguments your handlers receive, or pass them to the model yourself.

## Security

- **Your computer only.** The API listens on `127.0.0.1`; the adapter refuses any other address and never use a proxy.
- **The token never travels.** Each request is signed with it (HMAC-SHA256 over the time, a one-off random value, the method, path and body); each reply is signed back. A program pretending to be Eurycleia on the same port learns nothing and can't make your app run an action. Replayed or more than 2-minute-old requests are refused (so your computer's clock needs to be roughly right).
- **Web pages can't reach it.** Requests with an `Origin` header or an unexpected `Host` header are refused.
- **Limits:** 1 MB requests, 256 connections, idle connections dropped after 30 seconds, idle tasks after 30 minutes, actions your app doesn't finish within 2 minutes time out.
- **Whoever has the token is trusted like your app:** they can start tasks with any trusted inputs. The token file is owner-only; don't copy it elsewhere.

## Running the adapter's tests

From the repository root, with Eurycleia installed (`pip install -e .`):

```bash
node --test adapters/typescript/test/api.test.js
```

## Licence

The adapter is licensed under Apache-2.0 ([LICENSE](LICENSE)), so you can use it in any application, open or closed. The Eurycleia core they connect to is licensed under AGPL-3.0-only (see the project [NOTICE](../NOTICE)).
