# taskvault for other languages

Agents written in **TypeScript/JavaScript**, **Go** and **Java** can use taskvault through a local API.
The adapters are thin clients with **no dependencies**: every check, placeholder, pseudonym, audit entry and
block happens in taskvault itself, in the same code the Python SDK uses. Nothing security-related is
re-implemented per language.

| Language | File | Needs | Tested with |
| --- | --- | --- | --- |
| TypeScript / JavaScript | [`typescript/index.js`](typescript/index.js) (+ `index.d.ts`) | Node 18+ | Node 22, TypeScript 5 (types), Vercel AI SDK 5 (scripted model) |
| Go | [`go/taskvault.go`](go/taskvault.go) | Go 1.21+ | Go 1.24, race detector |
| Java | [`java/src/.../TaskVault.java`](java/src/io/github/agentpcodes/taskvault/TaskVault.java) (one file) | Java 17+ | Java 21 |

C#/.NET is planned. These adapters have been tested against the demo's simulated data only.

## 1. Start taskvault's local API

```bash
taskvault api --app taskvault_app:build_vault     # the connectors written by `taskvault setup`
# or, with the tools of an existing MCP server:
taskvault api --policy taskvault.yaml -- python my_crm_mcp_server.py
```

It listens on `127.0.0.1` only and writes its address and a fresh secret token to `~/.taskvault/api.json`
(owner-only). The adapters find it there, or in `TASKVAULT_URL` and `TASKVAULT_TOKEN`.

## 2. Use it from your agent

**TypeScript**

```ts
import { TaskVault } from "taskvault-client";

const tv = (await TaskVault.connect())
  .onAction("email.send", async ({ to, subject, body }) => mailer.send({ to, subject, body }))
  .onAction("payments.refund", async ({ card, amount }) => payments.refund(card, amount));

const task = await tv.startTask("customer_request", { customer_id: session.customerId });  // trusted: from your app
// give the model task.openAITools() / task.anthropicTools() / task.vercelTools({ tool, jsonSchema })
const text = await task.callForModel(toolCall.name, toolCall.args);   // what goes back to the model
await task.end();
```

**Go**

```go
tv, _ := taskvault.Connect(ctx)
tv.OnAction("email.send", func(ctx context.Context, a map[string]any) (any, error) { return mailer.Send(a) })
task, _ := tv.StartTask(ctx, "customer_request", map[string]any{"customer_id": customerID})
tools := task.OpenAITools()                                 // or task.AnthropicTools()
text, _ := task.CallForModel(ctx, call.Name, call.Args)
```

**Java**

```java
TaskVault tv = TaskVault.connect()
    .onAction("email.send", args -> mailer.send(args));
TaskVault.Task task = tv.startTask("customer_request", Map.of("customer_id", customerId));
String tools = task.openAIToolsJson();                      // or task.anthropicToolsJson()
String text = task.callForModel(call.name(), call.args());
```

## How actions work

When the model asks for an action (send an email, refund a card), taskvault checks it first. If it's
blocked, your handler never runs and the model is told why. If it's allowed, your handler runs **with the
real values** (the real card number, not the placeholder the model saw), exactly like a Python sink
function. Whatever the handler returns, or the error it throws, goes back through taskvault, which replaces
any real values with what the model saw before the model gets it.

Don't log the arguments your handlers receive, or pass them to the model yourself.

## Security

- **Your computer only.** The API listens on `127.0.0.1`; the adapters refuse any other address and never use a proxy.
- **The token never travels.** Each request is signed with it (HMAC-SHA256 over the time, a one-off random value, the method, path and body); each reply is signed back. A program pretending to be taskvault on the same port learns nothing and can't make your app run an action. Replayed or more than 2-minute-old requests are refused (so your computer's clock needs to be roughly right).
- **Web pages can't reach it.** Requests with an `Origin` header or an unexpected `Host` header are refused.
- **Limits:** 1 MB requests, 256 connections, idle connections dropped after 30 seconds, idle tasks after 30 minutes, actions your app doesn't finish within 2 minutes time out.
- **Whoever has the token is trusted like your app:** they can start tasks with any trusted inputs. The token file is owner-only; don't copy it elsewhere.

## Running the adapter tests

From the repository root, with taskvault installed (`pip install -e .`):

```bash
node --test adapters/typescript/test/api.test.js
(cd adapters/go && go test ./...)
javac -d build/java adapters/java/src/io/github/agentpcodes/taskvault/TaskVault.java adapters/java/test/TaskVaultTest.java
java -cp build/java TaskVaultTest
```

## Licence

The adapters are licensed under Apache-2.0 ([LICENSE](LICENSE)), so you can use them in any application, open or closed. The taskvault core they connect to is licensed under AGPL-3.0-only (see the project [NOTICE](../NOTICE)).
