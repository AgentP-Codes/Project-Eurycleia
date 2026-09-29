# taskvault-client

taskvault for TypeScript and JavaScript agents: a zero-dependency client (Node 18+) for `taskvault api`.
See [the adapters guide](../README.md) for setup, examples and the security model.

```ts
import { TaskVault } from "taskvault-client";
const tv = (await TaskVault.connect()).onAction("email.send", sendEmail);
const task = await tv.startTask("customer_request", { customer_id: 12 });
const reply = await task.callForModel("get_customer", {});
```

Licensed under Apache-2.0. Created by AgentP-Codes.
