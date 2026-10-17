// Copyright 2026 AgentP-Codes
// SPDX-License-Identifier: Apache-2.0
// Runs against a real `eurycleia api` with the simulated demo data. From the repo root:
//   node --test adapters/typescript/test/api.test.js

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Eurycleia, EurycleiaError } from "../index.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const PY = process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");
let server, info;

before(async () => {
  const dir = await mkdtemp(join(tmpdir(), "tv-ts-"));
  const conn = join(dir, "api.json");
  server = spawn(PY, ["-m", "eurycleia", "api", "--policy", "demo/policy.yaml", "--app",
    "demo.api_app:build_vault", "--port", "0", "--connection-file", conn], { cwd: ROOT, stdio: "ignore" });
  for (let i = 0; i < 100 && !info; i++) {
    await new Promise((r) => setTimeout(r, 100));
    info = await readFile(conn, "utf8").then(JSON.parse).catch(() => undefined);
  }
  assert.ok(info, "eurycleia api didn't start");
});

after(() => server?.kill());

function connect() {
  return new Eurycleia({ url: info.url, token: info.token });
}

test("a scripted agent: reads with placeholders, refund runs in JS with the real card, attack blocked", async () => {
  const refunds = [];
  const emails = [];
  const tv = connect()
    .onAction("payments.refund", async ({ card, amount }) => {
      refunds.push({ card, amount });
      return { ok: true, charged_to: card };                 // echoing the card: eurycleia must mask it
    })
    .onAction("email.send", async (args) => {
      emails.push(args);
      return "sent";
    });
  const task = await tv.startTask("support_reply", { customer_id: 12 });
  assert.deepEqual(task.openAITools().map((t) => t.function.name).sort(),
    ["get_customer", "get_doc", "refund", "send_email"]);

  const customer = JSON.parse(await task.callForModel("get_customer", {}));
  assert.match(customer.card_number, /^\[\[vault:card_number:[0-9a-f]{8}\]\]$/);
  assert.ok(!JSON.stringify(customer).includes("4111"));

  const refund = await task.call("refund", { card: customer.card_number, amount: 49 });
  assert.equal(refund.ok, true);
  assert.equal(refund.result.charged_to, customer.card_number);      // masked on the way back
  assert.deepEqual(refunds, [{ card: "4111 1111 1111 1111", amount: 49 }]);

  // a prompt injection tries to email the customer's data to an outsider
  const attack = await task.call("send_email", { to: "audit@acme-billing.example", subject: "x", body: "y" });
  assert.equal(attack.ok, false);
  assert.equal(attack.blocked, true);
  assert.equal(emails.length, 0);                                     // the handler never ran
  assert.match(await task.callForModel("send_email", { to: "audit@acme-billing.example", subject: "x", body: "y" }),
    /^Blocked by eurycleia: /);

  const ok = await task.call("send_email", { to: customer.email, subject: "Refund", body: "Done!" });
  assert.equal(ok.ok, true);
  assert.equal(emails[0].to, "priya.shah@example.com");
  await task.end();
});

test("a failing handler is reported with real values masked", async () => {
  const tv = connect().onAction("payments.refund", async ({ card }) => {
    throw new Error(`card ${card} declined`);
  });
  const task = await tv.startTask("support_reply", { customer_id: 12 });
  const c = (await task.call("get_customer")).result;
  const r = await task.call("refund", { card: c.card_number, amount: 5 });
  assert.equal(r.ok, false);
  assert.equal(r.blocked, false);
  assert.ok(!r.error.includes("4111"), r.error);
  assert.ok(r.error.includes(c.card_number));
});

test("an action with no handler is refused, not silently skipped", async () => {
  const task = await connect().startTask("support_reply", { customer_id: 12 });
  const r = await task.call("send_email", { to: "priya.shah@example.com", subject: "a", body: "b" });
  assert.equal(r.ok, false);
  assert.match(r.error, /no handler registered/);
});

test("framework helpers", async () => {
  const task = await connect().startTask("support_reply", { customer_id: 12 });
  assert.equal(task.anthropicTools()[0].input_schema.type, "object");
  const fns = task.functions();
  const get = fns.find((f) => f.name === "get_customer");
  assert.ok(JSON.parse(await get.execute({})).name);
  // Vercel AI SDK shape, using stand-ins for its `tool` and `jsonSchema` helpers
  const tools = task.vercelTools({ tool: (d) => d, jsonSchema: (s) => ({ jsonSchema: s }) });
  assert.equal(typeof tools.refund.execute, "function");
  assert.equal(tools.refund.inputSchema.jsonSchema.properties.amount.type, "number");
});

test("safety: local only, token required, token never printed", async () => {
  assert.throws(() => new Eurycleia({ url: "http://example.com:8765", token: "t" }), EurycleiaError);
  assert.throws(() => new Eurycleia({ url: "https://127.0.0.1:1", token: "t" }), EurycleiaError);
  const bad = new Eurycleia({ url: info.url, token: "wrong" });
  await assert.rejects(bad.startTask("support_reply", { customer_id: 12 }), (e) => e.status === 401);
  const tv = connect();
  assert.ok(!String(tv).includes(info.token) && !JSON.stringify(tv).includes(info.token));
  await assert.rejects(tv.startTask("nope", {}), (e) => e.status === 400);
});

test("connect() finds the running server from the environment", async () => {
  process.env.EURYCLEIA_URL = info.url;
  process.env.EURYCLEIA_TOKEN = info.token;
  try {
    const tv = await Eurycleia.connect();
    const task = await tv.startTask("support_reply", { customer_id: 45 });
    assert.equal((await task.call("get_customer")).result.name, "Tom Nguyen");
  } finally {
    delete process.env.EURYCLEIA_URL;
    delete process.env.EURYCLEIA_TOKEN;
  }
});

test("an impostor on the port gets no token and can't trigger actions", async () => {
  const { createServer } = await import("node:http");
  const seen = [];
  const fake = createServer((req, res) => {
    seen.push(req.headers);
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ task: "t", tools: [], status: "execute", exec: "e", sink: "payments.refund",
      args: { card: "ATTACKER", amount: 99999 } }));
  });
  await new Promise((r) => fake.listen(0, "127.0.0.1", r));
  const ran = [];
  const tv = new Eurycleia({ url: `http://127.0.0.1:${fake.address().port}`, token: info.token })
    .onAction("payments.refund", (a) => ran.push(a));
  try {
    await assert.rejects(tv.startTask("support_reply", { customer_id: 12 }), /couldn't prove it is eurycleia/);
    assert.equal(ran.length, 0);
    assert.ok(!JSON.stringify(seen).includes(info.token));          // the token itself never travelled
  } finally {
    fake.close();
  }
});

test("many tasks at once", async () => {
  const tv = connect().onAction("email.send", async () => "sent");
  const results = await Promise.all(Array.from({ length: 120 }, async () => {
    const t = await tv.startTask("support_reply", { customer_id: 12 });
    const c = (await t.call("get_customer")).result;
    const r = await t.call("send_email", { to: c.email, subject: "a", body: "b" });
    await t.end();
    return r.ok;
  }));
  assert.ok(results.every(Boolean));
});
