// Copyright 2026 AgentP-Codes
// SPDX-License-Identifier: Apache-2.0
//
// taskvault for TypeScript / JavaScript agents. No dependencies: Node 18+ built-ins only.
//
// A thin client for `taskvault api` running on the same computer. Every check, placeholder, pseudonym,
// audit entry and block happens in taskvault itself; this file only carries requests and runs the
// actions (email, refunds, ...) that taskvault has approved, using handlers you register.

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const LOCAL_HOSTS = new Set(["127.0.0.1", "localhost"]);
const sha256 = (data) => createHash("sha256").update(data).digest("hex");

/** Thrown when taskvault can't be reached or rejects a request (not for blocked actions: see CallResult). */
export class TaskVaultError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.name = "TaskVaultError";
    this.status = status;
  }
}

async function connectionInfo() {
  if (process.env.TASKVAULT_URL && process.env.TASKVAULT_TOKEN) {
    return { url: process.env.TASKVAULT_URL, token: process.env.TASKVAULT_TOKEN };
  }
  const home = process.env.TASKVAULT_HOME || join(homedir(), ".taskvault");
  try {
    const info = JSON.parse(await readFile(join(home, "api.json"), "utf8"));
    return { url: info.url, token: info.token };
  } catch {
    throw new TaskVaultError(
      "can't find a running taskvault: start `taskvault api`, or set TASKVAULT_URL and TASKVAULT_TOKEN");
  }
}

export class TaskVault {
  #url;
  #token;
  #handlers = new Map();
  #timeoutMs;

  /** Use `TaskVault.connect()` unless you pass the address and token yourself. */
  constructor({ url, token, timeoutMs = 600_000 }) {
    const u = new URL(url);
    if (u.protocol !== "http:" || !LOCAL_HOSTS.has(u.hostname)) {
      throw new TaskVaultError("taskvault api only runs on this computer (http://127.0.0.1)");
    }
    if (!token) throw new TaskVaultError("missing token");
    u.hostname = "127.0.0.1";          // the server listens on IPv4 only: never let "localhost" go to ::1
    this.#url = u.origin;
    this.#token = token;
    this.#timeoutMs = timeoutMs;
  }

  /** Connect using TASKVAULT_URL / TASKVAULT_TOKEN, or the file `taskvault api` writes. */
  static async connect(options = {}) {
    const tv = new TaskVault({ ...(await connectionInfo()), ...options });
    await tv.#request("GET", "/v1/health");
    return tv;
  }

  toString() {
    return `TaskVault(${this.#url})`;      // never the token
  }

  toJSON() {
    return { url: this.#url };
  }

  /**
   * Run an approved action in your own code. `handler(args)` gets the REAL values (e.g. the real card number)
   * only after taskvault has checked the action. Don't log them or pass them to the model; whatever you return
   * is masked by taskvault before the model sees it.
   */
  onAction(sink, handler) {
    if (typeof handler !== "function") throw new TypeError("handler must be a function");
    this.#handlers.set(sink, handler);
    return this;
  }

  /** Start a task. `trusted` must come from your app (e.g. the logged-in customer), never from the model. */
  async startTask(template, trusted = {}) {
    const out = await this.#request("POST", "/v1/tasks", { template, trusted });
    return new Task(this, out.task, out.tools);
  }

  // Every request is signed with the token (which itself never goes over the connection), and every reply
  // must carry the server's signature: a different program listening on the port can't pretend to be taskvault.
  async #request(method, path, body) {
    const text = body === undefined ? "" : JSON.stringify(body);
    const ts = String(Math.floor(Date.now() / 1000));
    const nonce = randomBytes(16).toString("hex");
    const mac = createHmac("sha256", this.#token)
      .update(["TV1", method, path, ts, nonce, sha256(text)].join("\n")).digest("hex");
    let res;
    try {
      res = await fetch(this.#url + path, {
        method,
        headers: { "content-type": "application/json", "x-taskvault-time": ts, "x-taskvault-nonce": nonce,
                   "x-taskvault-auth": mac },
        body: body === undefined ? undefined : text,
        redirect: "error",
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (e) {
      throw new TaskVaultError(`can't reach taskvault at ${this.#url}: ${e.cause?.code || e.name}`);
    }
    const raw = Buffer.from(await res.arrayBuffer());
    const expected = createHmac("sha256", this.#token)
      .update(["TV1-RESPONSE", nonce, String(res.status), sha256(raw)].join("\n")).digest();
    const got = Buffer.from(res.headers.get("x-taskvault-auth") || "", "hex");
    if (got.length !== expected.length || !timingSafeEqual(got, expected)) {
      throw new TaskVaultError(res.status === 401
        ? "taskvault refused the request: wrong token, or this computer's clock is off by more than 2 minutes"
        : `the server at ${this.#url} couldn't prove it is taskvault; not trusting its reply`, res.status);
    }
    let data;
    try {
      data = JSON.parse(raw.toString("utf8"));
    } catch {
      throw new TaskVaultError("unexpected reply from taskvault", res.status);
    }
    if (!res.ok) throw new TaskVaultError(data.error || `taskvault replied ${res.status}`, res.status);
    return data;
  }

  // Runs a task operation, performing any approved actions it hands back.
  async _run(taskId, op, body) {
    let out = await this.#request("POST", `/v1/tasks/${encodeURIComponent(taskId)}/${op}`, body);
    while (out.status === "execute") {
      const handler = this.#handlers.get(out.sink);
      let reply;
      if (!handler) {
        reply = { error: `no handler registered for ${out.sink} (use onAction)` };
      } else {
        try {
          const result = await handler(out.args);
          reply = { result: result === undefined ? null : result };
          JSON.stringify(reply);                     // fails here (not mid-request) if it can't be sent
        } catch (e) {
          reply = { error: `${e?.name || "Error"}: ${e?.message ?? e}` };
        }
      }
      out = await this.#request("POST", `/v1/exec/${encodeURIComponent(out.exec)}`, reply);
    }
    return out;
  }
}

/**
 * @typedef {{ok: true, result: any} | {ok: false, blocked: true, reason: string} |
 *           {ok: false, blocked: false, error: string}} CallResult
 */

export class Task {
  #tv;
  #id;

  constructor(tv, id, tools) {
    this.#tv = tv;
    this.#id = id;
    /** Tool definitions for this task: `{name, description, input_schema}` (JSON Schema). */
    this.tools = tools;
  }

  static #result(out) {
    if (out.status === "ok") return { ok: true, result: out.result };
    if (out.status === "blocked") return { ok: false, blocked: true, reason: out.reason };
    return { ok: false, blocked: false, error: out.message || "error" };
  }

  /** Call a tool the model asked for. Blocked calls come back as `{ok: false, blocked: true}`, not errors. */
  async call(name, args = {}) {
    return Task.#result(await this.#tv._run(this.#id, "call", { name, arguments: args }));
  }

  /** Same as `call`, as the text to hand back to the model. */
  async callForModel(name, args = {}) {
    const r = await this.call(name, args);
    if (r.ok) return typeof r.result === "string" ? r.result : JSON.stringify(r.result);
    return r.blocked ? `Blocked by taskvault: ${r.reason}` : `Error: ${r.error}`;
  }

  /** Read from a source directly (code-first apps). */
  async read(source, { key, fields } = {}) {
    return Task.#result(await this.#tv._run(this.#id, "read", { source, key, fields }));
  }

  /** Ask for an action directly (code-first apps). Runs your `onAction` handler if approved. */
  async act(sink, args = {}) {
    return Task.#result(await this.#tv._run(this.#id, "act", { sink, args }));
  }

  async end() {
    await this.#tv._run(this.#id, "end", {});
  }

  /** Framework-neutral: `[{name, description, parameters, execute(args) -> string}]`. */
  functions() {
    return this.tools.map((t) => ({
      name: t.name,
      description: t.description,
      parameters: t.input_schema,
      execute: (args) => this.callForModel(t.name, args ?? {}),
    }));
  }

  /** OpenAI chat-completions `tools` array (also Ollama, and most OpenAI-compatible servers). */
  openAITools() {
    return this.tools.map((t) => ({
      type: "function",
      function: { name: t.name, description: t.description, parameters: t.input_schema },
    }));
  }

  /** Anthropic Messages API `tools` array. */
  anthropicTools() {
    return this.tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.input_schema }));
  }

  /**
   * Vercel AI SDK tools. Pass the SDK's own helpers so this file needs no dependency:
   *   import { tool, jsonSchema } from "ai";
   *   const tools = task.vercelTools({ tool, jsonSchema });
   */
  vercelTools({ tool, jsonSchema }) {
    const out = {};
    for (const t of this.tools) {
      const schema = jsonSchema(t.input_schema);
      out[t.name] = tool({
        description: t.description,
        inputSchema: schema,     // AI SDK 5+
        parameters: schema,      // AI SDK 4
        execute: (args) => this.callForModel(t.name, args ?? {}),
      });
    }
    return out;
  }

  toString() {
    return "Task";
  }
}
