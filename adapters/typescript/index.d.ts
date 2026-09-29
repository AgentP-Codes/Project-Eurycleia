// Copyright 2026 AgentP-Codes
// SPDX-License-Identifier: Apache-2.0

export interface ToolSpec {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

export type CallResult =
  | { ok: true; result: unknown }
  | { ok: false; blocked: true; reason: string }
  | { ok: false; blocked: false; error: string };

export type ActionHandler = (args: Record<string, unknown>) => unknown | Promise<unknown>;

export class TaskVaultError extends Error {
  status: number;
}

export class TaskVault {
  constructor(options: { url: string; token: string; timeoutMs?: number });
  static connect(options?: { timeoutMs?: number }): Promise<TaskVault>;
  /** Run an approved action in your code. `args` holds REAL values: don't log them or give them to the model. */
  onAction(sink: string, handler: ActionHandler): this;
  /** `trusted` must come from your app (e.g. the logged-in customer), never from the model. */
  startTask(template: string, trusted?: Record<string, string | number>): Promise<Task>;
}

export class Task {
  readonly tools: ToolSpec[];
  call(name: string, args?: Record<string, unknown>): Promise<CallResult>;
  callForModel(name: string, args?: Record<string, unknown>): Promise<string>;
  read(source: string, options?: { key?: string | number; fields?: string[] }): Promise<CallResult>;
  act(sink: string, args?: Record<string, unknown>): Promise<CallResult>;
  end(): Promise<void>;
  functions(): Array<{
    name: string;
    description: string;
    parameters: Record<string, unknown>;
    execute(args: Record<string, unknown>): Promise<string>;
  }>;
  openAITools(): Array<{ type: "function"; function: { name: string; description: string; parameters: Record<string, unknown> } }>;
  anthropicTools(): ToolSpec[];
  vercelTools<T>(helpers: { tool: (def: any) => T; jsonSchema: (schema: any) => any }): Record<string, T>;
}
