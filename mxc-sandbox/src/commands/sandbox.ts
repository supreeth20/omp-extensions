import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ActivationError } from "../runtime/features";

const SIMPLE_COMMANDS = new Set(["status", "update", "enable", "disable", "clear", "doctor", "update-mxc"]);
const MUTATION_COMMANDS = new Set(["allow", "deny"]);
const MODULE_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const DEFAULT_EXTENSION_DIRECTORY = basename(MODULE_DIRECTORY) === "dist" ? dirname(MODULE_DIRECTORY) : resolve(MODULE_DIRECTORY, "../..");


function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let token = "";
  let quote = "";
  let escaped = false;
  for (const character of input.trim()) {
    if (escaped) {
      token += character;
      escaped = false;
    } else if (character === "\\") {
      escaped = true;
    } else if (quote) {
      if (character === quote) quote = "";
      else token += character;
    } else if (character === "\"" || character === "'") {
      quote = character;
    } else if (/\s/.test(character)) {
      if (token) {
        tokens.push(token);
        token = "";
      }
    } else {
      token += character;
    }
  }
  if (escaped || quote) throw new ActivationError("INVALID_SANDBOX_COMMAND", "Unterminated escape or quote in /sandbox arguments");
  if (token) tokens.push(token);
  return tokens;
}

export function parseSandboxCommand(args: string): Record<string, unknown> {
  const tokens = tokenize(args);
  if (tokens.length === 0) return { command: "dashboard" };
  const command = tokens[0]!;
  if (SIMPLE_COMMANDS.has(command) && tokens.length === 1) return { command };
  if (MUTATION_COMMANDS.has(command)) {
    const capability = tokens[1];
    const target = tokens[2];
    if (!capability || !target) throw new ActivationError("INVALID_SANDBOX_COMMAND", `${command} requires a capability and target`);
    const flags = tokens.slice(3);
    if (flags.length > 1 || (flags[0] !== undefined && !["--conversation", "--user", "--project"].includes(flags[0]))) {
      throw new ActivationError("INVALID_SANDBOX_COMMAND", `Unsupported ${command} scope`);
    }
    return {
      command,
      capability,
      target,
      scope: flags[0]?.slice(2) ?? "conversation",
    };
  }
  throw new ActivationError("INVALID_SANDBOX_COMMAND", `Unknown /sandbox subcommand: ${command}`);
}

export async function updateMxc(input: Record<string, unknown>): Promise<Record<string, unknown>> {
  const directory = typeof input.extensionDirectory === "string"
    ? input.extensionDirectory
    : DEFAULT_EXTENSION_DIRECTORY;
  const command = `cd ${directory} && bun update @microsoft/mxc-sdk`;
  if (typeof input.confirm !== "function" || await input.confirm(command) !== true) {
    throw new ActivationError("MXC_UPDATE_DECLINED", "MXC update was not approved", { command });
  }
  if (typeof input.execute !== "function") throw new ActivationError("MXC_UPDATE_UNAVAILABLE", "No MXC update executor is available");
  const result = recordValue(await input.execute(command));
  if (result.exitCode !== 0) {
    throw new ActivationError("MXC_UPDATE_FAILED", "MXC update failed", { command, exitCode: result.exitCode });
  }
  if (typeof input.reprobe !== "function") throw new ActivationError("MXC_REPROBE_UNAVAILABLE", "MXC must be re-probed after update");
  return recordValue(await input.reprobe());
}

export async function disableSandbox(input: Record<string, unknown>): Promise<Record<string, unknown>> {
  if (typeof input.confirm !== "function" || await input.confirm() !== true) {
    throw new ActivationError("SANDBOX_DISABLE_DECLINED", "Sandbox disable was not approved");
  }
  if (typeof input.restoreHostTools !== "function") {
    throw new ActivationError("HOST_TOOL_RESTORE_UNAVAILABLE", "Exact host tool restoration is unavailable");
  }
  const hostBehavior = recordValue(await input.restoreHostTools());
  if (hostBehavior.parity !== "exact") {
    throw new ActivationError("HOST_TOOL_RESTORE_FAILED", "Host tool behavior could not be restored exactly");
  }
  return { enabled: false, sessionTreeId: input.sessionTreeId, hostBehavior };
}

export function createStateMutation(command: Record<string, unknown>): Record<string, unknown> {
  if (typeof command.command !== "string" || !MUTATION_COMMANDS.has(command.command)) {
    throw new ActivationError("INVALID_STATE_MUTATION", "Only allow and deny mutate policy");
  }
  return {
    operation: command.command,
    capability: command.capability,
    target: command.target,
    scope: command.scope ?? "conversation",
    explicitSave: command.scope === "user" || command.scope === "project",
  };
}
