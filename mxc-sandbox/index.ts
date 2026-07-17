import { homedir, tmpdir } from "node:os";
import { release } from "node:os";
import { basename, delimiter, dirname, join, win32 } from "node:path";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { PermissionBroker } from "./src/broker/permission-broker";
import { createStateMutation, disableSandbox, parseSandboxCommand, updateMxc } from "./src/commands/sandbox";
import { interceptToolCall, sandboxRequest } from "./src/integration/tool-gate";
import { probeNativeMxcExecution } from "./src/mxc/probe";
import { loadMxcSdk, pruneLegacyDiscoveredPathGrants } from "./src/mxc/sdk";
import { assertPlatformPolicySupported } from "./src/mxc/config";
import { buildSandboxEnvironment } from "./src/policy/environment";
import { resolveNetworkPolicy } from "./src/policy/network";
import { loadProfileLayers, mergePolicyLayers } from "./src/profiles";
import { activateSandbox, ActivationError, probePublicOmpRuntime } from "./src/runtime/features";
import { createContainerId, executeShell, resolveShell } from "./src/runtime/process";
import type { StateRecord } from "./src/state";
import { handleSessionLifecycle, ProcessSensitiveApprovalStore, serializeState, snapshotBranchState } from "./src/state";
import { createDashboardPresentation, discoveredReadonlyGrants, getInitialSetupDefaults, createDashboardModel, createReenableModel, requireInteractiveUi, runSandboxDashboard } from "./src/ui";
import { deriveWindowsHostPreparation, windowsDoctor } from "./src/platform/windows";

interface ExtensionApi {
  registerCommand(name: string, definition: Record<string, unknown>): void;
  registerTool(definition: Record<string, unknown>): void;
  on(event: string, handler: (...arguments_: unknown[]) => unknown): void;
  appendEntry(customType: string, data: Record<string, unknown>): void;
  pi?: unknown;
  zod?: unknown;
  exec?: unknown;
}

export interface ExtensionDependencies {
  loadMxc?: () => Promise<Record<string, unknown> | null>;
  probeMxcExecution?: (input: Record<string, unknown>) => Promise<Record<string, unknown>>;
  platform?: string;
  homeDirectory?: string;
  spawnHost?: (
    executable: string,
    arguments_: string[],
    input: Record<string, unknown>,
    onUpdate: (update: Record<string, unknown>) => void,
  ) => Promise<Record<string, unknown>>;
}


const MODULE_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const EXTENSION_DIRECTORY = basename(MODULE_DIRECTORY) === "dist" ? dirname(MODULE_DIRECTORY) : MODULE_DIRECTORY;
const ADAPTED_TOOLS = new Set(["bash", "powershell", "read", "write", "edit", "ast_edit", "lsp", "web_search", "browser", "job", "sandbox_request"]);
const KNOWN_READ_ONLY_TOOLS = new Set(["grep", "glob"]);
const SANDBOX_COMMAND_COMPLETIONS = [
  { value: "status", label: "status", description: "Show whether sandboxing is enabled" },
  { value: "update", label: "update", description: "Review and change the active sandbox policy" },
  { value: "enable", label: "enable", description: "Probe installed MXC and turn on sandboxing" },
  { value: "disable", label: "disable", description: "Turn off sandboxing for this conversation" },
  { value: "doctor", label: "doctor", description: "Check MXC and OMP activation requirements" },
  { value: "clear", label: "clear", description: "Clear sandbox conversation state" },
  { value: "update-mxc", label: "update-mxc", description: "Update and re-probe the MXC SDK" },
  { value: "allow", label: "allow", description: "Allow a capability at a selected scope" },
  { value: "deny", label: "deny", description: "Deny a capability at a selected scope" },
] as const;

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function errorWithCode(code: string, message: string): Error & { code: string } {
  const error = new Error(message) as Error & { code: string };
  error.code = code;
  return error;
}

function observerIncrement(key: "spawned" | "installed" | "mxcLoaded"): void {
  const observer = recordValue((globalThis as Record<string, unknown>).__MXC_SANDBOX_TEST_OBSERVER__);
  if (typeof observer[key] === "number") observer[key] += 1;
}

function schema(api: ExtensionApi, kind: "string" | "boolean" | "number" | "record"): unknown {
  const zod = recordValue(api.zod);
  let value: unknown;
  if (kind === "record" && typeof zod.record === "function" && typeof zod.string === "function") value = zod.record(zod.string());
  else if (typeof zod[kind] === "function") value = (zod[kind] as () => unknown)();
  else value = kind === "record" ? { type: "object", additionalProperties: { type: "string" } } : { type: kind };
  const candidate = recordValue(value);
  return typeof candidate.optional === "function" ? candidate.optional() : value;
}

function objectSchema(api: ExtensionApi, shape: Record<string, unknown>): unknown {
  const zod = recordValue(api.zod);
  return typeof zod.object === "function" ? zod.object(shape) : { type: "object", properties: shape };
}


function toolInvocation(arguments_: unknown[]): { actual: boolean; input: Record<string, unknown>; context: Record<string, unknown> } {
  if (typeof arguments_[0] === "string") {
    const context = recordValue(arguments_[4]);
    return {
      actual: true,
      input: recordValue(arguments_[1]),
      context: { ...context, signal: arguments_[2], onShellUpdate: arguments_[3] },
    };
  }
  return { actual: false, input: recordValue(arguments_[0]), context: recordValue(arguments_[1]) };
}

function toolResult(value: Record<string, unknown>): Record<string, unknown> {
  const text = typeof value.preview === "string" ? value.preview : JSON.stringify(value);
  return { content: [{ type: "text", text }], details: value };
}

function powerShellToolResult(value: Record<string, unknown>, input: Record<string, unknown> = {}): Record<string, unknown> {
  const stdout = typeof value.stdout === "string" ? value.stdout : "";
  const stderr = typeof value.stderr === "string" ? value.stderr : "";
  const normalized = typeof value.preview === "string" ? value : { ...value, preview: `${stdout}${stderr}` || "(no output)" };
  const result = toolResult(normalized);
  const exitCode = typeof normalized.exitCode === "number" ? normalized.exitCode : undefined;
  return {
    ...result,
    details: {
      ...normalized,
      ...(typeof input.timeout === "number" ? {
        timeoutSeconds: typeof normalized.timeoutSeconds === "number" ? normalized.timeoutSeconds : input.timeout,
        requestedTimeoutSeconds: typeof normalized.requestedTimeoutSeconds === "number" ? normalized.requestedTimeoutSeconds : input.timeout,
      } : {}),
    },
    isError: exitCode !== undefined && exitCode !== 0 || normalized.timedOut === true || normalized.cancelled === true,
  };
}

function hostShellToolResult(value: Record<string, unknown>, input: Record<string, unknown>, powershell: boolean): Record<string, unknown> {
  const stdout = typeof value.stdout === "string" ? value.stdout : "";
  const stderr = typeof value.stderr === "string" ? value.stderr : "";
  const normalized = { ...value, preview: `${stdout}${stderr}` || "(no output)" };
  return powershell ? powerShellToolResult(normalized, input) : toolResult(normalized);
}

function normalizeHostExecResult(value: Record<string, unknown>): Record<string, unknown> {
  const exitCode = typeof value.exitCode === "number"
    ? value.exitCode
    : typeof value.code === "number" ? value.code : undefined;
  return {
    ...value,
    ...(exitCode === undefined ? {} : { exitCode }),
    ...(value.killed === true ? { cancelled: true } : {}),
  };
}

async function executeStreamingHostProcess(
  executable: string,
  arguments_: string[],
  input: Record<string, unknown>,
  onUpdate: (update: Record<string, unknown>) => void,
): Promise<Record<string, unknown>> {
  const environment = { ...process.env };
  for (const [name, value] of Object.entries(recordValue(input.env))) {
    if (typeof value === "string") environment[name] = value;
  }
  const started = Date.now();
  const processHandle = Bun.spawn({
    cmd: [executable, ...arguments_],
    ...(typeof input.cwd === "string" ? { cwd: input.cwd } : {}),
    env: environment,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  let stdout = "";
  let stderr = "";
  let preview = "";
  const pump = async (stream: ReadableStream<Uint8Array>, name: "stdout" | "stderr"): Promise<void> => {
    const reader = stream.getReader();
    const decoder = new TextDecoder();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const text = decoder.decode(value, { stream: true });
      if (name === "stdout") stdout += text;
      else stderr += text;
      preview += text;
      onUpdate({ stream: name, data: text });
    }
    const tail = decoder.decode();
    if (tail.length > 0) {
      if (name === "stdout") stdout += tail;
      else stderr += tail;
      preview += tail;
      onUpdate({ stream: name, data: tail });
    }
  };
  const signal = input.signal instanceof AbortSignal ? input.signal : undefined;
  let cancelled = signal?.aborted === true;
  let timedOut = false;
  const terminate = (): void => { processHandle.kill(); };
  const abort = (): void => { cancelled = true; terminate(); };
  signal?.addEventListener("abort", abort, { once: true });
  if (cancelled) terminate();
  const timeoutMs = typeof input.timeout === "number" && Number.isFinite(input.timeout) && input.timeout > 0
    ? input.timeout * 1000
    : undefined;
  const timeout = timeoutMs === undefined ? undefined : setTimeout(() => {
    timedOut = true;
    terminate();
  }, timeoutMs);
  try {
    const [exitCode] = await Promise.all([
      processHandle.exited,
      pump(processHandle.stdout, "stdout"),
      pump(processHandle.stderr, "stderr"),
    ]);
    return {
      preview: preview || "(no output)",
      stdout,
      stderr,
      exitCode,
      killed: cancelled || timedOut,
      cancelled,
      timedOut,
      wallTimeMs: Date.now() - started,
    };
  } finally {
    signal?.removeEventListener("abort", abort);
    if (timeout) clearTimeout(timeout);
  }
}

function powerShellRenderer(api: ExtensionApi): Record<string, unknown> {
  const pi = recordValue(api.pi);
  const fallback = recordValue(pi.bashToolRenderer);
  const configured = typeof pi.createShellRenderer === "function"
    ? recordValue(pi.createShellRenderer({
        resolveTitle: () => "PowerShell",
        resolveCommand: (args: unknown) => recordValue(args).command,
        resolveCwd: (args: unknown) => recordValue(args).cwd,
        resolveEnv: (args: unknown) => recordValue(args).env,
        showHeader: true,
      }))
    : {};
  const renderer = {
    ...fallback,
    ...configured,
  };
  if (typeof renderer.renderCall !== "function" || typeof renderer.renderResult !== "function") return {};
  return {
    renderCall: renderer.renderCall,
    renderResult: renderer.renderResult,
    mergeCallAndResult: renderer.mergeCallAndResult ?? true,
    inline: renderer.inline ?? true,
  };
}

function cumulativeShellUpdate(
  onUpdate: (update: Record<string, unknown>) => void,
  minimumIntervalMs = 100,
  details: Record<string, unknown> | undefined = undefined,
): (update: Record<string, unknown>) => void {
  let preview = "";
  let lastEmit = 0;
  return (update: Record<string, unknown>): void => {
    const data = update.data;
    if (typeof data === "string") preview += data;
    else if (data instanceof Uint8Array) preview += new TextDecoder().decode(data);
    const now = Date.now();
    if (minimumIntervalMs > 0 && now - lastEmit < minimumIntervalMs) return;
    lastEmit = now;
    onUpdate({ content: [{ type: "text", text: preview }], details });
  };
}

function notify(context: Record<string, unknown>, message: string, type: "info" | "warning" | "error" = "info"): void {
  const ui = recordValue(context.ui);
  if (typeof ui.notify === "function") ui.notify(message, type);
}

async function confirm(context: Record<string, unknown>, title: string, message: string): Promise<boolean> {
  if (context.hasUI !== true) return false;
  const ui = recordValue(context.ui);
  return typeof ui.confirm === "function" && await ui.confirm(title, message) === true;
}

async function loadMxcDeferred(): Promise<Record<string, unknown> | null> {
  observerIncrement("mxcLoaded");
  try {
    return recordValue(await loadMxcSdk());
  } catch {
    return null;
  }
}

function cleanPolicy(value: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
}

function autoBackgroundThreshold(context: Record<string, unknown>): number | undefined {
  const roots = [context, recordValue(context.config), recordValue(context.configuration), recordValue(context.settings), recordValue(context.preferences), recordValue(recordValue(context.pi).settings)];
  for (const root of roots) {
    const direct = root.autoBackgroundThresholdMs;
    if (typeof direct === "number" && Number.isFinite(direct) && direct > 0) return direct;
    const bash = recordValue(root.bash);
    if (typeof bash.autoBackgroundThresholdMs === "number" && Number.isFinite(bash.autoBackgroundThresholdMs) && bash.autoBackgroundThresholdMs > 0) return bash.autoBackgroundThresholdMs;
    if (typeof root.get === "function") {
      for (const key of ["bash.autoBackgroundThresholdMs", "autoBackgroundThresholdMs"]) {
        const configured = root.get(key);
        if (typeof configured === "number" && Number.isFinite(configured) && configured > 0) return configured;
      }
    }
  }
  return undefined;
}

function deriveGrantPolicy(basePolicy: Record<string, unknown>, approvedSensitiveNames: unknown, requests: Record<string, unknown>[], platformCapabilities: Record<string, unknown> = {}): { policy: Record<string, unknown>; sensitiveApprovedNames: string[] } {
  const policy = cleanPolicy(basePolicy);
  const filesystem = recordValue(policy.filesystem);
  const network = recordValue(policy.network);
  const environment = recordValue(policy.environment);
  const ui = recordValue(policy.ui);
  const trustedTools = Array.isArray(policy.trustedTools) ? policy.trustedTools.filter((name): name is string => typeof name === "string") : [];
  const sensitiveNames = Array.isArray(approvedSensitiveNames) ? approvedSensitiveNames.filter((name): name is string => typeof name === "string") : [];
  const overrides = Array.isArray(policy.explicitDenyOverrides) ? structuredClone(policy.explicitDenyOverrides) as unknown[] : [];
  const capabilityDenies = Array.isArray(policy.capabilityDenies) ? structuredClone(policy.capabilityDenies) as unknown[] : [];
  for (const request of requests) {
    const capability = request.capability;
    const value = request.value;
    const explicitlyDenied = capabilityDenies.some((item) => {
      const deny = recordValue(item);
      return deny.capability === capability && deny.value === value;
    });
    const explicitConversationOverride = request.explicitDenyOverride === true && request.scope === "conversation";
    const conversationOverride = explicitlyDenied && explicitConversationOverride;
    if (explicitlyDenied && !conversationOverride) throw errorWithCode("CAPABILITY_EXPLICITLY_DENIED", `Capability ${capability} for ${value} is explicitly denied`);
    if (typeof capability !== "string" || typeof value !== "string") throw errorWithCode("INVALID_SANDBOX_GRANT", "Capability and value are required");
    if (conversationOverride) overrides.push({ capability, value });
    if (capability === "read" || capability === "write") {
      const grants = Array.isArray(filesystem[capability]) ? filesystem[capability] as unknown[] : [];
      const grant = request.recursive === true
        ? { path: value, kind: "directory", recursive: true, permissions: [capability] }
        : { path: value, kind: "file", permissions: [capability] };
      filesystem[capability] = [...grants, grant];
      if (explicitConversationOverride) {
        const paths = Array.isArray(request.denyOverridePaths) ? request.denyOverridePaths.filter((path): path is string => typeof path === "string") : [value];
        for (const path of paths) overrides.push({ path, operation: capability });
      }
    } else if (capability === "internet") {
      const allowed = value === "true" || value === "allow";
      network.internet = allowed;
      network.unrestricted = allowed;
    } else if (capability === "local-network") network.localNetwork = value === "true" || value === "allow";
    else if (capability === "allowed-host" || capability === "blocked-host") {
      const key = capability === "allowed-host" ? "allowedHosts" : "blockedHosts";
      const values = Array.isArray(network[key]) ? network[key] as unknown[] : [];
      network[key] = [...new Set([...values, value])];
      if (capability === "allowed-host") network.internet = true;
    } else if (capability === "sensitive-environment-name") {
      sensitiveNames.push(value);
      if (request.scope === "user") {
        const persisted = Array.isArray(environment.persistSensitiveNames) ? environment.persistSensitiveNames as unknown[] : [];
        environment.persistSensitiveNames = [...new Set([...persisted, value])];
      }
    } else if (capability === "trusted-tool") trustedTools.push(value);
    else if (capability === "ui" && ["allowWindows", "clipboardRead", "clipboardWrite", "inputInjection"].includes(value)) ui[value] = true;
    else throw errorWithCode("INVALID_SANDBOX_GRANT", `Unsupported sandbox capability: ${capability}`);
  }
  policy.filesystem = filesystem;
  const networkResolution = resolveNetworkPolicy(network, platformCapabilities);
  policy.network = networkResolution.activation === "ready" ? recordValue(networkResolution.effective) : network;
  policy.environment = environment;
  policy.ui = ui;
  policy.trustedTools = [...new Set(trustedTools)];
  policy.explicitDenyOverrides = overrides.filter((candidate, index, values) => values.findIndex((item) => JSON.stringify(item) === JSON.stringify(candidate)) === index);
  policy.capabilityDenies = capabilityDenies.filter((item) => {
    const deny = recordValue(item);
    return !overrides.some((override) => {
      const exact = recordValue(override);
      return exact.capability === deny.capability && exact.value === deny.value;
    });
  });
  return { policy, sensitiveApprovedNames: [...new Set(sensitiveNames)] };
}

function profileDocument(policy: Record<string, unknown>, source: "user" | "project"): Record<string, unknown> {
  const filesystem = recordValue(policy.filesystem);
  const pathRules = (value: unknown): unknown[] => Array.isArray(value)
    ? value.flatMap((entry): unknown[] => {
        if (typeof entry === "string") return [entry];
        const grant = recordValue(entry);
        if (typeof grant.path !== "string" || grant.path.length === 0) return [];
        const directory = grant.kind === "directory" || grant.recursive === true;
        return [{ path: grant.path, kind: directory ? "directory" : "file", ...(grant.recursive === true ? { recursive: true } : {}), ...(Array.isArray(grant.permissions) ? { permissions: grant.permissions.filter((permission): permission is string => permission === "read" || permission === "write") } : {}) }];
      })
    : [];
  const sourceEnvironment = recordValue(policy.environment);
  const environment = Object.fromEntries(["persistSensitiveNames", "sensitive", "nonSensitive"].flatMap((key) => {
    const names = Array.isArray(sourceEnvironment[key]) ? sourceEnvironment[key].filter((name): name is string => typeof name === "string") : [];
    return names.length > 0 ? [[key, names]] : [];
  })) as Record<string, unknown>;
  if (source === "project") delete environment.persistSensitiveNames;
  return {
    version: 1,
    filesystem: { read: pathRules(filesystem.read), write: pathRules(filesystem.write), deny: pathRules(filesystem.deny) },
    network: cleanPolicy(recordValue(policy.network)),
    environment,
    ui: cleanPolicy(recordValue(policy.ui)),
    trustedTools: Array.isArray(policy.trustedTools) ? policy.trustedTools.filter((name): name is string => typeof name === "string") : [],
    capabilityDenies: Array.isArray(policy.capabilityDenies) ? structuredClone(policy.capabilityDenies) : [],
    ...(Object.keys(recordValue(policy.mxcOverrides)).length > 0 ? { mxcOverrides: cleanPolicy(recordValue(policy.mxcOverrides)) } : {}),
  };
}

async function saveProfile(path: string, policy: Record<string, unknown>, source: "user" | "project"): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(profileDocument(policy, source), null, 2)}\n`, { mode: 0o600 });
}

function applyProfileLayerDelta(layer: Record<string, unknown>, before: Record<string, unknown>, after: Record<string, unknown>): Record<string, unknown> {
  const key = (value: unknown): string => JSON.stringify(value);
  const apply = (current: unknown, prior: unknown, next: unknown): unknown => {
    if (key(prior) === key(next)) return structuredClone(current);
    if (Array.isArray(prior) && Array.isArray(next)) {
      const removed = new Set(prior.filter((item) => !next.some((candidate) => key(candidate) === key(item))).map(key));
      const additions = next.filter((item) => !prior.some((candidate) => key(candidate) === key(item)));
      const existing = Array.isArray(current) ? current.filter((item) => !removed.has(key(item))) : [];
      return [...existing, ...additions.filter((item) => !existing.some((candidate) => key(candidate) === key(item)))].map((item) => structuredClone(item));
    }
    if (prior && next && typeof prior === "object" && typeof next === "object" && !Array.isArray(prior) && !Array.isArray(next)) {
      const output = cleanPolicy(recordValue(current));
      const priorRecord = recordValue(prior);
      const nextRecord = recordValue(next);
      for (const property of new Set([...Object.keys(priorRecord), ...Object.keys(nextRecord)])) {
        if (!(property in nextRecord)) delete output[property];
        else output[property] = apply(output[property], priorRecord[property], nextRecord[property]);
      }
      return output;
    }
    return structuredClone(next);
  };
  return recordValue(apply(layer, before, after));
}

type InteractiveParentEntry = {
  owner: object;
  treeId: string;
  agentId: string;
  context: Record<string, unknown>;
  tail: Promise<void>;
  parent: Record<string, unknown>;
};

const sessionTreeParentRegistry = new Map<string, InteractiveParentEntry>();

function contextSessionTreeId(context: Record<string, unknown>): string | undefined {
  if (typeof context.sessionTreeId === "string" && context.sessionTreeId.length > 0) return context.sessionTreeId;
  const manager = recordValue(context.sessionManager);
  const tree = typeof manager.getSessionTreeId === "function" ? manager.getSessionTreeId() : undefined;
  if (typeof tree === "string" && tree.length > 0) return tree;
  const session = typeof manager.getSessionId === "function" ? manager.getSessionId() : context.sessionId;
  return typeof session === "string" && session.length > 0 ? session : undefined;
}

function permissionChoiceLabel(choice: string, details: Record<string, unknown>): string {
  const targets = Array.isArray(details.targets) ? details.targets.filter((value): value is string => typeof value === "string") : [];
  const broaderTargets = Array.isArray(details.broaderTargets) ? details.broaderTargets.filter((value): value is string => typeof value === "string") : [];
  const operation = typeof details.operation === "string" ? details.operation : "requested";
  if (choice === "allow-operation-once") return `Allow this ${operation} operation once`;
  if (choice === "allow-exact-conversation") return `Allow this exact path for this conversation: ${targets.join(", ")}`;
  if (choice === "allow-parent-or-workspace-conversation") return `Allow this directory recursively for this conversation: ${broaderTargets.join(", ")}`;
  if (choice === "allow-action-once") return "Allow this action once";
  if (choice === "grant-recursive-workspace-write") return "Allow recursive workspace writes for this conversation";
  if (choice === "allow-once") return "Allow once";
  if (choice === "allow-conversation") return "Allow for this conversation";
  if (choice === "deny") return "Deny";
  return choice;
}

async function promptFromInteractiveContext(context: Record<string, unknown>, request: Record<string, unknown>): Promise<Record<string, unknown>> {
  const ui = recordValue(context.ui);
  if (context.hasUI !== true) throw errorWithCode("NO_INTERACTIVE_PROMPT", "No interactive permission prompt is available");
  const details = recordValue(request.details);
  const title = typeof request.title === "string"
    ? `${request.title} ${JSON.stringify({ agentId: request.agentId, operation: request.operation, target: request.target, ...details })}`
    : request.operation === "shell"
      ? `Approve atomic sandbox run? ${JSON.stringify({ agentId: request.agentId, requestingAgent: request.agentId, operation: request.operation, command: request.target, capabilityExpansion: request.capabilityExpansion })}`
      : `Approve sandbox permission? ${JSON.stringify({ agentId: request.agentId, operation: request.operation, target: request.target, ...details })}`;
  const choices = Array.isArray(request.choices) && request.choices.every((choice) => typeof choice === "string")
    ? request.choices as string[]
    : ["allow-once", "allow-conversation", "deny"];
  if (typeof ui.select === "function") {
    const labels = choices.map((choice) => permissionChoiceLabel(choice, details));
    const displayed = await ui.select(title, labels);
    const labelIndex = labels.indexOf(String(displayed));
    const selected = labelIndex >= 0 ? choices[labelIndex]! : choices.includes(String(displayed)) ? String(displayed) : "deny";
    const decision = selected === "deny" || selected === "Deny"
      ? "deny"
      : selected.includes("conversation") || selected.startsWith("grant-")
        ? "allow-conversation"
        : "allow-once";
    return { decision, selected };
  }
  if (typeof ui.confirm !== "function") throw errorWithCode("NO_INTERACTIVE_PROMPT", "No interactive permission prompt is available");
  const allowed = await ui.confirm(title, JSON.stringify(details));
  return { decision: allowed === true ? "allow-conversation" : "deny", selected: allowed === true ? "allow-conversation" : choices.at(-1) };
}
export default function mxcSandboxExtension(api: ExtensionApi, dependencies: ExtensionDependencies = {}): void {
  const runtimePlatform = typeof dependencies.platform === "string" ? dependencies.platform : process.platform;
  const profileHome = typeof dependencies.homeDirectory === "string" ? dependencies.homeDirectory : homedir();
  const state: StateRecord = {
    enabled: false,
    restorationFailed: false,
    priorConversationPolicy: false,
    filesystem: { read: [], write: [], deny: [] },
    network: { internet: false, localNetwork: false },
    ui: { allowWindows: true, clipboardRead: false, clipboardWrite: false, inputInjection: false },
    environment: {},
    trustedTools: [],
    capabilityDenies: [],
    processIdentity: crypto.randomUUID(),
    runtimeReadonlyGrants: [],
  };
  const updateSandboxIndicator = (context: Record<string, unknown>, clear = false): void => {
    const ui = recordValue(context.ui);
    if (context.hasUI !== true || typeof ui.setWidget !== "function") return;
    if (typeof ui.setStatus === "function") (ui.setStatus as (key: string, value: undefined) => unknown)("mxc-sandbox", undefined);
    const options = { placement: "belowEditor" };
    if (clear || (state.enabled !== true && state.restorationFailed !== true)) {
      (ui.setWidget as (key: string, content: undefined, options: Record<string, unknown>) => unknown)("mxc-sandbox", undefined, options);
      return;
    }
    const failed = state.restorationFailed === true;
    const label = failed ? "sandbox · error" : "sandbox · enabled";
    const color = failed ? "error" : "success";
    const factory = (_tui: unknown, themeValue: unknown): Record<string, unknown> => ({
      render: (width: number): string[] => {
        const theme = recordValue(themeValue);
        const themeFg = theme.fg;
        const fg = typeof themeFg === "function" ? (color: string, text: string) => (themeFg as (this: unknown, color: string, text: string) => string).call(themeValue, color, text) : (_color: string, text: string) => text;
        const lead = "╰─ ";
        const trail = ` ${"─".repeat(Math.max(0, width - lead.length - label.length - 1))}`;
        return [fg("borderMuted", lead) + fg(color, label) + fg("borderMuted", trail)];
      },
    });
    (ui.setWidget as (key: string, content: unknown, options: Record<string, unknown>) => unknown)("mxc-sandbox", factory, options);
  };


  const sensitiveApprovals = new ProcessSensitiveApprovalStore();
  const promptContexts = new Map<string, Record<string, unknown>>();
  const oneTimeCapabilities: Record<string, unknown>[] = [];
  const registryOwner = {};
  const registeredParentTrees = new Set<string>();
  const registeredParentAgents = new Map<string, string>();
  const registerInteractiveParent = (context: Record<string, unknown>): void => {
    if (context.hasUI !== true) return;
    const ui = recordValue(context.ui);
    if (typeof ui.select !== "function" && typeof ui.confirm !== "function") return;
    const treeId = contextSessionTreeId(context);
    if (!treeId) return;
    const agentId = typeof context.agentId === "string" && context.agentId.length > 0 ? context.agentId : treeId;
    const entry = { owner: registryOwner, treeId, agentId, context, tail: Promise.resolve(), parent: {} } as InteractiveParentEntry;
    entry.parent = {
      interactive: true,
      treeId,
      agentId,
      request: (request: Record<string, unknown>): Promise<Record<string, unknown>> => {
        const operation = () => promptFromInteractiveContext(entry.context, request);
        const scheduled = entry.tail.then(operation, operation);
        entry.tail = scheduled.then(() => undefined, () => undefined);
        return scheduled;
      },
    };
    sessionTreeParentRegistry.set(treeId, entry);
    registeredParentTrees.add(treeId);
    registeredParentAgents.set(treeId, agentId);
  };
  const unregisterInteractiveParent = (treeId?: string): void => {
    const trees = treeId ? [treeId] : [...registeredParentTrees];
    for (const candidate of trees) {
      if (sessionTreeParentRegistry.get(candidate)?.owner === registryOwner) sessionTreeParentRegistry.delete(candidate);
      registeredParentTrees.delete(candidate);
      registeredParentAgents.delete(candidate);
    }
  };
  let pendingBranchSnapshot: StateRecord | undefined;
  const shellAdapterRegistered = typeof api.registerTool === "function" && typeof api.exec === "function";

  const sessionTreeIdentity = (context: Record<string, unknown>): string => {
    if (typeof context.sessionTreeId === "string" && context.sessionTreeId.length > 0) return context.sessionTreeId;
    const manager = recordValue(context.sessionManager);
    const tree = typeof manager.getSessionTreeId === "function" ? manager.getSessionTreeId() : undefined;
    if (typeof tree === "string" && tree.length > 0) return tree;
    const session = typeof manager.getSessionId === "function" ? manager.getSessionId() : context.sessionId;
    if (typeof session === "string" && session.length > 0) return session;
    if (typeof state.sessionTreeId === "string" && state.sessionTreeId.length > 0) return state.sessionTreeId;
    throw errorWithCode("SESSION_TREE_IDENTITY_UNRESOLVED", "The conversation/session-tree identity could not be resolved");
  };
  const permissionBroker = new PermissionBroker({
    prompt: async (request) => promptFromInteractiveContext(promptContexts.get(String(request.requestId)) ?? {}, request),
    resolveParent: (request) => {
      const treeId = typeof request.sessionTreeId === "string" ? request.sessionTreeId : undefined;
      if (!treeId) return undefined;
      const entry = sessionTreeParentRegistry.get(treeId);
      if (!entry) return undefined;
      if (typeof request.parentAgentId === "string" && request.parentAgentId !== entry.agentId) return undefined;
      return entry.parent;
    },
    promptParent: async (parent, request) => {
      const broker = recordValue(parent);
      if (typeof broker.request !== "function") throw errorWithCode("NO_INTERACTIVE_PARENT", "No interactive parent broker request surface is available");
      return recordValue(await broker.request(request));
    },
  });
  state.parentBroker = permissionBroker;
  const persist = (): void => api.appendEntry("mxc-sandbox/state", serializeState(state));
  const editablePolicy = (): Record<string, unknown> => {
    const filesystem = cleanPolicy(recordValue(state.filesystem));
    for (const key of ["read", "write", "deny"]) {
      if (!Array.isArray(filesystem[key])) continue;
      filesystem[key] = filesystem[key].map((value) => {
        const rule = recordValue(value);
        return rule.kind === "directory" && rule.recursive !== true ? { ...rule, recursive: true } : value;
      });
    }
    return {
      filesystem,
      network: cleanPolicy(recordValue(state.network)),
      ui: cleanPolicy(recordValue(state.ui)),
      environment: cleanPolicy(recordValue(state.environment)),
      mxcOverrides: cleanPolicy(recordValue(state.mxcOverrides)),
      trustedTools: Array.isArray(state.trustedTools) ? [...state.trustedTools] : [],
      capabilityDenies: Array.isArray(state.capabilityDenies) ? structuredClone(state.capabilityDenies) : [],
      explicitDenyOverrides: Array.isArray(state.explicitDenyOverrides) ? cleanPolicy({ values: state.explicitDenyOverrides }).values : [],
    };
  };
  const currentPolicy = (): Record<string, unknown> => {
    const policy = editablePolicy();
    const filesystem = recordValue(policy.filesystem);
    const editableRead = Array.isArray(filesystem.read) ? filesystem.read : [];
    const runtimeRead = Array.isArray(state.runtimeReadonlyGrants) ? state.runtimeReadonlyGrants : [];
    const editablePaths = new Set(editableRead.flatMap((grant): string[] => typeof grant === "string" ? [grant] : typeof recordValue(grant).path === "string" ? [String(recordValue(grant).path)] : []));
    filesystem.read = [...editableRead, ...runtimeRead.filter((grant) => !editablePaths.has(String(recordValue(grant).path ?? "")))];
    policy.filesystem = filesystem;
    return policy;
  };
  const applyEffectivePolicy = (policy: Record<string, unknown>): void => {
    const filesystem = cleanPolicy(recordValue(policy.filesystem));
    const runtimePaths = new Set((Array.isArray(state.runtimeReadonlyGrants) ? state.runtimeReadonlyGrants : []).flatMap((grant): string[] => typeof recordValue(grant).path === "string" ? [String(recordValue(grant).path)] : []));
    if (Array.isArray(filesystem.read) && runtimePaths.size > 0) filesystem.read = filesystem.read.filter((grant) => !runtimePaths.has(typeof grant === "string" ? grant : String(recordValue(grant).path ?? "")));
    state.filesystem = filesystem;
    state.network = cleanPolicy(recordValue(policy.network));
    state.ui = cleanPolicy(recordValue(policy.ui));
    state.environment = cleanPolicy(recordValue(policy.environment));
    state.mxcOverrides = cleanPolicy(recordValue(policy.mxcOverrides));
    state.trustedTools = Array.isArray(policy.trustedTools) ? policy.trustedTools.filter((name): name is string => typeof name === "string") : [];
    state.capabilityDenies = Array.isArray(policy.capabilityDenies) ? structuredClone(policy.capabilityDenies) : [];
    state.explicitDenyOverrides = Array.isArray(policy.explicitDenyOverrides) ? structuredClone(policy.explicitDenyOverrides) : [];
  };
  const setRuntimeReadonlyPaths = (paths: unknown): void => {
    const runtime = discoveredReadonlyGrants(Array.isArray(paths) ? paths.filter((path): path is string => typeof path === "string" && path.length > 0) : []);
    state.runtimeReadonlyGrants = runtime;
    state.policyRevision = 3;
    const filesystem = recordValue(state.filesystem);
    const runtimePaths = new Set(runtime.map((grant) => String(grant.path)));
    const existingRead = Array.isArray(filesystem.read) ? filesystem.read : [];
    const filteredRead = existingRead.filter((grant) => !runtimePaths.has(typeof grant === "string" ? grant : String(recordValue(grant).path ?? "")));
    filesystem.read = filteredRead;
    state.runtimePolicyChanged = filteredRead.length !== existingRead.length;
    state.filesystem = filesystem;
  };
  const applyGrants = async (requests: Record<string, unknown>[]): Promise<void> => {
    if (requests.some((request) => request.scope === "project") && (state.projectTrust !== true || typeof state.repositoryRoot !== "string")) {
      throw errorWithCode("UNTRUSTED_PROJECT_PROFILE", "Project grants require current-conversation trust");
    }
    if (requests.some((request) => request.capability === "local-network")
      && recordValue(state.platformCapabilities).independentLocalNetwork !== true
      && recordValue(state.platformCapabilities).coupledNetwork !== true) {
      throw errorWithCode("LOCAL_NETWORK_CAPABILITY_UNPROVEN", "Local-network grants require a successful native traffic probe attestation");
    }
    const treeId = requests.map((request) => request.sessionTreeId).find((value): value is string => typeof value === "string") ?? (typeof state.sessionTreeId === "string" ? state.sessionTreeId : undefined);
    const approvedNames = treeId ? sensitiveApprovals.get(treeId) : [];
    const derived = deriveGrantPolicy(currentPolicy(), approvedNames, requests, recordValue(state.platformCapabilities));
    applyEffectivePolicy(derived.policy);
    if (treeId) state.sensitiveApprovedNames = sensitiveApprovals.approve(treeId, derived.sensitiveApprovedNames);
    for (const scope of ["user", "project"] as const) {
      const scopedRequests = requests.filter((request) => request.scope === scope);
      if (scopedRequests.length === 0) continue;
      if (scope === "project" && (state.projectTrust !== true || typeof state.repositoryRoot !== "string")) {
        throw errorWithCode("UNTRUSTED_PROJECT_PROFILE", "Project grants require current-conversation trust");
      }
      const profiles = recordValue(state.profiles);
      const layer = cleanPolicy(recordValue(profiles[scope]));
      const layerPolicy = deriveGrantPolicy(layer, [], scopedRequests, recordValue(state.platformCapabilities)).policy;
      await saveProfile(scope === "user" ? join(profileHome, ".omp", "agent", "sandbox.yml") : join(String(state.repositoryRoot), ".omp", "sandbox.yml"), layerPolicy, scope);
      state.profiles = { ...profiles, [scope]: layerPolicy };
    }
    persist();
  };
  const applyGrant = async (request: Record<string, unknown>): Promise<void> => applyGrants([request]);
  const profileSensitiveNames = (): string[] => {
    const user = recordValue(recordValue(state.profiles).user);
    const environment = recordValue(user.environment);
    return Array.isArray(environment.persistSensitiveNames) ? environment.persistSensitiveNames.filter((name): name is string => typeof name === "string") : [];
  };
  const bindSensitiveApprovals = (context: Record<string, unknown>): string[] => {
    const treeId = sessionTreeIdentity(context);
    state.sessionTreeId = treeId;
    const names = sensitiveApprovals.get(treeId, profileSensitiveNames());
    state.sensitiveApprovedNames = names;
    return names;
  };
  const requesterIdentity = (context: Record<string, unknown>): string => {
    if (typeof context.agentId === "string" && context.agentId.length > 0) return context.agentId;
    const sessionManager = recordValue(context.sessionManager);
    const sessionId = typeof sessionManager.getSessionId === "function" ? sessionManager.getSessionId() : context.sessionId;
    const matches = Array.isArray(context.liveMatches) ? context.liveMatches.map(recordValue).filter((match) => match.live === true && match.sessionId === sessionId) : [];
    if (matches.length === 1 && typeof matches[0]!.agentId === "string") return matches[0]!.agentId as string;
    if (matches.length > 1) throw errorWithCode("REQUESTING_AGENT_UNRESOLVED", "Multiple live requesting agents matched this session");
    if (typeof sessionId === "string" && sessionId.length > 0) return sessionId;
    throw errorWithCode("REQUESTING_AGENT_UNRESOLVED", "The requesting session identity could not be resolved");
  };
  const promptRequesterIdentity = (context: Record<string, unknown>): string => {
    try {
      return requesterIdentity(context);
    } catch (error) {
      const interactive = context.hasUI === true || typeof recordValue(context.ui).select === "function" || typeof recordValue(context.ui).confirm === "function";
      const treeId = contextSessionTreeId(context) ?? (typeof state.sessionTreeId === "string" ? state.sessionTreeId : undefined);
      const agentId = treeId ? registeredParentAgents.get(treeId) : registeredParentAgents.size === 1 ? registeredParentAgents.values().next().value : undefined;
      if (interactive && typeof agentId === "string") return agentId;
      throw error;
    }
  };
  const brokeredSelection = async (context: Record<string, unknown>, operation: string, details: Record<string, unknown>, choices: string[], title: string): Promise<unknown> => {
    const ui = recordValue(context.ui);
    if (choices.length === 2 && choices[0] === "Approve" && choices[1] === "Deny" && typeof ui.confirm === "function") return await ui.confirm(title, JSON.stringify(details)) === true ? choices[0] : choices[1];
    if (typeof ui.select === "function") {
      const labels = choices.map((choice) => permissionChoiceLabel(choice, details));
      const displayed = await ui.select(`${title} ${JSON.stringify(details)}`, labels);
      const labelIndex = labels.indexOf(String(displayed));
      return labelIndex >= 0 ? choices[labelIndex] : choices.includes(String(displayed)) ? displayed : choices.at(-1);
    }
    if (typeof ui.confirm === "function") return await ui.confirm(title, JSON.stringify(details)) === true ? choices[0] : choices.at(-1);
    const result = recordValue(await permissionBroker.request({
      requestId: crypto.randomUUID(),
      agentId: promptRequesterIdentity(context),
      sessionTreeId: sessionTreeIdentity(context),
      headless: true,
      operation,
      target: `${String(details.command ?? details.action ?? details.operation ?? operation)}:${crypto.randomUUID()}`,
      title,
      details,
      choices,
    }));
    return result.selected;
  };
  const exactShellDetails = (shell: "bash" | "powershell", invocation: { input: Record<string, unknown> }, agentId: unknown, details: Record<string, unknown>): Record<string, unknown> => ({
    ...details,
    shell,
    command: invocation.input.command,
    cwd: invocation.input.cwd ?? process.cwd(),
    requestingAgent: agentId,
    timeout: invocation.input.timeout,
    pty: invocation.input.pty === true,
    async: invocation.input.async === true,
    outsideSandbox: invocation.input.outsideSandbox === true,
    environmentNames: Object.keys(recordValue(invocation.input.env)),
  });
  const storeOneTimeCapability = (result: Record<string, unknown>, treeId: string, agentId: string): void => {
    const token = recordValue(result.capabilityToken);
    if (result.oneTime !== true || typeof token.capabilityId !== "string" || typeof result.capability !== "string" || typeof result.value !== "string") return;
    oneTimeCapabilities.push({
      treeId,
      agentId,
      operation: result.capability,
      target: result.value,
      requestId: result.requestId,
      token,
      request: { capability: result.capability, value: result.value, scope: "once", ...(result.recursive === true ? { recursive: true, kind: "directory" } : {}) },
    });
  };
  const consumeOneTimeCapability = async (context: Record<string, unknown>, requested: Record<string, unknown>): Promise<boolean> => {
    let agentId: string;
    try {
      agentId = requesterIdentity(context);
    } catch {
      return false;
    }
    const treeId = contextSessionTreeId(context) ?? (typeof state.sessionTreeId === "string" ? state.sessionTreeId : undefined);
    if (!treeId) return false;
    const index = oneTimeCapabilities.findIndex((candidate) => candidate.treeId === treeId && candidate.agentId === agentId
      && candidate.operation === requested.capability && candidate.target === requested.value);
    if (index < 0) return false;
    const capability = oneTimeCapabilities[index]!;
    const consumed = recordValue(await permissionBroker.request({
      requestId: capability.requestId,
      agentId,
      operation: capability.operation,
      target: capability.target,
      consumeCapability: capability.token,
    }));
    oneTimeCapabilities.splice(index, 1);
    return consumed.allowed === true;
  };
  const consumeShellOneTimeCapabilities = async (context: Record<string, unknown>): Promise<Record<string, unknown>[]> => {
    const shellCapabilities = new Set(["read", "write", "internet", "local-network", "allowed-host", "sensitive-environment-name", "ui"]);
    const agentId = requesterIdentity(context);
    const treeId = sessionTreeIdentity(context);
    const selected = oneTimeCapabilities.filter((candidate) => candidate.treeId === treeId && candidate.agentId === agentId && shellCapabilities.has(String(candidate.operation)));
    if (selected.length === 0) return [];
    for (let index = oneTimeCapabilities.length - 1; index >= 0; index -= 1) {
      if (selected.includes(oneTimeCapabilities[index]!)) oneTimeCapabilities.splice(index, 1);
    }
    const consumed = await Promise.all(selected.map(async (capability) => recordValue(await permissionBroker.request({
      requestId: capability.requestId,
      agentId,
      operation: capability.operation,
      target: capability.target,
      consumeCapability: capability.token,
    }))));
    if (!consumed.every((result) => result.allowed === true)) {
      throw errorWithCode("ONE_TIME_CAPABILITY_CONSUMPTION_FAILED", "Shell pregrants could not be consumed atomically");
    }
    return selected.map((capability) => cleanPolicy(recordValue(capability.request)));
  };
  const clearOneTimeCapabilities = (treeId?: string): void => {
    if (!treeId) return;
    for (let index = oneTimeCapabilities.length - 1; index >= 0; index -= 1) {
      if (oneTimeCapabilities[index]?.treeId === treeId) oneTimeCapabilities.splice(index, 1);
    }
  };
  const ownership = (context: Record<string, unknown>): Record<string, unknown> => {
    const sessionManager = recordValue(context.sessionManager);
    const sessionId = typeof sessionManager.getSessionId === "function" ? sessionManager.getSessionId() : context.sessionId;
    const agentId = requesterIdentity(context);
    const scopedManager = context.scopedManager;
    const liveMatches = Array.isArray(context.liveMatches) ? context.liveMatches : [];
    return { sessionId, agentId, scopedManager, liveMatches };
  };
  const activationDependencies = (context: Record<string, unknown>): Record<string, unknown> => {
    let mxcExecutionVerified = false;
    return {
      loadMxc: dependencies.loadMxc ?? loadMxcDeferred,
      confirmInstall: async (installationCommand: unknown) => confirm(context, "Install MXC dependency?", String(installationCommand)),
      executeInstall: async () => {
        if (typeof api.exec !== "function") throw errorWithCode("DEPENDENCY_INSTALL_UNAVAILABLE", "OMP exec is unavailable");
        observerIncrement("installed");
        return (api.exec as (...arguments_: unknown[]) => unknown)("bun", ["add", "@microsoft/mxc-sdk@^0.7.0"], { cwd: EXTENSION_DIRECTORY });
      },
      probeMxcExecution: async (probeRequest: unknown) => {
        const requested = recordValue(probeRequest);
        const configuredShell = resolveShell({
          platform: runtimePlatform,
          requested: "bash",
          configuredShell: typeof context.configuredShell === "string" ? context.configuredShell : process.env.SHELL,
          discovered: context.discoveredExecutables,
        });
        const trafficShell = runtimePlatform === "win32"
          ? resolveShell({
              platform: runtimePlatform,
              requested: "powershell",
              configuredShell: typeof context.configuredShell === "string" ? context.configuredShell : process.env.SHELL,
              discovered: context.discoveredExecutables,
            })
          : configuredShell;
        const shell = runtimePlatform === "win32"
          ? {
              executable: win32.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe"),
              args: ["/d", "/s", "/c"],
              dialect: "cmd",
              ui: { allowWindows: false, clipboardRead: false, clipboardWrite: false, inputInjection: false },
            }
          : configuredShell;
        const hostEnvironment = Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
        const cwd = typeof context.cwd === "string" ? context.cwd : process.cwd();
        const capabilities = recordValue(requested.platformCapabilities);
        const compatibility = requested.windowsMode === "compatibility" && requested.allowDaclMutation === true;
        const shellRead = runtimePlatform === "win32"
          ? { path: win32.dirname(shell.executable), kind: "directory", recursive: true }
          : { path: shell.executable, kind: "file" };
        const probeInput = {
          ...(runtimePlatform === "win32"
            ? {
                containerId: createContainerId(),
                trafficShell,
                env: buildSandboxEnvironment(hostEnvironment, {}),
                requiredReadonlyPaths: [...new Set([win32.dirname(configuredShell.executable), win32.dirname(trafficShell.executable)])],
              }
            : { env: { PATH: process.env.PATH ?? "" } }),
          platform: runtimePlatform,
          shell,
          cwd,
          platformCapabilities: capabilities,
          policy: {
            filesystem: { read: [{ path: cwd, kind: "directory", recursive: true }, shellRead], write: [] },
            network: { internet: false, localNetwork: false },
            ...(runtimePlatform === "win32" ? { mxcOverrides: { fallback: { allowDaclMutation: compatibility } } } : {}),
          },
        };
        const result = dependencies.probeMxcExecution
          ? await dependencies.probeMxcExecution(probeInput)
          : await probeNativeMxcExecution(probeInput);
        mxcExecutionVerified = result.contained === true;
        return result;
      },
      probePlatformDiagnostics: async (details: unknown) => {
        if (runtimePlatform !== "win32") return {};
        const sdk = recordValue(recordValue(details).sdk);
        const support = typeof sdk.reprobePlatformSupport === "function" ? recordValue(await sdk.reprobePlatformSupport()) : {};
        const build = typeof context.windowsBuild === "number" ? context.windowsBuild : Number(release().split(".").at(-1));
        const preparation = deriveWindowsHostPreparation(support);
        return {
          windowsBuild: Number.isFinite(build) ? build : undefined,
          ...preparation,
          nativeEnforcementAvailable: support.isSupported === true && support.isolationTier === "base-container",
          reprobed: true,
        };
      },
      probeOmp: async () => {
        const probe = probePublicOmpRuntime(api as unknown as Record<string, unknown>, { ...context, mxcExecutionVerified });
        return { allRequired: probe.ok === true, missing: probe.missing, diagnostic: probe.diagnostic };
      },
    };
  };

  const platformCapabilitiesFor = (activation: Record<string, unknown>): Record<string, unknown> => {
    const support = recordValue(activation.platformSupport);
    const probed = recordValue(activation.platformCapabilities);
    const nativeEnforcementAvailable = probed.nativeEnforcementAvailable === true
      || (support.isSupported === true && (runtimePlatform !== "win32" || support.isolationTier === "base-container"));
    return {
      ...probed,
      allowedHosts: runtimePlatform === "darwin" || runtimePlatform === "win32" ? false : probed.allowedHosts === true,
      blockedHosts: runtimePlatform === "darwin" || runtimePlatform === "win32" ? false : probed.blockedHosts === true,
      coupledNetwork: runtimePlatform === "darwin" ? true : probed.coupledNetwork === true,
      pty: runtimePlatform === "darwin" ? false : probed.pty,
      windowsBuild: probed.windowsBuild,
      tier: probed.tier ?? support.isolationTier,
      nativeEnforcementAvailable,
      independentLocalNetwork: probed.independentLocalNetwork === true,
      ...(runtimePlatform === "win32" ? {
        internetLocalNetworkIsolation: probed.internetLocalNetworkIsolation === true,
        localNetworkAvailable: probed.localNetworkAvailable === true,
      } : {}),
      hostPreparationVerified: probed.hostPreparationVerified === true,
    };
  };

  const resolveActivatedPolicy = async (activation: Record<string, unknown>, context: Record<string, unknown>): Promise<void> => {
    const capabilities = platformCapabilitiesFor(activation);
    state.platformCapabilities = capabilities;
    const resolution = resolveNetworkPolicy(recordValue(state.network), capabilities);
    if (resolution.activation === "choice-required") {
      const ui = recordValue(context.ui);
      if (typeof ui.select !== "function") throw errorWithCode("UNSUPPORTED_HOST_RULES", "Saved host rules require an interactive block-all, unrestricted, or cancel choice before activation");
      const choices = Array.isArray(resolution.choices) ? resolution.choices.filter((choice): choice is string => typeof choice === "string") : [];
      const reason = resolution.reason === "unsupported-host-rules" ? "Saved network host rules are unsupported by this MXC backend" : "Saved network settings require an all-or-nothing outbound choice on this MXC backend";
      const choice = await ui.select(reason, choices);
      const network = recordValue(state.network);
      if (choice === "block-network") state.network = { ...network, internet: false, localNetwork: false, unrestricted: false, allowedHosts: [], blockedHosts: [] };
      else if (choice === "allow-unrestricted-network") state.network = { ...network, internet: true, localNetwork: capabilities.coupledNetwork === true, unrestricted: true, allowedHosts: [], blockedHosts: [] };
      else throw errorWithCode("SANDBOX_ACTIVATION_CANCELLED", "Sandbox activation was cancelled because its network policy is unsupported");
    } else state.network = cleanPolicy(recordValue(resolution.effective));
    setRuntimeReadonlyPaths(activation.requiredReadonlyPaths);
    assertPlatformPolicySupported(currentPolicy(), runtimePlatform, capabilities);
  };

  const validateDashboardPolicy = (
    policy: Record<string, unknown>,
    capabilities: Record<string, unknown> = recordValue(state.platformCapabilities),
    previous: Record<string, unknown> = editablePolicy(),
  ): Record<string, unknown> => {
    const candidate = cleanPolicy(policy);
    const savedDenies = [recordValue(recordValue(state.profiles).user), recordValue(recordValue(state.profiles).project), editablePolicy()]
      .flatMap((layer) => Array.isArray(layer.capabilityDenies) ? layer.capabilityDenies.map(recordValue) : [])
      .filter((deny, index, values) => values.findIndex((item) => item.capability === deny.capability && item.value === deny.value) === index);
    const granted = (subject: Record<string, unknown>, deny: Record<string, unknown>): boolean => {
      const capability = deny.capability;
      const value = deny.value;
      const filesystem = recordValue(subject.filesystem);
      const network = recordValue(subject.network);
      const uiPolicy = recordValue(subject.ui);
      const environment = recordValue(subject.environment);
      if ((capability === "read" || capability === "write") && typeof value === "string") {
        return (Array.isArray(filesystem[capability]) ? filesystem[capability] : []).some((entry) => typeof entry === "string" ? entry === value : recordValue(entry).path === value);
      }
      if (capability === "internet") return network.internet === true || network.unrestricted === true;
      if (capability === "local-network") return network.localNetwork === true;
      if (capability === "allowed-host") return Array.isArray(network.allowedHosts) && network.allowedHosts.includes(value);
      if (capability === "blocked-host") return Array.isArray(network.blockedHosts) && network.blockedHosts.includes(value);
      if (capability === "ui" && typeof value === "string") return uiPolicy[value] === true;
      if (capability === "trusted-tool") return Array.isArray(subject.trustedTools) && subject.trustedTools.includes(value);
      if (capability === "sensitive-environment-name") return [environment.persistSensitiveNames, environment.nonSensitive].some((names) => Array.isArray(names) && names.includes(value));
      return false;
    };
    const overrides = Array.isArray(candidate.explicitDenyOverrides) ? candidate.explicitDenyOverrides.map(recordValue) : [];
    for (const deny of savedDenies) {
      if (typeof deny.capability !== "string" || typeof deny.value !== "string" || !granted(candidate, deny)) continue;
      const existingOverride = overrides.some((override) => override.capability === deny.capability && override.value === deny.value);
      if (!existingOverride && !granted(previous, deny)) overrides.push({ capability: deny.capability, value: deny.value });
    }
    candidate.explicitDenyOverrides = overrides;
    candidate.capabilityDenies = savedDenies.filter((deny) => !overrides.some((override) => override.capability === deny.capability && override.value === deny.value));
    const reconciled = mergePolicyLayers({ baseline: {}, user: {}, project: {}, conversation: candidate });
    const resolution = resolveNetworkPolicy(recordValue(reconciled.network), capabilities);
    if (resolution.activation !== "ready") {
      throw errorWithCode("UNSUPPORTED_HOST_RULES", "Dashboard host-rule edits are unsupported by the active MXC backend");
    }
    reconciled.network = cleanPolicy(recordValue(resolution.effective));
    assertPlatformPolicySupported(reconciled, runtimePlatform, capabilities);
    return reconciled;
  };

  const executeHostShell = async (
    shell: "bash" | "powershell",
    input: Record<string, unknown>,
    context: Record<string, unknown>,
    onUpdate?: (update: Record<string, unknown>) => void,
  ): Promise<unknown> => {
    if (typeof api.exec !== "function") throw errorWithCode("HOST_EXECUTOR_UNAVAILABLE", "OMP exec is unavailable");
    if (shell === "powershell" && runtimePlatform !== "win32") throw errorWithCode("POWERSHELL_7_REQUIRED", "PowerShell host execution requires Windows and PowerShell 7");
    const resolved = resolveShell({
      platform: runtimePlatform,
      requested: shell,
      configuredShell: typeof context.configuredShell === "string" ? context.configuredShell : process.env.SHELL,
      discovered: context.discoveredExecutables,
    });
    if (typeof onUpdate === "function") {
      return (dependencies.spawnHost ?? executeStreamingHostProcess)(resolved.executable, [...resolved.args, String(input.command ?? "")], { ...input, signal: context.signal }, onUpdate);
    }
    if (shell === "powershell") {
      const timeoutMs = typeof input.timeout === "number" && Number.isFinite(input.timeout) && input.timeout > 0 ? input.timeout * 1000 : undefined;
      const options = { cwd: input.cwd, env: input.env, ...(timeoutMs === undefined ? {} : { timeout: timeoutMs }) };
      const result = await (api.exec as (...arguments_: unknown[]) => unknown)(resolved.executable, [...resolved.args, String(input.command ?? "")], options);
      return normalizeHostExecResult(recordValue(result));
    }
    const options = {
      cwd: input.cwd,
      env: input.env,
      ...(typeof input.timeout === "number" ? { timeout: input.timeout } : {}),
    };
    return (api.exec as (...arguments_: unknown[]) => unknown)(resolved.executable, [...resolved.args, String(input.command ?? "")], options);
  };

  const runShell = async (shell: "bash" | "powershell", invocation: { actual: boolean; input: Record<string, unknown>; context: Record<string, unknown> }, derived?: { policy: Record<string, unknown>; sensitiveApprovedNames: string[] }): Promise<unknown> => {
    const onShellUpdate = invocation.context.onShellUpdate;
    const shellUpdate = invocation.actual && typeof onShellUpdate === "function"
      ? cumulativeShellUpdate(onShellUpdate as (update: Record<string, unknown>) => void, shell === "bash" ? 0 : 100, shell === "bash" ? {} : undefined)
      : undefined;
    const sandboxUpdate = shellUpdate ?? (typeof onShellUpdate === "function"
      ? onShellUpdate as (update: Record<string, unknown>) => void
      : undefined);
    if (state.enabled !== true) {
      if (state.restorationFailed === true) {
        throw errorWithCode("SANDBOX_RESTORATION_FAILED", "Persisted sandbox restoration failed; model shell execution remains blocked until explicit disable or successful enable");
      }
      const normalized = recordValue(await executeHostShell(shell, invocation.input, invocation.context, shellUpdate));
      if (!invocation.actual) return normalized;
      return hostShellToolResult(normalized, invocation.input, shell === "powershell");
    }
    const context = invocation.context;
    const own = ownership(context);
    const ui = recordValue(context.ui);
    const treeId = sessionTreeIdentity(context);
    const oneTimeRequests = derived ? [] : await consumeShellOneTimeCapabilities(context);
    const invocationPolicy = derived ?? (oneTimeRequests.length > 0
      ? deriveGrantPolicy(currentPolicy(), sensitiveApprovals.get(treeId, profileSensitiveNames()), oneTimeRequests, recordValue(state.platformCapabilities))
      : undefined);
    const activePolicy = invocationPolicy?.policy ?? currentPolicy();
    const deniedSensitiveNames = (Array.isArray(activePolicy.capabilityDenies) ? activePolicy.capabilityDenies : []).flatMap((item): string[] => {
      const deny = recordValue(item);
      return deny.capability === "sensitive-environment-name" && typeof deny.value === "string" ? [deny.value] : [];
    });
    const approvedSensitiveNames = invocationPolicy?.sensitiveApprovedNames ?? sensitiveApprovals.get(treeId, profileSensitiveNames());
    if (shell === "powershell" && state.enabled === true && invocation.input.outsideSandbox !== true && typeof onShellUpdate === "function") {
      (onShellUpdate as (update: Record<string, unknown>) => void)({ content: [{ type: "text", text: "" }], details: undefined });
    }
    const result = await executeShell({
      ...invocation.input,
      shell,
      platform: runtimePlatform,
      configuredShell: typeof context.configuredShell === "string" ? context.configuredShell : process.env.SHELL,
      discovered: context.discoveredExecutables,
      policy: activePolicy,
      platformCapabilities: state.platformCapabilities,
      environmentPolicy: { ...recordValue(activePolicy.environment), approvedSensitiveNames, deniedSensitiveNames },
      autoBackgroundThresholdMs: autoBackgroundThreshold(context),
      ownerId: own.agentId,
      sessionId: own.sessionId,
      scopedManager: own.scopedManager,
      liveMatches: own.liveMatches,
      sessionManager: context.sessionManager,
      hasInteractiveOverlay: context.hasUI === true && Boolean(context.ptyOverlay),
      overlay: context.ptyOverlay,
      signal: context.signal,
      onUpdate: sandboxUpdate,
      renderer: context.shellRenderer,
      hostEnvironment: process.env,
      executeHost: (input: Record<string, unknown>) => executeHostShell(shell, input, context, shellUpdate),
      approveOutsideOnce: async (details: Record<string, unknown>) => await brokeredSelection(context, "outside-once", exactShellDetails(shell, invocation, own.agentId, details), ["Approve", "Deny"], "Run outside MXC once?") === "Approve",
      confirmCritical: async (details: Record<string, unknown>) => await brokeredSelection(context, "critical-command", exactShellDetails(shell, invocation, own.agentId, details), ["Approve", "Deny"], "Confirm critical command") === "Approve",
      approveSensitiveNames: async (details: Record<string, unknown>) => {
        const names = Array.isArray(details.names) ? details.names.filter((name): name is string => typeof name === "string") : [];
        if (names.length === 0 || typeof ui.select !== "function") return [];
        const choice = await ui.select("Sensitive environment names (values redacted)", ["Omit all", ...names.map((name) => `Allow ${name}`), "Allow all for this process"]);
        const selected = choice === "Allow all for this process"
          ? names
          : typeof choice === "string" && choice.startsWith("Allow ") ? [choice.slice(6)] : [];
        state.sensitiveApprovedNames = sensitiveApprovals.approve(treeId, selected);
        return selected;
      },
      chooseFailure: (choices: string[], failure: unknown) => brokeredSelection(context, "mxc-launch-failure", exactShellDetails(shell, invocation, own.agentId, { choices, ...(runtimePlatform === "win32" ? { failure: recordValue(failure) } : {}) }), choices, "MXC launch failed"),
      disableSandbox: async () => {
        state.enabled = false;
        state.priorConversationPolicy = true;
        persist();
        updateSandboxIndicator(context);
      },
    });
    if (!invocation.actual) return result;
    const normalized = recordValue(result);
    if (invocation.input.outsideSandbox === true || normalized.outsideSandbox === true) {
      return hostShellToolResult(normalized, invocation.input, shell === "powershell");
    }
    if (shell === "powershell") return powerShellToolResult(normalized, invocation.input);
    return toolResult(normalized);
  };

  api.registerCommand("sandbox", {
    description: "Configure and inspect MXC sandboxing",
    getArgumentCompletions: (argumentPrefix: unknown) => {
      if (typeof argumentPrefix !== "string" || /\s/.test(argumentPrefix)) return null;
      return SANDBOX_COMMAND_COMPLETIONS.filter((item) => item.value.startsWith(argumentPrefix));
    },
    handler: async (rawArguments: unknown, rawContext: unknown): Promise<void> => {
      const context = recordValue(rawContext);
      registerInteractiveParent(context);
      const command = parseSandboxCommand(typeof rawArguments === "string" ? rawArguments : "");
      const name = command.command;
      if (name === "status") {
        const status = {
          enabled: state.enabled === true,
          restorationFailed: state.restorationFailed === true,
          policy: editablePolicy(),
          runtime: { read: Array.isArray(state.runtimeReadonlyGrants) ? structuredClone(state.runtimeReadonlyGrants) : [] },
          platformCapabilities: state.platformCapabilities ?? {},
          profileSources: state.profileSources ?? [],
        };
        const ui = recordValue(context.ui);
        if (typeof ui.select === "function") {
          const presentation = createDashboardPresentation({ policy: status.policy, runtimeReadonlyGrants: recordValue(status.runtime).read, enabled: status.enabled });
          const selected = await ui.select(String(presentation.title), ["User Permissions", "Runtime Executable Access", "Diagnostics", "Close"]);
          if (selected === "User Permissions") await ui.select(`User-configured permissions:\n${JSON.stringify(status.policy, null, 2)}`, ["Back"]);
          else if (selected === "Runtime Executable Access") await ui.select(String(presentation.runtimeTitle), ["Back"]);
          else if (selected === "Diagnostics") await ui.select(`MXC diagnostics:\n${JSON.stringify({ enabled: status.enabled, restorationFailed: status.restorationFailed, platformCapabilities: status.platformCapabilities, profileSources: status.profileSources }, null, 2)}`, ["Back"]);
        } else {
          notify(context, `MXC sandbox status:\n${JSON.stringify(status, null, 2)}`, state.restorationFailed === true ? "error" : "info");
        }
        return;
      }
      if (name === "dashboard" || name === "update") {
        const beforeDashboard = editablePolicy();
        const result = await runSandboxDashboard({
          hasUI: context.hasUI,
          ui: context.ui,
          parentBroker: state.parentBroker,
          home: profileHome,
          cwd: typeof context.cwd === "string" ? context.cwd : process.cwd(),
          platform: runtimePlatform === "win32" ? "windows" : runtimePlatform,
          policy: beforeDashboard,
          runtimeReadonlyGrants: state.runtimeReadonlyGrants,
          windowsDiagnostics: state.platformCapabilities,
          diagnostics: { enabled: state.enabled, platformCapabilities: state.platformCapabilities, profileSources: state.profileSources },
        });
        if (result.action === "cancel") return;
        const validatedPolicy = validateDashboardPolicy(recordValue(result.policy), recordValue(state.platformCapabilities), beforeDashboard);
        applyEffectivePolicy(validatedPolicy);
        if (result.action === "save-user-profile") {
          const profiles = recordValue(state.profiles);
          const layer = applyProfileLayerDelta(recordValue(profiles.user), beforeDashboard, validatedPolicy);
          await saveProfile(join(profileHome, ".omp", "agent", "sandbox.yml"), layer, "user");
          state.profiles = { ...profiles, user: layer };
        }
        if (result.action === "save-project-profile") {
          if (state.projectTrust !== true || typeof state.repositoryRoot !== "string") throw errorWithCode("UNTRUSTED_PROJECT_PROFILE", "Saving a project profile requires explicit current-conversation trust");
          const profiles = recordValue(state.profiles);
          const layer = applyProfileLayerDelta(recordValue(profiles.project), beforeDashboard, validatedPolicy);
          await saveProfile(join(state.repositoryRoot, ".omp", "sandbox.yml"), layer, "project");
          state.profiles = { ...profiles, project: layer };
        }
        persist();
        return;
      }
      if (name === "doctor") {
        if (runtimePlatform === "win32") {
          const sdk = await loadMxcSdk();
          const support = sdk.reprobePlatformSupport();
          const build = Number(release().split(".").at(-1));
          const diagnostics = {
            windowsBuild: Number.isFinite(build) ? build : undefined,
            ...deriveWindowsHostPreparation(support),
            capabilities: support.uiCapabilities ?? {},
            nativeEnforcementAvailable: support.isSupported === true && support.isolationTier === "base-container",
            reprobed: true,
          };
          const report = windowsDoctor(diagnostics);
          notify(context, JSON.stringify(report), diagnostics.nativeEnforcementAvailable === false ? "error" : "info");
          return;
        }
        const probe = probePublicOmpRuntime(api as unknown as Record<string, unknown>, context);
        notify(context, probe.ok === true ? "MXC sandbox activation facilities are available" : String(probe.diagnostic), probe.ok === true ? "info" : "error");
        return;
      }
      if (name === "enable") {
        requireInteractiveUi({ hasUI: context.hasUI, parentBroker: state.parentBroker });
        let restorePrior = false;
        if (state.priorConversationPolicy === true) {
          const model = createReenableModel({ priorConversationPolicy: true });
          const ui = recordValue(context.ui);
          if (typeof ui.select !== "function") throw errorWithCode("INTERACTIVE_UI_REQUIRED", "Re-enable requires an interactive selection");
          const selected = await ui.select("Re-enable MXC sandbox", model.actions);
          if (selected === "restore-prior-policy-and-grants") restorePrior = true;
          else if (selected !== "reset-and-run-setup") return;
        }
        if (restorePrior) {
          state.enabled = false;
          state.restorationFailed = true;
          persist();
        }
        const activationUi = recordValue(context.ui);
        let activation: Record<string, unknown>;
        try {
          activation = await activateSandbox({
            action: "enable",
            platform: runtimePlatform,
            hasUI: context.hasUI,
            extensionDirectory: EXTENSION_DIRECTORY,
            dependencies: activationDependencies(context),
            chooseWindowsMode: runtimePlatform === "win32" && typeof activationUi.select === "function"
              ? async (diagnostics: unknown) => {
                  const details = recordValue(diagnostics);
                  notify(context, `Windows diagnostics: build ${String(details.windowsBuild ?? "unknown")}, tier ${String(details.tier ?? details.isolationTier ?? "unknown")}, prepared ${details.hostPreparationVerified === true ? "yes" : "no"}`);
                  const selected = await (activationUi.select as (title: string, choices: string[]) => Promise<unknown>)("Windows containment mode", ["strict-native-enforcement", "compatibility-after-verified-host-preparation"]);
                  return selected === "strict-native-enforcement" ? "strict" : selected === "compatibility-after-verified-host-preparation" ? "compatibility" : "cancel";
                }
              : undefined,
          });
        } catch (error) {
          if (state.restorationFailed === true) persist();
          throw error;
        }
        if (restorePrior) {
          await resolveActivatedPolicy(activation, context);
          state.enabled = true;
          state.restorationFailed = false;
          persist();
          updateSandboxIndicator(context);
          return;
        }
        const cwd = typeof context.cwd === "string" ? context.cwd : process.cwd();
        const loaded = await loadProfileLayers({ cwd, home: profileHome, projectTrusted: false, platform: runtimePlatform, env: process.env });
        state.repositoryRoot = loaded.repositoryRoot;
        state.profileSources = loaded.sources;
        const project = recordValue(loaded.project);
        if (Object.keys(project).length > 0) state.projectTrust = await confirm(context, "Trust project sandbox profile?", "Project broadening applies only to this conversation.");
        project.trusted = state.projectTrust === true;
        state.profiles = { user: loaded.user, project };
        const setupLayerBaseline = mergePolicyLayers({ baseline: {}, user: loaded.user, project, conversation: {} });
        setRuntimeReadonlyPaths(activation.requiredReadonlyPaths);
        const defaults = getInitialSetupDefaults({ cwd, temp: tmpdir(), discoveredReadonlyPaths: [] });
        const ui = recordValue(context.ui);
        if (typeof ui.select !== "function") throw errorWithCode("INTERACTIVE_UI_REQUIRED", "Initial setup requires the TUI");
        const setupChoice = await ui.select("Initial MXC sandbox policy", ["Use secure initial defaults", "Customize in dashboard", "Cancel"]);
        if (setupChoice === "Cancel" || (setupChoice !== "Use secure initial defaults" && setupChoice !== "Customize in dashboard")) throw errorWithCode("SETUP_CANCELLED", "Sandbox setup was cancelled");
        const effective = mergePolicyLayers({ baseline: defaults, user: loaded.user, project, conversation: {} });
        applyEffectivePolicy(effective);
        if (activation.approvedWindowsMode === "compatibility") state.mxcOverrides = { fallback: { allowDaclMutation: true } };
        else if (activation.approvedWindowsMode === "strict") state.mxcOverrides = { fallback: { allowDaclMutation: false } };
        let dashboardSaveChoice: unknown;
        if (setupChoice === "Customize in dashboard") {
          const edited = await runSandboxDashboard({ hasUI: context.hasUI, ui: context.ui, setup: true, home: profileHome, cwd, platform: runtimePlatform === "win32" ? "windows" : runtimePlatform, policy: editablePolicy(), runtimeReadonlyGrants: state.runtimeReadonlyGrants, windowsDiagnostics: activation.platformCapabilities, diagnostics: activation });
          if (edited.action === "cancel") throw errorWithCode("SETUP_CANCELLED", "Sandbox setup was cancelled");
          const validatedPolicy = validateDashboardPolicy(recordValue(edited.policy), platformCapabilitiesFor(activation));
          applyEffectivePolicy(validatedPolicy);
          dashboardSaveChoice = edited.action === "save-user-profile" ? "save-user-profile" : edited.action === "save-project-profile" ? "save-project-profile" : "use-for-conversation";
        }
        await resolveActivatedPolicy(activation, context);
        const saveChoice = dashboardSaveChoice ?? await ui.select("Apply sandbox setup", ["use-for-conversation", "save-user-profile", "save-project-profile"]);
        if (saveChoice === "save-user-profile") {
          const profiles = recordValue(state.profiles);
          const layer = applyProfileLayerDelta(recordValue(profiles.user), setupLayerBaseline, editablePolicy());
          await saveProfile(join(profileHome, ".omp", "agent", "sandbox.yml"), layer, "user");
          state.profiles = { ...profiles, user: layer };
        }
        if (saveChoice === "save-project-profile") {
          if (state.projectTrust !== true) state.projectTrust = await confirm(context, "Trust project sandbox profile?", "Saving grants to this project applies them only after explicit conversation trust.");
          if (state.projectTrust !== true || typeof state.repositoryRoot !== "string") throw errorWithCode("UNTRUSTED_PROJECT_PROFILE", "Saving a project profile requires explicit current-conversation trust");
          const profiles = recordValue(state.profiles);
          const layer = applyProfileLayerDelta(recordValue(profiles.project), setupLayerBaseline, editablePolicy());
          await saveProfile(join(state.repositoryRoot, ".omp", "sandbox.yml"), layer, "project");
          state.profiles = { ...profiles, project: layer };
        }
        if (!["use-for-conversation", "save-user-profile", "save-project-profile"].includes(String(saveChoice))) throw errorWithCode("SETUP_CANCELLED", "Sandbox setup was not applied");
        state.restorationFailed = false;
        state.enabled = true;
        state.priorConversationPolicy = false;
        persist();
        updateSandboxIndicator(context);
        return;
      }
      if (name === "disable") {
        const sessionManager = recordValue(context.sessionManager);
        await disableSandbox({
          sessionTreeId: typeof sessionManager.getSessionId === "function" ? sessionManager.getSessionId() : "unresolved",
          confirm: () => confirm(context, "Disable MXC sandbox?", "This restores normal unsandboxed behavior for this conversation tree."),
          restoreHostTools: async () => ({ parity: "exact", mode: shellAdapterRegistered ? "public-exec" : "unavailable" }),
        });
        state.priorConversationPolicy = true;
        state.enabled = false;
        state.restorationFailed = false;
        persist();
        updateSandboxIndicator(context);
        return;
      }
      if (name === "clear") {
        if (!await confirm(context, "Clear sandbox conversation state?", "Saved user and project profiles are not changed.")) return;
        state.enabled = false;
        state.priorConversationPolicy = false;
        state.filesystem = { read: [], write: [], deny: [] };
        state.network = { internet: false, localNetwork: false };
        state.environment = {};
        state.mxcOverrides = {};
        state.trustedTools = [];
        state.capabilityDenies = [];
        oneTimeCapabilities.splice(0);
        if (typeof state.sessionTreeId === "string") sensitiveApprovals.clear(state.sessionTreeId);
        delete state.sensitiveApprovedNames;
        persist();
        updateSandboxIndicator(context);
        return;
      }
      if (name === "update-mxc") {
        requireInteractiveUi({ hasUI: context.hasUI, parentBroker: state.parentBroker });
        await updateMxc({
          extensionDirectory: EXTENSION_DIRECTORY,
          confirm: (updateCommand: unknown) => confirm(context, "Update MXC dependency?", String(updateCommand)),
          execute: async () => {
            if (typeof api.exec !== "function") throw errorWithCode("MXC_UPDATE_UNAVAILABLE", "OMP exec is unavailable");
            return api.exec("bun", ["update", "@microsoft/mxc-sdk"], { cwd: EXTENSION_DIRECTORY });
          },
          reprobe: loadMxcDeferred,
        });
        return;
      }
      if (name === "allow" || name === "deny") {
        const mutation = createStateMutation(command);
        const capability = String(mutation.capability ?? "");
        const target = typeof mutation.target === "string" ? mutation.target : "";
        const supported = new Set(["read", "write", "internet", "local-network", "allowed-host", "blocked-host", "sensitive-environment-name", "trusted-tool", "ui"]);
        if (!supported.has(capability)) throw errorWithCode("UNSUPPORTED_SANDBOX_CAPABILITY", `Unsupported sandbox capability: ${capability}`);
        if (target.length === 0) throw errorWithCode("INVALID_SANDBOX_CAPABILITY_VALUE", "A non-empty exact deny target is required");
        if ((capability === "internet" || capability === "local-network") && target !== "allow" && target !== "true") throw errorWithCode("INVALID_SANDBOX_CAPABILITY_VALUE", `${capability} requires target allow`);
        if (capability === "ui" && !["allowWindows", "clipboardRead", "clipboardWrite", "inputInjection"].includes(target)) throw errorWithCode("INVALID_SANDBOX_CAPABILITY_VALUE", "Unsupported UI capability");
        if (capability === "sensitive-environment-name" && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(target)) throw errorWithCode("INVALID_SANDBOX_CAPABILITY_VALUE", "Sensitive environment deny requires an environment variable name");
        if ((capability === "allowed-host" || capability === "blocked-host") && (target.includes("://") || /[\s/]/.test(target))) throw errorWithCode("INVALID_SANDBOX_CAPABILITY_VALUE", "Host deny requires one exact hostname");
        if (mutation.scope === "project" && (state.projectTrust !== true || typeof state.repositoryRoot !== "string")) {
          throw errorWithCode("UNTRUSTED_PROJECT_PROFILE", `${name === "deny" ? "Project denies" : "Project grants"} require current-conversation trust`);
        }
        const beforeMutation = editablePolicy();
        if (name === "allow") {
          await applyGrant({ capability, value: target, scope: mutation.scope, sessionTreeId: state.sessionTreeId });
        } else {
          const exactDeny = { capability, value: target };
          const denies = Array.isArray(state.capabilityDenies) ? state.capabilityDenies as unknown[] : [];
          state.capabilityDenies = [...denies.filter((item) => JSON.stringify(item) !== JSON.stringify(exactDeny)), exactDeny];
          if (capability === "read" || capability === "write") {
            const filesystem = recordValue(state.filesystem);
            const grants = Array.isArray(filesystem[capability]) ? filesystem[capability] as unknown[] : [];
            filesystem[capability] = grants.filter((value) => typeof value === "string" ? value !== target : recordValue(value).path !== target);
            const pathDenies = Array.isArray(filesystem.deny) ? filesystem.deny as unknown[] : [];
            const exactPathDeny = { path: target, kind: "file", recursive: false, permissions: [capability] };
            filesystem.deny = [...pathDenies.filter((item) => !(recordValue(item).path === target && Array.isArray(recordValue(item).permissions) && (recordValue(item).permissions as unknown[]).includes(capability))), exactPathDeny];
            state.filesystem = filesystem;
          } else if (capability === "internet" || capability === "local-network" || capability === "allowed-host" || capability === "blocked-host") {
            const network = recordValue(state.network);
            if (capability === "internet") {
              network.internet = false;
              network.unrestricted = false;
            } else if (capability === "local-network") network.localNetwork = false;
            else if (capability === "allowed-host") {
              network.allowedHosts = (Array.isArray(network.allowedHosts) ? network.allowedHosts : []).filter((host) => host !== target);
              network.blockedHosts = [...new Set([...(Array.isArray(network.blockedHosts) ? network.blockedHosts : []), target])];
            } else network.blockedHosts = (Array.isArray(network.blockedHosts) ? network.blockedHosts : []).filter((host) => host !== target);
            state.network = network;
          } else if (capability === "ui") {
            const uiPolicy = recordValue(state.ui);
            uiPolicy[target] = false;
            state.ui = uiPolicy;
          } else if (capability === "trusted-tool") {
            state.trustedTools = (Array.isArray(state.trustedTools) ? state.trustedTools : []).filter((tool) => tool !== target);
          } else {
            const environment = recordValue(state.environment);
            environment.persistSensitiveNames = (Array.isArray(environment.persistSensitiveNames) ? environment.persistSensitiveNames : []).filter((name) => name !== target);
            state.environment = environment;
            if (typeof state.sessionTreeId === "string") sensitiveApprovals.deny(state.sessionTreeId, target);
          }
          if (mutation.scope === "user") {
            const profiles = recordValue(state.profiles);
            const layer = applyProfileLayerDelta(recordValue(profiles.user), beforeMutation, editablePolicy());
            await saveProfile(join(profileHome, ".omp", "agent", "sandbox.yml"), layer, "user");
            state.profiles = { ...profiles, user: layer };
          }
          if (mutation.scope === "project") {
            if (state.projectTrust !== true || typeof state.repositoryRoot !== "string") throw errorWithCode("UNTRUSTED_PROJECT_PROFILE", "Project denies require current-conversation trust");
            const profiles = recordValue(state.profiles);
            const layer = applyProfileLayerDelta(recordValue(profiles.project), beforeMutation, editablePolicy());
            await saveProfile(join(state.repositoryRoot, ".omp", "sandbox.yml"), layer, "project");
            state.profiles = { ...profiles, project: layer };
          }
          persist();
        }
        state.lastMutation = mutation;
        return;
      }
    },
  });

  api.registerTool({
    name: "sandbox_request",
    label: "Sandbox Request",
    description: "Request an exact sandbox capability before a dependent operation",
    parameters: objectSchema(api, { capability: schema(api, "string"), value: schema(api, "string"), saveTo: schema(api, "string") }),
    approval: "write",
    execute: async (...arguments_: unknown[]): Promise<unknown> => {
      const invocation = toolInvocation(arguments_);
      const agentId = requesterIdentity(invocation.context);
      const treeId = sessionTreeIdentity(invocation.context);
      const requestId = crypto.randomUUID();
      promptContexts.set(requestId, { ...invocation.context, requestingAgent: agentId });
      try {
        const result = await sandboxRequest(invocation.input, {
          requestId,
          agentId,
          sessionTreeId: treeId,
          cwd: invocation.context.cwd,
          hasUI: invocation.context.hasUI,
          projectTrusted: state.projectTrust === true,
          enforcePlatformCapabilities: true,
          platformCapabilities: state.platformCapabilities,
          permissionBroker,
          applyGrant,
        });
        storeOneTimeCapability(result, treeId, agentId);
        return invocation.actual ? toolResult(result) : result;
      } finally {
        promptContexts.delete(requestId);
      }
    },
  });


  if (shellAdapterRegistered) {
    api.registerTool({
      name: "bash",
      label: "Bash",
      description: "Run a configured POSIX shell command in a fresh MXC process sandbox. After an access denial, use sandbox_request before retrying.",
      parameters: objectSchema(api, {
        command: schema(api, "string"), env: schema(api, "record"), cwd: schema(api, "string"), timeout: schema(api, "number"),
        pty: schema(api, "boolean"), async: schema(api, "boolean"), outsideSandbox: schema(api, "boolean"),
      }),
      approval: "exec",
      execute: async (...arguments_: unknown[]): Promise<unknown> => runShell("bash", toolInvocation(arguments_)),
    });
    if (runtimePlatform === "win32") {
      api.registerTool({
        name: "powershell",
        label: "PowerShell 7",
        description: "Execute PowerShell 7 in a fresh MXC ProcessContainer. Returns stdout and stderr with Bash-style OMP rendering. PowerShell uses backticks for escaping, $env:NAME for environment variables, and doubled single quotes inside single-quoted strings. After an access denial, use sandbox_request before retrying.",
        promptSnippet: "Execute PowerShell 7 commands in an MXC process sandbox",
        promptGuidelines: ["Use PowerShell syntax, not Bash syntax; aliases include ls, cat, rm, cp, mv, pwd, and cd."],
        parameters: objectSchema(api, {
          command: schema(api, "string"), env: schema(api, "record"), cwd: schema(api, "string"), timeout: schema(api, "number"),
          pty: schema(api, "boolean"), async: schema(api, "boolean"), outsideSandbox: schema(api, "boolean"),
        }),
        approval: "exec",
        ...powerShellRenderer(api),
        execute: async (...arguments_: unknown[]): Promise<unknown> => runShell("powershell", toolInvocation(arguments_)),
      });
    }
  }

  api.on("tool_call", async (...arguments_: unknown[]): Promise<Record<string, unknown> | undefined> => {
    const event = recordValue(arguments_[0]);
    const context = recordValue(arguments_[1]);
    const toolName = typeof event.toolName === "string" ? event.toolName : "";
    const trustedTools = Array.isArray(state.trustedTools) ? state.trustedTools : [];
    const ui = recordValue(context.ui);
    const canPrompt = typeof ui.select === "function" || (context.hasUI === false && typeof context.agentId === "string" && contextSessionTreeId(context) !== undefined);
    const result = await interceptToolCall({
      ...event,
      source: event.source ?? "model",
      mutationOrExecution: !ADAPTED_TOOLS.has(toolName) && !KNOWN_READ_ONLY_TOOLS.has(toolName) && !trustedTools.includes(toolName),
    }, {
      enabled: state.enabled === true,
      restorationFailed: state.restorationFailed === true,
      sandboxPolicy: currentPolicy(),
      trustedTools,
      workspace: typeof context.cwd === "string" ? context.cwd : process.cwd(),
      platform: runtimePlatform,
      approveFileAccess: canPrompt
        ? (details: Record<string, unknown>) => brokeredSelection(context, "inline-file-access", { ...details, requestingAgent: promptRequesterIdentity(context), toolName }, details.choices as string[], "Approve sandbox file access?")
        : undefined,
      approveLspAction: canPrompt
        ? (details: Record<string, unknown>) => brokeredSelection(context, "nonreadonly-lsp", { ...details, requestingAgent: promptRequesterIdentity(context), toolName }, details.choices as string[], String(details.warning ?? "Approve non-readonly LSP action?"))
        : undefined,
      applyGrant,
      applyGrants,
      consumeOneTimePermission: (requested: Record<string, unknown>) => consumeOneTimeCapability(context, requested),
    });
    if (result?.block === true) return { block: true, reason: result.reason };
    if (result?.action === "sandbox" && !shellAdapterRegistered) return { block: true, reason: "sandbox-shell-adapter-unavailable" };
    return undefined;
  });

  api.on("session_before_switch", (...arguments_: unknown[]): void => {
    const treeId = contextSessionTreeId(recordValue(arguments_[1]));
    unregisterInteractiveParent(treeId);
    clearOneTimeCapabilities(treeId);
    updateSandboxIndicator(recordValue(arguments_[1]), true);
  });

  for (const eventName of ["session_start", "session_switch", "session_tree", "session_resume"] as const) {
    api.on(eventName, async (...arguments_: unknown[]): Promise<void> => {
      const event = recordValue(arguments_[0]);
      const context = recordValue(arguments_[1]);
      registerInteractiveParent(context);
      const sessionManager = recordValue(context.sessionManager);
      const cwd = typeof context.cwd === "string" ? context.cwd : process.cwd();
      const loaded = await loadProfileLayers({ cwd, home: profileHome, projectTrusted: state.projectTrust === true, platform: runtimePlatform, env: process.env });
      state.profiles = { user: loaded.user, project: loaded.project };
      await handleSessionLifecycle({
        ...event,
        type: eventName,
        entries: typeof sessionManager.getBranch === "function" ? sessionManager.getBranch() : [],
        sessionId: typeof sessionManager.getSessionId === "function" ? sessionManager.getSessionId() : undefined,
      }, state);
      const runtimePolicyMigrationRequired = Number(state.policyRevision ?? 0) < 3;
      let migratedLegacyPathGrants = false;
      if (Number(state.policyRevision ?? 0) < 2 && state.filesystem && typeof state.filesystem === "object" && !Array.isArray(state.filesystem)) {
        const migration = pruneLegacyDiscoveredPathGrants(recordValue(state.filesystem), {
          cwd,
          pathEntries: String(process.env.PATH ?? "").split(delimiter).filter(Boolean),
          platform: runtimePlatform,
          executableDirectory: dirname(process.execPath),
        });
        state.filesystem = recordValue(migration.filesystem);
        state.policyRevision = 2;
        migratedLegacyPathGrants = Array.isArray(migration.removed) && migration.removed.length > 0;
      }
      const restoredProject = cleanPolicy(recordValue(loaded.project));
      restoredProject.trusted = state.projectTrust === true;
      state.profiles = { user: loaded.user, project: restoredProject };
      state.profileSources = loaded.sources;
      state.repositoryRoot = loaded.repositoryRoot;
      applyEffectivePolicy(mergePolicyLayers({ baseline: {}, user: loaded.user, project: restoredProject, conversation: editablePolicy() }));
      if (migratedLegacyPathGrants) persist();
      state.parentBroker = permissionBroker;
      bindSensitiveApprovals(context);
      if (state.enabled === true) {
        const restoreWindowsMode = recordValue(recordValue(state.mxcOverrides).fallback).allowDaclMutation === true ? "compatibility" : "strict";
        state.enabled = false;
        state.restorationFailed = true;
        try {
          const activation = await activateSandbox({
            action: "enable",
            restore: true,
            platform: runtimePlatform,
            ...(runtimePlatform === "win32" ? { approvedWindowsMode: restoreWindowsMode } : {}),
            extensionDirectory: EXTENSION_DIRECTORY,
            dependencies: activationDependencies(context),
          });
          await resolveActivatedPolicy(activation, context);
          state.enabled = true;
          state.restorationFailed = false;
          if (runtimePolicyMigrationRequired && state.runtimePolicyChanged === true) persist();
          delete state.runtimePolicyChanged;
        } catch (error) {
          persist();
          updateSandboxIndicator(context);
          throw error;
        }
      }
      updateSandboxIndicator(context);
    });
  }
  api.on("session_shutdown", (...arguments_: unknown[]): void => {
    const context = recordValue(arguments_[1]);
    const treeId = contextSessionTreeId(context);
    unregisterInteractiveParent(treeId);
    clearOneTimeCapabilities(treeId);
    updateSandboxIndicator(context, true);
  });
  api.on("session_before_branch", (): void => {
    pendingBranchSnapshot = snapshotBranchState({ currentState: state });
  });
  api.on("session_branch", (...arguments_: unknown[]): void => {
    if (!pendingBranchSnapshot) return;
    const event = recordValue(arguments_[0]);
    const data = recordValue(pendingBranchSnapshot.data);
    api.appendEntry("mxc-sandbox/state", { ...data, branchEntryId: event.branchEntryId });
    pendingBranchSnapshot = undefined;
  });
}
