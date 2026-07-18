import { dirname, isAbsolute, normalize, resolve } from "node:path";
import { canonicalizeTarget, resolveToolTargets } from "../policy/paths";
import { evaluatePathAccessAsync, type PathGrant } from "../policy/filesystem";

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function networkPolicy(policy: Record<string, unknown>): Record<string, unknown> {
  const nested = recordValue(policy.network);
  return Object.keys(nested).length > 0 ? nested : policy;
}
function normalizedHostname(value: string): string {
  return value.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

function mappedIpv4Address(host: string): string | undefined {
  const dotted = host.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i)?.[1];
  if (dotted) return dotted;
  if (!host.includes(":")) return undefined;
  const halves = host.split("::");
  if (halves.length > 2) return undefined;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const omitted = halves.length === 2 ? 8 - left.length - right.length : 0;
  if (omitted < 0 || (halves.length === 1 && left.length !== 8)) return undefined;
  const segments = [...left, ...Array.from({ length: omitted }, () => "0"), ...right];
  if (segments.length !== 8 || segments.some((segment) => !/^[0-9a-f]{1,4}$/i.test(segment))) return undefined;
  const words = segments.map((segment) => Number.parseInt(segment, 16));
  if (words.slice(0, 5).some((word) => word !== 0) || words[5] !== 0xffff) return undefined;
  return `${words[6]! >> 8}.${words[6]! & 0xff}.${words[7]! >> 8}.${words[7]! & 0xff}`;
}

function isLocalNetworkHost(value: string): boolean {
  const host = normalizedHostname(value);
  if (host === "localhost" || host.endsWith(".localhost") || host === "::1") return true;
  if (/^(?:fc|fd)[0-9a-f]{2}:/i.test(host) || /^fe[89ab][0-9a-f]:/i.test(host)) return true;
  const ipv4 = (mappedIpv4Address(host) ?? host).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!ipv4) return false;
  const octets = ipv4.slice(1).map(Number);
  if (octets.some((part) => part > 255)) return false;
  const [first, second] = octets;
  return first === 0 || first === 10 || first === 127 || (first === 169 && second === 254)
    || (first === 172 && second! >= 16 && second! <= 31) || (first === 192 && second === 168);
}

function allowedInitialHost(input: Record<string, unknown>, policy: Record<string, unknown>): Record<string, unknown> {
  const rawUrl = typeof input.url === "string" ? input.url : typeof input.path === "string" ? input.path : "";
  try {
    const host = normalizedHostname(new URL(rawUrl).hostname);
    const network = networkPolicy(policy);
    const allowedHosts = Array.isArray(network.allowedHosts) ? network.allowedHosts.filter((value): value is string => typeof value === "string").map(normalizedHostname) : [];
    const blockedHosts = Array.isArray(network.blockedHosts) ? network.blockedHosts.filter((value): value is string => typeof value === "string").map(normalizedHostname) : [];
    if (blockedHosts.includes(host)) return { action: "block", reason: "network-host-blocked", initialHost: host };
    if (isLocalNetworkHost(host)) {
      return network.localNetwork === true
        ? { action: "allow-host-adapter", initialHost: host }
        : { action: "block", reason: "local-network-not-granted", initialHost: host };
    }
    return allowedHosts.includes(host) || network.unrestricted === true
      ? { action: "allow-host-adapter", initialHost: host }
      : { action: "block", reason: "network-host-not-granted", initialHost: host };
  } catch {
    return { action: "block", reason: "invalid-url" };
  }
}

export function classifyToolCall(input: Record<string, unknown>): Record<string, unknown> {
  const name = typeof input.name === "string" ? input.name : "";
  if (input.enabled !== true) return { action: "allow-host-unchanged", reason: "sandbox-disabled" };
  const trustedTools = Array.isArray(input.trustedTools) ? input.trustedTools : [];
  const deniedCapabilities = Array.isArray(recordValue(input.policy).capabilityDenies) ? recordValue(input.policy).capabilityDenies as unknown[] : [];
  const toolExplicitlyDenied = deniedCapabilities.some((item) => recordValue(item).capability === "trusted-tool" && recordValue(item).value === name);
  if (trustedTools.includes(name) && !toolExplicitlyDenied) return { action: "allow-host-unchanged", reason: "exact-trusted-tool" };
  const toolInput = recordValue(input.input);
  const policy = recordValue(input.policy);

  if (name === "read" || name === "write" || name === "edit" || name === "ast_edit") {
    const targets = resolveToolTargets(name, toolInput);
    const blocked = targets.find((target) => target.blocked === true);
    if (blocked) return { action: "block", reason: blocked.reason };
    const internal = targets.find((target) => typeof target.trustedInternal === "string");
    if (internal) return { action: "allow-internal", trustedInternal: internal.trustedInternal };
    const network = targets.find((target) => typeof target.host === "string");
    if (network) {
      const networkResult = allowedInitialHost({ url: `https://${network.host}` }, policy);
      return { ...networkResult, initialHost: network.host };
    }
    const onlyTarget = targets.length === 1 ? targets[0] : undefined;
    return {
      action: "allow-host-adapter",
      targets,
      ...(typeof onlyTarget?.path === "string" ? { gateTarget: onlyTarget.path } : {}),
    };
  }
  if (name === "web_search") {
    const network = networkPolicy(policy);
    return network.internet === true && network.unrestricted === true
      ? { action: "allow-host-adapter" }
      : { action: "block", reason: "unrestricted-internet-required" };
  }
  if (name === "browser") return allowedInitialHost(toolInput, policy);
  if (name === "lsp") return { action: "allow-host-adapter" };
  if (name === "bash" || name === "powershell" || name === "sandbox_request" || name === "job") {
    return { action: "allow-sandbox-adapter" };
  }
  if (input.mutationOrExecution === true) return { action: "allow-host-unchanged", reason: "unadapted-tool" };
  return { action: "allow-host-unchanged", reason: "non-mutating-tool" };
}

export function evaluateLspAction(input: Record<string, unknown>): Record<string, unknown> {
  if (input.readonly === true) return { action: "allow" };
  const workspace = typeof input.workspace === "string" ? input.workspace : "";
  const grants = Array.isArray(input.grants) ? input.grants : [];
  const recursiveWrite = grants.some((grant) => {
    if (!grant || typeof grant !== "object" || Array.isArray(grant)) return false;
    const candidate = grant as Record<string, unknown>;
    return candidate.path === workspace
      && candidate.kind === "directory"
      && candidate.recursive === true
      && Array.isArray(candidate.permissions)
      && candidate.permissions.includes("write");
  });
  if (recursiveWrite) return { action: "allow" };
  return {
    action: "prompt",
    warning: "The extension cannot precompute every file the language server may edit.",
    choices: ["allow-action-once", "grant-recursive-workspace-write", "deny"],
  };
}

export function detectCriticalCommand(shell: string, command: string): boolean {
  if (shell === "powershell") {
    const recursiveRemoval = /\b(?:remove-item|rm|ri|del|erase|rmdir|rd)\b/i.test(command) && /(?:\s|^)-(?:recurse|r)(?::\s*\$?true)?(?:\s|$)/i.test(command);
    const systemRootTarget = /(?:^|[\s'"`])(?:[a-z]:\\|\\\\|\$env:(?:systemdrive|systemroot)(?:\\|\b)|\$env:windir(?:\\|\b)|[a-z]:\\windows(?:\\|\b))/i.test(command);
    const writeCommand = /\b(?:set-content|add-content|clear-content|out-file|new-item|copy-item|move-item|sc|ac)\b/i.test(command)
      || /\[(?:system\.)?io\.file\]::(?:writealltext|writeallbytes|appendalltext)\b/i.test(command)
      || /(?:>>?|2>)\s*[^|;&]+/i.test(command);
    const credentialOrSystemTarget = /(?:\.ssh[\\/]authorized_keys|\.aws[\\/]credentials|\.azure[\\/]|\.kube[\\/]config|\$env:(?:systemroot|windir)[\\/]|\$env:programdata[\\/]microsoft[\\/]crypto[\\/]|[a-z]:\\windows(?:\\system32)?[\\/]|[a-z]:\\programdata\\microsoft\\crypto[\\/]|[\\/]etc[\\/](?:passwd|shadow|sudoers|hosts)\b|\\config\\(?:sam|security|system)\b)/i.test(command);
    return /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*\|\s*(?:iex|invoke-expression)\b/i.test(command)
      || /\b(?:restart-computer|stop-computer|shutdown(?:\.exe)?)\b/i.test(command)
      || (recursiveRemoval && systemRootTarget)
      || (writeCommand && credentialOrSystemTarget);
  }
  return /\brm\s+(?:-[a-z]*r[a-z]*f|-rf|-fr)\s+(?:--\s+)?\/(?:\s|$)/i.test(command)
    || /:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:\s*&[^}]*\}\s*;\s*:/i.test(command)
    || /\b(?:curl|wget)\b[^|]*\|\s*(?:sh|bash|zsh)\b/i.test(command)
    || />+\s*~\/\.ssh\/authorized_keys\b/i.test(command)
    || /\b(?:shutdown|reboot|halt|poweroff)\b/i.test(command);
}

class ToolGateError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ToolGateError";
    this.code = code;
  }
}

function filesystemPolicy(policy: Record<string, unknown>): Record<string, unknown> {
  const nested = recordValue(policy.filesystem);
  return Object.keys(nested).length > 0 ? nested : policy;
}

function policyGrants(policy: Record<string, unknown>): PathGrant[] {
  const filesystem = filesystemPolicy(policy);
  const grants: PathGrant[] = [];
  for (const operation of ["read", "write"] as const) {
    const values = Array.isArray(filesystem[operation]) ? filesystem[operation] as unknown[] : [];
    for (const value of values) {
      if (typeof value === "string") {
        grants.push({ path: value, kind: "file", permissions: [operation] });
        continue;
      }
      const item = recordValue(value);
      if (typeof item.path !== "string") continue;
      grants.push({
        path: item.path,
        kind: item.kind === "directory" || item.recursive === true ? "directory" : "file",
        ...(item.recursive === true ? { recursive: true } : {}),
        permissions: Array.isArray(item.permissions)
          ? item.permissions.filter((permission): permission is string => typeof permission === "string")
          : [operation],
      });
    }
  }
  return grants;
}

function policyDenies(policy: Record<string, unknown>, operation: "read" | "write"): PathGrant[] {
  const filesystem = filesystemPolicy(policy);
  const values = Array.isArray(filesystem.deny) ? filesystem.deny : [];
  return values.flatMap((value): PathGrant[] => {
    const item = recordValue(value);
    const path = typeof value === "string" ? value : typeof item.path === "string" ? item.path : "";
    if (path === "") return [];
    const permissions = Array.isArray(item.permissions) ? item.permissions : ["read", "write"];
    if (!permissions.includes(operation)) return [];
    const directory = item.kind === "directory" || item.recursive === true || typeof value === "string";
    return [{ path, kind: directory ? "directory" : "file", ...(directory && item.recursive !== false ? { recursive: true } : {}), permissions: [operation] }];
  });
}

async function hasExplicitDenyOverride(policy: Record<string, unknown>, operation: "read" | "write", path: string, platform: unknown): Promise<boolean> {
  const root = Array.isArray(policy.explicitDenyOverrides) ? policy.explicitDenyOverrides : [];
  const nested = filesystemPolicy(policy);
  const overrides = [...root, ...(Array.isArray(nested.explicitDenyOverrides) ? nested.explicitDenyOverrides : [])];
  const grants = overrides.flatMap((value): PathGrant[] => {
    const override = recordValue(value);
    return typeof override.path === "string" && override.operation === operation
      ? [{ path: override.path, kind: "file", permissions: [operation] }]
      : [];
  });
  if (grants.length === 0) return false;
  const access = await evaluatePathAccessAsync({ operation, target: path, platform, grants });
  return access.allowed === true;
}

function broaderGrantTarget(path: string, workspace: string): string {
  const normalizedWorkspace = normalize(workspace);
  const parent = dirname(path);
  return isAbsolute(path) && (path === normalizedWorkspace || path.startsWith(`${normalizedWorkspace}/`) || path.startsWith(`${normalizedWorkspace}\\`))
    ? normalizedWorkspace
    : parent;
}

async function consumeOneTimePermission(context: Record<string, unknown>, capability: string, value: string): Promise<boolean> {
  if (typeof context.consumeOneTimePermission !== "function") return false;
  return await context.consumeOneTimePermission({ capability, value }) === true;
}


export async function interceptToolCall(
  event: Record<string, unknown>,
  context: Record<string, unknown>,
): Promise<Record<string, unknown> | undefined> {
  if (event.source === "user-bang" || event.source === "rpc") return undefined;
  if (event.source !== undefined && event.source !== "model") return undefined;
  const name = typeof event.toolName === "string" ? event.toolName : "";
  const input = recordValue(event.input);
  if (context.restorationFailed === true) {
    return { block: true, reason: "sandbox-restoration-failed" };
  }
  if (context.enabled !== true) return undefined;
  if (name === "bash" || name === "powershell") return { action: "sandbox" };
  if (name === "sandbox_request" || name === "job") return { action: "sandbox-adapter" };

  const policy = recordValue(context.sandboxPolicy ?? context.policy);
  if (name === "read" || name === "write" || name === "edit" || name === "ast_edit") {
    const operation = name === "read" ? "read" : "write";
    const targets = resolveToolTargets(name, input);
    const blockedTarget = targets.find((target) => target.blocked === true);
    if (blockedTarget) return { block: true, reason: blockedTarget.reason };
    const networkTarget = targets.find((target) => typeof target.host === "string");
    if (networkTarget) {
      const host = String(networkTarget.host);
      const networkResult = allowedInitialHost({ url: `https://${host}` }, policy);
      if (networkResult.action === "block") {
        const candidate = networkResult.reason === "local-network-not-granted" ? ["local-network", "allow"] : networkResult.reason === "network-host-not-granted" ? ["allowed-host", host] : undefined;
        if (candidate && await consumeOneTimePermission(context, candidate[0]!, candidate[1]!)) {
          return { action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged", oneTimeCapabilityConsumed: true };
        }
        return { block: true, reason: networkResult.reason };
      }
      return networkResult;
    }
    const grants = policyGrants(policy);
    const workspace = typeof context.workspace === "string" ? context.workspace : typeof context.cwd === "string" ? context.cwd : process.cwd();
    const evaluations = await Promise.all(targets.map(async (target) => {
      if (target.trustedInternal) return { allowed: operation === "read" || target.internalWrite === true, target };
      if (typeof target.path !== "string") return { allowed: false, target };
      const requestedPath = isAbsolute(target.path) ? normalize(target.path) : resolve(workspace, target.path);
      const resolvedTarget = { ...target, path: requestedPath };
      const accessInput = { operation, target: requestedPath, platform: context.platform ?? process.platform };
      const overridden = await hasExplicitDenyOverride(policy, operation, requestedPath, context.platform ?? process.platform);
      const denied = overridden
        ? { allowed: false }
        : await evaluatePathAccessAsync({ ...accessInput, grants: policyDenies(policy, operation) });
      const savedDenied = denied.allowed === true;
      if (savedDenied) return { allowed: false, savedDenied, target: resolvedTarget, canonicalTarget: denied.canonicalTarget ?? requestedPath };
      const access = await evaluatePathAccessAsync({ ...accessInput, grants });
      return { allowed: access.allowed === true, savedDenied: false, target: resolvedTarget, canonicalTarget: access.canonicalTarget ?? requestedPath };
    }));
    if (evaluations.length > 0 && evaluations.every((evaluation) => evaluation.allowed)) {
      return { action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged" };
    }
    const oneTimeAllowed = await Promise.all(evaluations.map(async (evaluation) => evaluation.allowed || (evaluation.savedDenied !== true
      && typeof evaluation.target.path === "string" && await consumeOneTimePermission(context, operation, String(evaluation.canonicalTarget)))));
    if (oneTimeAllowed.length > 0 && oneTimeAllowed.every(Boolean)) return { action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged", oneTimeCapabilityConsumed: true };
    if (typeof context.approveFileAccess !== "function") return { block: true, reason: "sandbox-policy-denied" };
    const unresolved = evaluations.filter((evaluation) => !evaluation.allowed && typeof evaluation.target.path === "string");
    if (unresolved.length === 0) return { block: true, reason: "sandbox-policy-denied" };
    const exactTargets = unresolved.map((evaluation) => String(evaluation.canonicalTarget));
    const broaderTargets = [...new Set(exactTargets.map((target) => broaderGrantTarget(target, workspace)))];
    const denyOverridePaths = unresolved
      .filter((evaluation) => evaluation.savedDenied === true)
      .map((evaluation) => String(evaluation.canonicalTarget));
    const choices = ["allow-operation-once", "allow-exact-conversation", "allow-parent-or-workspace-conversation", "deny"];
    const decision = await context.approveFileAccess({
      toolName: name,
      operation,
      targets: exactTargets,
      broaderTargets,
      workspace,
      savedDenyOverrideRequired: denyOverridePaths.length > 0,
      choices,
    });
    if (decision === "allow-operation-once") {
      return { action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged" };
    }
    if (decision !== "allow-exact-conversation" && decision !== "allow-parent-or-workspace-conversation") {
      return { block: true, reason: "sandbox-policy-denied" };
    }
    const values = decision === "allow-exact-conversation" ? exactTargets : broaderTargets;
    const requests = values.map((value) => ({
      capability: operation,
      value,
      scope: "conversation",
      ...(decision === "allow-parent-or-workspace-conversation" ? { recursive: true, kind: "directory" } : {}),
      ...(denyOverridePaths.length > 0 ? { explicitDenyOverride: true, denyOverridePaths } : {}),
    }));
    if (typeof context.applyGrants === "function") await context.applyGrants(requests);
    else if (requests.length === 1 && typeof context.applyGrant === "function") await context.applyGrant(requests[0]);
    else return { block: true, reason: "sandbox-policy-store-unavailable" };
    return { action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged" };
  }
  if (name === "lsp") {
    const workspace = typeof context.workspace === "string" ? context.workspace : typeof context.cwd === "string" ? context.cwd : "";
    const evaluation = evaluateLspAction({ readonly: input.readonly === true, workspace, grants: policyGrants(policy) });
    if (evaluation.action === "allow") return { action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged" };
    if (typeof context.approveLspAction !== "function") return { block: true, reason: "lsp-workspace-write-approval-required" };
    const decision = await context.approveLspAction({ ...evaluation, action: input.action, workspace });
    if (decision === "allow-action-once") return { action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged" };
    if (decision === "grant-recursive-workspace-write" && typeof context.applyGrant === "function") {
      await context.applyGrant({ capability: "write", value: workspace, recursive: true, kind: "directory", scope: "conversation" });
      return { action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged" };
    }
    return { block: true, reason: "lsp-workspace-write-denied" };
  }
  const classified = classifyToolCall({
    name,
    input,
    policy,
    enabled: true,
    trustedTools: context.trustedTools,
    mutationOrExecution: event.mutationOrExecution,
  });
  if (classified.action === "block") {
    const host = typeof classified.initialHost === "string" ? classified.initialHost : "";
    const candidate = classified.reason === "unrestricted-internet-required" ? ["internet", "allow"]
      : classified.reason === "local-network-not-granted" ? ["local-network", "allow"]
      : classified.reason === "network-host-not-granted" && host ? ["allowed-host", host]
      : classified.reason === "unknown-tool" ? ["trusted-tool", name]
      : undefined;
    if (candidate && await consumeOneTimePermission(context, candidate[0]!, candidate[1]!)) {
      return { action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged", oneTimeCapabilityConsumed: true };
    }
    return { block: true, reason: classified.reason };
  }
  if (classified.action === "allow-host-unchanged" && classified.reason === "non-mutating-tool") return undefined;
  return classified;
}

function validateCapabilityValue(capability: string, value: string, strictNetwork = false): void {
  if (strictNetwork && (capability === "internet" || capability === "local-network") && value !== "allow" && value !== "true") {
    throw new ToolGateError("INVALID_SANDBOX_CAPABILITY_VALUE", `${capability} requires value allow`);
  }
  if (capability === "ui" && !["allowWindows", "clipboardRead", "clipboardWrite", "inputInjection"].includes(value)) {
    throw new ToolGateError("INVALID_SANDBOX_CAPABILITY_VALUE", "Unsupported UI capability");
  }
  if (capability === "sensitive-environment-name" && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new ToolGateError("INVALID_SANDBOX_CAPABILITY_VALUE", "Sensitive environment capability requires an environment variable name");
  }
  if ((capability === "allowed-host" || capability === "blocked-host") && (value.includes("://") || /[\s/]/.test(value))) {
    throw new ToolGateError("INVALID_SANDBOX_CAPABILITY_VALUE", "Host capabilities require one exact hostname");
  }
}
const REQUEST_CAPABILITIES = new Set([
  "read",
  "write",
  "internet",
  "local-network",
  "allowed-host",
  "blocked-host",
  "sensitive-environment-name",
  "ui",
  "trusted-tool",
]);


export async function sandboxRequest(input: Record<string, unknown>, context: Record<string, unknown>): Promise<Record<string, unknown>> {
  let capability = input.capability;
  if (capability === "internet" && typeof input.value === "string" && input.value !== "allow" && input.value !== "true") capability = "allowed-host";
  if (typeof capability !== "string" || !REQUEST_CAPABILITIES.has(capability)) {
    throw new ToolGateError("UNSUPPORTED_SANDBOX_CAPABILITY", "The requested sandbox capability is not supported");
  }
  if (typeof input.value !== "string" || input.value.length === 0) {
    throw new ToolGateError("INVALID_SANDBOX_CAPABILITY_VALUE", "A non-empty capability value is required");
  }
  if (context.enforcePlatformCapabilities === true) validateCapabilityValue(capability, input.value);
  if (capability === "local-network" && context.enforcePlatformCapabilities === true && recordValue(context.platformCapabilities).independentLocalNetwork !== true) {
    throw new ToolGateError("LOCAL_NETWORK_CAPABILITY_UNPROVEN", "Local-network grants require a successful native traffic probe attestation");
  }
  let exactValue = input.value;
  const filesystemTarget = isAbsolute(input.value) ? input.value : typeof context.cwd === "string" ? resolve(context.cwd, input.value) : undefined;
  if ((capability === "read" || capability === "write") && filesystemTarget) {
    try {
      exactValue = String((await canonicalizeTarget(filesystemTarget)).canonical);
    } catch {
      throw new ToolGateError("INVALID_SANDBOX_CAPABILITY_VALUE", "Filesystem capability target could not be canonicalized");
    }
  }
  if (capability === "allowed-host" || capability === "blocked-host") exactValue = normalizedHostname(exactValue);
  const scope = input.saveTo === "user" || input.saveTo === "project" ? input.saveTo : "conversation";
  if (scope === "project" && context.projectTrusted !== true) {
    throw new ToolGateError("UNTRUSTED_PROJECT_PROFILE", "Project grants require an explicitly trusted project");
  }
  if (scope === "project" && capability === "sensitive-environment-name") {
    throw new ToolGateError("PROJECT_SECRET_PERSISTENCE_FORBIDDEN", "Project profiles cannot persist sensitive environment approvals");
  }
  const requestingAgent = typeof context.agentId === "string" && context.agentId.length > 0 ? context.agentId : "";
  if (!requestingAgent) throw new ToolGateError("REQUESTING_AGENT_UNRESOLVED", "The live requesting agent identity is required");
  const request = {
    requestId: typeof context.requestId === "string" ? context.requestId : crypto.randomUUID(),
    agentId: requestingAgent,
    operation: capability,
    target: exactValue,
    capability,
    value: exactValue,
    scope,
    sessionTreeId: context.sessionTreeId,
    requestingAgent,
    explicitSave: scope !== "conversation",
    headless: context.hasUI !== true,
  };
  let granted = false;
  let persistentGrant = false;
  let brokerResult: Record<string, unknown> = {};
  const permissionBroker = recordValue(context.permissionBroker ?? context.parentBroker);
  if (typeof permissionBroker.request === "function") {
    brokerResult = recordValue(await permissionBroker.request(request));
    granted = brokerResult.allowed === true || String(brokerResult.decision ?? "").startsWith("allow-");
    persistentGrant = brokerResult.decision === "allow-conversation";
  } else if (typeof context.approve === "function") {
    granted = await context.approve(request) === true;
    persistentGrant = granted;
  } else throw new ToolGateError("INTERACTIVE_APPROVAL_REQUIRED", "No session-tree permission broker can approve this request");
  if (persistentGrant) {
    if (typeof context.applyGrant !== "function") throw new ToolGateError("POLICY_STORE_UNAVAILABLE", "The approved grant cannot be applied to the effective conversation-tree policy");
    await context.applyGrant(request);
  }
  return { ...request, ...brokerResult, granted, oneTime: brokerResult.decision === "allow-once" };
}

export async function confirmCriticalCommand(input: Record<string, unknown>): Promise<Record<string, unknown>> {
  const shell = input.shell === "powershell" ? "powershell" : "bash";
  if (!detectCriticalCommand(shell, String(input.command ?? ""))) return { critical: false, approved: true };
  if (typeof input.confirm !== "function" || await input.confirm({ shell, command: input.command, cwd: input.cwd }) !== true) {
    throw new ToolGateError("CRITICAL_COMMAND_DECLINED", "Critical command confirmation was declined");
  }
  return { critical: true, approved: true };
}

export async function executeOutsideOnce(input: Record<string, unknown>): Promise<Record<string, unknown>> {
  if (input.outsideSandbox !== true) {
    throw new ToolGateError("OUTSIDE_SANDBOX_FLAG_REQUIRED", "The model must explicitly request outsideSandbox: true");
  }
  const approvalDetails = {
    callId: input.callId,
    command: input.command,
    cwd: input.cwd,
    requestingAgent: input.agentId,
    scope: "exact-call-once",
  };
  if (typeof input.approve !== "function" || await input.approve(approvalDetails) !== true) {
    throw new ToolGateError("OUTSIDE_EXECUTION_DECLINED", "Outside-sandbox execution was declined");
  }
  await confirmCriticalCommand({
    shell: input.shell,
    command: input.command,
    cwd: input.cwd,
    confirm: input.confirmCritical,
  });
  if (typeof input.executeHost !== "function") throw new ToolGateError("HOST_EXECUTOR_UNAVAILABLE", "No host executor is available");
  return recordValue(await input.executeHost({
    callId: input.callId,
    command: input.command,
    cwd: input.cwd,
    agentId: input.agentId,
    env: input.hostEnvironment,
    timeout: input.timeout,
  }));
}

export async function handleMxcLaunchFailure(input: Record<string, unknown>): Promise<Record<string, unknown>> {
  if (typeof input.choose !== "function") throw new ToolGateError("INTERACTIVE_FAILURE_CHOICE_REQUIRED", "MXC launch failure requires a TUI choice");
  const choice = await input.choose(["Retry sandbox", "Run this command outside once", "Disable sandbox for this conversation", "Cancel"]);
  if (choice === "Retry sandbox") return { retry: true };
  if (choice === "Run this command outside once") return executeOutsideOnce({ ...input, outsideSandbox: true });
  if (choice === "Disable sandbox for this conversation") return { disableRequested: true };
  if (choice === "Cancel") return { cancelled: true };
  throw new ToolGateError("INVALID_FAILURE_CHOICE", "MXC launch failure prompt returned an invalid choice");
}
