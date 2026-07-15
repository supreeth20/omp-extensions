import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REQUIRED_FEATURES = [
  "sameNameBashReplacement",
  "disabledBashDelegate",
  "preToolInterception",
  "sessionStatePersistence",
  "interactivePermissionUi",
  "mxcExecution",
  "artifactAllocation",
] as const;

const MODULE_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const DEFAULT_EXTENSION_DIRECTORY = basename(MODULE_DIRECTORY) === "dist" ? dirname(MODULE_DIRECTORY) : resolve(MODULE_DIRECTORY, "../..");
const SDK_SPECIFIER = "@microsoft/mxc-sdk@^0.7.0";

export class ActivationError extends Error {
  readonly code: string;
  readonly details?: Record<string, unknown>;

  constructor(code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "ActivationError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

type ActivationInput = Record<string, unknown>;
type RegistryRef = Record<string, unknown>;

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function scopedOwnerMapping(input: ActivationInput): Record<string, unknown> {
  const sessionId = typeof input.sessionId === "string" ? input.sessionId : "";
  const refs = Array.isArray(input.registryRefs) ? input.registryRefs as RegistryRef[] : [];
  const matches = refs.filter((ref) => ref && ref.sessionId === sessionId);
  if (matches.length > 1) return { ok: false, missing: ["safeAsyncOwnerMapping"], reason: "ambiguous-session" };
  if (matches.length === 0) return { ok: false, missing: ["safeAsyncOwnerMapping"], reason: "session-not-found" };
  const match = matches[0]!;
  if (match.agentSessionId !== match.id || !match.scopedManager || typeof match.scopedManager !== "object") {
    return { ok: false, missing: ["safeAsyncOwnerMapping"], reason: "unverified-session-owner" };
  }
  return { ok: true, ownerId: match.id, scopedManager: match.scopedManager };
}

export async function probeActivationFeatures(input: ActivationInput): Promise<Record<string, unknown>> {
  if (input.capabilities && typeof input.capabilities === "object") {
    const capabilities = input.capabilities as Record<string, unknown>;
    const missing = REQUIRED_FEATURES.filter((name) => capabilities[name] !== true);
    return missing.length === 0 ? { ok: true, missing: [] } : { ok: false, missing };
  }
  return scopedOwnerMapping(input);
}

export function probePublicOmpRuntime(api: Record<string, unknown>, context: Record<string, unknown> = {}): Record<string, unknown> {
  const sameNameBashReplacement = typeof api.registerTool === "function";
  const sessionManager = recordValue(context.sessionManager);
  const pi = recordValue(api.pi);
  const sessionId = typeof sessionManager.getSessionId === "function" ? sessionManager.getSessionId() : context.sessionId;
  const agentId = typeof context.agentId === "string" ? context.agentId : "";
  const scopedManager = context.scopedManager;
  const liveMatches = Array.isArray(context.liveMatches) ? context.liveMatches.map(recordValue) : [];
  const ownershipMatches = liveMatches.filter((match) => match.live === true
    && match.sessionId === sessionId
    && match.agentId === agentId
    && match.scopedManager === scopedManager);
  const capabilities: Record<string, boolean> = {
    sameNameBashReplacement,
    disabledBashDelegate: typeof api.exec === "function",
    preToolInterception: typeof api.on === "function",
    sessionStatePersistence: typeof api.appendEntry === "function" && typeof sessionManager.getBranch === "function",
    interactivePermissionUi: context.hasUI === true && Boolean(context.ui),
    mxcExecution: context.mxcExecutionVerified === true,
    safeAsyncOwnerMapping: typeof sessionId === "string" && sessionId.length > 0 && agentId.length > 0
      && Boolean(scopedManager) && ownershipMatches.length === 1,
    renderer: typeof context.shellRenderer === "function" || Boolean(pi.bashToolRenderer || pi.createShellRenderer),
    outputSink: typeof context.onShellUpdate === "function" || Boolean(pi.OutputSink),
    artifactAllocation: typeof sessionManager.allocateArtifactPath === "function",
  };
  const missing = REQUIRED_FEATURES.filter((name) => !capabilities[name]);
  return {
    ok: missing.length === 0,
    missing,
    capabilities,
    ...(ownershipMatches.length === 1 ? { ownership: { sessionId, agentId, scopedManager, liveMatches } } : {}),
    diagnostic: missing.length === 0
      ? undefined
      : `Required OMP/MXC enforcement facilities are unavailable: ${missing.join(", ")}. Sandbox activation is refused.`,
  };
}

function installCommand(extensionDirectory: string): string {
  return `cd ${extensionDirectory} && bun add ${SDK_SPECIFIER}`;
}

function sdkSchemaVersion(sdk: Record<string, unknown>): string | undefined {
  const schemas = Array.isArray(sdk.schemaVersions) ? sdk.schemaVersions : [];
  return schemas.includes("0.7.0-alpha") ? "0.7.0-alpha" : undefined;
}

export async function activateSandbox(input: ActivationInput): Promise<Record<string, unknown>> {
  if (input.action !== "enable") return { enabled: false, action: input.action ?? "status" };
  const parentBroker = recordValue(input.parentBroker);
  const parentInteractive = parentBroker.interactive === true || parentBroker.validated === true;
  const restoring = input.restore === true;
  if (!restoring && input.hasUI !== true && !parentInteractive) {
    throw new ActivationError("INTERACTIVE_SETUP_REQUIRED", "Sandbox setup requires the TUI or a validated interactive parent broker");
  }

  const dependencies = recordValue(input.dependencies);
  if (typeof dependencies.loadMxc !== "function") {
    throw new ActivationError("MXC_LOADER_UNAVAILABLE", "No deferred MXC loader is available");
  }

  let sdk = recordValue(await dependencies.loadMxc());
  const extensionDirectory = typeof input.extensionDirectory === "string" ? input.extensionDirectory : DEFAULT_EXTENSION_DIRECTORY;
  if (Object.keys(sdk).length === 0) {
    if (restoring) throw new ActivationError("DEPENDENCY_REPROBE_FAILED", "MXC is unavailable while restoring persisted enabled state");
    const command = installCommand(extensionDirectory);
    if (typeof dependencies.confirmInstall !== "function" || await dependencies.confirmInstall(command) !== true) {
      throw new ActivationError("DEPENDENCY_INSTALL_DECLINED", "MXC dependency installation was not approved", { command });
    }
    if (typeof dependencies.executeInstall !== "function") {
      throw new ActivationError("DEPENDENCY_INSTALL_UNAVAILABLE", "No approved dependency installer is available", { command });
    }
    const install = recordValue(await dependencies.executeInstall(command));
    if (install.exitCode !== 0) {
      throw new ActivationError("DEPENDENCY_INSTALL_FAILED", "MXC dependency installation failed", { command, exitCode: install.exitCode });
    }
    sdk = recordValue(await dependencies.loadMxc());
    if (Object.keys(sdk).length === 0) throw new ActivationError("DEPENDENCY_REPROBE_FAILED", "MXC was unavailable after installation");
  }

  const platform = typeof input.platform === "string" ? input.platform : process.platform;
  const platformSupport = typeof sdk.reprobePlatformSupport === "function"
    ? recordValue(await sdk.reprobePlatformSupport())
    : {};
  const diagnostics = typeof dependencies.probePlatformDiagnostics === "function"
    ? recordValue(await dependencies.probePlatformDiagnostics({ sdk, platform, platformSupport }))
    : {};
  let approvedWindowsMode: "strict" | "compatibility" | undefined = input.approvedWindowsMode === "compatibility" ? "compatibility" : input.approvedWindowsMode === "strict" ? "strict" : undefined;
  if (platform === "win32" && approvedWindowsMode === "compatibility" && diagnostics.hostPreparationVerified !== true) {
    throw new ActivationError("WINDOWS_HOST_PREPARATION_REQUIRED", "Compatibility mode requires verified operator host preparation");
  }
  if (platform === "win32" && typeof input.chooseWindowsMode === "function") {
    const selected = await input.chooseWindowsMode({ ...platformSupport, ...diagnostics });
    if (selected !== "strict" && selected !== "compatibility") {
      throw new ActivationError("SETUP_CANCELLED", "Windows containment mode was not selected");
    }
    if (selected === "compatibility" && diagnostics.hostPreparationVerified !== true) {
      throw new ActivationError("WINDOWS_HOST_PREPARATION_REQUIRED", "Compatibility mode requires verified operator host preparation");
    }
    approvedWindowsMode = selected;
  }
  if (typeof dependencies.probeMxcExecution !== "function") {
    throw new ActivationError("MXC_CONTAINMENT_PROBE_UNAVAILABLE", "A real contained MXC dry-run is required");
  }
  const execution = recordValue(await dependencies.probeMxcExecution({
    sdk,
    platform,
    platformSupport,
    platformCapabilities: diagnostics,
    windowsMode: approvedWindowsMode,
    allowDaclMutation: approvedWindowsMode === "compatibility",
  }));
  if (execution.contained !== true) {
    throw new ActivationError("MXC_CONTAINMENT_PROBE_FAILED", "MXC failed its contained execution dry-run", { probe: execution });
  }

  if (typeof dependencies.probeOmp !== "function") {
    throw new ActivationError("OMP_FEATURE_PROBE_UNAVAILABLE", "Required OMP facilities were not probed");
  }
  const omp = recordValue(await dependencies.probeOmp());
  if (omp.allRequired !== true) {
    const missing = Array.isArray(omp.missing) ? omp.missing.filter((name): name is string => typeof name === "string") : [];
    throw new ActivationError("OMP_ACTIVATION_FEATURES_MISSING", `Required OMP enforcement facilities are unavailable: ${missing.join(", ")}`, {
      missing,
      diagnostic: omp.diagnostic,
    });
  }

  const schemaVersion = sdkSchemaVersion(sdk);
  if (!schemaVersion) throw new ActivationError("MXC_SCHEMA_UNSUPPORTED", "MXC does not expose the required 0.7.0-alpha policy schema");
  const reprobedPlatformSupport = typeof sdk.reprobePlatformSupport === "function"
    ? recordValue(await sdk.reprobePlatformSupport())
    : Object.keys(platformSupport).length > 0 ? platformSupport : recordValue(execution.platformSupport);
  const platformCapabilities = { ...diagnostics, ...recordValue(execution.platformCapabilities) };
  return {
    enabled: false,
    setupRequired: true,
    sdkVersion: sdk.version,
    schemaVersion,
    backend: execution.backend,
    platformSupport: reprobedPlatformSupport,
    platformCapabilities,
    ...(approvedWindowsMode ? { approvedWindowsMode } : {}),
    requiredReadonlyPaths: execution.readonlyPathDiscoveryAttested === true && Array.isArray(execution.requiredReadonlyPaths)
      ? execution.requiredReadonlyPaths.filter((path): path is string => typeof path === "string" && path.length > 0)
      : [],
  };
}
