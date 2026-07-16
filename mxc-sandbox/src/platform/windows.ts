type UnknownRecord = Record<string, unknown>;

export const MINIMUM_WINDOWS_BUILD = 26100;
export const WINDOWS_HOST_PREP_COMMANDS = [
  "wxc-host-prep prepare-system-drive",
  "wxc-host-prep prepare-null-device",
] as const;

export class WindowsContainmentError extends Error {
  readonly code: string;
  readonly choices?: string[];

  constructor(code: string, message: string, choices?: string[]) {
    super(message);
    this.name = "WindowsContainmentError";
    this.code = code;
    if (choices !== undefined) this.choices = choices;
  }
}

export function deriveWindowsHostPreparation(input: UnknownRecord): UnknownRecord {
  const tier = input.isolationTier ?? input.tier;
  const warnings = Array.isArray(input.isolationWarnings)
    ? input.isolationWarnings.filter((warning): warning is string => typeof warning === "string")
    : Array.isArray(input.warnings) ? input.warnings.filter((warning): warning is string => typeof warning === "string") : [];
  const preparationWarning = warnings.some((warning) => /(?:host\s*prep|wxc-host-prep|system\s+drive|null\s+device|prepar(?:e|ation))/i.test(warning));
  const explicitlyRequired = input.preparationRequired === true || input.hostPreparationRequired === true || input.requiresHostPreparation === true;
  const explicitlyVerified = input.preparationVerified === true || input.hostPreparationVerified === true || input.prepared === true;
  const compatibilityTier = tier === "appcontainer-dacl" || tier === "tier-3" || tier === 3;
  const hostPreparationVerified = compatibilityTier && !explicitlyRequired && !preparationWarning
    && (explicitlyVerified || tier !== undefined);
  return {
    tier,
    warnings,
    preparationRequired: explicitlyRequired || preparationWarning,
    hostPreparationVerified,
  };
}
export function createWindowsProcessContainerOptions(input: UnknownRecord): UnknownRecord {
  const build = typeof input.windowsBuild === "number" ? input.windowsBuild : 0;
  if (build < MINIMUM_WINDOWS_BUILD) {
    throw new WindowsContainmentError("WINDOWS_BUILD_UNSUPPORTED", `Windows build ${MINIMUM_WINDOWS_BUILD} or newer is required`);
  }
  const compatibility = input.mode === "compatibility";
  if (compatibility && input.explicitDaclOptIn !== true) {
    throw new WindowsContainmentError("DACL_COMPATIBILITY_OPT_IN_REQUIRED", "Tier-3 compatibility requires explicit approval for temporary DACL mutation");
  }
  if (compatibility && input.hostPreparationVerified !== true) {
    throw new WindowsContainmentError("WINDOWS_HOST_PREPARATION_REQUIRED", "Tier-3 compatibility requires verified host preparation");
  }
  const tier = input.tier;
  const compatibilityTierAvailable = typeof tier === "number"
    ? tier >= 3
    : tier === "tier-3" || tier === "appcontainer-dacl" || tier === "compatibility";
  if (!compatibility && input.nativeEnforcementAvailable !== true) {
    throw new WindowsContainmentError("WINDOWS_NATIVE_ENFORCEMENT_UNAVAILABLE", "Strict ProcessContainer enforcement is unavailable and host fallback is forbidden");
  }
  if (compatibility && !compatibilityTierAvailable) {
    throw new WindowsContainmentError("WINDOWS_COMPATIBILITY_TIER_UNAVAILABLE", "ProcessContainer compatibility requires at least Tier 3");
  }
  return {
    backend: "processcontainer",
    fallback: { allowDaclMutation: compatibility },
    compatibilityMode: compatibility,
  };
}

export function assertWindowsNetworkPolicy(policy: UnknownRecord, capabilities: UnknownRecord): void {
  const network = policy.network && typeof policy.network === "object" ? policy.network as UnknownRecord : {};
  if ((Array.isArray(network.allowedHosts) && network.allowedHosts.length > 0)
    || (Array.isArray(network.blockedHosts) && network.blockedHosts.length > 0)) {
    throw new WindowsContainmentError("UNSUPPORTED_HOST_RULES", "ProcessContainer does not support host allow/block lists", ["block-network", "allow-unrestricted-network", "cancel"]);
  }
  if (network.localNetwork === true && capabilities.independentLocalNetwork !== true) {
    throw new WindowsContainmentError("LOCAL_NETWORK_CAPABILITY_UNPROVEN", "Local-network grants require a successful native traffic probe attestation");
  }
  if (network.localNetwork === false && network.internet === true
    && capabilities.internetLocalNetworkIsolation !== true
    && capabilities.independentLocalNetwork !== true) {
    throw new WindowsContainmentError("LOCAL_NETWORK_ENFORCEMENT_UNAVAILABLE", "Internet access was not proven to exclude local-network destinations by a native traffic probe");
  }
}

/** Diagnostic-only data. This function deliberately has no executor/elevation input. */
export function windowsDoctor(input: UnknownRecord): UnknownRecord {
  return {
    windowsBuild: typeof input.windowsBuild === "number" ? input.windowsBuild : undefined,
    tier: typeof input.tier === "number" || typeof input.tier === "string" ? input.tier : undefined,
    warnings: Array.isArray(input.warnings) ? input.warnings.filter((warning): warning is string => typeof warning === "string") : [],
    preparationRequired: input.preparationRequired === true,
    commands: [...WINDOWS_HOST_PREP_COMMANDS],
    elevationAttempted: false,
    commandExecutionAttempted: false,
    reprobed: input.reprobed === true,
  };
}
