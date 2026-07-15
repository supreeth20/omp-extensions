type UnknownRecord = Record<string, unknown>;

export class MacosContainmentError extends Error {
  readonly code: string;
  readonly choices?: string[];

  constructor(code: string, message: string, choices?: string[]) {
    super(message);
    this.name = "MacosContainmentError";
    this.code = code;
    if (choices !== undefined) this.choices = choices;
  }
}

const NETWORK_CHOICES = ["block-network", "allow-unrestricted-network", "cancel"];

export function assertMacosSeatbeltPolicy(policy: UnknownRecord, capabilities: UnknownRecord): void {
  if (process.platform !== "darwin" && capabilities.allowCrossPlatformPlanning !== true) {
    throw new MacosContainmentError("MACOS_HOST_REQUIRED", "Seatbelt containment requires a genuine macOS host");
  }
  const network = policy.network && typeof policy.network === "object" ? policy.network as UnknownRecord : {};
  if (Array.isArray(network.blockedHosts) && network.blockedHosts.length > 0) {
    throw new MacosContainmentError("UNSUPPORTED_HOST_RULES", "MXC Seatbelt cannot enforce blockedHosts", NETWORK_CHOICES);
  }
  if (Array.isArray(network.allowedHosts) && network.allowedHosts.length > 0) {
    throw new MacosContainmentError("UNSUPPORTED_HOST_RULES", "This MXC Seatbelt runtime cannot enforce allowedHosts", NETWORK_CHOICES);
  }
  if (network.localNetwork === true && capabilities.independentLocalNetwork !== true && capabilities.coupledNetwork !== true) {
    throw new MacosContainmentError("LOCAL_NETWORK_CAPABILITY_UNPROVEN", "Local-network grants require a successful native traffic probe attestation");
  }
  if (network.localNetwork === false && network.internet === true && capabilities.independentLocalNetwork !== true && capabilities.coupledNetwork !== true) {
    throw new MacosContainmentError("LOCAL_NETWORK_ENFORCEMENT_UNAVAILABLE", "Independent local-network blocking was not proven by a native traffic probe");
  }
}

export function createMacosSeatbeltOptions(input: UnknownRecord): UnknownRecord {
  const ui = input.ui && typeof input.ui === "object" ? input.ui as UnknownRecord : {};
  return {
    backend: "seatbelt",
    guiAccess: ui.allowWindows === true,
    launchMethod: input.launchMethod === "sandbox-exec" ? "sandbox-exec" : "direct",
  };
}
