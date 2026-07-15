type UnknownRecord = Record<string, unknown>;

export function createLinuxBubblewrapOptions(capabilities: UnknownRecord): UnknownRecord {
  if (process.platform !== "linux" && capabilities.allowCrossPlatformPlanning !== true) {
    throw Object.assign(new Error("Bubblewrap preview requires a genuine Linux host"), { code: "LINUX_HOST_REQUIRED" });
  }
  if (capabilities.nativeBubblewrap !== true) {
    throw Object.assign(new Error("A native MXC Bubblewrap probe is required; no host fallback is permitted"), { code: "BUBBLEWRAP_NATIVE_PROBE_REQUIRED" });
  }
  return { backend: "bubblewrap", preview: true, hostFallback: false };
}
