import { executeShell } from "../runtime/process";
import type { ShellToolRuntime } from "./bash";

type UnknownRecord = Record<string, unknown>;

export function createPowerShellTool(runtime: ShellToolRuntime): UnknownRecord {
  if (process.platform !== "win32") {
    throw Object.assign(new Error("The PowerShell tool is registered only on Windows"), { code: "WINDOWS_HOST_REQUIRED" });
  }
  return {
    name: "powershell",
    label: "PowerShell 7",
    description: "Run PowerShell 7 in a fresh MXC ProcessContainer",
    approval: "exec",
    async execute(input: UnknownRecord, context: UnknownRecord): Promise<UnknownRecord> {
      const ownership = await runtime.resolveScopedOwnership(context);
      return executeShell({
        ...input,
        shell: "powershell",
        platform: "win32",
        discovered: context.discoveredExecutables,
        policy: await runtime.getEffectivePolicy(context),
        ownerId: ownership.ownerId,
        sessionId: ownership.sessionId,
        scopedManager: ownership.scopedManager,
        liveMatches: ownership.liveMatches,
        hasInteractiveOverlay: context.hasUI === true && Boolean(context.ptyOverlay),
        overlay: context.ptyOverlay,
        executeHost: runtime.executeHost,
        approveOutsideOnce: runtime.approveOutsideOnce,
        confirmCritical: runtime.confirmCritical,
      });
    },
  };
}
