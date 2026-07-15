import { executeShell } from "../runtime/process";

type UnknownRecord = Record<string, unknown>;

export interface ShellToolRuntime {
  getConfiguredShell(context: UnknownRecord): string | Promise<string>;
  getEffectivePolicy(context: UnknownRecord): UnknownRecord | Promise<UnknownRecord>;
  resolveScopedOwnership(context: UnknownRecord): UnknownRecord | Promise<UnknownRecord>;
  executeHost?(input: UnknownRecord): Promise<UnknownRecord>;
  approveOutsideOnce?(input: UnknownRecord): Promise<boolean>;
  confirmCritical?(input: UnknownRecord): Promise<boolean>;
}

export function createBashTool(runtime: ShellToolRuntime): UnknownRecord {
  return {
    name: "bash",
    label: "Bash",
    description: "Run a configured POSIX shell command in a fresh MXC process sandbox",
    approval: "exec",
    async execute(input: UnknownRecord, context: UnknownRecord): Promise<UnknownRecord> {
      const ownership = await runtime.resolveScopedOwnership(context);
      return executeShell({
        ...input,
        shell: "bash",
        platform: process.platform,
        configuredShell: await runtime.getConfiguredShell(context),
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
