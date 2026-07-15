import { sandboxRun } from "../integration/tool-gate";

type UnknownRecord = Record<string, unknown>;

export function createSandboxRunTool(resolveContext: (context: UnknownRecord) => UnknownRecord | Promise<UnknownRecord>): UnknownRecord {
  return {
    name: "sandbox_run",
    label: "Sandbox Run",
    description: "Atomically approve capabilities and execute the exact command in MXC",
    approval: "exec",
    async execute(input: UnknownRecord, context: UnknownRecord): Promise<UnknownRecord> {
      return sandboxRun(input, await resolveContext(context));
    },
  };
}
