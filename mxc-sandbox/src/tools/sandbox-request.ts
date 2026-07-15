import { sandboxRequest } from "../integration/tool-gate";

type UnknownRecord = Record<string, unknown>;

export function createSandboxRequestTool(resolveContext: (context: UnknownRecord) => UnknownRecord | Promise<UnknownRecord>): UnknownRecord {
  return {
    name: "sandbox_request",
    label: "Sandbox Request",
    description: "Request a specific sandbox capability before a dependent operation",
    approval: "write",
    async execute(input: UnknownRecord, context: UnknownRecord): Promise<UnknownRecord> {
      return sandboxRequest(input, await resolveContext(context));
    },
  };
}
