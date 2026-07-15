type UnknownRecord = Record<string, unknown>;

type ScopedJobManager = {
  register(tool: string, process: unknown, options: { ownerId: string }): unknown;
  list?(ownerId: string): unknown;
  poll?(id: string, ownerId: string): unknown;
  cancel?(id: string, ownerId: string): unknown;
  deliverCompletion?(id: string, ownerId: string): unknown;
  sessionId?: string;
  ownerId?: string;
};

export class JobOwnershipError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "JobOwnershipError";
    this.code = code;
  }
}

function record(value: unknown): UnknownRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as UnknownRecord : {};
}

function validateLiveMatch(input: UnknownRecord, manager: ScopedJobManager, sessionId: string, agentId: string): void {
  const matches = Array.isArray(input.liveMatches) ? input.liveMatches.map(record) : [];
  if (matches.length === 0) {
    throw new JobOwnershipError("SCOPED_JOB_OWNERSHIP_MISMATCH", "Async execution requires a live registry session/owner/scoped-manager match");
  }
  const exact = matches.filter((match) => match.sessionId === sessionId
    && match.agentId === agentId
    && match.scopedManager === manager
    && match.live === true);
  if (exact.length !== 1) {
    throw new JobOwnershipError("SCOPED_JOB_OWNERSHIP_MISMATCH", "Async execution requires exactly one live session/owner/scoped-manager match");
  }
  if (typeof manager.sessionId === "string" && manager.sessionId !== sessionId) {
    throw new JobOwnershipError("SCOPED_JOB_OWNERSHIP_MISMATCH", "The scoped manager belongs to a different session");
  }
  if (typeof manager.ownerId === "string" && manager.ownerId !== agentId) {
    throw new JobOwnershipError("SCOPED_JOB_OWNERSHIP_MISMATCH", "The scoped manager belongs to a different owner");
  }
}

export async function registerMxcJob(input: UnknownRecord): Promise<UnknownRecord> {
  const manager = input.scopedManager as ScopedJobManager | null | undefined;
  if (!manager || typeof manager.register !== "function") {
    throw new JobOwnershipError("SCOPED_JOB_MANAGER_REQUIRED", "A validated session-scoped async job manager is required");
  }
  const agentId = typeof input.agentId === "string" && input.agentId.length > 0 ? input.agentId : "";
  if (!agentId) throw new JobOwnershipError("ASYNC_OWNER_REQUIRED", "The exact live agent owner ID is required");
  const sessionId = typeof input.sessionId === "string" && input.sessionId.length > 0 ? input.sessionId : "";
  if (!sessionId) {
    throw new JobOwnershipError("ASYNC_SESSION_REQUIRED", "The exact live session ID is required for registry validation");
  }
  validateLiveMatch(input, manager, sessionId, agentId);
  const tool = input.tool === "powershell" ? "powershell" : "bash";
  const registered = record(await manager.register(tool, input.process, { ownerId: agentId }));
  const id = typeof registered.id === "string" ? registered.id : "";
  if (!id) throw new JobOwnershipError("ASYNC_JOB_REGISTRATION_FAILED", "The scoped manager did not return a job ID");
  return {
    ...registered,
    list: () => manager.list?.(agentId),
    poll: () => manager.poll?.(id, agentId),
    cancel: () => manager.cancel?.(id, agentId),
    deliverCompletion: () => manager.deliverCompletion?.(id, agentId),
  };
}
