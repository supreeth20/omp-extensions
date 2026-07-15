export type StateRecord = Record<string, unknown>;

function isStateRecord(value: unknown): value is StateRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
export class ProcessSensitiveApprovalStore {
  readonly #approvals = new Map<string, Set<string>>();

  get(sessionTreeId: string, profileNames: readonly string[] = []): string[] {
    const processNames = this.#approvals.get(sessionTreeId) ?? new Set<string>();
    return [...new Set([...profileNames, ...processNames])];
  }

  approve(sessionTreeId: string, names: readonly string[]): string[] {
    const approvals = this.#approvals.get(sessionTreeId) ?? new Set<string>();
    for (const name of names) approvals.add(name);
    this.#approvals.set(sessionTreeId, approvals);
    return [...approvals];
  }

  deny(sessionTreeId: string, name: string): void {
    this.#approvals.get(sessionTreeId)?.delete(name);
  }

  clear(sessionTreeId: string): void {
    this.#approvals.delete(sessionTreeId);
  }
}

function mergeState(base: StateRecord, update: StateRecord): StateRecord {
  const result = structuredClone(base);
  for (const [key, value] of Object.entries(update)) {
    if (key === "version" || key === "snapshot") continue;
    const current = result[key];
    if (Array.isArray(value)) {
      result[key] = structuredClone(value);
    } else if (current && value && typeof current === "object" && typeof value === "object" && !Array.isArray(current) && !Array.isArray(value)) {
      result[key] = mergeState(current as StateRecord, value as StateRecord);
    } else {
      result[key] = structuredClone(value);
    }
  }
  return result;
}

function stateEntries(input: StateRecord): StateRecord[] {
  if (!Array.isArray(input.entries)) return [];
  return input.entries
    .filter(isStateRecord)
    .filter((entry) => entry.type === "custom" && entry.customType === "mxc-sandbox/state")
    .map((entry) => entry.data)
    .filter(isStateRecord)
    .filter((data) => data.version === 1);
}

export function reconstructState(input: StateRecord): StateRecord {
  const entries = stateEntries(input);
  let state: StateRecord = {};
  for (const entry of entries) state = mergeState(entry.snapshot === true ? {} : state, entry);

  const userProfile = input.profiles && typeof input.profiles === "object" && !Array.isArray(input.profiles)
    ? (input.profiles as StateRecord).user
    : undefined;
  const userEnvironment = userProfile && typeof userProfile === "object" && !Array.isArray(userProfile)
    ? (userProfile as StateRecord).environment
    : undefined;
  const persistedNames = userEnvironment && typeof userEnvironment === "object" && !Array.isArray(userEnvironment)
    && Array.isArray((userEnvironment as StateRecord).persistSensitiveNames)
    ? (userEnvironment as StateRecord).persistSensitiveNames as unknown[]
    : [];
  const profileNames = persistedNames.filter((name): name is string => typeof name === "string");
  const priorProcessNames = Array.isArray(state.sensitiveApprovedNames)
    ? state.sensitiveApprovedNames.filter((name): name is string => typeof name === "string")
    : [];
  if (input.processRestarted === true) {
    state.sensitiveApprovedNames = profileNames;
    state.pendingSensitivePrompt = priorProcessNames.filter((name) => !profileNames.includes(name));
  } else if (profileNames.length > 0) {
    state.sensitiveApprovedNames = [...new Set([...profileNames, ...priorProcessNames])];
  }
  return state;
}

const SERIALIZED_KEYS = ["enabled", "restorationFailed", "priorConversationPolicy", "filesystem", "network", "ui", "environment", "mxcOverrides", "trustedTools", "capabilityDenies", "explicitDenyOverrides", "projectTrust", "profileSources", "processIdentity", "policyRevision"] as const;

export function serializeState(state: StateRecord): StateRecord {
  const serialized: StateRecord = { version: 1 };
  for (const key of SERIALIZED_KEYS) {
    if (state[key] !== undefined) serialized[key] = structuredClone(state[key]);
  }
  return serialized;
}

export function snapshotBranchState(input: StateRecord): StateRecord {
  const current = input.currentState && typeof input.currentState === "object" && !Array.isArray(input.currentState)
    ? input.currentState as StateRecord
    : {};
  const serialized = serializeState(current);
  const { version: _version, ...controls } = serialized;
  return {
    type: "custom",
    customType: "mxc-sandbox/state",
    data: { version: 1, snapshot: true, ...controls },
    sessionId: input.newSessionId,
  };
}

export async function handleSessionLifecycle(event: StateRecord, store: StateRecord): Promise<StateRecord> {
  const supported = event.type === "session_start"
    || event.type === "session_switch"
    || event.type === "session_tree"
    || event.type === "session_resume";
  if (!supported) return { ...store, reconstructed: false };
  const processIdentity = typeof store.processIdentity === "string" ? store.processIdentity : undefined;
  const entries = Array.isArray(event.entries) ? event.entries : [];
  const latestIdentity = entries
    .filter(isStateRecord)
    .filter((entry) => entry.customType === "mxc-sandbox/state")
    .map((entry) => isStateRecord(entry.data) ? entry.data.processIdentity : undefined)
    .filter((identity): identity is string => typeof identity === "string")
    .at(-1);
  const processRestarted = processIdentity !== undefined && latestIdentity !== processIdentity;
  const restored = reconstructState({ entries, profiles: store.profiles ?? {}, processRestarted });
  for (const key of Object.keys(store)) delete store[key];
  Object.assign(store, restored, processIdentity === undefined ? {} : { processIdentity });
  return { ...store, sessionId: event.sessionId, reconstructed: true };
}
