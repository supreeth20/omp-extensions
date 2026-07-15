export type PermissionRequest = Record<string, unknown>;
export type PermissionResult = Record<string, unknown>;

type Prompt = (request: PermissionRequest) => Promise<PermissionResult>;
type ResolveParent = (request: PermissionRequest) => unknown;
type PromptParent = (parent: unknown, request: PermissionRequest) => Promise<PermissionResult>;
type ExecuteSandboxed = (request: PermissionRequest, decision?: "allow-once" | "allow-conversation") => Promise<PermissionResult>;

interface BrokerOptions {
  prompt?: Prompt;
  resolveParent?: ResolveParent;
  promptParent?: PromptParent;
  executeSandboxed?: ExecuteSandboxed;
  sessionTreeId?: string;
}

interface CapabilityState {
  requestId: string;
  agentId: string;
  operation: string;
  target: string;
  usesRemaining: number;
}

class BrokerError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

function requiredString(request: PermissionRequest, key: string): string {
  const value = request[key];
  if (typeof value !== "string" || value === "") throw new BrokerError("INVALID_PERMISSION_REQUEST", `Missing ${key}`);
  return value;
}

export class PermissionBroker {
  readonly #options: BrokerOptions;
  #tail: Promise<void> = Promise.resolve();
  #capabilitySequence = 0;
  readonly #capabilities = new Map<string, CapabilityState>();
  readonly #conversationGrants = new Set<string>();

  constructor(options: BrokerOptions) {
    this.#options = options;
  }

  #grantKey(treeId: string, operation: string, target: string): string {
    return `${treeId}\u0000${operation}\u0000${target}`;
  }

  #enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const scheduled = this.#tail.then(operation, operation);
    this.#tail = scheduled.then(() => undefined, () => undefined);
    return scheduled;
  }

  #consumeCapability(request: PermissionRequest): PermissionResult {
    const supplied = request.consumeCapability;
    if (!supplied || typeof supplied !== "object" || Array.isArray(supplied) || !("capabilityId" in supplied)) {
      throw new BrokerError("INVALID_CAPABILITY", "A broker-issued capability is required");
    }
    const capabilityId = supplied.capabilityId;
    if (typeof capabilityId !== "string") throw new BrokerError("INVALID_CAPABILITY", "Capability identifier is invalid");
    const state = this.#capabilities.get(capabilityId);
    if (!state) throw new BrokerError("INVALID_CAPABILITY", "Capability is not owned by this broker");
    const requestId = requiredString(request, "requestId");
    const agentId = requiredString(request, "agentId");
    const operation = requiredString(request, "operation");
    const target = requiredString(request, "target");
    if (state.requestId !== requestId || state.agentId !== agentId) {
      throw new BrokerError("CAPABILITY_OWNER_MISMATCH", "Capability belongs to a different request or agent");
    }
    if (state.operation !== operation || state.target !== target) {
      throw new BrokerError("CAPABILITY_OPERATION_MISMATCH", "Capability is bound to a different operation");
    }
    if (state.usesRemaining === 0) throw new BrokerError("CAPABILITY_ALREADY_CONSUMED", "Capability was already consumed");
    state.usesRemaining -= 1;
    return { allowed: true, usesRemaining: state.usesRemaining };
  }

  async #prompt(request: PermissionRequest): Promise<PermissionResult> {
    if (request.headless === true) {
      requiredString(request, "agentId");
      const parent = this.#options.resolveParent?.(request);
      if (!parent || typeof parent !== "object" || Array.isArray(parent) || !("interactive" in parent) || parent.interactive !== true) {
        throw new BrokerError("NO_INTERACTIVE_PARENT", "No interactive parent can approve this request");
      }
      if (!this.#options.promptParent) throw new BrokerError("NO_INTERACTIVE_PARENT", "No parent prompt is available");
      return this.#options.promptParent(parent, request);
    }
    if (!this.#options.prompt) throw new BrokerError("NO_INTERACTIVE_PROMPT", "No interactive permission prompt is available");
    return this.#options.prompt(request);
  }

  request(request: PermissionRequest): Promise<PermissionResult> {
    if (request.consumeCapability !== undefined) {
      return Promise.resolve().then(() => this.#consumeCapability(request));
    }
    const operation = requiredString(request, "operation");
    const target = requiredString(request, "target");
    const treeId = typeof request.sessionTreeId === "string" ? request.sessionTreeId : this.#options.sessionTreeId;
    if (treeId && this.#conversationGrants.has(this.#grantKey(treeId, operation, target))) {
      return Promise.resolve({ allowed: true, source: "conversation-grant" });
    }

    return this.#enqueue(async () => {
      const decision = await this.#prompt(request);
      if (decision.decision === "allow-once") {
        const requestId = requiredString(request, "requestId");
        const agentId = requiredString(request, "agentId");
        const capabilityId = `capability-${++this.#capabilitySequence}`;
        const state: CapabilityState = { requestId, agentId, operation, target, usesRemaining: 1 };
        this.#capabilities.set(capabilityId, state);
        return {
          ...request,
          ...decision,
          capabilityToken: { capabilityId, ...state },
        };
      }
      if (decision.decision === "allow-conversation") {
        const grantTree = treeId ?? this.#options.sessionTreeId;
        if (grantTree) this.#conversationGrants.add(this.#grantKey(grantTree, operation, target));
        return { ...request, ...decision };
      }
      if (decision.decision === "deny") return { ...request, ...decision, allowed: false };
      throw new BrokerError("INVALID_PERMISSION_DECISION", "Prompt returned an unsupported decision");
    });
  }

  sandboxRun(request: PermissionRequest): Promise<PermissionResult> {
    return this.#enqueue(async () => {
      const decision = await this.#prompt(request);
      if (decision.decision !== "allow-once" && decision.decision !== "allow-conversation") {
        throw new BrokerError("PERMISSION_DENIED", "Sandbox run was not approved");
      }
      if (!this.#options.executeSandboxed) throw new BrokerError("SANDBOX_EXECUTOR_UNAVAILABLE", "No sandbox executor is available");
      if (decision.decision === "allow-once") {
        const requestId = requiredString(request, "requestId");
        const agentId = requiredString(request, "agentId");
        const operation = requiredString(request, "operation");
        const target = requiredString(request, "target");
        const capabilityId = `capability-${++this.#capabilitySequence}`;
        const state: CapabilityState = { requestId, agentId, operation, target, usesRemaining: 1 };
        this.#capabilities.set(capabilityId, state);
        this.#consumeCapability({ ...request, consumeCapability: { capabilityId } });
      }
      return this.#options.executeSandboxed(request, decision.decision);
    });
  }
}
