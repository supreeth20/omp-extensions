import { describe, expect, test } from "bun:test";
import { expectAsyncFailureCode, loadContract, requiredExport } from "./contracts";

type ReconstructState = (input: Record<string, unknown>) => Record<string, any>;
type SerializeState = (state: Record<string, unknown>) => Record<string, unknown>;
type SnapshotBranch = (input: Record<string, unknown>) => Record<string, unknown>;
type HandleLifecycle = (event: Record<string, unknown>, store: Record<string, unknown>) => Promise<Record<string, unknown>>;
type PermissionRequest = Record<string, any>;
type Broker = {
  request(input: PermissionRequest): Promise<Record<string, any>>;
};
type BrokerConstructor = new (options: Record<string, unknown>) => Broker;

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  const { promise, resolve } = Promise.withResolvers<T>();
  return { promise, resolve };
}

describe("conversation state", () => {
  test("reconstructs enabled state and effective grants from custom entries", async () => {
    const mod = await loadContract("state");
    const reconstruct = requiredExport<ReconstructState>(mod, "reconstructState");
    const state = reconstruct({
      entries: [
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: ["/repo"] }, network: { internet: false } } },
        { type: "custom", customType: "other-extension", data: { enabled: false } },
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, filesystem: { write: ["/repo/out"] } } },
      ],
      profiles: { user: { version: 1 } },
      processIdentity: "process-2",
    });
    expect(state).toMatchObject({ enabled: true, filesystem: { read: ["/repo"], write: ["/repo/out"] }, network: { internet: false } });
  });

  test("applies ordered revocation and clear snapshots without resurrecting grants", async () => {
    const mod = await loadContract("state");
    const reconstruct = requiredExport<ReconstructState>(mod, "reconstructState");
    const state = reconstruct({ entries: [
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, filesystem: { read: ["/repo/a", "/repo/b"], write: ["/repo/out"] } } },
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, filesystem: { read: ["/repo/a"] } } },
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, snapshot: true, filesystem: { read: [], write: [] } } },
    ] });
    expect(state.filesystem).toEqual({ read: [], write: [] });
  });

  test("restores state on start, switch, tree navigation, and resume", async () => {
    const mod = await loadContract("state");
    const handle = requiredExport<HandleLifecycle>(mod, "handleSessionLifecycle");
    for (const type of ["session_start", "session_switch", "session_tree", "session_resume"]) {
      const result = await handle({ type, sessionId: "S1", entries: [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true } }] }, {});
      expect(result).toMatchObject({ sessionId: "S1", enabled: true, reconstructed: true });
    }
  });

  test("branches inherit the current effective state rather than historical branch position", async () => {
    const mod = await loadContract("state");
    const snapshot = requiredExport<SnapshotBranch>(mod, "snapshotBranchState");
    const current = { enabled: true, filesystem: { read: ["/repo"], write: ["/repo/later"] }, trustedTools: ["vendor.safe"] };
    const entry = snapshot({ currentState: current, branchFromEntryId: "before-later-grant", newSessionId: "branch-2" });
    expect(entry).toEqual({
      type: "custom",
      customType: "mxc-sandbox/state",
      data: { version: 1, snapshot: true, enabled: true, filesystem: { read: ["/repo"], write: ["/repo/later"] }, trustedTools: ["vendor.safe"] },
      sessionId: "branch-2",
    });
  });

  test("persists controls but never secrets, one-time grants, handles, or a second audit log", async () => {
    const mod = await loadContract("state");
    const serialize = requiredExport<SerializeState>(mod, "serializeState");
    const serialized = serialize({
      enabled: true,
      filesystem: { read: ["/repo"] },
      network: { internet: false },
      ui: { allowWindows: true },
      trustedTools: ["vendor.safe"],
      projectTrust: true,
      profileSources: [{ source: "user", version: 1 }],
      sensitiveApprovals: { API_TOKEN: "actual-secret" },
      oneTimeGrants: [{ id: "grant-1" }],
      processHandles: [{ pid: 42 }],
      auditLog: [{ action: "read" }],
    });
    expect(serialized).toEqual({
      version: 1,
      enabled: true,
      filesystem: { read: ["/repo"] },
      network: { internet: false },
      ui: { allowWindows: true },
      trustedTools: ["vendor.safe"],
      projectTrust: true,
      profileSources: [{ source: "user", version: 1 }],
    });
    expect(JSON.stringify(serialized)).not.toContain("actual-secret");
  });

  test("re-prompts process-local secret approval after restart but retains user-profile names", async () => {
    const mod = await loadContract("state");
    const reconstruct = requiredExport<ReconstructState>(mod, "reconstructState");
    const state = reconstruct({
      entries: [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, sensitiveApprovedNames: ["API_TOKEN"] } }],
      profiles: { user: { version: 1, environment: { persistSensitiveNames: ["GITHUB_TOKEN"] } } },
      processRestarted: true,
    });
    expect(state.sensitiveApprovedNames).toEqual(["GITHUB_TOKEN"]);
    expect(state.pendingSensitivePrompt).toContain("API_TOKEN");
  });

  test("replaces prior conversation state and clears absent transient secret approvals", async () => {
    const mod = await loadContract("state");
    const handle = requiredExport<HandleLifecycle>(mod, "handleSessionLifecycle");
    const store: Record<string, unknown> = {
      processIdentity: "process-live",
      enabled: true,
      sensitiveApprovedNames: ["OLD_CONVERSATION_TOKEN"],
      pendingSensitivePrompt: ["STALE"],
      trustedTools: ["old.tool"],
    };
    const result = await handle({
      type: "session_switch",
      sessionId: "S2",
      entries: [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, processIdentity: "process-live", enabled: true, filesystem: { read: [] } } }],
    }, store);
    expect(store).toEqual({ processIdentity: "process-live", enabled: true, filesystem: { read: [] } });
    expect(result).not.toHaveProperty("sensitiveApprovedNames");
    expect(result).not.toHaveProperty("trustedTools");
  });
});

describe("permission broker", () => {
  test("serializes simultaneous permission dialogs", async () => {
    const mod = await loadContract("broker");
    const PermissionBroker = requiredExport<BrokerConstructor>(mod, "PermissionBroker");
    const first = deferred<Record<string, string>>();
    const second = deferred<Record<string, string>>();
    const prompts: PermissionRequest[] = [];
    const broker = new PermissionBroker({
      prompt: (request: PermissionRequest) => {
        prompts.push(request);
        return prompts.length === 1 ? first.promise : second.promise;
      },
    });
    const result1 = broker.request({ requestId: "R1", agentId: "A1", operation: "read", target: "/a" });
    const result2 = broker.request({ requestId: "R2", agentId: "A2", operation: "write", target: "/b" });
    await Promise.resolve();
    expect(prompts.map((prompt) => prompt.requestId)).toEqual(["R1"]);
    first.resolve({ decision: "allow-once" });
    expect(await result1).toMatchObject({ requestId: "R1", agentId: "A1", decision: "allow-once" });
    await Promise.resolve();
    expect(prompts.map((prompt) => prompt.requestId)).toEqual(["R1", "R2"]);
    second.resolve({ decision: "deny" });
    expect(await result2).toMatchObject({ requestId: "R2", agentId: "A2", decision: "deny" });
  });

  test("binds one-time grants to the exact request and agent", async () => {
    const mod = await loadContract("broker");
    const PermissionBroker = requiredExport<BrokerConstructor>(mod, "PermissionBroker");
    const broker = new PermissionBroker({ prompt: async () => ({ decision: "allow-once" }) });
    const granted = await broker.request({ requestId: "R1", agentId: "A1", operation: "write", target: "/repo/a" });
    expect(granted).toMatchObject({ capabilityToken: { requestId: "R1", agentId: "A1", operation: "write", target: "/repo/a", usesRemaining: 1 } });
    await expectAsyncFailureCode(() => broker.request({ requestId: "R2", agentId: "A2", consumeCapability: granted.capabilityToken, operation: "write", target: "/repo/a" }), "CAPABILITY_OWNER_MISMATCH");
    const consumed = await broker.request({ requestId: "R1", agentId: "A1", consumeCapability: granted.capabilityToken, operation: "write", target: "/repo/a" });
    expect(consumed).toMatchObject({ allowed: true, usesRemaining: 0 });
    await expectAsyncFailureCode(() => broker.request({ requestId: "R1", agentId: "A1", consumeCapability: granted.capabilityToken, operation: "write", target: "/repo/a" }), "CAPABILITY_ALREADY_CONSUMED");
  });

  test("bubbles headless subagent requests to the identified interactive parent", async () => {
    const mod = await loadContract("broker");
    const PermissionBroker = requiredExport<BrokerConstructor>(mod, "PermissionBroker");
    const seen: PermissionRequest[] = [];
    const broker = new PermissionBroker({
      resolveParent: (request: PermissionRequest) => request.agentId === "child" ? { agentId: "main", interactive: true } : null,
      promptParent: async (parent: unknown, request: PermissionRequest) => { seen.push({ parent, ...request }); return { decision: "allow-conversation" }; },
    });
    expect(await broker.request({ requestId: "R1", agentId: "child", headless: true, operation: "read", target: "/repo/a" })).toMatchObject({ decision: "allow-conversation" });
    expect(seen).toEqual([{ parent: { agentId: "main", interactive: true }, requestId: "R1", agentId: "child", headless: true, operation: "read", target: "/repo/a" }]);
  });

  test("fails closed when a new prompt has no interactive parent", async () => {
    const mod = await loadContract("broker");
    const PermissionBroker = requiredExport<BrokerConstructor>(mod, "PermissionBroker");
    const broker = new PermissionBroker({ resolveParent: () => null });
    await expectAsyncFailureCode(() => broker.request({ requestId: "R1", agentId: "child", headless: true, operation: "read", target: "/repo/a" }), "NO_INTERACTIVE_PARENT");
  });

  test("applies a conversation grant to existing and future session-tree agents", async () => {
    const mod = await loadContract("broker");
    const PermissionBroker = requiredExport<BrokerConstructor>(mod, "PermissionBroker");
    const broker = new PermissionBroker({ prompt: async () => ({ decision: "allow-conversation" }), sessionTreeId: "TREE1" });
    await broker.request({ requestId: "R1", agentId: "main", operation: "read", target: "/repo/data" });
    expect(await broker.request({ requestId: "R2", agentId: "existing-child", sessionTreeId: "TREE1", operation: "read", target: "/repo/data" })).toMatchObject({ allowed: true, source: "conversation-grant" });
    expect(await broker.request({ requestId: "R3", agentId: "future-child", sessionTreeId: "TREE1", operation: "read", target: "/repo/data" })).toMatchObject({ allowed: true, source: "conversation-grant" });
  });

});
