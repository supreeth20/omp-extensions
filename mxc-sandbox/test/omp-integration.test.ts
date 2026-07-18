import { describe, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { createConnection } from "node:net";
import { expectAsyncFailureCode, loadContract, requiredExport } from "./contracts";
function isRecord(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}


type ExtensionFactory = (api: RecordingApi, dependencies?: Record<string, unknown>) => void | Promise<void>;
type ActivateSandbox = (input: Record<string, any>) => Promise<Record<string, any>>;
type ProbeActivation = (input: Record<string, any>) => Promise<Record<string, any>>;
type ParseCommand = (args: string) => Record<string, any>;
type SetupDefaults = (input: Record<string, unknown>) => Record<string, any>;
type DashboardModel = (input: Record<string, unknown>) => Record<string, any>;
type DashboardPresentation = (input: Record<string, unknown>) => Record<string, any>;

type FailureChoices = () => string[];
type InterceptToolCall = (event: Record<string, any>, context: Record<string, any>) => Promise<Record<string, any> | undefined>;
type OutsideOnce = (input: Record<string, any>) => Promise<Record<string, any>>;
type DisableSandbox = (input: Record<string, any>) => Promise<Record<string, any>>;

class RecordingApi {
  readonly commands = new Map<string, Record<string, unknown>>();
  readonly tools = new Map<string, Record<string, unknown>>();
  readonly handlers = new Map<string, ((...arguments_: unknown[]) => unknown)[]>();
  readonly entries: Record<string, unknown>[] = [];
  hostRuns = 0;
  readonly execCalls: unknown[][] = [];

  registerCommand(name: string, definition: Record<string, unknown>): void {
    this.commands.set(name, definition);
  }

  registerTool(definition: Record<string, unknown>): void {
    this.tools.set(String(definition.name), definition);
  }

  on(event: string, handler: (...arguments_: unknown[]) => unknown): void {
    this.handlers.set(event, [...(this.handlers.get(event) ?? []), handler]);
  }

  appendEntry(customType: string, data: Record<string, unknown>): void {
    this.entries.push({ customType, data });
  }

  async exec(...arguments_: unknown[]): Promise<Record<string, unknown>> {
    this.execCalls.push(arguments_);
    this.hostRuns += 1;
    return { code: 0, stdout: "host", stderr: "", killed: false };
  }
}


function enabledLifecycleContext(entries: Record<string, unknown>[], overrides: Record<string, any> = {}): Record<string, any> {
  const scopedManager = {};
  const sessionManager = {
    getSessionId: () => "S1",
    getBranch: () => entries,
    allocateArtifactPath: async () => ({ id: "ART", path: join(tmpdir(), `mxc-artifact-${crypto.randomUUID()}`) }),
  };
  return {
    hasUI: true,
    cwd: process.cwd(),
    agentId: "A1",
    configuredShell: "/bin/zsh",
    discoveredExecutables: ["C:\\Program Files\\Git\\bin\\bash.exe", "C:\\Program Files\\PowerShell\\7\\pwsh.exe"],
    sessionManager,
    scopedManager,
    liveMatches: [{ live: true, sessionId: "S1", agentId: "A1", scopedManager }],
    shellRenderer: async () => undefined,
    onShellUpdate: () => undefined,
    ui: {},
    ...overrides,
  };
}

const successfulRestoreDependencies = {
  loadMxc: async () => ({ version: "0.7.0", schemaVersions: ["0.7.0-alpha"] }),
  probeMxcExecution: async () => ({ contained: true, backend: "test-contained" }),
};

describe("production extension enforcement regressions", () => {
  test("registered Bash exposes the exact schema and executes through MXC when restored enabled", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    const bash = api.tools.get("bash") as Record<string, any>;
    expect(bash.parameters.properties).toMatchObject({
      command: { type: "string" }, env: { type: "object" }, cwd: { type: "string" }, timeout: { type: "number" },
      pty: { type: "boolean" }, async: { type: "boolean" }, outsideSandbox: { type: "boolean" },
    });
    const lifecycle = api.handlers.get("session_start")?.[0];
    expect(lifecycle).toBeFunction();
    await lifecycle!({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
    ]));
    let config: Record<string, any> | undefined;
    const result = await bash.execute({ command: "printf ok", timeout: 3, spawn: async (value: Record<string, any>) => { config = value; return { exitCode: 0, stdout: "ok" }; } }, { agentId: "A1", configuredShell: "/bin/zsh" });
    expect(result).toMatchObject({ exitCode: 0, stdout: "ok" });
    expect(config?.process.timeoutMs).toBe(3000);
    expect(api.hostRuns).toBe(0);
  });

  test("passes a valid Bash tool result to the OMP renderer", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    let rendererCalls = 0;
    const context = enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, policyRevision: 2, enabled: true, filesystem: { read: [], write: [] } } },
    ], { shellRenderer: (value: Record<string, any>) => { rendererCalls += 1; return value.content[0]; } });
    await api.handlers.get("session_start")?.[0]?.({}, context);
    const bash = api.tools.get("bash") as Record<string, any>;
    const result = await bash.execute("CALL", { command: "printf ok", spawn: async () => ({ exitCode: 0, stdout: "ok" }) }, undefined, undefined, context);
    expect(result.content).toEqual([{ type: "text", text: "ok" }]);
    expect(result.details).toMatchObject({ exitCode: 0, stdout: "ok" });
    expect(rendererCalls).toBe(1);
  });

  test("renders a themed sandbox continuity line below the editor and clears it when disabled", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    const widgets: Array<{ key: string; content: unknown; options: Record<string, unknown> }> = [];
    const context = enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, policyRevision: 3, enabled: true, filesystem: { read: [], write: [] } } },
    ], { ui: { setWidget: (key: string, content: unknown, options: Record<string, unknown>) => widgets.push({ key, content, options }), confirm: async () => true } });
    await api.handlers.get("session_start")?.[0]?.({}, context);
    const active = widgets.at(-1)!;
    expect(active).toMatchObject({ key: "mxc-sandbox", options: { placement: "belowEditor" } });
    expect(active.content).toBeFunction();
    const theme = { marker: "theme", fg(this: Record<string, any>, color: string, text: string) { if (this.marker !== "theme") throw new TypeError("theme receiver lost"); return `<${color}>${text}</${color}>`; } };
    const component = (active.content as (tui: unknown, theme: Record<string, any>) => Record<string, any>)({}, theme);
    const line = component.render(48)[0];
    expect(line).toContain("<borderMuted>╰─ </borderMuted>");
    expect(line).toContain("<success>sandbox · enabled</success>");
    await (api.commands.get("sandbox") as Record<string, any>).handler("disable", context);
    expect(widgets.at(-1)).toMatchObject({ key: "mxc-sandbox", content: undefined, options: { placement: "belowEditor" } });
  });


  test("activates and runs synchronously with only the documented public extension context", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    const entries = [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } }];
    const context = enabledLifecycleContext(entries);
    for (const key of ["agentId", "scopedManager", "liveMatches", "shellRenderer", "onShellUpdate", "configuredShell"]) delete context[key];
    await api.handlers.get("session_start")?.[0]?.({}, context);
    const bash = api.tools.get("bash") as Record<string, any>;
    const result = await bash.execute({ command: "printf public", spawn: async () => ({ exitCode: 0, stdout: "public" }) }, context);
    expect(result).toMatchObject({ exitCode: 0, stdout: "public" });
  });

  test("re-probes a restore and remains disabled after any facility failure", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    let nativeProbes = 0;
    await factory(api, {
      loadMxc: async () => ({ version: "0.7.0", schemaVersions: ["0.7.0-alpha"] }),
      probeMxcExecution: async () => { nativeProbes += 1; throw new Error("probe failed"); },
    });
    await api.handlers.get("session_start")?.[0]?.({}, { sessionManager: {
      getSessionId: () => "S1",
      getBranch: () => [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: false, priorConversationPolicy: true } }],
    } });
    const command = api.commands.get("sandbox") as Record<string, any>;
    const context = { hasUI: true, cwd: process.cwd(), ui: { select: async () => "restore-prior-policy-and-grants", confirm: async () => true } };
    await expect(command.handler("enable", context)).rejects.toThrow("probe failed");
    expect(nativeProbes).toBe(1);
    const bash = api.tools.get("bash") as Record<string, any>;
    await expect(bash.execute({ command: "printf host" }, {})).rejects.toMatchObject({ code: "SANDBOX_RESTORATION_FAILED" });
    expect(api.hostRuns).toBe(0);
    expect(api.entries.at(-1)?.data).toMatchObject({ enabled: false, restorationFailed: true });
    const dispatch = api.handlers.get("tool_call")?.[0];
    const blockedCalls = [
      { toolName: "bash", input: { command: "printf host" } },
      { toolName: "write", input: { path: "/tmp/restoration-write" } },
      { toolName: "edit", input: { path: "/tmp/restoration-edit" } },
      { toolName: "ast_edit", input: { paths: ["/tmp/restoration-ast"] } },
      { toolName: "lsp", input: { readonly: false, action: "rename" } },
      { toolName: "browser", input: { url: "https://example.invalid" } },
      { toolName: "web_search", input: { query: "host network" } },
      { toolName: "read", input: { path: "https://example.invalid/secret" } },
      { toolName: "unknown_host_executor", input: {} },
    ];
    for (const call of blockedCalls) {
      expect(await dispatch?.({ source: "model", ...call }, {})).toEqual({ block: true, reason: "sandbox-restoration-failed" });
    }
    await command.handler("disable", context);
    expect(await dispatch?.({ source: "model", toolName: "write", input: { path: "/tmp/normal-host-write" } }, {})).toBeUndefined();
    await bash.execute({ command: "printf host" }, {});
    expect(api.hostRuns).toBe(1);
  });

  test("persisted enabled MXC restore failure blocks every model host-tool class until explicit disable", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    let failReprobe = true;
    await factory(api, {
      loadMxc: async () => ({ version: "0.7.0", schemaVersions: ["0.7.0-alpha"] }),
      probeMxcExecution: async () => {
        if (failReprobe) throw new Error("persisted MXC reprobe failed");
        return { contained: true, backend: "test-contained" };
      },
    });
    const entries = [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } }];
    const lifecycleContext = enabledLifecycleContext(entries);
    await expect(api.handlers.get("session_resume")?.[0]?.({}, lifecycleContext)).rejects.toThrow("persisted MXC reprobe failed");
    expect(api.entries.at(-1)?.data).toMatchObject({ enabled: false, restorationFailed: true });

    const dispatch = api.handlers.get("tool_call")?.[0];
    expect(dispatch).toBeFunction();
    const modelHostCalls = [
      { toolName: "read", input: { path: "/tmp/restoration-read" } },
      { toolName: "grep", input: { pattern: "secret", path: "/tmp" } },
      { toolName: "glob", input: { path: "/tmp/**" } },
      { toolName: "lsp", input: { readonly: true, action: "references" } },
      { toolName: "lsp", input: { readonly: false, action: "rename" } },
      { toolName: "browser", input: { url: "https://example.invalid" } },
      { toolName: "web_search", input: { query: "host network" } },
      { toolName: "read", input: { path: "https://example.invalid/secret" } },
      { toolName: "write", input: { path: "/tmp/restoration-write", content: "escaped" } },
      { toolName: "edit", input: { path: "/tmp/restoration-edit" } },
      { toolName: "ast_edit", input: { paths: ["/tmp/restoration-ast"] } },
      { toolName: "unknown_host_executor", mutationOrExecution: true, input: {} },
      { toolName: "bash", input: { command: "printf escaped" } },
    ];
    for (const call of modelHostCalls) {
      expect(await dispatch!({ source: "model", ...call }, {})).toEqual({ block: true, reason: "sandbox-restoration-failed" });
    }
    const bash = api.tools.get("bash") as Record<string, any>;
    await expect(bash.execute({ command: "printf escaped" }, {})).rejects.toMatchObject({ code: "SANDBOX_RESTORATION_FAILED" });
    expect(api.hostRuns).toBe(0);

    await (api.commands.get("sandbox") as Record<string, any>).handler("disable", { hasUI: true, ui: { confirm: async () => true } });
    for (const call of modelHostCalls) expect(await dispatch!({ source: "model", ...call }, {})).toBeUndefined();
    await bash.execute({ command: "printf normal" }, {});
    expect(api.hostRuns).toBe(1);
    failReprobe = false;
  });

  test("restoration failure blocks Bash and host tools when public OMP exec is unavailable", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    (api as unknown as Record<string, unknown>).exec = undefined;
    await factory(api, successfulRestoreDependencies);
    expect(api.tools.has("bash")).toBe(false);
    const entries = [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } }];
    const missingArtifactContext = enabledLifecycleContext(entries, { sessionManager: { getSessionId: () => "S1", getBranch: () => entries } });
    await expect(api.handlers.get("session_resume")?.[0]?.({}, missingArtifactContext)).rejects.toMatchObject({ code: "OMP_ACTIVATION_FEATURES_MISSING" });
    const dispatch = api.handlers.get("tool_call")?.[0];
    for (const call of [
      { toolName: "bash", input: { command: "printf escaped" } },
      { toolName: "write", input: { path: "/tmp/escaped" } },
      { toolName: "browser", input: { url: "https://example.invalid" } },
      { toolName: "unknown_host_executor", input: {} },
    ]) expect(await dispatch?.({ source: "model", ...call }, {})).toEqual({ block: true, reason: "sandbox-restoration-failed" });
    expect(api.hostRuns).toBe(0);
    await (api.commands.get("sandbox") as Record<string, any>).handler("disable", { hasUI: true, ui: { confirm: async () => true } });
    expect(await dispatch?.({ source: "model", toolName: "bash", input: { command: "printf normal" } }, {})).toBeUndefined();
  });

  test("production tool dispatcher blocks canonical symlink escape and non-readonly LSP denial", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-dispatch-"));
    const outside = await mkdtemp(join(tmpdir(), "mxc-dispatch-out-"));
    try {
      await writeFile(join(outside, "secret"), "secret");
      await symlink(outside, join(root, "escape"), "dir");
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, successfulRestoreDependencies);
      await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { write: [{ path: root, kind: "directory", recursive: true, permissions: ["write"] }] } } },
      ], { cwd: root }));
      const dispatch = api.handlers.get("tool_call")?.[0];
      expect(await dispatch?.({ source: "model", toolName: "write", input: { path: join(root, "escape", "secret") } }, { cwd: root })).toEqual({ block: true, reason: "sandbox-policy-denied" });
      await api.handlers.get("session_switch")?.[0]?.({}, enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, snapshot: true, enabled: true, filesystem: { read: [], write: [] } } },
      ], { cwd: root }));
      expect(await dispatch?.({ source: "model", toolName: "lsp", input: { readonly: false, action: "rename" } }, { agentId: "A1", cwd: root, ui: { select: async () => "deny" } })).toEqual({ block: true, reason: "lsp-workspace-write-denied" });
    } finally {
      await Promise.all([rm(root, { recursive: true, force: true }), rm(outside, { recursive: true, force: true })]);
    }
  });

  test("reprobes dependency native MXC and OMP facilities on every enabled lifecycle restore", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    let dependencyProbes = 0;
    let nativeProbes = 0;
    await factory(api, {
      loadMxc: async () => { dependencyProbes += 1; return { version: "0.7.0", schemaVersions: ["0.7.0-alpha"] }; },
      probeMxcExecution: async () => { nativeProbes += 1; return { contained: true, backend: "test-contained" }; },
    });
    const entries = [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } }];
    for (const eventName of ["session_start", "session_switch", "session_tree", "session_resume"]) {
      await api.handlers.get(eventName)?.[0]?.({}, enabledLifecycleContext(entries));
    }
    expect(dependencyProbes).toBe(4);
    expect(nativeProbes).toBe(4);
  });

  test("an OMP reprobe failure leaves restored state disabled", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    const entries = [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } }];
    const missingArtifactContext = enabledLifecycleContext(entries, { sessionManager: { getSessionId: () => "S1", getBranch: () => entries } });
    await expect(api.handlers.get("session_resume")?.[0]?.({}, missingArtifactContext)).rejects.toMatchObject({ code: "OMP_ACTIVATION_FEATURES_MISSING" });
    await expect((api.tools.get("bash") as Record<string, any>).execute({ command: "printf host" }, {})).rejects.toMatchObject({ code: "SANDBOX_RESTORATION_FAILED" });
    expect(api.hostRuns).toBe(0);
    expect((api.entries.at(-1) as Record<string, any>).data).toMatchObject({ enabled: false, restorationFailed: true });
    const dispatch = api.handlers.get("tool_call")?.[0];
    expect(await dispatch?.({ source: "model", toolName: "write", input: { path: "/tmp/omp-restoration-write" } }, {})).toEqual({ block: true, reason: "sandbox-restoration-failed" });
    const restoredContext = enabledLifecycleContext(entries);
    await api.handlers.get("session_resume")?.[0]?.({}, restoredContext);
    expect(await dispatch?.({ source: "model", toolName: "bash", input: { command: "printf restored" } }, {})).toBeUndefined();
    expect(await dispatch?.({ source: "model", toolName: "read", input: { path: "/tmp/omp-restoration-read" } }, {})).toEqual({ block: true, reason: "sandbox-policy-denied" });
    let spawned = false;
    await (api.tools.get("bash") as Record<string, any>).execute({ command: "printf restored", spawn: async () => { spawned = true; return { exitCode: 0 }; } }, restoredContext);
    expect(spawned).toBe(true);
    expect(api.hostRuns).toBe(0);
  });

  test("warns once when the running OMP version drifts from the internal URI registry", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    (api as unknown as Record<string, unknown>).pi = { VERSION: "18.0.0" };
    await factory(api, successfulRestoreDependencies);
    const notices: { message: string; type: string }[] = [];
    const entries = [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } }];
    const context = enabledLifecycleContext(entries, { ui: { notify: (message: string, type: string) => notices.push({ message, type }) } });
    await api.handlers.get("session_start")?.[0]?.({}, context);
    expect(notices.filter((notice) => notice.type === "warning")).toEqual([
      expect.objectContaining({ message: expect.stringContaining("OMP 18.0.0 differs from the internal-URL registry verified for OMP 17.0.4") }),
    ]);
    await (api.commands.get("sandbox") as Record<string, any>).handler("status", context);
    expect(notices.some((notice) => notice.message.includes('"synchronizedOmpVersion": "17.0.4"') && notice.message.includes('"drift": true'))).toBe(true);
    expect(notices.filter((notice) => notice.type === "warning")).toHaveLength(1);
  });

  test("PowerShell outside-once uses only the PowerShell 7 host executor", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, { ...successfulRestoreDependencies, platform: "win32" });
    const lifecycleContext = enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
    ]);
    await api.handlers.get("session_start")?.[0]?.({}, lifecycleContext);
    const powershell = api.tools.get("powershell") as Record<string, any>;
    expect(powershell).toBeDefined();
    const result = await powershell.execute({ outsideSandbox: true, command: "Write-Output 'safe'", cwd: "C:\\repo" }, {
      ...lifecycleContext,
      ui: { confirm: async () => true },
    });
    expect(result).toMatchObject({ exitCode: 0, stdout: "host" });
    expect(api.hostRuns).toBe(1);
    expect(api.execCalls).toHaveLength(1);
    expect(String(api.execCalls[0]?.[0])).toMatch(/[\\/]pwsh\.exe$/i);
    expect(api.execCalls[0]?.[1]).toEqual(["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-Command", "Write-Output 'safe'"]);
    const failureResult = await powershell.execute({
      command: "Write-Output 'after failure'",
      cwd: "C:\\repo",
      spawn: async () => { throw new Error("MXC launch failed"); },
    }, {
      ...lifecycleContext,
      ui: { confirm: async () => true, select: async () => "Run this command outside once" },
    });
    expect(failureResult).toMatchObject({ exitCode: 0, outsideSandbox: true, launchFailed: true });
    expect(api.hostRuns).toBe(2);
    expect(api.execCalls).toHaveLength(2);
    expect(String(api.execCalls[1]?.[0])).toMatch(/[\\/]pwsh\.exe$/i);
    expect(api.execCalls[1]?.[1]).toEqual(["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-Command", "Write-Output 'after failure'"]);
  });

  test("PowerShell outside-once renders stderr instead of result JSON", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    api.exec = async () => ({ code: 1, stdout: "", stderr: "fatal: not a git repository\n", killed: false });
    await factory(api, { ...successfulRestoreDependencies, platform: "win32" });
    const context = enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
    ], { ui: { confirm: async () => true } });
    await api.handlers.get("session_start")?.[0]?.({}, context);
    const powershell = api.tools.get("powershell") as Record<string, any>;
    const result = await powershell.execute("CALL", {
      outsideSandbox: true,
      command: "git status --short",
      cwd: "C:\\repo",
    }, undefined, undefined, context);
    expect(result).toMatchObject({
      content: [{ type: "text", text: "fatal: not a git repository\n" }],
      details: { exitCode: 1, stderr: "fatal: not a git repository\n" },
      isError: true,
    });
    expect(result.content[0].text).not.toContain('"stderr"');
  });

  test("PowerShell outside-once streams before host completion", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    const release = Promise.withResolvers<void>();
    await factory(api, {
      ...successfulRestoreDependencies,
      platform: "win32",
      spawnHost: async (_executable: string, _arguments: string[], _input: Record<string, unknown>, onUpdate: (update: Record<string, unknown>) => void) => {
        onUpdate({ stream: "stdout", data: "outside first\n" });
        await release.promise;
        await Bun.sleep(110);
        onUpdate({ stream: "stderr", data: "outside second\n" });
        return { stdout: "outside first\n", stderr: "outside second\n", exitCode: 0 };
      },
    });
    const context = enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
    ], { ui: { confirm: async () => true } });
    await api.handlers.get("session_start")?.[0]?.({}, context);
    const powershell = api.tools.get("powershell") as Record<string, any>;
    const updates: Record<string, any>[] = [];
    const firstUpdate = Promise.withResolvers<void>();
    const execution = powershell.execute("CALL", {
      outsideSandbox: true,
      command: "Write-Output 'outside first'",
      cwd: "C:\\repo",
    }, undefined, (update: Record<string, any>) => {
      updates.push(update);
      firstUpdate.resolve();
    }, context);
    await firstUpdate.promise;
    expect(updates).toEqual([{ content: [{ type: "text", text: "outside first\n" }], details: undefined }]);
    expect(api.execCalls).toHaveLength(0);
    release.resolve();
    await expect(execution).resolves.toMatchObject({
      content: [{ type: "text", text: "outside first\noutside second\n" }],
      details: { exitCode: 0 },
      isError: false,
    });
    expect(updates.at(-1)).toEqual({ content: [{ type: "text", text: "outside first\noutside second\n" }], details: undefined });
  });

  test("Bash outside-once expands a tilde cwd for direct and launch-failure host execution", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    const home = await mkdtemp(join(tmpdir(), "mxc-outside-home-"));
    try {
      const projects = join(home, "Projects");
      await mkdir(projects);
      await factory(api, { ...successfulRestoreDependencies, platform: "darwin", homeDirectory: home });
      const lifecycleContext = enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
      ], { onShellUpdate: undefined, ui: { confirm: async () => true } });
      await api.handlers.get("session_start")?.[0]?.({}, lifecycleContext);
      const bash = api.tools.get("bash") as Record<string, any>;

      await bash.execute({ outsideSandbox: true, command: "printf direct", cwd: "~/Projects" }, lifecycleContext);
      expect((api.execCalls[0]?.[2] as Record<string, unknown>).cwd).toBe(projects);

      await bash.execute({
        command: "printf fallback",
        cwd: "~/Projects",
        spawn: async () => { throw new Error("MXC launch failed"); },
      }, { ...lifecycleContext, ui: { confirm: async () => true, select: async () => "Run this command outside once" } });
      expect((api.execCalls[1]?.[2] as Record<string, unknown>).cwd).toBe(projects);
      expect(api.hostRuns).toBe(2);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  test("Bash outside-once streams before host completion on macOS and Linux", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    for (const platform of ["darwin", "linux"] as const) {
      const api = new RecordingApi();
      const release = Promise.withResolvers<void>();
      await factory(api, {
        ...successfulRestoreDependencies,
        platform,
        spawnHost: async (_executable: string, _arguments: string[], _input: Record<string, unknown>, onUpdate: (update: Record<string, unknown>) => void) => {
          onUpdate({ stream: "stdout", data: "outside first\n" });
          await release.promise;
          onUpdate({ stream: "stderr", data: "outside second\n" });
          return { stdout: "outside first\n", stderr: "outside second\n", exitCode: 0 };
        },
      });
      const context = enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
      ], { configuredShell: "/bin/zsh", ui: { confirm: async () => true } });
      await api.handlers.get("session_start")?.[0]?.({}, context);
      const bash = api.tools.get("bash") as Record<string, any>;
      const updates: Record<string, any>[] = [];
      const firstUpdate = Promise.withResolvers<void>();
      const execution = bash.execute("CALL", {
        outsideSandbox: true,
        command: "printf 'outside first'",
        cwd: "/repo",
      }, undefined, (update: Record<string, any>) => {
        updates.push(update);
        firstUpdate.resolve();
      }, context);
      await firstUpdate.promise;
      expect(updates).toEqual([{ content: [{ type: "text", text: "outside first\n" }], details: {} }]);
      expect(api.execCalls).toHaveLength(0);
      release.resolve();
      await expect(execution).resolves.toMatchObject({
        content: [{ type: "text", text: "outside first\noutside second\n" }],
        details: { exitCode: 0 },
      });
      expect(updates.at(-1)).toEqual({ content: [{ type: "text", text: "outside first\noutside second\n" }], details: {} });
    }
  });

  test("PowerShell uses OMP shell rendering for pending, partial, and completed states", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    const rendererCalls: { args: Record<string, unknown>; options: Record<string, unknown> }[] = [];
    const renderResult = () => ({ render: () => [] });
    const renderCall = (args: Record<string, unknown>, options: Record<string, unknown>) => {
      rendererCalls.push({ args, options });
      return { render: () => ["pending"] };
    };
    let rendererFactoryCalls = 0;
    let rendererConfig: Record<string, any> | undefined;
    (api as unknown as Record<string, unknown>).pi = {
      bashToolRenderer: { renderCall: () => ({ render: () => ["bash-fallback"] }), renderResult, mergeCallAndResult: true, inline: true },
      createShellRenderer: (config: Record<string, any>) => {
        rendererFactoryCalls += 1;
        rendererConfig = config;
        return { renderCall, renderResult, mergeCallAndResult: true, inline: true };
      },
    };
    await factory(api, { ...successfulRestoreDependencies, platform: "win32" });
    const context = enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
    ]);
    await api.handlers.get("session_start")?.[0]?.({}, context);
    const powershell = api.tools.get("powershell") as Record<string, any>;
    expect(rendererFactoryCalls).toBe(1);
    expect(rendererConfig?.resolveTitle()).toBe("PowerShell");
    expect(rendererConfig?.showHeader).toBe(true);
    expect(rendererConfig?.resolveCommand({ command: "Get-Location" })).toBe("Get-Location");
    expect(powershell.renderResult).toBe(renderResult);
    expect(powershell).toMatchObject({ mergeCallAndResult: true, inline: true });
    const pendingOptions = { isPartial: true, spinnerFrame: 3 };
    powershell.renderCall({ command: "Get-Location", cwd: "C:\\repo" }, pendingOptions, {});
    powershell.renderCall({ outsideSandbox: true, command: "git status", cwd: "C:\\repo" }, pendingOptions, {});
    expect(rendererCalls).toEqual([
      { args: { command: "Get-Location", cwd: "C:\\repo" }, options: pendingOptions },
      { args: { outsideSandbox: true, command: "git status", cwd: "C:\\repo" }, options: pendingOptions },
    ]);

    const updates: Record<string, any>[] = [];
    const firstUpdate = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const execution = powershell.execute("CALL", {
      command: "Write-Output 'first'; Write-Error 'second'; Write-Output 'third'",
      timeout: 3,
      spawn: async (config: Record<string, any>, events: Record<string, (data: string) => void>) => {
        const payload = String(config.process.commandLine.at(-1));
        const bootstrap = Buffer.from(payload.split(" -EncodedCommand ").at(-1) ?? "", "base64").toString("utf16le");
        const marker = bootstrap.match(/__OMP_MXC_READY_[A-Za-z0-9_-]+__/)?.[0];
        expect(marker).toBeDefined();
        events.stderr!(`${marker}\r\n`);
        events.stdout!("first\n");
        await release.promise;
        events.stderr!("second\n");
        events.stdout!("third\n");
        return { exitCode: 7 };
      },
    }, undefined, (update: Record<string, any>) => {
      updates.push(update);
      if (updates.length === 1) firstUpdate.resolve();
    }, context);
    await firstUpdate.promise;
    expect(updates).toHaveLength(1);
    release.resolve();
    const result = await execution;
    expect(updates).toHaveLength(2);
    expect(updates[0]).toEqual({ content: [{ type: "text", text: "" }], details: undefined });
    expect(updates[1]).toEqual({ content: [{ type: "text", text: "first\n" }], details: undefined });
    expect(result).toMatchObject({
      content: [{ type: "text", text: "first\nsecond\nthird\n" }],
      details: { exitCode: 7, stdout: "first\nthird\n", stderr: "second\n", timeoutSeconds: 3, wallTimeMs: expect.any(Number) },
      isError: true,
    });
  });

  test("PowerShell 7 works immediately while sandboxing remains disabled", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, { platform: "win32" });
    const powershell = api.tools.get("powershell") as Record<string, any>;
    expect(powershell).toBeDefined();
    const result = await powershell.execute("CALL", { command: "$PSVersionTable.PSVersion.Major", timeout: 12 }, undefined, undefined, {
      discoveredExecutables: ["C:\\Program Files\\PowerShell\\7\\pwsh.exe"],
    });
    expect(result).toMatchObject({
      content: [{ type: "text", text: "host" }],
      details: { exitCode: 0, stdout: "host", timeoutSeconds: 12, requestedTimeoutSeconds: 12 },
      isError: false,
    });
    expect(String(api.execCalls[0]?.[0])).toMatch(/[\\/]pwsh\.exe$/i);
    expect(api.execCalls[0]?.[1]).toEqual(["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-Command", "$PSVersionTable.PSVersion.Major"]);
    expect(api.execCalls[0]?.[2]).toEqual({ cwd: undefined, env: undefined, timeout: 12_000 });
  });

  test("disabled PowerShell streams one cumulative result before host completion", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    const release = Promise.withResolvers<void>();
    await factory(api, {
      platform: "win32",
      spawnHost: async (_executable: string, _arguments: string[], _input: Record<string, unknown>, onUpdate: (update: Record<string, unknown>) => void) => {
        onUpdate({ stream: "stdout", data: "first\n" });
        await release.promise;
        await Bun.sleep(110);
        onUpdate({ stream: "stderr", data: "second\n" });
        return { stdout: "first\n", stderr: "second\n", exitCode: 0 };
      },
    });
    const powershell = api.tools.get("powershell") as Record<string, any>;
    const updates: Record<string, any>[] = [];
    const firstUpdate = Promise.withResolvers<void>();
    const execution = powershell.execute("CALL", { command: "Write-Output first" }, undefined, (update: Record<string, any>) => {
      updates.push(update);
      firstUpdate.resolve();
    }, { discoveredExecutables: ["C:\\Program Files\\PowerShell\\7\\pwsh.exe"] });
    await firstUpdate.promise;
    expect(updates).toEqual([{ content: [{ type: "text", text: "first\n" }], details: undefined }]);
    expect(api.execCalls).toHaveLength(0);
    release.resolve();
    await expect(execution).resolves.toMatchObject({
      content: [{ type: "text", text: "first\nsecond\n" }],
      details: { exitCode: 0 },
      isError: false,
    });
    expect(updates.at(-1)).toEqual({ content: [{ type: "text", text: "first\nsecond\n" }], details: undefined });
  });

  test("disabled host Bash returns normal rendered results on macOS and Linux", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    for (const platform of ["darwin", "linux"] as const) {
      const api = new RecordingApi();
      await factory(api, { platform });
      const bash = api.tools.get("bash") as Record<string, any>;
      const result = await bash.execute("CALL", { command: "printf ok", timeout: 2.5 }, undefined, undefined, { configuredShell: "/bin/zsh" });
      expect(result).toMatchObject({
        content: [{ type: "text", text: "host" }],
        details: { code: 0, stdout: "host", stderr: "", killed: false },
      });
      expect(api.execCalls).toEqual([["/bin/zsh", ["-lc", "printf ok"], { cwd: undefined, env: undefined, timeout: 2.5 }]]);
    }
  });

  test("macOS and Linux activation stays stable while contained Bash uses normal streaming updates", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    for (const platform of ["darwin", "linux"] as const) {
      const api = new RecordingApi();
      let probeInput: Record<string, any> | undefined;
      await factory(api, {
        ...successfulRestoreDependencies,
        platform,
        probeMxcExecution: async (input: Record<string, any>) => {
          probeInput = input;
          return { contained: true, backend: platform === "darwin" ? "seatbelt" : "bubblewrap", platformCapabilities: { independentLocalNetwork: true } };
        },
      });
      const context = enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, network: { internet: false, localNetwork: false } } },
      ], { configuredShell: "/bin/zsh" });
      await api.handlers.get("session_start")?.[0]?.({}, context);
      expect(probeInput).toMatchObject({
        platform,
        shell: { executable: "/bin/zsh", args: ["-lc"], dialect: "posix" },
        env: { PATH: process.env.PATH ?? "" },
      });
      expect(Object.keys(probeInput?.env ?? {})).toEqual(["PATH"]);
      expect(probeInput).not.toHaveProperty("containerId");
      expect(probeInput).not.toHaveProperty("trafficShell");
      expect(probeInput).not.toHaveProperty("requiredReadonlyPaths");

      const updates: Record<string, unknown>[] = [];
      const bash = api.tools.get("bash") as Record<string, any>;
      const result = await bash.execute("CALL", {
        command: "printf ok",
        spawn: async (_config: unknown, events: Record<string, (data: string) => void>) => {
          events.stdout!("first\n");
          return { exitCode: 0 };
        },
      }, undefined, (update: Record<string, unknown>) => updates.push(update), context);
      expect(updates).toEqual([{ content: [{ type: "text", text: "first\n" }], details: {} }]);
      expect(result).toMatchObject({ details: { exitCode: 0, stdout: "first\n" } });
    }
  });

  test("production dispatcher passes effective network and host lists to all host adapters", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, { ...successfulRestoreDependencies, platform: "linux", probeMxcExecution: async () => ({ contained: true, backend: "bubblewrap", platformCapabilities: { allowedHosts: true, blockedHosts: true, independentLocalNetwork: true } }) });
    await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, network: { internet: true, unrestricted: true, allowedHosts: ["allowed.example"], blockedHosts: ["blocked.example"] } } },
    ]));
    const dispatch = api.handlers.get("tool_call")?.[0];
    expect(await dispatch?.({ source: "model", toolName: "web_search", input: { query: "safe" } }, {})).toBeUndefined();
    expect(await dispatch?.({ source: "model", toolName: "browser", input: { url: "https://allowed.example/a" } }, {})).toBeUndefined();
    expect(await dispatch?.({ source: "model", toolName: "read", input: { path: "https://allowed.example/a" } }, {})).toBeUndefined();
    expect(await dispatch?.({ source: "model", toolName: "browser", input: { url: "https://blocked.example/a" } }, {})).toEqual({ block: true, reason: "network-host-blocked" });
    expect(await dispatch?.({ source: "model", toolName: "browser", input: { url: "http://127.0.0.1/private" } }, {})).toEqual({ block: true, reason: "local-network-not-granted" });
    expect(await dispatch?.({ source: "model", toolName: "read", input: { path: "http://192.168.1.20/private" } }, {})).toEqual({ block: true, reason: "local-network-not-granted" });
  });

  test("inline file approval atomically grants host access and records only explicit saved-deny overrides", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-inline-grant-"));
    try {
      const deniedA = join(root, "denied-a.txt");
      const deniedB = join(root, "denied-b.txt");
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      const canonicalDeniedA = await realpath(root).then((canonicalRoot) => join(canonicalRoot, "denied-a.txt"));
      await factory(api, successfulRestoreDependencies);
      await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [], deny: [deniedA, deniedB] } } },
      ], { cwd: root }));
      const dispatch = api.handlers.get("tool_call")?.[0];
      let offered: unknown;
      expect(await dispatch?.({ source: "model", toolName: "write", input: { path: deniedA, content: "x" } }, {
        cwd: root,
        agentId: "A1",
        ui: { select: async (_title: string, options: unknown) => { offered = options; return "allow-exact-conversation"; } },
      })).toBeUndefined();
      expect(offered).toEqual([
        "Allow this write operation once",
        `Allow this exact path for this conversation: ${canonicalDeniedA}`,
        `Allow this directory recursively for this conversation: ${dirname(canonicalDeniedA)}`,
        "Deny",
      ]);
      expect((api.entries.at(-1) as Record<string, any>).data.explicitDenyOverrides).toEqual([{ path: canonicalDeniedA, operation: "write" }]);
      expect(await dispatch?.({ source: "model", toolName: "write", input: { path: deniedA, content: "again" } }, { cwd: root })).toBeUndefined();

      const sandboxRequestTool = api.tools.get("sandbox_request") as Record<string, any>;
      await sandboxRequestTool.execute({ capability: "write", value: deniedB }, { agentId: "A1", hasUI: true, ui: { confirm: async () => true } });
      expect(await dispatch?.({ source: "model", toolName: "write", input: { path: deniedB, content: "still blocked" } }, { cwd: root })).toEqual({ block: true, reason: "sandbox-policy-denied" });
      expect((api.entries.at(-1) as Record<string, any>).data.explicitDenyOverrides).toEqual([{ path: canonicalDeniedA, operation: "write" }]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("exports a mandatory genuine-host native E2E driver adapter", async () => {
    const mod = await loadContract("e2e");
    const createDriver = requiredExport<(platform: "macos" | "windows") => unknown>(mod, "createNativeExtensionDriver");
    const prior = process.env.MXC_E2E_NATIVE_DRIVER;
    delete process.env.MXC_E2E_NATIVE_DRIVER;
    try {
      expect(() => createDriver("macos")).toThrow(expect.objectContaining({ code: "NATIVE_E2E_EVIDENCE_REQUIRED" }));
    } finally {
      if (prior === undefined) delete process.env.MXC_E2E_NATIVE_DRIVER;
      else process.env.MXC_E2E_NATIVE_DRIVER = prior;
    }
  });

  test("completes secure TUI setup and persists the applied conversation policy", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-setup-"));
    try {
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, {
        loadMxc: async () => ({ version: "0.7.0", schemaVersions: ["0.7.0-alpha"] }),
        probeMxcExecution: async () => ({ contained: true, backend: "seatbelt" }),
      });
      const scopedManager = {};
      const sessionManager = { getSessionId: () => "S1", getBranch: () => [], allocateArtifactPath: async () => ({ id: "A1", path: join(root, "artifact") }) };
      const context = {
        hasUI: true, cwd: root, agentId: "A1", sessionManager, scopedManager,
        liveMatches: [{ live: true, sessionId: "S1", agentId: "A1", scopedManager }],
        shellRenderer: async () => undefined, onShellUpdate: () => undefined,
        ui: {
          confirm: async () => true,
          select: async (title: string) => title === "Initial MXC sandbox policy" ? "Use secure initial defaults" : "use-for-conversation",
        },
      };
      const command = api.commands.get("sandbox") as Record<string, any>;
      await command.handler("enable", context);
      const latest = api.entries.at(-1) as Record<string, any>;
      expect(latest.data).toMatchObject({ enabled: true, filesystem: { read: [{ path: root, recursive: true }] }, network: { internet: false, localNetwork: false } });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("approved internet request enables coupled unrestricted outbound access on Darwin", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, network: { internet: false, unrestricted: false, localNetwork: false } } },
    ]));
    const request = api.tools.get("sandbox_request") as Record<string, any>;
    await request.execute({ capability: "internet", value: "allow" }, { agentId: "A1", hasUI: true, ui: { confirm: async () => true } });
    expect((api.entries.at(-1) as Record<string, any>).data.network).toMatchObject({ internet: true, unrestricted: true, localNetwork: true });
    expect(await api.handlers.get("tool_call")?.[0]?.({ source: "model", toolName: "web_search", input: { query: "approved" } }, {})).toBeUndefined();
    const commandApi = new RecordingApi();
    await factory(commandApi, successfulRestoreDependencies);
    await commandApi.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, network: { internet: false, unrestricted: false, localNetwork: false } } },
    ]));
    await (commandApi.commands.get("sandbox") as Record<string, any>).handler("allow internet allow --conversation", {});
    expect((commandApi.entries.at(-1) as Record<string, any>).data.network).toMatchObject({ internet: true, unrestricted: true, localNetwork: true });
    expect(await commandApi.handlers.get("tool_call")?.[0]?.({ source: "model", toolName: "web_search", input: { query: "command-approved" } }, {})).toBeUndefined();
  });


  test("factory passes structurally configured auto-background threshold to shell execution", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    const entries = [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } }];
    const lifecycleContext = enabledLifecycleContext(entries);
    await api.handlers.get("session_start")?.[0]?.({}, lifecycleContext);
    const manager = { register: () => ({ id: "J-threshold" }) };
    const executionContext = { ...lifecycleContext, scopedManager: manager, liveMatches: [{ live: true, sessionId: "S1", agentId: "A1", scopedManager: manager }], config: { bash: { autoBackgroundThresholdMs: 1 } } };
    const result = await (api.tools.get("bash") as Record<string, any>).execute({ command: "long-running", spawn: async () => ({ pid: 42, once: () => undefined, kill: () => undefined }) }, executionContext);
    expect(result).toMatchObject({ backgrounded: true, jobId: "J-threshold" });
  });

  test("enable and restore probe backend capabilities and force saved-host-rule choices", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, { ...successfulRestoreDependencies, platform: "win32", probeMxcExecution: async () => ({ contained: true, backend: "processcontainer", platformCapabilities: { allowedHosts: false, blockedHosts: false, independentLocalNetwork: true } }) });
    const offered: string[][] = [];
    await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, network: { internet: true, localNetwork: false, allowedHosts: ["saved.example"] } } },
    ], { ui: { select: async (_title: string, choices: string[]) => { offered.push(choices); return "block-network"; } } }));
    expect(offered).toContainEqual(["block-network", "allow-unrestricted-network", "cancel"]);
    expect(await api.handlers.get("tool_call")?.[0]?.({ source: "model", toolName: "web_search", input: { query: "blocked" } }, {})).toEqual({ block: true, reason: "unrestricted-internet-required" });
    const root = await mkdtemp(join(tmpdir(), "mxc-host-rule-enable-"));
    try {
      await mkdir(join(root, ".git"), { recursive: true });
      await mkdir(join(root, ".omp"), { recursive: true });
      await writeFile(join(root, ".omp", "sandbox.yml"), JSON.stringify({ version: 1, network: { internet: true, allowedHosts: ["fresh.example"] } }));
      const fresh = new RecordingApi();
      await factory(fresh, { ...successfulRestoreDependencies, platform: "win32", probeMxcExecution: async () => ({ contained: true, backend: "processcontainer", platformCapabilities: { allowedHosts: false, blockedHosts: false, independentLocalNetwork: true } }) });
      const freshOffered: string[][] = [];
      const context = enabledLifecycleContext([], {
        cwd: root,
        ui: {
          confirm: async () => true,
          select: async (title: string, choices: string[]) => {
            if (title.startsWith("Saved network")) { freshOffered.push(choices); return "block-network"; }
            if (title === "Initial MXC sandbox policy") return "Use secure initial defaults";
            if (title === "Windows containment mode") return "strict-native-enforcement";
            return "use-for-conversation";
          },
        },
      });
      await (fresh.commands.get("sandbox") as Record<string, any>).handler("enable", context);
      expect(freshOffered).toContainEqual(["block-network", "allow-unrestricted-network", "cancel"]);
      expect((fresh.entries.at(-1) as Record<string, any>).data).toMatchObject({ enabled: true, network: { internet: false, unrestricted: false } });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("Windows dashboard enables internet while preserving proven local-network isolation", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, {
      ...successfulRestoreDependencies,
      platform: "win32",
      probeMxcExecution: async () => ({ contained: true, backend: "processcontainer", platformCapabilities: { internetLocalNetworkIsolation: true, localNetworkAvailable: false, independentLocalNetwork: false } }),
    });
    await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, network: { internet: false, localNetwork: false } } },
    ]));
    const choices = ["Network", "Internet", "Enable", "Apply"];
    await (api.commands.get("sandbox") as Record<string, any>).handler("", { hasUI: true, ui: { select: async () => choices.shift() } });
    expect((api.entries.at(-1) as Record<string, any>).data.network).toMatchObject({ internet: true, localNetwork: false, unrestricted: true });
  });

  test("production Windows factory wires approved compatibility and critical PowerShell gates", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    const dependencies = {
      ...successfulRestoreDependencies,
      platform: "win32",
      loadMxc: async () => ({ version: "0.7.0", schemaVersions: ["0.7.0-alpha"], reprobePlatformSupport: () => ({ isSupported: true, isolationTier: "appcontainer-dacl", isolationWarnings: ["BaseContainer unavailable"] }) }),
      probeMxcExecution: async () => ({ contained: true, backend: "processcontainer", platformCapabilities: { windowsBuild: 26100, tier: "appcontainer-dacl", nativeEnforcementAvailable: false, independentLocalNetwork: true } }),
    };
    await factory(api, dependencies);
    const entries = [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, mxcOverrides: { fallback: { allowDaclMutation: true } } } }];
    const context = enabledLifecycleContext(entries, { windowsBuild: 26100 });
    await api.handlers.get("session_start")?.[0]?.({}, context);
    let config: Record<string, any> | undefined;
    await (api.tools.get("bash") as Record<string, any>).execute({ command: "echo ok", allowDaclMutation: false, spawn: async (value: Record<string, any>) => { config = value; return { exitCode: 0 }; } }, context);
    expect(config?.fallback).toEqual({ allowDaclMutation: true });
    let spawned = false;
    await expect((api.tools.get("powershell") as Record<string, any>).execute({ command: "shutdown.exe /s /t 0", spawn: async () => { spawned = true; return { exitCode: 0 }; } }, { ...context, ui: { confirm: async () => false } })).rejects.toMatchObject({ code: "CRITICAL_COMMAND_DECLINED" });
    expect(spawned).toBe(false);
  });

  test("project saves strip sensitive approvals and recursive setup scope survives reload enforcement", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-profile-roundtrip-"));
    try {
      await mkdir(join(root, ".git"), { recursive: true });
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, successfulRestoreDependencies);
      const scopedManager = {};
      const sessionManager = { getSessionId: () => "S-profile", getBranch: () => [], allocateArtifactPath: async () => ({ id: "A-profile", path: join(root, "artifact") }) };
      const context = {
        hasUI: true, cwd: root, agentId: "A-profile", sessionManager, scopedManager,
        liveMatches: [{ live: true, sessionId: "S-profile", agentId: "A-profile", scopedManager }], shellRenderer: async () => undefined, onShellUpdate: () => undefined,
        ui: { confirm: async () => true, select: async (title: string) => title === "Initial MXC sandbox policy" ? "Use secure initial defaults" : title === "Apply sandbox setup" ? "save-project-profile" : "use-for-conversation" },
      };
      await (api.commands.get("sandbox") as Record<string, any>).handler("enable", context);
      const profilePath = join(root, ".omp", "sandbox.yml");
      const savedSetup = JSON.parse(await Bun.file(profilePath).text());
      expect(savedSetup.filesystem.read).toContainEqual({ path: root, kind: "directory", recursive: true });

      const second = new RecordingApi();
      await factory(second, successfulRestoreDependencies);
      const secondScoped = {};
      const secondSession = { getSessionId: () => "S-reload", getBranch: () => [], allocateArtifactPath: async () => ({ id: "A-reload", path: join(root, "artifact-2") }) };
      const secondContext = {
        ...context, sessionManager: secondSession, scopedManager: secondScoped,
        liveMatches: [{ live: true, sessionId: "S-reload", agentId: "A-profile", scopedManager: secondScoped }],
        ui: { confirm: async () => true, select: async (title: string) => title === "Initial MXC sandbox policy" ? "Use secure initial defaults" : "use-for-conversation" },
      };
      await (second.commands.get("sandbox") as Record<string, any>).handler("enable", secondContext);
      expect(await second.handlers.get("tool_call")?.[0]?.({ source: "model", toolName: "read", input: { path: join(root, "nested", "file.txt") } }, { cwd: root })).toBeUndefined();

      const third = new RecordingApi();
      await factory(third, successfulRestoreDependencies);
      await third.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, projectTrust: true, environment: { persistSensitiveNames: ["PROJECT_FORBIDDEN_TOKEN"] }, filesystem: { read: [], write: [] } } },
      ], { cwd: root }));
      await (third.tools.get("sandbox_request") as Record<string, any>).execute({ capability: "read", value: join(root, "exact.txt"), saveTo: "project" }, { agentId: "A1", hasUI: true, ui: { confirm: async () => true } });
      const stripped = JSON.parse(await Bun.file(profilePath).text());
      expect(stripped.environment.persistSensitiveNames).toBeUndefined();
      expect(JSON.stringify(stripped)).not.toContain("PROJECT_FORBIDDEN_TOKEN");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("orders Windows Tier-3 diagnostics and approval before the compatibility native probe", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    const calls: string[] = [];
    let observedProbeInput: Record<string, any> | undefined;
    await factory(api, {
      platform: "win32",
      loadMxc: async () => ({
        version: "0.7.0",
        schemaVersions: ["0.7.0-alpha"],
        reprobePlatformSupport: () => ({ isolationTier: "appcontainer-dacl", isolationWarnings: ["BaseContainer unavailable; selected DACL compatibility"], isSupported: true }),
      }),
      probeMxcExecution: async (input: Record<string, any>) => {
        observedProbeInput = input;
        calls.push(`probe:${input.policy.mxcOverrides.fallback.allowDaclMutation}`);
        return { contained: true, backend: "processcontainer", readonlyPathDiscoveryAttested: true, requiredReadonlyPaths: ["C:\\mxc\\bin", "C:\\runtime"], platformCapabilities: { windowsBuild: 26100, tier: "appcontainer-dacl", nativeEnforcementAvailable: false } };
      },
    });
    const context = enabledLifecycleContext([], {
      windowsBuild: 26100,
      cwd: "C:\\workspace",
      discoveredReadonlyPaths: ["C:\\injected-untrusted"],
      ui: {
        notify: () => undefined,
        confirm: async () => true,
        select: async (title: string) => {
          if (title === "Windows containment mode") { calls.push("select-compatibility"); return "compatibility-after-verified-host-preparation"; }
          if (title === "Initial MXC sandbox policy") return "Use secure initial defaults";
          return "use-for-conversation";
        },
      },
    });
    await (api.commands.get("sandbox") as Record<string, any>).handler("enable", context);
    expect(calls).toEqual(["select-compatibility", "probe:true"]);
    expect(observedProbeInput).toMatchObject({
      platform: "win32",
      shell: { executable: "C:\\Windows\\System32\\cmd.exe", args: ["/d", "/s", "/c"], dialect: "cmd" },
      policy: { filesystem: { read: [{ path: "C:\\workspace", kind: "directory", recursive: true }, { path: "C:\\Windows\\System32", kind: "directory", recursive: true }] } },
    });
    expect(observedProbeInput?.containerId).toMatch(/^mxc-/);
    expect(observedProbeInput?.env.SystemRoot).toBe(process.env.SystemRoot);
    expect(observedProbeInput?.requiredReadonlyPaths).toContain("C:\\Program Files\\Git\\bin");
    const saved = (api.entries.at(-1) as Record<string, any>).data;
    expect(saved.mxcOverrides.fallback.allowDaclMutation).toBe(true);
    expect(saved.filesystem.read).toEqual([{ path: "C:\\workspace", recursive: true }]);
  });

  test("fails production local-network grants closed without native probe evidence", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, network: { internet: false, localNetwork: false } } },
    ]));
    await expect((api.tools.get("sandbox_request") as Record<string, any>).execute({ capability: "local-network", value: "allow" }, { agentId: "A1", hasUI: true, ui: { confirm: async () => true } })).rejects.toMatchObject({ code: "LOCAL_NETWORK_CAPABILITY_UNPROVEN" });
  });

  test("registers the lifecycle parent, serializes ordinary child prompts, and removes it at teardown", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    const first = Promise.withResolvers<string>();
    const firstPrompted = Promise.withResolvers<void>();
    const secondPrompted = Promise.withResolvers<void>();
    const second = Promise.withResolvers<string>();
    const prompts: string[] = [];
    const parentContext = enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
    ], {
      sessionTreeId: "TREE",
      ui: { select: async (title: string) => { prompts.push(title); if (prompts.length === 1) { firstPrompted.resolve(); return first.promise; } secondPrompted.resolve(); return second.promise; } },
    });
    await api.handlers.get("session_start")?.[0]?.({}, parentContext);
    const tool = api.tools.get("sandbox_request") as Record<string, any>;
    const a = tool.execute({ capability: "read", value: "/tree/a" }, { agentId: "child-a", sessionTreeId: "TREE", hasUI: false });
    const b = tool.execute({ capability: "write", value: "/tree/b" }, { agentId: "child-b", sessionTreeId: "TREE", hasUI: false });
    await firstPrompted.promise;
    expect(prompts).toHaveLength(1);
    first.resolve("allow-conversation");
    await secondPrompted.promise;
    expect(prompts).toHaveLength(2);
    second.resolve("allow-conversation");
    await Promise.all([a, b]);
    expect((api.entries.at(-1) as Record<string, any>).data.filesystem).toMatchObject({ read: [expect.objectContaining({ path: "/tree/a" })], write: [expect.objectContaining({ path: "/tree/b" })] });
    await api.handlers.get("session_shutdown")?.[0]?.({}, parentContext);
    await expect(tool.execute({ capability: "read", value: "/tree/after" }, { agentId: "child-c", sessionTreeId: "TREE", hasUI: false })).rejects.toMatchObject({ code: "NO_INTERACTIVE_PARENT" });
  });

  test("dashboard edits apply atomically and cancel leaves policy unchanged", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, ui: { allowWindows: false, clipboardRead: false, clipboardWrite: false, inputInjection: false } } },
    ]));
    const choices = ["UI", "Clipboard Read", "Enable", "Apply"];
    await (api.commands.get("sandbox") as Record<string, any>).handler("update", { hasUI: true, ui: { select: async () => choices.shift() } });
    expect((api.entries.at(-1) as Record<string, any>).data.ui.clipboardRead).toBe(true);
    const count = api.entries.length;
    await (api.commands.get("sandbox") as Record<string, any>).handler("", { hasUI: true, ui: { select: async () => "Cancel" } });
    expect(api.entries).toHaveLength(count);
    await expect((api.commands.get("sandbox") as Record<string, any>).handler("", { hasUI: false, ui: {} })).rejects.toMatchObject({ code: "INTERACTIVE_UI_REQUIRED" });
  });

  test("dashboard exposes one coupled macOS network switch", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, {
      ...successfulRestoreDependencies,
      platform: "darwin",
      probeMxcExecution: async () => ({ contained: true, backend: "seatbelt", platformCapabilities: { coupledNetwork: true, allowedHosts: false, pty: false } }),
    });
    await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, network: { internet: false, localNetwork: false } } },
    ]));
    const choices = ["Network", "Network Access", "Enable", "Apply"];
    await (api.commands.get("sandbox") as Record<string, any>).handler("", { hasUI: true, ui: { select: async () => choices.shift() } });
    expect((api.entries.at(-1) as Record<string, any>).data.network).toMatchObject({ internet: true, localNetwork: true, unrestricted: true });
    expect(await api.handlers.get("tool_call")?.[0]?.({ source: "model", toolName: "browser", input: { url: "http://127.0.0.1:3210" } }, {})).toBeUndefined();
  });

  test("consumes an allow-once broker token for exactly one production interceptor operation", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-once-"));
    const target = join(root, "once.txt");
    try {
      await writeFile(target, "once");
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const canonicalTarget = await realpath(target);
      const api = new RecordingApi();
      await factory(api, successfulRestoreDependencies);
      const parent = enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
      ], { cwd: root, sessionTreeId: "ONCE-TREE", ui: { select: async () => "allow-once" } });
      await api.handlers.get("session_start")?.[0]?.({}, parent);
      const request = api.tools.get("sandbox_request") as Record<string, any>;
      const approved = await request.execute({ capability: "read", value: target }, { agentId: "once-child", sessionTreeId: "ONCE-TREE", hasUI: false });
      expect(approved).toMatchObject({ capability: "read", value: canonicalTarget, oneTime: true, granted: true, capabilityToken: { usesRemaining: 1 } });
      const dispatch = api.handlers.get("tool_call")?.[0];
      const child = { agentId: "once-child", sessionTreeId: "ONCE-TREE", cwd: root };
      expect(await dispatch?.({ source: "model", toolName: "read", input: { path: target } }, child)).toBeUndefined();
      expect(await dispatch?.({ source: "model", toolName: "read", input: { path: target } }, child)).toEqual({ block: true, reason: "sandbox-policy-denied" });
      expect(api.entries).toHaveLength(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("consumes an exact one-time write grant for a hashline edit target", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-edit-once-"));
    const target = join(root, "existing.txt");
    try {
      await writeFile(target, "before");
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, successfulRestoreDependencies);
      const context = enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
      ], { cwd: root, sessionTreeId: "EDIT-ONCE", ui: { select: async () => "allow-once" } });
      await api.handlers.get("session_start")?.[0]?.({}, context);
      const request = api.tools.get("sandbox_request") as Record<string, any>;
      const approved = await request.execute({ capability: "write", value: target }, context);
      expect(approved).toMatchObject({ capability: "write", oneTime: true, capabilityToken: { usesRemaining: 1 } });
      const dispatch = api.handlers.get("tool_call")?.[0];
      const invocation = { source: "model", toolName: "edit", input: { input: `[${target}#A1B2]\nSWAP 1.=1:\n+after` } };
      expect(await dispatch?.(invocation, context)).toBeUndefined();
      expect(await dispatch?.(invocation, context)).toEqual({ block: true, reason: "sandbox-policy-denied" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("normalizes a one-time internet host request and consumes it on the immediate URL read", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    const context = enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, network: { internet: false, localNetwork: false } } },
    ], { sessionTreeId: "HOST-ONCE", ui: { select: async (_title: string, choices: string[]) => choices.includes("Allow once") ? "Allow once" : choices.at(-1) } });
    await api.handlers.get("session_start")?.[0]?.({}, context);
    const request = api.tools.get("sandbox_request") as Record<string, any>;
    const approved = await request.execute({ capability: "internet", value: "example.com" }, context);
    expect(approved).toMatchObject({ capability: "allowed-host", value: "example.com", oneTime: true, capabilityToken: { usesRemaining: 1 } });
    const dispatch = api.handlers.get("tool_call")?.[0];
    expect(await dispatch?.({ source: "model", toolName: "read", input: { path: "https://example.com" } }, context)).toBeUndefined();
    expect(await dispatch?.({ source: "model", toolName: "read", input: { path: "https://example.com" } }, context)).toEqual({ block: true, reason: "network-host-not-granted" });
  });

  test("dashboard filesystem edits preserve single-file and recursive-directory scopes", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, network: { internet: false, localNetwork: false } } },
    ]));
    const choices = ["Filesystem", "Read-only paths", "Single Files", "Filesystem", "Read-only paths", "Directories and All Contents", "Apply"];
    const inputs = ["/scope/file.txt", "/scope/recursive-directory"];
    await (api.commands.get("sandbox") as Record<string, any>).handler("", { hasUI: true, ui: { select: async () => choices.shift(), input: async () => inputs.shift() } });
    expect((api.entries.at(-1) as Record<string, any>).data.filesystem.read).toEqual([
      { path: "/scope/file.txt", kind: "file" },
      { path: "/scope/recursive-directory", kind: "directory", recursive: true },
    ]);
  });

  test("expands tilde paths in the dashboard and labels its exit action clearly", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    const home = join(tmpdir(), `mxc-dashboard-home-${crypto.randomUUID()}`);
    await factory(api, { ...successfulRestoreDependencies, homeDirectory: home });
    await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
    ]));
    const selections = ["Filesystem", "Read-only paths", "Directories and All Contents", "Apply"];
    let topLevelChoices: string[] = [];
    await (api.commands.get("sandbox") as Record<string, any>).handler("", {
      hasUI: true,
      ui: {
        select: async (title: string, choices: string[]) => {
          if (title.startsWith("MXC Sandbox")) topLevelChoices = choices;
          return selections.shift();
        },
        input: async () => "~/.omp",
      },
    });
    expect(topLevelChoices).toContain("Apply Changes and Exit");
    expect((api.entries.at(-1) as Record<string, any>).data.filesystem.read).toContainEqual({ path: join(home, ".omp"), kind: "directory", recursive: true });
  });

  test("removes an existing permission directly from the update UI", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, policyRevision: 2, enabled: true, filesystem: { read: [{ path: "/custom/cache", kind: "directory", recursive: true }], write: [] } } },
    ]));
    let step = 0;
    await (api.commands.get("sandbox") as Record<string, any>).handler("update", {
      hasUI: true,
      ui: { select: async (_title: string, choices: string[]) => {
        step += 1;
        if (step === 1) return choices.find((choice) => choice.startsWith("Filesystem"));
        if (step === 2) return "Read-only paths";
        if (step === 3) return choices.find((choice) => choice.includes("/custom/cache"));
        if (step === 4) return "Remove";
        if (step === 5) return "Back";
        return "Apply Changes and Exit";
      } },
    });
    expect((api.entries.at(-1) as Record<string, any>).data.filesystem.read).toEqual([]);
  });

  test("separates runtime executable access from user permissions without breaking enforcement", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-runtime-policy-"));
    const command = join(root, "custom-command");
    const userFile = join(root, "user-approved.txt");
    try {
      await Promise.all([writeFile(command, "#!/bin/sh\nprintf ok"), writeFile(userFile, "approved")]);
      await chmod(command, 0o755);
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, { ...successfulRestoreDependencies, probeMxcExecution: async () => ({ contained: true, backend: "seatbelt", readonlyPathDiscoveryAttested: true, requiredReadonlyPaths: [command], platformCapabilities: { coupledNetwork: true } }) });
      const context = enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, policyRevision: 2, enabled: true, filesystem: { read: [{ path: userFile, kind: "file" }], write: [] } } },
      ], { cwd: "/Users/example/.omp" });
      await api.handlers.get("session_start")?.[0]?.({}, context);
      let status = "";
      await (api.commands.get("sandbox") as Record<string, any>).handler("status", { hasUI: true, ui: { notify: (message: string) => { status = message; } } });
      const payload = JSON.parse(status.slice(status.indexOf("{")));
      expect(payload.policy.filesystem.read).toEqual([{ path: userFile, kind: "file" }]);
      expect(payload.runtime.read).toEqual([{ path: command, kind: "file" }]);
      const dispatch = api.handlers.get("tool_call")?.[0];
      expect(await dispatch?.({ source: "model", toolName: "read", input: { path: command } }, context)).toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("status displays state and upgrades legacy directory grants to include contents", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [{ path: "/Users/example/.omp", kind: "directory", recursive: false }], write: [] } } },
    ]));
    let status = "";
    await (api.commands.get("sandbox") as Record<string, any>).handler("status", { hasUI: true, ui: { notify: (message: string) => { status = message; } } });
    expect(status).toContain('\"enabled\": true');
    expect(status).toContain('\"path\": \"/Users/example/.omp\"');
    expect(status).toContain('\"recursive\": true');
  });

  test("resolves relative tool paths against cwd before checking recursive grants", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-relative-grant-"));
    try {
      await writeFile(join(root, "write-probe.txt"), "ok");
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, successfulRestoreDependencies);
      const context = enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [{ path: root, kind: "directory", recursive: true }], write: [] } } },
      ], { cwd: root });
      await api.handlers.get("session_start")?.[0]?.({}, context);
      let prompted = false;
      const result = await api.handlers.get("tool_call")?.[0]?.({ source: "model", toolName: "read", input: { path: "write-probe.txt" } }, { cwd: root, ui: { select: async () => { prompted = true; return "Deny"; } } });
      expect(result).toBeUndefined();
      expect(prompted).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("enforces exact non-filesystem denies and rejects invalid deny forms", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-deny-"));
    const denied = join(root, "denied.txt");
    const sibling = join(root, "sibling.txt");
    const secret = `MXC_DENIED_SECRET_${crypto.randomUUID().replaceAll("-", "_")}`;
    process.env[secret] = "must-not-leak";
    try {
      await Promise.all([writeFile(denied, "x"), writeFile(sibling, "y")]);
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, { ...successfulRestoreDependencies, platform: "linux", probeMxcExecution: async () => ({ contained: true, backend: "bubblewrap", platformCapabilities: { allowedHosts: true, blockedHosts: true, independentLocalNetwork: true } }) });
      const lifecycle = enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [{ path: root, kind: "directory", recursive: true }], write: [] }, network: { internet: true, unrestricted: true, localNetwork: true, allowedHosts: ["allowed.example"] }, ui: { allowWindows: true, clipboardRead: true, clipboardWrite: false, inputInjection: false }, trustedTools: ["vendor.safe"] } },
      ], { cwd: root, sessionTreeId: "DENY-TREE" });
      await api.handlers.get("session_start")?.[0]?.({}, lifecycle);
      const command = api.commands.get("sandbox") as Record<string, any>;
      for (const value of [
        `deny read ${denied}`,
        "deny internet allow",
        "deny local-network allow",
        "deny allowed-host allowed.example",
        `deny sensitive-environment-name ${secret}`,
        "deny ui clipboardRead",
        "deny trusted-tool vendor.safe",
      ]) await command.handler(value, {});
      const dispatch = api.handlers.get("tool_call")?.[0];
      expect(await dispatch?.({ source: "model", toolName: "read", input: { path: denied } }, { cwd: root })).toEqual({ block: true, reason: "sandbox-policy-denied" });
      expect(await dispatch?.({ source: "model", toolName: "read", input: { path: sibling } }, { cwd: root })).toBeUndefined();
      expect(await dispatch?.({ source: "model", toolName: "web_search", input: { query: "blocked" } }, {})).toEqual({ block: true, reason: "unrestricted-internet-required" });
      expect(await dispatch?.({ source: "model", toolName: "browser", input: { url: "https://allowed.example" } }, {})).toEqual({ block: true, reason: "network-host-blocked" });
      expect(await dispatch?.({ source: "model", toolName: "vendor.safe", mutationOrExecution: true, input: {} }, {})).toBeUndefined();
      let config: Record<string, any> | undefined;
      await (api.tools.get("bash") as Record<string, any>).execute({ command: "env", spawn: async (value: Record<string, any>) => { config = value; return { exitCode: 0 }; } }, { ...lifecycle, ui: { select: async () => "Omit all" } });
      expect(config?.process.env[secret]).toBeUndefined();
      expect(config?.ui.clipboardRead).toBe(false);
      expect((api.entries.at(-1) as Record<string, any>).data.capabilityDenies).toEqual(expect.arrayContaining([
        { capability: "internet", value: "allow" }, { capability: "allowed-host", value: "allowed.example" }, { capability: "trusted-tool", value: "vendor.safe" },
      ]));
      await expect(command.handler("deny ui not-a-capability", {})).rejects.toMatchObject({ code: "INVALID_SANDBOX_CAPABILITY_VALUE" });
      await expect(command.handler("deny unknown anything", {})).rejects.toMatchObject({ code: "UNSUPPORTED_SANDBOX_CAPABILITY" });
    } finally {
      delete process.env[secret];
      await rm(root, { recursive: true, force: true });
    }
  });

  test("restores process-local secrets within one tree but not another conversation", async () => {
    const secret = `MXC_TREE_SECRET_${crypto.randomUUID().replaceAll("-", "_")}`;
    process.env[secret] = "tree-only";
    try {
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, successfulRestoreDependencies);
      const entries = [{ type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, environment: { sensitive: [secret] } } }];
      const contextFor = (sessionId: string, sessionTreeId: string, ui: Record<string, unknown>) => {
        const scopedManager = {};
        const sessionManager = { getSessionId: () => sessionId, getSessionTreeId: () => sessionTreeId, getBranch: () => entries, allocateArtifactPath: async () => ({ id: `A-${sessionId}`, path: join(tmpdir(), `artifact-${sessionId}`) }) };
        return { hasUI: true, cwd: process.cwd(), agentId: "A1", sessionTreeId, sessionManager, scopedManager, liveMatches: [{ live: true, sessionId, agentId: "A1", scopedManager }], configuredShell: "/bin/zsh", shellRenderer: async () => undefined, onShellUpdate: () => undefined, ui };
      };
      const firstContext = contextFor("S-secret-1", "TREE-SECRET", { select: async (title: string) => title.startsWith("Sensitive environment") ? `Allow ${secret}` : "Omit all" });
      await api.handlers.get("session_start")?.[0]?.({}, firstContext);
      let firstConfig: Record<string, any> | undefined;
      await (api.tools.get("bash") as Record<string, any>).execute({ command: "env", spawn: async (value: Record<string, any>) => { firstConfig = value; return { exitCode: 0 }; } }, firstContext);
      expect(firstConfig?.process.env[secret]).toBe("tree-only");

      const sameTreeContext = contextFor("S-secret-2", "TREE-SECRET", { select: async () => "Omit all" });
      await api.handlers.get("session_switch")?.[0]?.({}, sameTreeContext);
      let sameTreeConfig: Record<string, any> | undefined;
      await (api.tools.get("bash") as Record<string, any>).execute({ command: "env", spawn: async (value: Record<string, any>) => { sameTreeConfig = value; return { exitCode: 0 }; } }, sameTreeContext);
      expect(sameTreeConfig?.process.env[secret]).toBe("tree-only");

      const otherTreeContext = contextFor("S-secret-3", "TREE-OTHER", { select: async () => "Omit all" });
      await api.handlers.get("session_switch")?.[0]?.({}, otherTreeContext);
      let otherTreeConfig: Record<string, any> | undefined;
      await (api.tools.get("bash") as Record<string, any>).execute({ command: "env", spawn: async (value: Record<string, any>) => { otherTreeConfig = value; return { exitCode: 0 }; } }, otherTreeContext);
      expect(otherTreeConfig?.process.env[secret]).toBeUndefined();
    } finally {
      delete process.env[secret];
    }
  });

  test("routes headless inline file and nonreadonly LSP prompts through the lifecycle parent", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-headless-inline-"));
    try {
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, successfulRestoreDependencies);
      const prompts: string[] = [];
      const parent = enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
      ], { cwd: root, sessionTreeId: "INLINE-TREE", ui: { select: async (title: string, choices: string[]) => { prompts.push(title); return choices.includes("Allow this action once") ? "Allow this action once" : choices.find((choice) => choice.startsWith("Allow this exact path")) ?? "Deny"; } } });
      await api.handlers.get("session_start")?.[0]?.({}, parent);
      const dispatch = api.handlers.get("tool_call")?.[0];
      const child = { agentId: "inline-child", sessionTreeId: "INLINE-TREE", hasUI: false, cwd: root };
      const target = join(root, "child-output.txt");
      const canonicalTarget = join(await realpath(root), "child-output.txt");
      expect(await dispatch?.({ source: "model", toolName: "write", input: { path: target, content: "x" } }, child)).toBeUndefined();
      expect(await dispatch?.({ source: "model", toolName: "lsp", input: { readonly: false, action: "rename" } }, child)).toBeUndefined();
      expect(JSON.stringify(prompts)).toContain("inline-child");
      expect(JSON.stringify(prompts)).toContain("child-output.txt");
      expect(JSON.stringify(prompts)).toContain("rename");
      expect(JSON.stringify(prompts)).toContain("nonreadonly-lsp");
      expect(api.entries.at(-1)?.data).toMatchObject({ filesystem: { write: [expect.objectContaining({ path: canonicalTarget })] } });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("routes headless outside-once and critical confirmations to the exact registered parent", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    const prompts: string[] = [];
    const parent = enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] } } },
    ], { sessionTreeId: "SHELL-TREE", ui: { select: async (title: string) => { prompts.push(title); return "Approve"; } } });
    await api.handlers.get("session_start")?.[0]?.({}, parent);
    const scopedManager = {};
    const sessionManager = { getSessionId: () => "CHILD-SHELL", getSessionTreeId: () => "SHELL-TREE", allocateArtifactPath: parent.sessionManager.allocateArtifactPath };
    const child = { agentId: "shell-child", sessionTreeId: "SHELL-TREE", sessionManager, scopedManager, liveMatches: [{ live: true, sessionId: "CHILD-SHELL", agentId: "shell-child", scopedManager }], configuredShell: "/bin/zsh", hasUI: false };
    const bash = api.tools.get("bash") as Record<string, any>;
    await bash.execute({ outsideSandbox: true, command: "printf outside", cwd: "/exact/cwd" }, child);
    let spawned = false;
    await bash.execute({ command: "rm -rf /", cwd: "/critical/cwd", spawn: async () => { spawned = true; return { exitCode: 0 }; } }, child);
    expect(api.hostRuns).toBe(1);
    expect(spawned).toBe(true);
    expect(prompts.some((title) => title.includes("Run outside MXC once") && title.includes("printf outside") && title.includes("/exact/cwd") && title.includes("shell-child"))).toBe(true);
    expect(prompts.some((title) => title.includes("Confirm critical command") && title.includes("rm -rf /") && title.includes("/critical/cwd") && title.includes("shell-child"))).toBe(true);
  });

  test("upgrades legacy exact-directory grants to recursive directory access", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-exact-directory-"));
    try {
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, successfulRestoreDependencies);
      const context = enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [{ path: root, kind: "directory", recursive: false }], write: [] } } },
      ], { cwd: root });
      await api.handlers.get("session_start")?.[0]?.({}, context);
      const dispatch = api.handlers.get("tool_call")?.[0];
      expect(await dispatch?.({ source: "model", toolName: "read", input: { path: root } }, { cwd: root })).toBeUndefined();
      expect(await dispatch?.({ source: "model", toolName: "read", input: { path: join(root, "child.txt") } }, { cwd: root })).toBeUndefined();
      let sdkCalls = 0;
      const adapter = { version: "0.7.0", schemaVersion: "0.7.0-alpha", schemaVersions: ["0.7.0-alpha"], getPlatformSupport: () => ({}), reprobePlatformSupport: () => ({}), createConfigFromPolicy: async () => { sdkCalls += 1; return { process: {} }; }, spawnSandboxFromConfig: async () => ({ exitCode: 0 }) };
      const bash = api.tools.get("bash") as Record<string, any>;
      await expect(bash.execute({ command: "ls", mxcAdapter: adapter }, context)).resolves.toMatchObject({ exitCode: 0 });
      expect(sdkCalls).toBe(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("saves only mixed user and project deltas while conversation grants remain conversation-only", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-layer-delta-"));
    const home = join(root, "home");
    const repo = join(root, "repo");
    try {
      await Promise.all([mkdir(join(home, ".omp", "agent"), { recursive: true }), mkdir(join(repo, ".git"), { recursive: true }), mkdir(join(repo, ".omp"), { recursive: true })]);
      const userExisting = join(repo, "user-existing.txt");
      const projectExisting = join(repo, "project-existing.txt");
      const conversationOnly = join(repo, "conversation-only.txt");
      const userAdded = join(repo, "user-added.txt");
      const projectAdded = join(repo, "project-added.txt");
      await writeFile(join(home, ".omp", "agent", "sandbox.yml"), JSON.stringify({ version: 1, filesystem: { read: [userExisting] } }));
      await writeFile(join(repo, ".omp", "sandbox.yml"), JSON.stringify({ version: 1, filesystem: { read: [projectExisting] } }));
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, { ...successfulRestoreDependencies, homeDirectory: home });
      const context = enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, projectTrust: true, filesystem: { read: [{ path: conversationOnly, kind: "file" }], write: [] } } },
      ], { cwd: repo });
      await api.handlers.get("session_start")?.[0]?.({}, context);
      const request = api.tools.get("sandbox_request") as Record<string, any>;
      await request.execute({ capability: "read", value: userAdded, saveTo: "user" }, { agentId: "A1", hasUI: true, ui: { confirm: async () => true } });
      await request.execute({ capability: "read", value: projectAdded, saveTo: "project" }, { agentId: "A1", hasUI: true, ui: { confirm: async () => true } });
      const userSaved = JSON.parse(await Bun.file(join(home, ".omp", "agent", "sandbox.yml")).text());
      const projectSaved = JSON.parse(await Bun.file(join(repo, ".omp", "sandbox.yml")).text());
      expect(JSON.stringify(userSaved)).toContain(userExisting);
      expect(JSON.stringify(userSaved)).toContain(userAdded);
      expect(JSON.stringify(userSaved)).not.toContain(projectExisting);
      expect(JSON.stringify(userSaved)).not.toContain(conversationOnly);
      expect(JSON.stringify(projectSaved)).toContain(projectExisting);
      expect(JSON.stringify(projectSaved)).toContain(projectAdded);
      expect(JSON.stringify(projectSaved)).not.toContain(userExisting);
      expect(JSON.stringify(projectSaved)).not.toContain(conversationOnly);
      const persisted = api.entries.at(-1)?.data;
      if (!isRecord(persisted)) throw new Error("Expected persisted mixed-layer state");
      const reloaded = new RecordingApi();
      await factory(reloaded, { ...successfulRestoreDependencies, homeDirectory: home });
      await reloaded.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { ...persisted, version: 1 } },
      ], { cwd: repo }));
      const reloadDispatch = reloaded.handlers.get("tool_call")?.[0];
      for (const path of [userExisting, userAdded, projectExisting, projectAdded, conversationOnly]) expect(await reloadDispatch?.({ source: "model", toolName: "read", input: { path } }, { cwd: repo })).toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("consumes filesystem network environment and UI shell pregrants for one invocation only", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-shell-pregrant-"));
    const target = join(root, "once.txt");
    const secret = `MXC_SHELL_ONCE_SECRET_${crypto.randomUUID().replaceAll("-", "_")}`;
    process.env[secret] = "one-use-secret";
    try {
      await writeFile(target, "once");
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, { ...successfulRestoreDependencies, platform: "linux" });
      const parent = enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, network: { internet: false, localNetwork: false }, ui: { allowWindows: false, clipboardRead: false, clipboardWrite: false, inputInjection: false } } },
      ], { cwd: root, sessionTreeId: "SHELL-ONCE", ui: { select: async () => "allow-once" } });
      await api.handlers.get("session_start")?.[0]?.({}, parent);
      const request = api.tools.get("sandbox_request") as Record<string, any>;
      const childBase = { agentId: "once-shell-child", sessionTreeId: "SHELL-ONCE", hasUI: false };
      for (const grant of [{ capability: "read", value: target }, { capability: "internet", value: "allow" }, { capability: "sensitive-environment-name", value: secret }, { capability: "ui", value: "clipboardRead" }]) await request.execute(grant, childBase);
      const scopedManager = {};
      const sessionManager = { getSessionId: () => "SHELL-ONCE-SESSION", getSessionTreeId: () => "SHELL-ONCE", allocateArtifactPath: parent.sessionManager.allocateArtifactPath };
      const child = { ...childBase, sessionManager, scopedManager, liveMatches: [{ live: true, sessionId: "SHELL-ONCE-SESSION", agentId: "once-shell-child", scopedManager }], configuredShell: "/bin/zsh" };
      const configs: Record<string, any>[] = [];
      const bash = api.tools.get("bash") as Record<string, any>;
      const first = await bash.execute({ command: `cat ${target}`, spawn: async (config: Record<string, any>) => { configs.push(config); return { exitCode: 0 }; } }, child);
      const second = await bash.execute({ command: `cat ${target}`, spawn: async (config: Record<string, any>) => { configs.push(config); return { exitCode: 73 }; } }, child);
      expect(first.exitCode).toBe(0);
      expect(second.exitCode).toBe(73);
      expect(configs[0]?.policy).toMatchObject({ filesystem: { read: [expect.objectContaining({ path: await realpath(target) })] }, network: { internet: true, unrestricted: true }, ui: { clipboardRead: true } });
      expect(configs[0]?.process.env[secret]).toBe("one-use-secret");
      expect(configs[1]?.policy).toMatchObject({ filesystem: { read: [] }, network: { internet: false }, ui: { clipboardRead: false } });
      expect(configs[1]?.process.env[secret]).toBeUndefined();
    } finally {
      delete process.env[secret];
      await rm(root, { recursive: true, force: true });
    }
  });

  test("never trusts macOS allowedHosts attestation on MXC 0.7", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, {
      ...successfulRestoreDependencies,
      platform: "darwin",
      probeMxcExecution: async () => ({ contained: true, backend: "seatbelt", platformCapabilities: { independentLocalNetwork: true, allowedHosts: true } }),
    });
    let choices = 0;
    await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
      { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, network: { internet: true, localNetwork: true, allowedHosts: ["allowed.example"] } } },
    ], { ui: { select: async () => { choices += 1; return "block-network"; } } }));
    expect(choices).toBe(1);
    expect(await api.handlers.get("tool_call")?.[0]?.({ source: "model", toolName: "browser", input: { url: "https://allowed.example/x" } }, {})).toEqual({ block: true, reason: "network-host-not-granted" });
  });

  test("dashboard approval records saved-deny overrides and preserves them across reload", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-dashboard-override-"));
    const home = join(root, "home");
    try {
      await mkdir(join(home, ".omp", "agent"), { recursive: true });
      await writeFile(join(home, ".omp", "agent", "sandbox.yml"), JSON.stringify({ version: 1, capabilityDenies: [{ capability: "ui", value: "clipboardRead" }], ui: { clipboardRead: true } }));
      const mod = await loadContract("extension");
      const factory = requiredExport<ExtensionFactory>(mod, "default");
      const api = new RecordingApi();
      await factory(api, { ...successfulRestoreDependencies, homeDirectory: home });
      await api.handlers.get("session_start")?.[0]?.({}, enabledLifecycleContext([
        { type: "custom", customType: "mxc-sandbox/state", data: { version: 1, enabled: true, filesystem: { read: [], write: [] }, ui: { allowWindows: false, clipboardRead: false, clipboardWrite: false, inputInjection: false } } },
      ], { cwd: root }));
      let deniedConfig: Record<string, any> | undefined;
      const initiallyDeniedBash = api.tools.get("bash") as Record<string, any>;
      const deniedContext = enabledLifecycleContext([], { cwd: root });
      await initiallyDeniedBash.execute({ command: "printf denied", spawn: async (value: Record<string, any>) => { deniedConfig = value; return { exitCode: 0 }; } }, deniedContext);
      expect(deniedConfig?.ui.clipboardRead).toBe(false);
      const dashboardChoices = ["UI", "Clipboard Read", "Enable", "Apply"];
      const dashboard = api.commands.get("sandbox") as Record<string, any>;
      await dashboard.handler("", { hasUI: true, ui: { select: async () => dashboardChoices.shift() } });
      const savedState = api.entries.at(-1)?.data;
      if (!isRecord(savedState)) throw new Error("Expected persisted dashboard state");
      expect(savedState.explicitDenyOverrides).toContainEqual({ capability: "ui", value: "clipboardRead" });
      expect(savedState.capabilityDenies).not.toContainEqual({ capability: "ui", value: "clipboardRead" });
      const reloaded = new RecordingApi();
      await factory(reloaded, { ...successfulRestoreDependencies, homeDirectory: home });
      const reloadContext = enabledLifecycleContext([{ type: "custom", customType: "mxc-sandbox/state", data: { ...savedState, version: 1 } }], { cwd: root });
      await reloaded.handlers.get("session_start")?.[0]?.({}, reloadContext);
      let config: Record<string, any> | undefined;
      const bash = reloaded.tools.get("bash") as Record<string, any>;
      await bash.execute({ command: "printf ok", spawn: async (value: Record<string, any>) => { config = value; return { exitCode: 0 }; } }, reloadContext);
      expect(config?.ui.clipboardRead).toBe(true);
      const persistedProfile = JSON.parse(await Bun.file(join(home, ".omp", "agent", "sandbox.yml")).text());
      if (!isRecord(persistedProfile)) throw new Error("Expected persisted user profile");
      expect(persistedProfile.capabilityDenies).toContainEqual({ capability: "ui", value: "clipboardRead" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("disabled-by-default extension loading", () => {
  test("registers the approved surface without loading MXC, installing, or spawning", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    const before = { spawned: 0, installed: 0, mxcLoaded: 0 };
    (globalThis as Record<string, unknown>).__MXC_SANDBOX_TEST_OBSERVER__ = before;
    await factory(api);
    expect(api.commands.has("sandbox")).toBe(true);
    expect([...api.commands.keys()]).toEqual(["sandbox"]);
    expect(api.tools.has("sandbox_run")).toBe(false);
    expect(before).toEqual({ spawned: 0, installed: 0, mxcLoaded: 0 });
    expect(api.entries).toEqual([]);
    delete (globalThis as Record<string, unknown>).__MXC_SANDBOX_TEST_OBSERVER__;
  });

  test("starts disabled and preserves exact ordinary behavior", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api);
    const bash = api.tools.get("bash") as { execute(input: Record<string, unknown>, context: Record<string, unknown>): Promise<unknown> };
    expect(bash).toBeDefined();
    await expect(bash.execute({ command: "printf ok", cwd: "/tmp", pty: false }, {})).resolves.toEqual({ code: 0, stdout: "host", stderr: "", killed: false });
    if (process.platform === "win32") expect(String(api.execCalls[0]?.[0])).toMatch(/[\\/]bash\.exe$/i);
    else expect(api.execCalls[0]?.[0]).toBe(process.env.SHELL ?? "/bin/bash");
    expect(api.execCalls[0]?.[1]).toEqual(["-lc", "printf ok"]);
  });

  test("does not intercept user bang commands or RPC bash", async () => {
    const mod = await loadContract("tools");
    const intercept = requiredExport<InterceptToolCall>(mod, "interceptToolCall");
    expect(await intercept({ source: "user-bang", toolName: "bash", input: { command: "echo host" } }, { enabled: true })).toBeUndefined();
    expect(await intercept({ source: "rpc", toolName: "bash", input: { command: "echo host" } }, { enabled: true })).toBeUndefined();
    expect(await intercept({ source: "model", toolName: "bash", input: { command: "echo sandbox" } }, { enabled: true })).toMatchObject({ action: "sandbox" });
  });
});

describe("activation gates and dependency bootstrap", () => {
  test("loads and probes MXC only on first enable", async () => {
    const mod = await loadContract("activation");
    const activate = requiredExport<ActivateSandbox>(mod, "activateSandbox");
    const calls: string[] = [];
    const dependencies = {
      loadMxc: async () => { calls.push("load-mxc"); return { version: "0.7.0", schemaVersions: ["0.7.0-alpha"] }; },
      probeMxcExecution: async () => { calls.push("probe-execution"); return { backend: "seatbelt", contained: true }; },
      probeOmp: async () => { calls.push("probe-omp"); return { allRequired: true }; },
    };
    expect(calls).toEqual([]);
    await activate({ action: "status", dependencies });
    expect(calls).toEqual([]);
    expect(await activate({ action: "enable", dependencies, hasUI: true })).toMatchObject({ enabled: false, setupRequired: true });
    expect(calls).toEqual(["load-mxc", "probe-execution", "probe-omp"]);
  });

  test("shows and confirms the exact install command, then re-probes", async () => {
    const mod = await loadContract("activation");
    const activate = requiredExport<ActivateSandbox>(mod, "activateSandbox");
    const calls: string[] = [];
    const exact = "cd /Users/example/.omp/agent/extensions/mxc-sandbox && bun add @microsoft/mxc-sdk@^0.7.0";
    const result = await activate({
      action: "enable",
      hasUI: true,
      extensionDirectory: "/Users/example/.omp/agent/extensions/mxc-sandbox",
      dependencies: {
        loadMxc: async () => { calls.push("load"); return calls.filter((item) => item === "load").length === 1 ? null : { version: "0.7.0", schemaVersions: ["0.7.0-alpha"] }; },
        confirmInstall: async (command: string) => { calls.push(`confirm:${command}`); return true; },
        executeInstall: async (command: string) => { calls.push(`execute:${command}`); return { exitCode: 0 }; },
        probeMxcExecution: async () => ({ contained: true, backend: "seatbelt" }),
        probeOmp: async () => ({ allRequired: true }),
      },
    });
    expect(calls).toEqual(["load", `confirm:${exact}`, `execute:${exact}`, "load"]);
    expect(result).toMatchObject({ enabled: false, setupRequired: true, sdkVersion: "0.7.0", schemaVersion: "0.7.0-alpha" });
  });

  test("refuses installation without positive approval", async () => {
    const mod = await loadContract("activation");
    const activate = requiredExport<ActivateSandbox>(mod, "activateSandbox");
    let executed = false;
    await expectAsyncFailureCode(() => activate({
      action: "enable",
      hasUI: true,
      dependencies: {
        loadMxc: async () => null,
        confirmInstall: async () => false,
        executeInstall: async () => { executed = true; return { exitCode: 0 }; },
      },
    }), "DEPENDENCY_INSTALL_DECLINED");
    expect(executed).toBe(false);
  });

  test("hard-fails every required missing OMP feature", async () => {
    const mod = await loadContract("activation");
    const probe = requiredExport<ProbeActivation>(mod, "probeActivationFeatures");
    const required = ["sameNameBashReplacement", "disabledBashDelegate", "preToolInterception", "sessionStatePersistence", "interactivePermissionUi", "mxcExecution", "artifactAllocation"];
    for (const missing of required) {
      const capabilities = Object.fromEntries(required.map((name) => [name, name !== missing]));
      expect(await probe({ capabilities })).toMatchObject({ ok: false, missing: [missing] });
    }
  });

  test("rejects ambiguous or unscoped async session mapping", async () => {
    const mod = await loadContract("activation");
    const probe = requiredExport<ProbeActivation>(mod, "probeActivationFeatures");
    expect(await probe({ sessionId: "S1", registryRefs: [] })).toMatchObject({ ok: false, missing: ["safeAsyncOwnerMapping"] });
    expect(await probe({ sessionId: "S1", registryRefs: [{ id: "A1", sessionId: "S1", scopedManager: {} }, { id: "A2", sessionId: "S1", scopedManager: {} }] })).toMatchObject({ ok: false, missing: ["safeAsyncOwnerMapping"], reason: "ambiguous-session" });
    expect(await probe({ sessionId: "S1", registryRefs: [{ id: "A1", sessionId: "S1", agentSessionId: "A1", scopedManager: {} }] })).toMatchObject({ ok: true, ownerId: "A1" });
  });

  test("uses a real contained dry-run rather than platform support alone", async () => {
    const mod = await loadContract("activation");
    const activate = requiredExport<ActivateSandbox>(mod, "activateSandbox");
    await expectAsyncFailureCode(() => activate({
      action: "enable",
      hasUI: true,
      dependencies: {
        loadMxc: async () => ({ version: "0.7.0", schemaVersions: ["0.7.0-alpha"] }),
        getPlatformSupport: async () => ({ supported: true }),
        probeMxcExecution: async () => ({ contained: false, backend: "seatbelt", error: "native launch failed" }),
        probeOmp: async () => ({ allRequired: true }),
      },
    }), "MXC_CONTAINMENT_PROBE_FAILED");
  });

  test("fails a fresh setup closed without a TUI or safely resolved parent", async () => {
    const mod = await loadContract("activation");
    const activate = requiredExport<ActivateSandbox>(mod, "activateSandbox");
    await expectAsyncFailureCode(() => activate({ action: "enable", hasUI: false, parentBroker: null }), "INTERACTIVE_SETUP_REQUIRED");
  });
});

describe("commands and UI contracts", () => {
  test("parses all subcommands from one sandbox command", async () => {
    const mod = await loadContract("commands");
    const parse = requiredExport<ParseCommand>(mod, "parseSandboxCommand");
    expect(parse("")).toEqual({ command: "dashboard" });
    for (const command of ["status", "update", "enable", "disable", "clear", "doctor", "update-mxc"]) expect(parse(command)).toEqual({ command });
    expect(parse("allow read /repo/a --conversation")).toEqual({ command: "allow", capability: "read", target: "/repo/a", scope: "conversation" });
    expect(parse("deny write /repo/private --project")).toEqual({ command: "deny", capability: "write", target: "/repo/private", scope: "project" });
  });

  test("suggests every sandbox subcommand while typing arguments", async () => {
    const mod = await loadContract("extension");
    const factory = requiredExport<ExtensionFactory>(mod, "default");
    const api = new RecordingApi();
    await factory(api, successfulRestoreDependencies);
    const command = api.commands.get("sandbox") as Record<string, any>;
    const complete = command.getArgumentCompletions as (prefix: string) => Record<string, string>[] | null;
    expect(complete("")?.map((item) => item.value)).toEqual(["status", "update", "enable", "disable", "doctor", "clear", "update-mxc", "allow", "deny"]);
    expect(complete("en")).toEqual([{ value: "enable", label: "enable", description: "Probe installed MXC and turn on sandboxing" }]);
    expect(complete("allow ")).toBeNull();
  });

  test("runs the explicit MXC update flow only after confirmation", async () => {
    const mod = await loadContract("commands");
    const updateMxc = requiredExport<(input: Record<string, any>) => Promise<Record<string, any>>>(mod, "updateMxc");
    const exact = "cd /Users/example/.omp/agent/extensions/mxc-sandbox && bun update @microsoft/mxc-sdk";
    const calls: string[] = [];
    expect(await updateMxc({ extensionDirectory: "/Users/example/.omp/agent/extensions/mxc-sandbox", confirm: async (command: string) => { calls.push(`confirm:${command}`); return true; }, execute: async (command: string) => { calls.push(`execute:${command}`); return { exitCode: 0 }; }, reprobe: async () => { calls.push("reprobe"); return { version: "0.7.0" }; } })).toMatchObject({ version: "0.7.0" });
    expect(calls).toEqual([`confirm:${exact}`, `execute:${exact}`, "reprobe"]);
  });

  test("provides the approved setup defaults from exact cwd and discovered paths", async () => {
    const mod = await loadContract("ui");
    const defaults = requiredExport<SetupDefaults>(mod, "getInitialSetupDefaults");
    expect(defaults({ cwd: "/repo/subdir", temp: "/private/tmp", discoveredReadonlyPaths: ["/bin", "/usr/lib", "/opt/toolchain"] })).toEqual({
      filesystem: { read: [{ path: "/repo/subdir", recursive: true }, { path: "/bin", recursive: true }, { path: "/usr/lib", recursive: true }, { path: "/opt/toolchain", recursive: true }], write: [{ path: "/private/tmp", recursive: true }] },
      network: { internet: false, localNetwork: false },
      ui: { allowWindows: true, clipboardRead: false, clipboardWrite: false, inputInjection: false },
      environment: { inheritOrdinary: true, sensitive: "prompt" },
      shellApproval: { normal: "automatic", critical: "confirm" },
    });
  });

  test("separates user filesystem rules from managed runtime access in the update UI", async () => {
    const mod = await loadContract("ui");
    const present = requiredExport<DashboardPresentation>(mod, "createDashboardPresentation");
    const view = present({ enabled: true, runtimeReadonlyGrants: [{ path: "/opt/runtime/bin/tool", kind: "file" }], policy: {
      filesystem: {
        read: [{ path: "/repo", kind: "directory", recursive: true }, { path: "/repo/config.json", kind: "file" }],
        write: [{ path: "/repo/out", kind: "directory", recursive: true }],
        deny: [{ path: "/repo/private", kind: "directory", recursive: true }],
      },
      network: { internet: false, localNetwork: false },
      trustedTools: ["vendor.safe"],
    } });
    expect(view.title).toContain("[ENABLED]");
    expect(view.title).toContain("2 read");
    expect(view.filesystemTitle).toContain("/repo/config.json");
    expect(view.filesystemTitle).toContain("/repo/private");
    expect(view.filesystemTitle).not.toContain("/opt/runtime/bin/tool");
    expect(view.runtimeTitle).toContain("/opt/runtime/bin/tool");
    expect(view.options[1]).toContain("Runtime Executables");
  });

  test("opens every approved dashboard section", async () => {
    const mod = await loadContract("ui");
    const model = requiredExport<DashboardModel>(mod, "createDashboardModel");
    expect(model({ platform: "windows" }).tabs).toEqual(["General", "Filesystem", "Runtime Executables", "Network", "Environment", "UI", "Trusted Tools", "Windows Compatibility/Advanced", "Status/Diagnostics"]);
  });

  test("offers explicit user and project save actions only after setup completion", async () => {
    const mod = await loadContract("ui");
    const model = requiredExport<DashboardModel>(mod, "createSetupCompletionModel");
    expect(model({ complete: false }).actions).toEqual([]);
    expect(model({ complete: true }).actions).toEqual(["use-for-conversation", "save-user-profile", "save-project-profile"]);
  });

  test("MXC launch failure displays exactly four non-fallback choices", async () => {
    const mod = await loadContract("ui");
    const choices = requiredExport<FailureChoices>(mod, "mxcLaunchFailureChoices");
    expect(choices()).toEqual(["Retry sandbox", "Run this command outside once", "Disable sandbox for this conversation", "Cancel"]);
  });

  test("re-enable offers restore or reset after prior disable", async () => {
    const mod = await loadContract("ui");
    const model = requiredExport<DashboardModel>(mod, "createReenableModel");
    expect(model({ priorConversationPolicy: true }).actions).toEqual(["restore-prior-policy-and-grants", "reset-and-run-setup"]);
  });
});

describe("tool interception and escape flows", () => {
  test("allows adapted host tools only after pre-execution gate and leaves OMP approval separate", async () => {
    const mod = await loadContract("tools");
    const intercept = requiredExport<InterceptToolCall>(mod, "interceptToolCall");
    const result = await intercept({ source: "model", toolName: "write", input: { path: "/repo/a", content: "x" } }, { enabled: true, sandboxPolicy: { write: ["/repo/a"] }, ompApproval: "still-required" });
    expect(result).toEqual({ action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged" });
  });
  test("delegates passive OMP URIs while gating SSH, Vault, and unknown schemes", async () => {
    const mod = await loadContract("tools");
    const intercept = requiredExport<InterceptToolCall>(mod, "interceptToolCall");
    const context = { enabled: true, sandboxPolicy: { read: [], write: [] } };
    const internalTargets = [
      "artifact://A1", "agent://A1", "skill://domain-modeling", "local://context.txt", "memory://key",
      "rule://policy", "omp://", "issue://1", "pr://1", "history://A1", "mcp://resource",
      "xd://sandbox_request", "xd://resolve", "xd://reject", "xd://propose",
    ];
    for (const path of internalTargets) {
      expect(await intercept({ source: "model", toolName: "read", input: { path } }, context)).toEqual({ action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged" });
      expect(await intercept({ source: "model", toolName: "write", input: { path, content: "{}" } }, context)).toEqual({ action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged" });
    }
    expect(await intercept({ source: "model", toolName: "read", input: { path: "ssh://user@example.com/a" } }, { ...context, sandboxPolicy: { network: { allowedHosts: [] } } })).toEqual({ block: true, reason: "network-host-not-granted" });
    expect(await intercept({ source: "model", toolName: "read", input: { path: "ssh://user@example.com/a" } }, { ...context, sandboxPolicy: { network: { allowedHosts: ["example.com"] } } })).toMatchObject({ action: "allow-host-adapter", initialHost: "example.com" });
    expect(await intercept({ source: "model", toolName: "read", input: { path: "vault://secret" } }, context)).toEqual({ block: true, reason: "vault-access-requires-sandbox-disable" });
    expect(await intercept({ source: "model", toolName: "write", input: { path: "conflict://C1", content: "resolution" } }, context)).toEqual({ action: "allow-original-tool", sandboxPolicyApproved: true, ompApproval: "unchanged" });
    expect(await intercept({ source: "model", toolName: "write", input: { path: "vendor://unknown", content: "x" } }, context)).toEqual({ block: true, reason: "unsupported-scheme" });
  });


  test("blocks instead of assuming tool_call can mutate input or replace results", async () => {
    const mod = await loadContract("tools");
    const intercept = requiredExport<InterceptToolCall>(mod, "interceptToolCall");
    expect(await intercept({ source: "model", toolName: "write", input: { path: "/denied/a", content: "x" } }, { enabled: true, sandboxPolicy: { write: [] } })).toEqual({ block: true, reason: "sandbox-policy-denied" });
  });

  test("sandbox_request pre-grants every approved capability and defaults to conversation scope", async () => {
    const mod = await loadContract("tools");
    const request = requiredExport<(input: Record<string, any>, context: Record<string, any>) => Promise<Record<string, any>>>(mod, "sandboxRequest");
    for (const capability of ["read", "write", "internet", "local-network", "allowed-host", "blocked-host", "sensitive-environment-name", "ui", "trusted-tool"]) {
      const value = capability === "internet" || capability === "local-network" ? "allow" : "example";
      expect(await request({ capability, value }, { agentId: "A1", approve: async () => true, applyGrant: async () => undefined })).toMatchObject({ capability, value, scope: "conversation", granted: true });
    }
    expect(await request({ capability: "read", value: "/repo/a", saveTo: "user" }, { agentId: "A1", approve: async () => true, applyGrant: async () => undefined })).toMatchObject({ scope: "user", explicitSave: true });
    expect(await request({ capability: "read", value: "/repo/a", saveTo: "project" }, { agentId: "A1", approve: async () => true, applyGrant: async () => undefined, projectTrusted: true })).toMatchObject({ scope: "project", explicitSave: true });
  });

  test("outside-once requires model flag and positive approval bound to the exact call", async () => {
    const mod = await loadContract("tools");
    const outside = requiredExport<OutsideOnce>(mod, "executeOutsideOnce");
    const displayed: Record<string, unknown>[] = [];
    const hostEnvironment = { PATH: "/bin", API_TOKEN: "secret" };
    const input = { callId: "C1", outsideSandbox: true, command: "tool --arg", cwd: "/repo", agentId: "child", hostEnvironment, timeout: 2.5 };
    let hostInput: Record<string, unknown> | undefined;
    expect(await outside({
      ...input,
      approve: async (details: Record<string, unknown>) => { displayed.push(details); return true; },
      executeHost: async (details: Record<string, unknown>) => { hostInput = details; return { details, exitCode: 0 }; },
    })).toMatchObject({ exitCode: 0 });
    expect(displayed).toEqual([{ callId: "C1", command: "tool --arg", cwd: "/repo", requestingAgent: "child", scope: "exact-call-once" }]);
    expect(hostInput).toMatchObject({ command: "tool --arg", cwd: "/repo", env: hostEnvironment, timeout: 2.5 });
    await expectAsyncFailureCode(() => outside({ ...input, callId: "C2", approve: async () => false }), "OUTSIDE_EXECUTION_DECLINED");
  });

  test("never automatically executes on host after MXC launch failure", async () => {
    const mod = await loadContract("tools");
    const outside = requiredExport<OutsideOnce>(mod, "handleMxcLaunchFailure");
    let hostRuns = 0;
    expect(await outside({ command: "touch /tmp/unsafe", choose: async () => "Cancel", executeHost: async () => { hostRuns += 1; } })).toMatchObject({ cancelled: true });
    expect(hostRuns).toBe(0);
  });

  test("disable confirms and restores normal unsandboxed behavior for the session tree", async () => {
    const mod = await loadContract("commands");
    const disable = requiredExport<DisableSandbox>(mod, "disableSandbox");
    const result = await disable({ sessionTreeId: "T1", confirm: async () => true, restoreHostTools: async () => ({ parity: "exact" }) });
    expect(result).toEqual({ enabled: false, sessionTreeId: "T1", hostBehavior: { parity: "exact" } });
  });
});
