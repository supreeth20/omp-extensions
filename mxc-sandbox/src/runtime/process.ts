import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { delimiter, dirname, join } from "node:path";
import type { ShellLaunch } from "../mxc/config";
import { buildProcessConfig } from "../mxc/config";
import { spawnMxcFromInvocation } from "../mxc/sdk";
import type { MxcSdkAdapter } from "../mxc/sdk";
import { confirmCriticalCommand, executeOutsideOnce } from "../integration/tool-gate";
import { prepareSandboxEnvironment } from "../policy/environment";
import { createLosslessArtifactSink, type LosslessArtifactSink } from "./artifacts";
import { registerMxcJob } from "./jobs";
import { renderMxcOutput } from "./output";
const WINDOWS_DACL_SETUP_GRACE_MS = 30_000;

type UnknownRecord = Record<string, unknown>;
type StreamEvents = { stdout(data: string | Uint8Array): void; stderr(data: string | Uint8Array): void };

type Killable = {
  kill(signal?: string): unknown;
  on?(event: string, listener: (...values: unknown[]) => void): unknown;
  once?(event: string, listener: (...values: unknown[]) => void): unknown;
  stdout?: { on(event: string, listener: (data: unknown) => void): unknown };
  stderr?: { on(event: string, listener: (data: unknown) => void): unknown };
};

export class ExecutionError extends Error {
  readonly code: string;
  readonly autoInstall?: boolean;

  constructor(code: string, message: string, details: UnknownRecord = {}) {
    super(message);
    this.name = "ExecutionError";
    this.code = code;
    if (typeof details.autoInstall === "boolean") this.autoInstall = details.autoInstall;
  }
}

function record(value: unknown): UnknownRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as UnknownRecord : {};
}

function baseName(path: string): string {
  return path.replaceAll("\\", "/").split("/").at(-1)?.toLowerCase() ?? "";
}

function findWindowsExecutable(name: "bash.exe" | "pwsh.exe", discovered: string[], input: UnknownRecord): string | undefined {
  const environment = input.environment && typeof input.environment === "object" && !Array.isArray(input.environment)
    ? input.environment as Record<string, unknown>
    : process.env;
  const supplied = discovered.find((path) => baseName(path) === name);
  const pathCandidates = String(environment.PATH ?? "")
    .split(delimiter)
    .map((directory) => directory.trim().replace(/^"|"$/g, ""))
    .filter(Boolean)
    .map((directory) => join(directory, name));
  const programRoots = [environment.ProgramW6432, environment.ProgramFiles]
    .filter((value): value is string => typeof value === "string" && value.length > 0);
  const fixedCandidates = name === "pwsh.exe"
    ? [
        ...(typeof environment.LOCALAPPDATA === "string" ? [join(environment.LOCALAPPDATA, "Programs", "PowerShell", "7-preview", name)] : []),
        ...(supplied ? [supplied] : []),
        ...pathCandidates,
        ...programRoots.map((root) => join(root, "PowerShell", "7", name)),
      ]
    : [
        ...(supplied ? [supplied] : []),
        ...programRoots.flatMap((root) => [join(root, "Git", "bin", name), join(root, "Git", "usr", "bin", name)]),
        ...(typeof environment.LOCALAPPDATA === "string" ? [join(environment.LOCALAPPDATA, "Programs", "Git", "bin", name)] : []),
      ];
  return fixedCandidates.find(existsSync);
}

export function createContainerId(): string {
  return `mxc-${randomBytes(24).toString("base64url")}`;
}

export function resolveShell(input: UnknownRecord): ShellLaunch & { dialect: "posix" | "powershell7" } {
  const platform = typeof input.platform === "string" ? input.platform : process.platform;
  const requested = input.requested === "powershell" ? "powershell" : "bash";
  const discovered = Array.isArray(input.discovered) ? input.discovered.filter((item): item is string => typeof item === "string") : [];
  if (requested === "powershell") {
    const executable = platform === "win32" ? findWindowsExecutable("pwsh.exe", discovered, input) : undefined;
    if (platform !== "win32" || !executable) {
      throw new ExecutionError("POWERSHELL_7_REQUIRED", "PowerShell 7 (pwsh.exe) is required and is never auto-installed", { autoInstall: false });
    }
    return {
      executable,
      dialect: "powershell7",
      args: ["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-Command"],
      ui: { allowWindows: true, clipboardRead: false, clipboardWrite: false, inputInjection: false },
    };
  }
  if (platform === "win32") {
    const executable = findWindowsExecutable("bash.exe", discovered, input);
    if (!executable) throw new ExecutionError("POSIX_BASH_REQUIRED", "A discovered POSIX-compatible bash.exe, such as Git Bash, is required");
    return { executable, dialect: "posix", args: ["-lc"] };
  }
  const configured = typeof input.configuredShell === "string" ? input.configuredShell : "/bin/bash";
  if (!["bash", "zsh", "sh"].includes(baseName(configured))) {
    throw new ExecutionError("POSIX_BASH_REQUIRED", "The configured Bash tool shell must be POSIX-compatible");
  }
  return { executable: configured, dialect: "posix", args: ["-lc"] };
}

export function buildInvocationConfig(input: UnknownRecord): UnknownRecord {
  return buildProcessConfig(input);
}

function resolvedShell(input: UnknownRecord): ShellLaunch {
  const supplied = record(input.resolvedShell);
  if (typeof supplied.executable === "string" && Array.isArray(supplied.args)) return supplied as unknown as ShellLaunch;
  const shellObject = record(input.shell);
  if (typeof shellObject.executable === "string" && Array.isArray(shellObject.args)) return shellObject as unknown as ShellLaunch;
  return resolveShell({
    platform: input.platform,
    requested: input.shell,
    configuredShell: input.configuredShell,
    discovered: input.discovered,
  });
}

function shellExecutionPolicy(value: unknown, shell: ShellLaunch, platform: string): UnknownRecord {
  const policy = structuredClone(record(value));
  if (platform !== "win32" || shell.dialect !== "powershell7") return policy;
  const filesystem = record(policy.filesystem);
  const read = Array.isArray(filesystem.read) ? [...filesystem.read] : [];
  const runtimeDirectories = [dirname(shell.executable), join(process.env.SystemRoot ?? "C:\\Windows", "System32")];
  const existing = new Set(read.map((entry) => typeof entry === "string" ? entry.toLowerCase() : String(record(entry).path ?? "").toLowerCase()));
  for (const path of runtimeDirectories) {
    if (!existing.has(path.toLowerCase())) read.push({ path, kind: "directory", recursive: true });
  }
  return { ...policy, filesystem: { ...filesystem, read } };
}

function killReturned(processHandle: unknown): void {
  const handle = processHandle as Partial<Killable> | null;
  if (handle && typeof handle.kill === "function") handle.kill("SIGKILL");
}

function attachStream(stream: Killable["stdout"], name: "stdout" | "stderr", events: StreamEvents): void {
  stream?.on("data", (chunk) => events[name](chunk instanceof Uint8Array ? chunk : String(chunk)));
}

async function awaitChildProcess(child: unknown, input: UnknownRecord, events: StreamEvents): Promise<UnknownRecord> {
  if (typeof input.awaitExit === "function") return record(await input.awaitExit(child));
  const immediate = record(child);
  if (typeof immediate.exitCode === "number" || immediate.timedOut === true || immediate.cancelled === true) return immediate;
  if (typeof immediate.onExit === "function") {
    const { promise, resolve } = Promise.withResolvers<UnknownRecord>();
    if (typeof immediate.onData === "function") immediate.onData((data: string) => events.stdout(data));
    immediate.onExit((event: unknown) => {
      const exit = record(event);
      resolve({ exitCode: typeof exit.exitCode === "number" ? exit.exitCode : 0 });
    });
    return promise;
  }
  const handle = child as Partial<Killable> | null;
  if (!handle || (typeof handle.once !== "function" && typeof handle.on !== "function")) return immediate;
  attachStream(handle.stdout, "stdout", events);
  attachStream(handle.stderr, "stderr", events);
  const { promise, resolve, reject } = Promise.withResolvers<UnknownRecord>();
  const subscribe = typeof handle.once === "function" ? handle.once.bind(handle) : handle.on!.bind(handle);
  subscribe("exit", (code: unknown, signal: unknown) => resolve({ exitCode: typeof code === "number" ? code : signal ? 128 : 0 }));
  subscribe("error", (error: unknown) => reject(error));
  return promise;
}

export function createMxcPtyBridge(input: UnknownRecord): UnknownRecord {
  const pty = record(input.pty);
  const overlay = record(input.overlay);
  const writeOverlay = overlay.write;
  const writePty = pty.write;
  const resizePty = pty.resize;
  let closed = false;
  let timer: Timer | undefined;
  const kill = (): void => {
    if (closed) return;
    if (typeof pty.kill === "function") pty.kill();
  };
  if (typeof pty.onData === "function" && typeof writeOverlay === "function") pty.onData((data: string) => writeOverlay(data));
  if (typeof overlay.onInput === "function" && typeof writePty === "function") overlay.onInput((data: string) => writePty(data));
  if (typeof overlay.onResize === "function" && typeof resizePty === "function") {
    overlay.onResize((size: UnknownRecord) => resizePty(Number(size.columns), Number(size.rows)));
  }
  if (typeof overlay.onCancel === "function") overlay.onCancel(kill);
  if (typeof pty.onExit === "function") {
    pty.onExit((event: unknown) => {
      closed = true;
      if (timer) clearTimeout(timer);
      if (typeof overlay.onExit === "function") overlay.onExit(event);
    });
  }
  if (typeof input.timeoutMs === "number" && input.timeoutMs > 0) timer = setTimeout(kill, input.timeoutMs);
  return {
    cancel: kill,
    dispose: () => {
      closed = true;
      if (timer) clearTimeout(timer);
    },
  };
}

function launchFailureDetails(error: unknown): UnknownRecord {
  if (!(error instanceof Error)) return { message: String(error) };
  const value = record(error);
  return {
    name: error.name,
    message: error.message,
    ...(typeof value.code === "string" || typeof value.code === "number" ? { code: value.code } : {}),
    ...(value.details && typeof value.details === "object" ? { details: value.details } : {}),
  };
}

async function chooseLaunchFailure(input: UnknownRecord, error: unknown): Promise<UnknownRecord | "retry"> {
  if (typeof input.chooseFailure !== "function") throw error;
  const choices = ["Retry sandbox", "Run this command outside once", "Disable sandbox for this conversation", "Cancel"];
  const choice = (typeof input.platform === "string" ? input.platform : process.platform) === "win32"
    ? await input.chooseFailure(choices, launchFailureDetails(error))
    : await input.chooseFailure(choices);
  if (choice === "Retry sandbox") return "retry";
  if (choice === "Run this command outside once") {
    const outside = await executeOutsideOnce({
      ...input,
      outsideSandbox: true,
      callId: typeof input.callId === "string" ? input.callId : createContainerId(),
      agentId: input.ownerId,
      approve: input.approveOutsideOnce,
      confirmCritical: input.confirmCritical,
    });
    return { ...outside, outsideSandbox: true, launchFailed: true };
  }
  if (choice === "Disable sandbox for this conversation") {
    if (typeof input.disableSandbox !== "function") throw new ExecutionError("DISABLE_SANDBOX_UNAVAILABLE", "The sandbox cannot be disabled safely");
    await input.disableSandbox();
    return { disabled: true, launchFailed: true };
  }
  if (choice === "Cancel") return { cancelled: true, launchFailed: true };
  throw new ExecutionError("INVALID_FAILURE_CHOICE", "MXC launch failure returned an invalid choice");
}

export function sandboxDenialGuidance(input: UnknownRecord): UnknownRecord | undefined {
  const exitCode = typeof input.exitCode === "number" ? input.exitCode : 0;
  if (exitCode === 0 || input.timedOut === true || input.cancelled === true) return undefined;
  const command = String(input.command ?? "");
  const output = `${String(input.stdout ?? "")}\n${String(input.stderr ?? "")}`;
  const explicitDenial = /operation not permitted|permission denied|access (?:is )?denied|unauthorizedaccess|eacces|eperm/i.test(output);
  const url = command.match(/https?:\/\/[^\s'"`]+/i)?.[0];
  const network = record(record(input.policy).network);
  const networkCommand = /\b(?:curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm)\b/i.test(command);
  const packageInstall = /\b(?:npm|pnpm|yarn)\s+(?:install|add|update)\b|\bbun\s+(?:install|add|update)\b/i.test(command);
  const restrictedNetworkAttempt = network.internet !== true && network.unrestricted !== true && ((Boolean(url) && networkCommand) || packageInstall);
  if (!explicitDenial && !restrictedNetworkAttempt) return undefined;
  let suggestedCapability: UnknownRecord | undefined;
  if (restrictedNetworkAttempt && url) {
    if (record(input.platformCapabilities).allowedHosts === true) {
      try {
        suggestedCapability = { capability: "allowed-host", value: new URL(url).hostname };
      } catch {
        suggestedCapability = { capability: "internet", value: "allow" };
      }
    } else {
      suggestedCapability = { capability: "internet", value: "allow" };
    }
  } else if (restrictedNetworkAttempt) {
    suggestedCapability = { capability: "internet", value: "allow" };
  }
  return {
    denied: true,
    kind: restrictedNetworkAttempt ? "network" : "filesystem-or-network",
    shell: input.shell === "powershell" ? "powershell" : "bash",
    nextTool: "sandbox_request",
    capabilities: ["read", "write", "allowed-host", "internet", "local-network"],
    ...(suggestedCapability ? { suggestedCapability } : {}),
    instruction: "Do not retry the same shell command unchanged. Request the required capability with sandbox_request, then retry bash/powershell after approval.",
  };
}

export async function executeShell(input: UnknownRecord): Promise<UnknownRecord> {
  if (input.outsideSandbox === true) {
    return executeOutsideOnce({
      ...input,
      callId: typeof input.callId === "string" ? input.callId : createContainerId(),
      agentId: input.ownerId,
      approve: input.approveOutsideOnce,
      confirmCritical: input.confirmCritical,
    });
  }
  await confirmCriticalCommand({ shell: input.shell, command: input.command, cwd: input.cwd, confirm: input.confirmCritical });
  const started = Date.now();
  const shell = resolvedShell(input);
  const runtimePlatform = typeof input.platform === "string" ? input.platform : process.platform;
  const executionPolicy = shellExecutionPolicy(input.policy, shell, runtimePlatform);
  const containerId = createContainerId();
  const requestedPty = input.pty === true;
  const hasInteractiveOverlay = input.hasInteractiveOverlay === true;
  const ptySupported = record(input.platformCapabilities).pty !== false;
  const usePty = requestedPty && hasInteractiveOverlay && ptySupported;
  const notices: string[] = requestedPty && !hasInteractiveOverlay
    ? ["PTY requested in a headless context; running in MXC pipe mode."]
    : requestedPty && !ptySupported
      ? ["PTY is unsupported by this MXC backend; running in contained pipe mode."]
      : [];
  const requestedTimeoutMs = typeof input.timeout === "number" && Number.isFinite(input.timeout) && input.timeout > 0
    ? input.timeout * 1000
    : undefined;
  const daclCompatibility = runtimePlatform === "win32"
    && record(record(executionPolicy.mxcOverrides).fallback).allowDaclMutation === true;
  const timeoutMs = requestedTimeoutMs === undefined
    ? undefined
    : requestedTimeoutMs + (daclCompatibility ? WINDOWS_DACL_SETUP_GRACE_MS : 0);
  const readyMarker = runtimePlatform === "win32" && shell.dialect === "powershell7" && requestedTimeoutMs !== undefined
    ? `__OMP_MXC_READY_${containerId}__`
    : undefined;
  if (runtimePlatform === "darwin" && timeoutMs !== undefined && timeoutMs < 500) {
    throw new ExecutionError("MXC_TIMEOUT_BELOW_PLATFORM_MINIMUM", "macOS MXC 0.7 requires a timeout of at least 0.5 seconds");
  }
  const environmentPolicy = record(input.environmentPolicy);
  const hostEnvironment = input.hostEnvironment && typeof input.hostEnvironment === "object" && !Array.isArray(input.hostEnvironment)
    ? input.hostEnvironment
    : process.env;
  const env = await prepareSandboxEnvironment({
    hostEnvironment,
    env: input.env,
    policy: environmentPolicy,
    approveSensitiveNames: input.approveSensitiveNames,
  });
  const config = buildInvocationConfig({
    ...input,
    platform: runtimePlatform,
    shell,
    policy: executionPolicy,
    containerId,
    timeoutMs,
    readyMarker,
    env,
    usePty,
  });
  const stdout: string[] = [];
  const stderr: string[] = [];
  const outputEvents: { sequence: number; stream: "stdout" | "stderr"; data: string | Uint8Array }[] = [];
  let outputSequence = 0;
  let artifactSink: LosslessArtifactSink | undefined;
  let outputClosed = false;
  const sessionManager = record(input.sessionManager);
  if (typeof sessionManager.allocateArtifactPath === "function") artifactSink = await createLosslessArtifactSink(sessionManager, input.shell === "powershell" ? "powershell" : "bash");
  let commandReady = readyMarker === undefined;
  let readyMarkerPending = readyMarker !== undefined;
  let readyMarkerBuffer = "";
  let startRequestedTimeout = (): void => {};
  const markCommandReady = (): void => {
    if (commandReady) return;
    commandReady = true;
    startRequestedTimeout();
  };
  const appendOutput = (stream: "stdout" | "stderr", text: string): void => {
    if (text.length === 0 || outputClosed) return;
    outputEvents.push({ sequence: ++outputSequence, stream, data: text });
    (stream === "stdout" ? stdout : stderr).push(text);
    artifactSink?.write(new TextEncoder().encode(text));
    if (typeof input.onUpdate === "function") input.onUpdate({ stream, data: text });
  };
  const pushOutput = (stream: "stdout" | "stderr", data: string | Uint8Array): void => {
    if (outputClosed) return;
    const text = typeof data === "string" ? data : new TextDecoder().decode(data);
    if (stream === "stdout") markCommandReady();
    if (stream === "stderr" && readyMarkerPending && readyMarker) {
      readyMarkerBuffer += text;
      const markerIndex = readyMarkerBuffer.indexOf(readyMarker);
      if (markerIndex < 0) return;
      const before = readyMarkerBuffer.slice(0, markerIndex).replace(/^DACL recovery:.*(?:\r?\n|$)/gm, "");
      const after = readyMarkerBuffer.slice(markerIndex + readyMarker.length).replace(/^\r?\n/, "");
      readyMarkerBuffer = "";
      readyMarkerPending = false;
      markCommandReady();
      appendOutput("stderr", `${before}${after}`);
      return;
    }
    appendOutput(stream, text);
  };
  const streamEvents: StreamEvents = {
    stdout: (data) => pushOutput("stdout", data),
    stderr: (data) => pushOutput("stderr", data),
  };

  let spawned: unknown;
  for (;;) {
    try {
      if (usePty) {
        spawned = typeof input.spawnMxcPty === "function"
          ? await input.spawnMxcPty(config, streamEvents)
          : await spawnMxcFromInvocation(config, { usePty: true }, input.mxcAdapter as MxcSdkAdapter | undefined);
      } else {
        spawned = typeof input.spawn === "function"
          ? await input.spawn(config, streamEvents)
          : await spawnMxcFromInvocation(config, { usePty: false }, input.mxcAdapter as MxcSdkAdapter | undefined);
      }
      break;
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "UNSUPPORTED_NONRECURSIVE_DIRECTORY") throw error;
      const decision = await chooseLaunchFailure(input, error);
      if (decision === "retry") continue;
      outputClosed = true;
      await artifactSink?.close();
      return { ...decision, notices };
    }
  }

  if (usePty && record(spawned).onData && input.overlay) createMxcPtyBridge({ pty: spawned, overlay: input.overlay, timeoutMs });
  const abortSignal = input.signal instanceof AbortSignal ? input.signal : undefined;
  let cancelled = abortSignal?.aborted === true;
  let timedOut = false;
  let exitPromise: Promise<UnknownRecord> | undefined;
  const forcedExit = Promise.withResolvers<UnknownRecord>();
  const childExit = (): Promise<UnknownRecord> => exitPromise ??= awaitChildProcess(spawned, input, streamEvents);
  let terminationRequested = false;
  const cancel = (): void => {
    if (terminationRequested) return;
    terminationRequested = true;
    cancelled = true;
    killReturned(spawned);
    forcedExit.resolve({ exitCode: 130, cancelled: true });
  };
  abortSignal?.addEventListener("abort", cancel, { once: true });
  if (cancelled) {
    terminationRequested = false;
    cancel();
  }
  const scheduleTimeout = typeof input.scheduleTimeout === "function"
    ? input.scheduleTimeout as (callback: () => void, milliseconds: number) => number | Timer
    : setTimeout;
  let timeoutTimer: number | Timer | undefined;
  startRequestedTimeout = (): void => {
    if (requestedTimeoutMs === undefined || timeoutTimer !== undefined) return;
    timeoutTimer = scheduleTimeout(() => {
      timedOut = true;
      killReturned(spawned);
      forcedExit.resolve({ exitCode: 137, timedOut: true });
    }, requestedTimeoutMs);
  };
  if (commandReady) startRequestedTimeout();

  let finalized = false;
  const finalize = async (result: UnknownRecord): Promise<UnknownRecord> => {
    if (finalized) return result;
    finalized = true;
    abortSignal?.removeEventListener("abort", cancel);
    if (timeoutTimer) clearTimeout(timeoutTimer);
    if (result.timedOut === true || result.cancelled === true || cancelled || timedOut) killReturned(spawned);
    if (outputEvents.length === 0) {
      if (typeof result.stdout === "string" && result.stdout.length > 0) pushOutput("stdout", result.stdout);
      if (typeof result.stderr === "string" && result.stderr.length > 0) pushOutput("stderr", result.stderr);
    }
    if (readyMarkerPending && readyMarkerBuffer.length > 0) {
      readyMarkerPending = false;
      appendOutput("stderr", readyMarkerBuffer);
      readyMarkerBuffer = "";
    }
    outputClosed = true;
    await artifactSink?.close();
    const wallTimeMs = typeof result.wallTimeMs === "number" ? result.wallTimeMs : Date.now() - started;
    const rendered = await renderMxcOutput({
      events: outputEvents,
      exitCode: result.exitCode,
      timedOut: result.timedOut === true || timedOut,
      cancelled: result.cancelled === true || cancelled,
      wallTimeMs,
      maxColumns: input.maxColumns,
      maxLines: input.maxLines,
      ...(artifactSink ? { artifact: `artifact://${artifactSink.allocation.id}` } : {}),
    });
    const denial = sandboxDenialGuidance({
      shell: input.shell,
      command: input.command,
      policy: input.policy,
      platformCapabilities: input.platformCapabilities,
      exitCode: result.exitCode,
      timedOut: result.timedOut === true || timedOut,
      cancelled: result.cancelled === true || cancelled,
      stdout: typeof result.stdout === "string" ? result.stdout : stdout.join(""),
      stderr: typeof result.stderr === "string" ? result.stderr : stderr.join(""),
    });
    if (denial) {
      const guidance = String(denial.instruction);
      rendered.preview = `${String(rendered.preview ?? "")}\n\nMXC sandbox access denied. ${guidance}`.trim();
      rendered.details = { ...record(rendered.details), sandboxDenial: denial };
      notices.push(guidance);
    }
    const finalResult = {
      ...result,
      ...rendered,
      wallTimeMs,
      stdout: stdout.join(""),
      stderr: stderr.join(""),
      containerId,
      notices,
      ...(requestedTimeoutMs === undefined ? {} : { timeoutSeconds: requestedTimeoutMs / 1000 }),
    };
    if (typeof input.renderer === "function") {
      await input.renderer({ content: [{ type: "text", text: String(rendered.preview ?? "") }], details: finalResult });
    }
    return finalResult;
  };
  const completion = Promise.race([childExit(), forcedExit.promise])
    .then(finalize, async (error) => {
      abortSignal?.removeEventListener("abort", cancel);
      if (timeoutTimer) clearTimeout(timeoutTimer);
      outputClosed = true;
      await artifactSink?.close();
      throw error;
    });
  const background = async (): Promise<UnknownRecord> => {
    const handle = spawned as Partial<Killable> | null;
    const ownedProcess: UnknownRecord = {
      ...record(spawned),
      process: spawned,
      completion,
      cancel,
      kill: (signal?: string) => {
        cancelled = true;
        const result = handle && typeof handle.kill === "function" ? handle.kill(signal) : undefined;
        forcedExit.resolve({ exitCode: 130, cancelled: true });
        return result;
      },
      ...(handle?.stdout ? { stdout: handle.stdout } : {}),
      ...(handle?.stderr ? { stderr: handle.stderr } : {}),
      ...(typeof handle?.on === "function" ? { on: handle.on.bind(handle) } : {}),
      ...(typeof handle?.once === "function" ? { once: handle.once.bind(handle) } : {}),
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
      ...(artifactSink ? { artifactSink, artifact: `artifact://${artifactSink.allocation.id}` } : {}),
    };
    try {
      const job = await registerMxcJob({
        tool: input.shell,
        sessionId: input.sessionId,
        agentId: input.ownerId,
        scopedManager: input.scopedManager,
        liveMatches: input.liveMatches,
        process: ownedProcess,
      });
      return { backgrounded: true, jobId: job.id, containerId, notices, ...(artifactSink ? { artifact: `artifact://${artifactSink.allocation.id}` } : {}) };
    } catch (error) {
      cancel();
      outputClosed = true;
      await artifactSink?.close();
      throw error;
    }
  };
  const shouldBackground = input.async === true
    || (typeof input.autoBackgroundThresholdMs === "number"
      && typeof input.elapsedMs === "number"
      && input.elapsedMs >= input.autoBackgroundThresholdMs);
  if (shouldBackground) return background();

  if (typeof input.autoBackgroundThresholdMs === "number" && input.autoBackgroundThresholdMs > 0 && input.elapsedMs === undefined) {
    const threshold = Promise.withResolvers<{ kind: "threshold" }>();
    const thresholdTimer: Timer = setTimeout(() => threshold.resolve({ kind: "threshold" }), input.autoBackgroundThresholdMs);
    const first = await Promise.race([
      completion.then((result) => ({ kind: "exit" as const, result })),
      threshold.promise,
    ]);
    clearTimeout(thresholdTimer);
    if (first.kind === "threshold") return background();
    return first.result;
  }

  return completion;
}
