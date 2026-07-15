import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { executeShell } from "../../src/runtime/process";
import { registerMxcJob } from "../../src/runtime/jobs";
import { renderMxcOutput } from "../../src/runtime/output";
import { loadMxcSdk, spawnMxcFromInvocation } from "../../src/mxc/sdk";

type UnknownRecord = Record<string, unknown>;
type Killable = { pid?: number; kill(signal?: string): unknown };
type ProcessRecord = {
  id: string;
  ownerId: string;
  tool: string;
  process: UnknownRecord;
  progress: string[];
  state: "running" | "completed" | "cancelled" | "failed";
  completion?: UnknownRecord;
  completionDelivered: boolean;
};

type CaseContext = {
  root: string;
  sentinelRoot: string;
  sentinel: string;
};

type Execution = {
  result: UnknownRecord;
  handle: Killable;
  nativeProcessId: number;
};

const NOTICE = "PTY requested in a headless context; running in MXC pipe mode.";
const UNSUPPORTED_PTY_NOTICE = "PTY is unsupported by this MXC backend; running in contained pipe mode.";
const CONTAINED_MARKER = "__MXC_CONTAINED__";
const ESCAPED_MARKER = "__MXC_ESCAPED__";
const activeProcesses = new Set<Killable>();
let readonlyPathsPromise: Promise<string[]> | undefined;

function record(value: unknown): UnknownRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as UnknownRecord : {};
}

function quote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function integer(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : fallback;
}

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

async function readonlyPaths(): Promise<string[]> {
  readonlyPathsPromise ??= (async () => {
    const sdk = await loadMxcSdk();
    return [...new Set([
      ...sdk.discoverRequiredReadonlyPaths(),
      "/bin",
      "/usr/bin",
      "/usr/lib",
      "/System/Library",
      dirname(process.execPath),
    ])];
  })();
  return readonlyPathsPromise;
}

async function createContext(label: string): Promise<CaseContext> {
  const root = await mkdtemp(join(tmpdir(), `omp-mxc-${label}-`));
  const sentinelRoot = await mkdtemp(join(tmpdir(), "omp-mxc-host-sentinel-"));
  const sentinel = join(sentinelRoot, "host-only");
  await writeFile(sentinel, "this must not be visible inside Seatbelt\n", { mode: 0o600 });
  return { root, sentinelRoot, sentinel };
}

async function cleanupContext(context: CaseContext): Promise<void> {
  await Promise.all([
    rm(context.root, { recursive: true, force: true }),
    rm(context.sentinelRoot, { recursive: true, force: true }),
  ]);
}

function sentinelProbe(context: CaseContext): string {
  return `if /bin/cat ${quote(context.sentinel)} >/dev/null 2>&1; then printf '${ESCAPED_MARKER}\\n'; else printf '${CONTAINED_MARKER}\\n'; fi`;
}

async function shellInput(context: CaseContext, command: string): Promise<UnknownRecord> {
  const reads = (await readonlyPaths()).map((path) => ({ path, kind: "directory", recursive: true }));
  return {
    shell: "bash",
    configuredShell: "/bin/bash",
    platform: "darwin",
    command,
    cwd: context.root,
    env: {},
    hostEnvironment: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      LANG: process.env.LANG ?? "C.UTF-8",
    },
    environmentPolicy: { approvedSensitiveNames: [] },
    policy: {
      filesystem: {
        read: reads,
        write: [{ path: context.root, kind: "directory", recursive: true }],
        deny: [{ path: context.sentinel, kind: "file", recursive: false }],
      },
      network: { internet: false, localNetwork: false },
      ui: { allowWindows: false, clipboardRead: false, clipboardWrite: false, inputInjection: false },
    },
    platformCapabilities: {},
  };
}

function captureHandle(value: unknown): Killable {
  const candidate = value as Killable | null;
  if (!candidate || typeof candidate.kill !== "function" || !Number.isInteger(candidate.pid) || Number(candidate.pid) <= 0) {
    throw new Error("MXC did not return a genuine killable native process handle");
  }
  activeProcesses.add(candidate);
  return candidate;
}

function releaseHandle(handle: Killable): void {
  activeProcesses.delete(handle);
}

async function executePipe(context: CaseContext, command: string, extra: UnknownRecord = {}): Promise<Execution> {
  let handle: Killable | undefined;
  const observeConfig = typeof extra.observeConfig === "function" ? extra.observeConfig as (config: UnknownRecord) => void : undefined;
  const { observeConfig: _observeConfig, ...executionInput } = extra;
  try {
    const result = await executeShell({
      ...await shellInput(context, command),
      ...executionInput,
      spawn: async (config: UnknownRecord) => {
        observeConfig?.(config);
        const spawned = captureHandle(await spawnMxcFromInvocation(config, { usePty: false }));
        handle = spawned;
        return spawned;
      },
    });
    if (!handle) throw new Error("The production shell path did not spawn MXC");
    releaseHandle(handle);
    return { result, handle, nativeProcessId: handle.pid! };
  } catch (error) {
    if (handle && activeProcesses.delete(handle)) handle.kill("SIGKILL");
    throw error;
  }
}

function observedContainment(execution: Execution): UnknownRecord {
  const output = `${text(execution.result.stdout)}${text(execution.result.stderr)}${text(execution.result.preview)}`;
  if (!output.includes(CONTAINED_MARKER) || output.includes(ESCAPED_MARKER)) {
    throw new Error(`The Seatbelt child did not produce denied-host-sentinel containment evidence: ${output.slice(0, 500)}`);
  }
  const containerId = execution.result.containerId;
  if (typeof containerId !== "string" || !containerId.startsWith("mxc-")) {
    throw new Error("The production execution path did not return an MXC container ID");
  }
  return {
    backend: "seatbelt",
    realMxc: true,
    escapedToHost: false,
    nativeProcessId: execution.nativeProcessId,
    containerId,
  };
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return record(error).code !== "ESRCH";
  }
}

async function waitFor(predicate: () => boolean | Promise<boolean>, timeoutMs = 5_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return true;
    await Bun.sleep(20);
  }
  return await predicate();
}

async function readPid(path: string): Promise<number> {
  const found = await waitFor(async () => {
    try {
      return /^\d+\s*$/.test(await readFile(path, "utf8"));
    } catch {
      return false;
    }
  });
  if (!found) throw new Error(`Contained process did not write PID evidence at ${path}`);
  const pid = Number.parseInt(await readFile(path, "utf8"), 10);
  if (!Number.isInteger(pid) || pid <= 0) throw new Error("Contained process wrote invalid PID evidence");
  return pid;
}

async function waitDead(...pids: number[]): Promise<boolean> {
  return await waitFor(() => pids.every((pid) => !processAlive(pid)), 5_000);
}

class ScopedJobManager {
  readonly sessionId: string;
  readonly ownerId: string;
  readonly jobs = new Map<string, ProcessRecord>();
  #nextId = 1;

  constructor(sessionId: string, ownerId: string) {
    this.sessionId = sessionId;
    this.ownerId = ownerId;
  }

  register(tool: string, processValue: unknown, options: { ownerId: string }): UnknownRecord {
    if (options.ownerId !== this.ownerId) throw new Error("Owner mismatch at scoped job registration");
    const processRecord = record(processValue);
    if (!(processRecord.completion instanceof Promise) || typeof processRecord.cancel !== "function") {
      throw new Error("A scoped job must own a real completion and cancellation surface");
    }
    const id = `mxc-job-${this.#nextId++}`;
    const job: ProcessRecord = {
      id,
      ownerId: options.ownerId,
      tool,
      process: processRecord,
      progress: [],
      state: "running",
      completionDelivered: false,
    };
    this.jobs.set(id, job);
    processRecord.completion.then(
      (value) => {
        job.completion = record(value);
        job.state = job.completion.cancelled === true ? "cancelled" : "completed";
      },
      (error) => {
        job.completion = { error: String(error) };
        job.state = "failed";
      },
    );
    return { id };
  }

  list(ownerId: string): UnknownRecord[] {
    return [...this.jobs.values()]
      .filter((job) => job.ownerId === ownerId)
      .map((job) => ({ id: job.id, ownerId: job.ownerId, tool: job.tool, state: job.state, progress: [...job.progress] }));
  }

  poll(id: string, ownerId: string): UnknownRecord | undefined {
    const job = this.jobs.get(id);
    if (!job || job.ownerId !== ownerId) return undefined;
    return { id, state: job.state, progress: [...job.progress], completion: job.completion };
  }

  cancel(id: string, ownerId: string): boolean {
    const job = this.jobs.get(id);
    if (!job || job.ownerId !== ownerId || job.state !== "running") return false;
    (job.process.cancel as () => void)();
    return true;
  }

  async deliverCompletion(id: string, ownerId: string): Promise<UnknownRecord | undefined> {
    const job = this.jobs.get(id);
    if (!job || job.ownerId !== ownerId) return undefined;
    const completion = record(await job.process.completion);
    job.completion = completion;
    job.state = completion.cancelled === true ? "cancelled" : "completed";
    job.completionDelivered = true;
    return completion;
  }

  progress(ownerId: string, value: string): void {
    const jobs = [...this.jobs.values()];
    for (let index = jobs.length - 1; index >= 0; index -= 1) {
      const job = jobs[index]!;
      if (job.ownerId === ownerId && job.state === "running") {
        job.progress.push(value);
        return;
      }
    }
  }
}

async function runPtyRoundtrip(_input: UnknownRecord): Promise<UnknownRecord> {
  const context = await createContext("pty-fallback");
  try {
    let observedUsePty: unknown;
    let clientTerminalRuns = 0;
    const execution = await executePipe(context, `${sentinelProbe(context)}; printf 'PIPE-FALLBACK\\n'`, {
      pty: true,
      hasInteractiveOverlay: true,
      platformCapabilities: { pty: false },
      runClientTerminal: () => { clientTerminalRuns += 1; },
      observeConfig: (config: UnknownRecord) => {
        observedUsePty = record(config.process).usePty;
      },
    });
    const notices = Array.isArray(execution.result.notices) ? execution.result.notices : [];
    return {
      containment: observedContainment(execution),
      assertions: {
        pipeFallback: observedUsePty === false && notices.includes(UNSUPPORTED_PTY_NOTICE),
        outputObserved: text(execution.result.stdout).includes("PIPE-FALLBACK"),
        clientTerminalUsed: clientTerminalRuns !== 0,
      },
    };
  } finally {
    await cleanupContext(context);
  }
}

async function runHeadlessPty(): Promise<UnknownRecord> {
  const context = await createContext("headless-pty");
  try {
    let observedUsePty: unknown;
    const execution = await executePipe(context, `${sentinelProbe(context)}; /usr/bin/tty || true`, {
      pty: true,
      hasInteractiveOverlay: false,
      observeConfig: (config: UnknownRecord) => {
        observedUsePty = record(config.process).usePty;
      },
    });
    const notices = Array.isArray(execution.result.notices) ? execution.result.notices : [];
    if (observedUsePty !== false || !notices.includes(NOTICE)) throw new Error("Headless PTY did not use production pipe fallback");
    return { containment: observedContainment(execution), usePty: false, notice: NOTICE };
  } finally {
    await cleanupContext(context);
  }
}

async function runAsyncJob(input: UnknownRecord): Promise<UnknownRecord> {
  const context = await createContext("async-job");
  const ownerId = typeof input.ownerId === "string" ? input.ownerId : "e2e-owner";
  const sessionId = "mxc-e2e-process-session";
  const manager = new ScopedJobManager(sessionId, ownerId);
  const controller = new AbortController();
  let handle: Killable | undefined;
  let jobId = "";
  const pendingProgress: string[] = [];
  try {
    const childPidPath = join(context.root, "async-child.pid");
    const command = `${sentinelProbe(context)}; printf '%s' "$$" > ${quote(childPidPath)}; printf 'PROGRESS:started\\n'; while :; do /bin/sleep 1; done`;
    const completion = executeShell({
      ...await shellInput(context, command),
      signal: controller.signal,
      onUpdate: (update: UnknownRecord) => {
        const data = text(update.data);
        if (!data.includes("PROGRESS:")) return;
        if (jobId) manager.progress(ownerId, data.trim());
        else pendingProgress.push(data.trim());
      },
      spawn: async (config: UnknownRecord) => {
        handle = captureHandle(await spawnMxcFromInvocation(config, { usePty: false }));
        return handle;
      },
    });
    if (!await waitFor(() => Boolean(handle))) throw new Error("Async MXC process did not start");
    const ownedProcess = { pid: handle!.pid, process: handle, completion, cancel: () => controller.abort("e2e cancellation"), kill: (signal?: string) => handle!.kill(signal) };
    const liveMatches = [{ sessionId, agentId: ownerId, scopedManager: manager, live: true }];
    const job = await registerMxcJob({ tool: "bash", sessionId, agentId: ownerId, scopedManager: manager, liveMatches, process: ownedProcess });
    jobId = String(job.id);
    for (const progress of pendingProgress) manager.progress(ownerId, progress);
    if (!await waitFor(() => manager.poll(jobId, ownerId)?.progress instanceof Array && (manager.poll(jobId, ownerId)!.progress as unknown[]).length > 0)) {
      throw new Error("Async job emitted no observable progress");
    }
    const listedForOwner = record(job).list instanceof Function && (job.list as () => UnknownRecord[])().some((item) => item.id === jobId);
    const hiddenFromOtherOwner = manager.list("different-owner").every((item) => item.id !== jobId);
    const polled = (job.poll as () => UnknownRecord | undefined)();
    const pollWorked = Array.isArray(record(polled).progress) && (record(polled).progress as unknown[]).length > 0;
    const childPid = await readPid(childPidPath);
    const cancelWorked = (job.cancel as () => unknown)() === true;
    const completed = record(await (job.deliverCompletion as () => Promise<unknown>)());
    const processTreeDead = await waitDead(handle!.pid!, childPid);
    releaseHandle(handle!);
    const execution: Execution = { result: completed, handle: handle!, nativeProcessId: handle!.pid! };
    return {
      containment: observedContainment(execution),
      assertions: {
        listedForOwner,
        hiddenFromOtherOwner,
        pollWorked,
        progressDelivered: (manager.jobs.get(jobId)?.progress.length ?? 0) > 0,
        cancelWorked,
        completionDelivered: manager.jobs.get(jobId)?.completionDelivered === true && completed.cancelled === true,
        processTreeDead,
      },
    };
  } finally {
    if (handle && activeProcesses.delete(handle)) handle.kill("SIGKILL");
    await cleanupContext(context);
  }
}

async function runAutoBackground(input: UnknownRecord): Promise<UnknownRecord> {
  const context = await createContext("auto-background");
  const thresholdMs = integer(input.thresholdMs, 50);
  const ownerId = "auto-background-owner";
  const sessionId = "auto-background-session";
  const manager = new ScopedJobManager(sessionId, ownerId);
  let handle: Killable | undefined;
  try {
    const started = Date.now();
    const result = await executeShell({
      ...await shellInput(context, `${sentinelProbe(context)}; printf 'BACKGROUND-STARTED\\n'; /bin/sleep 30`),
      autoBackgroundThresholdMs: thresholdMs,
      ownerId,
      sessionId,
      scopedManager: manager,
      liveMatches: [{ sessionId, agentId: ownerId, scopedManager: manager, live: true }],
      spawn: async (config: UnknownRecord) => {
        handle = captureHandle(await spawnMxcFromInvocation(config, { usePty: false }));
        return handle;
      },
    });
    const elapsed = Date.now() - started;
    const jobId = String(result.jobId);
    const jobVisible = manager.list(ownerId).some((item) => item.id === jobId);
    const jobRecord = manager.jobs.get(jobId);
    if (!jobRecord) throw new Error("Threshold transition did not register a scoped job");
    manager.cancel(jobId, ownerId);
    const completion = record(await jobRecord.process.completion);
    if (!handle) throw new Error("Auto-background execution did not return a native handle");
    const execution: Execution = { result: completion, handle, nativeProcessId: handle.pid! };
    observedContainment(execution);
    await waitDead(handle.pid!);
    releaseHandle(handle);
    return {
      containment: observedContainment(execution),
      backgrounded: result.backgrounded === true,
      thresholdPreserved: elapsed >= thresholdMs && elapsed < thresholdMs + 2_000,
      jobVisible,
    };
  } finally {
    if (handle && activeProcesses.delete(handle)) handle.kill("SIGKILL");
    await cleanupContext(context);
  }
}

async function runTimeoutCancel(): Promise<UnknownRecord> {
  const timeoutContext = await createContext("timeout");
  const cancelContext = await createContext("cancel");
  let timeoutHandle: Killable | undefined;
  let cancelHandle: Killable | undefined;
  try {
    const childPath = join(timeoutContext.root, "child.pid");
    const descendantPath = join(timeoutContext.root, "descendant.pid");
    const timeoutCommand = `${sentinelProbe(timeoutContext)}; printf '%s' "$$" > ${quote(childPath)}; /bin/sleep 30 & printf '%s' "$!" > ${quote(descendantPath)}; wait`;
    const timeoutPromise = executeShell({
      ...await shellInput(timeoutContext, timeoutCommand),
      timeout: 1.5,
      spawn: async (config: UnknownRecord) => {
        timeoutHandle = captureHandle(await spawnMxcFromInvocation(config, { usePty: false }));
        return timeoutHandle;
      },
    });
    const [childPid, descendantPid] = await Promise.all([readPid(childPath), readPid(descendantPath)]);
    const timeoutResult = await timeoutPromise;
    if (!timeoutHandle) throw new Error("Timed execution did not return a native handle");
    releaseHandle(timeoutHandle);

    const ownerId = "timeout-cancel-owner";
    const sessionId = "timeout-cancel-session";
    const manager = new ScopedJobManager(sessionId, ownerId);
    const controller = new AbortController();
    const cancelChildPath = join(cancelContext.root, "cancel-child.pid");
    const cancellation = executeShell({
      ...await shellInput(cancelContext, `${sentinelProbe(cancelContext)}; printf '%s' "$$" > ${quote(cancelChildPath)}; /bin/sleep 30`),
      signal: controller.signal,
      spawn: async (config: UnknownRecord) => {
        cancelHandle = captureHandle(await spawnMxcFromInvocation(config, { usePty: false }));
        return cancelHandle;
      },
    });
    if (!await waitFor(() => Boolean(cancelHandle))) throw new Error("Cancellation execution did not start");
    const owned = { pid: cancelHandle!.pid, completion: cancellation, cancel: () => controller.abort("e2e cancellation"), kill: (signal?: string) => cancelHandle!.kill(signal) };
    const liveMatches = [{ sessionId, agentId: ownerId, scopedManager: manager, live: true }];
    const job = await registerMxcJob({ tool: "bash", sessionId, agentId: ownerId, scopedManager: manager, liveMatches, process: owned });
    const cancelChildPid = await readPid(cancelChildPath);
    const ownerMappedBefore = manager.list(ownerId).some((item) => item.id === job.id);
    (job.cancel as () => unknown)();
    const cancelResult = record(await owned.completion);
    const ownerMappedAfter = manager.poll(String(job.id), ownerId) !== undefined;
    const cancellationDead = await waitDead(cancelHandle!.pid!, cancelChildPid);
    releaseHandle(cancelHandle!);

    const childProcessDead = await waitDead(timeoutHandle.pid!, childPid);
    const descendantProcessDead = await waitDead(descendantPid) && cancellationDead;
    const execution: Execution = { result: timeoutResult, handle: timeoutHandle, nativeProcessId: timeoutHandle.pid! };
    return {
      containment: observedContainment(execution),
      assertions: {
        timeoutReported: record(timeoutResult.details).timedOut === true,
        cancellationReported: record(cancelResult.details).cancelled === true,
        childProcessDead,
        descendantProcessDead,
        ownerStillMapped: ownerMappedBefore && ownerMappedAfter,
      },
    };
  } finally {
    for (const handle of [timeoutHandle, cancelHandle]) {
      if (handle && activeProcesses.delete(handle)) handle.kill("SIGKILL");
    }
    await Promise.all([cleanupContext(timeoutContext), cleanupContext(cancelContext)]);
  }
}

async function runOutputArtifact(input: UnknownRecord): Promise<UnknownRecord> {
  const context = await createContext("output-artifact");
  const bytes = integer(input.bytes, 262_144);
  const columns = integer(input.columns, 80);
  const lines = integer(input.lines, 100);
  const artifactPath = join(context.root, "full-output.bin");
  let rendered: UnknownRecord | undefined;
  try {
    await mkdir(dirname(artifactPath), { recursive: true });
    const execution = await executePipe(
      context,
      `${sentinelProbe(context)}; /usr/bin/yes x | /usr/bin/head -c ${bytes}`,
      {
        maxColumns: columns,
        maxLines: lines,
        sessionManager: { allocateArtifactPath: async () => ({ id: "mxc-process-output", path: artifactPath }) },
        renderer: (value: UnknownRecord) => { rendered = structuredClone(value); },
      },
    );
    const artifact = new Uint8Array(await readFile(artifactPath));
    const raw = new TextEncoder().encode(text(execution.result.stdout));
    const directRender = await renderMxcOutput({ rawChunks: [raw], maxColumns: columns, maxLines: lines });
    const preview = text(execution.result.preview);
    const previewLines = preview.split("\n");
    const previewWithinLimits = previewLines.length <= lines && previewLines.every((line) => line.length <= columns);
    const rendererDetails = record(rendered?.details);
    const rendererContent = Array.isArray(rendered?.content) ? text(record(rendered.content[0]).text) : "";
    const rendererMatched = rendererContent === execution.result.preview
      && rendererDetails.preview === execution.result.preview
      && rendererDetails.truncated === execution.result.truncated
      && directRender.preview === execution.result.preview;
    return {
      containment: observedContainment(execution),
      truncated: execution.result.truncated === true,
      artifactScheme: text(execution.result.artifact).split(":", 1)[0],
      previewWithinLimits,
      rendererMatched,
      rawSha256: sha256(raw),
      artifactSha256: sha256(artifact),
      rawBytes: raw.byteLength,
      artifactBytes: artifact.byteLength,
    };
  } finally {
    await cleanupContext(context);
  }
}

async function runParallelContainerIds(input: UnknownRecord): Promise<UnknownRecord> {
  const count = integer(input.count, 32);
  const contexts = await Promise.all(Array.from({ length: count }, (_, index) => createContext(`parallel-${index}`)));
  try {
    const executions = await Promise.all(contexts.map(async (context, index) => await executePipe(
      context,
      `${sentinelProbe(context)}; printf 'PARALLEL:${index}:%s\\n' "$$"`,
    )));
    return {
      ids: executions.map((execution) => execution.result.containerId),
      containments: executions.map(observedContainment),
      containment: observedContainment(executions[0]!),
    };
  } finally {
    await Promise.all(contexts.map(cleanupContext));
    for (const handle of activeProcesses) handle.kill("SIGKILL");
    activeProcesses.clear();
  }
}

export async function runProcessCase(caseName: string, input: UnknownRecord): Promise<UnknownRecord | null> {
  switch (caseName) {
    case "pty-roundtrip": return await runPtyRoundtrip(input);
    case "headless-pty": return await runHeadlessPty();
    case "async-job": return await runAsyncJob(input);
    case "auto-background": return await runAutoBackground(input);
    case "timeout-cancel": return await runTimeoutCancel();
    case "output-artifact": return await runOutputArtifact(input);
    case "parallel-container-ids": return await runParallelContainerIds(input);
    default: return null;
  }
}
