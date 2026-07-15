import { randomUUID } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { createEffectivePolicy } from "../../src/mxc/config";
import { probeIndependentLocalNetworkSeparation } from "../../src/mxc/probe";
import { loadMxcSdk, spawnMxcFromInvocation, spawnMxcTrafficProbeFromInvocation, type MxcSdkAdapter } from "../../src/mxc/sdk";
import { resolveNetworkPolicy } from "../../src/policy/network";
import { createContainerId, executeShell } from "../../src/runtime/process";

type UnknownRecord = Record<string, unknown>;
type NativeChild = {
  pid?: number;
  kill(signal?: string): unknown;
  once(event: "exit" | "error", listener: (...values: unknown[]) => void): unknown;
  stdout?: { on(event: "data", listener: (chunk: unknown) => void): unknown };
  stderr?: { on(event: "data", listener: (chunk: unknown) => void): unknown };
};
type NativeEvidence = {
  containerId: string;
  nativeProcessId: number;
  escapeDenied: boolean;
};
type ChildResult = {
  exitCode: number;
  timedOut: boolean;
  stdout: string;
  stderr: string;
};

const seenContainerIds = new Set<string>();

function record(value: unknown): UnknownRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as UnknownRecord : {};
}

function nativeChild(value: unknown): NativeChild {
  const child = value as Partial<NativeChild> | null;
  if (!child || typeof child.kill !== "function" || typeof child.once !== "function" || !Number.isInteger(child.pid)) {
    throw Object.assign(new Error("MXC did not return a native ChildProcess with a process id"), { code: "MXC_NATIVE_CHILD_REQUIRED" });
  }
  return child as NativeChild;
}

async function waitForChild(child: NativeChild, timeoutMs: number): Promise<ChildResult> {
  const stdout: string[] = [];
  const stderr: string[] = [];
  child.stdout?.on("data", (chunk) => stdout.push(String(chunk)));
  child.stderr?.on("data", (chunk) => stderr.push(String(chunk)));
  const completion = Promise.withResolvers<number>();
  child.once("exit", (code) => completion.resolve(typeof code === "number" ? code : -1));
  child.once("error", completion.reject);
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, timeoutMs);
  try {
    return { exitCode: await completion.promise, timedOut, stdout: stdout.join(""), stderr: stderr.join("") };
  } finally {
    clearTimeout(timer);
  }
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function privateIpv4Address(): string | undefined {
  for (const addresses of Object.values(networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (address.family !== "IPv4" || address.internal) continue;
      const octets = address.address.split(".").map(Number);
      const first = octets[0];
      const second = octets[1];
      if (first === 10 || (first === 172 && second !== undefined && second >= 16 && second <= 31) || (first === 192 && second === 168)) return address.address;
    }
  }
  return undefined;
}

function runtimeReadGrants(adapter: MxcSdkAdapter, extraDirectories: string[]): UnknownRecord[] {
  return [...new Set([...adapter.discoverRequiredReadonlyPaths(), dirname(process.execPath), "/bin", ...extraDirectories])]
    .map((path) => ({ path, kind: "directory", recursive: true }));
}

function containment(evidence: NativeEvidence): UnknownRecord {
  return {
    backend: "seatbelt",
    realMxc: true,
    escapedToHost: !evidence.escapeDenied,
    nativeProcessId: evidence.nativeProcessId,
    containerId: evidence.containerId,
  };
}

async function executeContainedShell(input: UnknownRecord, adapter: MxcSdkAdapter): Promise<{
  result: UnknownRecord;
  evidence: NativeEvidence;
  spawnCount: number;
  invocation?: UnknownRecord;
}> {
  let spawnCount = 0;
  let invocation: UnknownRecord | undefined;
  let nativeProcessId: number | undefined;
  const result = await executeShell({
    ...input,
    platform: "macos",
    spawn: async (config: UnknownRecord) => {
      spawnCount += 1;
      invocation = structuredClone(config);
      const child = nativeChild(await spawnMxcFromInvocation(config, { usePty: false }, adapter));
      nativeProcessId = child.pid;
      return child;
    },
  });
  const containerId = typeof result.containerId === "string" ? result.containerId : "";
  if (!Number.isInteger(nativeProcessId) || !containerId.startsWith("mxc-")) {
    throw Object.assign(new Error("Contained shell execution omitted native identity evidence"), { code: "MXC_NATIVE_IDENTITY_MISSING" });
  }
  return {
    result,
    spawnCount,
    ...(invocation ? { invocation } : {}),
    evidence: {
      containerId,
      nativeProcessId: nativeProcessId as number,
      escapeDenied: result.escapeDenied === true,
    },
  };
}


async function runFilesystemMatrix(): Promise<UnknownRecord> {
  const root = await mkdtemp(join(tmpdir(), "omp-mxc-core-fs-"));
  try {
    const cwd = join(root, "contained cwd");
    const readonlyWorkspace = join(root, "readonly-workspace");
    const exactDirectory = join(root, "exact-files");
    const recursiveDirectory = join(root, "recursive-tree");
    await Promise.all([
      mkdir(cwd, { recursive: true }),
      mkdir(readonlyWorkspace, { recursive: true }),
      mkdir(exactDirectory, { recursive: true }),
      mkdir(join(recursiveDirectory, "nested"), { recursive: true }),
    ]);
    const readonlyFile = join(readonlyWorkspace, "source.txt");
    const exactFile = join(exactDirectory, "granted.txt");
    const exactSibling = join(exactDirectory, "sibling.txt");
    const recursiveDescendant = join(recursiveDirectory, "nested", "descendant.txt");
    const hostSentinel = join(root, "host-sentinel.txt");
    const values = {
      readonly: `readonly-${randomUUID()}`,
      exact: `exact-${randomUUID()}`,
      sibling: `sibling-${randomUUID()}`,
      recursive: `recursive-${randomUUID()}`,
      sentinel: `sentinel-${randomUUID()}`,
    };
    await Promise.all([
      writeFile(readonlyFile, values.readonly),
      writeFile(exactFile, values.exact),
      writeFile(exactSibling, values.sibling),
      writeFile(recursiveDescendant, values.recursive),
      writeFile(hostSentinel, values.sentinel),
    ]);

    const adapter = await loadMxcSdk();
    const script = [
      `const fs=process.getBuiltinModule("node:fs");`,
      `const read=(path)=>{try{return{allowed:true,value:fs.readFileSync(path,"utf8")}}catch{return{allowed:false,value:""}}};`,
      `const write=(path,value)=>{try{fs.writeFileSync(path,value);return true}catch{return false}};`,
      `process.stdout.write(JSON.stringify({readonlyRead:read(${JSON.stringify(readonlyFile)}),readonlyWrite:write(${JSON.stringify(readonlyFile)},"changed"),exactRead:read(${JSON.stringify(exactFile)}),siblingRead:read(${JSON.stringify(exactSibling)}),recursiveRead:read(${JSON.stringify(recursiveDescendant)}),sentinelWrite:write(${JSON.stringify(hostSentinel)},"escaped")}));`,
    ].join("");
    const encoded = Buffer.from(script).toString("base64");
    const command = `${shellQuote(process.execPath)} -e ${shellQuote(`eval(Buffer.from("${encoded}","base64").toString())`)}`;
    let launchedPid: number | undefined;
    let spawnCount = 0;
    const result = await executeShell({
      platform: "macos",
      shell: "bash",
      configuredShell: "/bin/bash",
      command,
      cwd,
      hostEnvironment: {},
      env: {},
      policy: createEffectivePolicy({
        filesystem: {
          read: [
            ...runtimeReadGrants(adapter, [cwd]),
            { path: readonlyWorkspace, kind: "directory", recursive: true },
            { path: exactFile, kind: "file" },
            { path: recursiveDirectory, kind: "directory", recursive: true },
          ],
          write: [],
        },
        network: { internet: false, localNetwork: false },
      }),
      spawn: async (config: UnknownRecord) => {
        spawnCount += 1;
        const child = nativeChild(await spawnMxcFromInvocation(config, { usePty: false }, adapter));
        launchedPid = child.pid;
        return child;
      },
    });
    if (result.exitCode !== 0) {
      const stderr = typeof result.stderr === "string" ? result.stderr.trim() : "";
      const stdout = typeof result.stdout === "string" ? result.stdout.trim() : "";
      throw new Error(`Filesystem probe exited ${String(result.exitCode)}${stderr ? `: ${stderr}` : stdout ? `: ${stdout}` : ""}`);
    }
    const output = record(JSON.parse(typeof result.stdout === "string" ? result.stdout.trim() : "{}"));
    const [readonlyAfter, sentinelAfter] = await Promise.all([readFile(readonlyFile, "utf8"), readFile(hostSentinel, "utf8")]);
    const containerId = typeof result.containerId === "string" ? result.containerId : "";
    if (!Number.isInteger(launchedPid) || !containerId.startsWith("mxc-")) throw new Error("Filesystem case omitted native invocation identity");
    const escapeDenied = output.sentinelWrite === false && sentinelAfter === values.sentinel;
    return {
      assertions: {
        readonlyWorkspaceRead: record(output.readonlyRead).allowed === true && record(output.readonlyRead).value === values.readonly,
        readonlyWorkspaceWriteDenied: output.readonlyWrite === false && readonlyAfter === values.readonly,
        exactFileRead: record(output.exactRead).allowed === true && record(output.exactRead).value === values.exact,
        exactSiblingDenied: record(output.siblingRead).allowed === false && record(output.siblingRead).value === "",
        recursiveDescendantRead: record(output.recursiveRead).allowed === true && record(output.recursiveRead).value === values.recursive,
        ungrantedWriteDenied: escapeDenied,
        noPartialRetry: spawnCount === 1,
      },
      containment: containment({ containerId, nativeProcessId: launchedPid as number, escapeDenied }),
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function runBash(input: UnknownRecord): Promise<UnknownRecord> {
  const root = await mkdtemp(join(tmpdir(), "omp-mxc-core-bash-"));
  try {
    const cwd = join(root, "workspace with spaces");
    await mkdir(cwd, { recursive: true });
    const sentinel = join(root, "host-sentinel.txt");
    const sentinelValue = `sentinel-${randomUUID()}`;
    await writeFile(sentinel, sentinelValue);
    const attemptEvidenceFile = join(root, "escape-attempted.txt");
    const command = typeof input.command === "string" ? input.command : "";
    const wrappedCommand = `printf '%s' escaped 2>/dev/null >\"$MXC_E2E_HOST_SENTINEL\"; printf '%s' attempted >\"$MXC_E2E_ATTEMPT_EVIDENCE\"; ${command}`;
    const requestedEnvironment = record(input.env);
    const env = Object.fromEntries(Object.entries(requestedEnvironment).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
    const adapter = await loadMxcSdk();
    const execution = await executeContainedShell({
      shell: "bash",
      configuredShell: "/bin/bash",
      command: wrappedCommand,
      cwd,
      hostEnvironment: {},
      env: { ...env, MXC_E2E_HOST_SENTINEL: sentinel, MXC_E2E_ATTEMPT_EVIDENCE: attemptEvidenceFile },
      policy: createEffectivePolicy({
        filesystem: { read: runtimeReadGrants(adapter, [cwd]), write: [{ path: attemptEvidenceFile, kind: "file" }] },
        network: { internet: false, localNetwork: false },
      }),
    }, adapter);
    const [sentinelAfter, attemptEvidence] = await Promise.all([readFile(sentinel, "utf8"), readFile(attemptEvidenceFile, "utf8")]);
    execution.evidence.escapeDenied = attemptEvidence === "attempted" && sentinelAfter === sentinelValue;
    const processConfig = record(execution.invocation?.process);
    const commandLine = Array.isArray(processConfig.commandLine) ? processConfig.commandLine : [];
    const wasPreviouslySeen = seenContainerIds.has(execution.evidence.containerId);
    seenContainerIds.add(execution.evidence.containerId);
    return {
      exitCode: execution.result.exitCode,
      stdout: execution.result.stdout,
      configuredPosixShell: commandLine[0] === "/bin/bash" && commandLine[1] === "-lc",
      freshSandbox: execution.spawnCount === 1 && !wasPreviouslySeen,
      containment: containment(execution.evidence),
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function trafficCommand(host: string, port: number, sentinel: string, escapeAttemptMarker: string, marker?: string): string {
  const script = [
    `const fs=process.getBuiltinModule("node:fs"),net=process.getBuiltinModule("node:net");`,
    `try{fs.writeFileSync(${JSON.stringify(sentinel)},"escaped")}catch{}`,
    `process.stdout.write(${JSON.stringify(escapeAttemptMarker)});`,
    `let finished=false,timer;const done=(code)=>{if(finished)return;finished=true;clearTimeout(timer);socket.destroy();process.exitCode=code};`,
    `const socket=net.createConnection({host:${JSON.stringify(host)},port:${port}},()=>{${marker === undefined ? "done(0)" : `socket.write(${JSON.stringify(marker)})`}});`,
    ...(marker === undefined ? [] : [`socket.once("data",()=>done(0));`]),
    `socket.once("error",()=>done(22));timer=setTimeout(()=>done(21),4000);`,
  ].join("");
  const encoded = Buffer.from(script).toString("base64");
  return `${shellQuote(process.execPath)} -e ${shellQuote(`eval(Buffer.from("${encoded}","base64").toString())`)}`;
}

async function hostEndpointReachable(url: string): Promise<boolean> {
  try {
    const response = await fetch(url, { method: "HEAD", redirect: "follow", signal: AbortSignal.timeout(8_000) });
    await response.body?.cancel();
    return response.status > 0 && response.status < 500;
  } catch {
    return false;
  }
}

async function runNetworkObservations(attestAllowedHosts: boolean): Promise<{
  probe: UnknownRecord;
  evidence: NativeEvidence[];
}> {
  const root = await mkdtemp(join(tmpdir(), "omp-mxc-core-network-"));
  try {
    const sentinel = join(root, "host-sentinel.txt");
    const sentinelValue = `sentinel-${randomUUID()}`;
    await writeFile(sentinel, sentinelValue);
    const adapter = await loadMxcSdk();
    const evidence: NativeEvidence[] = [];
    const probe = await probeIndependentLocalNetworkSeparation({
      ...(privateIpv4Address() ? { privateHost: privateIpv4Address() } : {}),
      attestAllowedHosts,
      executeTraffic: async (traffic: UnknownRecord) => {
        const containerId = createContainerId();
        const escapeAttemptMarker = `MXC_ESCAPE_ATTEMPT_${randomUUID()}`;
        const child = nativeChild(await spawnMxcTrafficProbeFromInvocation({
          platform: "macos",
          shell: { executable: "/bin/bash", args: ["-lc"] },
          command: trafficCommand(String(traffic.host), Number(traffic.port), sentinel, escapeAttemptMarker, String(traffic.marker)),
          cwd: root,
          usePty: false,
          containerId,
          policy: createEffectivePolicy({
            filesystem: { read: runtimeReadGrants(adapter, [root]), write: [] },
            network: {
              internet: traffic.internet === true,
              localNetwork: traffic.localNetwork === true,
              ...(Array.isArray(traffic.allowedHosts) ? { allowedHosts: traffic.allowedHosts } : {}),
            },
          }),
        }, { usePty: false }, adapter));
        const result = await waitForChild(child, 7_000);
        const sentinelAfter = await readFile(sentinel, "utf8");
        evidence.push({
          containerId,
          nativeProcessId: child.pid as number,
          escapeDenied: result.stdout.includes(escapeAttemptMarker) && sentinelAfter === sentinelValue,
        });
        return { exitCode: result.exitCode, timedOut: result.timedOut };
      },
    });
    return { probe, evidence };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function executePublicTraffic(internet: boolean): Promise<{ result: ChildResult; evidence: NativeEvidence }> {
  const root = await mkdtemp(join(tmpdir(), "omp-mxc-core-public-"));
  try {
    const sentinel = join(root, "host-sentinel.txt");
    const sentinelValue = `sentinel-${randomUUID()}`;
    await writeFile(sentinel, sentinelValue);
    const adapter = await loadMxcSdk();
    const containerId = createContainerId();
    const escapeAttemptMarker = `MXC_ESCAPE_ATTEMPT_${randomUUID()}`;
    const child = nativeChild(await spawnMxcTrafficProbeFromInvocation({
      platform: "macos",
      shell: { executable: "/bin/bash", args: ["-lc"] },
      command: trafficCommand("example.com", 443, sentinel, escapeAttemptMarker),
      cwd: root,
      usePty: false,
      containerId,
      policy: createEffectivePolicy({
        filesystem: { read: runtimeReadGrants(adapter, [root]), write: [] },
        network: { internet, localNetwork: false },
      }),
    }, { usePty: false }, adapter));
    const result = await waitForChild(child, 7_000);
    const sentinelAfter = await readFile(sentinel, "utf8");
    return {
      result,
      evidence: {
        containerId,
        nativeProcessId: child.pid as number,
        escapeDenied: result.stdout.includes(escapeAttemptMarker) && sentinelAfter === sentinelValue,
      },
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function runNetworkMatrix(): Promise<UnknownRecord> {
  const hostBefore = await hostEndpointReachable("https://example.com/");
  const blocked = await executePublicTraffic(false);
  const allowed = await executePublicTraffic(true);
  const local = await runNetworkObservations(false);
  const hostAfter = await hostEndpointReachable("https://example.com/");
  const localEvidence = Array.isArray(local.probe.evidence) ? local.probe.evidence.map(record) : [];
  const allEvidence = [blocked.evidence, allowed.evidence, ...local.evidence];
  const finalEvidence = allEvidence.at(-1);
  if (!finalEvidence) throw new Error("Network case performed no native invocation");
  return {
    assertions: {
      networkBlocked: hostBefore && blocked.result.exitCode !== 0,
      networkAllowed: hostBefore && allowed.result.exitCode === 0 && !allowed.result.timedOut,
      coupledNetworkObserved: localEvidence.filter((item) => item.mode === "blocked").length === 2
        && localEvidence.filter((item) => item.mode === "blocked").every((item) => item.observed === true && item.exitCode === 0)
        && localEvidence.filter((item) => item.mode === "allowed").length === 2
        && localEvidence.filter((item) => item.mode === "allowed").every((item) => item.observed === false && item.exitCode !== 0),
      modelTrafficUnaffected: hostBefore && hostAfter,
    },
    containment: containment({ ...finalEvidence, escapeDenied: allEvidence.every((item) => item.escapeDenied) }),
  };
}

async function runHostRules(): Promise<UnknownRecord> {
  const capabilities = { allowedHosts: false, blockedHosts: false };
  const allowedResolution = resolveNetworkPolicy({ internet: true, allowedHosts: ["api.example"] }, capabilities);
  const blockedResolution = resolveNetworkPolicy({ internet: true, blockedHosts: ["blocked.example"] }, capabilities);
  const native = await executePublicTraffic(false);
  const choices = Array.isArray(allowedResolution.choices)
    ? allowedResolution.choices.filter((choice): choice is string => typeof choice === "string")
    : [];
  const allowedHostsRefused = allowedResolution.activation === "choice-required" && allowedResolution.reason === "unsupported-host-rules";
  const blockedHostsRefused = blockedResolution.activation === "choice-required" && blockedResolution.reason === "unsupported-host-rules";
  return {
    assertions: {
      allowedHostsRefused,
      blockedHostsRefused,
      choices,
      noSilentWeakening: allowedHostsRefused && blockedHostsRefused
        && choices.join("\u0000") === ["block-network", "allow-unrestricted-network", "cancel"].join("\u0000"),
    },
    containment: containment(native.evidence),
  };
}

async function runExactPathExecutable(): Promise<UnknownRecord> {
  const root = await mkdtemp(join(tmpdir(), "omp-mxc-path-exec-"));
  try {
    const cwd = join(root, "workspace");
    const bin = join(root, "custom-bin");
    await Promise.all([mkdir(cwd, { recursive: true }), mkdir(bin, { recursive: true })]);
    const command = join(bin, "custom-command");
    const sibling = join(bin, "private-notes.txt");
    await Promise.all([
      writeFile(command, '#!/bin/sh\nprintf "tool-ok|"\nif /bin/cat "$PRIVATE_NOTES" >/dev/null 2>&1; then printf leaked; else printf denied; fi\n'),
      writeFile(sibling, "private"),
    ]);
    await chmod(command, 0o755);
    const adapter = await loadMxcSdk();
    const execution = await executeContainedShell({
      shell: "bash",
      configuredShell: "/bin/bash",
      command: "custom-command",
      cwd,
      hostEnvironment: { PATH: `${bin}:/usr/bin:/bin` },
      env: { PRIVATE_NOTES: sibling },
      policy: createEffectivePolicy({
        filesystem: { read: [...runtimeReadGrants(adapter, [cwd]), { path: command, kind: "file" }], write: [] },
        network: { internet: false, localNetwork: false },
      }),
    }, adapter);
    execution.evidence.escapeDenied = execution.result.stdout === "tool-ok|denied";
    return {
      exitCode: execution.result.exitCode,
      stdout: execution.result.stdout,
      assertions: { exactExecutableRan: execution.result.stdout === "tool-ok|denied", siblingDataDenied: !String(execution.result.stdout).includes("leaked") },
      containment: containment(execution.evidence),
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

export async function runCoreCase(caseName: string, input: Record<string, unknown>): Promise<Record<string, unknown> | null> {
  if (caseName === "filesystem-matrix") return runFilesystemMatrix();
  if (caseName === "bash") return runBash(input);
  if (caseName === "exact-path-executable") return runExactPathExecutable();
  if (caseName === "network-matrix") return runNetworkMatrix();
  if (caseName === "host-rules") return runHostRules();
  return null;
}
