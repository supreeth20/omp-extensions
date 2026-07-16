#!/usr/bin/env bun

import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { arch, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import mxcSandboxExtension from "../../index";
import { probeNativeMxcExecution } from "../../src/mxc/probe";
import { loadMxcSdk } from "../../src/mxc/sdk";
import { runCoreCase } from "./native-macos-core";
import { runPolicyCase } from "./native-macos-policy";
import { runProcessCase } from "./native-macos-process";

type UnknownRecord = Record<string, unknown>;
type CaseRunner = (caseName: string, input: UnknownRecord) => Promise<UnknownRecord | null>;

const DRIVER_PROTOCOL = "omp-mxc-native-v1";
const DRIVER_OWNER_FILE = ".omp-mxc-native-driver-owner";

function record(value: unknown): UnknownRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as UnknownRecord : {};
}

function driverError(code: string, message: string, details?: UnknownRecord): Error & { code: string; details?: UnknownRecord } {
  return Object.assign(new Error(message), { code, ...(details === undefined ? {} : { details }) });
}

function driverRoot(): string {
  const uid = typeof process.getuid === "function" ? process.getuid() : "unknown";
  return join(tmpdir(), `omp-mxc-native-driver-${uid}-${process.ppid}`);
}

function ownerDocument(): string {
  return JSON.stringify({ driverProtocol: DRIVER_PROTOCOL, parentProcessId: process.ppid });
}

async function ensureDriverRoot(): Promise<string> {
  const root = driverRoot();
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  await writeFile(join(root, DRIVER_OWNER_FILE), ownerDocument(), { encoding: "utf8", mode: 0o600 });
  return root;
}

async function cleanupDriverRoot(): Promise<{ removed: boolean; resource: string }> {
  const root = driverRoot();
  let owner: string;
  try {
    owner = await readFile(join(root, DRIVER_OWNER_FILE), "utf8");
  } catch (cause) {
    if (cause && typeof cause === "object" && "code" in cause && cause.code === "ENOENT") return { removed: false, resource: root };
    throw cause;
  }
  if (owner !== ownerDocument()) {
    throw driverError("NATIVE_DRIVER_RESOURCE_OWNERSHIP_MISMATCH", "Refusing to remove a temp resource not attested as driver-owned", { root });
  }
  await rm(root, { recursive: true, force: false });
  return { removed: true, resource: root };
}

function invokeProductionExtensionFactory(): { commands: string[]; tools: string[]; events: string[] } {
  const commands: string[] = [];
  const tools: string[] = [];
  const events: string[] = [];
  const api = {
    registerCommand(name: string, _definition: UnknownRecord): void {
      commands.push(name);
    },
    registerTool(definition: UnknownRecord): void {
      if (typeof definition.name === "string") tools.push(definition.name);
    },
    on(event: string, _handler: (...arguments_: unknown[]) => unknown): void {
      events.push(event);
    },
    appendEntry(_customType: string, _data: UnknownRecord): void {},
    async exec(): Promise<UnknownRecord> {
      throw driverError("NATIVE_DRIVER_HOST_EXEC_FORBIDDEN", "The recording OMP API never executes host commands");
    },
    pi: {},
  };
  mxcSandboxExtension(api);
  if (!commands.includes("sandbox") || !tools.includes("sandbox_request") || !events.includes("session_start")) {
    throw driverError("PRODUCTION_EXTENSION_FACTORY_INCOMPLETE", "The production extension factory did not register its required OMP surface", { commands, tools, events });
  }
  return { commands, tools, events };
}

async function capture(command: string, arguments_: string[]): Promise<{ command: string[]; stdout: string; stderr: string; exitCode: number }> {
  const child = Bun.spawn([command, ...arguments_], { stdin: "ignore", stdout: "pipe", stderr: "pipe", env: process.env });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { command: [command, ...arguments_], stdout: stdout.trim(), stderr: stderr.trim(), exitCode };
}

async function locateSeatbeltBinary(): Promise<string> {
  const packageMetadata = fileURLToPath(import.meta.resolve("@microsoft/mxc-sdk/package.json"));
  const packageRoot = dirname(packageMetadata);
  const sdkArchitecture = arch() === "arm64" ? "arm64" : "x64";
  const targetTriple = arch() === "arm64" ? "aarch64-apple-darwin" : "x86_64-apple-darwin";
  const sdkDistDirectory = join(packageRoot, "dist");
  const targetDirectory = join(sdkDistDirectory, "..", "..", "src", "target");
  const candidates = [
    ...(process.env.MXC_BIN_DIR ? [join(process.env.MXC_BIN_DIR, sdkArchitecture, "mxc-exec-mac")] : []),
    join(packageRoot, "bin", sdkArchitecture, "mxc-exec-mac"),
    join(targetDirectory, targetTriple, "release", "mxc-exec-mac"),
    join(targetDirectory, targetTriple, "debug", "mxc-exec-mac"),
    join(targetDirectory, "release", "mxc-exec-mac"),
    join(targetDirectory, "debug", "mxc-exec-mac"),
  ];
  for (const candidate of candidates) {
    try {
      const metadata = await stat(candidate);
      if (metadata.isFile() && (metadata.mode & 0o111) !== 0) return realpath(candidate);
    } catch (cause) {
      if (!cause || typeof cause !== "object" || !("code" in cause) || cause.code !== "ENOENT") throw cause;
    }
  }
  throw driverError("MXC_NATIVE_BINARY_NOT_FOUND", "The SDK Seatbelt native executable could not be located", { candidates });
}

async function sha256File(path: string): Promise<string> {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

async function runProbe(factory: { commands: string[]; tools: string[]; events: string[] }): Promise<UnknownRecord> {
  if (process.platform !== "darwin") throw driverError("MACOS_HOST_REQUIRED", "The native Seatbelt driver requires genuine macOS");
  const sdk = await loadMxcSdk();
  const platformSupport = sdk.reprobePlatformSupport();
  if (platformSupport.isSupported !== true) {
    throw driverError("MXC_SEATBELT_UNSUPPORTED", "The real MXC SDK does not report Seatbelt support", { platformSupport });
  }

  const root = await ensureDriverRoot();
  const sentinelPath = join(root, `host-sentinel-${crypto.randomUUID()}`);
  const sentinelSecret = randomBytes(32).toString("hex");
  await writeFile(sentinelPath, sentinelSecret, { encoding: "utf8", mode: 0o600 });

  const denialMarker = `mxc-seatbelt-denied-${crypto.randomUUID()}`;
  const containerId = `mxc-probe-${crypto.randomUUID()}`;
  const nativeBinaryPath = await locateSeatbeltBinary();
  const readonlyPaths = [...new Set([...sdk.discoverRequiredReadonlyPaths(), dirname(process.execPath), "/bin", tmpdir()])];
  const command = `if /bin/cat ${shellQuote(sentinelPath)} >/dev/null 2>&1; then exit 91; else printf '%s' ${shellQuote(denialMarker)}; fi`;
  const execution = record(await probeNativeMxcExecution({
    platform: "darwin",
    containerId,
    cwd: tmpdir(),
    shell: { executable: "/bin/zsh", args: ["-lc"] },
    command,
    env: { PATH: "/usr/bin:/bin" },
    policy: {
      filesystem: {
        read: readonlyPaths.map((path) => ({ path, kind: "directory", recursive: true })),
        write: [],
        deny: [{ path: sentinelPath, kind: "file" }],
      },
      network: { internet: false, localNetwork: false },
      ui: { allowWindows: false, clipboardRead: false, clipboardWrite: false, inputInjection: false },
    },
    probeTimeoutMs: 15_000,
    networkProbeTimeoutMs: 5_000,
  }));
  const nativeProcessId = execution.nativeProcessId;
  const denialObserved = execution.exitCode === 0 && execution.output === denialMarker;
  if (execution.contained !== true || execution.realMxc !== true || execution.backend !== "seatbelt" || !Number.isInteger(nativeProcessId) || !denialObserved) {
    throw driverError("MXC_NATIVE_PROBE_ATTESTATION_FAILED", "The production native probe did not observe the Seatbelt denial sentinel", { execution });
  }

  const [nativeBinarySha256, omp, osBuild] = await Promise.all([
    sha256File(nativeBinaryPath),
    capture("omp", ["--version"]),
    capture("/usr/bin/sw_vers", ["-buildVersion"]),
  ]);
  if (omp.exitCode !== 0 || !/^omp\/16\.[0-9]+\.[0-9]+$/.test(omp.stdout)) {
    throw driverError("OMP_VERSION_UNVERIFIED", "The actual OMP executable did not report a supported 16.x version", { command: omp.command, exitCode: omp.exitCode, stdout: omp.stdout, stderr: omp.stderr });
  }
  if (osBuild.exitCode !== 0 || osBuild.stdout.length === 0) {
    throw driverError("MACOS_BUILD_UNVERIFIED", "The actual macOS build could not be queried", { command: osBuild.command, exitCode: osBuild.exitCode, stdout: osBuild.stdout, stderr: osBuild.stderr });
  }

  return {
    os: "macos",
    architecture: arch(),
    osBuild: osBuild.stdout,
    ompVersion: omp.stdout.slice("omp/".length),
    sdkVersion: sdk.version,
    schemaVersion: sdk.schemaVersion,
    backend: execution.backend,
    platformSupport: platformSupport.isSupported,
    nativeBinaryExecuted: true,
    nativeBinaryPath,
    nativeBinarySha256,
    containmentDeniedHostSentinel: true,
    nativeProcessId,
    containerId,
    transcript: [
      { operation: "production-extension-factory", commands: factory.commands, tools: factory.tools, events: factory.events },
      { operation: "sdk-load", version: sdk.version, schemaVersion: sdk.schemaVersion, platformSupport },
      { operation: "native-seatbelt-denial-probe", containerId, nativeProcessId, exitCode: execution.exitCode, outputMatchedDenialMarker: denialObserved },
      { operation: "native-binary-sha256", path: nativeBinaryPath, sha256: nativeBinarySha256 },
      { operation: "omp-version", command: omp.command, exitCode: omp.exitCode, stdout: omp.stdout },
      { operation: "macos-build", command: osBuild.command, exitCode: osBuild.exitCode, stdout: osBuild.stdout },
    ],
  };
}

async function runCase(caseName: string, input: UnknownRecord): Promise<UnknownRecord> {
  const runners: readonly CaseRunner[] = [runCoreCase, runProcessCase, runPolicyCase];
  for (const runner of runners) {
    const result = await runner(caseName, input);
    if (result !== null) return record(result);
  }
  throw driverError("NATIVE_E2E_CASE_UNKNOWN", `Unknown native macOS E2E case: ${caseName}`, { caseName });
}

async function validateRequest(value: unknown): Promise<UnknownRecord> {
  const request = record(value);
  if (request.platform !== "macos" || request.requireRealMxc !== true || request.allowSimulation !== false || request.allowMock !== false) {
    throw driverError("NATIVE_E2E_REAL_LANE_REQUIRED", "The native driver requires the explicit genuine macOS MXC lane contract");
  }
  if (typeof request.extensionEntry !== "string") throw driverError("PRODUCTION_EXTENSION_ENTRY_REQUIRED", "The production extension entry path is required");
  const [requestedEntry, productionEntry] = await Promise.all([
    realpath(request.extensionEntry),
    realpath(fileURLToPath(new URL("../../index.ts", import.meta.url))),
  ]);
  if (requestedEntry !== productionEntry) {
    throw driverError("PRODUCTION_EXTENSION_ENTRY_MISMATCH", "The requested extension entry is not the production MXC sandbox extension", { requestedEntry, productionEntry });
  }
  return request;
}

async function main(): Promise<void> {
  const requestText = await Bun.stdin.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(requestText);
  } catch (cause) {
    throw driverError("NATIVE_DRIVER_INVALID_JSON", "The native driver requires exactly one JSON request on stdin", { cause: cause instanceof Error ? cause.message : String(cause) });
  }
  const request = await validateRequest(parsed);
  const factory = invokeProductionExtensionFactory();
  let response: UnknownRecord;
  if (request.operation === "probe") {
    response = await runProbe(factory);
  } else if (request.operation === "run") {
    if (typeof request.caseName !== "string" || request.caseName.length === 0) throw driverError("NATIVE_E2E_CASE_REQUIRED", "A non-empty caseName is required");
    response = await runCase(request.caseName, record(request.input));
  } else if (request.operation === "cleanup") {
    response = { cleanup: await cleanupDriverRoot() };
  } else {
    throw driverError("NATIVE_DRIVER_OPERATION_UNKNOWN", "Unknown native driver operation", { operation: request.operation });
  }
  process.stdout.write(`${JSON.stringify({ ...response, driverProtocol: DRIVER_PROTOCOL, productionExtensionFactoryInvoked: true })}\n`);
}

try {
  await main();
} catch (cause) {
  const error = cause instanceof Error ? cause : new Error(String(cause));
  const details = record(error).details;
  process.stderr.write(`${JSON.stringify({ error: error.message, code: "code" in error ? error.code : "NATIVE_DRIVER_FAILED", ...(details === undefined ? {} : { details }) })}\n`);
  process.exitCode = 1;
}
