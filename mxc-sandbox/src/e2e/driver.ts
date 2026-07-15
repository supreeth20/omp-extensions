import { MXC_SCHEMA_VERSION } from "../mxc/config";
import { loadMxcSdk } from "../mxc/sdk";

type UnknownRecord = Record<string, unknown>;

export interface NativeDriver {
  probe(): Promise<UnknownRecord>;
  run(caseName: string, input?: UnknownRecord): Promise<UnknownRecord>;
  cleanup(): Promise<void>;
}

export interface RealMxcE2eOptions {
  platform: "macos" | "windows";
  requireRealMxc: true;
  allowSimulation: false;
  allowMock: false;
  nativeDriver: NativeDriver;
}

const NON_CONTAINED_CASES = new Set(["outside-once", "launch-failure", "disable-reenable", "resume-branch", "windows-doctor"]);

function record(value: unknown): UnknownRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as UnknownRecord : {};
}

function evidenceError(message: string): Error & { code: string } {
  return Object.assign(new Error(message), { code: "NATIVE_E2E_EVIDENCE_REQUIRED" });
}

async function invokeNativeDriver(executable: string, request: UnknownRecord): Promise<UnknownRecord> {
  const processHandle = Bun.spawn([executable], {
    stdin: new Blob([JSON.stringify(request)]),
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, MXC_E2E_REAL: "1" },
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(processHandle.stdout).text(),
    new Response(processHandle.stderr).text(),
    processHandle.exited,
  ]);
  if (exitCode !== 0) throw evidenceError(`Native OMP/MXC driver failed (${exitCode}): ${stderr.trim()}`);
  let result: UnknownRecord;
  try {
    result = record(JSON.parse(stdout));
  } catch {
    throw evidenceError("Native OMP/MXC driver returned invalid JSON evidence");
  }
  if (result.driverProtocol !== "omp-mxc-native-v1" || result.productionExtensionFactoryInvoked !== true) {
    throw evidenceError("Native driver evidence must prove the production extension factory/dispatcher was invoked");
  }
  return result;
}

export function createNativeExtensionDriver(platform: "macos" | "windows"): NativeDriver {
  const executable = process.env.MXC_E2E_NATIVE_DRIVER;
  if (typeof executable !== "string" || !executable.startsWith("/") && !/^[A-Za-z]:[\\/]/.test(executable)) {
    throw evidenceError("MXC_E2E_NATIVE_DRIVER must name an absolute genuine-host OMP/MXC driver executable");
  }
  const extensionEntry = new URL("../../index.ts", import.meta.url).pathname;
  const base = { platform, extensionEntry, requireRealMxc: true, allowSimulation: false, allowMock: false };
  return {
    probe: () => invokeNativeDriver(executable, { ...base, operation: "probe" }),
    run: (caseName, input = {}) => invokeNativeDriver(executable, { ...base, operation: "run", caseName, input }),
    cleanup: async () => { await invokeNativeDriver(executable, { ...base, operation: "cleanup" }); },
  };
}

function assertNativeEvidence(value: UnknownRecord, platform: "macos" | "windows"): void {
  const containment = record(value.containment);
  const expectedBackend = platform === "macos" ? "seatbelt" : "processcontainer";
  if (containment.backend !== expectedBackend
    || containment.realMxc !== true
    || containment.escapedToHost !== false
    || !Number.isInteger(containment.nativeProcessId)
    || typeof containment.containerId !== "string"
    || !containment.containerId.startsWith("mxc-")) {
    throw evidenceError(`The ${expectedBackend} result did not include genuine native containment evidence`);
  }
}

function nativeDriverFromOptions(options: RealMxcE2eOptions): NativeDriver {
  const candidate = options.nativeDriver;
  if (typeof candidate.probe !== "function" || typeof candidate.run !== "function" || typeof candidate.cleanup !== "function") {
    throw evidenceError("A platform lane must supply a native OMP/MXC driver; mocks, simulations, and inferred containment are rejected");
  }
  return candidate;
}

export async function createRealMxcE2eHarness(options: RealMxcE2eOptions): Promise<NativeDriver> {
  const expectedHost = options.platform === "macos" ? "darwin" : "win32";
  if (process.platform !== expectedHost) throw evidenceError(`The ${options.platform} E2E contract requires a genuine ${expectedHost} host`);
  if (process.env.MXC_E2E_REAL !== "1" || options.requireRealMxc !== true || options.allowSimulation !== false || options.allowMock !== false) {
    throw evidenceError("The real-MXC lane gate and explicit mock/simulation prohibitions are required");
  }
  const sdk = await loadMxcSdk();
  if (sdk.version !== "0.7.0" || sdk.schemaVersion !== MXC_SCHEMA_VERSION) {
    throw evidenceError("The native E2E lane requires exactly MXC SDK 0.7.0 and schema 0.7.0-alpha");
  }
  const driver = nativeDriverFromOptions(options);
  return {
    async probe(): Promise<UnknownRecord> {
      const evidence = record(await driver.probe());
      if (evidence.nativeBinaryExecuted !== true
        || evidence.containmentDeniedHostSentinel !== true
        || typeof evidence.nativeBinarySha256 !== "string"
        || !/^[a-f0-9]{64}$/.test(evidence.nativeBinarySha256)
        || !Array.isArray(evidence.transcript)
        || evidence.transcript.length === 0) {
        throw evidenceError("Native binary execution, denied-host sentinel, SHA-256, and command transcript evidence are mandatory");
      }
      return evidence;
    },
    async run(caseName: string, input?: UnknownRecord): Promise<UnknownRecord> {
      const result = record(await driver.run(caseName, input));
      if (!NON_CONTAINED_CASES.has(caseName)) assertNativeEvidence(result, options.platform);
      return result;
    },
    cleanup: () => driver.cleanup(),
  };
}
