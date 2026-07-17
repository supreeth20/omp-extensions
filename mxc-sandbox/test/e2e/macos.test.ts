import { beforeAll, describe, expect, test } from "bun:test";

type Result = Record<string, any>;
type Harness = {
  probe(): Promise<Result>;
  run(caseName: string, input?: Record<string, unknown>): Promise<Result>;
  cleanup(): Promise<void>;
};

let harness: Harness;
let attestation: Result;

function expectNativeSeatbelt(result: Result): void {
  expect(result.containment).toMatchObject({ backend: "seatbelt", realMxc: true, escapedToHost: false });
  expect(result.containment.nativeProcessId).toBeInteger();
  expect(result.containment.containerId).toMatch(/^mxc-/);
}

beforeAll(async () => {
  expect(process.platform, "macOS E2E must run on genuine macOS").toBe("darwin");
  expect(process.env.MXC_E2E_REAL, "Set MXC_E2E_REAL=1 only on an authorized real-MXC lane").toBe("1");
  const moduleUrl = new URL("../../src/e2e/driver.ts", import.meta.url).href;
  let module: Record<string, any>;
  try {
    // Platform-only test driver is intentionally loaded at runtime after the genuine-OS gate.
    module = await import(moduleUrl);
  } catch (error) {
    throw new Error("Missing real MXC E2E driver", { cause: error });
  }
  expect(module.createRealMxcE2eHarness).toBeFunction();
  harness = await module.createRealMxcE2eHarness({ platform: "macos", requireRealMxc: true, allowSimulation: false, allowMock: false, nativeDriver: module.createNativeExtensionDriver("macos") });
  attestation = await harness.probe();
  expect(attestation).toMatchObject({ os: "macos", architecture: process.arch, sdkVersion: "0.7.0", schemaVersion: "0.7.0-alpha", backend: "seatbelt", nativeBinaryExecuted: true, containmentDeniedHostSentinel: true });
  expect(attestation.osBuild).toBeString();
  expect(attestation.ompVersion).toMatch(/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/);
  expect(attestation.nativeBinarySha256).toMatch(/^[a-f0-9]{64}$/);
  expect(attestation.transcript.length).toBeGreaterThan(0);
});

describe("real macOS MXC Seatbelt extension E2E", () => {
  test("probes the SDK and native Seatbelt backend with containment evidence", () => {
    expect(attestation.platformSupport).toBe(true);
    expect(attestation.containmentDeniedHostSentinel).toBe(true);
  });

  test("enforces readonly workspace, exact grants, recursive grants, and denied writes", async () => {
    const result = await harness.run("filesystem-matrix");
    expectNativeSeatbelt(result);
    expect(result.assertions).toEqual({ readonlyWorkspaceRead: true, readonlyWorkspaceWriteDenied: true, exactFileRead: true, exactSiblingDenied: true, recursiveDescendantRead: true, ungrantedWriteDenied: true, noPartialRetry: true });
  });

  test("executes configured Bash inside a fresh Seatbelt process", async () => {
    const result = await harness.run("bash", { command: "printf '%s' \"$MXC_E2E_VALUE\"", cwdWithSpaces: true, env: { MXC_E2E_VALUE: "héllo world" } });
    expectNativeSeatbelt(result);
    expect(result).toMatchObject({ exitCode: 0, stdout: "héllo world", configuredPosixShell: true, freshSandbox: true });
  });

  test("executes exact custom PATH commands without exposing sibling files", async () => {
    const result = await harness.run("exact-path-executable");
    expectNativeSeatbelt(result);
    expect(result).toMatchObject({ exitCode: 0, stdout: "tool-ok|denied", assertions: { exactExecutableRan: true, siblingDataDenied: true } });
  });

  test("runs an installed Homebrew language-server executable inside Seatbelt", async () => {
    const result = await harness.run("bash", { command: "/opt/homebrew/bin/typescript-language-server --version", env: { PATH: process.env.PATH } });
    expectNativeSeatbelt(result);
    expect(result.exitCode, JSON.stringify(result)).toBe(0);
    expect(String(result.stdout).trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  test("falls back unsupported interactive PTY to contained pipe mode", async () => {
    const result = await harness.run("pty-roundtrip", { input: "hello\n", resize: { columns: 101, rows: 37 }, cancel: true });
    expectNativeSeatbelt(result);
    expect(result.assertions).toEqual({ pipeFallback: true, outputObserved: true, clientTerminalUsed: false });
  });

  test("falls back headless PTY to contained pipe mode with notice", async () => {
    const result = await harness.run("headless-pty");
    expectNativeSeatbelt(result);
    expect(result).toMatchObject({ usePty: false, notice: "PTY requested in a headless context; running in MXC pipe mode." });
  });

  test("integrates explicit async jobs with existing list, poll, cancel, progress, and completion", async () => {
    const result = await harness.run("async-job", { ownerId: "e2e-owner" });
    expectNativeSeatbelt(result);
    expect(result.assertions).toEqual({ listedForOwner: true, hiddenFromOtherOwner: true, pollWorked: true, progressDelivered: true, cancelWorked: true, completionDelivered: true, processTreeDead: true });
  });

  test("auto-backgrounds after the configured foreground threshold", async () => {
    const result = await harness.run("auto-background", { thresholdMs: 50 });
    expectNativeSeatbelt(result);
    expect(result).toMatchObject({ backgrounded: true, thresholdPreserved: true, jobVisible: true });
  });

  test("reports timeout and cancellation and leaves no orphan", async () => {
    const result = await harness.run("timeout-cancel");
    expectNativeSeatbelt(result);
    expect(result.assertions).toEqual({ timeoutReported: true, cancellationReported: true, childProcessDead: true, descendantProcessDead: true, ownerStillMapped: true });
  });

  test("truncates preview while storing byte-identical full output artifact", async () => {
    const result = await harness.run("output-artifact", { bytes: 262144, columns: 80, lines: 100 });
    expectNativeSeatbelt(result);
    expect(result).toMatchObject({ truncated: true, artifactScheme: "artifact", previewWithinLimits: true, rendererMatched: true });
    expect(result.rawSha256).toBe(result.artifactSha256);
    expect(result.rawBytes).toBe(result.artifactBytes);
  });

  test("blocks or allows all outbound traffic on the coupled macOS network switch", async () => {
    const result = await harness.run("network-matrix");
    expectNativeSeatbelt(result);
    expect(result.assertions).toEqual({ networkBlocked: true, networkAllowed: true, coupledNetworkObserved: true, modelTrafficUnaffected: true });
  });

  test("refuses unsupported host allowlists and blocklists without weakening", async () => {
    const result = await harness.run("host-rules");
    expectNativeSeatbelt(result);
    expect(result.assertions).toEqual({ allowedHostsRefused: true, blockedHostsRefused: true, choices: ["block-network", "allow-unrestricted-network", "cancel"], noSilentWeakening: true });
  });

  test("selects sensitive environment names without displaying or persisting values", async () => {
    const result = await harness.run("sensitive-environment", { ordinary: "ordinary", secretValue: "mxc-e2e-secret" });
    expectNativeSeatbelt(result);
    expect(result.assertions).toEqual({ namesGroupedOnce: true, valuesRedacted: true, selectedPresent: true, unselectedAbsent: true, stateHasNoSecretValue: true, profileHasNoSecretValue: true, restartReprompted: true });
  });

  test("serializes subagent bubbling and applies whole-tree grants without cross-agent one-time consumption", async () => {
    const result = await harness.run("subagent-permissions");
    expectNativeSeatbelt(result);
    expect(result.assertions).toEqual({ requesterIdentified: true, fullOperationDisplayed: true, promptsSerialized: true, parentGrantInherited: true, futureChildInherited: true, wrongAgentCouldNotConsumeOnce: true, noParentFailsClosed: true });
  });

  test("runs an approved exact command outside once with full host environment", async () => {
    const result = await harness.run("outside-once");
    expect(result.assertions).toEqual({ modelFlagRequired: true, commandDisplayed: true, cwdDisplayed: true, agentDisplayed: true, approvalRequired: true, sensitiveHostEnvPresent: true, exactCallOnly: true, criticalConfirmationPreserved: true });
    expect(result.hostRuns).toBe(1);
  });

  test("never falls back to host and presents exact failure choices", async () => {
    const result = await harness.run("launch-failure");
    expect(result.assertions).toEqual({ hostRunsBeforeChoice: 0, choices: ["Retry sandbox", "Run this command outside once", "Disable sandbox for this conversation", "Cancel"], cancelHostRuns: 0, noAutomaticFallback: true });
  });

  test("disable restores host behavior and re-enable offers restore or reset", async () => {
    const result = await harness.run("disable-reenable");
    expect(result.assertions).toEqual({ confirmationRequired: true, wholeTreeDisabled: true, exactHostParity: true, reenableChoices: ["restore-prior-policy-and-grants", "reset-and-run-setup"], restoreWorked: true, resetReranSetup: true });
  });

  test("restores conversation state on resume and snapshots current policy into an older branch", async () => {
    const result = await harness.run("resume-branch");
    expect(result.assertions).toEqual({ resumeRestored: true, switchRestored: true, treeRestored: true, laterGrantInOlderBranch: true, transientSecretNotRestored: true });
  });

  test("uses unique container IDs for concurrent calls", async () => {
    const result = await harness.run("parallel-container-ids", { count: 32 });
    expect(result.ids).toHaveLength(32);
    expect(new Set(result.ids).size).toBe(32);
    for (const containment of result.containments) expectNativeSeatbelt({ containment });
  });

  test("keeps unadapted, trusted, and similarly named tools available", async () => {
    const result = await harness.run("unknown-and-trusted-tools");
    expect(result.assertions).toEqual({ unknownRanUnchanged: true, exactTrustedRanUnchanged: true, prefixLookalikeRanUnchanged: true, hostRuns: 3 });
  });
});
