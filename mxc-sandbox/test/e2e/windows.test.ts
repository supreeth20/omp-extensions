import { beforeAll, describe, expect, test } from "bun:test";

type Result = Record<string, any>;
type Harness = {
  probe(): Promise<Result>;
  run(caseName: string, input?: Record<string, unknown>): Promise<Result>;
  cleanup(): Promise<void>;
};

let harness: Harness;
let attestation: Result;

function expectNativeProcessContainer(result: Result): void {
  expect(result.containment).toMatchObject({ backend: "processcontainer", realMxc: true, escapedToHost: false });
  expect(result.containment.nativeProcessId).toBeInteger();
  expect(result.containment.containerId).toMatch(/^mxc-/);
}

beforeAll(async () => {
  expect(process.platform, "Windows E2E must run on genuine Windows").toBe("win32");
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
  harness = await module.createRealMxcE2eHarness({ platform: "windows", requireRealMxc: true, allowSimulation: false, allowMock: false, nativeDriver: module.createNativeExtensionDriver("windows") });
  attestation = await harness.probe();
  expect(attestation).toMatchObject({ os: "windows", sdkVersion: "0.7.0", schemaVersion: "0.7.0-alpha", backend: "processcontainer", nativeBinaryExecuted: true, containmentDeniedHostSentinel: true });
  expect(attestation.windowsBuild).toBeGreaterThanOrEqual(26100);
  expect(attestation.windowsRelease).toMatch(/^(24H2|25H2|2[6-9]H2)$/);
  expect(attestation.ompVersion).toMatch(/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/);
  expect(attestation.nativeBinarySha256).toMatch(/^[a-f0-9]{64}$/);
  expect(attestation.tier).toBeInteger();
  expect(attestation.transcript.length).toBeGreaterThan(0);
});

describe("real Windows MXC ProcessContainer extension E2E", () => {
  test("probes genuine Windows 11 24H2+ and native ProcessContainer evidence", () => {
    expect(attestation.platformSupport).toBe(true);
    expect(attestation.containmentDeniedHostSentinel).toBe(true);
    expect(attestation.probeWarnings).toBeArray();
  });

  test("enforces readonly workspace, exact grants, recursive grants, and denied writes", async () => {
    const result = await harness.run("filesystem-matrix");
    expectNativeProcessContainer(result);
    expect(result.assertions).toEqual({ readonlyWorkspaceRead: true, readonlyWorkspaceWriteDenied: true, exactFileRead: true, exactSiblingDenied: true, recursiveDescendantRead: true, ungrantedWriteDenied: true, reparseEscapeDenied: true, caseInsensitiveMatch: true, noPartialRetry: true });
  });

  test("executes configured Git Bash rather than PowerShell through the bash tool", async () => {
    const result = await harness.run("bash", { command: "printf '%s' \"$MXC_E2E_VALUE\"", cwdWithSpaces: true, env: { MXC_E2E_VALUE: "héllo world" } });
    expectNativeProcessContainer(result);
    expect(result).toMatchObject({ exitCode: 0, stdout: "héllo world", executableKind: "git-bash", posixCompatible: true, freshSandbox: true });
  });

  test("requires PowerShell 7 and never falls back to Windows PowerShell 5.1", async () => {
    const result = await harness.run("powershell-version", { command: "$PSVersionTable.PSVersion.Major" });
    expectNativeProcessContainer(result);
    expect(result).toMatchObject({ executable: "pwsh.exe", majorVersion: 7, windowsPowerShellFallbackAttempted: false, autoInstallAttempted: false });
  });

  test("PowerShell fails without allowWindows and starts with it without clipboard/input broadening", async () => {
    const result = await harness.run("powershell-ui-requirement");
    expectNativeProcessContainer(result);
    expect(result.assertions).toEqual({ withoutAllowWindowsFailed: true, withAllowWindowsSucceeded: true, clipboardReadBlocked: true, clipboardWriteBlocked: true, inputInjectionBlocked: true });
  });

  test("forwards PTY input, output, resize, cancellation, and timeout only through MXC", async () => {
    const result = await harness.run("pty-roundtrip", { input: "hello\r\n", resize: { columns: 101, rows: 37 }, cancel: true });
    expectNativeProcessContainer(result);
    expect(result.assertions).toEqual({ inputObserved: true, outputObserved: true, resizeObserved: true, cancelled: true, containedProcessTreeDead: true, clientTerminalUsed: false });
  });

  test("falls back headless PTY to contained pipe mode with notice", async () => {
    const result = await harness.run("headless-pty");
    expectNativeProcessContainer(result);
    expect(result).toMatchObject({ usePty: false, notice: "PTY requested in a headless context; running in MXC pipe mode." });
  });

  test("integrates explicit async jobs with owner-filtered existing job operations", async () => {
    const result = await harness.run("async-job", { ownerId: "e2e-owner" });
    expectNativeProcessContainer(result);
    expect(result.assertions).toEqual({ listedForOwner: true, hiddenFromOtherOwner: true, pollWorked: true, progressDelivered: true, cancelWorked: true, completionDelivered: true, processTreeDead: true });
  });

  test("auto-backgrounds at the configured threshold", async () => {
    const result = await harness.run("auto-background", { thresholdMs: 50 });
    expectNativeProcessContainer(result);
    expect(result).toMatchObject({ backgrounded: true, thresholdPreserved: true, jobVisible: true });
  });

  test("reports timeout and cancellation and leaves no orphan", async () => {
    const result = await harness.run("timeout-cancel");
    expectNativeProcessContainer(result);
    expect(result.assertions).toEqual({ timeoutReported: true, cancellationReported: true, childProcessDead: true, descendantProcessDead: true, ownerStillMapped: true });
  });

  test("truncates preview while storing byte-identical full output artifact", async () => {
    const result = await harness.run("output-artifact", { bytes: 262144, columns: 80, lines: 100 });
    expectNativeProcessContainer(result);
    expect(result).toMatchObject({ truncated: true, artifactScheme: "artifact", previewWithinLimits: true, rendererMatched: true });
    expect(result.rawSha256).toBe(result.artifactSha256);
    expect(result.rawBytes).toBe(result.artifactBytes);
  });

  test("blocks and allows internet while refusing unsupported host lists", async () => {
    const result = await harness.run("network-matrix");
    expectNativeProcessContainer(result);
    expect(result.assertions).toEqual({ internetBlocked: true, internetAllowed: true, unsupportedAllowedHostsRefused: true, unsupportedBlockedHostsRefused: true, choices: ["block-network", "allow-unrestricted-network", "cancel"], noSilentWeakening: true });
  });

  test("fails closed if independent local-network enforcement cannot be proven", async () => {
    const result = await harness.run("local-network-capability");
    expect(result.assertions).toMatchObject({ probedWithRealTraffic: true, unsupportedMeansActivationRefused: true, noSilentWeakening: true });
    if (result.assertions.supported) expect(result.assertions).toMatchObject({ localBlocked: true, localAllowed: true });
  });

  test("selects sensitive environment names without displaying or persisting values", async () => {
    const result = await harness.run("sensitive-environment", { secretValue: "mxc-e2e-secret" });
    expectNativeProcessContainer(result);
    expect(result.assertions).toEqual({ namesGroupedOnce: true, valuesRedacted: true, selectedPresent: true, unselectedAbsent: true, stateHasNoSecretValue: true, profileHasNoSecretValue: true, restartReprompted: true });
  });

  test("serializes subagent bubbling and prevents cross-agent one-time consumption", async () => {
    const result = await harness.run("subagent-permissions");
    expectNativeProcessContainer(result);
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

  test("restores resume state and snapshots current policy into an older branch", async () => {
    const result = await harness.run("resume-branch");
    expect(result.assertions).toEqual({ resumeRestored: true, switchRestored: true, treeRestored: true, laterGrantInOlderBranch: true, transientSecretNotRestored: true });
  });

  test("uses unique container IDs for concurrent calls", async () => {
    const result = await harness.run("parallel-container-ids", { count: 32 });
    expect(result.ids).toHaveLength(32);
    expect(new Set(result.ids).size).toBe(32);
    for (const containment of result.containments) expectNativeProcessContainer({ containment });
  });

  test("strict mode keeps allowDaclMutation false and fails if native enforcement is unavailable", async () => {
    const result = await harness.run("windows-strict-mode");
    expect(result.assertions).toEqual({ allowDaclMutation: false, nativeTierUnavailableWasDetected: true, unavailableRunFailedClosed: true, hostFallbackRuns: 0 });
  });

  test("doctor reports build/tier and prints but never runs exact elevated host-prep commands", async () => {
    const result = await harness.run("windows-doctor");
    expect(result.windowsBuild).toBeGreaterThanOrEqual(26100);
    expect(result.tier).toBeInteger();
    expect(result.commands).toEqual(["wxc-host-prep prepare-system-drive", "wxc-host-prep prepare-null-device"]);
    expect(result).toMatchObject({ elevationAttempted: false, commandExecutionAttempted: false, reprobedAfterOperatorPreparation: true });
  });

  test("opt-in Tier-3 compatibility mutates and restores DACLs after real host preparation", async () => {
    expect(process.env.MXC_E2E_WINDOWS_DACL_APPROVED, "DACL lane requires explicit operator approval").toBe("1");
    const result = await harness.run("windows-dacl-compatibility", { requireOperatorPreparation: true });
    expectNativeProcessContainer(result);
    expect(result.assertions).toEqual({ explicitOptIn: true, writeDacVerified: true, aclBeforeCaptured: true, aclChangedForRun: true, containedRunSucceeded: true, aclRestoredAfterSuccess: true, aclRestoredAfterFailure: true, aclRestoredAfterCancellation: true });
    expect(result.aclBeforeSha256).toBe(result.aclAfterSha256);
  });

  test("blocks unknown mutation tools without host execution", async () => {
    const result = await harness.run("unknown-and-trusted-tools");
    expect(result.assertions).toEqual({ unknownBlockedPreExecution: true, unknownHostRuns: 0, exactTrustedRanUnchanged: true, prefixLookalikeBlocked: true });
  });
});
