import { describe, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createConnection } from "node:net";
import { expectAsyncFailureCode } from "./contracts";
import { loadContract, requiredExport, uniqueValues } from "./contracts";

type BuildInvocationConfig = (input: Record<string, any>) => Record<string, any>;
type ResolveShell = (input: Record<string, any>) => Record<string, any>;
type ExecuteShell = (input: Record<string, any>) => Promise<Record<string, any>>;
type CreateContainerId = () => string;
type RegisterAsyncJob = (input: Record<string, any>) => Promise<Record<string, any>>;
type RenderOutput = (input: Record<string, any>) => Promise<Record<string, any>>;
type CreatePtyBridge = (input: Record<string, any>) => Record<string, any>;
type FilterRequiredReadonlyPaths = (paths: string[], input: Record<string, string>) => string[];
type ResolveRequiredReadonlyPaths = (paths: string[], input: Record<string, unknown>) => string[];
type RuntimeRootForExecutableTarget = (target: string, platform: string) => string | undefined;
type ResolveExecutionWorkingDirectory = (requested: unknown, currentDirectory?: string, fallbackDirectory?: string) => string;
type LoadMxcSdk = () => Promise<{ executablePath?: string; reprobePlatformSupport(): Record<string, unknown> }>;



type PruneLegacyDiscoveredPathGrants = (filesystem: Record<string, unknown>, input: Record<string, unknown>) => Record<string, any>;
type SandboxDenialGuidance = (input: Record<string, unknown>) => Record<string, unknown> | undefined;




describe("per-invocation MXC process configuration", () => {
  test("builds schema 0.7.0-alpha process containment with explicit cwd, env, and timeout", async () => {
    const mod = await loadContract("execution");
    const build = requiredExport<BuildInvocationConfig>(mod, "buildInvocationConfig");
    const config = build({
      platform: "darwin",
      shell: { executable: "/bin/zsh", args: ["-lc"] },
      command: "printf '%s' \"$GREETING\"",
      cwd: "/repo dir",
      env: { PATH: "/usr/bin:/bin", GREETING: "héllo world" },
      timeoutMs: 1234,
      policy: { filesystem: { read: ["/repo dir"] }, network: { internet: false } },
      containerId: "mxc-call-unique",
    });
    expect(config).toMatchObject({
      version: "0.7.0-alpha",
      backend: "process",
      containerId: "mxc-call-unique",
      process: { commandLine: ["/bin/zsh", "-lc", "printf '%s' \"$GREETING\""], cwd: "/repo dir", env: { PATH: "/usr/bin:/bin", GREETING: "héllo world" }, timeoutMs: 1234 },
    });
    expect(config.process.inheritEnvironment).toBe(false);
  });

  test("sets the requested cwd inside contained Windows PowerShell", async () => {
    const mod = await loadContract("execution");
    const build = requiredExport<BuildInvocationConfig>(mod, "buildInvocationConfig");
    const config = build({
      platform: "win32",
      shell: { executable: "C:\\Program Files\\PowerShell\\7\\pwsh.exe", args: ["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-Command"], dialect: "powershell7" },
      command: "Get-ChildItem -File | Select-Object -First 1",
      cwd: "C:\\repo's dir",
      env: {},
      policy: { filesystem: { read: [{ path: "C:\\repo's dir", recursive: true }] }, network: { internet: false }, mxcOverrides: { fallback: { allowDaclMutation: true } } },
      platformCapabilities: { windowsBuild: 26200, tier: "appcontainer-dacl", hostPreparationVerified: true, nativeEnforcementAvailable: false },
      containerId: "mxc-powershell-cwd",
    });
    expect(config.process.commandLine.slice(0, 4)).toEqual(["C:\\Windows\\System32\\cmd.exe", "/d", "/s", "/c"]);
    const payload = String(config.process.commandLine.at(-1));
    expect(payload).toContain(`"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -NoLogo -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand`);
    const bootstrap = Buffer.from(payload.split(" -EncodedCommand ").at(-1) ?? "", "base64").toString("utf16le");
    expect(bootstrap).toContain(`New-PSDrive -Name MXC -PSProvider FileSystem -Root 'C:\\repo''s dir'`);
    expect(bootstrap).toContain(`[Environment]::CurrentDirectory='C:\\repo''s dir'`);
    expect(bootstrap).toContain("function global:Remove-Item");
    const encoded = /FromBase64String\('([^']+)'\)/.exec(bootstrap)?.[1] ?? "";
    expect(Buffer.from(encoded, "base64").toString("utf16le")).toBe("Get-ChildItem -File | Select-Object -First 1");
  });

  test("launches portable preview PowerShell through contained cmd with an encoded command", async () => {
    const mod = await loadContract("execution");
    const build = requiredExport<BuildInvocationConfig>(mod, "buildInvocationConfig");
    const config = build({
      platform: "win32",
      shell: { executable: "C:\\Users\\dev\\AppData\\Local\\Programs\\PowerShell\\7-preview\\pwsh.exe", args: ["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-Command"], dialect: "powershell7" },
      command: "Write-Output 'ok'",
      cwd: "C:\\repo",
      env: {},
      policy: { filesystem: { read: [{ path: "C:\\repo", recursive: true }] }, network: { internet: false }, mxcOverrides: { fallback: { allowDaclMutation: true } } },
      platformCapabilities: { windowsBuild: 26200, tier: "appcontainer-dacl", hostPreparationVerified: true, nativeEnforcementAvailable: false },
      containerId: "mxc-preview-powershell",
    });
    expect(config.process.commandLine.slice(0, 4)).toEqual(["C:\\Windows\\System32\\cmd.exe", "/d", "/s", "/c"]);
    const payload = String(config.process.commandLine.at(-1));
    expect(payload).toContain(`"C:\\Users\\dev\\AppData\\Local\\Programs\\PowerShell\\7-preview\\pwsh.exe" -NoLogo -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand`);
    const bootstrap = Buffer.from(payload.split(" -EncodedCommand ").at(-1) ?? "", "base64").toString("utf16le");
    expect(bootstrap).toContain(`New-PSDrive -Name MXC -PSProvider FileSystem -Root 'C:\\repo'`);
    expect(bootstrap).toContain(`[Environment]::CurrentDirectory='C:\\repo'`);
    expect(bootstrap).toContain("function global:Remove-Item");
    const encoded = /FromBase64String\('([^']+)'\)/.exec(bootstrap)?.[1] ?? "";
    expect(Buffer.from(encoded, "base64").toString("utf16le")).toBe("Write-Output 'ok'");
  });

  test("accepts internet-only Windows policy only with native local-destination isolation evidence", async () => {
    const mod = await loadContract("execution");
    const build = requiredExport<BuildInvocationConfig>(mod, "buildInvocationConfig");
    const base = {
      platform: "win32",
      shell: { executable: "C:\\Windows\\System32\\cmd.exe", args: ["/d", "/s", "/c"], dialect: "cmd" },
      command: "echo ok",
      cwd: "C:\\repo",
      env: {},
      policy: { filesystem: { read: [{ path: "C:\\repo", recursive: true }] }, network: { internet: true, localNetwork: false }, mxcOverrides: { fallback: { allowDaclMutation: true } } },
      containerId: "mxc-isolated-internet",
    };
    expect(build({ ...base, platformCapabilities: { windowsBuild: 26200, tier: "appcontainer-dacl", hostPreparationVerified: true, nativeEnforcementAvailable: false, internetLocalNetworkIsolation: true } }).policy.network).toMatchObject({ internet: true, localNetwork: false });
    expect(() => build({ ...base, policy: { ...base.policy, network: { internet: false, localNetwork: true } }, platformCapabilities: { windowsBuild: 26200, tier: "appcontainer-dacl", hostPreparationVerified: true, nativeEnforcementAvailable: false, internetLocalNetworkIsolation: true } })).toThrow(expect.objectContaining({ code: "LOCAL_NETWORK_CAPABILITY_UNPROVEN" }));
  });

  test("leaves Darwin Seatbelt settings to SDK process backend defaults", async () => {
    const execution = await loadContract("execution");
    const sdk = await loadContract("sdk");
    const build = requiredExport<BuildInvocationConfig>(execution, "buildInvocationConfig");
    const createSdkConfig = requiredExport<(input: Record<string, any>, adapter: Record<string, any>) => Promise<Record<string, any>>>(sdk, "createSdkInvocationConfig");
    const invocation = build({
      platform: "darwin",
      shell: { executable: "/bin/zsh", args: ["-lc"] },
      command: "echo contained",
      cwd: "/tmp",
      env: {},
      policy: { network: { internet: false } },
      containerId: "mxc-darwin-sdk-defaults",
    });
    expect(invocation).toMatchObject({ backend: "process", containerId: "mxc-darwin-sdk-defaults" });
    expect(invocation).not.toHaveProperty("seatbelt");

    let sdkRequest: Record<string, any> | undefined;
    const config = await createSdkConfig(invocation, {
      version: "0.7.0",
      schemaVersion: "0.7.0-alpha",
      schemaVersions: ["0.7.0-alpha"],
      createConfigFromPolicy: async (policy: Record<string, any>, backend: string, containerId: string) => {
        sdkRequest = { policy, backend, containerId };
        return { backend, process: {}, seatbelt: {} };
      },
      spawnSandboxFromConfig: async () => ({}),
      getPlatformSupport: () => ({ isSupported: true }),
      reprobePlatformSupport: () => ({ isSupported: true }),
      discoverRequiredReadonlyPaths: () => [],
    });

    expect(sdkRequest).toMatchObject({
      backend: "process",
      containerId: "mxc-darwin-sdk-defaults",
      policy: { version: "0.7.0-alpha", network: { allowOutbound: false, allowLocalNetwork: false } },
    });
    expect(config).toMatchObject({ backend: "process", seatbelt: {} });
    expect(config.seatbelt).not.toHaveProperty("guiAccess");
    expect(config.seatbelt).not.toHaveProperty("launchMethod");
  });

  test("resolves and passes the SDK native launcher without an extension bin link", async () => {
    const sdkModule = await loadContract("sdk");
    const resolveExecutable = requiredExport<() => string | undefined>(sdkModule, "resolveInstalledMxcExecutable");
    const spawn = requiredExport<(input: Record<string, any>, options: Record<string, any>, adapter: Record<string, any>) => Promise<unknown>>(sdkModule, "spawnMxcFromInvocation");
    const executablePath = resolveExecutable();
    const executableName = process.platform === "darwin" ? "mxc-exec-mac" : process.platform === "win32" ? "wxc-exec.exe" : "lxc-exec";
    expect(executablePath).toEndWith(join("node_modules", "@microsoft", "mxc-sdk", "bin", process.arch === "arm64" ? "arm64" : "x64", executableName));
    expect(executablePath).not.toContain(join("mxc-sandbox", "bin"));

    let observedOptions: Record<string, any> | undefined;
    await spawn({
      platform: process.platform,
      shell: { executable: "/bin/zsh", args: ["-lc"] },
      command: "printf ok",
      cwd: "/tmp",
      env: {},
      policy: { network: { internet: false, localNetwork: false } },
      containerId: "mxc-sdk-native-path",
    }, {}, {
      version: "0.7.0",
      schemaVersion: "0.7.0-alpha",
      schemaVersions: ["0.7.0-alpha"],
      executablePath,
      createConfigFromPolicy: async () => ({ process: {} }),
      spawnSandboxFromConfig: async (_config: unknown, options: Record<string, any>) => { observedOptions = options; return {}; },
    });
    expect(observedOptions?.executablePath).toBe(executablePath);
  });

  test("serializes Darwin shell argv without expanding process identifiers", async () => {
    const sdk = await loadContract("sdk");
    const createSdkConfig = requiredExport<(input: Record<string, any>, adapter: Record<string, any>) => Promise<Record<string, any>>>(sdk, "createSdkInvocationConfig");
    const config = await createSdkConfig({
      platform: "darwin",
      shell: { executable: "/bin/bash", args: ["-lc"] },
      command: `printf "%s" "$$" "$!"`,
      cwd: "/tmp",
      env: {},
      policy: { network: { internet: false, localNetwork: false } },
      containerId: "mxc-posix-argv",
    }, {
      version: "0.7.0",
      schemaVersion: "0.7.0-alpha",
      schemaVersions: ["0.7.0-alpha"],
      createConfigFromPolicy: async () => ({ process: {} }),
      spawnSandboxFromConfig: async () => ({}),
    });
    expect(config.process.commandLine).toBe(`'/bin/bash' '-lc' 'printf "%s" "$$" "$!"'`);
  });

  test("creates a fresh sandbox and unique cryptographic container ID per concurrent call", async () => {
    const mod = await loadContract("execution");
    const createId = requiredExport<CreateContainerId>(mod, "createContainerId");
    const ids = Array.from({ length: 256 }, () => createId());
    uniqueValues(ids);
    for (const id of ids) expect(id).toMatch(/^mxc-[a-zA-Z0-9_-]{16,}$/);
  });

  test("does not carry shell-local cd, alias, or export state across calls", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    const configs: Record<string, any>[] = [];
    const spawn = async (config: Record<string, any>) => { configs.push(config); return { exitCode: 0, stdout: "", stderr: "" }; };
    await execute({ shell: "bash", command: "cd /tmp; export X=one; alias ll='ls'", cwd: "/repo", env: { X: "base" }, spawn });
    await execute({ shell: "bash", command: "pwd; printf $X; alias ll", cwd: "/repo", env: { X: "base" }, spawn });
    expect(configs).toHaveLength(2);
    expect(configs[0]?.containerId).not.toBe(configs[1]?.containerId);
    expect(configs[1]?.process).toMatchObject({ cwd: "/repo", env: { X: "base" } });
  });

  test("uses configured POSIX Bash/Zsh and never disguises PowerShell as bash", async () => {
    const mod = await loadContract("execution");
    const resolve = requiredExport<ResolveShell>(mod, "resolveShell");
    expect(resolve({ platform: "darwin", requested: "bash", configuredShell: "/bin/zsh" })).toEqual({ executable: "/bin/zsh", dialect: "posix", args: ["-lc"] });
    expect(resolve({ platform: "win32", requested: "bash", discovered: ["C:\\Program Files\\Git\\bin\\bash.exe"] })).toEqual({ executable: "C:\\Program Files\\Git\\bin\\bash.exe", dialect: "posix", args: ["-lc"] });
    expect(() => resolve({ platform: "win32", requested: "bash", discovered: ["powershell.exe"], environment: { PATH: "", ProgramFiles: "Z:\\missing", ProgramW6432: "Z:\\missing", LOCALAPPDATA: "Z:\\missing" } })).toThrow(expect.objectContaining({ code: "POSIX_BASH_REQUIRED" }));
  });

  test("requires PowerShell 7 and sets only the minimum startup window permission", async () => {
    const mod = await loadContract("execution");
    const resolve = requiredExport<ResolveShell>(mod, "resolveShell");
    expect(resolve({ platform: "win32", requested: "powershell", discovered: ["C:\\Program Files\\PowerShell\\7\\pwsh.exe"], environment: { LOCALAPPDATA: "Z:\\missing", PATH: "" } })).toEqual({ executable: "C:\\Program Files\\PowerShell\\7\\pwsh.exe", dialect: "powershell7", args: ["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-Command"], ui: { allowWindows: true, clipboardRead: false, clipboardWrite: false, inputInjection: false } });
    expect(() => resolve({ platform: "win32", requested: "powershell", discovered: ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"], environment: { PATH: "", ProgramFiles: "Z:\\missing", ProgramW6432: "Z:\\missing" } })).toThrow(expect.objectContaining({ code: "POWERSHELL_7_REQUIRED", autoInstall: false }));
  });

  test("discovers PowerShell 7 and Git Bash without private OMP context fields", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-shell-discovery-"));
    try {
      const powershell = join(root, "pwsh.exe");
      const bash = join(root, "Git", "bin", "bash.exe");
      await mkdir(join(root, "Git", "bin"), { recursive: true });
      await Promise.all([writeFile(powershell, ""), writeFile(bash, "")]);
      const mod = await loadContract("execution");
      const resolve = requiredExport<ResolveShell>(mod, "resolveShell");
      const environment = { PATH: root, ProgramFiles: root };
      expect(resolve({ platform: "win32", requested: "powershell", environment })).toMatchObject({ executable: powershell, dialect: "powershell7" });
      expect(resolve({ platform: "win32", requested: "bash", environment })).toMatchObject({ executable: bash, dialect: "posix" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("Windows strict mode defaults DACL mutation off", async () => {
    const mod = await loadContract("execution");
    const build = requiredExport<BuildInvocationConfig>(mod, "buildInvocationConfig");
    const config = build({ platform: "win32", shell: { executable: "bash.exe", args: ["-lc"] }, command: "echo ok", cwd: "C:\\repo", env: {}, policy: {}, containerId: "mxc-win-strict" });
    expect(config.fallback).toEqual({ allowDaclMutation: false });
  });

  test("refuses unsupported platform host rules before SDK configuration", async () => {
    const mod = await loadContract("execution");
    const build = requiredExport<BuildInvocationConfig>(mod, "buildInvocationConfig");
    expect(() => build({ platform: "win32", shell: { executable: "bash.exe", args: ["-lc"] }, command: "echo ok", policy: { network: { allowedHosts: ["api.example"] } }, containerId: "mxc-win-hosts" })).toThrow(expect.objectContaining({ code: "UNSUPPORTED_HOST_RULES" }));
  });

  test("couples Darwin outbound settings while keeping host rules fail closed", async () => {
    const mod = await loadContract("execution");
    const build = requiredExport<BuildInvocationConfig>(mod, "buildInvocationConfig");
    const config = build({
      platform: "darwin",
      platformCapabilities: { coupledNetwork: true, allowedHosts: false },
      shell: { executable: "/bin/bash", args: ["-lc"] },
      command: "echo ok",
      policy: { network: { internet: true, localNetwork: false } },
      containerId: "mxc-darwin-network",
    });
    expect(config.policy.network).toMatchObject({ internet: true, localNetwork: true });
    expect(() => build({
      platform: "darwin",
      platformCapabilities: { coupledNetwork: true, allowedHosts: false },
      shell: { executable: "/bin/bash", args: ["-lc"] },
      command: "echo unsafe",
      policy: { network: { allowedHosts: ["api.example"] } },
      containerId: "mxc-darwin-hosts",
    })).toThrow(expect.objectContaining({ code: "UNSUPPORTED_HOST_RULES" }));
  });

  test("converts structured setup and inline filesystem grants into SDK paths", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    let sdkPolicy: Record<string, any> | undefined;
    const adapter = {
      version: "0.7.0",
      schemaVersion: "0.7.0-alpha",
      schemaVersions: ["0.7.0-alpha"],
      getPlatformSupport: () => ({ isSupported: true }),
      reprobePlatformSupport: () => ({ isSupported: true }),
      createConfigFromPolicy: async (policy: Record<string, any>) => { sdkPolicy = policy; return { process: {} }; },
      spawnSandboxFromConfig: async () => ({ exitCode: 0, stdout: "ok" }),
    };
    await execute({
      shell: "bash", configuredShell: "/bin/zsh", command: "cat /repo/a", mxcAdapter: adapter,
      policy: { filesystem: { read: [{ path: "/repo", recursive: true }, { path: "/repo/a", kind: "file" }], write: [{ path: "/tmp", recursive: true }] } },
    });
    expect(sdkPolicy?.filesystem).toMatchObject({ readonlyPaths: ["/repo", "/repo/a"], readwritePaths: [await realpath("/tmp")] });
  });

  test("fails closed instead of broadening exact nonrecursive directories in native MXC", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    let sdkCalls = 0;
    const adapter = {
      version: "0.7.0",
      schemaVersion: "0.7.0-alpha",
      schemaVersions: ["0.7.0-alpha"],
      getPlatformSupport: () => ({ isSupported: true }),
      reprobePlatformSupport: () => ({ isSupported: true }),
      createConfigFromPolicy: async () => { sdkCalls += 1; return { process: {} }; },
      spawnSandboxFromConfig: async () => ({ exitCode: 0 }),
    };
    await expect(execute({
      shell: "bash",
      configuredShell: "/bin/zsh",
      command: "ls /scope/exact",
      mxcAdapter: adapter,
      policy: { filesystem: { read: [{ path: "/scope/exact", kind: "directory", recursive: false }], write: [] } },
    })).rejects.toMatchObject({ code: "UNSUPPORTED_NONRECURSIVE_DIRECTORY", details: { field: "read", path: "/scope/exact" } });
    expect(sdkCalls).toBe(0);
  });

  test("canonicalizes native exact-file rules and rejects real directories before the SDK adapter seam", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    const root = await mkdtemp(join(tmpdir(), "mxc-native-exact-file-"));
    const directory = join(root, "actual-directory");
    await mkdir(directory);
    try {
      for (const rule of [directory, { path: directory, kind: "file" }]) {
        let sdkCalls = 0;
        const adapter = {
          version: "0.7.0",
          schemaVersion: "0.7.0-alpha",
          schemaVersions: ["0.7.0-alpha"],
          getPlatformSupport: () => ({ isSupported: true }),
          reprobePlatformSupport: () => ({ isSupported: true }),
          createConfigFromPolicy: async () => { sdkCalls += 1; return { process: {} }; },
          spawnSandboxFromConfig: async () => ({ exitCode: 0 }),
        };
        await expect(execute({
          shell: "bash",
          configuredShell: "/bin/zsh",
          command: "cat exact target",
          mxcAdapter: adapter,
          policy: { filesystem: { read: [rule], write: [] } },
        })).rejects.toMatchObject({ code: "UNSUPPORTED_NONRECURSIVE_DIRECTORY", details: { field: "read", path: directory } });
        expect(sdkCalls).toBe(0);
      }

      let sdkPolicy: Record<string, any> | undefined;
      const nonexistent = join(root, "missing-parent", "exact-file.txt");
      const adapter = {
        version: "0.7.0",
        schemaVersion: "0.7.0-alpha",
        schemaVersions: ["0.7.0-alpha"],
        getPlatformSupport: () => ({ isSupported: true }),
        reprobePlatformSupport: () => ({ isSupported: true }),
        createConfigFromPolicy: async (policy: Record<string, any>) => { sdkPolicy = policy; return { process: {} }; },
        spawnSandboxFromConfig: async () => ({ exitCode: 0 }),
      };
      await execute({ shell: "bash", configuredShell: "/bin/zsh", command: "cat missing", mxcAdapter: adapter, policy: { filesystem: { read: [{ path: nonexistent, kind: "file" }], write: [] } } });
      expect(sdkPolicy?.filesystem.readonlyPaths).toEqual([join(await realpath(root), "missing-parent", "exact-file.txt")]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("derives Windows DACL compatibility only from approved policy and verified host status", async () => {
    const mod = await loadContract("execution");
    const build = requiredExport<BuildInvocationConfig>(mod, "buildInvocationConfig");
    const base = { platform: "win32", shell: { executable: "bash.exe", args: ["-lc"] }, command: "echo ok", cwd: "C:\\repo", env: {}, containerId: "mxc-win-policy" };
    expect(build({ ...base, allowDaclMutation: true, platformCapabilities: { windowsBuild: 26100, tier: 3, hostPreparationVerified: true, nativeEnforcementAvailable: false } }).fallback).toEqual({ allowDaclMutation: false });
    expect(() => build({ ...base, policy: { mxcOverrides: { fallback: { allowDaclMutation: true } } }, platformCapabilities: { windowsBuild: 26100, tier: 3, hostPreparationVerified: false, nativeEnforcementAvailable: false } })).toThrow(expect.objectContaining({ code: "WINDOWS_HOST_PREPARATION_REQUIRED" }));
    expect(build({ ...base, policy: { mxcOverrides: { fallback: { allowDaclMutation: true } } }, platformCapabilities: { windowsBuild: 26100, tier: 3, hostPreparationVerified: true, nativeEnforcementAvailable: false } }).fallback).toEqual({ allowDaclMutation: true });
  });

  test("reprobes native Windows isolation facts without the SDK five-second diagnostics ceiling", async () => {
    if (process.platform !== "win32") return;
    const mod = await loadContract("sdk");
    const loadMxcSdk = requiredExport<LoadMxcSdk>(mod, "loadMxcSdk");
    const sdk = await loadMxcSdk();
    const support = sdk.reprobePlatformSupport();
    expect(support.isSupported).toBe(true);
    expect(typeof support.isolationTier).toBe("string");
    expect(["base-container", "appcontainer-bfs", "appcontainer-dacl"]).toContain(String(support.isolationTier));
  });
  test("excludes unrelated user and application PATH directories from default read access", async () => {
    const mod = await loadContract("sdk");
    const filter = requiredExport<FilterRequiredReadonlyPaths>(mod, "filterRequiredReadonlyPaths");
    expect(filter([
      "/usr/bin",
      "/opt/homebrew/bin",
      "/Applications/VMware Fusion.app/Contents/Public",
      "/Users/example/Course Video transcriptions",
      "/Users/example/cli-tools/whisper.cpp/build/bin",
      "/opt/homebrew/Cellar/omp/16.5.2/bin",
    ], { platform: "darwin", executableDirectory: "/opt/homebrew/Cellar/omp/16.5.2/bin" })).toEqual([
      "/usr/bin",
      "/opt/homebrew/bin",
      "/opt/homebrew/Cellar/omp/16.5.2/bin",
    ]);
  });

  test("derives versioned runtime roots for Homebrew executable symlinks", async () => {
    const mod = await loadContract("sdk");
    const runtimeRoot = requiredExport<RuntimeRootForExecutableTarget>(mod, "runtimeRootForExecutableTarget");
    expect(runtimeRoot("/opt/homebrew/Cellar/node/26.4.0/bin/node", "darwin")).toBe("/opt/homebrew/Cellar/node/26.4.0");
    expect(runtimeRoot("/usr/bin/env", "darwin")).toBeUndefined();
  });


  test("keeps custom PATH commands as exact executable grants without exposing sibling data", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-path-tools-"));
    const command = join(root, "custom-command");
    try {
      const privateData = join(root, "private-notes.txt");
      await Promise.all([writeFile(command, "#!/bin/sh\nprintf ok"), writeFile(privateData, "private")]);
      await chmod(command, 0o755);
      const mod = await loadContract("sdk");
      const resolvePaths = requiredExport<ResolveRequiredReadonlyPaths>(mod, "resolveRequiredReadonlyPaths");
      expect(resolvePaths([root, "/usr/bin"], { platform: "darwin", pathEntries: [root, "/usr/bin"], executableDirectory: "/opt/homebrew/bin" })).toEqual([command, "/usr/bin"]);
      const ui = await loadContract("ui");
      const defaults = requiredExport<(input: Record<string, unknown>) => Record<string, any>>(ui, "getInitialSetupDefaults");
      expect(defaults({ cwd: "/repo", temp: "/tmp", discoveredReadonlyPaths: [command, "/usr/bin"] }).filesystem.read).toEqual([
        { path: "/repo", recursive: true },
        { path: command, kind: "file" },
        { path: "/usr/bin", recursive: true },
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("removes legacy recursive grants sourced only from custom PATH entries", async () => {
    const mod = await loadContract("sdk");
    const prune = requiredExport<PruneLegacyDiscoveredPathGrants>(mod, "pruneLegacyDiscoveredPathGrants");
    const result = prune({ read: [
      { path: "/Users/example/.omp", kind: "directory", recursive: true },
      { path: "/Users/example/Course Video transcriptions", kind: "directory", recursive: true },
      { path: "/Applications/VMware Fusion.app/Contents/Public", kind: "directory", recursive: true },
      { path: "/usr/bin", kind: "directory", recursive: true },
    ], write: [] }, {
      cwd: "/Users/example/.omp",
      pathEntries: ["/usr/bin", "/Applications/VMware Fusion.app/Contents/Public", "/Users/example/Course Video transcriptions"],
      platform: "darwin",
      executableDirectory: "/opt/homebrew/Cellar/omp/16.5.2/bin",
    });
    expect(result.removed).toEqual(["/Users/example/Course Video transcriptions", "/Applications/VMware Fusion.app/Contents/Public"]);
    expect(result.filesystem.read).toEqual([
      { path: "/Users/example/.omp", kind: "directory", recursive: true },
      { path: "/usr/bin", kind: "directory", recursive: true },
    ]);
  });

  test("tells agents to request capabilities after filesystem or network shell denials", async () => {
    const mod = await loadContract("execution");
    const guidance = requiredExport<SandboxDenialGuidance>(mod, "sandboxDenialGuidance");
    expect(guidance({ shell: "bash", command: "cat /private/data.txt", exitCode: 1, stderr: "cat: /private/data.txt: Operation not permitted", policy: { network: { internet: false } } })).toMatchObject({
      denied: true,
      nextTool: "sandbox_request",
      capabilities: ["read", "write", "allowed-host", "internet", "local-network"],
    });
    expect(guidance({ shell: "powershell", command: "Invoke-WebRequest https://example.com", exitCode: 1, stderr: "Unable to connect", policy: { network: { internet: false } } })).toMatchObject({
      denied: true,
      kind: "network",
      suggestedCapability: { capability: "internet", value: "allow" },
    });
    expect(guidance({ shell: "powershell", command: "Invoke-WebRequest https://example.com", exitCode: 1, stderr: "Unable to connect", policy: { network: { internet: false } }, platformCapabilities: { allowedHosts: true } })).toMatchObject({
      suggestedCapability: { capability: "allowed-host", value: "example.com" },
    });
    expect(guidance({ shell: "bash", command: "npm install --global typescript", exitCode: 1, stderr: "network request failed", policy: { network: { internet: false } } })).toMatchObject({
      denied: true,
      kind: "network",
      suggestedCapability: { capability: "internet", value: "allow" },
    });
    expect(guidance({ shell: "bash", command: "false", exitCode: 1, stderr: "", policy: { network: { internet: false } } })).toBeUndefined();
  });

  test("includes actionable permission guidance in contained shell output", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    const result = await execute({
      shell: "bash",
      configuredShell: "/bin/bash",
      command: "cat /private/data.txt",
      policy: { filesystem: { read: [], write: [] }, network: { internet: false } },
      spawn: async () => ({ exitCode: 1, stderr: "cat: /private/data.txt: Operation not permitted" }),
    });
    expect(result.preview).toContain("sandbox_request");
    expect(result.details.sandboxDenial).toMatchObject({ denied: true, nextTool: "sandbox_request" });
  });

});

describe("native local-network separation probe", () => {
  test("keeps Windows activation runtime grants below command-line limits", async () => {
    const mod = await loadContract("probe");
    const select = requiredExport<(input: Record<string, unknown>) => string[]>(mod, "selectProbeRuntimeReadonlyPaths");
    const bulkSdkPaths = Array.from({ length: 5000 }, (_, index) => `C:\\tools\\tool-${index}.exe`);
    expect(select({
      platform: "win32",
      sdkPaths: bulkSdkPaths,
      requestedPaths: ["C:\\Program Files\\Git\\bin"],
      shellExecutable: "C:\\Windows\\System32\\cmd.exe",
      spawnfile: "C:\\mxc\\wxc-exec.exe",
    })).toEqual(["C:\\Program Files\\Git\\bin", "C:\\Windows\\System32", "C:\\mxc"]);
    expect(select({ platform: "linux", sdkPaths: ["/usr/bin"], shellExecutable: "/bin/bash" })).toEqual(["/usr/bin", "/bin"]);
  });

  test("attests only observed blocked and allowed traffic against its ephemeral endpoint", async () => {
    const mod = await loadContract("probe");
    const probe = requiredExport<(input: Record<string, any>) => Promise<Record<string, any>>>(mod, "probeIndependentLocalNetworkSeparation");
    const executeTraffic = async (input: Record<string, any>): Promise<Record<string, any>> => {
      if (Array.isArray(input.allowedHosts) && !input.allowedHosts.includes(input.host)) return { exitCode: 25 };
      if (input.localNetwork !== true) return { exitCode: 23 };
      const socket = createConnection({ host: input.host, port: input.port });
      const { promise, resolve } = Promise.withResolvers<void>();
      let failed = false;
      socket.once("connect", () => socket.write(input.marker));
      socket.once("data", () => socket.end());
      socket.once("error", () => { failed = true; resolve(); });
      socket.once("close", resolve);
      await promise;
      return { exitCode: failed ? 24 : 0 };
    };
    const attested = await probe({ platform: "win32", privateHost: "127.0.0.1", attestAllowedHosts: true, executeTraffic });
    expect(attested.independentLocalNetwork).toBe(true);
    expect(attested.allowedHosts).toBe(true);
    expect(attested.evidence).toHaveLength(4);
    expect(attested.hostRuleEvidence).toHaveLength(2);
    expect(attested.evidence.filter((item: Record<string, any>) => item.mode === "blocked").every((item: Record<string, any>) => item.observed === false)).toBe(true);
    expect(attested.evidence.filter((item: Record<string, any>) => item.mode === "allowed").every((item: Record<string, any>) => item.observed === true)).toBe(true);
    expect(attested.internetLocalNetworkIsolation).toBe(true);
    expect(attested.localNetworkAvailable).toBe(true);
    const internetOnly = await probe({ platform: "win32", privateHost: "127.0.0.1", executeTraffic: async () => ({ exitCode: 23 }) });
    expect(internetOnly).toMatchObject({ internetLocalNetworkIsolation: true, localNetworkAvailable: false, independentLocalNetwork: false });
    const unobserved = await probe({ platform: "win32", privateHost: "127.0.0.1", attestAllowedHosts: true, executeTraffic: async () => ({ exitCode: 0 }) });
    expect(unobserved.independentLocalNetwork).toBe(false);
    expect(unobserved.allowedHosts).toBe(false);
  });

  test("preserves upstream macOS and Linux traffic-probe semantics and result shape", async () => {
    const mod = await loadContract("probe");
    const probe = requiredExport<(input: Record<string, any>) => Promise<Record<string, any>>>(mod, "probeIndependentLocalNetworkSeparation");
    const executeTraffic = async (input: Record<string, any>): Promise<Record<string, any>> => {
      if (input.localNetwork !== true) return { exitCode: 23, timedOut: true };
      const socket = createConnection({ host: input.host, port: input.port });
      const { promise, resolve } = Promise.withResolvers<void>();
      let failed = false;
      socket.once("connect", () => socket.write(input.marker));
      socket.once("data", () => socket.end());
      socket.once("error", () => { failed = true; resolve(); });
      socket.once("close", resolve);
      await promise;
      return { exitCode: failed ? 24 : 0 };
    };
    for (const platform of ["darwin", "linux"] as const) {
      const result = await probe({ platform, privateHost: "127.0.0.1", executeTraffic });
      expect(result.independentLocalNetwork).toBe(true);
      expect(result).not.toHaveProperty("internetLocalNetworkIsolation");
      expect(result).not.toHaveProperty("localNetworkAvailable");
    }
  });

  test("launches controlled native traffic policies only through the internal probe seam", async () => {
    const mod = await loadContract("sdk");
    const spawnProbe = requiredExport<(input: Record<string, any>, options: Record<string, any>, adapter: Record<string, any>) => Promise<unknown>>(mod, "spawnMxcTrafficProbeFromInvocation");
    const createNormal = requiredExport<(input: Record<string, any>, adapter: Record<string, any>) => Promise<Record<string, any>>>(mod, "createSdkInvocationConfig");
    let observedPolicy: Record<string, any> | undefined;
    const adapter = {
      version: "0.7.0",
      schemaVersion: "0.7.0-alpha",
      schemaVersions: ["0.7.0-alpha"],
      createConfigFromPolicy: async (policy: Record<string, any>) => { observedPolicy = policy; return { process: {} }; },
      spawnSandboxFromConfig: async () => ({ kill() {}, once() {} }),
      getPlatformSupport: () => ({}),
      reprobePlatformSupport: () => ({}),
      discoverRequiredReadonlyPaths: () => [],
    };
    const invocation = {
      platform: "darwin",
      shell: { executable: "/bin/zsh", args: ["-lc"] },
      command: "probe-traffic",
      cwd: "/tmp",
      usePty: false,
      containerId: "mxc-probe-controlled",
      policy: { filesystem: { read: [{ path: "/bin", kind: "directory", recursive: true }, { path: "/tmp", kind: "directory", recursive: true }], write: [] }, network: { internet: false, localNetwork: true, allowedHosts: ["127.0.0.1"] } },
    };
    await expect(createNormal(invocation, adapter)).rejects.toMatchObject({ code: "UNSUPPORTED_HOST_RULES" });
    await spawnProbe(invocation, {}, adapter);
    expect(observedPolicy).toMatchObject({ network: { allowOutbound: false, allowLocalNetwork: true, allowedHosts: ["127.0.0.1"] } });
    await expect(spawnProbe({ ...invocation, policy: { ...invocation.policy, filesystem: { read: [], write: ["/tmp"] } } }, {}, adapter)).rejects.toMatchObject({ code: "INVALID_INTERNAL_TRAFFIC_PROBE" });
  });
});

test("expands a tilde cwd, recovers a missing implicit cwd, and rejects missing explicit cwd", async () => {
  const mod = await loadContract("execution");
  const resolveCwd = requiredExport<ResolveExecutionWorkingDirectory>(mod, "resolveExecutionWorkingDirectory");
  const missing = join(tmpdir(), `mxc-missing-cwd-${crypto.randomUUID()}`);
  const home = await mkdtemp(join(tmpdir(), "mxc-test-home-"));
  try {
    await mkdir(join(home, "Projects"));
    expect(resolveCwd("~/Projects", missing, home)).toBe(join(home, "Projects"));
    expect(resolveCwd(undefined, missing, home)).toBe(home);
    expect(() => resolveCwd(missing, process.cwd(), home)).toThrow(expect.objectContaining({
      code: "WORKING_DIRECTORY_UNAVAILABLE",
      message: `Sandbox working directory does not exist or is not a directory: ${missing}`,
    }));
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

describe("pipe, PTY, cancellation, and failure lifecycle", () => {
  test("streams separated pipe output and reports exit code and wall time", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    const updates: Record<string, unknown>[] = [];
    const result = await execute({
      shell: "bash",
      command: "printf out; printf err >&2; exit 7",
      cwd: "/repo",
      env: {},
      spawn: async (_config: unknown, events: Record<string, (value: string) => void>) => {
        events.stdout!("out");
        events.stderr!("err");
        return { exitCode: 7, timedOut: false, cancelled: false, wallTimeMs: 42 };
      },
      onUpdate: (update: Record<string, unknown>) => updates.push(update),
    });
    expect(updates).toEqual([{ stream: "stdout", data: "out" }, { stream: "stderr", data: "err" }]);
    expect(result).toMatchObject({ exitCode: 7, timedOut: false, cancelled: false, wallTimeMs: 42 });
  });

  test("forwards PTY input, output, resize, cancel, and timeout through MXC", async () => {
    const mod = await loadContract("execution");
    const bridge = requiredExport<CreatePtyBridge>(mod, "createMxcPtyBridge");
    const calls: unknown[] = [];
    const pty = { write: (data: string) => calls.push(["write", data]), resize: (columns: number, rows: number) => calls.push(["resize", columns, rows]), kill: () => calls.push(["kill"]), onData: (handler: (data: string) => void) => handler("sandbox-output"), onExit: (handler: (event: unknown) => void) => handler({ exitCode: 130 }) };
    const overlay = { write: (data: string) => calls.push(["overlay-output", data]), onInput: (handler: (data: string) => void) => handler("user-input"), onResize: (handler: (size: Record<string, number>) => void) => handler({ columns: 120, rows: 40 }), onCancel: (handler: () => void) => handler() };
    bridge({ pty, overlay, timeoutMs: 5 });
    expect(calls).toContainEqual(["write", "user-input"]);
    expect(calls).toContainEqual(["resize", 120, 40]);
    expect(calls).toContainEqual(["overlay-output", "sandbox-output"]);
    expect(calls).toContainEqual(["kill"]);
  });

  test("headless PTY falls back to contained pipe mode with an explicit notice", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    let observedConfig: Record<string, any> | undefined;
    const result = await execute({ shell: "bash", command: "tty", pty: true, hasInteractiveOverlay: false, spawn: async (config: Record<string, any>) => { observedConfig = config; return { exitCode: 0, stdout: "not a tty", stderr: "" }; } });
    expect(observedConfig?.process.usePty).toBe(false);
    expect(result.notices).toContain("PTY requested in a headless context; running in MXC pipe mode.");
  });

  test("unsupported Darwin PTY falls back to a contained pipe", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    let observedUsePty: unknown;
    let ptySpawns = 0;
    const result = await execute({
      platform: "darwin",
      platformCapabilities: { pty: false },
      shell: "bash",
      command: "printf ok",
      pty: true,
      hasInteractiveOverlay: true,
      spawn: async (config: Record<string, any>) => {
        observedUsePty = config.process.usePty;
        return { exitCode: 0, stdout: "ok", stderr: "" };
      },
      spawnMxcPty: async () => {
        ptySpawns += 1;
        return { exitCode: 0 };
      },
    });
    expect(observedUsePty).toBe(false);
    expect(ptySpawns).toBe(0);
    expect(result.notices).toContain("PTY is unsupported by this MXC backend; running in contained pipe mode.");
  });

  test("never calls an unsandboxed client terminal for PTY", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    let clientTerminalRuns = 0;
    await execute({ shell: "bash", command: "printf ok", pty: true, hasInteractiveOverlay: true, spawnMxcPty: async () => ({ exitCode: 0 }), runClientTerminal: async () => { clientTerminalRuns += 1; } });
    expect(clientTerminalRuns).toBe(0);
  });

  test("kills the returned process on timeout and cancellation without host fallback", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    const events: string[] = [];
    const child = { kill: () => events.push("kill") };
    const result = await execute({ shell: "bash", command: "sleep 30", timeout: 1, spawn: async () => child, awaitExit: async () => ({ timedOut: true }), executeHost: async () => events.push("host") });
    expect(result).toMatchObject({ timedOut: true });
    expect(events).toEqual(["kill"]);
  });

  test("converts OMP timeout seconds to explicit MXC milliseconds", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    let observedConfig: Record<string, any> | undefined;
    await execute({ shell: "bash", command: "printf ok", timeout: 2.5, spawn: async (config: Record<string, any>) => { observedConfig = config; return { exitCode: 0 }; } });
    expect(observedConfig?.process.timeoutMs).toBe(2500);
  });

  test("adds Windows DACL setup grace without losing the requested command timeout", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    let observedConfig: Record<string, any> | undefined;
    const result = await execute({
      platform: "win32",
      shell: "powershell",
      discovered: ["C:\\Program Files\\PowerShell\\7\\pwsh.exe"],
      command: "Write-Output ok",
      timeout: 2.5,
      policy: { mxcOverrides: { fallback: { allowDaclMutation: true } } },
      platformCapabilities: { windowsBuild: 26200, tier: "appcontainer-dacl", hostPreparationVerified: true, nativeEnforcementAvailable: false },
      spawn: async (config: Record<string, any>) => { observedConfig = config; return { exitCode: 0 }; },
    });
    expect(observedConfig?.process.timeoutMs).toBe(32_500);
    expect(result).toMatchObject({ timeoutSeconds: 2.5, notices: [] });
    expect(result).not.toHaveProperty("requestedTimeoutSeconds");
  });

  test("starts the requested timeout after contained PowerShell signals readiness", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    const pendingExit = Promise.withResolvers<Record<string, unknown>>();
    let scheduledMilliseconds: number | undefined;
    let kills = 0;
    const result = await execute({
      platform: "win32",
      shell: "powershell",
      discovered: ["C:\\Program Files\\PowerShell\\7\\pwsh.exe"],
      command: "Start-Sleep -Seconds 30",
      timeout: 2.5,
      policy: { mxcOverrides: { fallback: { allowDaclMutation: true } } },
      platformCapabilities: { windowsBuild: 26200, tier: "appcontainer-dacl", hostPreparationVerified: true, nativeEnforcementAvailable: false },
      spawn: async (config: Record<string, any>, events: Record<string, (data: string) => void>) => {
        expect(scheduledMilliseconds).toBeUndefined();
        const payload = String(config.process.commandLine.at(-1));
        const bootstrap = Buffer.from(payload.split(" -EncodedCommand ").at(-1) ?? "", "base64").toString("utf16le");
        const marker = bootstrap.match(/__OMP_MXC_READY_[A-Za-z0-9_-]+__/)?.[0];
        expect(marker).toBeDefined();
        events.stderr!("DACL recovery: 1 file(s), 1 ACE(s) restored, 0 error(s)\n");
        events.stderr!(marker!.slice(0, 12));
        expect(scheduledMilliseconds).toBeUndefined();
        events.stderr!(`${marker!.slice(12)}\r\n`);
        return { kill: () => { kills += 1; } };
      },
      awaitExit: async () => pendingExit.promise,
      scheduleTimeout: (callback: () => void, milliseconds: number) => {
        scheduledMilliseconds = milliseconds;
        queueMicrotask(callback);
        return undefined;
      },
    });
    expect(scheduledMilliseconds).toBe(2500);
    expect(kills).toBeGreaterThan(0);
    expect(result).toMatchObject({ exitCode: 137, timedOut: true, timeoutSeconds: 2.5 });
    expect(result.preview).toBe("");
    expect(result.stderr).toBe("");
  });

  test("rejects macOS MXC timeouts below the native launch floor", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    await expect(execute({
      platform: "darwin",
      shell: "bash",
      command: "sleep 30",
      timeout: 0.4,
      spawn: async () => ({ exitCode: 0 }),
    })).rejects.toMatchObject({ code: "MXC_TIMEOUT_BELOW_PLATFORM_MINIMUM" });
  });

  test("default MXC adapter receives the prepared sanitized environment and timeout", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    let sdkPolicy: Record<string, any> | undefined;
    let spawnedConfig: Record<string, any> | undefined;
    const adapter = {
      version: "0.7.0",
      schemaVersion: "0.7.0-alpha",
      schemaVersions: ["0.7.0-alpha"],
      createConfigFromPolicy: async (policy: Record<string, any>) => { sdkPolicy = policy; return { process: {} }; },
      spawnSandboxFromConfig: async (config: Record<string, any>) => { spawnedConfig = config; return { exitCode: 0 }; },
      getPlatformSupport: () => ({}),
      reprobePlatformSupport: () => ({}),
    };
    await execute({
      shell: "bash",
      command: "printf ok",
      timeout: 2.5,
      hostEnvironment: { PATH: "/usr/bin", LANG: "en_US.UTF-8", API_TOKEN: "omit-me" },
      env: { GREETING: "héllo" },
      environmentPolicy: { approvedSensitiveNames: [] },
      mxcAdapter: adapter,
    });
    expect(sdkPolicy?.timeoutMs).toBe(2500);
    expect(spawnedConfig?.process).toMatchObject({ timeout: 2500, cwd: process.cwd() });
    expect(spawnedConfig?.process.env).toContain("PATH=/usr/bin");
    expect(spawnedConfig?.process.env).toContain("LANG=en_US.UTF-8");
    expect(spawnedConfig?.process.env).toContain("GREETING=héllo");
    expect(spawnedConfig?.process.env.some((entry: string) => entry.startsWith("API_TOKEN="))).toBe(false);
  });

  test("requires critical confirmation before every contained launch", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    let spawned = false;
    await expectAsyncFailureCode(() => execute({ shell: "bash", command: "rm -rf /", confirmCritical: async () => false, spawn: async () => { spawned = true; return { exitCode: 0 }; } }), "CRITICAL_COMMAND_DECLINED");
    expect(spawned).toBe(false);
    await expectAsyncFailureCode(() => execute({ shell: "powershell", command: "Remove-Item C:\\ -Recurse -Force", confirmCritical: async () => false, spawn: async () => { spawned = true; return { exitCode: 0 }; } }), "CRITICAL_COMMAND_DECLINED");
    expect(spawned).toBe(false);
  });

  test("launch-failure outside choice uses exact-call approval before host execution", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    const displayed: Record<string, unknown>[] = [];
    const result = await execute({
      shell: "bash", command: "printf safe", cwd: "/repo", ownerId: "A1",
      spawn: async () => { throw new Error("launch failed"); },
      chooseFailure: async () => "Run this command outside once",
      approveOutsideOnce: async (details: Record<string, unknown>) => { displayed.push(details); return true; },
      executeHost: async () => ({ exitCode: 0, stdout: "host" }),
    });
    expect(result).toMatchObject({ outsideSandbox: true, launchFailed: true, exitCode: 0 });
    expect(displayed).toHaveLength(1);
    expect(displayed[0]).toMatchObject({ command: "printf safe", cwd: "/repo", requestingAgent: "A1", scope: "exact-call-once" });
  });

  test("surfaces the four-choice dialog on launch error and performs no automatic retry", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    const events: string[] = [];
    let failure: Record<string, unknown> | undefined;
    const result = await execute({ platform: "win32", shell: "bash", discovered: ["C:\\Program Files\\Git\\bin\\bash.exe"], command: "touch /tmp/host", spawn: async () => { events.push("mxc"); throw Object.assign(new Error("name too long"), { code: "ENAMETOOLONG" }); }, chooseFailure: async (choices: string[], details: Record<string, unknown>) => { events.push(...choices); failure = details; return "Cancel"; }, executeHost: async () => events.push("host") });
    expect(result).toMatchObject({ cancelled: true, launchFailed: true });
    expect(events).toEqual(["mxc", "Retry sandbox", "Run this command outside once", "Disable sandbox for this conversation", "Cancel"]);
    expect(failure).toMatchObject({ name: "Error", message: "name too long", code: "ENAMETOOLONG" });
  });

  test("preserves the one-argument Unix launch-failure callback", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    let argumentCount = 0;
    const result = await execute({
      platform: "linux",
      shell: "bash",
      configuredShell: "/bin/bash",
      command: "false",
      spawn: async () => { throw new Error("launch failed"); },
      chooseFailure: async (...arguments_: unknown[]) => { argumentCount = arguments_.length; return "Cancel"; },
    });
    expect(result).toMatchObject({ cancelled: true, launchFailed: true });
    expect(argumentCount).toBe(1);
  });
});

describe("async ownership and existing job integration", () => {
  test("registers explicit async work in the uniquely matched scoped manager with owner ID", async () => {
    const mod = await loadContract("jobs");
    const register = requiredExport<RegisterAsyncJob>(mod, "registerMxcJob");
    const calls: unknown[] = [];
    const manager = { register: (...args: unknown[]) => { calls.push(args); return { id: "J1" }; } };
    const liveMatches = [{ sessionId: "S1", agentId: "A1", scopedManager: manager, live: true }];
    expect(await register({ tool: "bash", sessionId: "S1", agentId: "A1", scopedManager: manager, liveMatches, process: { pid: 42 } })).toMatchObject({ id: "J1" });
    expect(calls).toEqual([["bash", { pid: 42 }, { ownerId: "A1" }]]);
  });

  test("rejects async execution without safe manager or owner mapping", async () => {
    const mod = await loadContract("jobs");
    const register = requiredExport<RegisterAsyncJob>(mod, "registerMxcJob");
    await expect(register({ tool: "bash", sessionId: "S1", agentId: "A1", scopedManager: null, process: {} })).rejects.toMatchObject({ code: "SCOPED_JOB_MANAGER_REQUIRED" });
    await expect(register({ tool: "bash", sessionId: "S1", agentId: null, scopedManager: { register() {} }, process: {} })).rejects.toMatchObject({ code: "ASYNC_OWNER_REQUIRED" });
    await expectAsyncFailureCode(() => register({ tool: "bash", sessionId: "S1", agentId: "A1", scopedManager: { register: () => ({ id: "J1" }) }, process: {} }), "SCOPED_JOB_OWNERSHIP_MISMATCH");
  });

  test("supports explicit async and configured auto-background through the unchanged job surface", async () => {

    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    for (const input of [{ async: true, elapsedMs: 0 }, { async: false, elapsedMs: 5001, autoBackgroundThresholdMs: 5000 }]) {
      const managerCalls: unknown[] = [];
      const manager = { register: (...args: unknown[]) => { managerCalls.push(args); return { id: "J1" }; } };
      const result = await execute({ ...input, shell: "bash", command: "long-command", ownerId: "A1", sessionId: "S1", scopedManager: manager, liveMatches: [{ sessionId: "S1", agentId: "A1", scopedManager: manager, live: true }], spawn: async () => ({ pid: 42 }) });
      expect(result).toMatchObject({ backgrounded: true, jobId: "J1" });
      expect(managerCalls[0]).toEqual(["bash", expect.anything(), { ownerId: "A1" }]);
    }
  });

  test("background job owns streams artifact completion cancellation and timeout", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    const root = await mkdtemp(join(tmpdir(), "mxc-job-owned-"));
    const artifactPath = join(root, "async-output");
    try {
      const listeners = new Map<string, ((...values: unknown[]) => void)[]>();
      let kills = 0;
      const child = {
        stdout: { on: (event: string, listener: (data: unknown) => void) => { if (event === "data") listeners.set("stdout", [listener]); } },
        stderr: { on: (event: string, listener: (data: unknown) => void) => { if (event === "data") listeners.set("stderr", [listener]); } },
        once: (event: string, listener: (...values: unknown[]) => void) => listeners.set(event, [...(listeners.get(event) ?? []), listener]),
        kill: () => { kills += 1; },
      };
      let registered: Record<string, any> | undefined;
      const manager = { register: (_tool: string, process: unknown) => { registered = process as Record<string, any>; return { id: "J-owned" }; } };
      const result = await execute({
        platform: "linux", shell: "bash", command: "long", async: true, timeout: 0.01,
        ownerId: "A1", sessionId: "S1", scopedManager: manager,
        liveMatches: [{ sessionId: "S1", agentId: "A1", scopedManager: manager, live: true }],
        sessionManager: { allocateArtifactPath: async () => ({ id: "ART-ASYNC", path: artifactPath }) },
        spawn: async () => child,
      });
      expect(result).toMatchObject({ backgrounded: true, jobId: "J-owned", artifact: "artifact://ART-ASYNC" });
      listeners.get("stdout")?.[0]?.("before-timeout\n");
      const completed = await registered?.completion;
      expect(completed).toMatchObject({ timedOut: true, artifact: "artifact://ART-ASYNC" });
      expect(kills).toBeGreaterThan(0);
      expect(await readFile(artifactPath, "utf8")).toBe("before-timeout\n");
      expect(typeof registered?.cancel).toBe("function");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("uses existing job list, poll, cancel, progress, and completion delivery", async () => {
    const mod = await loadContract("jobs");
    const register = requiredExport<RegisterAsyncJob>(mod, "registerMxcJob");
    const calls: string[] = [];
    const manager = {
      register: () => ({ id: "J1" }),
      list: (ownerId: string) => { calls.push(`list:${ownerId}`); return [{ id: "J1" }]; },
      poll: (id: string, ownerId: string) => { calls.push(`poll:${id}:${ownerId}`); return { progress: "half" }; },
      cancel: (id: string, ownerId: string) => { calls.push(`cancel:${id}:${ownerId}`); return true; },
      deliverCompletion: (id: string, ownerId: string) => calls.push(`complete:${id}:${ownerId}`),
    };
    const job = await register({ tool: "bash", sessionId: "S1", agentId: "A1", scopedManager: manager, liveMatches: [{ sessionId: "S1", agentId: "A1", scopedManager: manager, live: true }], process: { pid: 42 } });
    job.list(); job.poll(); job.cancel(); job.deliverCompletion();
    expect(calls).toEqual(["list:A1", "poll:J1:A1", "cancel:J1:A1", "complete:J1:A1"]);
  });
});


  test("connects production stream output to preview metadata and a lossless allocated artifact", async () => {
    const mod = await loadContract("execution");
    const execute = requiredExport<ExecuteShell>(mod, "executeShell");
    const root = await mkdtemp(join(tmpdir(), "mxc-output-"));
    const artifactPath = join(root, "full-output");
    try {
      const result = await execute({
        shell: "bash", command: "emit", maxColumns: 8, maxLines: 2,
        sessionManager: { allocateArtifactPath: async () => ({ id: "ART1", path: artifactPath }) },
        spawn: async (_config: unknown, events: Record<string, (data: string) => void>) => {
          events.stdout!("first-line\n");
          events.stderr!("second-line\n");
          return { exitCode: 7 };
        },
      });
      expect(result).toMatchObject({ truncated: true, artifact: "artifact://ART1", details: { exitCode: 7, truncated: true } });
      expect(await readFile(artifactPath, "utf8")).toBe("first-line\nsecond-line\n");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
describe("streaming output and lossless artifacts", () => {
  test("applies column and head-tail limits while preserving byte-identical full output", async () => {
    const mod = await loadContract("output");
    const render = requiredExport<RenderOutput>(mod, "renderMxcOutput");
    const raw = Buffer.from(`first\n${"x".repeat(200)}\nmiddle\nlast\n`, "utf8");
    const artifactWrites: Uint8Array[] = [];
    const result = await render({ rawChunks: [raw.subarray(0, 17), raw.subarray(17)], maxColumns: 40, maxLines: 3, allocateArtifactPath: async () => ({ id: "ART1", path: "/artifacts/ART1" }), writeArtifact: async (_path: string, chunk: Uint8Array) => artifactWrites.push(chunk) });
    expect(result.preview.split("\n").length).toBeLessThanOrEqual(4);
    expect(result.preview).toContain("first");
    expect(result.preview).toContain("last");
    expect(result).toMatchObject({ truncated: true, artifact: "artifact://ART1" });
    expect(Buffer.concat(artifactWrites).equals(raw)).toBe(true);
  });

  test("reports exit, timeout, cancellation, wall time, and truncation metadata", async () => {
    const mod = await loadContract("output");
    const render = requiredExport<RenderOutput>(mod, "renderMxcOutput");
    const result = await render({ rawChunks: [Buffer.from("out")], exitCode: 137, timedOut: true, cancelled: true, wallTimeMs: 900, maxLines: 10 });
    expect(result.details).toEqual({ exitCode: 137, timedOut: true, cancelled: true, wallTimeMs: 900, truncated: false });
  });

  test("keeps deterministic stdout/stderr ordering in preview and lossless stream artifacts", async () => {
    const mod = await loadContract("output");
    const render = requiredExport<RenderOutput>(mod, "renderMxcOutput");
    const result = await render({ events: [{ sequence: 1, stream: "stdout", data: "A" }, { sequence: 2, stream: "stderr", data: "B" }, { sequence: 3, stream: "stdout", data: "C" }], maxLines: 10 });
    expect(result.preview).toBe("ABC");
    expect(result.streams).toEqual({ stdout: "AC", stderr: "B" });
  });
});
