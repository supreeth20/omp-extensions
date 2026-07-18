import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { accessSync, constants, existsSync, readdirSync, realpathSync, statSync } from "node:fs";
import { delimiter, dirname, join, normalize, sep } from "node:path";
import * as installedMxcSdk from "@microsoft/mxc-sdk";
import sdkPackageMetadata from "../../node_modules/@microsoft/mxc-sdk/package.json";
import * as installedMxcPlatform from "../../node_modules/@microsoft/mxc-sdk/dist/platform.js";
import { buildInternalTrafficProbeConfig, buildProcessConfig, createEffectivePolicy, MXC_SCHEMA_VERSION, toSdkCommandLine, toSdkEnvironment, toSdkPolicy, type MxcInvocationConfig } from "./config";

const REQUIRED_SDK_VERSION = /^0\.7\.0(?:[-+]|$)/;

type UnknownRecord = Record<string, unknown>;
type CreateConfig = (policy: UnknownRecord, backend: "process", containerId: string) => UnknownRecord | Promise<UnknownRecord>;
type SpawnConfig = (config: UnknownRecord, options?: UnknownRecord, workingDirectory?: string) => unknown | Promise<unknown>;

export interface MxcSdkAdapter {
  readonly version: string;
  readonly schemaVersion: typeof MXC_SCHEMA_VERSION;
  readonly schemaVersions: readonly [typeof MXC_SCHEMA_VERSION];
  createConfigFromPolicy: CreateConfig;
  readonly executablePath?: string;
  spawnSandboxFromConfig: SpawnConfig;
  getPlatformSupport(): UnknownRecord;
  reprobePlatformSupport(): UnknownRecord;
  discoverRequiredReadonlyPaths(): string[];
}

export class MxcSdkError extends Error {
  readonly code: string;
  readonly details?: UnknownRecord;

  constructor(code: string, message: string, details?: UnknownRecord) {
    super(message);
    this.name = "MxcSdkError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

let loadedSdk: Promise<MxcSdkAdapter> | undefined;

function record(value: unknown): UnknownRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as UnknownRecord : {};
}
function executableName(platform: NodeJS.Platform): string | undefined {
  if (platform === "darwin") return "mxc-exec-mac";
  if (platform === "win32") return "wxc-exec.exe";
  if (platform === "linux") return "lxc-exec";
  return undefined;
}

function executableFile(path: string, platform: NodeJS.Platform): boolean {
  try {
    if (!statSync(path).isFile()) return false;
    if (platform !== "win32") accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function resolveInstalledMxcExecutable(
  platform: NodeJS.Platform = process.platform,
  architecture: NodeJS.Architecture = process.arch,
  environment: NodeJS.ProcessEnv = process.env,
): string | undefined {
  const name = executableName(platform);
  if (!name) return undefined;
  const sdkArchitecture = architecture === "arm64" ? "arm64" : "x64";
  const candidates: string[] = [];
  if (typeof environment.MXC_BIN_DIR === "string" && environment.MXC_BIN_DIR.length > 0) {
    candidates.push(join(environment.MXC_BIN_DIR, sdkArchitecture, name));
  }
  try {
    const packageJson = createRequire(import.meta.url).resolve("@microsoft/mxc-sdk/package.json");
    candidates.push(join(dirname(packageJson), "bin", sdkArchitecture, name));
  } catch {
    // The normal SDK validation reports a missing dependency if package resolution fails.
  }
  return candidates.find((candidate) => executableFile(candidate, platform));
}

function withInstalledMxcBinDirectory<T>(action: () => T, executablePath: string | undefined): T {
  if (!executablePath) return action();
  const prior = process.env.MXC_BIN_DIR;
  process.env.MXC_BIN_DIR = dirname(dirname(executablePath));
  try {
    return action();
  } finally {
    if (prior === undefined) delete process.env.MXC_BIN_DIR;
    else process.env.MXC_BIN_DIR = prior;
  }
}

async function sdkVersion(module: UnknownRecord): Promise<string> {
  if (typeof module.version === "string") return module.version;
  const metadata = record(module.metadata);
  if (typeof metadata.version === "string") return metadata.version;
  const packageMetadata = record(sdkPackageMetadata);
  if (typeof packageMetadata.version === "string") return packageMetadata.version;
  throw new MxcSdkError("MXC_SDK_VERSION_UNVERIFIED", "The installed MXC SDK does not expose verifiable package metadata");
}

async function importSdk(): Promise<UnknownRecord> {
  return record(installedMxcSdk);
}

function within(root: string, candidate: string): boolean {
  const normalizedRoot = normalize(root);
  const normalizedCandidate = normalize(candidate);
  return normalizedCandidate === normalizedRoot || normalizedCandidate.startsWith(`${normalizedRoot}${sep}`);
}

export function filterRequiredReadonlyPaths(paths: string[], input: Record<string, string> = {}): string[] {
  const platform = input.platform ?? process.platform;
  const executableDirectory = normalize(input.executableDirectory ?? dirname(process.execPath));
  const trustedRoots = platform === "darwin"
    ? ["/bin", "/sbin", "/usr", "/System", "/opt/homebrew", "/var/run/com.apple.security.cryptexd"]
    : platform === "win32"
      ? [process.env.SystemRoot ?? "C:\\Windows", process.env.ProgramFiles ?? "C:\\Program Files"]
      : ["/bin", "/sbin", "/usr", "/lib", "/lib64"];
  return [...new Set(paths.filter((path) => {
    if (typeof path !== "string" || path.length === 0) return false;
    const candidate = normalize(path);
    return candidate === executableDirectory || trustedRoots.some((root) => within(root, candidate));
  }))];
}

export function runtimeRootForExecutableTarget(target: string, platform: string): string | undefined {
  const normalized = normalize(target);
  if (platform === "darwin") return normalized.match(/^(\/opt\/homebrew\/Cellar\/[^/]+\/[^/]+)(?:\/|$)/)?.[1];
  if (platform === "linux") return normalized.match(/^(\/nix\/store\/[^/]+)(?:\/|$)/)?.[1];
  return undefined;
}



function homebrewRuntimePackageRoots(): string[] {
  const opt = "/opt/homebrew/opt";
  try {
    return [...new Set(readdirSync(opt, { withFileTypes: true }).flatMap((entry): string[] => {
      try {
        const target = realpathSync(join(opt, entry.name));
        const root = runtimeRootForExecutableTarget(target, "darwin");
        return root ? [root] : [];
      } catch {
        return [];
      }
    }))];
  } catch {
    return [];
  }
}

export function resolveRequiredReadonlyPaths(paths: string[], input: Record<string, unknown> = {}): string[] {
  const platform = typeof input.platform === "string" ? input.platform : process.platform;
  const executableDirectory = typeof input.executableDirectory === "string" ? input.executableDirectory : dirname(process.execPath);
  const pathEntries = new Set((Array.isArray(input.pathEntries) ? input.pathEntries : []).filter((path): path is string => typeof path === "string").map(normalize));
  const trustedDirectories = new Set(filterRequiredReadonlyPaths(paths, { platform, executableDirectory }).map(normalize));
  const resolved: string[] = [];
  for (const path of paths) {
    const directory = normalize(path);
    const pathEntry = pathEntries.has(directory);
    const trusted = trustedDirectories.has(directory) || !pathEntry;
    if (trusted) resolved.push(directory);
    if (!pathEntry) continue;
    try {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        if (!entry.isFile() && !entry.isSymbolicLink()) continue;
        const candidate = join(directory, entry.name);
        if (entry.isSymbolicLink()) {
          try {
            const runtimeRoot = runtimeRootForExecutableTarget(realpathSync(candidate), platform);
            if (runtimeRoot) resolved.push(runtimeRoot);
          } catch {
            // Ignore broken executable symlinks.
          }
        }
        if (trusted) continue;
        const windowsExecutable = platform === "win32" && /\.(?:exe|com|cmd|bat|ps1)$/i.test(entry.name);
        if (!windowsExecutable) {
          try {
            accessSync(candidate, constants.X_OK);
          } catch {
            continue;
          }
        }
        if (statSync(candidate).isFile()) resolved.push(candidate);
      }
    } catch {
      // A disappearing or unreadable PATH entry contributes no default grant.
    }
  }
  return [...new Set(resolved)];
}

export function pruneLegacyDiscoveredPathGrants(filesystem: Record<string, unknown>, input: Record<string, unknown>): Record<string, unknown> {
  const pathEntries = Array.isArray(input.pathEntries) ? input.pathEntries.filter((path): path is string => typeof path === "string") : [];
  const required = new Set(filterRequiredReadonlyPaths(pathEntries, {
    platform: typeof input.platform === "string" ? input.platform : process.platform,
    executableDirectory: typeof input.executableDirectory === "string" ? input.executableDirectory : dirname(process.execPath),
  }).map(normalize));
  const cwd = typeof input.cwd === "string" ? normalize(input.cwd) : "";
  const stale = new Set(pathEntries.map(normalize).filter((path) => path !== cwd && !required.has(path)));
  const removed: string[] = [];
  const read = (Array.isArray(filesystem.read) ? filesystem.read : []).filter((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return true;
    const grant = entry as Record<string, unknown>;
    const path = typeof grant.path === "string" ? normalize(grant.path) : "";
    const legacyDirectory = grant.recursive === true && (grant.kind === "directory" || grant.kind === undefined);
    if (!legacyDirectory || !stale.has(path)) return true;
    removed.push(String(grant.path));
    return false;
  });
  return { filesystem: { ...filesystem, read }, removed };
}

export async function loadMxcSdk(): Promise<MxcSdkAdapter> {
  loadedSdk ??= (async () => {
    const module = await importSdk();
    const version = await sdkVersion(module);
    if (!REQUIRED_SDK_VERSION.test(version)) {
      throw new MxcSdkError("MXC_SDK_VERSION_UNSUPPORTED", `MXC SDK ${version} is unsupported; verified version 0.7.0 is required`, { version });
    }
    if (typeof module.createConfigFromPolicy !== "function" || typeof module.spawnSandboxFromConfig !== "function" || typeof module.getPlatformSupport !== "function" || typeof module.getAvailableToolsPolicy !== "function") {
      throw new MxcSdkError("MXC_SDK_API_UNAVAILABLE", "MXC SDK 0.7.0 createConfigFromPolicy/spawnSandboxFromConfig/getPlatformSupport/getAvailableToolsPolicy APIs are required");
    }
    const executablePath = resolveInstalledMxcExecutable();
    return {
      version,
      schemaVersion: MXC_SCHEMA_VERSION,
      schemaVersions: [MXC_SCHEMA_VERSION],
      ...(executablePath ? { executablePath } : {}),
      createConfigFromPolicy: module.createConfigFromPolicy as CreateConfig,
      spawnSandboxFromConfig: module.spawnSandboxFromConfig as SpawnConfig,
      getPlatformSupport: () => withInstalledMxcBinDirectory(
        () => record(installedMxcPlatform.getPlatformSupport()),
        executablePath,
      ),
      reprobePlatformSupport: () => withInstalledMxcBinDirectory(() => {
        installedMxcPlatform._resetPlatformSupportCache();
        if (process.platform !== "win32") return record(installedMxcPlatform.getPlatformSupport());
        const executable = installedMxcPlatform.findWxcExecutable();
        if (!executable) return record(installedMxcPlatform.getPlatformSupport());
        installedMxcPlatform._setProbeRunner(() => execFileSync(executable, ["--probe"], {
          timeout: 30_000,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }));
        try {
          return record(installedMxcPlatform.getPlatformSupport());
        } finally {
          installedMxcPlatform._setProbeRunner(null);
        }
      }, executablePath),
      discoverRequiredReadonlyPaths: () => {
        const discovered = record((module.getAvailableToolsPolicy as (environment?: NodeJS.ProcessEnv, options?: UnknownRecord) => unknown)(process.env, process.platform === "win32" ? { containerType: "processcontainer" } : undefined));
        const tools = Array.isArray(discovered.readonlyPaths)
          ? discovered.readonlyPaths.filter((path): path is string => typeof path === "string" && path.length > 0)
          : [];
        const requiredTools = resolveRequiredReadonlyPaths(tools, { platform: process.platform, executableDirectory: dirname(process.execPath), pathEntries: String(process.env.PATH ?? "").split(delimiter).filter(Boolean) });
        const osLibraries = process.platform === "darwin"
          ? ["/usr/lib", "/System/Library"]
          : process.platform === "win32"
            ? [join(process.env.SystemRoot ?? "C:\\Windows", "System32")]
            : ["/lib", "/usr/lib"];
        const packageRuntime = process.platform === "darwin"
          ? [...homebrewRuntimePackageRoots(), "/opt/homebrew/lib/node_modules", "/opt/homebrew/etc/openssl@3", "/opt/homebrew/etc/ca-certificates"]
          : [];
        return [...new Set([...requiredTools, dirname(process.execPath), ...osLibraries, ...packageRuntime].filter((path) => existsSync(path)))];
      },
    };
  })();
  try {
    return await loadedSdk;
  } catch (error) {
    loadedSdk = undefined;
    throw error;
  }
}

function isPreparedInvocation(input: Record<string, unknown>): input is MxcInvocationConfig {
  const processConfig = record(input.process);
  return input.version === MXC_SCHEMA_VERSION
    && input.backend === "process"
    && typeof input.containerId === "string"
    && Array.isArray(processConfig.commandLine)
    && typeof processConfig.cwd === "string"
    && processConfig.env !== null
    && typeof processConfig.env === "object";
}

function invocationConfig(input: Record<string, unknown>): MxcInvocationConfig {
  return isPreparedInvocation(input) ? structuredClone(input) : buildProcessConfig(input);
}

export async function createSdkInvocationConfig(
  input: Record<string, unknown>,
  adapter?: MxcSdkAdapter,
): Promise<UnknownRecord> {
  const sdk = adapter ?? await loadMxcSdk();
  const invocation = invocationConfig(input);
  const effectivePolicy = createEffectivePolicy(invocation.policy);
  const sdkPolicy = await toSdkPolicy(effectivePolicy, invocation.process.timeoutMs);
  const created = record(await sdk.createConfigFromPolicy(sdkPolicy, "process", invocation.containerId));
  const sdkProcess = record(created.process);
  return {
    ...created,
    version: MXC_SCHEMA_VERSION,
    containerId: invocation.containerId,
    process: {
      ...sdkProcess,
      commandLine: toSdkCommandLine(invocation.process.commandLine, invocation.platform),
      cwd: invocation.process.cwd,
      env: toSdkEnvironment(invocation.process.env),
      ...(invocation.process.timeoutMs === undefined ? {} : { timeout: invocation.process.timeoutMs }),
    },
    ...(invocation.fallback ? { fallback: invocation.fallback } : {}),
    ...(invocation.seatbelt ? { seatbelt: { ...record(created.seatbelt), ...invocation.seatbelt } } : {}),
  };
}

export async function spawnMxcFromInvocation(
  input: Record<string, unknown>,
  options: Record<string, unknown> = {},
  adapter?: MxcSdkAdapter,
): Promise<unknown> {
  const sdk = adapter ?? await loadMxcSdk();
  const invocation = invocationConfig(input);
  const config = await createSdkInvocationConfig(input, sdk);
  // One-shot MXC ignores AbortSignal. Callers must kill the returned ChildProcess/IPty on cancel or timeout.
  const { signal: _ignoredSignal, ...supportedOptions } = options;
  const executablePath = typeof supportedOptions.executablePath === "string" ? undefined : sdk.executablePath;
  return sdk.spawnSandboxFromConfig(config, { ...supportedOptions, ...(executablePath ? { executablePath } : {}), usePty: invocation.process.usePty }, invocation.process.cwd);
}

export async function spawnMxcTrafficProbeFromInvocation(
  input: Record<string, unknown>,
  options: Record<string, unknown> = {},
  adapter?: MxcSdkAdapter,
): Promise<unknown> {
  const sdk = adapter ?? await loadMxcSdk();
  const invocation = buildInternalTrafficProbeConfig(input);
  const config = await createSdkInvocationConfig(invocation, sdk);
  const { signal: _ignoredSignal, ...supportedOptions } = options;
  const executablePath = typeof supportedOptions.executablePath === "string" ? undefined : sdk.executablePath;
  return sdk.spawnSandboxFromConfig(config, { ...supportedOptions, ...(executablePath ? { executablePath } : {}), usePty: false }, invocation.process.cwd);
}

export function clearMxcSdkCacheForReprobe(): void {
  loadedSdk = undefined;
}
