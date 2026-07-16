import { stat } from "node:fs/promises";
import { join } from "node:path";
import { canonicalizeTarget } from "../policy/paths";
import { assertMacosSeatbeltPolicy } from "../platform/macos";
import { assertWindowsNetworkPolicy } from "../platform/windows";
import { resolveNetworkPolicy } from "../policy/network";
import { createWindowsProcessContainerOptions } from "../platform/windows";

export const MXC_SCHEMA_VERSION = "0.7.0-alpha" as const;

export type ProcessEnvironment = Readonly<Record<string, string>>;

export interface ShellLaunch {
  executable: string;
  args: readonly string[];
  dialect?: "posix" | "powershell7" | "cmd";
  ui?: Readonly<{
    allowWindows: boolean;
    clipboardRead: boolean;
    clipboardWrite: boolean;
    inputInjection: boolean;
  }>;
}

/** Fields present in the stable schema but missing from the 0.7.0 SDK declarations. */
export interface StableSchemaExtensions {
  fallback?: { allowDaclMutation: boolean };
  seatbelt?: { guiAccess?: boolean; launchMethod?: "direct" | "sandbox-exec" };
}

export type MxcInvocationConfig = Record<string, unknown> & StableSchemaExtensions & {
  version: typeof MXC_SCHEMA_VERSION;
  backend: "process";
  containerId: string;
  platform: string;
  policy: Record<string, unknown>;
  process: {
    commandLine: string[];
    cwd: string;
    env: Record<string, string>;
    inheritEnvironment: false;
    timeoutMs?: number;
    usePty: boolean;
  };
  ui: {
    allowWindows: boolean;
    clipboardRead: boolean;
    clipboardWrite: boolean;
    inputInjection: boolean;
  };
};

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function stringEnvironment(value: unknown): Record<string, string> {
  const source = record(value);
  const environment: Record<string, string> = {};
  for (const [name, item] of Object.entries(source)) {
    if (typeof item === "string") environment[name] = item;
  }
  return environment;
}
function windowsFallback(policy: Record<string, unknown>, capabilities: Record<string, unknown>): { allowDaclMutation: boolean } {
  const requested = record(record(policy.mxcOverrides).fallback).allowDaclMutation === true;
  if (!requested) return { allowDaclMutation: false };
  const windowsOptions = createWindowsProcessContainerOptions({
    windowsBuild: capabilities.windowsBuild,
    tier: capabilities.tier,
    nativeEnforcementAvailable: capabilities.nativeEnforcementAvailable,
    hostPreparationVerified: capabilities.hostPreparationVerified,
    mode: "compatibility",
    explicitDaclOptIn: true,
  });
  return record(windowsOptions.fallback) as { allowDaclMutation: boolean };
}

export function assertPlatformPolicySupported(policy: Record<string, unknown>, platform: string, capabilities: Record<string, unknown>): void {
  if (platform === "win32") {
    assertWindowsNetworkPolicy(policy, capabilities);
    windowsFallback(policy, capabilities);
    return;
  }
  if (platform === "darwin") {
    assertMacosSeatbeltPolicy(policy, { ...capabilities, allowCrossPlatformPlanning: process.platform !== "darwin" });
    return;
  }
  const network = record(policy.network);
  if (network.localNetwork === true && capabilities.independentLocalNetwork !== true) {
    throw Object.assign(new Error("Local-network grants require a successful native traffic probe attestation"), { code: "LOCAL_NETWORK_CAPABILITY_UNPROVEN" });
  }
}

export function createEffectivePolicy(value: unknown): Record<string, unknown> {
  const supplied = structuredClone(record(value));
  const filesystem = record(supplied.filesystem);
  const network = record(supplied.network);
  const ui = record(supplied.ui);
  return {
    ...supplied,
    version: MXC_SCHEMA_VERSION,
    filesystem: {
      read: [],
      write: [],
      ...filesystem,
    },
    network: {
      internet: false,
      localNetwork: false,
      ...network,
    },
    ui: {
      allowWindows: false,
      clipboardRead: false,
      clipboardWrite: false,
      inputInjection: false,
      ...ui,
    },
  };
}

function quoteCmdArgument(value: string): string {
  return `"${value.replaceAll("\"", "\"\"")}"`;
}

function processCommandLine(shell: ShellLaunch, command: string, cwd: string, platform: string, readyMarker?: string): string[] {
  if (platform !== "win32" || shell.dialect !== "powershell7") return [shell.executable, ...shell.args, command];
  const powershellArguments = shell.args.filter((argument) => argument.toLowerCase() !== "-command").join(" ");
  const executable = quoteCmdArgument(shell.executable);
  const workingDirectoryLiteral = cwd.replaceAll("'", "''");
  const userCommand = Buffer.from(command, "utf16le").toString("base64");
  const removeItemCompatibility = `function global:Remove-Item {[CmdletBinding(SupportsShouldProcess=$true,DefaultParameterSetName='Path')]param([Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='Path')][string[]]$Path,[Alias('PSPath','LP')][Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='LiteralPath')][string[]]$LiteralPath,[string]$Filter,[string[]]$Include,[string[]]$Exclude,[switch]$Recurse,[switch]$Force,[pscredential]$Credential)process{$bound=@{};foreach($entry in $PSBoundParameters.GetEnumerator()){$bound[$entry.Key]=$entry.Value};$key=if($PSCmdlet.ParameterSetName -eq 'LiteralPath'){'LiteralPath'}else{'Path'};$bound[$key]=@($bound[$key]|ForEach-Object{if([IO.Path]::IsPathRooted($_) -or $_ -match '^[^\\/:]+:'){$_}else{[IO.Path]::GetFullPath($_,[Environment]::CurrentDirectory)}});Microsoft.PowerShell.Management\\Remove-Item @bound}}`;
  const readySignal = readyMarker ? `[Console]::Error.WriteLine('${readyMarker.replaceAll("'", "''")}'); [Console]::Error.Flush(); ` : "";
  const bootstrap = `New-PSDrive -Name MXC -PSProvider FileSystem -Root '${workingDirectoryLiteral}' | Out-Null; Set-Location MXC:\\; [Environment]::CurrentDirectory='${workingDirectoryLiteral}'; ${removeItemCompatibility}; $script=[ScriptBlock]::Create([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${userCommand}'))); ${readySignal}& $script; $success=$?; if($LASTEXITCODE -is [int]){exit $LASTEXITCODE}; if(-not $success){exit 1}`;
  const launcher = `${executable} ${powershellArguments} -EncodedCommand ${Buffer.from(bootstrap, "utf16le").toString("base64")}`;
  return [join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe"), "/d", "/s", "/c", launcher];
}

function buildProcessConfigInternal(input: Record<string, unknown>, internalTrafficProbe: boolean): MxcInvocationConfig {
  const shell = record(input.shell) as unknown as ShellLaunch;
  if (typeof shell.executable !== "string" || !Array.isArray(shell.args)) {
    throw Object.assign(new Error("A resolved shell executable and argument vector are required"), { code: "SHELL_NOT_RESOLVED" });
  }
  const cwd = typeof input.cwd === "string" && input.cwd.length > 0 ? input.cwd : process.cwd();
  const platform = typeof input.platform === "string" ? input.platform : process.platform;
  const capabilities = record(input.platformCapabilities);
  const requestedPolicy = createEffectivePolicy(input.policy);
  const networkResolution = resolveNetworkPolicy(record(requestedPolicy.network), capabilities);
  const policy = platform === "darwin" && networkResolution.activation === "ready"
    ? { ...requestedPolicy, network: record(networkResolution.effective) }
    : requestedPolicy;
  if (!internalTrafficProbe) assertPlatformPolicySupported(policy, platform, capabilities);
  const configuredUi = record(policy.ui);
  const shellUi = shell.ui ?? { allowWindows: false, clipboardRead: false, clipboardWrite: false, inputInjection: false };
  const ui = {
    allowWindows: shellUi.allowWindows === true || configuredUi.allowWindows === true,
    clipboardRead: configuredUi.clipboardRead === true,
    clipboardWrite: configuredUi.clipboardWrite === true,
    inputInjection: configuredUi.inputInjection === true,
  };
  const config: MxcInvocationConfig = {
    version: MXC_SCHEMA_VERSION,
    backend: "process",
    containerId: String(input.containerId),
    platform,
    policy: { ...policy, ui },
    process: {
      commandLine: processCommandLine(shell, String(input.command ?? ""), cwd, platform, typeof input.readyMarker === "string" ? input.readyMarker : undefined),
      cwd,
      env: stringEnvironment(input.env),
      inheritEnvironment: false,
      ...(typeof input.timeoutMs === "number" && Number.isFinite(input.timeoutMs) && input.timeoutMs > 0 ? { timeoutMs: input.timeoutMs } : {}),
      usePty: input.usePty === true,
    },
    ui,
  };
  if (platform === "win32") config.fallback = windowsFallback(policy, record(input.platformCapabilities));
  return config;
}

export function buildProcessConfig(input: Record<string, unknown>): MxcInvocationConfig {
  return buildProcessConfigInternal(input, false);
}

export function buildInternalTrafficProbeConfig(input: Record<string, unknown>): MxcInvocationConfig {
  const policy = record(input.policy);
  const filesystem = record(policy.filesystem);
  const network = record(policy.network);
  const ui = record(policy.ui);
  const networkKeys = Object.keys(network);
  const safeNetworkShape = networkKeys.every((key) => ["internet", "localNetwork", "allowedHosts"].includes(key))
    && (!Array.isArray(network.allowedHosts) || (network.allowedHosts.length <= 1 && network.allowedHosts.every((host) => typeof host === "string" && host.length > 0)));
  if (input.usePty === true || !Array.isArray(filesystem.write) || filesystem.write.length !== 0 || Object.values(ui).some((value) => value === true) || !safeNetworkShape) {
    throw Object.assign(new Error("Internal native traffic probes require a narrow, noninteractive policy"), { code: "INVALID_INTERNAL_TRAFFIC_PROBE" });
  }
  return buildProcessConfigInternal(input, true);
}

async function sdkPathList(value: unknown, field: "read" | "write" | "deny"): Promise<string[]> {
  if (!Array.isArray(value)) return [];
  return await Promise.all(value.map(async (item): Promise<string | undefined> => {
    const grant = record(item);
    const path = typeof item === "string" ? item : grant.path;
    if (typeof path !== "string" || path.length === 0) return undefined;
    if (typeof item !== "string") {
      if (grant.kind !== undefined && grant.kind !== "file" && grant.kind !== "directory") return undefined;
      if (grant.recursive !== undefined && typeof grant.recursive !== "boolean") return undefined;
    }
    const resolved = await canonicalizeTarget(path);
    const resolvedAncestor = String(resolved.resolvedAncestor);
    const canonical = String(resolved.canonical);
    const target = /^[A-Za-z]:[\\/]?$/.test(path) ? `${path.slice(0, 2)}\\` : canonical;
    const targetExists = Array.isArray(resolved.unresolvedSuffix) && resolved.unresolvedSuffix.length === 0;
    const targetIsDirectory = targetExists && (await stat(resolvedAncestor)).isDirectory();
    const exact = field !== "deny" && (typeof item === "string" || grant.recursive !== true);
    const declaredExactDirectory = grant.kind === "directory" && grant.recursive !== true;
    if (declaredExactDirectory || (exact && targetIsDirectory)) {
      throw Object.assign(new Error(`MXC 0.7 cannot preserve exact nonrecursive directory semantics for ${field}`), {
        code: "UNSUPPORTED_NONRECURSIVE_DIRECTORY",
        details: { field, path },
      });
    }
    return target;
  })).then((paths) => paths.filter((path): path is string => typeof path === "string"));
}

export async function toSdkPolicy(policy: Record<string, unknown>, timeoutMs?: number): Promise<Record<string, unknown>> {
  const filesystem = record(policy.filesystem);
  const network = record(policy.network);
  const ui = record(policy.ui);
  const [write, candidateRead, deniedPaths] = await Promise.all([
    sdkPathList(filesystem.write ?? filesystem.readwritePaths, "write"),
    sdkPathList(filesystem.read ?? filesystem.readonlyPaths, "read"),
    sdkPathList(filesystem.deny ?? filesystem.deniedPaths, "deny"),
  ]);
  const read = candidateRead.filter((path) => !write.includes(path));
  const clipboardRead = ui.clipboardRead === true;
  const clipboardWrite = ui.clipboardWrite === true;
  const clipboard = clipboardRead && clipboardWrite ? "all" : clipboardRead ? "read" : clipboardWrite ? "write" : "none";
  return {
    version: MXC_SCHEMA_VERSION,
    filesystem: {
      readwritePaths: write,
      readonlyPaths: read,
      deniedPaths,
      clearPolicyOnExit: true,
    },
    network: {
      allowOutbound: network.internet === true || network.allowOutbound === true,
      allowLocalNetwork: network.localNetwork === true || network.allowLocalNetwork === true,
      ...(Array.isArray(network.allowedHosts) ? { allowedHosts: structuredClone(network.allowedHosts) } : {}),
      ...(Array.isArray(network.blockedHosts) ? { blockedHosts: structuredClone(network.blockedHosts) } : {}),
    },
    ui: {
      allowWindows: ui.allowWindows === true,
      clipboard,
      allowInputInjection: ui.inputInjection === true,
    },
    ...(typeof timeoutMs === "number" && timeoutMs > 0 ? { timeoutMs } : {}),
  };
}

function quoteWindowsCommandArgument(value: string): string {
  if (value.length === 0) return "\"\"";
  if (!/[\s"\\]/.test(value)) return value;
  let quoted = "\"";
  let backslashes = 0;
  for (const character of value) {
    if (character === "\\") {
      backslashes += 1;
      continue;
    }
    if (character === "\"") quoted += `${"\\".repeat(backslashes * 2 + 1)}\"`;
    else quoted += `${"\\".repeat(backslashes)}${character}`;
    backslashes = 0;
  }
  return `${quoted}${"\\".repeat(backslashes * 2)}\"`;
}

function quotePosixCommandArgument(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

export function toSdkCommandLine(commandLine: readonly string[], platform: string = process.platform): string {
  const quote = platform === "win32" ? quoteWindowsCommandArgument : quotePosixCommandArgument;
  if (platform === "win32") {
    const executable = commandLine[0]?.replaceAll("\\", "/").split("/").at(-1)?.toLowerCase();
    const commandIndex = commandLine.findIndex((argument) => argument.toLowerCase() === "/c");
    if (executable === "cmd.exe" && commandIndex >= 0 && commandIndex === commandLine.length - 2) {
      const prefix = commandLine.slice(0, commandIndex + 1).map(quote).join(" ");
      return `${prefix} "${commandLine[commandIndex + 1]}"`;
    }
  }
  return commandLine.map(quote).join(" ");
}

export function toSdkEnvironment(environment: Readonly<Record<string, string>>): string[] {
  return Object.entries(environment).map(([name, value]) => `${name}=${value}`);
}
