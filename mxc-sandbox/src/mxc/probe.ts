import { networkInterfaces } from "node:os";
import { dirname, win32 } from "node:path";
import { createServer } from "node:net";
import { loadMxcSdk, spawnMxcFromInvocation, spawnMxcTrafficProbeFromInvocation } from "./sdk";

type UnknownRecord = Record<string, unknown>;
type NativeChild = {
  pid?: number;
  spawnfile?: string;
  kill(signal?: string): unknown;
  once(event: string, listener: (...values: unknown[]) => void): unknown;
  stdout?: { on(event: "data", listener: (chunk: unknown) => void): unknown };
  stderr?: { on(event: "data", listener: (chunk: unknown) => void): unknown };
};

function expectedBackend(platform: string): string {
  if (platform === "darwin") return "seatbelt";
  if (platform === "win32") return "processcontainer";
  if (platform === "linux") return "bubblewrap";
  throw Object.assign(new Error(`Unsupported MXC process host: ${platform}`), { code: "MXC_HOST_UNSUPPORTED" });
}

function nativeChild(value: unknown): NativeChild {
  if (!value || typeof value !== "object" || !("kill" in value) || !("once" in value)
    || typeof value.kill !== "function" || typeof value.once !== "function") {
    throw Object.assign(new Error("MXC probe did not return a native ChildProcess"), { code: "MXC_NATIVE_CHILD_REQUIRED" });
  }
  return value as NativeChild;
}

type TrafficProbeResult = { exitCode: number; timedOut?: boolean; stderr?: string };
type TrafficExecutor = (input: UnknownRecord) => Promise<TrafficProbeResult>;

async function waitForChild(child: NativeChild, timeoutMs: number): Promise<{ exitCode: number; timedOut: boolean; stdout: string; stderr: string }> {
  const stdout: string[] = [];
  const stderr: string[] = [];
  child.stdout?.on("data", (chunk) => stdout.push(String(chunk)));
  child.stderr?.on("data", (chunk) => stderr.push(String(chunk)));
  const { promise, resolve, reject } = Promise.withResolvers<number>();
  child.once("exit", (code) => resolve(typeof code === "number" ? code : -1));
  child.once("error", reject);
  let timedOut = false;
  const timeout: Timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, timeoutMs);
  try {
    return { exitCode: await promise, timedOut, stdout: stdout.join(""), stderr: stderr.join("") };
  } finally {
    clearTimeout(timeout);
  }
}

function privateIpv4Address(): string | undefined {
  for (const addresses of Object.values(networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (address.family !== "IPv4" || address.internal) continue;
      const [first, second] = address.address.split(".").map(Number);
      if (first === 10 || (first === 172 && second! >= 16 && second! <= 31) || (first === 192 && second === 168)) return address.address;
    }
  }
  return undefined;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function trafficCommand(platform: string, host: string, port: number, marker: string): string {
  if (platform === "win32") {
    const escapedHost = host.replaceAll("'", "''");
    const escapedMarker = marker.replaceAll("'", "''");
    return `$client=[Net.Sockets.TcpClient]::new();try{$task=$client.ConnectAsync('${escapedHost}',${port});if(-not $task.Wait(2000)){exit 21};$stream=$client.GetStream();$bytes=[Text.Encoding]::UTF8.GetBytes('${escapedMarker}');$stream.Write($bytes,0,$bytes.Length);$buffer=New-Object byte[] 2;$read=$stream.ReadAsync($buffer,0,2);if(-not $read.Wait(2000)){exit 23};exit 0}catch{exit 22}finally{$client.Dispose()}`;
  }
  const script = `const net=process.getBuiltinModule("node:net");const s=net.createConnection({host:${JSON.stringify(host)},port:${port}},()=>s.write(${JSON.stringify(marker)}));s.on("data",()=>s.end());s.setTimeout(2000,()=>{s.destroy();process.exitCode=21});s.on("error",()=>{process.exitCode=22});`;
  const encoded = Buffer.from(script).toString("base64");
  const executable = process.execPath.replaceAll("\\", "/");
  return `${shellQuote(executable)} -e ${shellQuote(`eval(Buffer.from("${encoded}","base64").toString())`)}`;
}

export async function probeIndependentLocalNetworkSeparation(input: UnknownRecord): Promise<UnknownRecord> {
  const platform = typeof input.platform === "string" ? input.platform : process.platform;
  const privateHost = typeof input.privateHost === "string" ? input.privateHost : privateIpv4Address();
  if (!privateHost) return { independentLocalNetwork: false, allowedHosts: false, reason: "private-endpoint-unavailable" };
  const observed = new Set<string>();
  const server = createServer((socket) => {
    socket.on("data", (chunk) => {
      observed.add(String(chunk));
      socket.end("ok");
    });
  });
  const { promise: listening, resolve, reject } = Promise.withResolvers<void>();
  server.once("listening", resolve);
  server.once("error", reject);
  server.listen(0, process.platform === "win32" && privateHost === "127.0.0.1" ? "127.0.0.1" : "0.0.0.0");
  try {
    await listening;
    const address = server.address();
    if (!address || typeof address === "string") return { independentLocalNetwork: false, allowedHosts: false, reason: "ephemeral-endpoint-unavailable" };
    const execute = typeof input.executeTraffic === "function" ? input.executeTraffic as TrafficExecutor : undefined;
    if (!execute) return { independentLocalNetwork: false, allowedHosts: false, reason: "contained-traffic-executor-unavailable" };
    const evidence: UnknownRecord[] = [];
    for (const [mode, localNetwork] of [["blocked", false], ["allowed", true]] as const) {
      for (const [kind, host] of [["loopback", "127.0.0.1"], ["private", privateHost]] as const) {
        const marker = `mxc-network-${mode}-${kind}-${crypto.randomUUID()}`;
        const result = await execute({ host, port: address.port, marker, localNetwork, internet: !localNetwork });
        evidence.push({ mode, kind, host, marker, exitCode: result.exitCode, timedOut: result.timedOut === true, observed: observed.has(marker), ...(platform === "win32" && result.stderr ? { stderr: result.stderr.slice(0, 512) } : {}) });
      }
    }
    const internetLocalNetworkIsolation = evidence.filter((item) => item.mode === "blocked").every((item) => item.exitCode !== 0 && item.timedOut === false && item.observed === false);
    const localNetworkAvailable = evidence.filter((item) => item.mode === "allowed").every((item) => item.exitCode === 0 && item.timedOut === false && item.observed === true);
    const independentLocalNetwork = platform === "win32"
      ? internetLocalNetworkIsolation && localNetworkAvailable
      : evidence.every((item) => item.mode === "blocked"
          ? item.exitCode !== 0 && item.observed === false
          : item.exitCode === 0 && item.timedOut === false && item.observed === true);
    const hostRuleEvidence: UnknownRecord[] = [];
    if (input.attestAllowedHosts === true) {
      for (const [mode, allowedHosts] of [["allowed-host", ["127.0.0.1"]], ["unlisted-host", ["mxc-probe-denied.invalid"]]] as const) {
        const marker = `mxc-host-rule-${mode}-${crypto.randomUUID()}`;
        const result = await execute({ host: "127.0.0.1", port: address.port, marker, localNetwork: true, internet: true, allowedHosts });
        hostRuleEvidence.push({ mode, host: "127.0.0.1", allowedHosts, marker, exitCode: result.exitCode, timedOut: result.timedOut === true, observed: observed.has(marker) });
      }
    }
    const allowedHosts = hostRuleEvidence.length === 2 && hostRuleEvidence.every((item) => item.mode === "allowed-host"
      ? item.exitCode === 0 && item.timedOut === false && item.observed === true
      : item.exitCode !== 0 && item.observed === false);
    return platform === "win32"
      ? { independentLocalNetwork, internetLocalNetworkIsolation, localNetworkAvailable, allowedHosts, evidence, hostRuleEvidence }
      : { independentLocalNetwork, allowedHosts, evidence, hostRuleEvidence };
  } catch (cause) {
    return platform === "win32"
      ? { independentLocalNetwork: false, internetLocalNetworkIsolation: false, localNetworkAvailable: false, allowedHosts: false, reason: "native-traffic-probe-failed", cause: cause instanceof Error ? cause.message : String(cause) }
      : { independentLocalNetwork: false, allowedHosts: false, reason: "native-traffic-probe-failed", cause: cause instanceof Error ? cause.message : String(cause) };
  } finally {
    server.close();
  }
}

export function selectProbeRuntimeReadonlyPaths(input: UnknownRecord): string[] {
  const platform = typeof input.platform === "string" ? input.platform : process.platform;
  const sdkPaths = platform === "win32" ? [] : Array.isArray(input.sdkPaths) ? input.sdkPaths.filter((path): path is string => typeof path === "string") : [];
  const requestedPaths = Array.isArray(input.requestedPaths) ? input.requestedPaths.filter((path): path is string => typeof path === "string") : [];
  const candidates = [
    ...sdkPaths,
    ...requestedPaths,
    ...(typeof input.shellExecutable === "string" ? [platform === "win32" ? win32.dirname(input.shellExecutable) : dirname(input.shellExecutable)] : []),
    ...(typeof input.spawnfile === "string" ? [platform === "win32" ? win32.dirname(input.spawnfile) : dirname(input.spawnfile)] : []),
  ];
  return candidates.filter((path, index, paths) => path.length > 0 && paths.indexOf(path) === index);
}

export async function probeNativeMxcExecution(input: UnknownRecord): Promise<UnknownRecord> {
  const sdk = await loadMxcSdk();
  const platform = typeof input.platform === "string" ? input.platform : process.platform;
  const marker = `mxc-native-probe-${crypto.randomUUID()}`;
  const command = typeof input.command === "string"
    ? input.command
    : platform === "win32" ? `echo ${marker}` : `printf '%s' '${marker}'`;
  const child = nativeChild(await spawnMxcFromInvocation({
    ...input,
    ...(platform === "win32" && (typeof input.containerId !== "string" || input.containerId.length === 0)
      ? { containerId: `mxc-probe-${crypto.randomUUID()}` }
      : {}),
    platform,
    command,
    usePty: false,
  }, { usePty: false }, sdk));
  const result = await waitForChild(child, typeof input.probeTimeoutMs === "number" ? input.probeTimeoutMs : 10_000);
  const markerMatched = input.command !== undefined || (platform === "win32" ? result.stdout.trimEnd() === marker : result.stdout === marker);
  if (result.timedOut || result.exitCode !== 0 || !markerMatched) {
    throw Object.assign(new Error("The real MXC contained execution probe failed"), {
      code: "MXC_CONTAINMENT_PROBE_FAILED",
      details: { exitCode: result.exitCode, timedOut: result.timedOut, stderr: result.stderr },
    });
  }
  const shell = input.shell && typeof input.shell === "object" && !Array.isArray(input.shell) ? input.shell as UnknownRecord : {};
  const trafficShell = platform === "win32" && input.trafficShell && typeof input.trafficShell === "object" && !Array.isArray(input.trafficShell)
    ? input.trafficShell as UnknownRecord
    : shell;
  const sourcePolicy = input.policy && typeof input.policy === "object" && !Array.isArray(input.policy) ? input.policy as UnknownRecord : {};
  const requestedReadonlyPaths = Array.isArray(input.requiredReadonlyPaths)
    ? input.requiredReadonlyPaths.filter((path): path is string => typeof path === "string" && path.length > 0)
    : [];
  const verifiedPaths = selectProbeRuntimeReadonlyPaths({
    platform,
    sdkPaths: platform === "win32" ? [] : sdk.discoverRequiredReadonlyPaths(),
    requestedPaths: platform === "win32" ? requestedReadonlyPaths : [],
    shellExecutable: shell.executable,
    spawnfile: child.spawnfile,
  });
  const traffic = await probeIndependentLocalNetworkSeparation({
    platform,
    attestAllowedHosts: false,
    executeTraffic: async (probe: UnknownRecord): Promise<TrafficProbeResult> => {
      const trafficChild = nativeChild(await spawnMxcTrafficProbeFromInvocation({
        ...input,
        ...(platform === "win32" ? { shell: trafficShell } : {}),
        platform,
        command: trafficCommand(platform, String(probe.host), Number(probe.port), String(probe.marker)),
        usePty: false,
        policy: {
          ...(sourcePolicy.mxcOverrides && typeof sourcePolicy.mxcOverrides === "object" && !Array.isArray(sourcePolicy.mxcOverrides) ? { mxcOverrides: sourcePolicy.mxcOverrides } : {}),
          filesystem: {
            read: [...verifiedPaths, ...(platform === "win32" && typeof trafficShell.executable === "string" ? [dirname(trafficShell.executable)] : []), ...(platform === "win32" ? [] : [dirname(process.execPath)]), ...(typeof input.cwd === "string" ? [input.cwd] : [])].map((path) => ({ path, kind: "directory", recursive: true })),
            write: [],
          },
          network: {
            internet: probe.internet === true,
            localNetwork: probe.localNetwork === true,
            ...(Array.isArray(probe.allowedHosts) ? { allowedHosts: probe.allowedHosts } : {}),
          },
        },
      }, { usePty: false }, sdk));
      const trafficResult = await waitForChild(trafficChild, typeof input.networkProbeTimeoutMs === "number" ? input.networkProbeTimeoutMs : platform === "win32" ? 8_000 : 5_000);
      return platform === "win32"
        ? { exitCode: trafficResult.exitCode, timedOut: trafficResult.timedOut, stderr: trafficResult.stderr }
        : { exitCode: trafficResult.exitCode, timedOut: trafficResult.timedOut };
    },
  });
  return {
    contained: true,
    realMxc: true,
    sdkVersion: sdk.version,
    schemaVersion: sdk.schemaVersion,
    backend: expectedBackend(platform),
    nativeProcessId: child.pid,
    output: result.stdout,
    exitCode: result.exitCode,
    requiredReadonlyPaths: verifiedPaths,
    readonlyPathDiscoveryAttested: true,
    platformCapabilities: {
      independentLocalNetwork: traffic.independentLocalNetwork === true,
      ...(platform === "win32" ? {
        internetLocalNetworkIsolation: traffic.internetLocalNetworkIsolation === true,
        localNetworkAvailable: traffic.localNetworkAvailable === true,
      } : {}),
      coupledNetwork: platform === "darwin" && traffic.independentLocalNetwork !== true,
      allowedHosts: false,
      blockedHosts: false,
      ...(platform === "darwin" ? { pty: false } : {}),
    },
    localNetworkProbe: traffic,
  };
}
