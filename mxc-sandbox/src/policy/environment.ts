export interface SensitivityOverrides {
  sensitive?: string[];
  nonSensitive?: string[];
}

const KNOWN_SENSITIVE_NAMES: Record<string, true> = {
  AWS_ACCESS_KEY_ID: true,
  AWS_SECRET_ACCESS_KEY: true,
  AWS_SESSION_TOKEN: true,
  AZURE_CLIENT_SECRET: true,
  GOOGLE_APPLICATION_CREDENTIALS: true,
  GITHUB_TOKEN: true,
  GH_TOKEN: true,
  GIT_ASKPASS: true,
  SSH_AUTH_SOCK: true,
  SSH_AGENT_PID: true,
  KUBECONFIG: true,
};

export function classifySensitiveName(name: string, overrides: SensitivityOverrides = {}): boolean {
  const normalized = name.toUpperCase();
  if (overrides.nonSensitive?.some((candidate) => candidate.toUpperCase() === normalized)) return false;
  if (overrides.sensitive?.some((candidate) => candidate.toUpperCase() === normalized)) return true;
  if (KNOWN_SENSITIVE_NAMES[normalized]) return true;
  return /(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE_KEY|API_KEY)(?:_|$)/.test(normalized)
    || /(?:^|_)(?:AUTH|AGENT)_SOCK(?:_|$)/.test(normalized);
}

function stringEnvironment(value: unknown): Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
}

export function sensitiveEnvironmentNames(host: Record<string, string>, policy: Record<string, unknown>): string[] {
  const overrides: SensitivityOverrides = {
    ...(Array.isArray(policy.sensitive) ? { sensitive: policy.sensitive.filter((name): name is string => typeof name === "string") } : {}),
    ...(Array.isArray(policy.nonSensitive) ? { nonSensitive: policy.nonSensitive.filter((name): name is string => typeof name === "string") } : {}),
  };
  return Object.keys(host).filter((name) => classifySensitiveName(name, overrides)).sort();
}

export async function prepareSandboxEnvironment(input: Record<string, unknown>): Promise<Record<string, string>> {
  const host = { ...stringEnvironment(input.hostEnvironment), ...stringEnvironment(input.env) };
  const policy = input.policy && typeof input.policy === "object" && !Array.isArray(input.policy)
    ? input.policy as Record<string, unknown>
    : {};
  const approved = new Set(Array.isArray(policy.approvedSensitiveNames)
    ? policy.approvedSensitiveNames.filter((name): name is string => typeof name === "string")
    : []);
  const denied = new Set(Array.isArray(policy.deniedSensitiveNames) ? policy.deniedSensitiveNames.filter((name): name is string => typeof name === "string") : []);
  for (const name of denied) approved.delete(name);
  const pending = sensitiveEnvironmentNames(host, policy).filter((name) => !approved.has(name) && !denied.has(name));
  if (pending.length > 0 && typeof input.approveSensitiveNames === "function") {
    const selected = await input.approveSensitiveNames({ names: pending, valuesRedacted: true, grouped: true });
    if (Array.isArray(selected)) {
      for (const name of selected) if (typeof name === "string" && pending.includes(name)) approved.add(name);
    }
  }
  return buildSandboxEnvironment(host, { ...policy, approvedSensitiveNames: [...approved] });
}

export function buildSandboxEnvironment(host: Record<string, string>, policy: Record<string, unknown>): Record<string, string> {
  const denied = new Set(Array.isArray(policy.deniedSensitiveNames) ? policy.deniedSensitiveNames.filter((name): name is string => typeof name === "string") : []);
  const approved = Array.isArray(policy.approvedSensitiveNames)
    ? policy.approvedSensitiveNames.filter((name): name is string => typeof name === "string" && !denied.has(name))
    : [];
  const overrides: SensitivityOverrides = {
    ...(Array.isArray(policy.sensitive) ? { sensitive: policy.sensitive.filter((name): name is string => typeof name === "string") } : {}),
    ...(Array.isArray(policy.nonSensitive) ? { nonSensitive: policy.nonSensitive.filter((name): name is string => typeof name === "string") } : {}),
  };
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(host)) {
    if (!classifySensitiveName(name, overrides) || approved.includes(name)) result[name] = value;
  }
  return result;
}
