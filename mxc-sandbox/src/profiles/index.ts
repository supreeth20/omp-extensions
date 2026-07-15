import { dirname, isAbsolute, join, normalize, relative } from "node:path";
import { access, readFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";


export type PolicyRecord = Record<string, unknown>;

class ProfileError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

function parseYaml(source: string): PolicyRecord {
  try {
    const candidate: unknown = Bun.YAML.parse(source);
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
      throw new ProfileError("INVALID_PROFILE", "A profile must be a YAML mapping");
    }
    return candidate as PolicyRecord;
  } catch (error) {
    if (error instanceof ProfileError) throw error;
    throw new ProfileError("INVALID_PROFILE", "Profile YAML could not be parsed");
  }
}

const ALLOWED_KEYS: Record<string, readonly string[]> = {
  root: ["version", "filesystem", "network", "environment", "ui", "trustedTools", "capabilityDenies", "deny", "mxcOverrides", "macos", "windows", "linux"],
  macos: ["filesystem", "network", "environment", "ui", "trustedTools", "capabilityDenies", "deny", "mxcOverrides"],
  windows: ["filesystem", "network", "environment", "ui", "trustedTools", "capabilityDenies", "deny", "mxcOverrides"],
  linux: ["filesystem", "network", "environment", "ui", "trustedTools", "capabilityDenies", "deny", "mxcOverrides"],
  filesystem: ["read", "write", "deny"],
  network: ["internet", "localNetwork", "unrestricted", "allowedHosts", "blockedHosts"],
  environment: ["persistSensitiveNames", "sensitive", "nonSensitive", "values"],
  ui: ["allowWindows", "clipboardRead", "clipboardWrite", "inputInjection"],
  mxcOverrides: ["fallback", "diagnostics"],
  fallback: ["allowDaclMutation"],
  filesystemGrant: ["path", "kind", "recursive", "permissions"],
  diagnostics: ["verbose"],
};

function requireKnownKeys(value: PolicyRecord, section: string): void {
  const allowed = ALLOWED_KEYS[section];
  if (!allowed) return;
  for (const [key, child] of Object.entries(value)) {
    if (!allowed.includes(key)) throw new ProfileError("INVALID_PROFILE", `Unsupported ${section} capability: ${key}`);
    if (child && typeof child === "object" && !Array.isArray(child)) requireKnownKeys(child as PolicyRecord, key);
  }
}

function requireStringArray(value: unknown, label: string): void {
  if (value !== undefined && (!Array.isArray(value) || value.some((item) => typeof item !== "string"))) {
    throw new ProfileError("INVALID_PROFILE", `${label} must be a string array`);
  }
}
function requirePathRuleArray(value: unknown, label: string): void {
  if (value === undefined) return;
  if (!Array.isArray(value)) throw new ProfileError("INVALID_PROFILE", `${label} must be a path-rule array`);
  for (const item of value) {
    if (typeof item === "string") continue;
    const grant = requireMapping(item, label);
    requireKnownKeys(grant, "filesystemGrant");
    if (typeof grant.path !== "string" || grant.path.length === 0) throw new ProfileError("INVALID_PROFILE", `${label} path rules require a non-empty path`);
    if (grant.kind !== undefined && grant.kind !== "file" && grant.kind !== "directory") throw new ProfileError("INVALID_PROFILE", `${label} path-rule kind must be file or directory`);
    if (grant.recursive !== undefined && typeof grant.recursive !== "boolean") throw new ProfileError("INVALID_PROFILE", `${label} path-rule recursive must be boolean`);
    if (grant.recursive === true && grant.kind === "file") throw new ProfileError("INVALID_PROFILE", `${label} file rules cannot be recursive`);
    if (grant.permissions !== undefined && (!Array.isArray(grant.permissions) || grant.permissions.some((permission) => permission !== "read" && permission !== "write"))) throw new ProfileError("INVALID_PROFILE", `${label} path-rule permissions must contain only read/write`);
  }
}

function requireMapping(value: unknown, label: string): PolicyRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ProfileError("INVALID_PROFILE", `${label} must be a mapping`);
  }
  return value as PolicyRecord;
}

function validatePolicySections(policy: PolicyRecord, source: "user" | "project"): void {
  const filesystem = policy.filesystem === undefined ? {} : requireMapping(policy.filesystem, "filesystem");
  for (const key of ["read", "write", "deny"]) requirePathRuleArray(filesystem[key], `filesystem.${key}`);
  const network = policy.network === undefined ? {} : requireMapping(policy.network, "network");
  for (const key of ["internet", "localNetwork", "unrestricted"]) {
    if (network[key] !== undefined && typeof network[key] !== "boolean") throw new ProfileError("INVALID_PROFILE", `network.${key} must be boolean`);
  }
  requireStringArray(network.allowedHosts, "network.allowedHosts");
  requireStringArray(network.blockedHosts, "network.blockedHosts");
  const environment = policy.environment === undefined ? {} : requireMapping(policy.environment, "environment");
  if (Object.hasOwn(environment, "values")) throw new ProfileError("SECRET_VALUE_FORBIDDEN", "Profiles may never contain environment values");
  for (const key of ["persistSensitiveNames", "sensitive", "nonSensitive"]) requireStringArray(environment[key], `environment.${key}`);
  if (source === "project" && environment.persistSensitiveNames !== undefined) {
    throw new ProfileError("PROJECT_SECRET_PERSISTENCE_FORBIDDEN", "Project profiles may not persist sensitive approvals");
  }
  const ui = policy.ui === undefined ? {} : requireMapping(policy.ui, "ui");
  for (const key of ["allowWindows", "clipboardRead", "clipboardWrite", "inputInjection"]) {
    if (ui[key] !== undefined && typeof ui[key] !== "boolean") throw new ProfileError("INVALID_PROFILE", `ui.${key} must be boolean`);
  }
  requireStringArray(policy.trustedTools, "trustedTools");
  requireStringArray(policy.deny, "deny");
  if (policy.capabilityDenies !== undefined) {
    if (!Array.isArray(policy.capabilityDenies)) throw new ProfileError("INVALID_PROFILE", "capabilityDenies must be an array");
    for (const item of policy.capabilityDenies) {
      const deny = requireMapping(item, "capabilityDenies item");
      if (Object.keys(deny).some((key) => key !== "capability" && key !== "value")) throw new ProfileError("INVALID_PROFILE", "Unsupported capabilityDenies item field");
      if (typeof deny.capability !== "string" || typeof deny.value !== "string" || deny.capability.length === 0 || deny.value.length === 0) {
        throw new ProfileError("INVALID_PROFILE", "capabilityDenies items require exact capability and value strings");
      }
    }
  }
  if (policy.mxcOverrides !== undefined) validateMxcOverrides(requireMapping(policy.mxcOverrides, "mxcOverrides"));
  for (const platform of ["macos", "windows", "linux"]) {
    if (policy[platform] !== undefined) validatePolicySections(requireMapping(policy[platform], platform), source);
  }
}

export function validateMxcOverrides(value: PolicyRecord): PolicyRecord {
  for (const key of Object.keys(value)) {
    if (key !== "fallback" && key !== "diagnostics") {
      throw new ProfileError("FORBIDDEN_MXC_OVERRIDE", `MXC override ${key} can weaken containment`);
    }
  }
  requireKnownKeys(value, "mxcOverrides");
  const fallback = value.fallback === undefined ? {} : requireMapping(value.fallback, "mxcOverrides.fallback");
  const diagnostics = value.diagnostics === undefined ? {} : requireMapping(value.diagnostics, "mxcOverrides.diagnostics");
  if (fallback.allowDaclMutation !== undefined && typeof fallback.allowDaclMutation !== "boolean") throw new ProfileError("INVALID_PROFILE", "allowDaclMutation must be boolean");
  if (diagnostics.verbose !== undefined && typeof diagnostics.verbose !== "boolean") throw new ProfileError("INVALID_PROFILE", "diagnostics.verbose must be boolean");
  return structuredClone(value);
}

export function parseProfile(yaml: string, source: "user" | "project"): PolicyRecord {
  const parsed = parseYaml(yaml);
  if (parsed.version !== 1) throw new ProfileError("UNSUPPORTED_PROFILE_VERSION", "Only profile version 1 is supported");
  requireKnownKeys(parsed, "root");
  validatePolicySections(parsed, source);
  return parsed;
}

function mergeValue(base: unknown, overlay: unknown): unknown {
  if (overlay === undefined) return structuredClone(base);
  if (Array.isArray(base) && Array.isArray(overlay)) return [...new Set([...base, ...overlay])];
  if (base && overlay && typeof base === "object" && typeof overlay === "object" && !Array.isArray(base) && !Array.isArray(overlay)) {
    const result: PolicyRecord = structuredClone(base as PolicyRecord);
    for (const [key, value] of Object.entries(overlay as PolicyRecord)) result[key] = mergeValue(result[key], value);
    return result;
  }
  return structuredClone(overlay);
}

function pathContains(parent: string, child: string): boolean {
  const difference = relative(normalize(parent), normalize(child));
  return difference === "" || (!difference.startsWith("..") && !isAbsolute(difference));
}
function grantAllows(grant: unknown, child: string): boolean {
  if (typeof grant === "string") return normalize(grant) === normalize(child);
  const rule = grant && typeof grant === "object" && !Array.isArray(grant) ? grant as PolicyRecord : {};
  if (typeof rule.path !== "string") return false;
  const directory = rule.kind === "directory" || rule.recursive === true;
  return directory ? (rule.recursive === true ? pathContains(rule.path, child) : normalize(rule.path) === normalize(child)) : normalize(rule.path) === normalize(child);
}

export function mergePolicyLayers(input: PolicyRecord): PolicyRecord {
  const baseline = input.baseline && typeof input.baseline === "object" ? input.baseline as PolicyRecord : {};
  const user = input.user && typeof input.user === "object" ? input.user as PolicyRecord : {};
  const project = input.project && typeof input.project === "object" ? input.project as PolicyRecord : {};
  const conversation = input.conversation && typeof input.conversation === "object" ? input.conversation as PolicyRecord : {};
  let effective = mergeValue({}, baseline) as PolicyRecord;
  effective = mergeValue(effective, user) as PolicyRecord;

  const projectTrusted = project.trusted === true;
  const projectRestrictions: PolicyRecord = {};
  if (Array.isArray(project.deny)) projectRestrictions.deny = project.deny;
  if (Array.isArray(project.capabilityDenies)) projectRestrictions.capabilityDenies = project.capabilityDenies;
  if (project.filesystem && typeof project.filesystem === "object" && !Array.isArray(project.filesystem)) {
    const deny = (project.filesystem as PolicyRecord).deny;
    if (Array.isArray(deny)) projectRestrictions.filesystem = { deny };
  }
  if (project.network && typeof project.network === "object" && !Array.isArray(project.network)) {
    const network = project.network as PolicyRecord;
    projectRestrictions.network = {
      ...(network.internet === false ? { internet: false } : {}),
      ...(network.localNetwork === false ? { localNetwork: false } : {}),
      ...(network.unrestricted === false ? { unrestricted: false } : {}),
      ...(Array.isArray(network.blockedHosts) ? { blockedHosts: network.blockedHosts } : {}),
    };
  }
  if (project.ui && typeof project.ui === "object" && !Array.isArray(project.ui)) {
    const ui = project.ui as PolicyRecord;
    projectRestrictions.ui = Object.fromEntries(Object.entries(ui).filter(([, allowed]) => allowed === false));
  }
  if (project.environment && typeof project.environment === "object" && !Array.isArray(project.environment)) {
    const sensitive = (project.environment as PolicyRecord).sensitive;
    if (Array.isArray(sensitive)) projectRestrictions.environment = { sensitive };
  }
  effective = mergeValue(effective, projectTrusted ? project : projectRestrictions) as PolicyRecord;
  effective = mergeValue(effective, conversation) as PolicyRecord;
  delete effective.trusted;

  const filesystem = effective.filesystem && typeof effective.filesystem === "object" && !Array.isArray(effective.filesystem)
    ? effective.filesystem as PolicyRecord
    : {};
  if (!Array.isArray(filesystem.read)) filesystem.read = [];
  if (!Array.isArray(filesystem.write)) filesystem.write = [];
  if (!Array.isArray(filesystem.deny)) filesystem.deny = [];
  const savedDeny = [baseline, user, project]
    .flatMap((layer) => {
      const section = layer.filesystem;
      return section && typeof section === "object" && Array.isArray((section as PolicyRecord).deny)
        ? (section as PolicyRecord).deny as unknown[]
        : [];
    })
    .filter((path): path is string => typeof path === "string");
  const topDenied = [baseline, user, project]
    .flatMap((layer) => Array.isArray(layer.deny) ? layer.deny : [])
    .filter((path): path is string => typeof path === "string");
  effective.denied = [...new Set(topDenied)];
  const explicitOverrides = Array.isArray(conversation.explicitDenyOverrides)
    ? conversation.explicitDenyOverrides.filter((item): item is PolicyRecord => Boolean(item) && typeof item === "object" && !Array.isArray(item))
    : [];
  const savedCapabilityDenies = [baseline, user, project].flatMap((layer) => Array.isArray(layer.capabilityDenies)
    ? layer.capabilityDenies.filter((item): item is PolicyRecord => Boolean(item) && typeof item === "object" && !Array.isArray(item))
    : []);
  const allCapabilityDenies = [...savedCapabilityDenies, ...(Array.isArray(effective.capabilityDenies) ? effective.capabilityDenies : [])]
    .filter((candidate, index, values) => values.findIndex((item) => JSON.stringify(item) === JSON.stringify(candidate)) === index);
  const activeCapabilityDenies = allCapabilityDenies.filter((deny) => !explicitOverrides.some((override) => override.capability === (deny as PolicyRecord).capability && override.value === (deny as PolicyRecord).value));
  effective.capabilityDenies = activeCapabilityDenies;
  const network = effective.network && typeof effective.network === "object" && !Array.isArray(effective.network) ? effective.network as PolicyRecord : {};
  const ui = effective.ui && typeof effective.ui === "object" && !Array.isArray(effective.ui) ? effective.ui as PolicyRecord : {};
  const environment = effective.environment && typeof effective.environment === "object" && !Array.isArray(effective.environment) ? effective.environment as PolicyRecord : {};
  let trustedTools = Array.isArray(effective.trustedTools) ? effective.trustedTools.filter((name): name is string => typeof name === "string") : [];
  for (const deny of activeCapabilityDenies) {
    const capability = deny.capability;
    const value = deny.value;
    if (typeof capability !== "string" || typeof value !== "string") continue;
    if (capability === "read" || capability === "write") {
      const grants = Array.isArray(filesystem[capability]) ? filesystem[capability] as unknown[] : [];
      filesystem[capability] = grants.filter((grant) => typeof grant === "string" ? normalize(grant) !== normalize(value) : normalize(String((grant as PolicyRecord).path ?? "")) !== normalize(value));
      const exactDeny = { path: value, kind: "file", recursive: false, permissions: [capability] };
      filesystem.deny = [...filesystem.deny as unknown[], exactDeny];
    } else if (capability === "internet" && (value === "allow" || value === "true")) {
      network.internet = false;
      network.unrestricted = false;
    } else if (capability === "local-network" && (value === "allow" || value === "true")) network.localNetwork = false;
    else if (capability === "allowed-host") {
      network.allowedHosts = (Array.isArray(network.allowedHosts) ? network.allowedHosts : []).filter((host) => host !== value);
      network.blockedHosts = [...new Set([...(Array.isArray(network.blockedHosts) ? network.blockedHosts : []), value])];
    } else if (capability === "blocked-host") network.blockedHosts = (Array.isArray(network.blockedHosts) ? network.blockedHosts : []).filter((host) => host !== value);
    else if (capability === "ui") ui[value] = false;
    else if (capability === "trusted-tool") trustedTools = trustedTools.filter((tool) => tool !== value);
    else if (capability === "sensitive-environment-name") {
      environment.persistSensitiveNames = (Array.isArray(environment.persistSensitiveNames) ? environment.persistSensitiveNames : []).filter((name) => name !== value);
      environment.nonSensitive = (Array.isArray(environment.nonSensitive) ? environment.nonSensitive : []).filter((name) => name !== value);
      environment.sensitive = [...new Set([...(Array.isArray(environment.sensitive) ? environment.sensitive : []), value])];
    }
  }
  effective.network = network;
  effective.ui = ui;
  effective.environment = environment;
  effective.trustedTools = trustedTools;
  filesystem.access = (request: PolicyRecord): PolicyRecord => {
    const requestPath = typeof request.path === "string" ? request.path : "";
    const operation = typeof request.operation === "string" ? request.operation : "";
    if (explicitOverrides.some((override) => override.path === requestPath && override.operation === operation)) {
      return { allowed: true, reason: "session-override" };
    }
    if (savedDeny.some((deniedPath) => pathContains(deniedPath, requestPath))) return { allowed: false, reason: "saved-deny" };
    const grants = operation === "write" ? filesystem.write : filesystem.read;
    const allowed = Array.isArray(grants) && grants.some((grant) => grantAllows(grant, requestPath));
    return { allowed, reason: allowed ? "saved-grant" : "not-granted" };
  };
  effective.filesystem = filesystem;
  return effective;
}

export function expandPathToken(value: string, context: PolicyRecord): string {
  const env = context.env && typeof context.env === "object" && !Array.isArray(context.env) ? context.env as PolicyRecord : {};
  const replacements: Record<string, unknown> = {
    workspace: context.workspace,
    home: context.home,
    temp: context.temp,
  };
  let expanded = value.replace(/^~(?=$|[\\/])/, typeof context.home === "string" ? context.home : "${home}");
  expanded = expanded.replace(/\$\{(workspace|home|temp|env:([A-Za-z_][A-Za-z0-9_]*))\}/g, (token, name: string, envName?: string) => {
    const replacement = envName ? env[envName] : replacements[name];
    if (typeof replacement !== "string" || replacement === "") throw new ProfileError("UNRESOLVED_PATH_TOKEN", `Cannot resolve ${token}`);
    return replacement;
  });
  if (/\$\{[^}]+\}/.test(expanded)) throw new ProfileError("UNRESOLVED_PATH_TOKEN", `Cannot resolve token in ${value}`);
  return expanded;
}

export async function discoverProjectProfile(input: PolicyRecord): Promise<PolicyRecord | null> {
  const cwd = input.cwd;
  const repositoryRoot = input.repositoryRoot;
  const probe = input.probe;
  if (typeof cwd !== "string" || typeof repositoryRoot !== "string" || typeof probe !== "function") return null;
  const root = normalize(repositoryRoot);
  let current = normalize(cwd);
  if (!pathContains(root, current)) return null;
  while (pathContains(root, current)) {
    const candidate = join(current, ".omp", "sandbox.yml");
    if (await probe(candidate)) return { path: candidate, trusted: false };
    if (current === root) break;
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export async function discoverRepositoryRoot(cwd: string): Promise<string> {
  let current = normalize(cwd);
  for (;;) {
    if (await pathExists(join(current, ".git"))) return current;
    const parent = dirname(current);
    if (parent === current) return normalize(cwd);
    current = parent;
  }
}

function platformProfileName(platform: string): "macos" | "windows" | "linux" {
  if (platform === "win32") return "windows";
  if (platform === "linux") return "linux";
  return "macos";
}

function expandProfile(profile: PolicyRecord, context: PolicyRecord): PolicyRecord {
  const platformBlock = profile[platformProfileName(String(context.platform ?? process.platform))];
  const withoutPlatforms = structuredClone(profile);
  delete withoutPlatforms.macos;
  delete withoutPlatforms.windows;
  delete withoutPlatforms.linux;
  let effective = mergeValue(withoutPlatforms, platformBlock) as PolicyRecord;
  const filesystem = effective.filesystem && typeof effective.filesystem === "object" && !Array.isArray(effective.filesystem)
    ? effective.filesystem as PolicyRecord
    : undefined;
  if (filesystem) {
    for (const key of ["read", "write", "deny"] as const) {
      if (Array.isArray(filesystem[key])) filesystem[key] = (filesystem[key] as unknown[]).map((rule) => {
        if (typeof rule === "string") return normalize(expandPathToken(rule, context));
        const grant = rule as PolicyRecord;
        return { ...grant, path: normalize(expandPathToken(String(grant.path), context)) };
      });
    }
    effective = { ...effective, filesystem };
  }
  return effective;
}

export async function loadProfileLayers(input: PolicyRecord): Promise<PolicyRecord> {
  const cwd = typeof input.cwd === "string" ? normalize(input.cwd) : process.cwd();
  const repositoryRoot = typeof input.repositoryRoot === "string" ? normalize(input.repositoryRoot) : await discoverRepositoryRoot(cwd);
  const home = typeof input.home === "string" ? input.home : homedir();
  const reader = typeof input.read === "function" ? input.read : (path: string) => readFile(path, "utf8");
  const probe = typeof input.probe === "function" ? input.probe : pathExists;
  const context = { workspace: cwd, home, temp: typeof input.temp === "string" ? input.temp : tmpdir(), env: input.env ?? process.env, platform: input.platform ?? process.platform };
  const userPath = join(home, ".omp", "agent", "sandbox.yml");
  let user: PolicyRecord = {};
  if (await probe(userPath)) user = expandProfile(parseProfile(String(await reader(userPath)), "user"), context);
  const discovered = await discoverProjectProfile({ cwd, repositoryRoot, probe });
  let project: PolicyRecord = {};
  if (discovered && typeof discovered.path === "string") {
    project = expandProfile(parseProfile(String(await reader(discovered.path)), "project"), context);
    project.trusted = input.projectTrusted === true;
  }
  return {
    user,
    project,
    repositoryRoot,
    sources: [
      ...(Object.keys(user).length > 0 ? [{ source: "user", path: userPath, version: 1 }] : []),
      ...(Object.keys(project).length > 0 && discovered ? [{ source: "project", path: discovered.path, version: 1, trusted: project.trusted === true }] : []),
    ],
  };
}
