import { isAbsolute, normalize, resolve } from "node:path";
import { statSync } from "node:fs";


export interface UiPolicy {
  allowWindows: boolean;
  clipboardRead: boolean;
  clipboardWrite: boolean;
  inputInjection: boolean;
}

export function resolveUiPolicy(policy: UiPolicy, shell: string): UiPolicy {
  return {
    allowWindows: shell === "powershell" ? true : policy.allowWindows,
    clipboardRead: policy.clipboardRead,
    clipboardWrite: policy.clipboardWrite,
    inputInjection: policy.inputInjection,
  };
}

export function discoveredReadonlyGrants(paths: string[]): Record<string, unknown>[] {
  return paths.filter((path) => path.length > 0).map((path) => {
    try {
      if (statSync(path).isFile()) return { path, kind: "file" };
    } catch {
      // Preserve unresolved discovered directories for deterministic setup previews.
    }
    return { path, recursive: true };
  });
}

export function getInitialSetupDefaults(input: Record<string, unknown>): Record<string, unknown> {
  const cwd = typeof input.cwd === "string" ? input.cwd : "";
  const temp = typeof input.temp === "string" ? input.temp : "";
  const discovered = Array.isArray(input.discoveredReadonlyPaths)
    ? input.discoveredReadonlyPaths.filter((path): path is string => typeof path === "string")
    : [];
  return {
    filesystem: {
      read: [...(cwd ? [{ path: cwd, recursive: true }] : []), ...discoveredReadonlyGrants(discovered)],
      write: temp ? [{ path: temp, recursive: true }] : [],
    },
    network: { internet: false, localNetwork: false },
    ui: { allowWindows: true, clipboardRead: false, clipboardWrite: false, inputInjection: false },
    environment: { inheritOrdinary: true, sensitive: "prompt" },
    shellApproval: { normal: "automatic", critical: "confirm" },
  };
}

export function createDashboardModel(input: Record<string, unknown>): Record<string, unknown> {
  const tabs = ["General", "Filesystem", "Runtime Executables", "Network", "Environment", "UI", "Trusted Tools"];
  if (input.platform === "windows") tabs.push("Windows Compatibility/Advanced");
  tabs.push("Status/Diagnostics");
  return { kind: "sandbox-dashboard", tuiOnly: true, tabs };
}

export function createSetupCompletionModel(input: Record<string, unknown>): Record<string, unknown> {
  return {
    kind: "sandbox-setup-completion",
    tuiOnly: true,
    actions: input.complete === true
      ? ["use-for-conversation", "save-user-profile", "save-project-profile"]
      : [],
  };
}

export function mxcLaunchFailureChoices(): string[] {
  return ["Retry sandbox", "Run this command outside once", "Disable sandbox for this conversation", "Cancel"];
}

export function createReenableModel(input: Record<string, unknown>): Record<string, unknown> {
  return {
    kind: "sandbox-reenable",
    tuiOnly: true,
    actions: input.priorConversationPolicy === true
      ? ["restore-prior-policy-and-grants", "reset-and-run-setup"]
      : ["reset-and-run-setup"],
  };
}

export function requireInteractiveUi(input: Record<string, unknown>): Record<string, unknown> {
  const parent = input.parentBroker;
  const validatedParent = parent && typeof parent === "object" && !Array.isArray(parent)
    && ((parent as Record<string, unknown>).validated === true || (parent as Record<string, unknown>).interactive === true);
  if (input.hasUI !== true && !validatedParent) {
    const error = new Error("This sandbox action requires the TUI or a validated interactive parent broker") as Error & { code: string };
    error.code = "INTERACTIVE_UI_REQUIRED";
    throw error;
  }
  return { interactive: true, brokered: input.hasUI !== true };
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

export async function applySetupCompletionAction(input: Record<string, unknown>): Promise<Record<string, unknown>> {
  requireInteractiveUi(input);
  if (input.complete !== true) {
    const error = new Error("Setup must be complete before it can be applied") as Error & { code: string };
    error.code = "SETUP_INCOMPLETE";
    throw error;
  }
  const action = input.action;
  const policy = asRecord(input.policy);
  if (action === "use-for-conversation") {
    if (typeof input.applyConversation !== "function") {
      const error = new Error("Conversation policy store is unavailable") as Error & { code: string };
      error.code = "CONVERSATION_SAVE_UNAVAILABLE";
      throw error;
    }
    await input.applyConversation(policy);
    return { action, scope: "conversation", saved: true };
  }
  if (action === "save-user-profile") {
    if (typeof input.saveUserProfile !== "function") {
      const error = new Error("User profile store is unavailable") as Error & { code: string };
      error.code = "USER_PROFILE_SAVE_UNAVAILABLE";
      throw error;
    }
    await input.saveUserProfile(policy);
    return { action, scope: "user", saved: true };
  }
  if (action === "save-project-profile") {
    if (input.projectTrusted !== true) {
      const error = new Error("Project profile saves require explicit project trust") as Error & { code: string };
      error.code = "UNTRUSTED_PROJECT_PROFILE";
      throw error;
    }
    if (typeof input.saveProjectProfile !== "function") {
      const error = new Error("Project profile store is unavailable") as Error & { code: string };
      error.code = "PROJECT_PROFILE_SAVE_UNAVAILABLE";
      throw error;
    }
    await input.saveProjectProfile(policy);
    return { action, scope: "project", saved: true };
  }
  const error = new Error("Unknown setup completion action") as Error & { code: string };
  error.code = "INVALID_SETUP_ACTION";
  throw error;
}

type UiSurface = {
  select(title: string, choices: string[]): Promise<unknown>;
  input?: (title: string, initial?: string) => Promise<unknown>;
  notify?: (message: string, type?: string) => unknown;
};

function dashboardSections(platform: unknown): string[] {
  return ["Current Policy", "General", "Filesystem", "Runtime Executables", "Network", "Environment", "UI", "Trusted Tools", ...(platform === "windows" ? ["Windows Advanced"] : []), "Diagnostics"];
}

function pathRules(value: unknown): Record<string, unknown>[] {
  return (Array.isArray(value) ? value : []).flatMap((item): Record<string, unknown>[] => {
    if (typeof item === "string") return [{ path: item, kind: "directory", recursive: true }];
    return item && typeof item === "object" && !Array.isArray(item) && typeof (item as Record<string, unknown>).path === "string"
      ? [item as Record<string, unknown>]
      : [];
  });
}

function formatRule(rule: Record<string, unknown>): string {
  const scope = rule.kind === "directory" || rule.recursive === true ? "folder" : "file";
  const suffix = rule.recursive === true ? "  (all contents)" : "";
  return `  ${scope.padEnd(6)} ${String(rule.path)}${suffix}`;
}

function formatRuleGroup(label: string, rules: Record<string, unknown>[]): string[] {
  return [label, ...(rules.length > 0 ? rules.map(formatRule) : ["  none"])];
}

export function createDashboardPresentation(input: Record<string, unknown>): Record<string, unknown> {
  const policy = asRecord(input.policy);
  const filesystem = asRecord(policy.filesystem);
  const network = asRecord(policy.network);
  const read = pathRules(filesystem.read);
  const write = pathRules(filesystem.write);
  const deny = pathRules(filesystem.deny);
  const runtimeRead = pathRules(input.runtimeReadonlyGrants);
  const trustedTools = Array.isArray(policy.trustedTools) ? policy.trustedTools.filter((tool): tool is string => typeof tool === "string") : [];
  const networkStatus = network.internet === true || network.localNetwork === true ? "allowed" : "blocked";
  const title = [
    "MXC Sandbox",
    input.enabled === true ? "[ENABLED]  Policy changes apply to this conversation" : "[DISABLED]  Configure policy before enabling",
    "",
    `Filesystem     ${read.length} read  |  ${write.length} write  |  ${deny.length} denied`,
    `Runtime access ${runtimeRead.length} executable and dependency paths`,
    `Network        ${networkStatus}`,
    `Trusted tools  ${trustedTools.length}`,
    "",
    "Select a category. Changes are staged until Apply Changes and Exit.",
  ].join("\n");
  const filesystemTitle = [
    "Filesystem permissions",
    "",
    ...formatRuleGroup("READ ONLY", read),
    "",
    ...formatRuleGroup("WRITABLE", write),
    "",
    ...formatRuleGroup("DENIED", deny),
  ].join("\n");
  const runtimeTitle = [
    "Runtime executable access",
    "",
    "These read-only paths are managed automatically so executables can launch.",
    "They are not user permissions and cannot be edited here.",
    "",
    ...formatRuleGroup("EXECUTABLES AND DEPENDENCIES", runtimeRead),
  ].join("\n");
  return {
    title,
    filesystemTitle,
    runtimeTitle,
    options: [
      `Filesystem  ${read.length} read · ${write.length} write · ${deny.length} denied`,
      `Runtime Executables  ${runtimeRead.length} managed paths`,
      `Network  ${networkStatus}`,
      "Environment",
      "UI and desktop access",
      `Trusted Tools  ${trustedTools.length}`,
      "General",
      "Current Policy  raw JSON",
      "Diagnostics",
    ],
  };
}

function dashboardSection(value: unknown): string | undefined {
  const selected = String(value ?? "");
  if (selected.startsWith("Filesystem")) return "Filesystem";
  if (selected.startsWith("Runtime Executables")) return "Runtime Executables";
  if (selected.startsWith("Network")) return "Network";
  if (selected.startsWith("Environment")) return "Environment";
  if (selected === "UI" || selected.startsWith("UI and desktop access")) return "UI";
  if (selected.startsWith("Trusted Tools")) return "Trusted Tools";
  if (selected.startsWith("General")) return "General";
  if (selected.startsWith("Current Policy")) return "Current Policy";
  if (selected.startsWith("Diagnostics")) return "Diagnostics";
  if (selected.startsWith("Windows Advanced")) return "Windows Advanced";
  return undefined;
}

async function editFilesystemRuleList(ui: UiSurface, title: string, current: unknown, input: Record<string, unknown>): Promise<Record<string, unknown>[]> {
  let rules = pathRules(current);
  while (true) {
    const labels = rules.map((rule, index) => `${index + 1}. ${formatRule(rule).trim()}`);
    const selected = await ui.select([
      title,
      "",
      ...(rules.length > 0 ? rules.map(formatRule) : ["  none"]),
      "",
      "Select an existing rule to remove it, or add a new rule.",
    ].join("\n"), [...labels, "Add a file", "Add a folder and all contents", "Back"]);
    if (selected === "Single Files" || selected === "Directories and All Contents") {
      const fileScope = selected === "Single Files";
      const inScope = (rule: Record<string, unknown>): boolean => fileScope ? rule.kind !== "directory" && rule.recursive !== true : rule.kind === "directory" || rule.recursive === true;
      const edited = (await editStringList(ui, `${title} — ${String(selected)} (comma-separated paths)`, rules.filter(inScope).map((rule) => String(rule.path)))).map((path) => {
        const expanded = dashboardPath(path, input);
        return fileScope ? { path: expanded, kind: "file" } : { path: expanded, kind: "directory", recursive: true };
      });
      return [...rules.filter((rule) => !inScope(rule)), ...edited];
    }
    if (selected === "Add a file" || selected === "Add a folder and all contents") {
      if (typeof ui.input !== "function") throw Object.assign(new Error("Adding a filesystem rule requires the OMP TUI input surface"), { code: "INTERACTIVE_INPUT_REQUIRED" });
      const value = await ui.input(selected === "Add a file" ? "Absolute or ~/ path to file" : "Absolute or ~/ path to folder");
      if (typeof value === "string" && value.trim() !== "") {
        const path = dashboardPath(value, input);
        const rule = selected === "Add a file" ? { path, kind: "file" } : { path, kind: "directory", recursive: true };
        rules = [...rules.filter((candidate) => candidate.path !== path), rule];
      }
      continue;
    }
    const index = labels.indexOf(String(selected));
    if (index >= 0) {
      const decision = await ui.select(`Remove this permission?\n${formatRule(rules[index]!)}`, ["Remove", "Keep"]);
      if (decision === "Remove") rules = rules.filter((_rule, candidate) => candidate !== index);
      continue;
    }
    return rules;
  }
}

async function editStringList(ui: UiSurface, title: string, current: unknown): Promise<string[]> {
  if (typeof ui.input !== "function") {
    const error = new Error("Editing this dashboard field requires the OMP TUI input surface") as Error & { code: string };
    error.code = "INTERACTIVE_INPUT_REQUIRED";
    throw error;
  }
  const value = await ui.input(title, Array.isArray(current) ? current.filter((item): item is string => typeof item === "string").join(", ") : "");
  if (typeof value !== "string") return Array.isArray(current) ? current.filter((item): item is string => typeof item === "string") : [];
  return [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))];
}

function dashboardPath(value: string, input: Record<string, unknown>): string {
  const home = typeof input.home === "string" ? input.home : "";
  const cwd = typeof input.cwd === "string" ? input.cwd : process.cwd();
  let expanded = value.trim().replace(/^~(?=$|[\\/])/, home);
  if (input.platform === "darwin" && /^Users[\\/]/.test(expanded)) expanded = `/${expanded}`;
  return normalize(isAbsolute(expanded) ? expanded : resolve(cwd, expanded));
}

async function editBoolean(ui: UiSurface, title: string, current: unknown): Promise<boolean> {
  const selected = await ui.select(`${title} (currently ${current === true ? "enabled" : "disabled"})`, ["Enable", "Disable", "Back"]);
  return selected === "Enable" ? true : selected === "Disable" ? false : current === true;
}

export async function runSandboxDashboard(input: Record<string, unknown>): Promise<Record<string, unknown>> {
  requireInteractiveUi(input);
  const ui = asRecord(input.ui) as unknown as UiSurface;
  if (typeof ui.select !== "function") {
    const error = new Error("The verified OMP TUI selection surface is unavailable") as Error & { code: string };
    error.code = "INTERACTIVE_UI_REQUIRED";
    throw error;
  }
  const original = structuredClone(asRecord(input.policy));
  const draft = structuredClone(original);
  const sections = dashboardSections(input.platform);
  while (true) {
    const presentation = createDashboardPresentation({ policy: draft, runtimeReadonlyGrants: input.runtimeReadonlyGrants, enabled: asRecord(input.diagnostics).enabled === true });
    const options = presentation.options as string[];
    if (input.platform === "windows") options.splice(options.length - 2, 0, "Windows Advanced");
    const rawSelected = await ui.select(input.setup === true ? `MXC Sandbox Setup\n\n${String(presentation.title)}` : String(presentation.title), [...options, "Apply Changes and Exit", "Save User Profile and Exit", "Save Project Profile and Exit", "Cancel"]);
    if (rawSelected === "Apply Changes and Exit" || rawSelected === "Apply") return { action: "apply", policy: draft, changed: JSON.stringify(draft) !== JSON.stringify(original) };
    if (rawSelected === "Save User Profile and Exit" || rawSelected === "Save User Profile") return { action: "save-user-profile", policy: draft, changed: true };
    if (rawSelected === "Save Project Profile and Exit" || rawSelected === "Save Project Profile") return { action: "save-project-profile", policy: draft, changed: true };
    const selected = dashboardSection(rawSelected);
    if (rawSelected === "Cancel" || !selected || !sections.includes(selected)) return { action: "cancel", policy: original, changed: false };
    const filesystem = asRecord(draft.filesystem);
    const network = asRecord(draft.network);
    const environment = asRecord(draft.environment);
    const uiPolicy = asRecord(draft.ui);
    if (selected === "Current Policy") {
      await ui.select(`User-configured policy: ${JSON.stringify(draft, null, 2)}`, ["Back"]);
    } else if (selected === "Runtime Executables") {
      const presentation = createDashboardPresentation({ policy: draft, runtimeReadonlyGrants: input.runtimeReadonlyGrants, enabled: asRecord(input.diagnostics).enabled === true });
      await ui.select(String(presentation.runtimeTitle), ["Back"]);
    } else if (selected === "General") {
      const enabled = await editBoolean(ui, "Visible-window compatibility", uiPolicy.allowWindows);
      uiPolicy.allowWindows = enabled;
      draft.ui = uiPolicy;
    } else if (selected === "Filesystem") {
      const presentation = createDashboardPresentation({ policy: draft, runtimeReadonlyGrants: input.runtimeReadonlyGrants, enabled: asRecord(input.diagnostics).enabled === true });
      const field = await ui.select(String(presentation.filesystemTitle), ["Read-only paths", "Writable paths", "Denied paths", "Back"]);
      const key = field === "Read-only paths" ? "read" : field === "Writable paths" ? "write" : field === "Denied paths" ? "deny" : undefined;
      if (key) {
        filesystem[key] = await editFilesystemRuleList(ui, String(field), filesystem[key], input);
        draft.filesystem = filesystem;
      }
    } else if (selected === "Network") {
      const coupledNetwork = input.platform === "darwin";
      const field = await ui.select("Network policy", coupledNetwork
        ? ["Network Access", "Back"]
        : ["Internet", "Local Network", "Allowed Hosts", "Blocked Hosts", "Back"]);
      if (field === "Network Access") {
        const enabled = await editBoolean(ui, "All outbound network access", network.internet === true || network.localNetwork === true);
        network.internet = enabled;
        network.localNetwork = enabled;
        network.unrestricted = enabled;
      } else if (field === "Internet") {
        network.internet = await editBoolean(ui, "Internet", network.internet);
        network.unrestricted = network.internet === true;
      } else if (field === "Local Network") network.localNetwork = await editBoolean(ui, "Local Network", network.localNetwork);
      else if (field === "Allowed Hosts") network.allowedHosts = await editStringList(ui, "Allowed hosts", network.allowedHosts);
      else if (field === "Blocked Hosts") network.blockedHosts = await editStringList(ui, "Blocked hosts", network.blockedHosts);
      draft.network = network;
    } else if (selected === "Environment") {
      const field = await ui.select("Environment policy", ["Sensitive Names", "Non-sensitive Overrides", "Back"]);
      if (field === "Sensitive Names") environment.sensitive = await editStringList(ui, "Sensitive environment names", environment.sensitive);
      else if (field === "Non-sensitive Overrides") environment.nonSensitive = await editStringList(ui, "Non-sensitive environment names", environment.nonSensitive);
      draft.environment = environment;
    } else if (selected === "UI") {
      const field = await ui.select("UI policy", ["Visible Windows", "Clipboard Read", "Clipboard Write", "Input Injection", "Back"]);
      const key = field === "Visible Windows" ? "allowWindows" : field === "Clipboard Read" ? "clipboardRead" : field === "Clipboard Write" ? "clipboardWrite" : field === "Input Injection" ? "inputInjection" : undefined;
      if (key) uiPolicy[key] = await editBoolean(ui, field as string, uiPolicy[key]);
      draft.ui = uiPolicy;
    } else if (selected === "Trusted Tools") {
      draft.trustedTools = await editStringList(ui, "Exact trusted tool names", draft.trustedTools);
    } else if (selected === "Windows Advanced") {
      const diagnostics = asRecord(input.windowsDiagnostics);
      const choice = await ui.select(`Windows build ${String(diagnostics.windowsBuild ?? "unknown")}, tier ${String(diagnostics.tier ?? "unknown")}`, ["Strict Native Enforcement", "Tier-3 Compatibility", "Back"]);
      if (choice === "Tier-3 Compatibility") {
        if (diagnostics.hostPreparationVerified !== true) {
          const error = new Error("Tier-3 compatibility requires verified operator host preparation") as Error & { code: string };
          error.code = "WINDOWS_HOST_PREPARATION_REQUIRED";
          throw error;
        }
        draft.mxcOverrides = { ...asRecord(draft.mxcOverrides), fallback: { allowDaclMutation: true } };
      } else if (choice === "Strict Native Enforcement") draft.mxcOverrides = { ...asRecord(draft.mxcOverrides), fallback: { allowDaclMutation: false } };
    } else if (selected === "Diagnostics") {
      await ui.select(`MXC Diagnostics: ${JSON.stringify(input.diagnostics ?? {})}`, ["Back"]);
    }
  }
}
