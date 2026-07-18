import { access, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, normalize, parse, sep } from "node:path";
import { win32 } from "node:path";

export type ToolTarget = Record<string, unknown>;

class PathPolicyError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export async function canonicalizeTarget(target: string): Promise<Record<string, unknown>> {
  if (!isAbsolute(target)) throw new PathPolicyError("ABSOLUTE_PATH_REQUIRED", "Policy targets must be absolute");
  if (target.includes("\0") || target.split(/[\\/]/).some((part) => part === ".." || part === ".")) {
    throw new PathPolicyError("AMBIGUOUS_PATH", "Policy targets may not contain traversal segments");
  }
  const requested = normalize(target);
  let ancestor = requested;
  const unresolvedSuffix: string[] = [];
  while (true) {
    try {
      await access(ancestor);
      break;
    } catch {
      const parent = dirname(ancestor);
      if (parent === ancestor) throw new PathPolicyError("PATH_RESOLUTION_FAILED", `No existing ancestor for ${target}`);
      unresolvedSuffix.unshift(basename(ancestor));
      ancestor = parent;
    }
  }
  const resolvedAncestor = await realpath(ancestor);
  const canonical = unresolvedSuffix.length === 0 ? resolvedAncestor : join(resolvedAncestor, ...unresolvedSuffix);
  return { absolute: requested, existingAncestor: ancestor, unresolvedSuffix, canonical, resolvedAncestor };
}

export function canonicalizeWindowsPath(target: string): string {
  const normalized = win32.normalize(target.replaceAll("/", "\\")).toLowerCase();
  const root = win32.parse(normalized).root;
  return normalized.length > root.length ? normalized.replace(/[\\]+$/, "") : normalized;
}

export const OMP_INTERNAL_URL_REGISTRY_VERSION = "17.0.4";

const OMP_INTERNAL_URL_SCHEMES = new Set([
  "agent", "artifact", "history", "issue", "local", "mcp", "memory",
  "omp", "pr", "rule", "skill", "ssh", "vault", "xd",
]);

const POLICY_GATED_INTERNAL_URL_SCHEMES = new Set(["ssh", "vault"]);


function urlScheme(target: string): string | undefined {
  const separator = target.indexOf("://");
  return separator > 0 ? target.slice(0, separator).toLowerCase() : undefined;
}

function isOmpInternalUrl(target: string): boolean {
  const scheme = urlScheme(target);
  return scheme !== undefined && OMP_INTERNAL_URL_SCHEMES.has(scheme);
}
function isTrustedOmpInternalUrl(target: string): boolean {
  const scheme = urlScheme(target);
  return scheme !== undefined && OMP_INTERNAL_URL_SCHEMES.has(scheme) && !POLICY_GATED_INTERNAL_URL_SCHEMES.has(scheme);
}

function classifySshTarget(target: string): ToolTarget {
  try {
    const parsed = new URL(target);
    return parsed.hostname.length > 0
      ? { host: parsed.hostname, operation: "network", remoteInternal: target }
      : { blocked: true, reason: "invalid-ssh-url" };
  } catch {
    return { blocked: true, reason: "invalid-ssh-url" };
  }
}

function classifyPolicyGatedInternalTarget(target: string, scheme: string | undefined): ToolTarget | undefined {
  if (scheme === "ssh") return classifySshTarget(target);
  if (scheme === "vault") return { blocked: true, reason: "vault-access-requires-sandbox-disable" };
  return undefined;
}



function classifyReadPath(target: string): ToolTarget {
  const scheme = urlScheme(target);
  if (scheme === "http" || scheme === "https") {
    try {
      const parsed = new URL(target);
      return { host: parsed.hostname, operation: "network", redirectPolicy: "initial-host-only" };
    } catch {
      return { blocked: true, reason: "invalid-url" };
    }
  }
  const gated = classifyPolicyGatedInternalTarget(target, scheme);
  if (gated) return gated;
  if (isTrustedOmpInternalUrl(target)) return { trustedInternal: target, internalWrite: true };
  if (scheme !== undefined) return { blocked: true, reason: "unsupported-scheme" };

  const archive = target.match(/^(.*\.(?:zip|tar|tgz|tar\.gz)):(.+)$/i);
  if (archive) return { path: archive[1], operation: "read", compound: "archive" };
  const sqlite = target.match(/^(.*\.(?:sqlite|sqlite3|db|db3)):(.+)$/i);
  if (sqlite) return { path: sqlite[1], operation: "read", compound: "sqlite" };
  return { path: target, operation: "read" };
}

function editTargets(input: Record<string, unknown>): ToolTarget[] {
  if (typeof input.path === "string") return [{ path: input.path, operation: "write" }];
  if (typeof input.input !== "string") return [{ blocked: true, reason: "missing-target" }];
  const patch = input.input;
  const headers = [...patch.matchAll(/^\[(.+)#[0-9A-Fa-f]{4}\]\s*$/gm)];
  if (headers.length === 0) return [{ blocked: true, reason: "missing-target" }];
  const targets: ToolTarget[] = [];
  const seen = new Set<string>();
  const add = (path: string): void => {
    if (path.length === 0 || seen.has(path)) return;
    seen.add(path);
    targets.push({ path, operation: "write" });
  };
  for (let index = 0; index < headers.length; index += 1) {
    const header = headers[index]!;
    add(String(header[1]));
    const sectionStart = Number(header.index) + header[0].length;
    const sectionEnd = index + 1 < headers.length ? Number(headers[index + 1]!.index) : patch.length;
    const section = patch.slice(sectionStart, sectionEnd);
    for (const move of section.matchAll(/^MV\s+(.+?)\s*$/gm)) {
      const rawDestination = String(move[1]);
      if (rawDestination.startsWith('"')) {
        try {
          const parsed = JSON.parse(rawDestination);
          if (typeof parsed === "string") add(parsed);
        } catch {
          return [{ blocked: true, reason: "invalid-target" }];
        }
      } else {
        add(rawDestination);
      }
    }
  }
  return targets.length > 0 ? targets : [{ blocked: true, reason: "missing-target" }];
}

export function resolveToolTargets(tool: string, input: Record<string, unknown>): ToolTarget[] {
  if (tool === "ast_edit") {
    return Array.isArray(input.paths)
      ? input.paths.map((path) => typeof path === "string" ? { path, operation: "write" } : { blocked: true, reason: "invalid-target" })
      : [{ blocked: true, reason: "missing-target" }];
  }
  if (tool === "edit") return editTargets(input);
  const target = input.path;
  if (typeof target !== "string") return [{ blocked: true, reason: "missing-target" }];
  if (tool === "read") return [classifyReadPath(target)];
  if (tool === "write") {
    const scheme = urlScheme(target);
    const gated = classifyPolicyGatedInternalTarget(target, scheme);
    if (gated) return [gated];
    if (isTrustedOmpInternalUrl(target) || scheme === "conflict") return [{ trustedInternal: target, internalWrite: true }];
    if (urlScheme(target) !== undefined) return [{ blocked: true, reason: "unsupported-scheme" }];
    return [{ path: target, operation: "write" }];
  }
  return [{ blocked: true, reason: "unsupported-tool" }];
}
