import { existsSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, normalize, relative, win32 } from "node:path";
import { canonicalizeWindowsPath } from "./paths";
import { canonicalizeTarget } from "./paths";

export interface PathGrant {
  path: string;
  kind: "file" | "directory";
  recursive?: boolean;
  permissions: string[];
}

interface AccessRequest {
  operation?: unknown;
  target?: unknown;
  platform?: unknown;
  grants?: unknown;
  resolvedSegments?: unknown;
}

function canonicalizePosixSync(target: string): string {
  const requested = normalize(target);
  let ancestor = requested;
  const suffix: string[] = [];
  while (!existsSync(ancestor)) {
    const parent = dirname(ancestor);
    if (parent === ancestor) return requested;
    suffix.unshift(basename(ancestor));
    ancestor = parent;
  }
  const resolved = realpathSync(ancestor);
  return suffix.length === 0 ? resolved : join(resolved, ...suffix);
}

function isGrant(value: unknown): value is PathGrant {
  if (!value || typeof value !== "object" || !("path" in value) || !("kind" in value) || !("permissions" in value)) return false;
  return typeof value.path === "string"
    && (value.kind === "file" || value.kind === "directory")
    && Array.isArray(value.permissions)
    && value.permissions.every((permission) => typeof permission === "string");
}

function hasPermission(grant: PathGrant, operation: string): boolean {
  return grant.permissions.includes(operation) || (operation === "read" && grant.permissions.includes("write"));
}

function containsPath(parent: string, child: string, windows: boolean): boolean {
  const pathApi = windows ? win32 : { relative, isAbsolute };
  const difference = pathApi.relative(parent, child);
  return difference === "" || (!difference.startsWith("..") && !pathApi.isAbsolute(difference));
}

export function evaluatePathAccess(input: AccessRequest): Record<string, unknown> {
  if (typeof input.target !== "string" || typeof input.operation !== "string") return { allowed: false, reason: "invalid-request" };
  const operation = input.operation;
  const requestedTarget = input.target;
  const windows = input.platform === "win32";
  const target = windows ? canonicalizeWindowsPath(requestedTarget) : canonicalizePosixSync(requestedTarget);
  const grants = Array.isArray(input.grants) ? input.grants.filter(isGrant) : [];

  if (windows && Array.isArray(input.resolvedSegments)) {
    const recursiveRoots = grants
      .filter((grant) => grant.kind === "directory" && grant.recursive && hasPermission(grant, operation))
      .map((grant) => canonicalizeWindowsPath(grant.path));
    const escaped = input.resolvedSegments.some((segment) => typeof segment !== "string"
      || !recursiveRoots.some((root) => containsPath(root, canonicalizeWindowsPath(segment), true)));
    if (escaped) return { allowed: false, reason: "reparse-point-escape" };
  }

  for (const grant of grants) {
    if (!hasPermission(grant, operation)) continue;
    const grantPath = windows ? canonicalizeWindowsPath(grant.path) : canonicalizePosixSync(grant.path);
    if (grant.kind === "file" && target === grantPath) return { allowed: true, reason: "granted" };
    if (grant.kind === "directory" && (target === grantPath || (grant.recursive && containsPath(grantPath, target, windows)))) {
      return { allowed: true, reason: "granted" };
    }
  }

  const lexicalCandidate = windows ? canonicalizeWindowsPath(requestedTarget) : normalize(requestedTarget);
  const wasLexicallyWithinGrant = grants.some((grant) => {
    const grantPath = windows ? canonicalizeWindowsPath(grant.path) : normalize(grant.path);
    return grant.kind === "directory" && grant.recursive && containsPath(grantPath, lexicalCandidate, windows);
  });
  if (wasLexicallyWithinGrant) return { allowed: false, reason: "canonical-target-outside-grant" };
  return { allowed: false, reason: "not-granted" };
}

export async function evaluatePathAccessAsync(input: AccessRequest): Promise<Record<string, unknown>> {
  if (typeof input.target !== "string" || typeof input.operation !== "string") return { allowed: false, reason: "invalid-request" };
  const windows = input.platform === "win32";
  const grants = Array.isArray(input.grants) ? input.grants.filter(isGrant) : [];
  let canonicalTarget: string;
  try {
    const targetResult = await canonicalizeTarget(input.target);
    canonicalTarget = String(targetResult.canonical);
  } catch {
    return { allowed: false, reason: "canonicalization-failed" };
  }
  for (const grant of grants) {
    if (!hasPermission(grant, input.operation)) continue;
    let canonicalGrant: string;
    try {
      const grantResult = await canonicalizeTarget(grant.path);
      canonicalGrant = String(grantResult.canonical);
    } catch {
      continue;
    }
    const target = windows ? canonicalizeWindowsPath(canonicalTarget) : canonicalTarget;
    const root = windows ? canonicalizeWindowsPath(canonicalGrant) : canonicalGrant;
    if (grant.kind === "file" && target === root) return { allowed: true, reason: "granted", canonicalTarget };
    if (grant.kind === "directory" && (target === root || (grant.recursive === true && containsPath(root, target, windows)))) {
      return { allowed: true, reason: "granted", canonicalTarget };
    }
  }
  const lexical = evaluatePathAccess(input);
  return lexical.allowed === true
    ? { allowed: false, reason: "canonical-target-outside-grant", canonicalTarget }
    : { ...lexical, canonicalTarget };
}

export function permissionChoicesForTarget(input: Record<string, unknown>): Record<string, unknown>[] {
  const target = typeof input.target === "string" ? normalize(input.target) : "";
  const workspace = typeof input.workspace === "string" ? normalize(input.workspace) : "";
  const choices: Record<string, unknown>[] = [
    { id: "once", target, scope: "once" },
    { id: "exact-conversation", target, scope: "conversation" },
    { id: "parent-recursive", target: dirname(target), scope: "conversation", recursive: true },
  ];
  if (workspace !== "" && workspace !== dirname(target)) choices.push({ id: "workspace-recursive", target: workspace, scope: "conversation", recursive: true });
  choices.push({ id: "deny" });
  return choices;
}
