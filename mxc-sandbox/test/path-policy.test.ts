import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { expectAsyncFailureCode, loadContract, requiredExport } from "./contracts";

type CanonicalizeTarget = (path: string, options?: Record<string, unknown>) => Promise<Record<string, any>>;
type EvaluatePathAccess = (input: Record<string, unknown>) => Record<string, unknown>;
type PermissionChoicesForTarget = (input: Record<string, unknown>) => Record<string, unknown>[];
type CanonicalizeWindowsPath = (path: string) => string;
type ResolveToolTargets = (tool: string, input: Record<string, unknown>) => Record<string, unknown>[];
type EvaluateLspAction = (input: Record<string, unknown>) => Record<string, unknown>;

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("canonical path enforcement", () => {
  test("canonicalizes an existing absolute file", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-path-"));
    roots.push(root);
    const target = join(root, "a.txt");
    await writeFile(target, "a");
    const mod = await loadContract("paths");
    const canonicalize = requiredExport<CanonicalizeTarget>(mod, "canonicalizeTarget");
    const result = await canonicalize(target);
    expect(result).toMatchObject({ absolute: target, existingAncestor: target, unresolvedSuffix: [] });
  });

  test("canonicalizes a nonexistent target from its nearest existing ancestor", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-path-"));
    roots.push(root);
    const existing = join(root, "existing");
    await mkdir(existing);
    const target = join(existing, "future", "child.txt");
    const mod = await loadContract("paths");
    const canonicalize = requiredExport<CanonicalizeTarget>(mod, "canonicalizeTarget");
    const result = await canonicalize(target);
    expect(result.existingAncestor).toBe(existing);
    expect(result.unresolvedSuffix).toEqual(["future", "child.txt"]);
    expect(result.absolute).toBe(target);
  });

  test("rejects relative and traversal-ambiguous policy targets", async () => {
    const mod = await loadContract("paths");
    const canonicalize = requiredExport<CanonicalizeTarget>(mod, "canonicalizeTarget");
    await expectAsyncFailureCode(() => canonicalize("relative/file"), "ABSOLUTE_PATH_REQUIRED");
  });

  test("prevents a recursive grant escaping through a symlink", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-path-"));
    const outside = await mkdtemp(join(tmpdir(), "mxc-outside-"));
    roots.push(root, outside);
    await writeFile(join(outside, "secret.txt"), "secret");
    await symlink(outside, join(root, "escape"), "dir");
    const mod = await loadContract("filesystem");
    const evaluate = requiredExport<EvaluatePathAccess>(mod, "evaluatePathAccess");
    const result = evaluate({
      operation: "read",
      target: join(root, "escape", "secret.txt"),
      grants: [{ path: root, kind: "directory", recursive: true, permissions: ["read"] }],
    });
    expect(result).toEqual({ allowed: false, reason: "canonical-target-outside-grant" });
  });

  test("prevents a nonexistent suffix from escaping after ancestor symlink resolution", async () => {
    const root = await mkdtemp(join(tmpdir(), "mxc-path-"));
    const outside = await mkdtemp(join(tmpdir(), "mxc-outside-"));
    roots.push(root, outside);
    await symlink(outside, join(root, "escape"), "dir");
    const mod = await loadContract("filesystem");
    const evaluate = requiredExport<EvaluatePathAccess>(mod, "evaluatePathAccess");
    expect(evaluate({
      operation: "write",
      target: join(root, "escape", "future.txt"),
      grants: [{ path: root, kind: "directory", recursive: true, permissions: ["write"] }],
    })).toEqual({ allowed: false, reason: "canonical-target-outside-grant" });
  });

  test("treats Windows paths case-insensitively without prefix confusion", async () => {
    const mod = await loadContract("paths");
    const normalize = requiredExport<CanonicalizeWindowsPath>(mod, "canonicalizeWindowsPath");
    expect(normalize("C:\\Users\\Alice\\Repo\\File.TXT")).toBe("c:\\users\\alice\\repo\\file.txt");
    const filesystem = await loadContract("filesystem");
    const evaluate = requiredExport<EvaluatePathAccess>(filesystem, "evaluatePathAccess");
    expect(evaluate({ platform: "win32", operation: "read", target: "c:\\USERS\\ALICE\\REPO\\a.txt", grants: [{ path: "C:\\Users\\Alice\\Repo", kind: "directory", recursive: true, permissions: ["read"] }] }).allowed).toBe(true);
    expect(evaluate({ platform: "win32", operation: "read", target: "C:\\Users\\Alice\\Repository\\a.txt", grants: [{ path: "C:\\Users\\Alice\\Repo", kind: "directory", recursive: true, permissions: ["read"] }] }).allowed).toBe(false);
  });

  test("rejects Windows reparse-point escapes supplied by the platform resolver", async () => {
    const mod = await loadContract("filesystem");
    const evaluate = requiredExport<EvaluatePathAccess>(mod, "evaluatePathAccess");
    const result = evaluate({
      platform: "win32",
      operation: "write",
      target: "C:\\repo\\link\\out.txt",
      grants: [{ path: "C:\\repo", kind: "directory", recursive: true, permissions: ["write"] }],
      resolvedSegments: ["C:\\repo", "D:\\outside", "D:\\outside\\out.txt"],
    });
    expect(result).toEqual({ allowed: false, reason: "reparse-point-escape" });
  });
});

describe("grant boundaries and host file-tool targets", () => {
  test("distinguishes exact-file grants from recursive directories", async () => {
    const mod = await loadContract("filesystem");
    const evaluate = requiredExport<EvaluatePathAccess>(mod, "evaluatePathAccess");
    const fileGrant = [{ path: "/repo/a.txt", kind: "file", permissions: ["read"] }];
    expect(evaluate({ operation: "read", target: "/repo/a.txt", grants: fileGrant }).allowed).toBe(true);
    expect(evaluate({ operation: "read", target: "/repo/a.txt/child", grants: fileGrant }).allowed).toBe(false);
    expect(evaluate({ operation: "read", target: "/repo/b.txt", grants: fileGrant }).allowed).toBe(false);
    const directoryGrant = [{ path: "/repo/data", kind: "directory", recursive: true, permissions: ["read"] }];
    expect(evaluate({ operation: "read", target: "/repo/data/deep/a.txt", grants: directoryGrant }).allowed).toBe(true);
    expect(evaluate({ operation: "read", target: "/repo/database/a.txt", grants: directoryGrant }).allowed).toBe(false);
  });

  test("write permission implies read but read never implies write", async () => {
    const mod = await loadContract("filesystem");
    const evaluate = requiredExport<EvaluatePathAccess>(mod, "evaluatePathAccess");
    expect(evaluate({ operation: "read", target: "/repo/a", grants: [{ path: "/repo/a", kind: "file", permissions: ["write"] }] }).allowed).toBe(true);
    expect(evaluate({ operation: "write", target: "/repo/a", grants: [{ path: "/repo/a", kind: "file", permissions: ["read"] }] }).allowed).toBe(false);
  });

  test("defaults a direct approval to the exact target and exposes broader scope separately", async () => {
    const mod = await loadContract("filesystem");
    const evaluate = requiredExport<PermissionChoicesForTarget>(mod, "permissionChoicesForTarget");
    expect(evaluate({ operation: "write", target: "/repo/src/a.ts", workspace: "/repo" })).toEqual([
      { id: "once", target: "/repo/src/a.ts", scope: "once" },
      { id: "exact-conversation", target: "/repo/src/a.ts", scope: "conversation" },
      { id: "parent-recursive", target: "/repo/src", scope: "conversation", recursive: true },
      { id: "workspace-recursive", target: "/repo", scope: "conversation", recursive: true },
      { id: "deny" },
    ]);
  });

  test("extracts every explicit target before allowing original host tools", async () => {
    const mod = await loadContract("paths");
    const targets = requiredExport<ResolveToolTargets>(mod, "resolveToolTargets");
    expect(targets("read", { path: "/repo/a" })).toEqual([{ path: "/repo/a", operation: "read" }]);
    expect(targets("write", { path: "/repo/a" })).toEqual([{ path: "/repo/a", operation: "write" }]);
    expect(targets("edit", { path: "/repo/a" })).toEqual([{ path: "/repo/a", operation: "write" }]);
    expect(targets("ast_edit", { paths: ["/repo/a.ts", "/repo/b.ts"] })).toEqual([{ path: "/repo/a.ts", operation: "write" }, { path: "/repo/b.ts", operation: "write" }]);
  });

  test("extracts source and move destinations from hashline edit patches", async () => {
    const mod = await loadContract("paths");
    const targets = requiredExport<ResolveToolTargets>(mod, "resolveToolTargets");
    expect(targets("edit", { input: "[/repo/a.ts#A1B2]\nSWAP 1.=1:\n+updated" })).toEqual([{ path: "/repo/a.ts", operation: "write" }]);
    expect(targets("edit", { input: "[/repo/a.ts#A1B2]\nMV \"/repo/new a.ts\"\n[/repo/b.ts#C3D4]\nDEL 1" })).toEqual([
      { path: "/repo/a.ts", operation: "write" },
      { path: "/repo/new a.ts", operation: "write" },
      { path: "/repo/b.ts", operation: "write" },
    ]);
    expect(targets("edit", { input: "not a hashline patch" })).toEqual([{ blocked: true, reason: "missing-target" }]);
  });

  test("gates archives, SQLite, URLs, trusted internal resources, and unknown schemes", async () => {
    const mod = await loadContract("paths");
    const targets = requiredExport<ResolveToolTargets>(mod, "resolveToolTargets");
    expect(targets("read", { path: "/repo/a.zip:dir/file" })).toEqual([{ path: "/repo/a.zip", operation: "read", compound: "archive" }]);
    expect(targets("read", { path: "/repo/data.sqlite:users:42" })).toEqual([{ path: "/repo/data.sqlite", operation: "read", compound: "sqlite" }]);
    expect(targets("read", { path: "https://example.com/a" })).toEqual([{ host: "example.com", operation: "network", redirectPolicy: "initial-host-only" }]);
    expect(targets("read", { path: "artifact://A1" })).toEqual([{ trustedInternal: "artifact://A1" }]);
    expect(targets("write", { path: "ssh://host/a" })).toEqual([{ blocked: true, reason: "unsupported-scheme" }]);
  });

  test("keeps readonly LSP available and warns before broad non-readonly actions", async () => {
    const mod = await loadContract("tools");
    const evaluate = requiredExport<EvaluateLspAction>(mod, "evaluateLspAction");
    expect(evaluate({ readonly: true, workspace: "/repo", grants: [] })).toEqual({ action: "allow" });
    expect(evaluate({ readonly: false, workspace: "/repo", grants: [] })).toEqual({
      action: "prompt",
      warning: "The extension cannot precompute every file the language server may edit.",
      choices: ["allow-action-once", "grant-recursive-workspace-write", "deny"],
    });
    expect(evaluate({ readonly: false, workspace: "/repo", grants: [{ path: "/repo", kind: "directory", recursive: true, permissions: ["write"] }] })).toEqual({ action: "allow" });
  });
});
