import { access, mkdir, rm, symlink } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const extensionRoot = fileURLToPath(new URL("..", import.meta.url));
const outputDirectory = join(extensionRoot, "dist");

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });
const build = await Bun.build({
  entrypoints: [join(extensionRoot, "index.ts")],
  outdir: outputDirectory,
  naming: "index.js",
  target: "bun",
});
if (!build.success) {
  throw new Error(`MXC extension bundle failed: ${build.logs.map(String).join("\n")}`);
}

async function linkDirectory(target: string, link: string): Promise<void> {
  await rm(link, { recursive: true, force: true });
  const source = process.platform === "win32" ? target : relative(dirname(link), target);
  await symlink(source, link, process.platform === "win32" ? "junction" : "dir");
}

await linkDirectory(join(extensionRoot, "node_modules", "@microsoft", "mxc-sdk", "bin"), join(extensionRoot, "bin"));
const sdkArchitecture = process.arch === "arm64" ? "arm64" : "x64";
const nativeLauncher = process.platform === "darwin" ? "mxc-exec-mac" : process.platform === "win32" ? "wxc-exec.exe" : "lxc-exec";
await access(join(extensionRoot, "bin", sdkArchitecture, nativeLauncher), constants.X_OK);
await linkDirectory(join(extensionRoot, "node_modules", "node-pty", "prebuilds"), join(outputDirectory, "prebuilds"));
