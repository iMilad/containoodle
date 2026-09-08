import { copyFile, lstat, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { EXPECTED_FILES, validateSource } from "./build-xpi.mjs";

const defaultRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const LINT_TIMEOUT_MS = 60_000;
const pngSignature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const approvedIcons = new Map([["icons/icon-48.png", 48], ["icons/icon-96.png", 96]]);

export async function validateLintImages(source) {
  for (const [file, dimension] of approvedIcons) {
    const stat = await lstat(join(source, file));
    if (!stat.isFile() || stat.size > 1024 * 1024) {
      throw new Error(`Lint image must be a small regular PNG: ${file}`);
    }
    const bytes = await readFile(join(source, file));
    // Check bytes, not the filename: ICNS/JXL/HEIF can be disguised as .png.
    if (bytes.length < 33 || !bytes.subarray(0, 8).equals(pngSignature) ||
        bytes.readUInt32BE(8) !== 13 || bytes.toString("ascii", 12, 16) !== "IHDR" ||
        bytes.readUInt32BE(16) !== dimension || bytes.readUInt32BE(20) !== dimension) {
      throw new Error(`Lint image must be the expected ${dimension}px PNG: ${file}`);
    }
  }
  const manifest = JSON.parse(await readFile(join(source, "manifest.json"), "utf8"));
  const checkPaths = value => {
    if (value === undefined) return;
    if (typeof value === "string") {
      if (!approvedIcons.has(value)) throw new Error("Manifest image must use an approved PNG");
    } else if (value && typeof value === "object" && !Array.isArray(value)) {
      for (const path of Object.values(value)) checkPaths(path);
    } else {
      throw new Error("Unsupported manifest image declaration");
    }
  };
  checkPaths(manifest.icons);
  for (const key of ["action", "browser_action", "page_action", "sidebar_action"]) {
    checkPaths(manifest[key]?.default_icon);
    for (const icon of manifest[key]?.theme_icons ?? []) {
      checkPaths(icon.light);
      checkPaths(icon.dark);
    }
  }
  // This is an extension, not a theme. New image surfaces need an explicit
  // review of this containment rather than bypassing it silently.
  if (manifest.theme || manifest.theme_experiment) {
    throw new Error("Theme images are not approved for this extension build");
  }
}

export async function lintExtension({ root = defaultRoot, run = spawnSync } = {}) {
  const { source } = await validateSource(root);
  const staging = await mkdtemp(join(tmpdir(), "containoodle-lint-"));
  try {
    for (const file of EXPECTED_FILES) {
      if (!(await lstat(join(source, file))).isFile()) {
        throw new Error("Lint source must contain only regular files");
      }
      const target = join(staging, file);
      await mkdir(dirname(target), { recursive: true });
      await copyFile(join(source, file), target);
    }
    // Inspect the exact staged bytes consumed by the child process.
    await validateLintImages(staging);
    const result = run(process.execPath, [
      "--require", join(defaultRoot, "scripts/lint-image-guard.cjs"),
      join(defaultRoot, "node_modules/web-ext/bin/web-ext.js"),
      "lint", `--source-dir=${staging}`, "--self-hosted", "--no-input", "--no-config-discovery",
    ], {
      cwd: staging, encoding: "utf8", timeout: LINT_TIMEOUT_MS,
      killSignal: "SIGKILL", maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, NO_UPDATE_NOTIFIER: "1" },
    });
    if (result.error?.code === "ETIMEDOUT") throw new Error("Extension lint exceeded its 60-second deadline");
    if (result.error || result.status !== 0) {
      throw new Error(`Extension lint failed: ${result.error?.message || result.stderr || result.stdout || "unknown error"}`);
    }
    return { stdout: result.stdout, stderr: result.stderr };
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await lintExtension();
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
}
