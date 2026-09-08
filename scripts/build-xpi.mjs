import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  utimes,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const defaultRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const EXPECTED_FILES = Object.freeze([
  "_locales/en/messages.json",
  "background.js",
  "icons/icon-48.png",
  "icons/icon-96.png",
  "manifest.json",
  "options/options.css",
  "options/options.html",
  "options/options.js",
  "portal-interceptor.js",
  "shared/accounts.js",
  "shared/backend.js",
  "shared/group-naming.js",
  "shared/i18n.js",
  "shared/onboarding.js",
  "shared/permissions.js",
  "shared/portal.js",
  "shared/service-icons.js",
  "sidebar/env.js",
  "sidebar/sidebar.css",
  "sidebar/sidebar.html",
  "sidebar/sidebar.js",
]);

async function requireDirectory(directory) {
  if (!(await lstat(directory)).isDirectory()) {
    throw new Error(`directory must not be a symlink or special file: ${directory}`);
  }
}

async function filesBelow(directory, source) {
  await requireDirectory(directory);
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(`symlinks are not allowed in the extension: ${path}`);
    }
    if (entry.isDirectory()) {
      files.push(...await filesBelow(path, source));
    } else if (entry.isFile()) {
      files.push(relative(source, path).split(sep).join("/"));
    } else {
      throw new Error(`unsupported extension entry: ${path}`);
    }
  }
  return files;
}

export async function validateSource(root) {
  const source = join(root, "firefox-extension");
  const actualFiles = (await filesBelow(source, source)).sort();
  if (JSON.stringify(actualFiles) !== JSON.stringify(EXPECTED_FILES)) {
    throw new Error(
      `extension file allowlist mismatch\nexpected: ${EXPECTED_FILES.join(", ")}\n` +
      `actual: ${actualFiles.join(", ")}`,
    );
  }

  const manifest = JSON.parse(await readFile(join(source, "manifest.json"), "utf8"));
  if (typeof manifest.version !== "string" || !/^\d+\.\d+\.\d+$/.test(manifest.version)) {
    throw new Error("manifest version must use X.Y.Z");
  }
  const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  const lock = JSON.parse(await readFile(join(root, "package-lock.json"), "utf8"));
  if ([pkg.version, lock.version, lock.packages?.[""]?.version]
    .some(version => version !== manifest.version)) {
    throw new Error("manifest.json, package.json, and package-lock.json versions must match");
  }
  return { source, version: manifest.version };
}

const fixedTime = new Date("1980-01-01T00:00:00.000Z");

function archiveEnvironment() {
  const env = { ...process.env, TZ: "UTC", LANG: "C", LC_ALL: "C" };
  // User shell defaults must not change compression, encryption, or inspection.
  for (const key of ["ZIPOPT", "UNZIP", "UNZIPOPT", "ZIPINFO", "ZIPINFOOPT"]) {
    delete env[key];
  }
  return env;
}

function runArchiveTool(run, command, args, cwd) {
  const result = run(command, args, {
    cwd,
    encoding: "utf8",
    env: archiveEnvironment(),
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${command} failed: ${result.error?.message || result.stderr || result.stdout || "unknown error"}`);
  }
  return result.stdout;
}

async function createArchive(source, workspace, run) {
  const staging = join(workspace, "source");
  const archive = join(workspace, "extension.xpi");
  await mkdir(staging);
  for (const file of EXPECTED_FILES) {
    // Recheck before copying: a symlink must never make it into staging.
    if (!(await lstat(join(source, file))).isFile()) {
      throw new Error(`extension file must not be a symlink or special file: ${file}`);
    }
    const destination = join(staging, file);
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(join(source, file), destination);
    await chmod(destination, 0o644);
    await utimes(destination, fixedTime, fixedTime);
  }

  runArchiveTool(run, "zip", ["-X", "-q", archive, ...EXPECTED_FILES], staging);
  runArchiveTool(run, "unzip", ["-tqq", archive], workspace);
  const listed = runArchiveTool(run, "unzip", ["-Z1", archive], workspace);
  const packagedFiles = listed.trim().split("\n").filter(Boolean);
  if (JSON.stringify(packagedFiles) !== JSON.stringify(EXPECTED_FILES)) {
    throw new Error("built XPI contents differ from the approved allowlist");
  }
  return archive;
}

export async function buildXpi({ root = defaultRoot, run = spawnSync } = {}) {
  root = resolve(root);
  const { source, version } = await validateSource(root);
  const artifacts = join(root, "artifacts");
  const output = join(artifacts, `containoodle-${version}.xpi`);
  const workspaces = [];
  let publishing;
  try {
    // Both archives are independently staged from source, never copied from
    // one another. Publish nothing until their complete bytes AND hashes match.
    const firstWorkspace = await mkdtemp(join(tmpdir(), "containoodle-xpi-first-"));
    workspaces.push(firstWorkspace);
    const firstArchive = await createArchive(source, firstWorkspace, run);
    await validateSource(root);
    const secondWorkspace = await mkdtemp(join(tmpdir(), "containoodle-xpi-second-"));
    workspaces.push(secondWorkspace);
    const secondArchive = await createArchive(source, secondWorkspace, run);
    const first = await readFile(firstArchive);
    const second = await readFile(secondArchive);
    const digest = createHash("sha256").update(first).digest("hex");
    const secondDigest = createHash("sha256").update(second).digest("hex");
    if (!first.equals(second) || digest !== secondDigest) {
      throw new Error("reproducibility check failed: two independent XPI builds differ");
    }
    if ((await validateSource(root)).version !== version) {
      throw new Error("source version changed during the build");
    }

    await mkdir(artifacts, { recursive: true });
    await requireDirectory(artifacts);
    const previous = await lstat(output).catch(error => {
      if (error.code !== "ENOENT") throw error;
      return null;
    });
    if (previous && !previous.isFile()) {
      throw new Error("existing XPI output must be a regular file, not a symlink");
    }
    // Atomic replacement also preserves a previous good XPI if building fails.
    publishing = await mkdtemp(join(artifacts, ".containoodle-xpi-"));
    const candidate = join(publishing, "extension.xpi");
    await copyFile(firstArchive, candidate);
    await chmod(candidate, 0o644);
    await rename(candidate, output);
    return { output, digest, version, files: [...EXPECTED_FILES] };
  } finally {
    for (const workspace of workspaces) {
      await rm(workspace, { recursive: true, force: true });
    }
    if (publishing) await rm(publishing, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { output, digest } = await buildXpi();
  console.log(`${relative(defaultRoot, output)}  sha256:${digest} (two independent builds match)`);
}
