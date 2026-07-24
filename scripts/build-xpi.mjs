import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  utimes,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "firefox-extension");
const manifest = JSON.parse(await readFile(join(source, "manifest.json"), "utf8"));
if (!/^\d+\.\d+\.\d+$/.test(manifest.version)) {
  throw new Error("manifest version must use X.Y.Z");
}

const expectedFiles = [
  "background.js",
  "icons/icon.svg",
  "manifest.json",
  "options/options.css",
  "options/options.html",
  "options/options.js",
  "portal-interceptor.js",
  "shared/accounts.js",
  "shared/backend.js",
  "shared/group-naming.js",
  "shared/portal.js",
  "sidebar/env.js",
  "sidebar/sidebar.css",
  "sidebar/sidebar.html",
  "sidebar/sidebar.js",
];

async function filesBelow(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(`symlinks are not allowed in the extension: ${path}`);
    }
    if (entry.isDirectory()) {
      files.push(...await filesBelow(path));
    } else if (entry.isFile()) {
      files.push(relative(source, path));
    } else {
      throw new Error(`unsupported extension entry: ${path}`);
    }
  }
  return files;
}

const actualFiles = (await filesBelow(source)).sort();
if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
  throw new Error(
    `extension file allowlist mismatch\nexpected: ${expectedFiles.join(", ")}\n` +
    `actual: ${actualFiles.join(", ")}`,
  );
}

const artifacts = join(root, "artifacts");
const output = join(artifacts, `orbiting-turnip-${manifest.version}.xpi`);
const staging = await mkdtemp(join(tmpdir(), "orbiting-turnip-xpi-"));
const fixedTime = new Date("1980-01-01T00:00:00.000Z");

try {
  await mkdir(artifacts, { recursive: true });
  for (const file of expectedFiles) {
    const destination = join(staging, file);
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(join(source, file), destination);
    await chmod(destination, 0o644);
    await utimes(destination, fixedTime, fixedTime);
  }

  await rm(output, { force: true });
  const zipped = spawnSync("zip", ["-X", "-q", output, ...expectedFiles], {
    cwd: staging,
    encoding: "utf8",
    env: { ...process.env, TZ: "UTC" },
  });
  if (zipped.status !== 0) {
    throw new Error(zipped.stderr || "zip failed");
  }

  const listed = spawnSync("unzip", ["-Z1", output], {
    encoding: "utf8",
  });
  if (listed.status !== 0) {
    throw new Error(listed.stderr || "could not inspect XPI");
  }
  const packagedFiles = listed.stdout.trim().split("\n").filter(Boolean);
  if (JSON.stringify(packagedFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error("built XPI contents differ from the approved allowlist");
  }

  const digest = createHash("sha256")
    .update(await readFile(output))
    .digest("hex");
  console.log(`${relative(root, output)}  sha256:${digest}`);
} finally {
  await rm(staging, { recursive: true, force: true });
}
