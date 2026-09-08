import assert from "node:assert/strict";
import { appendFileSync, writeFileSync } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { buildXpi, EXPECTED_FILES, validateSource } from "../scripts/build-xpi.mjs";

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "containoodle-build-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "firefox-extension");
  for (const file of EXPECTED_FILES) {
    const path = join(source, file);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `Synthetic fixture: ${file}\n`);
  }
  await writeFile(join(source, "manifest.json"), JSON.stringify({
    name: "Synthetic extension", manifest_version: 3, version: "1.2.0",
  }));
  await writeFile(join(root, "package.json"), JSON.stringify({ version: "1.2.0" }));
  await writeFile(join(root, "package-lock.json"), JSON.stringify({
    version: "1.2.0", packages: { "": { version: "1.2.0" } },
  }));
  return { root, source, output: join(root, "artifacts", "containoodle-1.2.0.xpi") };
}

async function exists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    return false;
  }
}

async function sourceSnapshot(source) {
  return Promise.all(EXPECTED_FILES.map(async file => {
    const path = join(source, file);
    const stat = await lstat(path);
    return { file, mode: stat.mode, mtimeMs: stat.mtimeMs, content: await readFile(path) };
  }));
}

test("XPI builder compares two independent staged archives and preserves source files", async t => {
  const { root, source, output } = await fixture(t);
  await chmod(join(source, "background.js"), 0o600);
  const unusualTime = new Date("2020-07-08T09:10:12Z");
  await utimes(join(source, "background.js"), unusualTime, unusualTime);
  const before = await sourceSnapshot(source);
  const invocations = [];
  const result = await buildXpi({
    root,
    run(command, args, options) {
      invocations.push({ command, args, options });
      return spawnSync(command, args, options);
    },
  });
  const zipRuns = invocations.filter(call => call.command === "zip");
  assert.equal(zipRuns.length, 2);
  assert.notEqual(zipRuns[0].options.cwd, zipRuns[1].options.cwd);
  assert.notEqual(zipRuns[0].args[2], zipRuns[1].args[2]);
  for (const call of invocations) {
    assert.equal(call.options.env.TZ, "UTC");
    assert.equal(call.options.env.LC_ALL, "C");
    for (const key of ["ZIPOPT", "UNZIP", "UNZIPOPT", "ZIPINFO", "ZIPINFOOPT"]) {
      assert.equal(Object.hasOwn(call.options.env, key), false);
    }
  }
  assert.equal(invocations.filter(call => call.args[0] === "-tqq").length, 2);
  assert.equal(invocations.filter(call => call.args[0] === "-Z1").length, 2);
  assert.deepEqual(result.files, EXPECTED_FILES);
  assert.equal(result.output, output);
  const bytes = await readFile(output);
  assert.equal(result.digest, createHash("sha256").update(bytes).digest("hex"));
  assert.deepEqual(await sourceSnapshot(source), before);
  const listed = spawnSync("unzip", ["-Z1", output], { encoding: "utf8" });
  assert.equal(listed.status, 0);
  assert.deepEqual(listed.stdout.trim().split("\n"), EXPECTED_FILES);
  for (const file of EXPECTED_FILES) {
    const extracted = spawnSync("unzip", ["-p", output, file]);
    assert.equal(extracted.status, 0);
    assert.deepEqual(extracted.stdout, await readFile(join(source, file)));
  }
  for (const call of zipRuns) assert.equal(await exists(call.options.cwd), false);

  // A separate invocation must produce identical bytes, not update a prior ZIP.
  await buildXpi({ root });
  assert.deepEqual(await readFile(output), bytes);
});

test("XPI builder fails on byte drift and retains the previous good artifact", async t => {
  const { root, source, output } = await fixture(t);
  await mkdir(dirname(output));
  await writeFile(output, "previous verified candidate");
  const before = await sourceSnapshot(source);
  let zipCalls = 0;
  const stages = [];
  await assert.rejects(buildXpi({
    root,
    run(command, args, options) {
      if (command === "zip") {
        stages.push(options.cwd);
        if (++zipCalls === 2) appendFileSync(join(options.cwd, "background.js"), "different bytes\n");
      }
      return spawnSync(command, args, options);
    },
  }), /two independent XPI builds differ/);
  assert.equal(zipCalls, 2);
  assert.equal(await readFile(output, "utf8"), "previous verified candidate");
  assert.deepEqual(await sourceSnapshot(source), before);
  for (const stage of stages) assert.equal(await exists(stage), false);
});

test("XPI builder rejects unexpected and missing extension files", async t => {
  for (const kind of ["unexpected", "missing"]) {
    await t.test(kind, async t => {
      const { root, source, output } = await fixture(t);
      if (kind === "unexpected") await writeFile(join(source, "do-not-package.txt"), "synthetic private fixture");
      else await rm(join(source, "background.js"));
      await assert.rejects(buildXpi({ root }), /extension file allowlist mismatch/);
      assert.equal(await exists(output), false);
    });
  }
});

test("XPI builder rejects symlinked files, directories, and the extension root", async t => {
  for (const kind of ["file", "directory", "source root"]) {
    await t.test(kind, async t => {
      const { root, source, output } = await fixture(t);
      const target = kind === "file" ? join(source, "background.js")
        : kind === "directory" ? join(source, "shared") : source;
      const original = join(root, "untouched-original");
      await rename(target, original);
      await symlink(original, target);
      await assert.rejects(buildXpi({ root }), /symlinks? /);
      assert.equal(await exists(output), false);
      assert.equal(await exists(original), true);
    });
  }
});

test("XPI builder rejects special files without opening them", async t => {
  const { root, source } = await fixture(t);
  const path = join(source, "background.js");
  await rm(path);
  const made = spawnSync("mkfifo", [path], { encoding: "utf8" });
  assert.equal(made.status, 0, made.stderr);
  await assert.rejects(buildXpi({ root }), /unsupported extension entry/);
});

test("XPI builder rejects manifest and package version drift", async t => {
  const cases = [
    ["manifest format", "firefox-extension/manifest.json", { version: "1.2" }, /X.Y.Z/],
    ["non-string manifest version", "firefox-extension/manifest.json", { version: 123 }, /X.Y.Z/],
    ["package", "package.json", { version: "1.1.1" }, /versions must match/],
    ["lock top level", "package-lock.json", { version: "1.1.1", packages: { "": { version: "1.2.0" } } }, /versions must match/],
    ["lock root package", "package-lock.json", { version: "1.2.0", packages: { "": { version: "1.1.1" } } }, /versions must match/],
    ["missing lock package", "package-lock.json", { version: "1.2.0" }, /versions must match/],
  ];
  for (const [label, file, json, error] of cases) {
    await t.test(label, async t => {
      const { root, output } = await fixture(t);
      await writeFile(join(root, file), JSON.stringify(json));
      await assert.rejects(validateSource(root), error);
      await assert.rejects(buildXpi({ root }), error);
      assert.equal(await exists(output), false);
    });
  }
});

test("XPI builder rejects output-directory and artifact symlinks without modifying their targets", async t => {
  for (const kind of ["directory", "file"]) {
    await t.test(kind, async t => {
      const { root, output } = await fixture(t);
      const external = join(root, "do-not-touch");
      if (kind === "directory") {
        await mkdir(external);
        await symlink(external, dirname(output));
      } else {
        await mkdir(dirname(output));
        await writeFile(external, "untouched");
        await symlink(external, output);
      }
      await assert.rejects(buildXpi({ root }), /symlink/);
      if (kind === "file") assert.equal(await readFile(external, "utf8"), "untouched");
      else assert.equal(await exists(join(external, "containoodle-1.2.0.xpi")), false);
    });
  }
});

test("XPI builder verifies archive integrity and exact members before publishing", async t => {
  for (const kind of ["corrupt archive", "unexpected member", "missing zip"]) {
    await t.test(kind, async t => {
      const { root, output } = await fixture(t);
      const run = (command, args, options) => {
        if (command === "zip" && kind === "missing zip") {
          return { status: null, error: new Error("zip unavailable") };
        }
        const result = spawnSync(command, args, options);
        if (command === "zip" && kind === "corrupt archive") writeFileSync(args[2], "not a ZIP");
        if (command === "unzip" && args[0] === "-Z1" && kind === "unexpected member") {
          result.stdout += "unexpected.txt\n";
        }
        return result;
      };
      await assert.rejects(buildXpi({ root, run }),
        kind === "unexpected member" ? /approved allowlist/ : /zip failed/);
      assert.equal(await exists(output), false);
    });
  }
});

test("local AMO preparation reuses validation and the verified builder without signing or uploading", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.scripts["build-for-amo"], "npm run check");
  assert.equal(pkg.scripts.check, "npm test && npm run lint:ext && npm run build:ext");
  assert.equal(pkg.scripts["build:ext"], "node scripts/build-xpi.mjs");
});
