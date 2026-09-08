import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { lintExtension, LINT_TIMEOUT_MS, validateLintImages } from "../scripts/lint-extension.mjs";
import { evaluateAudit, EXCEPTION_EXPIRES } from "../scripts/audit-dependencies.mjs";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "containoodle-lint-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await cp(join(repo, "firefox-extension"), join(root, "firefox-extension"), { recursive: true });
  for (const file of ["package.json", "package-lock.json"]) {
    await cp(join(repo, file), join(root, file));
  }
  return root;
}

test("lint stages approved PNGs and invokes a bounded guarded child without config discovery", async t => {
  const root = await fixture(t);
  let staged;
  const result = await lintExtension({ root, run(command, args, options) {
    staged = options.cwd;
    assert.equal(command, process.execPath);
    assert.ok(args.includes("--no-config-discovery"));
    assert.ok(args.includes(join(repo, "scripts/lint-image-guard.cjs")));
    assert.ok(args.includes(`--source-dir=${staged}`));
    assert.equal(options.timeout, LINT_TIMEOUT_MS);
    assert.equal(options.killSignal, "SIGKILL");
    assert.notEqual(staged, join(root, "firefox-extension"));
    return { status: 0, stdout: "synthetic success", stderr: "" };
  } });
  assert.equal(result.stdout, "synthetic success");
  await assert.rejects(readFile(join(staged, "manifest.json")), { code: "ENOENT" });
});

const malformedImages = {
  ICNS: Buffer.from("69636e730000001069636f6e00000000", "hex"),
  JXL: Buffer.from("0000000c4a584c200d0a870a00000014667479706a786c20000000006a786c20000000006a786c63", "hex"),
  HEIF: Buffer.from("00000018667479706865696300000000686569636d696631000000006d657461", "hex"),
};
for (const [type, bytes] of Object.entries(malformedImages)) {
  test(`lint rejects disguised ${type} bytes before invoking the linter`, async t => {
    const root = await fixture(t);
    await writeFile(join(root, "firefox-extension/icons/icon-48.png"), bytes);
    let invoked = false;
    await assert.rejects(lintExtension({ root, run() { invoked = true; } }), /expected 48px PNG/);
    assert.equal(invoked, false);
  });
  test(`the actual linter parser rejects ${type} with its calculation disabled`, () => {
    const result = spawnSync(process.execPath, [
      "--require", join(repo, "scripts/lint-image-guard.cjs"), "-e",
      `const r = require('node:module').createRequire(require.resolve('addons-linter'));
       require('node:assert/strict').throws(() => r('image-size').imageSize(Buffer.from('${bytes.toString("hex")}', 'hex')), /disabled file type/);`,
    ], { cwd: repo, encoding: "utf8", timeout: 2000, killSignal: "SIGKILL" });
    assert.equal(result.error, undefined, "parser must reject without hanging");
    assert.equal(result.status, 0, result.stderr);
  });
}

test("manifest image references cannot route text or unapproved formats into the image parser", async t => {
  const root = await fixture(t);
  const source = join(root, "firefox-extension");
  const path = join(source, "manifest.json");
  const manifest = JSON.parse(await readFile(path, "utf8"));
  manifest.sidebar_action.default_icon = "background.js";
  await writeFile(path, JSON.stringify(manifest));
  await assert.rejects(validateLintImages(source), /approved PNG/);
});

test("lint timeout fails and removes the staging directory", async t => {
  const root = await fixture(t);
  let staged;
  await assert.rejects(lintExtension({ root, run(_command, _args, options) {
    staged = options.cwd;
    return { status: null, error: Object.assign(new Error("synthetic timeout"), { code: "ETIMEDOUT" }) };
  } }), /60-second deadline/);
  await assert.rejects(readFile(join(staged, "manifest.json")), { code: "ENOENT" });
});

function auditFixture() {
  const names = ["image-size", "addons-linter", "web-ext"];
  const versions = ["2.0.2", "10.10.0", "10.6.0"];
  const vulnerabilities = {};
  const packages = {};
  names.forEach((name, index) => {
    packages[`node_modules/${name}`] = { version: versions[index], dev: true };
    vulnerabilities[name] = { name, nodes: [`node_modules/${name}`], via: index
      ? [names[index - 1]]
      : ["GHSA-w3rx-r6r6-pgpr", "GHSA-5p2g-fcmc-qvqq"].map(id => ({
        name, dependency: name, url: `https://github.com/advisories/${id}`,
      })) };
  });
  return { report: { auditReportVersion: 2, vulnerabilities }, lock: { packages } };
}
const reviewDate = new Date("2026-09-05T00:00:00Z");

test("full audit accepts only the two contained advisories and their build-only dependency chain", () => {
  const { report, lock } = auditFixture();
  const result = evaluateAudit(report, lock, reviewDate);
  assert.equal(result.accepted.length, 2);
  assert.equal(result.affectedPackages, 3);
});
test("full audit fails closed on new advisories, production dependencies, or version drift", () => {
  for (const mutate of [
    ({ report }) => { report.vulnerabilities["image-size"].via.push({ name: "image-size", dependency: "image-size", url: "https://example.invalid/new-advisory" }); },
    ({ lock }) => { lock.packages["node_modules/image-size"].dev = false; },
    ({ lock }) => { lock.packages["node_modules/image-size"].version = "9.9.9"; },
    ({ report }) => { report.vulnerabilities["web-ext"].via = ["web-ext"]; },
    ({ report }) => { report.vulnerabilities["image-size"].nodes.push("node_modules/other/node_modules/image-size"); },
  ]) {
    const data = auditFixture();
    mutate(data);
    assert.throws(() => evaluateAudit(data.report, data.lock, reviewDate), /Unapproved/);
  }
});
test("full audit rejects expired exceptions and unavailable or malformed reports", () => {
  const { report, lock } = auditFixture();
  assert.throws(() => evaluateAudit(report, lock, new Date(EXCEPTION_EXPIRES)), /expired/);
  for (const bad of [undefined, {}, { error: { code: "ENOTFOUND" } }, { auditReportVersion: 2, vulnerabilities: [] }]) {
    assert.throws(() => evaluateAudit(bad, lock, reviewDate), /valid complete report/);
  }
  assert.deepEqual(evaluateAudit({ auditReportVersion: 2, vulnerabilities: {} }, lock, reviewDate),
    { affectedPackages: 0, accepted: [] });
});
