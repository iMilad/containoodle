import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validateLintImages } from "./lint-extension.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const EXCEPTION_EXPIRES = "2026-10-05T00:00:00Z";
const knownAdvisories = new Set([
  "https://github.com/advisories/GHSA-w3rx-r6r6-pgpr",
  "https://github.com/advisories/GHSA-5p2g-fcmc-qvqq",
]);
const expectedVersions = {
  "image-size": "2.0.2", "addons-linter": "10.10.0", "web-ext": "10.6.0",
};

// Full audit, not --omit=dev. Only these two explicitly contained, build-only
// findings may pass, and the exception expires. Network/report errors fail closed.
export function evaluateAudit(report, lock, now = new Date()) {
  if (report?.error || report?.auditReportVersion !== 2 || !report.vulnerabilities ||
      typeof report.vulnerabilities !== "object" || Array.isArray(report.vulnerabilities)) {
    throw new Error("Dependency audit did not return a valid complete report");
  }
  const findings = report.vulnerabilities;
  const accepted = new Set();
  const inspect = (name, ancestors = new Set()) => {
    const finding = findings[name];
    const entry = lock.packages?.[`node_modules/${name}`];
    if (!Object.hasOwn(expectedVersions, name) || ancestors.has(name) || !finding ||
        finding.name !== name || !Array.isArray(finding.via) || !finding.via.length ||
        !Array.isArray(finding.nodes) || finding.nodes.length !== 1 ||
        finding.nodes[0] !== `node_modules/${name}` ||
        entry?.version !== expectedVersions[name] || entry.dev !== true) {
      throw new Error(`Unapproved dependency finding: ${name}`);
    }
    if (!Number.isFinite(now.getTime()) || now >= new Date(EXCEPTION_EXPIRES)) {
      throw new Error("Build-parser advisory exception expired; review upstream fixes before release");
    }
    const next = new Set([...ancestors, name]);
    for (const via of finding.via) {
      if (typeof via === "string") inspect(via, next);
      else if (name === "image-size" && via?.name === "image-size" &&
               via.dependency === "image-size" && knownAdvisories.has(via.url)) {
        accepted.add(via.url);
      } else throw new Error(`Unapproved dependency advisory: ${name}`);
    }
  };
  for (const name of Object.keys(findings)) inspect(name);
  return { affectedPackages: Object.keys(findings).length, accepted: [...accepted].sort() };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await validateLintImages(join(root, "firefox-extension"));
  const result = spawnSync("npm", ["audit", "--json"], {
    cwd: root, encoding: "utf8", timeout: 60_000, killSignal: "SIGKILL", maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error || ![0, 1].includes(result.status)) {
    throw new Error("Dependency audit failed or timed out; no successful audit is recorded");
  }
  const summary = evaluateAudit(JSON.parse(result.stdout),
    JSON.parse(await readFile(join(root, "package-lock.json"), "utf8")));
  console.log(summary.accepted.length
    ? `Full audit: ${summary.accepted.length} known build-only advisories in ${summary.affectedPackages} packages; PNG-only parser guard and bounded lint contain the affected paths. Exception expires ${EXCEPTION_EXPIRES}. See TOOLING_SECURITY.md.`
    : "Full audit: no dependency vulnerabilities reported.");
}
