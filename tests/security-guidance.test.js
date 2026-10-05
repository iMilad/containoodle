import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("public installation guidance preserves Firefox signature enforcement", () => {
  for (const name of ["README.md", "RELEASE_NOTES_1.2.0.md", "TESTING_1.2.0.md", "REVIEWER_GUIDE.md", "QA_BASELINE.md"]) {
    const text = readFileSync(new URL(`../${name}`, import.meta.url), "utf8");
    assert.doesNotMatch(text, /xpinstall\.signatures\.required[\s\S]{0,80}\bfalse\b/i, name);
    assert.doesNotMatch(text, /\bpermanent unsigned (?:installation|install|testing)\b/i, name);
  }
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  const install = readme.split("## Install the extension\n")[1].split("\n## ")[0];
  assert.match(install, /Firefox Add-ons/);
  assert.match(install, /Load Temporary Add-on/);
  assert.match(install, /isolated test profile/i);
});
