/* ═══════════════════════════════════════════════════════════════════
   Containoodle — environment classification from an AWS account name.

   Pure, no AWS calls. ES module shared by the sidebar, the background
   script (tab-group / container colors) and Node unit tests.

   Rules: prod > qa > dev > test/eval (grey). A name with no recognized
   keyword is treated as prod — better a false red than a missed prod.
   "non/pre prod" means NOT production; "dev ops" is a role, not an env.
   ═══════════════════════════════════════════════════════════════════ */

export function accountEnv(name) {
  const tokens = String(name)
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z]+/);
  const words = tokens.map((t, i) => {
    if (t === "prod" && (tokens[i - 1] === "non" || tokens[i - 1] === "pre")) return "nonprod";
    if (t === "dev" && tokens[i + 1] === "ops") return "devops";
    return t;
  });
  if (words.includes("prod") || words.includes("production")) return "prod";
  if (words.includes("qa")) return "qa";
  if (words.includes("dev") || words.includes("development")) return "dev";
  const grey = ["test", "testing", "eval", "evaluation", "nonprod", "preprod"];
  if (grey.some((t) => words.includes(t))) return "test";
  return "prod";
}
