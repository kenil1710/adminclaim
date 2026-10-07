/**
 * Reads each deployed contract's code BACK FROM STUDIO DEV (gen_getContractCode)
 * and compares it byte for byte with contracts/ at HEAD and with the sha256 in
 * deployments.json. Also checks every deployment came from the same commit and
 * that contracts/ did not change after it.
 *   node tools/verify_source.mjs        exit 1 on any mismatch
 */
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
const root = new URL("..", import.meta.url).pathname;
const require = createRequire(new URL("../test/package.json", import.meta.url));
const { createClient } = require("genlayer-js");
const { studioDevnet } = require("genlayer-js/chains");
const sha = (b) => createHash("sha256").update(b).digest("hex");
const dep = JSON.parse(readFileSync(root + "deployments.json", "utf8")).contracts;
const git = (...a) => execFileSync("git", ["-C", root, ...a]).toString().trim();
const head = git("rev-parse", "HEAD");
const client = createClient({ chain: studioDevnet });
let bad = 0;
console.log(`HEAD ${head}`);
const commits = new Set(Object.values(dep).map((r) => r.commit));
for (const [name, rec] of Object.entries(dep)) {
  let code = "";
  for (let i = 0; i < 5 && !code; i++) { try { code = await client.getContractCode(rec.address); } catch { await new Promise((r) => setTimeout(r, 3000)); } }
  const atHead = execFileSync("git", ["-C", root, "show", `HEAD:${rec.file}`]);
  const onChain = Buffer.from(String(code), "utf8");
  const same = onChain.equals(atHead), recorded = rec.sha256 === sha(atHead);
  const touched = git("log", "--format=%H", `${rec.commit}..HEAD`, "--", "contracts");
  if (!same || !recorded || touched !== "") bad++;
  console.log(`${name.padEnd(15)} ${rec.address}  chain sha256 ${sha(onChain)}  ${same ? "identical to HEAD" : "DIFFERS FROM HEAD"}  ${recorded ? "matches deployments.json" : "MISMATCH"}  deploy commit ${rec.commit.slice(0, 10)}  ${touched === "" ? "contracts/ unchanged since" : "contracts/ CHANGED since: " + touched.split("\n").join(",")}`);
}
if (commits.size !== 1) { bad++; console.log("deployments come from more than one commit:", [...commits]); }
else console.log(`all deployments from one commit: ${[...commits][0]}`);
process.exit(bad ? 1 : 0);
