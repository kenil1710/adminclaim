/**
 * Files every seed in seeds.json on the CANONICAL deployment, one at a time,
 * and writes what happened to docs/seed-canonical.json (resumable: seeds that
 * already have a record are skipped). Nothing is forced: a refusal or an
 * unsettled round is recorded as such and retried at most `--tries` times.
 *   node seed_canonical.mjs [--only=id,id] [--tries=3]
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { connect, argOf, sleep, returnedJson } from "./harness.mjs";

const dep = JSON.parse(readFileSync(new URL("../deployments.json", import.meta.url), "utf8"));
const target = argOf("target", "AdminClaim");
const address = dep.contracts[target].address;
const outPath = new URL(`../docs/seed-${target === "AdminClaim" ? "canonical" : "demo"}.json`, import.meta.url);
const seeds = JSON.parse(readFileSync(new URL("./seeds.json", import.meta.url), "utf8"));
const only = argOf("only") ? argOf("only").split(",") : null;
const tries = Number(argOf("tries", "3"));
const doc = existsSync(outPath) ? JSON.parse(readFileSync(outPath, "utf8")) : { contract: address, runs: [] };
const save = () => writeFileSync(outPath, JSON.stringify(doc, null, 2) + "\n");
const { send, viewJson, view } = connect({ address, role: argOf("role", "filer") });
console.log(`${target} ${address}`);

for (const s of seeds) {
  if (only && !only.includes(s.id)) continue;
  if (doc.runs.some((r) => r.id === s.id && r.record_id)) { console.log(`skip ${s.id} (recorded)`); continue; }
  for (let t = 1; t <= tries; t++) {
    console.log(`\n${s.id}  try ${t}  ${s.chain} ${s.addresses.join(",")}`);
    const out = await send("file_claim", [s.url, "", s.chain, s.addresses.join(",")]);
    const ret = returnedJson(out);
    const run = { id: s.id, label: s.label, try: t, at: new Date().toISOString(), tx: out.hash, status: out.status,
      ok: out.ok, seconds: out.seconds, revert: out.ok ? "" : String(out.revertReason ?? out.failure ?? "").slice(0, 200) };
    if (out.ok && ret?.record_id) {
      run.record_id = ret.record_id; run.verdict = ret.verdict; run.basis = ret.basis; run.block = ret.block; run.summary = ret.summary;
    }
    doc.runs.push(run); save();
    console.log(`  ${out.status} ok=${out.ok} ${run.verdict ?? run.revert}  ${out.seconds}s  ${out.hash}`);
    if (run.record_id) break;
    const wait = /GITHUB_API_HTTP_403|GITHUB_API_HTTP_429/.test(run.revert) ? 900_000 : 60_000;
    console.log(`  waiting ${wait / 1000}s`);
    await sleep(wait);
  }
  await sleep(20_000);
}
console.log("\nstats", JSON.stringify(await view("get_stats")));
