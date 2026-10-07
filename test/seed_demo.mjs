/**
 * Drives the DEMO deployment (60 s cooldown, 10 min freshness) through every
 * path: each verdict, every refusal, a recheck after the cooldown, and the
 * duplicate rule. Writes docs/seed-demo.json. Real contracts, real docs; the
 * statements file docs/demo/claims.md is this repo's own (see its header).
 *   node seed_demo.mjs [--only=step,step]
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { connect, argOf, sleep, returnedJson } from "./harness.mjs";

const dep = JSON.parse(readFileSync(new URL("../deployments.json", import.meta.url), "utf8"));
const address = dep.contracts.AdminClaimDemo.address;
const outPath = new URL("../docs/seed-demo.json", import.meta.url);
const doc = existsSync(outPath) ? JSON.parse(readFileSync(outPath, "utf8")) : { contract: address, steps: [] };
const save = () => writeFileSync(outPath, JSON.stringify(doc, null, 2) + "\n");
const { send, view } = connect({ address, role: "demo" });
const only = argOf("only") ? argOf("only").split(",") : null;

const DEMO_SHA = argOf("demo_sha", "99d81aa3463d21bd2af6bdfed114c9a94c7db30c");
const DEMO = `https://raw.githubusercontent.com/kenil1710/adminclaim/${DEMO_SHA}/docs/demo/claims.md`;
const BAL = "https://raw.githubusercontent.com/balancer/docs-v3/98d4c352e332419d70415fa07a584579ac65b8e2/docs/concepts/governance/multisig.md";
const LIDO_EB = "https://raw.githubusercontent.com/lidofinance/docs/4c391cfe400f359ff346035b86f9d1703c3929e5/docs/multisigs/emergency-brakes.md";
const YEARN_FORK = "https://raw.githubusercontent.com/yearn/yearn-devdocs/21233a9e98ce6052b891dbbac0b07a65fd409281/docs/developers/security/multisig.md";

const STEPS = [
  // verdicts
  ["match_safe", "file_claim", [DEMO, "", "polygon", "0xeE071f4B516F69a1603dA393CdE8e76C40E5Be85"], "MATCH"],
  ["match_real_docs", "file_claim", [BAL, "", "polygon", "0xeE071f4B516F69a1603dA393CdE8e76C40E5Be85"], "MATCH"],
  ["weaker", "file_claim", [DEMO, "", "polygon", "0x87D93d9B2C672bf9c9642d853a8682546a5012B5"], "WEAKER_THAN_CLAIMED"],
  ["stronger", "file_claim", [DEMO, "", "polygon", "0xC18F11735C6a1941431cCC5BcF13AF0a052A5022"], "STRONGER_THAN_CLAIMED"],
  ["match_immutable", "file_claim", [DEMO, "", "polygon", "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"], "MATCH"],
  ["unverifiable_nonstandard", "file_claim", [DEMO, "", "polygon", "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619"], "UNVERIFIABLE"],
  ["unverifiable_modules", "file_claim", [DEMO, "", "polygon", "0x3c58668054c299bE836a0bBB028Bee3aD4724846"], "UNVERIFIABLE"],
  ["hard_to_read", "file_claim", [DEMO, "", "polygon", "0xFc832dA3D688352C0aB1A32136c7fABbB16d66E6"], "(model decides what to quote; any outcome)"],
  // refusals
  ["refuse_branch", "file_claim", [DEMO.replace(DEMO_SHA, "main"), "", "polygon", "0xeE071f4B516F69a1603dA393CdE8e76C40E5Be85"], "URL_NOT_PINNED_TO_COMMIT"],
  ["refuse_tag", "file_claim", [BAL.replace("98d4c352e332419d70415fa07a584579ac65b8e2", "v1.0.0"), "", "polygon", "0xeE071f4B516F69a1603dA393CdE8e76C40E5Be85"], "URL_NOT_PINNED_TO_COMMIT"],
  ["refuse_percent", "file_claim", [DEMO.replace("claims.md", "cl%61ims.md"), "", "polygon", "0xeE071f4B516F69a1603dA393CdE8e76C40E5Be85"], "URL_PERCENT_ENCODED"],
  ["refuse_query", "file_claim", [DEMO + "?plain=1", "", "polygon", "0xeE071f4B516F69a1603dA393CdE8e76C40E5Be85"], "URL_HAS_QUERY_OR_FRAGMENT"],
  ["refuse_host", "file_claim", ["https://docs.balancer.fi/concepts/governance/multisig.html", "", "polygon", "0xeE071f4B516F69a1603dA393CdE8e76C40E5Be85"], "URL_HOST_NOT_ALLOWED"],
  ["refuse_fork_branch", "file_claim", [DEMO, "attacker:main", "polygon", "0xeE071f4B516F69a1603dA393CdE8e76C40E5Be85"], "BAD_BRANCH"],
  ["refuse_chain", "file_claim", [DEMO, "", "bsc", "0xeE071f4B516F69a1603dA393CdE8e76C40E5Be85"], "UNSUPPORTED_CHAIN"],
  ["refuse_bad_address", "file_claim", [DEMO, "", "polygon", "0xeE071f4B516F69a1603dA393CdE8e76C40E5Be8"], "BAD_ADDRESS"],
  ["refuse_address_not_in_docs", "file_claim", [DEMO, "", "polygon", "0x7c68c42De679ffB0f16216154C996C354cF1161B"], "ADDRESS_NOT_IN_DOCS"],
  ["refuse_fork_commit", "file_claim", [YEARN_FORK, "", "ethereum", "0xFEB4acf3df3cDEA7399794D0869ef76A6EfAff52"], "COMMIT_NOT_ON_BRANCH"],
  ["refuse_block_too_old", "file_claim", [LIDO_EB, "", "ethereum", "0x73b047fe6337183A454c5217241D780a932777bD"], "BLOCK_TOO_OLD"],
  ["refuse_cooldown", "file_claim", [DEMO, "", "polygon", "0xeE071f4B516F69a1603dA393CdE8e76C40E5Be85"], "COOLDOWN"],
  ["refuse_recheck_cooldown", "recheck", ["@match_safe"], "COOLDOWN"],
  ["wait_cooldown", "sleep", [65_000], ""],
  ["recheck_after_cooldown", "recheck", ["@match_safe"], "(new record linked to match_safe)"],
  ["refuse_unknown_record", "recheck", [9999], "NO_SUCH_RECORD"],
];

const idOf = (name) => doc.steps.find((s) => s.step === name && s.record_id)?.record_id;
for (const [name, method, args0, expect] of STEPS) {
  if (only && !only.includes(name)) continue;
  if (!only && doc.steps.some((s) => s.step === name && (s.record_id || s.matched))) { console.log(`skip ${name}`); continue; }
  if (method === "sleep") { console.log(`sleep ${args0[0] / 1000}s`); await sleep(args0[0]); continue; }
  const args = args0.map((a) => (typeof a === "string" && a.startsWith("@") ? idOf(a.slice(1)) : a));
  console.log(`\n${name}: ${method}(${JSON.stringify(args).slice(0, 160)})  expect ${expect}`);
  const out = await send(method, args);
  const ret = returnedJson(out);
  const step = { step: name, method, args, expect, at: new Date().toISOString(), tx: out.hash, status: out.status, ok: out.ok,
    seconds: out.seconds, revert: out.ok ? "" : String(out.revertReason ?? out.failure ?? "").slice(0, 200) };
  if (out.ok && ret?.record_id) Object.assign(step, { record_id: ret.record_id, prev_id: ret.prev_id, verdict: ret.verdict, basis: ret.basis, block: ret.block, summary: ret.summary });
  step.matched = expect.startsWith("(") ? Boolean(step.record_id) : (step.verdict === expect || step.revert.includes(expect));
  doc.steps.push(step); save();
  console.log(`  ${out.status} ok=${out.ok} ${step.verdict ?? step.revert}  matched=${step.matched}  ${out.seconds}s ${out.hash}`);
  await sleep(8_000);
}
console.log("\nstats", JSON.stringify(await view("get_stats")));
