/** Demo: two filings on one key submitted back to back; the second must be refused COOLDOWN. Appends to docs/seed-demo.json. */
import { readFileSync, writeFileSync } from "node:fs";
import { connect, sleep, returnedJson } from "./harness.mjs";
const dep = JSON.parse(readFileSync(new URL("../deployments.json", import.meta.url), "utf8"));
const path = new URL("../docs/seed-demo.json", import.meta.url);
const doc = JSON.parse(readFileSync(path, "utf8"));
const { send } = connect({ address: dep.contracts.AdminClaimDemo.address, role: "demo" });
const rec = doc.steps.find((s) => s.step === "stronger").record_id;
const args = doc.steps.find((s) => s.step === "stronger").args;
const a = send("recheck", [rec]);
await sleep(4000);
const b = send("file_claim", args);
const [oa, ob] = await Promise.all([a, b]);
for (const [name, o, method, ar, expect] of [["recheck_after_cooldown_2", oa, "recheck", [rec], "(new record linked)"], ["refuse_cooldown", ob, "file_claim", args, "COOLDOWN"]]) {
  const ret = returnedJson(o);
  const step = { step: name, method, args: ar, expect, at: new Date().toISOString(), tx: o.hash, status: o.status, ok: o.ok, seconds: o.seconds,
    revert: o.ok ? "" : String(o.revertReason ?? o.failure ?? "").slice(0, 200) };
  if (o.ok && ret?.record_id) Object.assign(step, { record_id: ret.record_id, prev_id: ret.prev_id, verdict: ret.verdict, block: ret.block, summary: ret.summary });
  step.matched = expect.startsWith("(") ? Boolean(step.record_id) : step.revert.includes(expect);
  doc.steps.push(step);
  console.log(name, o.status, o.ok, step.verdict ?? step.revert, "prev", step.prev_id, "matched", step.matched, o.hash);
}
writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
