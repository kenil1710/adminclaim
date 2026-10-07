/** Deploys test/probe/_probe.py to Studio Dev (or reuses --address=) and runs one batch of requests from GenVM. */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createClient, createAccount } from "genlayer-js";
import { CHAINS, accounts, fundOnStudio, deploy, connect, argOf } from "./harness.mjs";
const chain = CHAINS.studiodev;
const account = createAccount(accounts().probe.key);
const wallet = createClient({ chain, account });
const read = createClient({ chain });
await fundOnStudio(chain, account.address, 1000n * 10n ** 18n);
let address = argOf("address");
if (!address) {
  const res = await deploy({ chain, wallet, read, code: readFileSync(new URL("./probe/_probe.py", import.meta.url), "utf8"), args: [], label: "probe" });
  if (!res.ok) { console.error("deploy failed", res.out?.stderr?.slice(-1500), res.reason, res.out?.revertReason); process.exit(1); }
  address = res.address;
}
console.log("probe at", address);
const { send, view } = connect({ address, role: "probe" });
const reqs = readFileSync(argOf("file"), "utf8");
const out = await send("probe", [reqs]);
console.log(out.status, out.ok, out.revertReason?.slice(0, 300), out.seconds, "s", out.hash);
const last = await view("get_last");
mkdirSync(new URL("../docs/research/", import.meta.url), { recursive: true });
const result = (() => { try { return JSON.parse(last); } catch { return last; } })();
writeFileSync(new URL(`../docs/research/probe_${argOf("tag", "1")}.json`, import.meta.url), JSON.stringify({ address, tx: out.hash, status: out.status, seconds: out.seconds, result }, null, 2) + "\n");
console.log(JSON.stringify(result, null, 1).slice(0, 12000));
