/**
 * Scratch run (NOT a submission deploy): deploys the WORKING TREE contract to
 * Studio Dev with demo-like params, or reuses --address=, then files one claim.
 *   node try.mjs [--address=0x..] --url=... --chain=... --addrs=0xa,0xb [--branch=]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { createClient, createAccount } from "genlayer-js";
import { CHAINS, accounts, fundOnStudio, deploy, connect, argOf } from "./harness.mjs";
const chain = CHAINS.studiodev;
const account = createAccount(accounts().probe.key);
const wallet = createClient({ chain, account });
const read = createClient({ chain });
await fundOnStudio(chain, account.address, 1000n * 10n ** 18n);
let address = argOf("address");
if (!address) {
  const code = readFileSync(new URL("../contracts/AdminClaim.py", import.meta.url), "utf8");
  const res = await deploy({ chain, wallet, read, code, args: [argOf("mode", "DEMO"), Number(argOf("cooldown", "60")), Number(argOf("fresh", "3600"))], label: "scratch" });
  if (!res.ok) { console.error("deploy failed", res.out?.status, res.reason, res.out?.revertReason, res.out?.stderr?.slice(-3000)); process.exit(1); }
  address = res.address;
}
console.log("scratch at", address);
const { send, view } = connect({ address, role: "probe" });
if (argOf("url")) {
  const out = await send("file_claim", [argOf("url"), argOf("branch", ""), argOf("chain"), argOf("addrs")]);
  console.log(out.status, out.ok, "revert:", out.revertReason?.slice(0, 500), out.seconds, "s", out.hash);
  console.log("returned:", JSON.stringify(out.returned)?.slice(0, 1500));
  if (!out.ok) console.log("stderr:", out.stderr.slice(-3000));
}
const stats = await view("get_stats");
console.log("stats", JSON.stringify(stats));
if (argOf("show")) console.log(JSON.stringify(await view("get_record", [Number(argOf("show"))]), (k, v) => typeof v === "bigint" ? Number(v) : v, 1).slice(0, 8000));
