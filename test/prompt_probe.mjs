/** Sends AdminClaim's exact prompt for a docs file to the model twice (via the probe contract) and prints the raw answers and what code keeps. */
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createClient, createAccount } from "genlayer-js";
import { CHAINS, accounts, fundOnStudio, deploy, connect, argOf } from "./harness.mjs";
const chain = CHAINS.studiodev;
const account = createAccount(accounts().probe.key);
const wallet = createClient({ chain, account });
const read = createClient({ chain });
let address = argOf("address");
if (!address) {
  await fundOnStudio(chain, account.address, 1000n * 10n ** 18n);
  const res = await deploy({ chain, wallet, read, code: readFileSync(new URL("./probe/_probe.py", import.meta.url), "utf8"), args: [], label: "probe" });
  address = res.address; console.log("probe at", address);
}
const prompt = execFileSync("python3", [new URL("../tools/prompt_of.py", import.meta.url).pathname, argOf("url"), argOf("chain"), argOf("addrs")]).toString();
const { send, view } = connect({ address, role: "probe" });
const out = await send("probe_prompt", [prompt]);
console.log(out.status, out.ok, out.seconds);
const last = JSON.parse(await view("get_last"));
writeFileSync("/tmp/adminclaim_answers.json", JSON.stringify(last));
console.log(execFileSync("python3", [new URL("../tools/prompt_of.py", import.meta.url).pathname, argOf("url"), argOf("chain"), argOf("addrs"), "/tmp/adminclaim_answers.json"]).toString());
