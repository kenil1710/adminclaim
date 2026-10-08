/** ADDRESSES.md and docs/superseded/README.md from deployments.json. */
import { readFileSync, writeFileSync } from "node:fs";
const root = new URL("..", import.meta.url).pathname;
const dep = JSON.parse(readFileSync(root + "deployments.json", "utf8"));
const EX = "https://explorer-studio-dev.genlayer.com";
const c = dep.contracts;
const row = (n, r) => `| ${r.mode} | [\`${r.address}\`](${EX}/address/${r.address}) | \`${JSON.stringify(r.constructor_args)}\` | [\`${r.commit.slice(0, 10)}\`](https://github.com/kenil1710/adminclaim/commit/${r.commit}) | [deploy tx](${EX}/tx/${r.deploy_tx}) | \`${r.sha256}\` |`;
writeFileSync(root + "ADDRESSES.md", `# Addresses

Network: GenLayer Studio Dev (chain id ${dep.chain_id}), RPC \`${dep.rpc}\`, explorer ${dep.explorer}

| Deployment | Address | Constructor | Commit | Deploy | contracts/AdminClaim.py sha256 |
|---|---|---|---|---|---|
${row("AdminClaim", c.AdminClaim)}
${row("AdminClaimDemo", c.AdminClaimDemo)}

Both deployments are the same file from the same commit; only the constructor differs (cooldown seconds, freshness seconds). \`node tools/verify_source.mjs\` reads the code back with \`gen_getContractCode\` and compares it byte for byte with \`contracts/\` at HEAD.

Previous deployments: [docs/superseded/README.md](docs/superseded/README.md).
`);
const sup = dep.superseded ?? [];
writeFileSync(root + "docs/superseded/README.md", `# Superseded deployments

These addresses ran earlier versions of \`contracts/AdminClaim.py\`. They are kept here only for history; use [ADDRESSES.md](../../ADDRESSES.md).

| Deployment | Address | Commit | Replaced by | Why |
|---|---|---|---|---|
${sup.map((s) => `| ${s.name} (${s.mode}) | \`${s.address}\` | \`${s.commit.slice(0, 10)}\` | \`${s.superseded_by}\` | ${s.why} |`).join("\n")}

Seed run on the first canonical deployment (v1.0.0): [seed-canonical-v1.0.0.json](seed-canonical-v1.0.0.json) (7 records: MATCH 5, WEAKER_THAN_CLAIMED 2; the 8th filing was refused when the GitHub API budget ran out). It was stopped when the round-1 attacker pass changed the contract.
`);
console.log("written");
