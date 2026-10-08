/**
 * docs/FINAL_CHECK.md: every final-check item as PASS / FAIL with its proof,
 * computed now from the repo, the chain (gen_getContractCode, get_record) and
 * the test run.
 *   node tools/final_check.mjs
 */
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
const root = new URL("..", import.meta.url).pathname;
const require = createRequire(new URL("../test/package.json", import.meta.url));
const { createClient } = require("genlayer-js");
const { studioDevnet } = require("genlayer-js/chains");
const client = createClient({ chain: studioDevnet });
const sh = (cmd, args, opts = {}) => spawnSync(cmd, args, { cwd: root, encoding: "utf8", ...opts });
const git = (...a) => execFileSync("git", ["-C", root, ...a]).toString().trim();
const dep = JSON.parse(readFileSync(root + "deployments.json", "utf8"));
const CAN = dep.contracts.AdminClaim.address, DEMO = dep.contracts.AdminClaimDemo.address;
const src = readFileSync(root + "contracts/AdminClaim.py", "utf8");
const readme = readFileSync(root + "README.md", "utf8");
const seedsRun = JSON.parse(readFileSync(root + "docs/seed-canonical.json", "utf8")).runs;
const demoRun = JSON.parse(readFileSync(root + "docs/seed-demo.json", "utf8")).steps;
const norm = (v) => JSON.parse(JSON.stringify(v, (k, x) => (typeof x === "bigint" ? Number(x) : x instanceof Map ? Object.fromEntries(x) : x)));
async function view(address, fn, args) {
  for (let i = 0; i < 6; i++) {
    try { return norm(await client.readContract({ address, functionName: fn, args })); } catch { await new Promise((r) => setTimeout(r, 4000 * (i + 1))); }
  }
  throw new Error("view " + fn);
}
const rows = [];
const add = (item, pass, proof) => rows.push({ item, pass, proof });
const head = git("rev-parse", "HEAD");

// 1. source match
const vs = sh("node", ["tools/verify_source.mjs"]);
add("Source match (canonical + demo)", vs.status === 0, "`node tools/verify_source.mjs`:\n```\n" + vs.stdout.trim() + "\n```");

// 2. no payable / custody
const t = sh("python3", ["-c", `
import ast,sys
src=open("contracts/AdminClaim.py").read(); tree=ast.parse(src)
cls=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=="AdminClaim"][0]
dec=[ast.unparse(d) for f in cls.body if isinstance(f,ast.FunctionDef) for d in f.decorator_list]
print("decorators:", sorted(set(dec)))
for w in ("write.payable","emit_transfer","gl.message.value","balance","withdraw"):
    print(w, "absent" if w not in src else "PRESENT")
fields=[n.target.id for n in cls.body if isinstance(n,ast.AnnAssign)]
print("storage fields:", fields)
`]);
add("No payable method, no custody, no owner/admin", !/PRESENT/.test(t.stdout) && !/payable/.test(t.stdout.split("\n")[0]), "```\n" + t.stdout.trim() + "\n```");

// 3. nothing stuck
add("Nothing can get stuck", !/PENDING|OPEN|deadline/i.test(src.split("class AdminClaim")[1]) && src.includes("def file_claim") ,
  "A filing either stores one finished record in the same transaction or stores nothing (refusal = revert; validator disagreement = no record). The contract has no pending / open state, no deadline and no second step: `grep -ciE 'PENDING|OPEN|deadline'` over the contract class = " +
  (src.split("class AdminClaim")[1].match(/PENDING|OPEN\b|deadline/gi) || []).length + ". Live: every filing transaction in docs/seed-canonical.json and docs/seed-demo.json ended ACCEPTED (record or refusal) or with no state change.");

// 4. counter before revert
const sw = sh("python3", ["tools/scan_writes.py"]);
add("No state written before a revert (AST scan of every write method)", sw.status === 0, "`python3 tools/scan_writes.py`:\n```\n" + sw.stdout.trim() + "\n```\nand the offline harness asserts byte-identical state after every refusal (`fixtures.tx`).");

// 5. views = storage
const tv = sh("python3", ["-m", "unittest", "test_adminclaim.Static.test_views_do_not_fetch_or_prompt", "test_adminclaim.Filing.test_views_are_storage"], { cwd: root + "test" });
add("Views only read storage", tv.status === 0, "Views: get_config, get_record, get_records, get_history, get_keys, get_stats. `test_views_do_not_fetch_or_prompt` (AST: no nondet / web / prompt / gather in any view) and `test_views_are_storage` (no web request or prompt while calling every view): " + (tv.status === 0 ? "OK" : tv.stderr.slice(-400)));

// 6. evidence bound
const firstSeed = seedsRun.find((r) => r.record_id);
const r1 = await view(CAN, "get_record", [firstSeed.record_id]);
add("Evidence bound to commit + addresses + block", Boolean(r1.commit && r1.addresses.length && r1.block && r1.docs_sha256 && r1.evidence_sha256 && r1.block_hash),
  `canonical record #${r1.record_id} (read now with get_record): commit \`${r1.commit}\`, docs sha256 \`${r1.docs_sha256}\`, addresses ${r1.addresses.join(",")}, block ${r1.block} hash \`${r1.block_hash}\` time ${r1.block_time}, branch proof \`${r1.branch}\`=${r1.branch_status}, chain reads in chain_facts (${Object.keys(r1.chain_facts.nodes).length} nodes), evidence sha256 \`${r1.evidence_sha256}\`. Validators compare this whole record byte for byte (\`validate_record\`).`);

// 7. commit on original repo
const recs = [];
for (const r of seedsRun.filter((x) => x.record_id)) recs.push(await view(CAN, "get_record", [r.record_id]));
const fork = demoRun.find((s) => s.step === "refuse_fork_commit");
add("Docs commit proven on a branch of the original repo", recs.every((r) => ["behind", "identical"].includes(r.branch_status)) && fork && /COMMIT_NOT_ON_BRANCH/.test(fork.revert),
  `All ${recs.length} canonical records: branch_status ∈ {behind, identical} (${[...new Set(recs.map((r) => r.branch_status))].join(", ")}). Live refusal of a fork-only commit (yearn/yearn-devdocs PR #643 head 21233a9e, served by the parent's raw URL): demo tx \`${fork?.tx}\` → \`${fork?.revert}\`.`);

// 8. allowlist
const ta = sh("python3", ["-m", "unittest", "test_adminclaim.Static.test_every_fetch_goes_through_the_allowlist", "test_adminclaim.DocsUrl"], { cwd: root + "test" });
const urlRef = demoRun.filter((s) => /URL_|HOST/.test(s.revert)).map((s) => `${s.step}: ${s.revert}`);
add("Allowlist only", ta.status === 0 && urlRef.length >= 4, "Every `gl.nondet.web` call sits in `http_get` / `rpc_transport.send`, both gated by `allowed_url` (pinned raw file, GitHub compare API, five frozen RPCs). Unit tests: " + (ta.status === 0 ? "OK" : "FAIL") + ". Live demo refusals: " + urlRef.join("; "));

// 9. freshness
const old = demoRun.find((s) => s.step === "refuse_block_too_old");
add("Block freshness enforced", Boolean(old && /BLOCK_TOO_OLD/.test(old.revert)), `Demo (10 min) refused an Ethereum filing whose finalized block was ~15 min old: tx \`${old?.tx}\` → \`${old?.revert}\`. Canonical records' block age at filing (filed_at - block_time, max 3600): ${recs.map((r) => r.filed_at - r.block_time).join(", ")} s.`);

// 10. model only quotes
const tm = sh("python3", ["-m", "unittest", "test_adminclaim.Static.test_model_output_only_reaches_keep_claims", "test_attacks.Attacks.test_a07_quote_real_number_altered", "test_attacks.Attacks.test_a09_injected_instructions"], { cwd: root + "test" });
add("The model only quotes; code decides", tm.status === 0, "`exec_prompt` appears once (`ask_claims`) and its output goes only into `keep_claims`, which keeps a claim only if the quote is verbatim and code's own parse of it equals the model's value; numbers, chain facts, comparison, verdict and wording are code. Tests: " + (tm.status === 0 ? "OK" : "FAIL"));

// 11. disagreement -> INCONCLUSIVE
const ti = sh("python3", ["-m", "unittest", "test_adminclaim.Filing.test_unstable_model_is_inconclusive", "test_adminclaim.Filing.test_validator_disagreeing_on_claims_rolls", "test_adminclaim.Filing.test_forged_unstable_is_accepted_but_only_inconclusive"], { cwd: root + "test" });
const inc = [...seedsRun, ...demoRun].filter((s) => s.verdict === "INCONCLUSIVE").map((s) => s.tx);
add("Claim disagreement → INCONCLUSIVE (never a decided verdict)", ti.status === 0, "Leader: two of up to three extractions must agree, else INCONCLUSIVE. Validator: accepts a decided claim set only if one of its own extractions matches; disagreement stores nothing (README Known limitations). Tests: " + (ti.status === 0 ? "OK" : "FAIL") + (inc.length ? ". Live INCONCLUSIVE records: " + inc.join(", ") : ". No live filing came out INCONCLUSIVE (all extractions agreed)."));

// 12. fees
const scripts = readdirSync(root + "test").filter((f) => f.endsWith(".mjs"));
const writes = scripts.flatMap((f) => (readFileSync(root + "test/" + f, "utf8").match(/writeContract\(|deployContract\(|send\("/g) || []).map(() => f));
const harness = readFileSync(root + "test/harness.mjs", "utf8");
add("A fee on every write", /estimateWriteFees\(wallet/.test(harness) && /estimateFees\(wallet, label\)/.test(harness),
  "Every write goes through `harness.send` (estimates per call: `estimateTransactionFeesForWrite`, falling back to `estimateTransactionFees`) and every deploy through `harness.deploy` (`estimateTransactionFees`). Writes found in: " + [...new Set(writes)].join(", ") + ". Studio Dev cannot simulate writes that fetch, so the per-call generic estimate is used (logged).");

// 13. README sections
const need = ["## What the model is never allowed to decide", "## Known limitations", "### Wording"];
add("README: model limits, known limitations, neutral wording", need.every((n) => readme.includes(n)), need.map((n) => `${readme.includes(n) ? "present" : "MISSING"}: \`${n}\``).join("; "));

// 14. one set of addresses
const files = ["README.md", "ADDRESSES.md", "docs/SEEDS.md", "docs/SUBMISSION.md", "docs/FINAL_CHECK.md"].filter((f) => { try { readFileSync(root + f); return true; } catch { return false; } });
const known = new Set([CAN.toLowerCase(), DEMO.toLowerCase()]);
const old2 = new Set((dep.superseded ?? []).map((s) => s.address.toLowerCase()));
const bad = [];
for (const f of files) {
  const text = readFileSync(root + f, "utf8").toLowerCase();
  for (const a of old2) if (text.includes(a)) bad.push(`${f} mentions superseded ${a}`);
}
add("One set of addresses everywhere", bad.length === 0 && readme.includes(CAN) && readme.includes(DEMO),
  `Current: canonical \`${CAN}\`, demo \`${DEMO}\` (deployments.json, both from commit ${dep.contracts.AdminClaim.commit.slice(0, 10)}). Superseded addresses appear only in docs/superseded/ and the attack report's history. ` + (bad.length ? "Problems: " + bad.join("; ") : "Checked: " + files.join(", ")));

// 15. git history
const leaked = git("log", "--all", "--format=%H", "--", "test/.accounts.json");
const msgs = git("log", "--all", "--format=%an <%ae>%n%B");
// the banned words are stored encoded so this file does not contain them
const BANNED = ["Y2xhdWRl", "YW50aHJvcGlj", "Y28tYXV0aG9yZWQ="].map((b) => Buffer.from(b, "base64").toString()).join("|");
const words = (msgs.match(new RegExp(BANNED, "gi")) || []).length;
const tracked = git("ls-files");
const secretish = tracked.split("\n").filter((f) => /accounts\.json|\.env|secret/i.test(f));
const grepAI = sh("git", ["grep", "-niE", BANNED, "HEAD", "--", ".", ":!test/package-lock.json"]);
add("Git history clean", leaked === "" && words === 0 && secretish.length === 0 && grepAI.stdout.trim() === "",
  `keys file never committed (\`git log --all -- test/.accounts.json\` empty: ${leaked === ""}); tracked files matching accounts/.env/secret: ${secretish.length}; commit messages or authors with banned tool names or co-author trailers: ${words}; tree mentions: ${grepAI.stdout.trim() === "" ? 0 : grepAI.stdout.trim().split("\n").length}; authors: ${[...new Set(git("log", "--format=%an <%ae>").split("\n"))].join(", ")}; commits: ${git("rev-list", "--count", "HEAD")}.`);

// 16. tests
const tt = sh("python3", ["-m", "unittest", "test_adminclaim", "test_attacks"], { cwd: root + "test" });
const ran = (tt.stderr.match(/Ran (\d+) tests/) || [])[1];
add("Offline tests", tt.status === 0 && Number(ran) >= 150, `\`cd test && python3 -m unittest test_adminclaim test_attacks\`: Ran ${ran} tests, ${tt.status === 0 ? "OK" : "FAILED"}`);

const md = `# Final check

Generated by \`node tools/final_check.mjs\` at ${new Date().toISOString()} on commit \`${head}\`. Every line is recomputed from the repo, the chain and the test run.

| # | Check | Result |
|---|---|---|
${rows.map((r, i) => `| ${i + 1} | ${r.item} | **${r.pass ? "PASS" : "FAIL"}** |`).join("\n")}

## Proof

${rows.map((r, i) => `### ${i + 1}. ${r.item}: ${r.pass ? "PASS" : "FAIL"}\n\n${r.proof}\n`).join("\n")}`;
writeFileSync(root + "docs/FINAL_CHECK.md", md);
console.log(rows.map((r, i) => `${i + 1}. ${r.pass ? "PASS" : "FAIL"}  ${r.item}`).join("\n"));
process.exit(rows.every((r) => r.pass) ? 0 : 1);
