# AdminClaim

**Protocols write down how their contracts are controlled: "upgrades need a 4-of-7 multisig and a 48-hour timelock", "immutable, no admin keys". AdminClaim is a GenLayer Intelligent Contract that checks those statements against the chain and records, with dates, whether on-chain control matches, is weaker, or is stronger than the docs say.**

* Contract: [`contracts/AdminClaim.py`](contracts/AdminClaim.py) (one file, GenVM `py-genlayer:5jycge4q...`)
* Deployed on GenLayer Studio Dev: canonical [`0x13cb760E534A5edA7e383cd9A0f6E1b0b84f23E8`](https://explorer-studio-dev.genlayer.com/address/0x13cb760E534A5edA7e383cd9A0f6E1b0b84f23E8), demo [`0x4974407d9611a979677E3203CA2f95e283907554`](https://explorer-studio-dev.genlayer.com/address/0x4974407d9611a979677E3203CA2f95e283907554) ([ADDRESSES.md](ADDRESSES.md))
* Real seeds: [docs/SEEDS.md](docs/SEEDS.md) · research: [docs/RESEARCH.md](docs/RESEARCH.md) · threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) · attacker pass: [docs/ATTACK_REPORT.md](docs/ATTACK_REPORT.md) · final check: [docs/FINAL_CHECK.md](docs/FINAL_CHECK.md) · submission text: [docs/SUBMISSION.md](docs/SUBMISSION.md)

## What a filing does

A filer calls `file_claim(docs_url, branch, chain, addresses)`:

* `docs_url`: a docs file **pinned to a commit**: `https://raw.githubusercontent.com/<owner>/<repo>/<40-hex sha>/<path>` or `https://github.com/<owner>/<repo>/blob/<sha>/<path>` (converted to raw). Nothing else is accepted.
* `branch`: optional; empty means the repo's default branch.
* `chain`: `ethereum`, `arbitrum`, `optimism`, `base` or `polygon`.
* `addresses`: 1 to 4 contract addresses the docs make claims about (comma separated).

Then every validator, on its own:

1. **Pins the evidence.** It asks the GitHub API whether the commit is on that branch **of the repo in the URL** (`compare/<branch>...<sha>` must be `behind` or `identical`; a commit that only exists in a fork answers `diverged`). It fetches the file and checks that every submitted address appears in it (all 40 hex digits, any case).
2. **Lets the model point at sentences, and code reads them.** The model returns claims as `{field, value, quote}` for five fields: `multisig_threshold`, `multisig_signers`, `timelock_delay_seconds`, `upgradeable`, `admin_kind` (multisig / timelock / EOA / none / DAO). Code keeps a claim only if:
   * the quote is verbatim docs text (markdown `*` and backticks may be dropped by the model; code re-anchors to the docs' own characters),
   * the quote sits in a docs section that names a submitted address, with no other address on its own lines,
   * that section is not about a different chain,
   * code itself parses the number from the quote ("4-of-7", "4/7", "four of seven", "4 out of 7", "48 hours", "48h", "2 days", "172,800 seconds"), and it equals the model's value.

   The leader asks up to three times and needs two of its own answers with the same kept claims; if it cannot get two (or the model fails), it proposes an `INCONCLUSIVE` record.
3. **Walks the control path at one block.** The leader names the chain's latest *finalized* block, which must be at most 1 h old (canonical) or 10 min old (demo). Validators read exactly that block. Standard patterns only, depth at most 4:
   * EIP-1967 implementation / admin / beacon slots; the implementation must not be able to upgrade itself (UUPS).
   * Ownable `owner()` + `pendingOwner()`, including OpenZeppelin ProxyAdmin.
   * Gnosis Safe: canonical proxy code + canonical singleton + `VERSION()`, `getThreshold`, `getOwners`, `getModulesPaginated`, guard.
   * OpenZeppelin TimelockController: `getMinDelay`, and `hasRole(PROPOSER / TIMELOCK_ADMIN / DEFAULT_ADMIN)` for every address the walk meets.
   * Compound Timelock: `delay()`, `admin()`, `pendingAdmin()`.

   Non-standard, unreadable, deeper than 4, a delegating contract, or a Safe with modules: the claims that depend on it are `UNVERIFIABLE`.
4. **Agrees.** Validators accept the leader's record only if it is identical to their own: docs sha256, commit, branch proof, block, every chain read, kept claims. **If leader and validators extract different claims (or read different data), consensus fails and no record is written.** Nothing is left pending or stuck, and the filer can simply file again.

Then **code** compares each kept claim with the chain and writes an immutable record.

| Verdict | Meaning |
|---|---|
| `MATCH` | the chain shows what the docs state |
| `WEAKER_THAN_CLAIMED` | lower threshold, fewer signers, shorter delay, an EOA where a multisig or timelock is stated, upgradeable where immutable is stated, or a path that skips the stated timelock |
| `STRONGER_THAN_CLAIMED` | the chain is stricter than the docs (e.g. higher threshold, longer delay, no controller at all) |
| `UNVERIFIABLE` | no claim could be decided with the standard patterns (or no claim was kept) |
| `INCONCLUSIVE` | the leader's own model answers did not agree (no two of three matched) or the model failed, so nothing was compared. This is the only case that records INCONCLUSIVE; a disagreement between leader and validators writes no record at all |

Each claim is compared on every control route (pending owners, timelock admins and proposers are routes too). The **weakest route** decides. Overall = the worst decided claim (WEAKER > STRONGER > MATCH), or `UNVERIFIABLE` if none was decided. When only some claims were decided, the sentence says how many.

### Wording

Every record carries one sentence built by code, always dated, never naming a protocol (only the repo the docs came from):

> Docs from github.com/lidofinance/docs. On-chain control at block 26142250 (2026-10-07 18:17 UTC) is weaker than what the docs at commit 4641585987 (2026-10-05) state. (canonical record #3)

The other verdicts read "matches what the docs ... state", "is stronger than what the docs ... state", "could not be compared with what the docs ... state, using only the standard control patterns AdminClaim reads", and "Validators did not extract the same claims from the docs ...; on-chain control at block N (date) was read but not compared." AdminClaim never says a protocol lied, is a scam, or is unsafe: docs go stale, and the record shows both dates.

## What code decides

URL pinning and the allowlist; the branch proof; fetching and hashing the docs; that every address is in the docs; which finalized block is acceptable (freshness, finality, leader lag); every chain read and its ABI decoding; what each address is (Safe, proxy, timelock, Ownable, EOA, not standard); the control routes; every number, re-read from the quote; whether a quote is verbatim, next to the address and about the right chain; every comparison; the verdict; the sentence; cooldowns, duplicates and the history.

## What the model is never allowed to decide

* **Any number.** Thresholds, signer counts and delays are parsed by code from the verbatim quote. If the model's number differs, the claim is dropped.
* **Whether a quote is real.** Code checks it against the fetched docs, character for character.
* **Which contract or chain a sentence is about.** Code requires the section to name a submitted address, no other address on the quote's lines, and no other chain.
* **Anything about the chain.** The model never sees chain data; every on-chain fact is read and decoded by code.
* **The verdict, the comparison or the wording.** All code.
* **Whether a docs URL, commit, block or address is acceptable.** All code.

The model's only job is to point at sentences and say which of five fields each one is about. Docs are fenced with a per-filing nonce; whatever an injected instruction makes the model say, the value still comes from verbatim docs text next to the address.

## Evidence rules

* Allowlist: the pinned raw file, `api.github.com/repos/<owner>/<repo>/compare/...`, and one frozen RPC per chain (nodies / Pocket / Optimism endpoints, chosen by measurement; [docs/RESEARCH.md](docs/RESEARCH.md)). No query strings, `%`-escapes, branches, tags or other hosts.
* The commit must be reachable from a branch of the repo in the URL; the proof (branch, status, commit date) is stored.
* Every submitted address must be in the docs at that commit.
* One finalized block per record, named by the leader, read by everyone, no older than 1 h (canonical) / 10 min (demo); number, hash and time are stored.
* Strict equality on the whole evidence record; any mismatch stores nothing (no pending state exists to get stuck).
* No payable method, no balance, no owner, no setter. Cooldown and freshness are constructor arguments, frozen.
* Records are immutable. `recheck(record_id)` files again with the same inputs and links to the previous record. Cooldown per key: 6 h canonical, 60 s demo. Key = (chain, sorted addresses, docs repo). The same commit at the same block cannot be filed twice. The last 20 records per key are kept; older ones fold into counters.
* Nothing is written before the last check that can revert (`tools/scan_writes.py`). Views only read storage. A fetch failure refuses the filing; it never yields a verdict.

## Seeds

Twelve real docs files (Lido, Balancer, Yearn, Optimism, Uniswap), five chains, filed on the canonical deployment. MATCH 5 · WEAKER_THAN_CLAIMED 2 · UNVERIFIABLE 5 (12 records, 5 chains). Full records, quotes and chain facts per hop: [docs/SEEDS.md](docs/SEEDS.md).

| Protocol (docs) | Chain | Record | Block | Verdict |
| Lido - Emergency Brakes: Ethereum | ethereum | [#1](https://explorer-studio-dev.genlayer.com/tx/0x79c2fa43243d638a21bc8eb54f6c807aac28ba6adb4e4a3cb15de5551347f4b7) | 26142186 | **MATCH** |
| Lido - Emergency Brakes: Optimism | optimism | [#2](https://explorer-studio-dev.genlayer.com/tx/0x8a36cc8b6a9fca5e2fe40fb71658ad80b0ff0d540cd2eb64d43499aeef9821ed) | 157898891 | **MATCH** |
| Lido - Rewards Share Committee | ethereum | [#3](https://explorer-studio-dev.genlayer.com/tx/0x0bbd6e8b76e4eec62fedf7968d878fc1d47c34c19ac2f53a0cbd9d7a33dcbf1f) | 26142250 | **WEAKER_THAN_CLAIMED** |
| Lido - Bug Bounty Reserve Multisig | ethereum | [#4](https://explorer-studio-dev.genlayer.com/tx/0x0fd82046e5d040692d7736dacec4bc57394de1b6e4c10d332338334edc861ef1) | 26142282 | **WEAKER_THAN_CLAIMED** |
| Lido - LOL Committee ARB Token Multisig | arbitrum | [#5](https://explorer-studio-dev.genlayer.com/tx/0xfe02f4c8050cf083d92b6b40d66392e5fd6435b1c59fcbfeaee3fa15a3759db5) | 512646208 | **MATCH** |
| Lido - LOL Committee (Polygon) | polygon | [#6](https://explorer-studio-dev.genlayer.com/tx/0x86abfb2f757dead8bfc29823c7fa2cd44faed3db69b605e38ec81a5534a8c537) | 95129306 | **UNVERIFIABLE** |
| Balancer - DAO multisig on Polygon | polygon | [#7](https://explorer-studio-dev.genlayer.com/tx/0x1cb2414255764145a246dcf7b0c076549f8a33c89fe7700b6adf896f5c2b627b) | 95129555 | **MATCH** |
| Balancer - DAO multisig on Base | base | [#8](https://explorer-studio-dev.genlayer.com/tx/0x0ea953120c105638bf6bc9257f92bd69aa721e0554d2753ab5ffec277d46de16) | 52304602 | **MATCH** |
| Balancer - Treasury Safe | ethereum | [#9](https://explorer-studio-dev.genlayer.com/tx/0x900964c9c71c82d8c2e6d1cbc94481ae0e20536ee80470ae6cbf22788aa591a2) | 26142442 | **UNVERIFIABLE** |
| Yearn - governance multisig (yChad) | ethereum | [#10](https://explorer-studio-dev.genlayer.com/tx/0xaa49bbf95bbb925ee71f8cd172995f4fbe4b96671f9998838feb7e337b3cd3a0) | 26142474 | **UNVERIFIABLE** |
| Optimism - L1 ProxyAdmin owner | ethereum | [#11](https://explorer-studio-dev.genlayer.com/tx/0xe1e9979b175893a3022f49243b1fca45e99d4bac9484fa6017bfb73bd750fa71) | 26142506 | **UNVERIFIABLE** |
| Uniswap - Governance Timelock | ethereum | [#12](https://explorer-studio-dev.genlayer.com/tx/0x014a8e171f1b468b36d9dee9998e9f62c2ed35589620a20354e34193079bd44d) | 26142537 | **UNVERIFIABLE** |
| Field | Value (code's parse) | Quote | Result |
| multisig_threshold | 3 | `**Quorum:** 3/5` | MATCH |
| multisig_signers | 5 | `**Quorum:** 3/5` | MATCH |
| admin_kind | "multisig" | `**Purpose of the multisig:** The multisig is used to disable deposits & withdrawals for wstETH bridging to other chains (Arbitrum, Optimism, Base, Binance Smart` | MATCH |
| Field | Value (code's parse) | Quote | Result |
| multisig_threshold | 3 | `**Quorum:** 3/5` | MATCH |
| multisig_signers | 5 | `**Quorum:** 3/5` | MATCH |
| Field | Value (code's parse) | Quote | Result |
| multisig_threshold | 3 | `**Quorum:** 3/6` | MATCH |
| multisig_signers | 6 | `**Quorum:** 3/6` | WEAKER_THAN_CLAIMED |
| admin_kind | "multisig" | `**Purpose of the multisig:**` | MATCH |
| Field | Value (code's parse) | Quote | Result |
| multisig_threshold | 5 | `**Quorum:** 5/9` | MATCH |
| multisig_signers | 9 | `**Quorum:** 5/9` | WEAKER_THAN_CLAIMED |
| admin_kind | "multisig" | `**Purpose of the multisig:** The multisig has been established to manage a dedicated reserve for the [Lido Bug Bounty Program](https://immunefi.com/bug-bounty/l` | MATCH |
| Field | Value (code's parse) | Quote | Result |
| multisig_threshold | 4 | `**Quorum:** 4/8` | MATCH |
| multisig_signers | 8 | `**Quorum:** 4/8` | MATCH |
| admin_kind | "multisig" | `### 2.8.5 Liquidity Observation Lab Committee ARB Token Multisig
| Field | Value (code's parse) | Quote | Result |
| multisig_threshold | 6 | `All chain-specific DAO multisigs use the [DAO Signer Set](#dao-multisig-signer-set) with a 6/11 threshold.` | MATCH |
| multisig_signers | 11 | `All chain-specific DAO multisigs use the [DAO Signer Set](#dao-multisig-signer-set) with a 6/11 threshold.` | MATCH |
| Field | Value (code's parse) | Quote | Result |
| multisig_threshold | 6 | `All chain-specific DAO multisigs use the [DAO Signer Set](#dao-multisig-signer-set) with a 6/11 threshold.` | MATCH |
| multisig_signers | 11 | `All chain-specific DAO multisigs use the [DAO Signer Set](#dao-multisig-signer-set) with a 6/11 threshold.` | MATCH |
| Field | Value (code's parse) | Quote | Result |
| multisig_threshold | 5 | `\| Treasury Safe             \| [0x0EFcCBb9E2C09Ea29551879bd9Da32362b32fc89](https://app.safe.global/home?safe=eth:0x0EFcCBb9E2C09Ea29551879bd9Da32362b32fc89) \` | UNVERIFIABLE |
| multisig_signers | 7 | `\| Treasury Safe             \| [0x0EFcCBb9E2C09Ea29551879bd9Da32362b32fc89](https://app.safe.global/home?safe=eth:0x0EFcCBb9E2C09Ea29551879bd9Da32362b32fc89) \` | UNVERIFIABLE |
| admin_kind | "multisig" | `\| Treasury Safe             \| [0x0EFcCBb9E2C09Ea29551879bd9Da32362b32fc89](https://app.safe.global/home?safe=eth:0x0EFcCBb9E2C09Ea29551879bd9Da32362b32fc89) \` | UNVERIFIABLE |
| Field | Value (code's parse) | Quote | Result |
| multisig_threshold | 6 | `The multisig is implemented by a 6-of-9 multi-signature wallet.` | UNVERIFIABLE |
| multisig_signers | 9 | `The multisig is implemented by a 6-of-9 multi-signature wallet.` | UNVERIFIABLE |
| admin_kind | "multisig" | `The multisig is implemented by a 6-of-9 multi-signature wallet.` | UNVERIFIABLE |
| Field | Value (code's parse) | Quote | Result |
| admin_kind | "DAO" | `Uniswap Governance is a system that allows holders of the UNI token to collectively manage, upgrade, and steer the future of the Uniswap protocol.` | UNVERIFIABLE |

The two WEAKER records were checked by hand: each Lido Safe lost a signer on chain (2026-05-08 and 2026-07-31) after the docs section was written (2026-03-02 and 2026-03-05), and the docs were not updated. The UNVERIFIABLE ones are Safes with modules (Balancer Treasury, Yearn yChad), a governor-controlled timelock (Uniswap), and two where code dropped the only quote the model chose (wrong-chain section; a line naming another Safe).

## Using it

```js
import { createClient, createAccount } from "genlayer-js";
import { studioDevnet } from "genlayer-js/chains";
const client = createClient({ chain: studioDevnet, account: createAccount(PRIVATE_KEY) });
const fees = await client.estimateTransactionFees();            // a fee on every write
await client.writeContract({
  address: "0x13cb760E534A5edA7e383cd9A0f6E1b0b84f23E8",
  functionName: "file_claim",
  args: ["https://raw.githubusercontent.com/lidofinance/docs/4c391cfe400f359ff346035b86f9d1703c3929e5/docs/multisigs/emergency-brakes.md",
         "", "ethereum", "0x73b047fe6337183A454c5217241D780a932777bD"],
  value: 0n, fees,
});
await client.readContract({ address: "0x13cb...23E8", functionName: "get_record", args: [1] });
```

Views: `get_record(id)`, `get_records(offset, limit)`, `get_history(key)`, `get_keys(offset, limit)`, `get_stats()`, `get_config()`.

## How a reviewer can test

Use the **demo** contract `0x4974407d9611a979677E3203CA2f95e283907554` on Studio Dev and **Polygon** (the only chain whose finality fits the demo's 10-minute window). Example known to work (demo record #2, MATCH):

* `docs_url`: `https://raw.githubusercontent.com/balancer/docs-v3/98d4c352e332419d70415fa07a584579ac65b8e2/docs/concepts/governance/multisig.md`
* `branch`: `""` (default branch)
* `chain`: `polygon`
* `addresses`: `0xeE071f4B516F69a1603dA393CdE8e76C40E5Be85` (Balancer DAO multisig on Polygon, 6/11)

Call `file_claim(docs_url, "", "polygon", address)` with a fee estimate, then `get_record(<record_id>)` or `get_stats()`. The same key is in cooldown for 60 s after each record; `recheck(record_id)` after that files a new linked record. To see refusals, change the commit to `main` (`URL_NOT_PINNED_TO_COMMIT`), use an address that is not in the file (`ADDRESS_NOT_IN_DOCS`), or use `ethereum` (`BLOCK_TOO_OLD` on the demo). If you get `GITHUB_API_HTTP_403`, the shared GitHub budget is exhausted; retry later. More examples: [docs/SEEDS.md](docs/SEEDS.md).

## Repository

```
contracts/AdminClaim.py      the contract (the only deployed file)
test/test_adminclaim.py      offline suite: rules, verdicts, refusals, parsers, patterns (mock chain)
test/test_attacks.py         attacker pass, one test per attack
test/stub.py, fixtures.py    GenVM runtime stub, JSON-RPC mock chain, builders
test/deploy.mjs              deploys canonical + demo from HEAD (refuses a dirty contracts/)
test/seed_canonical.mjs      files test/seeds.json on canonical
test/seed_demo.mjs           drives the demo through every path
tools/verify_source.mjs      gen_getContractCode == contracts/ at HEAD, byte for byte
tools/scan_writes.py         no write before a revert (AST)
tools/live.py                runs the contract's own walk against the real chains (used for hand checks)
docs/                        research, threat model, seeds, attack report, final check, submission
```

Run the offline suite: `cd test && python3 -m unittest test_adminclaim test_attacks` (248 tests).

## Known limitations

* **Standard patterns only.** Governors (OZ Governor, GovernorBravo, Aragon), UUPS proxies, beacons, diamonds, clones, EIP-7702 accounts, custom proxies and any contract with DELEGATECALL in its own code are reported as not a standard pattern. Claims through them are `UNVERIFIABLE`. A `DAO` claim can only ever be shown weaker (an EOA controller), never matched.
* **OpenZeppelin timelock roles cannot be listed.** Only addresses the walk meets (submitted addresses, owners, admins, Safe signers) are tested with `hasRole`. So behind an OZ TimelockController a multisig claim can be WEAKER or UNVERIFIABLE, never MATCH. Delays are still decided.
* **Custom EIP-1967 proxies.** A proxy that writes the standard slots but has its own hidden upgrade path is not detected. UUPS-capable implementations are. Every node's code sha256 is stored for audit.
* **One RPC per chain.** Validators read the same frozen RPC. An RPC that lies identically to everyone would be believed; one that answers differently stores nothing.
* **Finality and the demo.** Ethereum, Arbitrum, Optimism and Base finalize 13 to 25 minutes behind the head, so the demo deployment (10-minute freshness) only accepts Polygon. Canonical (1 h) accepts all five.
* **GitHub API budget.** The GitHub REST API is used unauthenticated: 60 calls per hour, shared by all studio-dev validators (one call per node per filing), so roughly ten filings an hour network-wide. When it is exhausted a filing is refused with `GITHUB_API_HTTP_403` (no record, never a verdict); retry later (the budget resets hourly).
* **Leader/validator disagreement writes nothing.** A validator that extracts different claims than the leader's agreed set rejects the round, and GenLayer rotates the leader. If no leader satisfies the validators, consensus fails and no record is written: nothing is pending, nothing is stuck, and the filer can file again. GenLayer marks such a transaction UNDETERMINED; it is not recorded as `INCONCLUSIVE`. (`INCONCLUSIVE` is written only when the leader's own answers disagree; a dishonest leader could claim that and force `INCONCLUSIVE`, never a decided verdict.)
* **Docs structure matters.** Claims must sit in a markdown section that names the address. Docs with no headings are one section. Claims written far from the address (e.g. a table at the bottom) are dropped, giving `UNVERIFIABLE` rather than a guess.
* **Forked repos.** A repo that is itself a fork of a protocol's docs is accepted and named as such (`github.com/<fork-owner>/<repo>`). The commit must be on that repo's branch.
* **Duplicate refusal** (same commit, same block) only triggers if a chain's finalized head stalls for longer than the cooldown; it is covered offline.
* **Fee estimation.** Studio Dev cannot simulate a write that makes web requests, so scripts fall back to the node's per-call fee estimate.
* **Scope of "admin".** For a proxy the control path is the upgrade path; for anything else it is `owner()`. Other privileged roles (pausers, minters, AccessControl admins on the target itself) are out of scope, and `admin_kind: none` matches only code with no admin selector and no DELEGATECALL / SELFDESTRUCT.
