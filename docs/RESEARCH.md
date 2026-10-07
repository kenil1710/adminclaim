# Research

What was measured before and while building AdminClaim, and where every seed comes from. Raw probe outputs are in `docs/research/`.

## 1. Which RPCs a validator can use

A record binds every chain read to one finalized block that the leader names. Validators read that same block later, and the block may be up to 1 h old (canonical). So each chain needs an RPC that, **from inside GenVM on studio-dev**:

* answers `eth_getBlockByNumber("finalized")` and `eth_chainId`,
* serves `eth_call` / `eth_getStorageAt` / `eth_getCode` at blocks more than 1 h old (history),
* accepts JSON-RPC batches of 10 without rate-limiting `eth_call`.

| Chain | Chosen RPC | Rejected (why) |
|---|---|---|
| Ethereum | `https://eth-pokt.nodies.app` | `ethereum-rpc.publicnode.com` (archive reads need a token, 403); `eth.drpc.org` (free plan: batches of at most 3); `mainnet.gateway.tenderly.co` (429 on `eth_call` batches above about 5); `1rpc.io/eth` (403 from GenVM); `eth.llamarpc.com` (525) |
| Arbitrum | `https://arb-pokt.nodies.app` | `arb1.arbitrum.io/rpc` (no state older than ~2 h: "historical state ... is not available"); publicnode (archive token); tenderly (429 on batches) |
| Optimism | `https://mainnet.optimism.io` | publicnode (archive token) |
| Base | `https://base-pokt.nodies.app` | `mainnet.base.org` (`over rate limit` on `eth_call` batches, max 10 calls per batch); publicnode (archive token) |
| Polygon | `https://poly.api.pocket.network` | `polygon-rpc.com` (401); `polygon-bor-rpc.publicnode.com` (no history); tenderly (429); quiknode public (20 req/s limit hit from GenVM) |

Evidence: `docs/research/probe_rpc_github.json` (first GenVM probe: finalized tag and 1.5 h-old reads on 22 endpoints), `probe_batch.json` (batch support), `probe_rpc_batch10.json` (the five chosen endpoints and alternates: finalized block, three batches of ten `eth_call`s at a block ~1 h old, all answered from GenVM).

Finality lag measured on 2026-10-07 (seconds between "now" and the finalized block's timestamp): Ethereum 880 to 1130, Arbitrum ~950 to 1240, Optimism ~980 to 1420, Base ~1140 to 1320, Polygon 3 to 15. Consequence: the **demo** deployment (block no older than 10 min) can only accept Polygon; Ethereum, Arbitrum, Optimism and Base filings are refused there with `BLOCK_TOO_OLD`. The canonical deployment (1 h) accepts all five.

## 2. Proving the commit is on a branch of the repo in the URL

`raw.githubusercontent.com/<owner>/<repo>/<sha>/...` serves a commit that only exists in a **fork** of `<owner>/<repo>` (GitHub stores a fork network's objects together). A pinned SHA alone therefore proves nothing about the original repo.

AdminClaim asks the GitHub REST API `GET /repos/<owner>/<repo>/compare/<branch>...<sha>` (branch defaults to `HEAD`, the default branch). `status` is `behind` or `identical` exactly when `<sha>` is an ancestor of the branch, and then `merge_base_commit.sha == <sha>`. Measured:

* `OpenZeppelin/openzeppelin-contracts compare/HEAD...514ecc3b` -> `behind`, 11 KB answer (comparing in this direction keeps the answer small: no file list).
* `yearn/yearn-devdocs compare/HEAD...21233a9e` (head of an unmerged PR from the fork `lh1404/yearn-devdocs`) -> `diverged`, while `raw.githubusercontent.com/yearn/yearn-devdocs/21233a9e.../docs/developers/security/multisig.md` returns 200 with the yChad address in it. That is the fork case the rule exists for (used in the demo).
* `balancer/docs-v3` PR #328 from a fork, closed unmerged: compare says `behind`. Its commit did reach `main` later, so it is not a fork-only commit. The API answers the right question ("is it on the branch?"), not "where was the PR merged".

Rate limit: unauthenticated, 60 requests/hour, and studio-dev validators share one outbound IP (the probe saw `x-ratelimit-used` go up by about one per validator). A filing costs about one call per node, so the network can take roughly ten filings an hour. Seeding was paced accordingly. A 403/429 from the API refuses the filing (`GITHUB_API_HTTP_403`); it never produces a verdict.

The compare answer also gives the commit's committer date, which every record stores and prints.

## 3. What a Safe is

`getThreshold()` and `getOwners()` can be answered by any contract. AdminClaim treats an address as a Gnosis Safe only if:

* its runtime code minus the compiler metadata is exactly the canonical Safe proxy body (identical for the 1.1.1, 1.3.0 and 1.4.1 proxy factories; measured on Ethereum and Base, see the two code hashes below),
* storage slot 0 holds one of the canonical singletons (1.1.1, 1.2.0, the four 1.3.0 variants, 1.4.1 and 1.4.1-L2, 1.5.0 and 1.5.0-L2; each answered `VERSION()` with its version on all five chains),
* `VERSION()` through the proxy equals that singleton's version, `1 <= threshold <= owners`.

Proxy code seen: `e49f633c...` (170 bytes, solc 0.5.14 metadata) and `5b8bff32...` (171 bytes, solc 0.7.6); both strip to the same body. Safes deployed by the 1.5.0 factory may use a different proxy body. They are reported as not a standard pattern (`UNVERIFIABLE`) rather than guessed at.

Modules: a Safe with any enabled module (`getModulesPaginated(SENTINEL, 10)` non-empty) can be driven by that module without the threshold, so threshold, signer and kind claims through it are `UNVERIFIABLE`. Seen in the wild: Yearn's yChad (3 modules), Optimism's System Config owner (1 module), Balancer's Treasury Safe (1 module), a Polygon Safe used in the demo (1 module).

## 4. What the model gets wrong (and what code does about it)

Probed with AdminClaim's exact prompt via `test/prompt_probe.mjs`, two answers per call:

* **Markdown dropped from quotes.** On Lido's `emergency-brakes.md` one answer quoted `**Quorum:** 3/5`, the other `Quorum: 3/5`. That is not a substring of the file. Code now re-anchors a quote to the docs span it stands for, ignoring only `*` and backtick on both sides, and stores the docs' own characters. Both answers then keep `**Quorum:** 3/5`.
* **Kind "supported" by a link.** For Lido's Rewards Share Committee one answer claimed `admin_kind: multisig` quoting the `**Address:**` line, whose only "multisig" word was `app.safe.global` inside a URL. Code now blanks URLs before checking kind words, so that claim is dropped every time. The two answers were otherwise identical, and the record went from `INCONCLUSIVE` to a decided verdict.
* **Variable choice of optional claims.** Large pages (Lido `committees.md`, 88 KB) sometimes give a third claim in one answer and not the other. The leader asks up to three times and needs two answers with the same kept claims (same fields and code-read values; quotes may differ, every quote is re-checked by code on every node).

## 5. Seed sources

Docs repos cloned (depth 1, in the gitignored `research_cache/`) and searched for control claims next to addresses: `lidofinance/docs`, `balancer/docs-v3`, `yearn/yearn-devdocs`, `ethereum-optimism/docs`, `base/docs`, `OffchainLabs/arbitrum-docs`, `Uniswap/docs`, `compound-finance/compound-protocol`, `morpho-org/morpho-blue`, `Layr-Labs/eigenlayer-contracts`, `aave/aave-v3-origin`, `euler-xyz/euler-docs`, `ensdomains/docs`, `across-protocol/docs`.

What qualified (a docs file that states a concrete control fact next to the address it is about):

| Repo | File | What it states |
|---|---|---|
| lidofinance/docs | `docs/multisigs/emergency-brakes.md` | per multisig: `**Address:**` + `**Quorum:** n/m` (Ethereum, Optimism, ...) |
| lidofinance/docs | `docs/multisigs/committees.md` | same format, 30 committees on Ethereum, Optimism, Arbitrum, Polygon |
| balancer/docs-v3 | `docs/concepts/governance/multisig.md` | table of top-level Safes with thresholds; per-chain DAO multisigs "with a 6/11 threshold" |
| yearn/yearn-devdocs | `docs/developers/security/multisig.md` | "implemented by a 6-of-9 multi-signature wallet" + yChad address |
| ethereum-optimism/docs | `op-stack/protocol/privileged-roles.mdx` | "L1 Proxy Admin owner is a 2-of-2 multisig", "the 2/2 Safe owned by Foundation + Security Council" |
| Uniswap/docs | `content/ecosystem/governance/overview.mdx` | UNI holders "collectively manage, upgrade" the protocol; the treasury link is the Timelock |

Looked at and not used: EigenLayer README (addresses, no thresholds or delays in the same file); Euler `governance-parameters.md` ("Execution Delay 172800 seconds" about an OZ Governor, which AdminClaim does not read); ENS `process.mdx` ("delayed for a minimum of 2 days by the timelock contract" without the timelock's address in that file); Morpho Blue README ("immutable" without an address); Uniswap v3 governance reference ("hard-coded minimum delay of 2 days" without an address).

### Quorum scan (code's own walk)

`tools/scan_docs_quorums.py` ran AdminClaim's own `classify` (via `tools/live.py`) on every `Address` / `Quorum` pair in Lido's multisig pages and every threshold row of Balancer's page, at the finalized block on 2026-10-07. Output: `docs/research/quorum_scan.txt`. 38 Safes checked; 36 match; two differ:

| Safe | Docs (commit 4641585, 2026-10-05) | Chain (block 26142026) | Last owner change on chain |
|---|---|---|---|
| Lido Rewards Share Committee `0xe2A6...880c8C` | 3/6 | 3/5 | `RemovedOwner` at block 25049016, 2026-05-08 (tx `0x5bf597bf...`) |
| Lido Bug Bounty Reserve Multisig `0x9Eb8...C74071` | 5/9 | 5/8 | `RemovedOwner` at block 25655582, 2026-07-31 (tx `0x34d4c23b...`) |

Both were filed as ordinary seeds; AdminClaim returned `WEAKER_THAN_CLAIMED` for both on its own (docs/SEEDS.md). Three Dual Governance tiebreaker committees listed with a quorum are not Safes (custom contracts) and were not used.

## 6. Demo statements

The demo deployment can only accept Polygon (finality). To show every verdict on real contracts, `docs/demo/claims.md` in this repo makes deliberately chosen statements about real Polygon contracts (a 6/11 Safe called 6-of-11; a 2/3 Safe called 3-of-3 with a 48 h timelock; a 3/6 Safe called 2-of-6; WMATIC called immutable; bridged WETH, a non-standard proxy, called immutable; a 3/7 Safe with a module; one deliberately muddled paragraph). The file says so at the top, and records filed from it name `github.com/kenil1710/adminclaim` as the docs source. Canonical seeds use only protocols' own docs.
