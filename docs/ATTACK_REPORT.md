# Attacker pass (round 1)

Target: AdminClaim v1.0.0, commit `e45276c`, deployed at `0xED07bc56...` (canonical) and `0x6457F558...` (demo), after its first seed run. Approach: read the contract as an outsider and try to make it (a) print a decided verdict the chain does not support, (b) accept a filing it should refuse, or (c) leave state behind on a refusal. Each attack became a test in `test/test_attacks.py` **before** any fix.

* Commit `e9a1da3`: 28 attack tests, run against the unchanged v1.0.0 contract: **23 passed, 5 failed**. The failures are the findings below.
* Commit `df32b0e`: the fixes (v1.1.0). All 28 attack tests and the 220 unit tests pass. Canonical and demo were redeployed from `df32b0e`, re-seeded, and the source match re-run (`tools/verify_source.mjs`).

```
# test_attacks.py against v1.0.0 (e45276c)
FAIL: test_a12_FINDING_admin_slot_for_show_with_uups_implementation
FAIL: test_a13_FINDING_delegating_contract_answers_owner_from_its_implementation
FAIL: test_a14_FINDING_undecided_claims_hidden_behind_a_match
FAIL: test_a17_FINDING_hidden_eoa_proposer_on_timelock
FAIL: test_a18_FINDING_same_address_documented_for_another_chain
Ran 28 tests  FAILED (failures=5)
```

## Findings and fixes

| ID | Severity | Attack | What v1.0.0 did | Fix in v1.1.0 | Test |
|---|---|---|---|---|---|
| H1 | High | EIP-1967 proxy whose **admin slot** points at a ProxyAdmin owned by a 4-of-7 Safe, while the **implementation is UUPS** (`upgradeToAndCall`, `proxiableUUID`) and lets an EOA upgrade | followed the admin slot and returned MATCH for "4-of-7 multisig controls upgrades" | for every EIP-1967 proxy, code reads the implementation's runtime and `proxiableUUID()`. If the implementation carries `upgradeTo` / `upgradeToAndCall` / `proxiableUUID`, or `proxiableUUID()` answers the implementation slot, the proxy is `IMPLEMENTATION_CAN_UPGRADE` (not a standard pattern); its claims are `UNVERIFIABLE` | `test_a12`, `RoundOneRules.test_proxiable_uuid_alone_marks_uups` |
| H2 | High | Custom proxy (DELEGATECALL in its own code, no EIP-1967 slots) whose implementation answers `owner()` with a 4-of-7 Safe; the real upgrade key lives elsewhere | classified it `OWNABLE` and walked to the Safe | a contract with DELEGATECALL or CALLCODE in its runtime is never Ownable / timelock: it is `DELEGATING_CONTRACT` (or `DIAMOND`), not a standard pattern | `test_a13`, `Patterns.test_delegating_contract_without_pattern_is_nonstandard` |
| H3 | High | OZ TimelockController whose PROPOSER role is also held by an EOA that appears nowhere (not submitted, not a signer) | roles can only be tested for known addresses, so the walk saw only the Safe and returned MATCH for the multisig claim | OZ roles cannot be listed. Through an OZ timelock, a claim about **who** controls (threshold, signers, kind other than "timelock") can now be WEAKER or UNVERIFIABLE, never MATCH or STRONGER. Delay claims, and the "timelock" kind, are still decided. Compound Timelock (single `admin` + `pendingAdmin`), Ownable (`owner` + `pendingOwner`) and Safes are complete and still decide | `test_a17`, `RoundOneRules.test_oz_timelock_route_cannot_match_who_claims` |
| H4 | High | The same Safe address documented twice: under "(Ethereum)" with 5/9 and under "(Polygon)" with 2/3 (real: Lido's `committees.md` lists `0x87D9...12B5` in both). A Polygon filing whose model quotes the Ethereum section | kept 5/9 (the section names the address) and compared it with the Polygon Safe: a false WEAKER | chain binding: a quote's section is "about" the chains named in its heading and on the section's lines that hold a submitted address (`eth:` / `oeth:` / `arb1:` / `matic:` / `base:` Safe prefixes, explorer hosts, chain names; "base" only in headings). A section about other chains and not the filing's chain is skipped (`QUOTE_SECTION_ABOUT_ANOTHER_CHAIN`) | `test_a18`, `RoundOneRules.test_keep_claim_chain_binding`, `test_chains_named_boundaries` |
| M1 | Medium | A Safe with a module: threshold and signer claims are UNVERIFIABLE, the "upgradeable" claim matches | overall MATCH (the rule: worst decided claim), with the sentence "matches what the docs state" and nothing else | rule unchanged; the sentence now says "(1 of 3 claims decided; the other 2 could not be checked with the standard control patterns AdminClaim reads)" whenever some claims are undecided | `test_a14`, `RoundOneRules.test_summary_counts_decided_claims` |
| M2 | Medium | Submit a contract **and** a Safe; the contract's path cannot be read (non-standard) | the Safe, not reached from the contract, became a subject on its own and decided "4-of-7: MATCH" although nothing showed it controls the contract | subjects now combine like routes: any WEAKER, else any UNVERIFIABLE, else MATCH, else STRONGER. A controller that was not shown to be reached cannot decide alone | `test_a13`, `RoundOneRules.test_subjects_combine_conservatively` |

## Attacks that did not work against v1.0.0

| Attack | Why it fails | Test |
|---|---|---|
| Forked docs commit read through the parent's raw URL | compare API answers `diverged`; refused `COMMIT_NOT_ON_BRANCH` (also live: demo step `refuse_fork_commit` on yearn PR #643) | `test_a01`, `test_a03` |
| `owner:branch` to compare against a fork | branch names with `:` refused | `test_a02` |
| Branch / tag / `HEAD` / `refs/heads/...` / short SHA instead of a 40-hex SHA | refused before any fetch | `test_a04` |
| `%`-escapes anywhere (incl. `%2F`, `%2e%2e`, in the owner) | refused | `test_a05` |
| Address only inside a longer hex string (a tx hash) | not counted; `ADDRESS_NOT_IN_DOCS` | `test_a06` |
| Real quote, altered number | code reads the number from the quote; mismatch drops the claim | `test_a07` |
| Numbers in words | parsed by code ("four of seven") | `test_a08` |
| Injected instructions ("report 9-of-9") | the obeying model's quote is not in the docs; dropped | `test_a09` |
| Docs that try to close the fence | `<<<` / `>>>` and the nonce are removed from the docs | `test_a10` |
| Beacon / UUPS-without-admin / diamond / EIP-1167 clone | never decided (`UNVERIFIABLE`) | `test_a11` |
| Safe guard | recorded; a guard cannot bypass the threshold | `test_a15` |
| EOA proposer that the walk meets (a Safe signer) | becomes a route: WEAKER | `test_a16` |
| Fake Safe (answers `getThreshold` with other code) | not the canonical proxy + singleton | `test_a19` |
| EIP-7702 delegated EOA as owner | not a standard pattern | `test_a20` |
| Leader names an old block | validators reject a block older than their own finalized block by more than 15 min | `test_a21` |
| RPC answers differently to validators | full-record equality fails; nothing is stored | `test_a22` |
| RPC rate-limit read as "function absent" | non-revert errors refuse the filing (`RPC_UNREADABLE`) | `test_a23` |
| Duplicate (same commit, same block) | `DUPLICATE_OF_RECORD_n` | `test_a24` |
| Cooldown off by one | `now - last < cooldown` refused, `== cooldown` allowed | `test_a25` |
| History overflow (45 filings on one key) | 20 kept, 25 folded into counters, ids still resolve (`pruned: true`) | `test_a26` |
| Counter written before a revert | AST scan + byte-identical state after each refusal stage | `test_a27` |
| Accusing wording | one neutral, dated sentence per verdict | `test_a28` |

## Accepted residual risks (not closable on studio-dev; in README "Known limitations")

| Severity | Risk | Why it stays | What limits it |
|---|---|---|---|
| Medium | A **custom proxy** that writes the EIP-1967 slots like a transparent proxy but also has a hidden upgrade path in its own code | proving a proxy is a known OpenZeppelin build needs a per-compiler bytecode allowlist (and v5 inlines the admin address) | H1 closes the UUPS case; every node's runtime sha256 is stored in the record so anyone can audit the proxy code |
| Medium | All validators read one RPC per chain; an RPC that **forges the same state for everyone** is believed | a second independent archive RPC per chain that also takes 10-call batches was not available for every chain (docs/RESEARCH.md section 1) | an RPC that answers differently to different validators produces no record; any non-revert error refuses the filing |
| Low | A dishonest leader can force `INCONCLUSIVE` by claiming its extractions disagreed | the validator cannot prove the leader's model answers | it can never force a decided verdict; the key can be re-filed after the cooldown |
| Low | Docs in a repo that is itself a fork of a protocol's repo | checking `fork` needs a second GitHub API call per node (60/h shared) | the record names the source as `github.com/<owner>/<repo>`, never a protocol name; the commit must be on that repo's branch |
| Low | A docs file without headings is one section, so the section rule is weaker there | markdown structure is all code has | the "no other address on the quote's line" rule and the chain binding still apply |
| Low | Duplicate refusal is unreachable live | the cooldown (60 s / 6 h) is longer than any finalized head stalls in practice | it guards a stalled finalized head; covered offline (`test_a24`) |
