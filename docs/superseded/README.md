# Superseded deployments

These addresses ran earlier versions of `contracts/AdminClaim.py`. They are kept here only for history; use [ADDRESSES.md](../../ADDRESSES.md).

| Deployment | Address | Commit | Replaced by | Why |
|---|---|---|---|---|
| AdminClaim (CANONICAL) | `0xED07bc560ba67Ad811B9416c540dEA3a717AF606` | `e45276c6a0` | `0x13cb760E534A5edA7e383cd9A0f6E1b0b84f23E8` | round-1 attacker fixes (H1-H4, M1, M2): v1.1.0 |
| AdminClaimDemo (DEMO) | `0x6457F5583E264d970EB9c2a09F9E7E68d6aD2178` | `e45276c6a0` | `0x4974407d9611a979677E3203CA2f95e283907554` | round-1 attacker fixes (H1-H4, M1, M2): v1.1.0 |

Seed run on the first canonical deployment (v1.0.0): [seed-canonical-v1.0.0.json](seed-canonical-v1.0.0.json) (7 records: MATCH 5, WEAKER_THAN_CLAIMED 2; the 8th filing was refused when the GitHub API budget ran out). It was stopped when the round-1 attacker pass changed the contract.
