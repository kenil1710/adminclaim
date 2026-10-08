# Submission

## Intelligent Contract description (864 characters)

```
AdminClaim checks what a protocol's docs say about who controls its contracts against the chain. A filer gives a docs file pinned to a GitHub commit, a chain and the addresses. Validators prove the commit is on a branch of that repo, check each address is in the file, and read the control path at one fresh finalized block: proxies, owners, Safes, timelocks. The model only points at sentences. Code keeps a claim only if the quote is verbatim and next to the address, and code itself reads the number (4-of-7, 48 hours). Code compares and records, dated: MATCH, WEAKER, STRONGER, UNVERIFIABLE, or INCONCLUSIVE if extractions disagree. The model never decides a number, a chain fact or the verdict. Seeds: 12 real docs files on 5 chains: 5 MATCH, 2 WEAKER, 5 UNVERIFIABLE. The weaker ones are Lido committees whose Safes lost a signer after the docs were written.
```

Character count: **864** (limit 1000), counted by `tools/submission.py` with Python `len()` on the text above.

## Facts behind it

* Contract: `contracts/AdminClaim.py`; canonical `0x13cb760E534A5edA7e383cd9A0f6E1b0b84f23E8`, demo `0x4974407d9611a979677E3203CA2f95e283907554` (GenLayer Studio Dev), both from commit `df32b0eac7`.
* Seeds: docs/SEEDS.md (12 records on the canonical deployment, 5 chains). The two WEAKER records were checked by hand against Safe events and the docs' git history (docs/research/hand_checks.json).
* What code decides and what the model never decides: README.md.
