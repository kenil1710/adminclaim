# Submission

## Intelligent Contract description

```
AdminClaim checks what a protocol's docs say about who controls its contracts against the chain. A filer gives a docs file pinned to a GitHub commit, a chain and the addresses. Validators prove the commit is on a branch of that repo, check each address is in the file, and read the control path at one fresh finalized block: proxies, owners, Safes, timelocks. The model only points at sentences. Code keeps a claim only if the quote is verbatim and next to the address, and code itself reads the number (4-of-7, 48 hours). Code compares and records, dated: MATCH, WEAKER, STRONGER or UNVERIFIABLE. If validators extract different claims, no record is written. The model never decides a number, a chain fact or the verdict. Seeds: 12 real docs files on 5 chains: 5 MATCH, 2 WEAKER, 5 UNVERIFIABLE. The weaker ones are Lido committees whose Safes lost a signer after the docs were written.
```

Character count: **887** (limit 1000), Python `len()` of the text above.

Canonical `0x13cb760E534A5edA7e383cd9A0f6E1b0b84f23E8`, demo `0x4974407d9611a979677E3203CA2f95e283907554` (GenLayer Studio Dev), both from commit `df32b0e`. Seeds: docs/SEEDS.md.
