"""docs/SUBMISSION.md: the Intelligent Contract description (<= 1000
characters, exact count printed) with the real seed numbers from
docs/SEEDS.md."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
seeds = (ROOT / "docs" / "SEEDS.md").read_text()
line = re.search(r"Verdicts: (.*?) \((\d+) records, (\d+) chains\)", seeds)
counts = dict(re.findall(r"([A-Z_]+) (\d+)", line.group(1)))
n, chains = int(line.group(2)), int(line.group(3))
dep = json.loads((ROOT / "deployments.json").read_text())


def c(k):
    return int(counts.get(k, 0))


parts = []
for k, label in (("MATCH", "MATCH"), ("WEAKER_THAN_CLAIMED", "WEAKER"), ("STRONGER_THAN_CLAIMED", "STRONGER"),
                 ("UNVERIFIABLE", "UNVERIFIABLE"), ("INCONCLUSIVE", "INCONCLUSIVE")):
    if c(k):
        parts.append("%d %s" % (c(k), label))
text = (
    "AdminClaim checks what a protocol's docs say about who controls its contracts against the chain. "
    "A filer gives a docs file pinned to a GitHub commit, a chain and the addresses. Validators prove the commit "
    "is on a branch of that repo, check each address is in the file, and read the control path at one fresh "
    "finalized block: proxies, owners, Safes, timelocks. The model only points at sentences. Code keeps a claim "
    "only if the quote is verbatim and next to the address, and code itself reads the number (4-of-7, 48 hours). "
    "Code compares and records, dated: MATCH, WEAKER, STRONGER, UNVERIFIABLE, or INCONCLUSIVE if extractions "
    "disagree. The model never decides a number, a chain fact or the verdict. "
    "Seeds: %d real docs files on %d chains: %s. The weaker ones are Lido committees whose Safes lost a signer "
    "after the docs were written." % (n, chains, ", ".join(parts))
)
assert len(text) <= 1000, len(text)
out = """# Submission

## Intelligent Contract description (%d characters)

```
%s
```

Character count: **%d** (limit 1000), counted by `tools/submission.py` with Python `len()` on the text above.

## Facts behind it

* Contract: `contracts/AdminClaim.py`; canonical `%s`, demo `%s` (GenLayer Studio Dev), both from commit `%s`.
* Seeds: docs/SEEDS.md (%d records on the canonical deployment, %d chains). The two WEAKER records were checked by hand against Safe events and the docs' git history (docs/research/hand_checks.json).
* What code decides and what the model never decides: README.md.
""" % (len(text), text, len(text), dep["contracts"]["AdminClaim"]["address"], dep["contracts"]["AdminClaimDemo"]["address"],
       dep["contracts"]["AdminClaim"]["commit"][:10], n, chains)
(ROOT / "docs" / "SUBMISSION.md").write_text(out)
print(len(text))
print(text)
