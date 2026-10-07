"""Research helper: every "**Address:** <chain>:0x..." / "**Quorum:** n/m"
section of the Lido multisig pages and every table row "| name | 0x.. | n/m |"
of Balancer's multisig page, compared with the Safe on chain (code's own
walk). Prints mismatches and matches; used for docs/RESEARCH.md."""
import re
import sys
sys.path.insert(0, __import__("os").path.dirname(__file__))
from live import load

C = load()
PFX = {"eth": "ethereum", "oeth": "optimism", "arb1": "arbitrum", "matic": "polygon", "base": "base"}


def safe_facts(chain, a):
    blk = C["read_block"](chain, "finalized")
    rd = C["Reader"](C["rpc_transport"](chain), hex(blk["number"]))
    n = C["classify"](rd, a.lower())
    return n, blk["number"]


def lido(path):
    text = open(path).read()
    for sec in re.split(r"\n(?=#{2,4} )", text):
        head = sec.split("\n", 1)[0]
        q = re.search(r"\*\*Quorum:\*\*\s*([0-9]+/[0-9]+)", sec)
        for m in re.finditer(r"\*\*Address:\*\*\s*(?:(\w+):)?\[?`?(0x[0-9a-fA-F]{40})", sec):
            yield head, PFX.get(m.group(1) or "eth"), m.group(2), q.group(1) if q else None


def balancer(path):
    text = open(path).read()
    for m in re.finditer(r"\|\s*([^|]+?)\s*\|\s*\[(0x[0-9a-fA-F]{40})\]\(https://app.safe.global/home\?safe=(\w+):[^)]*\)\s*\|\s*([0-9]+/[0-9]+)", text):
        yield m.group(1), PFX.get(m.group(3)), m.group(2), m.group(4)


rows = []
for f in sys.argv[1:]:
    gen = balancer(f) if "balancer" in f else lido(f)
    for head, chain, a, q in gen:
        if not chain or not q:
            continue
        try:
            n, b = safe_facts(chain, a)
        except Exception as e:
            print("ERR", f, head, chain, a, e)
            continue
        if n["kind"] != "SAFE":
            print("NOT_SAFE", chain, a, n.get("why"), "|", head[:60])
            continue
        actual = "%d/%d" % (n["threshold"], len(n["owners"]))
        tag = "MATCH " if actual == q else "DIFF  "
        print(tag, chain.ljust(9), a, "docs", q.ljust(5), "chain", actual.ljust(5), "modules", len(n["modules"]), "block", b, "|", f.split("/")[-1], head[:50])
