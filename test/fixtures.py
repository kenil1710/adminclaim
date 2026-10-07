"""Builders for the offline suite: ABI words, standard-pattern contracts on a
MockChain, docs pages, GitHub compare answers, and a loaded contract module."""
import copy
import json
from pathlib import Path

import stub

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "contracts" / "AdminClaim.py"

stub._install_stub()
C = stub.load_full(CONTRACT, "adminclaim")

NOW_ISO = "2026-10-07T12:00:00Z"
NOW = C._epoch_from_iso(NOW_ISO)
FIN = 20_000_000                 # finalized block on every mock chain
FIN_TS = NOW - 900               # 15 minutes before the filing

OWNER, REPO = "acme", "protocol-docs"
SHA = "a" * 40
SHA2 = "b" * 40
PATH = "docs/security.md"
RAW = "https://raw.githubusercontent.com/%s/%s/%s/%s" % (OWNER, REPO, SHA, PATH)
BLOB = "https://github.com/%s/%s/blob/%s/%s" % (OWNER, REPO, SHA, PATH)
COMMIT_DATE = "2026-06-01T10:00:00Z"


def addr(n):
    return "0x" + ("%040x" % n)


PROXY = addr(0x1001)
PADMIN = addr(0x1002)
SAFE = addr(0x1003)
TL = addr(0x1004)
EOA1 = addr(0x2001)
EOA2 = addr(0x2002)
OWNERS7 = [addr(0x3000 + i) for i in range(7)]
SINGLETON = "0xd9db270c1b5e3bd161e8c8503c55ceabee709552"


def word(n):
    return "0x" + ("%064x" % n)


def aword(a):
    return "0x" + "0" * 24 + a[2:].lower()


def abi_string(s):
    b = s.encode()
    return "0x" + ("%064x" % 32) + ("%064x" % len(b)) + b.hex().ljust(((len(b) + 31) // 32) * 64, "0")


def abi_addrs(xs):
    out = ("%064x" % 32) + ("%064x" % len(xs))
    for x in xs:
        out += "0" * 24 + x[2:].lower()
    return "0x" + out


def abi_modules(mods, nxt="0x" + "0" * 39 + "1"):
    out = ("%064x" % 64) + ("0" * 24 + nxt[2:]) + ("%064x" % len(mods))
    for m in mods:
        out += "0" * 24 + m[2:].lower()
    return "0x" + out


SAFE_CODE = "0x" + C.SAFE_PROXY_BODY + "a2646970667358221220" + "11" * 32 + "64736f6c63430007060033"
# runtime with an owner() dispatcher entry, no DELEGATECALL/SELFDESTRUCT
OWNABLE_CODE = "0x6080604052" + "63" + "8da5cb5b" + "14" + "6000" + "fe"
TL_CODE = "0x6080604052" + "63" + "f27a0c92" + "14" + "6000" + "fe"
PLAIN_CODE = "0x6080604052" + "63" + "a9059cbb" + "14" + "6000" + "fe"        # transfer() only
DELEGATING_CODE = "0x6080604052" + "f4" + "6000" + "fe"
PROXY_CODE = "0x6080604052" + "363d3d37" + "f4" + "fe"
SEL = C.SEL


def call(sel, *words):
    return C.call_data(sel, *words)


class Chain:
    """Helpers that place standard-pattern contracts on a MockChain."""

    def __init__(self, mc):
        self.mc = mc

    def eoa(self, a):
        self.mc.code[a] = "0x"

    def safe(self, a, threshold, owners, modules=(), singleton=SINGLETON, version="1.3.0", code=SAFE_CODE,
             guard=None):
        mc = self.mc
        mc.code[a] = code
        mc.slots[(a, "0x0")] = aword(singleton)
        mc.calls[(a, SEL["VERSION"])] = abi_string(version)
        mc.calls[(a, SEL["getThreshold"])] = word(threshold)
        mc.calls[(a, SEL["getOwners"])] = abi_addrs(owners)
        mc.calls[(a, call(SEL["getModulesPaginated"], C.SENTINEL[2:], "a"))] = abi_modules(list(modules))
        if guard:
            mc.slots[(a, C.GUARD_SLOT)] = aword(guard)
        for o in owners:
            if o not in mc.code:
                mc.code[o] = "0x"

    def proxy(self, a, impl, admin, beacon=None, code=PROXY_CODE):
        mc = self.mc
        mc.code[a] = code
        mc.slots[(a, C.IMPL_SLOT)] = aword(impl)
        mc.slots[(a, C.ADMIN_SLOT)] = aword(admin) if admin else word(0)
        if beacon:
            mc.slots[(a, C.BEACON_SLOT)] = aword(beacon)
        if impl not in mc.code:
            mc.code[impl] = PLAIN_CODE

    def ownable(self, a, owner, pending=None, code=OWNABLE_CODE):
        mc = self.mc
        mc.code[a] = code
        mc.calls[(a, SEL["owner"])] = aword(owner)
        if pending:
            mc.calls[(a, SEL["pendingOwner"])] = aword(pending)

    def oz_timelock(self, a, min_delay, proposers=(), admins=(), open_executor=True, code=TL_CODE,
                    role=C.PROPOSER_ROLE):
        mc = self.mc
        mc.code[a] = code
        mc.calls[(a, SEL["getMinDelay"])] = word(min_delay)
        mc.calls[(a, SEL["PROPOSER_ROLE"])] = "0x" + role
        self._roles = getattr(self, "_roles", {})
        self._roles[a] = (list(proposers), list(admins), open_executor)
        for p in proposers:
            mc.calls[(a, call(SEL["hasRole"], C.PROPOSER_ROLE, p[2:]))] = word(1)
        for p in admins:
            mc.calls[(a, call(SEL["hasRole"], C.DEFAULT_ADMIN_ROLE, p[2:]))] = word(1)
        # every other hasRole answers false: install a default
        old = mc.fail

        def default_false(m, p, _a=a, _old=old):
            if _old is not None:
                e = _old(m, p)
                if e is not None:
                    return e
            return None
        mc.fail = default_false
        mc.calls[(a, call(SEL["hasRole"], C.EXECUTOR_ROLE, "0"))] = word(1 if open_executor else 0)

    def compound_timelock(self, a, delay, admin, pending=None, code=TL_CODE):
        mc = self.mc
        mc.code[a] = code
        mc.calls[(a, SEL["delay"])] = word(delay)
        mc.calls[(a, SEL["admin"])] = aword(admin)
        mc.calls[(a, SEL["GRACE_PERIOD"])] = word(14 * 86400)
        mc.calls[(a, SEL["pendingAdmin"])] = aword(pending) if pending else aword("0x" + "0" * 40)


def has_role_false_default(mc):
    """eth_call hasRole(...) that is not set answers false (OZ AccessControl
    returns false, it does not revert)."""
    orig = mc.answer

    def answer(req, _orig=orig):
        if req["method"] == "eth_call" and req["params"][0]["data"].startswith(SEL["hasRole"]):
            key = (req["params"][0]["to"].lower(), req["params"][0]["data"])
            blk = int(req["params"][-1], 16)
            if mc._state("calls", key, blk) is None and mc._state("code", key[0], blk) not in (None, "0x"):
                mc.log.append((req["method"], json.dumps(req["params"])))
                return {"jsonrpc": "2.0", "id": req["id"], "result": word(0)}
        return _orig(req)
    mc.answer = answer


def compare_page(sha=SHA, status="behind", date=COMMIT_DATE, merge_base=None):
    return json.dumps({"status": status, "ahead_by": 0 if status != "diverged" else 2, "behind_by": 12,
                       "base_commit": {"sha": "f" * 40},
                       "merge_base_commit": {"sha": merge_base or sha, "commit": {"committer": {"date": date}}},
                       "commits": [], "files": []})


def compare_url(branch="HEAD", sha=SHA, owner=OWNER, repo=REPO):
    return C.GITHUB_API + owner + "/" + repo + "/compare/" + branch + "..." + sha


DOCS = """# Acme security

Some intro text about Acme.

## Upgrade control

The Acme vault proxy (`%s`) is upgradeable. Upgrades go through the
ProxyAdmin `%s`, which is owned by a 4-of-7 multisig (`%s`).
Every upgrade waits for a 48-hour timelock.

## Other

Treasury: 0x00000000000000000000000000000000000fffff is a 2/3 Safe.
""" % (PROXY, PADMIN, SAFE)


def claims(*items):
    return {"claims": [{"field": f, "value": v, "quote": q} for (f, v, q) in items]}


GOOD_CLAIMS = claims(
    ("multisig_threshold", 4, "owned by a 4-of-7 multisig"),
    ("multisig_signers", 7, "owned by a 4-of-7 multisig"),
    ("upgradeable", True, "is upgradeable"),
)


def fresh_world(docs=DOCS, chain="ethereum"):
    """Reset the web, model and message; install docs, compare answer and a
    mock chain for `chain`. Returns (MockChain, Chain helper)."""
    stub.WEB.reset()
    stub.MODEL.reset()
    stub.FORGE["payload"] = None
    stub.FORGE["mutate"] = None
    stub.MESSAGE.raw = {"datetime": NOW_ISO}
    stub.MESSAGE.sender_address = stub._Addr("0x" + "a" * 40)
    stub.WEB.pages[RAW] = (200, docs)
    stub.WEB.pages[compare_url()] = (200, compare_page())
    mcs = {}
    for name, (cid, url) in C.CHAINS.items():
        mc = stub.MockChain(cid, FIN, FIN_TS)
        has_role_false_default(mc)
        stub.WEB.chains[url] = mc
        mcs[name] = mc
    return mcs[chain], Chain(mcs[chain])


def standard_path(ch, threshold=4, owners=None, delay=None, modules=()):
    """proxy -> ProxyAdmin (Ownable) -> [OZ timelock ->] Safe."""
    owners = owners or OWNERS7
    ch.proxy(PROXY, addr(0x9999), PADMIN)
    if delay is None:
        ch.ownable(PADMIN, SAFE)
    else:
        ch.ownable(PADMIN, TL)
        ch.oz_timelock(TL, delay, proposers=[SAFE], admins=[TL])
    ch.safe(SAFE, threshold, owners, modules=modules)


def new_contract(mode="CANONICAL", cooldown=21600, fresh=3600):
    c = C.AdminClaim(mode, cooldown, fresh)
    for name in C.AdminClaim.__annotations__:
        getattr(c, name)          # the stub creates storage fields on first read; create them all now
    return c


def snapshot(c):
    return copy.deepcopy(c.__dict__)


class Outcome:
    def __init__(self, ok, value=None, error=None, rolled=False):
        self.ok, self.value, self.error, self.rolled = ok, value, error, rolled

    def __repr__(self):
        return "Outcome(ok=%s, value=%r, error=%r, rolled=%s)" % (self.ok, self.value, self.error, self.rolled)


def tx(c, method, *args, at=None):
    """Run a write like a transaction: on a revert or an unsettled round the
    state must be exactly what it was before (asserted - that is the
    counter-before-revert check, dynamically), then it is restored."""
    if at is not None:
        stub.MESSAGE.raw = {"datetime": at}
    before = snapshot(c)
    try:
        v = getattr(c, method)(*args)
        return Outcome(True, v)
    except stub._UserError as e:
        assert snapshot(c) == before, "state changed before a revert in " + method
        c.__dict__.clear()
        c.__dict__.update(before)
        return Outcome(False, error=e.message)
    except stub._Rolled as e:
        assert snapshot(c) == before, "state changed before an unsettled round in " + method
        c.__dict__.clear()
        c.__dict__.update(before)
        return Outcome(False, error=str(e), rolled=True)


def iso(epoch):
    y, m, d = C._civil_from_days(epoch // 86400)
    s = epoch % 86400
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (y, m, d, s // 3600, (s % 3600) // 60, s % 60)
