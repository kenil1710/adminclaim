"""Run AdminClaim's own pure + fetch code locally against the REAL network
(GitHub, the five RPCs), with a tiny stand-in for gl.nondet.web. No model:
claims are not extracted here. Used for research and to verify the chain by
hand.

  python3 tools/live.py walk <chain> <addr,addr> [block|finalized]
  python3 tools/live.py gather <docs_url> <chain> <addr,addr> [branch]
"""
import json
import sys
import types
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class _Res:
    def __init__(self, status, body):
        self.status_code = status
        self.body = body
        self.headers = {}


def _request(url, method="GET", body=None, headers=None, **_k):
    req = urllib.request.Request(url, data=body.encode() if isinstance(body, str) else body,
                                 method=method, headers={"User-Agent": "adminclaim-live", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return _Res(r.status, r.read())
    except urllib.error.HTTPError as e:
        return _Res(e.code, e.read())


def load():
    mod = types.ModuleType("genlayer")
    web = types.SimpleNamespace(get=lambda url, **k: _request(url), request=_request)
    nondet = types.SimpleNamespace(web=web, exec_prompt=None)
    storage = types.SimpleNamespace(TreeMap=dict, DynArray=list, allow=lambda c: c)
    mod.gl = types.SimpleNamespace(nondet=nondet, storage=storage,
                                   contract=types.SimpleNamespace(Contract=object),
                                   public=types.SimpleNamespace(view=lambda f: f, write=lambda f: f),
                                   vm=types.SimpleNamespace(UserError=Exception, Result=object, Return=object),
                                   message=None)
    mod.Address = str
    for n in ("u8", "u16", "u32", "u64", "u128", "u256", "i64", "bigint"):
        setattr(mod, n, int)
    sys.modules["genlayer"] = mod
    ns = {}
    src = (ROOT / "contracts" / "AdminClaim.py").read_text()
    exec(compile(src, "AdminClaim.py", "exec"), ns)
    return ns


if __name__ == "__main__":
    C = load()
    cmd = sys.argv[1]
    if cmd == "walk":
        chain, addrs = sys.argv[2], sorted(a.lower() for a in sys.argv[3].split(","))
        tag = sys.argv[4] if len(sys.argv) > 4 else "finalized"
        blk = C["read_block"](chain, tag if not tag.isdigit() else hex(int(tag)))
        print("block", blk)
        rd = C["Reader"](C["rpc_transport"](chain), hex(blk["number"]))
        w = C["walk"](rd, addrs)
        print(json.dumps(w, indent=1)[:20000])
        for s in C["subjects_of"](addrs, w["routes"]):
            for r in w["routes"][s]:
                print("ROUTE", C["describe_route"](r, w["nodes"]), "->", C["route_facts"](r, w["nodes"]))
    elif cmd == "gather":
        url, chain, addrs = sys.argv[2], sys.argv[3], sorted(a.lower() for a in sys.argv[4].split(","))
        pin = C["docs_pin"](url)
        br = C["clean_branch"](sys.argv[5] if len(sys.argv) > 5 else "")
        import time
        p = {"pin": pin, "branch": br, "chain": chain, "addrs": addrs,
             "key": C["record_key"](chain, addrs, pin["owner"], pin["repo"])}
        ev = C["gather"](p, int(time.time()), 3600, -1)
        ev.pop("_text", None)
        print(json.dumps(ev, indent=1)[:20000])
