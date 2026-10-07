# v0.3.0
# { "Depends": "py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng" }
import genlayer as gl
from genlayer import *
import json
import typing

# Throwaway probe (not part of AdminClaim): which RPCs and GitHub endpoints
# answer from inside GenVM on studio-dev, and what they return.


def _status(res: typing.Any) -> int:
    s = getattr(res, "status_code", None)
    if s is None:
        s = getattr(res, "status", None)
    return 0 if s is None else int(s)


def _raw(res: typing.Any) -> bytes:
    b = getattr(res, "body", None)
    if b is None:
        return b""
    if isinstance(b, bytes):
        return b
    return str(b).encode("utf-8")


class Probe(gl.contract.Contract):
    last: str

    def __init__(self) -> None:
        self.last = ""

    @gl.public.write
    def probe(self, reqs: str) -> None:
        def run() -> str:
            out = []
            for r in json.loads(reqs):
                row = {"u": r["u"][:120]}
                try:
                    if r.get("b"):
                        res = gl.nondet.web.request(r["u"], method="POST", body=r["b"], headers={"Content-Type": "application/json"})
                    else:
                        res = gl.nondet.web.get(r["u"])
                    b = _raw(res)
                    row["s"] = _status(res)
                    row["n"] = len(b)
                    row["t"] = b[:int(r.get("k", 300))].decode("utf-8", errors="ignore")
                    h = getattr(res, "headers", None)
                    if isinstance(h, dict):
                        row["h"] = {str(k).lower(): str(h[k])[:80] for k in h if "ratelimit" in str(k).lower()}
                except Exception as e:
                    row["e"] = str(e)[:200]
                out.append(row)
            return json.dumps(out)

        self.last = gl.vm.run_nondet(run, lambda r: isinstance(r, gl.vm.Return))

    @gl.public.write
    def probe_prompt(self, prompt: str) -> None:
        def run() -> str:
            out = []
            for _ in range(2):
                try:
                    out.append(str(gl.nondet.exec_prompt(prompt, response_format="json"))[:4000])
                except Exception as e:
                    out.append("err " + str(e)[:200])
            return json.dumps(out)

        self.last = gl.vm.run_nondet(run, lambda r: isinstance(r, gl.vm.Return))

    @gl.public.view
    def get_last(self) -> str:
        return self.last
