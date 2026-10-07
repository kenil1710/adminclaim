"""Print AdminClaim's prompt for a docs file, or (with an answers file) what
code keeps from each raw model answer. Fetches the docs from GitHub raw."""
import ast
import json
import sys
import urllib.request
sys.path.insert(0, __import__("os").path.dirname(__file__))
from live import load

C = load()
url, chain, addrs = sys.argv[1], sys.argv[2], sorted(a.lower() for a in sys.argv[3].split(","))
pin = C["docs_pin"](url)
text = urllib.request.urlopen(pin["raw"]).read().decode("utf-8", errors="replace")
if len(sys.argv) == 4:
    sys.stdout.write(C["model_prompt"](text, chain, addrs, "N0NCE0123456789a"))
else:
    for raw in json.load(open(sys.argv[4])):
        try:
            obj = ast.literal_eval(raw)
        except Exception:
            obj = raw
        print("RAW :", str(raw)[:1500])
        out = {"kept": [], "drops": []}
        for c in (obj.get("claims", []) if isinstance(obj, dict) else []):
            k = C["keep_claim"](c, text, text.lower(), addrs)
            (out["drops"] if "drop" in k else out["kept"]).append(k if "drop" not in k else [c.get("field"), c.get("quote"), k["drop"]])
        print("KEEP:", json.dumps(out)[:1500])
