"""No state written before any check that can revert.

For every @gl.public.write method of AdminClaim, and every private method it
calls (`self._file`), walk the statements in source order (nested defs - the
nondet leader / validator - are skipped: they never write storage) and record

  * writes:  assignments / aug-assignments / deletes whose target is rooted at
             `self` or at a local alias of storage (x = self.<...>), and calls
             to module functions that mutate their argument (_bump);
  * reverts: `raise`, and calls to the private helpers that may raise.

A method passes if no revert appears after its first write.

   python3 tools/scan_writes.py [path]   (exit 1 on any violation)
"""
import ast
import sys
from pathlib import Path

SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "contracts" / "AdminClaim.py"
WRITER_FUNCS = {"_bump"}
RAISING_HELPERS = {"_file"}          # scanned on their own; calling one counts as a possible revert


def is_write_method(f):
    return any(ast.unparse(d).startswith("gl.public.write") for d in f.decorator_list)


def root(node):
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def scan(f):
    aliases = {"self"}
    events = []

    def visit(stmts):
        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                src = ast.unparse(s.value)
                if src.startswith("self.") and not src.startswith("self._now"):
                    aliases.add(s.targets[0].id)
            nodes = [s] if isinstance(s, (ast.If, ast.For, ast.While, ast.Try, ast.With)) else list(ast.walk(s))
            for n in nodes:
                if isinstance(n, ast.Raise):
                    events.append(("revert", n.lineno, "raise"))
                elif isinstance(n, ast.Call):
                    fn = n.func
                    if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id == "self" \
                            and fn.attr in RAISING_HELPERS:
                        events.append(("revert", n.lineno, "self." + fn.attr + "()"))
                    if isinstance(fn, ast.Name) and fn.id in WRITER_FUNCS:
                        events.append(("write", n.lineno, fn.id + "()"))
                elif isinstance(n, (ast.Assign, ast.AugAssign, ast.Delete)):
                    targets = n.targets if isinstance(n, (ast.Assign, ast.Delete)) else [n.target]
                    for t in targets:
                        if isinstance(t, (ast.Attribute, ast.Subscript)) and root(t) in aliases:
                            events.append(("write", n.lineno, ast.unparse(t)))
            if isinstance(s, ast.If):
                for n in ast.walk(s.test):
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                            isinstance(n.func.value, ast.Name) and n.func.value.id == "self" and \
                            n.func.attr in RAISING_HELPERS:
                        events.append(("revert", n.lineno, "self." + n.func.attr + "()"))
                visit(s.body)
                visit(s.orelse)
            elif isinstance(s, (ast.For, ast.While)):
                visit(s.body)
                visit(s.orelse)
            elif isinstance(s, ast.Try):
                visit(s.body)
                for h in s.handlers:
                    visit(h.body)
                visit(s.orelse)
                visit(s.finalbody)
            elif isinstance(s, ast.With):
                visit(s.body)

    visit(f.body)
    events.sort(key=lambda e: e[1])
    first_write = next((e for e in events if e[0] == "write"), None)
    late = [e for e in events if e[0] == "revert" and first_write and e[1] > first_write[1]]
    return events, first_write, late


def run(path=SRC, out=sys.stdout):
    tree = ast.parse(Path(path).read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AdminClaim")
    methods = {f.name: f for f in cls.body if isinstance(f, ast.FunctionDef)}
    targets = [f for f in methods.values() if is_write_method(f)] + [methods[h] for h in RAISING_HELPERS if h in methods]
    rows = []
    bad = 0
    for f in targets:
        events, fw, late = scan(f)
        reverts = [e for e in events if e[0] == "revert"]
        lr = max((e for e in reverts if not fw or e[1] < fw[1]), key=lambda e: e[1], default=None)
        ok = not late
        bad += 0 if ok else 1
        rows.append((f.name, fw, lr, ok, late))
        print(f"{f.name:12} first write {('L%d %s' % (fw[1], fw[2]))[:44] if fw else '-':46} "
              f"last revert before it {('L%d %s' % (lr[1], lr[2]))[:30] if lr else '-':32} "
              f"{'PASS' if ok else 'FAIL ' + str(late)}", file=out)
    return bad, rows


if __name__ == "__main__":
    b, _ = run()
    sys.exit(1 if b else 0)
