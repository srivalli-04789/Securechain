import re
NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
CLAUSE = re.compile(r"^(?:===|==|>=|<=|~=|!=|>|<)[A-Za-z0-9.*+!_-]+$")
def _norm(n): return re.sub(r"[-_.]+", "-", n).lower()
def parse_requirements(text: str):
    """Parse declarations only (never installs or executes). Returns unique direct dependencies.
    A dependency is 'pinned' only for a single exact '==X.Y.Z' clause (no wildcard, no ranges)."""
    out, seen = [], set()
    for raw in text.splitlines():
        line = re.split(r"\s--", raw.split("#")[0].split(";")[0].strip())[0].rstrip("\\").strip()  # drop comments, markers, per-line options
        if not line or line.startswith("-") or "://" in line or line.startswith("."): continue
        m = NAME.match(line)
        if not m or _norm(m.group(1)) in seen: continue
        rest = m.group(2).replace(" ", "")
        clauses = [c for c in rest.split(",") if c]
        if not all(CLAUSE.match(c) for c in clauses): continue  # not a plain requirement line; ignore rather than guess
        seen.add(_norm(m.group(1)))
        pinned = len(clauses) == 1 and clauses[0].startswith("==") and not clauses[0].startswith("===") and "*" not in clauses[0]
        out.append(dict(name=m.group(1), version=clauses[0][2:] if pinned else "unspecified", constraint=rest[:60], pinned=pinned, ecosystem="PyPI", dep_type="Direct"))
    return out
