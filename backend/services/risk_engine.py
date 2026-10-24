import json, re
from collections import Counter
from packaging.version import Version, InvalidVersion
W = {"Critical": 25, "High": 12, "Medium": 5, "Low": 2, "Unknown": 5}
RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 2}
def _plural(n, one, many): return f"{n} {one if n == 1 else many}"
def assess(deps, vulns, complete=True):
    """Transparent score: 70% severity-weighted findings, 20% exposure, 10% unpinned deps. No randomness, no ML."""
    c = Counter(max((v.severity for v in g), key=RANK.get) for g in group(vulns)); n = len(deps) or 1
    affected = {v.dependency_id for v in vulns}; unpinned_n = sum(1 for d in deps if not d.pinned)
    sev = min(100, sum(W.get(k, 5) * x for k, x in c.items())); exposure = round(100 * len(affected) / n); unpinned = round(100 * unpinned_n / n)
    score = round(0.7 * sev + 0.2 * exposure + 0.1 * unpinned)
    level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    if c["Critical"] and level in ("LOW", "MEDIUM"): level = "HIGH"
    why = []
    if not complete: why.append("Vulnerability data is incomplete: the OSV service could not be reached for some dependencies, so this score may understate the risk.")
    if c["Critical"]: why.append(f"Critical vulnerabilities were detected in {_plural(len({v.dependency_id for v in vulns if v.severity == 'Critical'}), 'dependency', 'dependencies')}.")
    if c["High"]: why.append(f"{c['High']} high-severity finding requires a security update." if c["High"] == 1 else f"{c['High']} high-severity findings require security updates.")
    if affected: why.append(f"{len(affected)} of {_plural(len(deps), 'dependency', 'dependencies')} ({exposure}%) have known vulnerabilities.")
    if unpinned_n: why.append(f"{unpinned_n} of {_plural(len(deps), 'dependency', 'dependencies')} {'is' if unpinned_n == 1 else 'are'} not pinned to an exact version (==), so {'it was' if unpinned_n == 1 else 'they were'} not checked against OSV.")
    if not why: why.append("No known vulnerabilities were found for the pinned dependencies.")
    names = {"Critical": "Critical vulnerabilities", "High": "High vulnerabilities", "Medium": "Medium vulnerabilities", "Low": "Low vulnerabilities", "Unknown": "Unrated vulnerabilities"}
    factors = [{"n": names[k], "v": min(100, c[k] * W[k]), "detail": f"{c[k]} unique × {W[k]} points"} for k in names] + [
        {"n": "Dependency exposure", "v": exposure, "detail": f"{len(affected)} of {len(deps)} dependencies have known vulnerabilities"},
        {"n": "Unpinned dependencies", "v": unpinned, "detail": f"{unpinned_n} of {len(deps)} dependencies are not pinned to an exact version"}]
    return {"score": score, "level": level, "complete": complete, "factors": factors, "reasons": why,
            "counts": {"unique": sum(c.values()), "records": len(vulns), "critical": c["Critical"], "high": c["High"], "medium": c["Medium"], "low": c["Low"], "unknown": c["Unknown"],
                       "dependencies": len(deps), "vulnerable_dependencies": len(affected), "vulnerable_pct": exposure, "unpinned": unpinned_n},
            "formula": f"score = round(0.7 × severity points ({sev}, capped at 100) + 0.2 × exposure ({exposure}%) + 0.1 × unpinned ({unpinned}%)) = {score}",
            "levels_note": "LOW below 25, MEDIUM 25–49, HIGH 50–74, CRITICAL 75 and above. Any critical finding raises LOW/MEDIUM to HIGH.",
            "transitive_note": "Transitive dependency information is not available from this dependency file.",
            "ml": {"available": False, "note": "ML-assisted anomaly analysis is not enabled yet; it needs more scan data."}}
def _vkey(v):
    try: return (0, Version(v))
    except InvalidVersion: return (1, v)
def recommend(deps, vulns):
    """Recommendations come only from this scan: OSV fixed versions, plus unpinned dependencies that could not be checked."""
    by = {}
    for g in group(vulns): by.setdefault(g[0].package, []).append(g)
    out = []
    for pkg, gs in by.items():
        ver = gs[0][0].version; sev = max((v.severity for g in gs for v in g), key=RANK.get)
        fixes = [next((v.fixed for v in g if v.fixed), None) for g in gs]; have = [f for f in fixes if f]; n = len(gs)
        lvl = "Medium" if sev == "Unknown" else sev
        if have:
            t = f"Upgrade {pkg} from {ver} to {max(have, key=_vkey)} or later; this addresses {len(have)} of {_plural(n, 'known vulnerability', 'known vulnerabilities')}."
            if len(have) < n: t += f" The other {n - len(have)} {'has' if n - len(have) == 1 else 'have'} no known fixed version and should be reviewed."
        else: t = f"Review {pkg} {ver}: {_plural(n, 'known vulnerability', 'known vulnerabilities')}, none with a known fixed version."
        out.append({"level": lvl, "text": t})
    loose = [d.name for d in deps if not d.pinned]
    if loose: out.append({"level": "Medium", "text": f"Pin {_plural(len(loose), 'dependency', 'dependencies')} to exact versions (==) so {'it' if len(loose) == 1 else 'they'} can be checked for known vulnerabilities: " + ", ".join(loose[:10]) + (f" and {len(loose) - 10} more." if len(loose) > 10 else ".")})
    return sorted(out, key=lambda r: -RANK[r["level"]])
def group(vs):
    """Merge advisory records that are aliases of the same issue (per package)."""
    parent = {}
    def f(x):
        while parent.setdefault(x, x) != x: parent[x] = parent[parent[x]]; x = parent[x]
        return x
    for v in vs:
        ids = [v.vuln_id] + json.loads(v.aliases or "[]"); f((v.package, ids[0]))
        for i in ids[1:]: parent[f((v.package, i))] = f((v.package, ids[0]))
    out = {}
    for v in vs: out.setdefault(f((v.package, v.vuln_id)), []).append(v)
    return list(out.values())
