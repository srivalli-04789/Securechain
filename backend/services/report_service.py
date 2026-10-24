from io import BytesIO
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
def count_sentence(sm):
    """Single source of wording for unique vs advisory counts (also used by the web UI)."""
    return f"{sm['vulns']} unique vulnerabilities identified across {sm['deps']} dependencies, represented by {sm['records']} advisory/identifier records."
def build_pdf(sm, deps, fnds, an, recs):
    st = getSampleStyleSheet(); E = []
    P = lambda t, s="BodyText": E.append(Paragraph(escape(str(t)), st[s]))
    def T(rows):
        t = Table([[Paragraph(escape(str(c)), st["BodyText"]) if i else c for c in r] for i, r in enumerate(rows)], repeatRows=1); t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B4038")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .3, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP")])); E.extend([t, Spacer(1, 8)])
    c = an.get("counts") or {}; unpinned = sm["unpinned"]
    P("SecureChain", "Title"); P("AI-Driven Software Dependency Threat Detection", "Heading3")
    P(f"Project: {sm['project']} | File: {sm['file']} | Scan date: {sm['date']} | Status: {sm['status']}")
    if sm.get("note"): P(f"Note: {sm['note']}")
    P("Executive Summary", "Heading2"); P(f"Risk score {sm['score']}/100, level {an['level']}. {count_sentence(sm)}")
    P(f"Severity of unique vulnerabilities: {sm['critical']} critical, {sm['high']} high, {sm['medium']} medium, {sm['low']} low" + (f", {sm['unknown']} without a severity rating from the source." if sm["unknown"] else "."))
    P(f"{unpinned} of {sm['deps']} dependencies {'is' if unpinned == 1 else 'are'} not pinned to an exact version and {'was' if unpinned == 1 else 'were'} not checked against OSV.")
    P("SBOM / Component Inventory", "Heading2"); P("Packages and versions parsed from the uploaded file. This is a component inventory, not a CycloneDX or SPDX document.")
    T([["Package", "Version", "Constraint", "Ecosystem", "Type"]] + [[d.name, d.version if d.pinned else "Not pinned", d.constraint or "—", d.ecosystem, d.dep_type] for d in deps])
    P("Vulnerability Summary", "Heading2")
    if fnds:
        T([["Package", "Version", "ID", "Severity", "Fixed"]] + [[f["package"], f["version"], f["vuln"], f["severity"], f["fixed"]] for f in fnds[:150]])
        if len(fnds) > 150: P(f"Showing the first 150 of {len(fnds)} unique vulnerabilities.")
    else: P("No vulnerabilities found.")
    P("Critical Findings", "Heading2")
    crit = [f for f in fnds if f["severity"] == "Critical"]
    for f in crit[:30]: P(f"{f['package']} {f['version']}: {f['vuln']}. {f['summary'][:200]}")
    if not crit: P("No critical findings.")
    P("Direct Dependency Graph", "Heading2"); P(f"{len(deps)} direct dependencies. Transitive dependency information is not available from this dependency file.")
    P("Risk Analysis (rules-based)", "Heading2")
    for r in an["reasons"]: P("- " + r)
    for f in an["factors"]: P(f"{f['n']}: {f['v']}/100" + (f" ({f['detail']})" if f.get("detail") else ""))
    if an.get("formula"): P(an["formula"])
    P(an["ml"]["note"])
    P("Threat Intelligence", "Heading2")
    if fnds: T([["ID", "Package", "Severity", "Published", "Fixed"]] + [[f["vuln"], f["package"], f["severity"], f["published"], f["fixed"]] for f in fnds[:50]])
    else: P("No matching threat intelligence found.")
    P("Recommendations", "Heading2")
    for r in recs: P(f"[{r['level']}] {r['text']}")
    if not recs: P("No recommendations available.")
    buf = BytesIO(); SimpleDocTemplate(buf, pagesize=A4, title="SecureChain Report").build(E); return buf.getvalue()
