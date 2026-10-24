import json
from collections import Counter
from datetime import datetime, timedelta
from fastapi import Response, APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session
from database import get_db
from models import Project, Scan, User
from auth import current_user
from services.dependency_parser import parse_requirements
from services.scan_engine import run_scan
from services.risk_engine import group, RANK
from services.report_service import build_pdf, count_sentence
router = APIRouter(); MAX_BYTES = 1_000_000; STALE = timedelta(minutes=10)  # a QUEUED/SCANNING scan older than this is considered stuck and may be deleted
def owned(db, sid, user):
    s = db.get(Scan, sid)
    if not s or s.project.user_id != user.id: raise HTTPException(404, "Scan not found")
    return s
def findings(s):
    out = []
    for g in group(s.vulnerabilities):
        top = max(g, key=lambda v: RANK[v.severity]); ids = {v.vuln_id for v in g}
        for v in g: ids.update(json.loads(v.aliases or "[]"))
        pid = next((i for i in sorted(ids) if i.startswith("CVE-")), top.vuln_id)
        out.append(dict(package=top.package, version=top.version, vuln=pid, aliases=", ".join(sorted(ids - {pid})) or "—", severity=top.severity, cvss=next((v.cvss for v in g if v.cvss), None) or "—",
                        summary=top.summary or "—", fixed=next((v.fixed for v in g if v.fixed), None) or "—", affected=top.affected or "—", refs=json.loads(top.refs or "[]"), published=top.published or "—", modified=top.modified or "—"))
    return out
def summary(s):
    f = findings(s); c = Counter(x["severity"] for x in f); a = json.loads(s.analysis) if s.analysis else None
    d = dict(id=s.id, project=s.project.name, project_id=s.project_id, file=s.file_name, date=s.created_at.strftime("%Y-%m-%d %H:%M UTC"), status=s.status, stage=s.stage, note=s.note,
                score=a["score"] if a else None, level=a["level"].title() if a else None, risk=a["level"].title() if a else None, incomplete=bool(a) and a.get("complete") is False,
                deps=len(s.dependencies), unpinned=sum(1 for d in s.dependencies if not d.pinned), vulns=len(f), records=len(s.vulnerabilities), project_scan_count=len(s.project.scans),
                critical=c["Critical"], high=c["High"], medium=c["Medium"], low=c["Low"], unknown=c["Unknown"])
    d["counts_text"] = count_sentence(d); return d
def start(db, bg, project, name, text):
    s = Scan(project_id=project.id, file_name=name, file_content=text); db.add(s); db.commit(); bg.add_task(run_scan, s.id); return {"id": s.id}
@router.post("/scans", status_code=201)
async def create_scan(bg: BackgroundTasks, project_name: str = Form(..., min_length=1, max_length=100), description: str = Form("", max_length=500),
                      dependency_file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    name = (dependency_file.filename or "").split("/")[-1].split("\\")[-1]
    if name != "requirements.txt": raise HTTPException(400, "Only requirements.txt is supported right now (package.json and pom.xml are coming soon).")
    raw = await dependency_file.read(MAX_BYTES + 1)
    if not raw: raise HTTPException(400, "The uploaded file is empty.")
    if len(raw) > MAX_BYTES: raise HTTPException(413, "File is too large (limit 1 MB).")
    try: text = raw.decode("utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig")  # UTF-16 is what PowerShell's `pip freeze >` writes
    except UnicodeDecodeError: raise HTTPException(400, "File must be UTF-8 text.")
    if not project_name.strip(): raise HTTPException(400, "Enter a project name.")
    if not parse_requirements(text): raise HTTPException(400, "No dependencies were found in this file.")
    p = Project(user_id=user.id, name=project_name.strip(), description=description.strip()); db.add(p); db.flush()
    return start(db, bg, p, name, text)
@router.post("/projects/{pid}/rescan", status_code=201)
def rescan(pid: int, bg: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(current_user)):
    p = db.get(Project, pid)
    if not p or p.user_id != user.id or not p.scans: raise HTTPException(404, "Project not found")
    return start(db, bg, p, p.scans[0].file_name, p.scans[0].file_content)
@router.get("/projects")
def projects(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [dict(id=p.id, name=p.name, description=p.description, latest=summary(p.scans[0]) if p.scans else None, history=[summary(x) for x in p.scans]) for p in sorted(user.projects, key=lambda p: -p.id)]
def latest_done(user): return [x for x in (next((s for s in p.scans if s.status == "COMPLETED"), None) for p in user.projects) if x]
@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), user: User = Depends(current_user)):
    scans = sorted([s for p in user.projects for s in p.scans], key=lambda s: -s.id); sums = [summary(s) for s in latest_done(user)]
    return dict(total_scans=len(scans), projects=len(user.projects), dependencies=sum(x["deps"] for x in sums), vulnerabilities=sum(x["vulns"] for x in sums),
                critical=sum(x["critical"] for x in sums), recent=[summary(s) for s in scans[:5]])
@router.get("/dashboard/risk-history")
def risk_history(db: Session = Depends(get_db), user: User = Depends(current_user)):
    done = sorted([s for p in user.projects for s in p.scans if s.status == "COMPLETED" and s.analysis], key=lambda s: s.id)
    return [dict(scan_id=s.id, project=s.project.name, date=s.created_at.strftime("%Y-%m-%d %H:%M"), score=json.loads(s.analysis)["score"]) for s in done]
@router.get("/dashboard/severity")
def severity_totals(db: Session = Depends(get_db), user: User = Depends(current_user)):
    c = Counter()
    for s in latest_done(user): c.update(x["severity"] for x in findings(s))
    return [{"n": k, "v": c[k]} for k in ("Critical", "High", "Medium", "Low", "Unknown")]
def running(s): return s.status in ("QUEUED", "SCANNING") and datetime.utcnow() - s.created_at < STALE
@router.delete("/scans/{sid}")
def delete_scan(sid: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    s = owned(db, sid, user)  # 404 unless the scan belongs to the authenticated user
    if running(s): raise HTTPException(409, "This scan is still running. Wait for it to finish before deleting it.")
    pid = s.project_id; db.delete(s); db.flush()  # ORM cascade removes dependencies and vulnerabilities; analysis, recommendations and the stored file are columns on the scan row
    gone = db.query(Scan).filter_by(project_id=pid).count() == 0
    if gone: db.delete(db.get(Project, pid))  # a project with no scans cannot be viewed or rescanned, so it is removed with its last scan
    db.commit(); return {"deleted": sid, "project_deleted": gone}
@router.delete("/projects/{pid}")
def delete_project(pid: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    p = db.get(Project, pid)
    if not p or p.user_id != user.id: raise HTTPException(404, "Project not found")
    if any(running(x) for x in p.scans): raise HTTPException(409, "A scan in this project is still running. Wait for it to finish before deleting the project.")
    n = len(p.scans); db.delete(p); db.commit(); return {"deleted": pid, "scans_deleted": n}
@router.get("/scans/{sid}")
def scan(sid: int, db: Session = Depends(get_db), user: User = Depends(current_user)): return summary(owned(db, sid, user))
@router.get("/scans/{sid}/status")
def status(sid: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    s = owned(db, sid, user); return dict(status=s.status, stage=s.stage, note=s.note)
@router.get("/scans/{sid}/sbom")
def sbom(sid: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    s = owned(db, sid, user); rows = []
    for d in s.dependencies:
        vs = [v.severity for v in s.vulnerabilities if v.dependency_id == d.id]
        risk = "Not checked" if not (d.pinned and d.checked is not False) else max(vs, key=RANK.get) if vs else "None found"  # unpinned or failed lookups are never shown as "clean"
        rows.append(dict(name=d.name, version=d.version if d.pinned else "Not pinned", constraint=d.constraint or "—", eco=d.ecosystem, type=d.dep_type, license="Not available", risk=risk))
    return rows
@router.get("/scans/{sid}/vulnerabilities")
def vulns(sid: int, severity: str = "", q: str = "", db: Session = Depends(get_db), user: User = Depends(current_user)):
    q = q.lower(); return [f for f in findings(owned(db, sid, user)) if (not severity or f["severity"] == severity) and (not q or q in f["package"].lower() or q in (f["vuln"] + f["aliases"]).lower())]
@router.get("/scans/{sid}/threats")
def threats(sid: int, db: Session = Depends(get_db), user: User = Depends(current_user)): return findings(owned(db, sid, user))
@router.get("/scans/{sid}/graph")
def graph(sid: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    s = owned(db, sid, user); cnt, risk = Counter(), {}
    for g in group(s.vulnerabilities):
        d = g[0].dependency_id; cnt[d] += 1; sev = max((v.severity for v in g), key=RANK.get)
        if d not in risk or RANK[sev] > RANK[risk[d]]: risk[d] = sev
    ok = lambda d: d.pinned and d.checked is not False
    nodes = [dict(id="root", label=s.project.name, version="", type="Application", risk="None", vulns=0, deps=[d.name for d in s.dependencies], by=[])] + [dict(id=str(d.id), label=d.name, version=d.version if d.pinned else "Not pinned", type=d.dep_type, risk=risk.get(d.id, "None found") if ok(d) else "Not checked", vulns=cnt[d.id], deps=[], by=[s.project.name]) for d in s.dependencies]
    return dict(nodes=nodes, edges=[["root", str(d.id)] for d in s.dependencies], note="Transitive dependency information is not available from this dependency file.")
@router.get("/scans/{sid}/report.pdf")
def report(sid: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    s = owned(db, sid, user)
    if s.status != "COMPLETED": raise HTTPException(409, "The scan has not completed yet.")
    pdf = build_pdf(summary(s), s.dependencies, findings(s), json.loads(s.analysis), json.loads(s.recs or "[]"))
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="securechain-report-{s.id}.pdf"'})
@router.get("/scans/{sid}/analysis")
def analysis(sid: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    s = owned(db, sid, user)
    if not s.analysis: raise HTTPException(409, "Analysis is not ready yet.")
    return json.loads(s.analysis)
@router.get("/scans/{sid}/recommendations")
def recs(sid: int, db: Session = Depends(get_db), user: User = Depends(current_user)): return json.loads(owned(db, sid, user).recs or "[]")
