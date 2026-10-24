"""End-to-end API tests. Run from backend/:  pip install pytest pypdf && python -m pytest tests -q
OSV is mocked at the client boundary (services.scan_engine.query_osv); everything else (parsing, DB, grouping, risk, recs, PDF, auth) is real."""
import io, json, os, sys, tempfile
from datetime import datetime, timedelta
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/t.db"; os.environ["SECRET_KEY"] = "test-secret"
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from fastapi.testclient import TestClient
from main import app
from database import SessionLocal
from models import User, Project, Scan, Dependency, Vulnerability
import services.scan_engine as engine
client = TestClient(app)
def rec(name, ver, vid, sev, aliases=(), fixed=None):
    return dict(package=name, version=ver, vuln_id=vid, summary=f"{vid} summary", severity=sev, cvss=None, fixed=fixed, refs="[]", published="2024-01-02T00:00:00Z", modified="2024-02-02T00:00:00Z", aliases=json.dumps(list(aliases)), affected="introduced 0")
FAKE = {"requests": [rec("requests", "2.0.0", "GHSA-aaaa", "High", ["CVE-2024-1", "PYSEC-1"], "2.5.0"), rec("requests", "2.0.0", "PYSEC-1", "Unknown", ["CVE-2024-1", "GHSA-aaaa"], "2.5.0"), rec("requests", "2.0.0", "GHSA-bbbb", "Critical", [], "2.9.0")],
        "pyyaml": [rec("pyyaml", "5.1", "GHSA-cccc", "Medium", [])], "flask": []}
@pytest.fixture(autouse=True)
def osv(monkeypatch):
    monkeypatch.setattr(engine, "query_osv", lambda n, v: [dict(x) for x in FAKE.get(n.lower(), [])])
REQ = "requests==2.0.0\npyyaml==5.1\nflask==3.0.0\nnumpy>=1.20\ndjango\n"
_n = [0]
def user(name="u"):
    _n[0] += 1; email = f"{name}{_n[0]}@example.com"; pw = "Str0ng!Passw0rd"
    assert client.post("/api/auth/register", json={"name": name, "email": email, "password": pw}).status_code == 201
    t = client.post("/api/auth/login", json={"email": email, "password": pw}).json()["access_token"]; return {"Authorization": f"Bearer {t}"}
def scan(h, text=REQ, fname="requirements.txt", project="Proj"):
    return client.post("/api/scans", headers=h, data={"project_name": project}, files={"dependency_file": (fname, io.BytesIO(text.encode() if isinstance(text, str) else text))})
def test_auth_and_hashing():
    assert client.post("/api/auth/register", json={"name": "x", "email": "weak@example.com", "password": "weakpass"}).status_code == 422
    h = user("alice"); me = client.get("/api/auth/me", headers=h).json(); assert me["email"].startswith("alice")
    db = SessionLocal(); u = db.query(User).filter_by(email=me["email"]).first(); assert u.password_hash.startswith("$2") and "Str0ng" not in u.password_hash; db.close()
    assert client.post("/api/auth/login", json={"email": me["email"], "password": "Wrong!Pass1"}).status_code == 401
def test_protected_endpoints_require_auth():
    for m, p in [("get", "/api/dashboard"), ("get", "/api/projects"), ("get", "/api/scans/1"), ("get", "/api/scans/1/report.pdf"), ("delete", "/api/scans/1"), ("delete", "/api/projects/1"), ("post", "/api/projects/1/rescan")]:
        assert getattr(client, m)(p).status_code == 401, p
    assert client.get("/api/scans/1", headers={"Authorization": "Bearer garbage"}).status_code == 401
def test_only_requirements_txt_accepted():
    h = user()
    assert scan(h, "{}", "package.json").status_code == 400 and scan(h, "<project/>", "pom.xml").status_code == 400 and scan(h, "", "requirements.txt").status_code == 400
    assert scan(h, "# nothing\n").status_code == 400
    assert client.get("/api/projects", headers=h).json() == []  # failed uploads created nothing
def test_full_flow_numbers_are_consistent_everywhere():
    h = user(); r = scan(h, project="My App"); assert r.status_code == 201; sid = r.json()["id"]
    assert client.get(f"/api/scans/{sid}/status", headers=h).json()["status"] == "COMPLETED"
    s = client.get(f"/api/scans/{sid}", headers=h).json()
    assert (s["project"], s["file"], s["deps"], s["unpinned"]) == ("My App", "requirements.txt", 5, 2)
    assert s["records"] == 4 and s["vulns"] == 3  # GHSA-aaaa + PYSEC-1 collapse into one issue; GHSA-bbbb; GHSA-cccc
    assert (s["critical"], s["high"], s["medium"], s["low"], s["unknown"]) == (1, 1, 1, 0, 0)
    assert s["counts_text"] == "3 unique vulnerabilities identified across 5 dependencies, represented by 4 advisory/identifier records."
    vs = client.get(f"/api/scans/{sid}/vulnerabilities", headers=h).json(); th = client.get(f"/api/scans/{sid}/threats", headers=h).json()
    assert len(vs) == len(th) == s["vulns"]
    assert {v["vuln"] for v in vs} == {"CVE-2024-1", "GHSA-bbbb", "GHSA-cccc"}
    sb = {x["name"]: x for x in client.get(f"/api/scans/{sid}/sbom", headers=h).json()}; assert len(sb) == s["deps"]
    assert sb["requests"]["risk"] == "Critical" and sb["flask"]["risk"] == "None found" and sb["numpy"]["risk"] == "Not checked" and sb["django"]["risk"] == "Not checked" and sb["numpy"]["version"] == "Not pinned" and sb["numpy"]["license"] == "Not available"
    g = client.get(f"/api/scans/{sid}/graph", headers=h).json(); assert len(g["nodes"]) == s["deps"] + 1 and len(g["edges"]) == s["deps"] and "not available" in g["note"]
    assert sum(n["vulns"] for n in g["nodes"]) == s["vulns"]
    a = client.get(f"/api/scans/{sid}/analysis", headers=h).json()
    assert a["score"] == s["score"] and a["counts"]["unique"] == s["vulns"] and a["counts"]["records"] == s["records"] and a["counts"]["unpinned"] == s["unpinned"] and a["ml"]["available"] is False
    assert "2 of 5" in " ".join(a["reasons"]) and "ML-assisted anomaly analysis is not enabled yet; it needs more scan data." == a["ml"]["note"]
    assert not any("Transitive" in f["n"] for f in a["factors"])
    # score is calculated, not hardcoded: 0.7*min(100,25+12+5)+0.2*60... verify against formula
    assert a["score"] == round(0.7 * min(100, 25 + 12 + 5) + 0.2 * round(100 * 2 / 5) + 0.1 * round(100 * 2 / 5))
    rc = [x["text"] for x in client.get(f"/api/scans/{sid}/recommendations", headers=h).json()]
    assert any(t.startswith("Upgrade requests from 2.0.0 to 2.9.0 or later") for t in rc) and "Review pyyaml 5.1: 1 known vulnerability, none with a known fixed version." in rc
    assert not any("flask" in t.lower() for t in rc) and any(t.startswith("Pin 2 dependencies") and "numpy" in t and "django" in t for t in rc)
    d = client.get("/api/dashboard", headers=h).json(); assert (d["total_scans"], d["projects"], d["dependencies"], d["vulnerabilities"], d["critical"]) == (1, 1, 5, 3, 1)
    assert client.get("/api/dashboard/risk-history", headers=h).json()[0]["score"] == s["score"]
    sev = {x["n"]: x["v"] for x in client.get("/api/dashboard/severity", headers=h).json()}; assert sev["Critical"] == sev["High"] == sev["Medium"] == 1 and sev["Low"] == 0
    # PDF carries the same stored numbers
    from pypdf import PdfReader
    pdf = client.get(f"/api/scans/{sid}/report.pdf", headers=h); assert pdf.headers["content-type"] == "application/pdf"
    txt = " ".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages).replace("\n", " ")
    assert s["counts_text"] in txt and f"Risk score {s['score']}/100" in txt and "My App" in txt and "2 of 5 dependencies are not pinned" in txt and "Upgrade requests from 2.0.0 to 2.9.0" in txt and s["date"] in txt
def test_empty_state_and_no_fake_data():
    h = user(); d = client.get("/api/dashboard", headers=h).json()
    assert d == dict(total_scans=0, projects=0, dependencies=0, vulnerabilities=0, critical=0, recent=[])
    assert client.get("/api/projects", headers=h).json() == [] and client.get("/api/dashboard/risk-history", headers=h).json() == []
def test_osv_total_failure_marks_scan_failed(monkeypatch):
    def boom(n, v): raise RuntimeError("down")
    monkeypatch.setattr(engine, "query_osv", boom); h = user(); sid = scan(h).json()["id"]
    st = client.get(f"/api/scans/{sid}/status", headers=h).json(); assert st["status"] == "FAILED" and "OSV" in st["note"]
    s = client.get(f"/api/scans/{sid}", headers=h).json(); assert s["score"] is None and s["level"] is None  # no fabricated 0 / LOW
    assert client.get(f"/api/scans/{sid}/report.pdf", headers=h).status_code == 409
def test_osv_partial_failure_is_flagged_incomplete(monkeypatch):
    def flaky(n, v):
        if n == "pyyaml": raise RuntimeError("down")
        return [dict(x) for x in FAKE.get(n, [])]
    monkeypatch.setattr(engine, "query_osv", flaky); h = user(); sid = scan(h).json()["id"]
    s = client.get(f"/api/scans/{sid}", headers=h).json(); assert s["status"] == "COMPLETED" and s["incomplete"] and "incomplete" in s["note"].lower()
    assert client.get(f"/api/scans/{sid}/analysis", headers=h).json()["complete"] is False
    assert {x["name"]: x["risk"] for x in client.get(f"/api/scans/{sid}/sbom", headers=h).json()}["pyyaml"] == "Not checked"
def test_users_cannot_access_each_others_scans():
    a, b = user("a"), user("b"); sid = scan(a).json()["id"]; pid = client.get("/api/projects", headers=a).json()[0]["id"]
    for sfx in ("", "/status", "/sbom", "/vulnerabilities", "/threats", "/graph", "/analysis", "/recommendations", "/report.pdf"):
        assert client.get(f"/api/scans/{sid}{sfx}", headers=b).status_code == 404, sfx
    assert client.delete(f"/api/scans/{sid}", headers=b).status_code == 404 and client.delete(f"/api/projects/{pid}", headers=b).status_code == 404 and client.post(f"/api/projects/{pid}/rescan", headers=b).status_code == 404
    assert client.get(f"/api/scans/{sid}", headers=a).status_code == 200  # still intact
    assert client.get("/api/projects", headers=b).json() == [] and client.get("/api/dashboard", headers=b).json()["total_scans"] == 0
def orphans(sid):
    db = SessionLocal(); n = (db.query(Dependency).filter_by(scan_id=sid).count(), db.query(Vulnerability).filter_by(scan_id=sid).count(), db.query(Scan).filter_by(id=sid).count()); db.close(); return n
def test_delete_scan_cascades_and_updates_everything():
    h = user(); first = scan(h).json()["id"]; pid = client.get("/api/projects", headers=h).json()[0]["id"]
    second = client.post(f"/api/projects/{pid}/rescan", headers=h).json()["id"]
    p = client.get("/api/projects", headers=h).json()[0]; assert [x["id"] for x in p["history"]] == [second, first] and p["latest"]["project_scan_count"] == 2
    assert client.get("/api/dashboard", headers=h).json()["total_scans"] == 2
    r = client.delete(f"/api/scans/{second}", headers=h); assert r.status_code == 200 and r.json() == {"deleted": second, "project_deleted": False}
    assert orphans(second) == (0, 0, 0) and orphans(first)[2] == 1 and orphans(first)[0] == 5
    assert client.get(f"/api/scans/{second}", headers=h).status_code == 404
    d = client.get("/api/dashboard", headers=h).json(); assert d["total_scans"] == 1 and [x["id"] for x in d["recent"]] == [first] and d["vulnerabilities"] == 3
    r = client.delete(f"/api/scans/{first}", headers=h); assert r.json() == {"deleted": first, "project_deleted": True}  # last scan removes the now-empty project
    assert orphans(first) == (0, 0, 0) and client.get("/api/projects", headers=h).json() == []
    d = client.get("/api/dashboard", headers=h).json(); assert (d["total_scans"], d["projects"], d["dependencies"], d["vulnerabilities"], d["recent"]) == (0, 0, 0, 0, [])
    assert client.get("/api/dashboard/risk-history", headers=h).json() == [] and all(x["v"] == 0 for x in client.get("/api/dashboard/severity", headers=h).json())
    assert client.delete(f"/api/scans/{first}", headers=h).status_code == 404  # already gone
def test_delete_project_cascades_and_other_users_data_survives():
    a, b = user("a"), user("b"); s1 = scan(a).json()["id"]; pid = client.get("/api/projects", headers=a).json()[0]["id"]; s2 = client.post(f"/api/projects/{pid}/rescan", headers=a).json()["id"]; sb = scan(b).json()["id"]
    r = client.delete(f"/api/projects/{pid}", headers=a); assert r.status_code == 200 and r.json()["scans_deleted"] == 2
    assert orphans(s1) == orphans(s2) == (0, 0, 0) and orphans(sb)[2] == 1 and client.get(f"/api/scans/{sb}", headers=b).status_code == 200
def test_cannot_delete_running_scan_but_can_delete_stuck_one():
    h = user(); sid = scan(h).json()["id"]; db = SessionLocal(); s = db.get(Scan, sid); s.status = "SCANNING"; db.commit()
    r = client.delete(f"/api/scans/{sid}", headers=h); assert r.status_code == 409 and "still running" in r.json()["detail"]
    s.created_at = datetime.utcnow() - timedelta(hours=1); db.commit(); db.close()
    assert client.delete(f"/api/scans/{sid}", headers=h).status_code == 200
def test_utf16_requirements_from_powershell_is_accepted():
    h = user(); r = scan(h, "requests==2.0.0\r\n".encode("utf-16")); assert r.status_code == 201
    assert client.get(f"/api/scans/{r.json()['id']}", headers=h).json()["deps"] == 1
