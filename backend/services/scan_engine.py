import json
from database import SessionLocal
from models import Scan, Dependency, Vulnerability
from services.dependency_parser import parse_requirements
from services.vulnerability_service import query_osv
from services.risk_engine import assess, recommend
def run_scan(scan_id: int):
    db = SessionLocal(); scan = db.get(Scan, scan_id)
    if not scan: db.close(); return  # scan was deleted before the worker started
    def stage(i): scan.stage = i; scan.status = "SCANNING"; db.commit()
    try:
        stage(0); stage(1)
        for d in parse_requirements(scan.file_content): db.add(Dependency(scan_id=scan.id, checked=False, **d))
        db.commit(); stage(2); stage(3); pinned = failed = 0
        for dep in list(scan.dependencies):
            if not dep.pinned: continue  # only exact '==' pins can be looked up; the rest are reported as "not checked"
            pinned += 1
            try: found = query_osv(dep.name, dep.version)
            except Exception: failed += 1; continue
            dep.checked = True
            for v in found: db.add(Vulnerability(scan_id=scan.id, dependency_id=dep.id, **v))
        db.commit(); db.refresh(scan)
        if pinned and failed == pinned:  # nothing could be retrieved: do not publish a misleading "clean" result
            scan.status = "FAILED"; scan.note = "Unable to reach the OSV vulnerability service. No vulnerability data was retrieved; please rescan later."; db.commit(); return
        stage(4); stage(5); ok = failed == 0
        scan.analysis = json.dumps(assess(scan.dependencies, scan.vulnerabilities, ok)); stage(6)
        scan.recs = json.dumps(recommend(scan.dependencies, scan.vulnerabilities)); stage(7)
        scan.note = None if ok else f"The OSV vulnerability service could not be reached for {failed} of {pinned} pinned dependencies. Results are incomplete."
        scan.stage = 8; scan.status = "COMPLETED"; db.commit()
    except Exception:
        try: db.rollback(); scan.status = "FAILED"; scan.note = "Scan failed unexpectedly."; db.commit()
        except Exception: db.rollback()  # e.g. the scan row was deleted while running
    finally: db.close()
