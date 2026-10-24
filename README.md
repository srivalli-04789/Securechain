# SecureChain: AI-Driven Software Dependency Threat Detection
Frontend: React + Vite + Tailwind. Backend: FastAPI + SQLite + SQLAlchemy, JWT auth, OSV vulnerability lookup.
## Run
Backend: `cd backend && python -m venv venv && venv\Scripts\activate (Windows) / source venv/bin/activate && pip install -r requirements.txt && copy .env.example .env && uvicorn main:app --reload`  (http://localhost:8000/docs)
Frontend (new terminal, project root): `npm install && npm run dev`  (http://localhost:5173). Set `VITE_API_URL` in `.env` to change the API address.
## How it works
Upload one `requirements.txt` (parsed, never executed) → direct dependencies stored → exactly-pinned (`==`) versions queried against OSV → rules-based risk score + recommendations → results tabs and a PDF, all read from the same stored scan.
- **Unique vulnerabilities vs advisory records:** one issue can have several identifiers (CVE/GHSA/PYSEC). They are merged per package into one *unique vulnerability*; the raw identifiers are the *advisory/identifier records*. Both numbers are always labelled.
- **Not checked:** dependencies without an exact `==` pin cannot be looked up and are shown as "Not checked", never as clean.
- **If OSV is unreachable:** partial failures produce an "incomplete results" scan; total failure marks the scan FAILED. No vulnerability data is invented.
- **Delete:** `DELETE /api/scans/{id}` and `DELETE /api/projects/{id}` verify ownership on the server (404 for other users' data) and cascade to dependencies, vulnerabilities, analysis, recommendations and the stored file. Deleting a project's last scan also removes the empty project. A scan that is still running cannot be deleted (409) unless it has been stuck for over 10 minutes.
## Limitations
requirements.txt only (no package.json/pom.xml). Direct dependencies only (no transitive data). Component inventory only, not a CycloneDX/SPDX document; licenses unavailable. Risk score is rules-based; no ML model is running. Severity comes from the advisory source; advisories without one are shown as "Unknown".
## Tests
`cd backend && pip install pytest pypdf && python -m pytest tests -q` (OSV is mocked; everything else is real).
