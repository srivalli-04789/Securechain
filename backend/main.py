import os
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
load_dotenv()
from database import Base, engine
from routers import auth, scans
Base.metadata.create_all(engine)
from sqlalchemy import text, inspect
def _add_missing_columns(table, cols):  # adds new columns to an existing database
    have = {c['name'] for c in inspect(engine).get_columns(table)}
    with engine.begin() as c:
        for n, t in cols:
            if n not in have: c.execute(text(f'ALTER TABLE {table} ADD COLUMN {n} {t}'))
_add_missing_columns('vulnerabilities', [(n, 'TEXT') for n in ('modified', 'aliases', 'affected')])
_add_missing_columns('dependencies', [('checked', 'BOOLEAN')])
app = FastAPI(title="SecureChain API")
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173").split(","), allow_methods=["*"], allow_headers=["*"])
app.include_router(auth.router, prefix="/api"); app.include_router(scans.router, prefix="/api")
@app.get("/api/health")
def health(): return {"ok": True}
