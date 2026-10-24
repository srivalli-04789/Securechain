from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import User
from schemas import RegisterIn, LoginIn, ChangePwIn
from auth import hash_pw, verify_pw, make_token, current_user
router = APIRouter(prefix="/auth")
@router.post("/register", status_code=201)
def register(b: RegisterIn, db: Session = Depends(get_db)):
    email = b.email.lower()
    if db.query(User).filter_by(email=email).first(): raise HTTPException(409, "An account with this email already exists")
    db.add(User(name=b.name.strip(), email=email, password_hash=hash_pw(b.password))); db.commit()
    return {"ok": True}
@router.post("/login")
def login(b: LoginIn, db: Session = Depends(get_db)):
    u = db.query(User).filter_by(email=b.email.lower()).first()
    if not u or not verify_pw(b.password, u.password_hash): raise HTTPException(401, "Incorrect email or password")
    return {"access_token": make_token(u.id), "token_type": "bearer"}
@router.get("/me")
def me(u: User = Depends(current_user)): return {"id": u.id, "name": u.name, "email": u.email}
@router.post("/change-password")
def change_password(b: ChangePwIn, db: Session = Depends(get_db), u: User = Depends(current_user)):
    if not verify_pw(b.current, u.password_hash): raise HTTPException(400, "Current password is incorrect")
    u.password_hash = hash_pw(b.new); db.commit(); return {"ok": True}
