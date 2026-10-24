import os, secrets
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from database import get_db
from models import User
SECRET = os.getenv("SECRET_KEY") or secrets.token_hex(32)  # set SECRET_KEY in .env or sessions reset on restart
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
hash_pw = pwd.hash
verify_pw = pwd.verify
def make_token(uid): return jwt.encode({"sub": str(uid), "exp": datetime.utcnow() + timedelta(hours=8)}, SECRET, algorithm="HS256")
def current_user(token: str = Depends(oauth), db: Session = Depends(get_db)):
    try: uid = int(jwt.decode(token, SECRET, algorithms=["HS256"])["sub"])
    except (JWTError, ValueError, KeyError): raise HTTPException(401, "Invalid or expired session")
    user = db.get(User, uid)
    if not user: raise HTTPException(401, "Invalid or expired session")
    return user
