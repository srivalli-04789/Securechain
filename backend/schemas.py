import re
from pydantic import BaseModel, Field, field_validator
EMAIL = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
def strong(p):
    if not (len(p) >= 8 and re.search(r"[A-Z]", p) and re.search(r"[a-z]", p) and re.search(r"\d", p) and re.search(r"[^A-Za-z0-9]", p)): raise ValueError("Password does not meet the requirements.")
    return p
class RegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=100); email: str = Field(pattern=EMAIL, max_length=254); password: str = Field(min_length=8, max_length=72)
    _p = field_validator("password")(strong)
class LoginIn(BaseModel):
    email: str = Field(pattern=EMAIL, max_length=254); password: str = Field(min_length=1, max_length=72)
class ChangePwIn(BaseModel):
    current: str = Field(min_length=1, max_length=72); new: str = Field(min_length=8, max_length=72)
    _p = field_validator("new")(strong)
