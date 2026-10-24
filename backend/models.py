from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True); name = Column(String(100)); email = Column(String(254), unique=True, index=True)
    password_hash = Column(String(200)); created_at = Column(DateTime, default=datetime.utcnow)
    projects = relationship("Project", back_populates="user")
class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True); user_id = Column(ForeignKey("users.id")); name = Column(String(100)); description = Column(String(500), default="")
    user = relationship("User", back_populates="projects"); scans = relationship("Scan", back_populates="project", order_by="Scan.id.desc()", cascade="all, delete-orphan")
class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True); project_id = Column(ForeignKey("projects.id")); file_name = Column(String(100))
    file_content = Column(Text)  # stored once; reused by Rescan
    status = Column(String(12), default="QUEUED"); stage = Column(Integer, default=0); note = Column(String(300))
    analysis = Column(Text); recs = Column(Text)  # risk_analysis + recommendations stored as JSON per scan
    created_at = Column(DateTime, default=datetime.utcnow)
    project = relationship("Project", back_populates="scans")
    dependencies = relationship("Dependency", cascade="all, delete-orphan"); vulnerabilities = relationship("Vulnerability", cascade="all, delete-orphan")
class Dependency(Base):
    __tablename__ = "dependencies"
    id = Column(Integer, primary_key=True); scan_id = Column(ForeignKey("scans.id"), index=True)
    name = Column(String(200)); version = Column(String(50)); constraint = Column(String(60)); pinned = Column(Boolean); ecosystem = Column(String(20)); dep_type = Column(String(12)); checked = Column(Boolean)  # True once OSV was queried for this dependency (NULL on scans made before this column existed)
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True); scan_id = Column(ForeignKey("scans.id"), index=True); dependency_id = Column(ForeignKey("dependencies.id"))
    package = Column(String(200)); version = Column(String(50)); vuln_id = Column(String(80)); summary = Column(Text); severity = Column(String(10))
    cvss = Column(String(200)); fixed = Column(String(50)); refs = Column(Text); published = Column(String(40)); modified = Column(String(40)); aliases = Column(Text); affected = Column(Text)
