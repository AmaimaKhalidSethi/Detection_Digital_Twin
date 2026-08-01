from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, ForeignKey, JSON, Text, create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=_uuid)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), default="analyst")
    created_at = Column(DateTime, default=_now)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id = Column(String, primary_key=True, default=_uuid)
    title = Column(String(255), nullable=False)
    status = Column(String(32), default="draft")  # draft | active | deprecated
    created_at = Column(DateTime, default=_now)
    versions = relationship("RuleVersion", back_populates="rule", cascade="all, delete-orphan")

    @property
    def latest_version(self):
        if not self.versions:
            return None
        return max(self.versions, key=lambda v: v.version_number)


class RuleVersion(Base):
    __tablename__ = "rule_versions"
    id = Column(String, primary_key=True, default=_uuid)
    rule_id = Column(String, ForeignKey("detection_rules.id"), nullable=False)
    version_number = Column(Integer, nullable=False)
    yaml_content = Column(Text, nullable=False)
    mitre_techniques = Column(JSON, default=list)
    created_at = Column(DateTime, default=_now)
    rule = relationship("DetectionRule", back_populates="versions")


class SimulationRun(Base):
    __tablename__ = "simulation_runs"
    id = Column(String, primary_key=True, default=_uuid)
    technique_id = Column(String(32), nullable=False)
    status = Column(String(32), default="completed")
    started_at = Column(DateTime, default=_now)
    finished_at = Column(DateTime, default=_now)


class GeneratedLog(Base):
    __tablename__ = "generated_logs"
    id = Column(String, primary_key=True, default=_uuid)
    simulation_run_id = Column(String, ForeignKey("simulation_runs.id"), nullable=False)
    source_type = Column(String(32))
    normalized_event = Column(JSON)
    captured_at = Column(DateTime, default=_now)


class DetectionResult(Base):
    __tablename__ = "detection_results"
    id = Column(String, primary_key=True, default=_uuid)
    rule_version_id = Column(String, ForeignKey("rule_versions.id"), nullable=False)
    simulation_run_id = Column(String, ForeignKey("simulation_runs.id"), nullable=False)
    matched = Column(Boolean, default=False)
    matched_event_id = Column(String, nullable=True)
    evaluated_at = Column(DateTime, default=_now)


class DriftRecord(Base):
    __tablename__ = "drift_report"
    id = Column(String, primary_key=True, default=_uuid)
    rule_version_id = Column(String, ForeignKey("rule_versions.id"), nullable=False)
    previous_result = Column(Boolean, nullable=True)
    current_result = Column(Boolean, nullable=False)
    detected_at = Column(DateTime, default=_now)


def make_engine(db_url: str = "sqlite:///./ddt.db"):
    connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
    return create_engine(db_url, connect_args=connect_args)


def make_session_factory(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db(engine):
    Base.metadata.create_all(bind=engine)
