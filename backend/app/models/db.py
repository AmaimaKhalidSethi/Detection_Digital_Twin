from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, Enum, Float, ForeignKey, Index, JSON,
    Text, create_engine, inspect, text,
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
    author = Column(String(255), nullable=True)
    license = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=_now)
    rule = relationship("DetectionRule", back_populates="versions")
    technique_mappings = relationship(
        "RuleTechniqueMap", back_populates="rule_version", cascade="all, delete-orphan"
    )


class RuleTechniqueMap(Base):
    """Technique evidence recorded independently for each rule version.

    The source is part of the primary key so that a technique can have both a
    declared tag and separately-confirmed brute-force evidence.
    """

    __tablename__ = "rule_technique_map"
    __table_args__ = (
        Index("ix_rule_technique_map_rule_version_id", "rule_version_id"),
        Index("ix_rule_technique_map_technique_id", "technique_id"),
    )

    rule_version_id = Column(String, ForeignKey("rule_versions.id"), primary_key=True)
    technique_id = Column(String(32), primary_key=True)
    source = Column(
        Enum(
            "declared_tag",
            "brute_force_confirmed",
            "ai_suggested",
            name="rule_technique_source",
            native_enum=False,
            create_constraint=True,
            validate_strings=True,
        ),
        primary_key=True,
    )
    confirmed = Column(Boolean, nullable=False, default=False)
    confidence = Column(Float, nullable=True)
    created_at = Column(DateTime, default=_now, nullable=False)

    rule_version = relationship("RuleVersion", back_populates="technique_mappings")


class Job(Base):
    __tablename__ = "jobs"

    id = Column(String, primary_key=True, default=_uuid)
    job_type = Column(String(64), nullable=False)
    status = Column(
        Enum(
            "queued",
            "running",
            "done",
            "failed",
            name="job_status",
            native_enum=False,
            create_constraint=True,
            validate_strings=True,
        ),
        nullable=False,
        default="queued",
    )
    progress_current = Column(Integer, nullable=False, default=0)
    progress_total = Column(Integer, nullable=False, default=0)
    result_summary = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=_now, nullable=False)
    finished_at = Column(DateTime, nullable=True)


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
    __table_args__ = (
        Index("ix_detection_results_rule_version_id_simulation_run_id", "rule_version_id", "simulation_run_id"),
    )
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


def make_engine(db_url: str | None = None):
    """Create an engine using an explicit URL or the environment override.

    ``DDT_DATABASE_URL`` lets tests and tooling select an isolated database
    without changing the application default of ``sqlite:///./ddt.db``.
    """
    db_url = db_url or os.getenv("DDT_DATABASE_URL", "sqlite:///./ddt.db")
    connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
    return create_engine(db_url, connect_args=connect_args)


def make_session_factory(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db(engine):
    Base.metadata.create_all(bind=engine)
    # Existing deployments predate rule attribution metadata. ``create_all``
    # does not add columns to an already-created table, so apply this small,
    # idempotent compatibility migration before the ORM loads RuleVersion rows.
    columns = {column["name"] for column in inspect(engine).get_columns("rule_versions")}
    with engine.begin() as connection:
        if "author" not in columns:
            connection.execute(text("ALTER TABLE rule_versions ADD COLUMN author VARCHAR(255)"))
        if "license" not in columns:
            connection.execute(text("ALTER TABLE rule_versions ADD COLUMN license VARCHAR(64)"))
