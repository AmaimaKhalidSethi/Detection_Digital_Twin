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
    role = Column(String(32), default="analyst", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=_now)


class Environment(Base):
    __tablename__ = "environments"
    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(32), default="active")
    created_at = Column(DateTime, default=_now)
    last_sync_at = Column(DateTime, nullable=True)

    endpoints = relationship("Endpoint", back_populates="environment", cascade="all, delete-orphan")
    detection_platforms = relationship("DetectionPlatform", back_populates="environment", cascade="all, delete-orphan")
    snapshots = relationship("EnvironmentSnapshot", back_populates="environment", cascade="all, delete-orphan")
    validation_runs = relationship("ValidationRun", back_populates="environment", cascade="all, delete-orphan")
    detection_gaps = relationship("DetectionGap", back_populates="environment", cascade="all, delete-orphan")
    wazuh_rules = relationship("WazuhRule", back_populates="environment", cascade="all, delete-orphan")


class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(String, primary_key=True, default=_uuid)
    environment_id = Column(String, ForeignKey("environments.id"), nullable=False)
    hostname = Column(String(255), nullable=False)
    operating_system = Column(String(64), nullable=True)
    agent_id = Column(String(64), nullable=True)
    agent_status = Column(String(32), nullable=True)
    agent_version = Column(String(64), nullable=True)
    last_seen = Column(DateTime, nullable=True)
    metadata_json = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=_now)

    environment = relationship("Environment", back_populates="endpoints")
    telemetry_sources = relationship("TelemetrySource", back_populates="endpoint", cascade="all, delete-orphan")
    validation_runs = relationship("ValidationRun", back_populates="endpoint", cascade="all, delete-orphan")


class TelemetrySource(Base):
    __tablename__ = "telemetry_sources"
    id = Column(String, primary_key=True, default=_uuid)
    endpoint_id = Column(String, ForeignKey("endpoints.id"), nullable=False)
    source_type = Column(String(64), nullable=False)
    status = Column(String(32), default="active")
    version = Column(String(64), nullable=True)
    metadata_json = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=_now)

    endpoint = relationship("Endpoint", back_populates="telemetry_sources")


class DetectionPlatform(Base):
    __tablename__ = "detection_platforms"
    id = Column(String, primary_key=True, default=_uuid)
    environment_id = Column(String, ForeignKey("environments.id"), nullable=False)
    platform_type = Column(String(64), nullable=False)
    version = Column(String(64), nullable=True)
    manager_url = Column(String(512), nullable=True)
    status = Column(String(32), default="active")
    last_sync_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_now)

    environment = relationship("Environment", back_populates="detection_platforms")


class EnvironmentSnapshot(Base):
    __tablename__ = "environment_snapshots"
    id = Column(String, primary_key=True, default=_uuid)
    environment_id = Column(String, ForeignKey("environments.id"), nullable=False)
    snapshot_timestamp = Column(DateTime, default=_now, nullable=False)
    metadata_json = Column("metadata", JSON, default=dict)

    environment = relationship("Environment", back_populates="snapshots")


class ValidationRun(Base):
    __tablename__ = "validation_runs"
    id = Column(String, primary_key=True, default=_uuid)
    environment_id = Column(String, ForeignKey("environments.id"), nullable=False)
    endpoint_id = Column(String, ForeignKey("endpoints.id"), nullable=True)
    telemetry_artifact_id = Column(String, ForeignKey("telemetry_artifacts.id"), nullable=True)
    rule_version_id = Column(String, ForeignKey("rule_versions.id"), nullable=True)
    technique_id = Column(String(32), nullable=True)
    simulation_id = Column(String(64), nullable=True)
    expected_detection = Column(String(32), nullable=True)
    observed_detection = Column(String(32), nullable=True)
    twin_observed_detection = Column(String(32), nullable=True)
    twin_evidence_json = Column("twin_evidence", JSON, default=dict)
    status = Column(String(32), default="PREDICTED")
    final_classification = Column(String(32), nullable=True)
    started_at = Column(DateTime, default=_now)
    completed_at = Column(DateTime, nullable=True)
    evidence_json = Column("evidence", JSON, default=dict)

    environment = relationship("Environment", back_populates="validation_runs")
    endpoint = relationship("Endpoint", back_populates="validation_runs")
    telemetry_artifact = relationship("TelemetryArtifact", back_populates="validation_runs")
    rule_version = relationship("RuleVersion")


class TelemetryArtifact(Base):
    """Immutable provenance record for generated or imported telemetry."""
    __tablename__ = "telemetry_artifacts"

    id = Column(String, primary_key=True, default=_uuid)
    source_type = Column(String(32), nullable=False)
    schema_version = Column(String(64), nullable=True)
    raw_telemetry = Column(Text, nullable=True)
    normalized_event = Column(JSON, nullable=False)
    content_hash = Column(String(64), nullable=False, index=True)
    simulation_run_id = Column(String, ForeignKey("simulation_runs.id"), nullable=True)
    created_at = Column(DateTime, default=_now, nullable=False)

    validation_runs = relationship("ValidationRun", back_populates="telemetry_artifact")


class DetectionGap(Base):
    __tablename__ = "detection_gaps"
    id = Column(String, primary_key=True, default=_uuid)
    environment_id = Column(String, ForeignKey("environments.id"), nullable=False)
    technique_id = Column(String(32), nullable=True)
    validation_run_id = Column(String, ForeignKey("validation_runs.id"), nullable=True)
    severity = Column(String(32), default="medium")
    reason = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    status = Column(String(32), default="open")
    created_at = Column(DateTime, default=_now)
    resolved_at = Column(DateTime, nullable=True)

    environment = relationship("Environment", back_populates="detection_gaps")


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
    source = Column(String(32), default="manual", nullable=False)
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


class WazuhRule(Base):
    __tablename__ = "wazuh_rules"

    id = Column(String, primary_key=True, default=_uuid)
    environment_id = Column(String, ForeignKey("environments.id"), nullable=False)
    rule_id = Column(String(64), nullable=False)
    description = Column(Text, nullable=True)
    level = Column(String(32), nullable=True)
    status = Column(String(32), nullable=True)
    groups = Column(JSON, default=list)
    decoder = Column(String(128), nullable=True)
    source = Column(String(128), nullable=True)
    metadata_json = Column("metadata", JSON, default=dict)
    fingerprint = Column(String(64), nullable=True)
    last_synced_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_now)

    environment = relationship("Environment", back_populates="wazuh_rules")
    technique_mappings = relationship(
        "WazuhRuleTechnique",
        back_populates="wazuh_rule",
        cascade="all, delete-orphan",
    )


class WazuhRuleTechnique(Base):
    __tablename__ = "wazuh_rule_techniques"
    __table_args__ = (
        Index("ix_wazuh_rule_techniques_rule_id", "wazuh_rule_id"),
        Index("ix_wazuh_rule_techniques_technique_id", "technique_id"),
    )

    wazuh_rule_id = Column(String, ForeignKey("wazuh_rules.id"), primary_key=True)
    technique_id = Column(String(32), primary_key=True)
    created_at = Column(DateTime, default=_now, nullable=False)

    wazuh_rule = relationship("WazuhRule", back_populates="technique_mappings")


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


class ProductionDriftSnapshot(Base):
    __tablename__ = "production_drift_snapshots"

    id = Column(String, primary_key=True, default=_uuid)
    wazuh_reachable = Column(Boolean, nullable=False)
    twin_verified_count = Column(Integer, nullable=True)
    production_active_count = Column(Integer, nullable=True)
    covered_both = Column(JSON, default=list)
    twin_only = Column(JSON, default=list)
    production_only = Column(JSON, default=list)
    created_at = Column(DateTime, default=_now, nullable=False)


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
    telemetry_artifact_id = Column(String, ForeignKey("telemetry_artifacts.id"), nullable=True)
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
        if "source" not in columns:
            connection.execute(text("ALTER TABLE rule_versions ADD COLUMN source VARCHAR(32) DEFAULT 'manual'"))
    # Authentication was introduced after the initial users table.  Keep
    # existing local SQLite deployments compatible without a database rewrite.
    user_columns = {column["name"] for column in inspect(engine).get_columns("users")}
    with engine.begin() as connection:
        if "is_active" not in user_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1 NOT NULL"))
    validation_columns = {column["name"] for column in inspect(engine).get_columns("validation_runs")}
    generated_log_columns = {column["name"] for column in inspect(engine).get_columns("generated_logs")}
    wazuh_rule_columns = {column["name"] for column in inspect(engine).get_columns("wazuh_rules")}
    with engine.begin() as connection:
        if "telemetry_artifact_id" not in validation_columns:
            connection.execute(text("ALTER TABLE validation_runs ADD COLUMN telemetry_artifact_id VARCHAR"))
        if "rule_version_id" not in validation_columns:
            connection.execute(text("ALTER TABLE validation_runs ADD COLUMN rule_version_id VARCHAR"))
        if "twin_observed_detection" not in validation_columns:
            connection.execute(text("ALTER TABLE validation_runs ADD COLUMN twin_observed_detection VARCHAR(32)"))
        if "twin_evidence" not in validation_columns:
            connection.execute(text("ALTER TABLE validation_runs ADD COLUMN twin_evidence JSON"))
        if "final_classification" not in validation_columns:
            connection.execute(text("ALTER TABLE validation_runs ADD COLUMN final_classification VARCHAR(32)"))
        if "telemetry_artifact_id" not in generated_log_columns:
            connection.execute(text("ALTER TABLE generated_logs ADD COLUMN telemetry_artifact_id VARCHAR"))
        if "fingerprint" not in wazuh_rule_columns:
            connection.execute(text("ALTER TABLE wazuh_rules ADD COLUMN fingerprint VARCHAR(64)"))
