from __future__ import annotations

import io
import hashlib
import json
import re
from datetime import datetime, timezone

from fastapi import BackgroundTasks, FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from app.models.db import (
    make_engine, make_session_factory, init_db,
    DetectionRule, RuleVersion, RuleTechniqueMap, WazuhRule, WazuhRuleTechnique,
    SimulationRun, GeneratedLog,
    DetectionResult, DriftRecord, Job, ProductionDriftSnapshot,
    Environment, Endpoint, TelemetrySource, DetectionPlatform, EnvironmentSnapshot,
    ValidationRun, DetectionGap, TelemetryArtifact, User,
)
from app.core.auth import (
    CSRF_COOKIE, SESSION_COOKIE, auth_required, cookie_secure, create_session_token,
    new_csrf_token, resolve_current_user, verify_csrf, verify_password,
)
from app.wazuh.client import WazuhClient
from app.detection_engine.rule_manager import validate_rule_yaml
from app.telemetry.parsers.sysmon_parser import parse_sysmon_text_block
from app.telemetry.parsers.auditd_parser import parse_auditd_batch
from app.detection_engine.evaluator import (
    evaluate_rule_version_against_events,
    evaluate_rule_versions_against_events,
)
from app.detection_engine.analysis import build_coverage_report, build_drift_report
from app.ai.rule_search import rebuild_rule_search_index, search_rules, _extract_yaml_scalar
from app.ai.technique_suggester import confirm_ai_suggestions, suggest_rule_techniques
from app.ai.alert_explainer import explain_match
from app.technique_maps import upsert_rule_technique_map
from app.telemetry.generators.synthetic_log_generator import (
    available_simulation_techniques,
    run_simulation,
    simulation_coverage_gaps,
)
from app.mitre.attack_data_loader import all_techniques

engine = make_engine()
SessionLocal = make_session_factory(engine)
init_db(engine)

app = FastAPI(title="Detection Digital Twin API", version="0.1.0")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Reusable authenticated-user dependency for routes that need user data."""
    user = getattr(request.state, "current_user", None)
    return user if user is not None else resolve_current_user(request, db)


@app.middleware("http")
async def require_authentication(request: Request, call_next):
    """Apply the backend security boundary to every application API route.

    A middleware guard keeps future endpoints protected by default.  Health and
    authentication endpoints are intentionally public; all other paths require
    a valid session and cookie-authenticated mutations also need a CSRF token.
    """
    public_paths = {"/health", "/auth/login", "/openapi.json", "/docs", "/redoc"}
    if not auth_required() or request.url.path in public_paths:
        return await call_next(request)
    db = SessionLocal()
    try:
        try:
            request.state.current_user = resolve_current_user(request, db)
            verify_csrf(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    finally:
        db.close()
    return await call_next(request)


# Register CORS after the guard so it remains the outer middleware and browser
# clients receive CORS headers on authentication failures as well.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-CSRF-Token"],
)


# ---------------------------------------------------------------- schemas --

class RuleUploadRequest(BaseModel):
    yaml_content: str


class SimulateRequest(BaseModel):
    technique_id: str


class EvaluateRequest(BaseModel):
    simulation_run_id: str


class EnvironmentCreateRequest(BaseModel):
    name: str
    description: str | None = None
    status: str = "active"


class EndpointCreateRequest(BaseModel):
    hostname: str
    operating_system: str | None = None
    agent_id: str | None = None
    agent_status: str | None = None
    last_seen: str | None = None
    metadata: dict | None = None


class ValidationRunCreateRequest(BaseModel):
    environment_id: str
    endpoint_id: str | None = None
    technique_id: str | None = None
    simulation_id: str | None = None
    expected_detection: str | None = None
    telemetry: str | None = None
    observed_detection: str | None = None
    status: str | None = None
    evidence: dict | None = None
    telemetry_artifact_id: str | None = None
    rule_version_id: str | None = None


class TelemetryIngestRequest(BaseModel):
    source_type: str
    raw_telemetry: str
    schema_version: str | None = None
    technique_id: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


def _user_payload(user: User) -> dict:
    return {"id": user.id, "username": user.username, "role": user.role, "created_at": user.created_at.isoformat()}


# ------------------------------------------------------------- Authentication

@app.post("/auth/login")
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    username = payload.username.strip().lower()
    user = db.query(User).filter(User.username == username).first() if username else None
    # A single generic response prevents account enumeration.  Do a hash check
    # only for a real user; bcrypt's normal verification still protects hashes.
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    csrf_token = new_csrf_token()
    max_age = 60 * 60
    response.set_cookie(
        key=SESSION_COOKIE, value=create_session_token(user), max_age=max_age,
        httponly=True, secure=cookie_secure(), samesite="lax", path="/",
    )
    response.set_cookie(
        key=CSRF_COOKIE, value=csrf_token, max_age=max_age,
        httponly=False, secure=cookie_secure(), samesite="lax", path="/",
    )
    return {"user": _user_payload(user), "csrf_token": csrf_token}


@app.get("/auth/me")
def me(current_user: User = Depends(get_current_user)):
    return {"user": _user_payload(current_user)}


@app.post("/auth/logout")
def logout(response: Response, current_user: User = Depends(get_current_user)):
    # The JWT is held only in the HttpOnly cookie, so deleting it ends the
    # browser session without leaving a reusable token in frontend storage.
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"status": "logged_out"}


def _normalize_detection_value(value: str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "DETECT" if value else "NO_DETECT"
    if isinstance(value, str):
        normalized = value.strip().upper()
        if normalized in {"DETECT", "MATCH", "YES", "TRUE", "FOUND", "DETECTED"}:
            return "DETECT"
        if normalized in {"NO_DETECT", "NO", "FALSE", "NONE", "NOT_FOUND", "NOT_DETECTED"}:
            return "NO_DETECT"
    return None


def _artifact_hash(raw_telemetry: str | None, normalized_event: dict) -> str:
    """Stable evidence fingerprint independent of database identifiers."""
    material = raw_telemetry if raw_telemetry is not None else json.dumps(normalized_event, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _classify_validation(expected: str | None, twin: str | None, wazuh: str | None, unavailable: bool) -> str:
    if expected not in {"DETECT", "NO_DETECT"} or unavailable:
        return "INCONCLUSIVE"
    observed = [value for value in (twin, wazuh) if value in {"DETECT", "NO_DETECT"}]
    if not observed:
        return "INCONCLUSIVE"
    if expected == "DETECT" and "NO_DETECT" in observed:
        return "DETECTION_GAP"
    if expected == "NO_DETECT" and "DETECT" in observed:
        return "FALSE_POSITIVE"
    return "PASS"


def _parse_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except Exception:
            return None
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except Exception:
                continue
    return None


def _compact_str(value):
    if value is None:
        return None
    return str(value).strip() or None


def _extract_agent_id(agent: dict) -> str | None:
    return _compact_str(agent.get("id") or agent.get("agent_id") or agent.get("agentId") or agent.get("name") or agent.get("hostname"))


def _extract_agent_hostname(agent: dict) -> str | None:
    return _compact_str(agent.get("name") or agent.get("hostname") or agent.get("agent_name") or agent.get("agentName"))


def _extract_agent_version(agent: dict) -> str | None:
    return _compact_str(agent.get("version") or agent.get("agent_version") or agent.get("agentVersion") or agent.get("os_version") or agent.get("osVersion"))


def _extract_agent_os(agent: dict) -> str | None:
    os_value = agent.get("os") or agent.get("os_name") or agent.get("osName")
    if isinstance(os_value, dict):
        name = os_value.get("name") or os_value.get("platform")
        version = os_value.get("version")
        if name and version:
            return f"{name} {version}"
        return _compact_str(name) or _compact_str(version)
    return _compact_str(os_value)


def _extract_agent_last_seen(agent: dict) -> datetime | None:
    return _parse_datetime(agent.get("last_keepalive") or agent.get("lastKeepalive") or agent.get("last_seen") or agent.get("lastSeen") or agent.get("last_keepalive_time") or agent.get("lastKeepAlive"))


def _extract_rule_id(rule: dict) -> str | None:
    return _compact_str(rule.get("rule_id") or rule.get("id") or rule.get("ruleId") or rule.get("rule"))


def _extract_rule_groups(rule: dict) -> list[str]:
    groups = rule.get("groups") or rule.get("group")
    if isinstance(groups, list):
        return [str(item) for item in groups if item is not None]
    if isinstance(groups, str):
        return [groups]
    return []


def _extract_rule_techniques(rule: dict) -> list[str]:
    mitre = rule.get("mitre") or rule.get("attack") or rule.get("techniques")
    if isinstance(mitre, list):
        return [str(item).strip().upper() for item in mitre if isinstance(item, str) and item.strip()]
    return []


def _evaluate_validation_result(expected_detection: str | None, wazuh_result: dict | None) -> tuple[str | None, str, str | None, dict]:
    if wazuh_result is None:
        return None, "UNAVAILABLE", None, {"reason": "wazuh_unavailable"}

    if not isinstance(wazuh_result, dict):
        return None, "ERROR", None, {"reason": "invalid_wazuh_response", "response_type": type(wazuh_result).__name__}

    matched_value = wazuh_result.get("matched")
    if isinstance(matched_value, bool):
        observed_detection = "DETECT" if matched_value else "NO_DETECT"
    elif isinstance(matched_value, str):
        normalized_match = _normalize_detection_value(matched_value)
        if normalized_match is None:
            return None, "ERROR", None, {"reason": "invalid_wazuh_match_value", "value": matched_value}
        observed_detection = normalized_match
    else:
        return None, "ERROR", None, {"reason": "missing_wazuh_match_value"}

    matched_rule_id = wazuh_result.get("rule_id") if isinstance(wazuh_result.get("rule_id"), str) else None
    evidence_payload = {
        "message": wazuh_result.get("message") if isinstance(wazuh_result.get("message"), str) else None,
        "matched_rule_id": matched_rule_id,
        "raw_result": {k: v for k, v in wazuh_result.items() if k not in {"matched", "rule_id"}},
    }

    expected_value = _normalize_detection_value(expected_detection)
    if expected_value is None:
        return observed_detection, "ERROR", matched_rule_id, evidence_payload

    if expected_value == observed_detection:
        return observed_detection, "VALIDATED", matched_rule_id, evidence_payload

    return observed_detection, "DETECTION_GAP", matched_rule_id, evidence_payload


def _active_rule_versions(db: Session) -> list[RuleVersion]:
    versions = []
    for rule in db.query(DetectionRule).filter(DetectionRule.status == "active").all():
        if rule.latest_version:
            versions.append(rule.latest_version)
    return sorted(versions, key=lambda v: v.version_number)


def _mapping_source_priority(source: str) -> int:
    return {"brute_force_confirmed": 3, "declared_tag": 2, "ai_suggested": 1}.get(source, 0)


def _candidate_techniques_for_rule_version(rule_version: RuleVersion, technique_meta: dict | None = None) -> list[str]:
    technique_meta = technique_meta or all_techniques()
    declared_mapped_techniques = sorted(
        {
            mapping.technique_id
            for mapping in rule_version.technique_mappings
            if getattr(mapping, "source", "declared_tag") == "declared_tag"
        }
    )
    techniques_to_test = set(declared_mapped_techniques)
    tactic_names = {
        technique_meta[technique_id]["tactic"]
        for technique_id in declared_mapped_techniques
        if technique_id in technique_meta
    }
    for tactic_name in tactic_names:
        for technique_id in sorted(technique_meta):
            if technique_id in declared_mapped_techniques:
                continue
            if technique_meta[technique_id].get("tactic") != tactic_name:
                continue
            techniques_to_test.add(technique_id)
    return sorted(techniques_to_test)


def _verified_techniques_for_rule_version(db: Session, rule_version_id: str) -> set[str]:
    verified = {
        row.technique_id
        for row in (
            db.query(RuleTechniqueMap)
            .filter(
                RuleTechniqueMap.rule_version_id == rule_version_id,
                RuleTechniqueMap.source == "brute_force_confirmed",
                RuleTechniqueMap.confirmed.is_(True),
            )
            .all()
        )
    }
    matched_techniques = {
        row[0]
        for row in (
            db.query(SimulationRun.technique_id)
            .join(DetectionResult, DetectionResult.simulation_run_id == SimulationRun.id)
            .filter(
                DetectionResult.rule_version_id == rule_version_id,
                DetectionResult.matched.is_(True),
            )
            .distinct()
            .all()
        )
    }
    verified.update(matched_techniques)
    return verified


def _run_full_matrix_evaluation(job_id: str) -> None:
    db = SessionLocal()
    try:
        job = db.get(Job, job_id)
        if not job:
            return

        job.status = "running"
        db.commit()

        active_versions = _active_rule_versions(db)
        simulatable_techniques = sorted(available_simulation_techniques())
        job.progress_total = len(active_versions) * len(simulatable_techniques)
        db.commit()

        for rule_version in active_versions:
            for technique_id in simulatable_techniques:
                events = run_simulation(technique_id, f"{job_id}:{rule_version.id}:{technique_id}")
                result = evaluate_rule_version_against_events(rule_version.id, rule_version.yaml_content, events)
                if result["matched"]:
                    upsert_rule_technique_map(
                        db,
                        rule_version.id,
                        technique_id,
                        "brute_force_confirmed",
                        confirmed=True,
                    )
                job.progress_current += 1
            db.commit()

        job.status = "done"
        job.result_summary = {
            "rules_evaluated": len(active_versions),
            "techniques_evaluated": job.progress_total,
        }
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as exc:  # pragma: no cover - best effort for background jobs
        job = db.get(Job, job_id)
        if job is not None:
            job.status = "failed"
            job.result_summary = {"error": str(exc)}
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


# ------------------------------------------------------- Environment / Twin (FR-11)

@app.get("/environments")
def list_environments(db: Session = Depends(get_db)):
    environments = db.query(Environment).order_by(Environment.created_at.asc()).all()
    return [
        {
            "id": environment.id,
            "name": environment.name,
            "description": environment.description,
            "status": environment.status,
            "created_at": environment.created_at.isoformat(),
            "last_sync_at": environment.last_sync_at.isoformat() if environment.last_sync_at else None,
        }
        for environment in environments
    ]


@app.post("/environments")
def create_environment(payload: EnvironmentCreateRequest, db: Session = Depends(get_db)):
    environment = Environment(name=payload.name, description=payload.description, status=payload.status)
    db.add(environment)
    db.flush()
    db.commit()
    return {
        "id": environment.id,
        "name": environment.name,
        "description": environment.description,
        "status": environment.status,
        "created_at": environment.created_at.isoformat(),
        "last_sync_at": environment.last_sync_at.isoformat() if environment.last_sync_at else None,
    }


@app.post("/environments/{environment_id}/endpoints")
def create_endpoint(environment_id: str, payload: EndpointCreateRequest, db: Session = Depends(get_db)):
    environment = db.get(Environment, environment_id)
    if not environment:
        raise HTTPException(status_code=404, detail="Environment not found")

    endpoint = Endpoint(
        environment_id=environment.id,
        hostname=payload.hostname,
        operating_system=payload.operating_system,
        agent_id=payload.agent_id,
        agent_status=payload.agent_status,
        metadata_json=payload.metadata or {},
    )
    if payload.last_seen:
        endpoint.last_seen = datetime.fromisoformat(payload.last_seen)

    db.add(endpoint)
    db.flush()
    db.commit()
    return {
        "id": endpoint.id,
        "environment_id": endpoint.environment_id,
        "hostname": endpoint.hostname,
        "operating_system": endpoint.operating_system,
        "agent_id": endpoint.agent_id,
        "agent_status": endpoint.agent_status,
        "last_seen": endpoint.last_seen.isoformat() if endpoint.last_seen else None,
    }


@app.get("/environments/{environment_id}/endpoints")
def list_endpoints(environment_id: str, db: Session = Depends(get_db)):
    environment = db.get(Environment, environment_id)
    if not environment:
        raise HTTPException(status_code=404, detail="Environment not found")
    return [
        {
            "id": endpoint.id,
            "environment_id": endpoint.environment_id,
            "hostname": endpoint.hostname,
            "operating_system": endpoint.operating_system,
            "agent_id": endpoint.agent_id,
            "agent_status": endpoint.agent_status,
            "last_seen": endpoint.last_seen.isoformat() if endpoint.last_seen else None,
            "metadata": endpoint.metadata_json,
        }
        for endpoint in environment.endpoints
    ]


@app.post("/environment/sync")
def sync_environment(db: Session = Depends(get_db)):
    environment = db.query(Environment).order_by(Environment.created_at.asc()).first()
    if environment is None:
        environment = Environment(name="Home Detection Lab", description="Default digital twin environment", status="active")
        db.add(environment)
        db.flush()

    client = WazuhClient()
    manager_info = client.get_manager_info()
    if manager_info is None:
        raise HTTPException(status_code=503, detail="Wazuh manager unavailable")

    agents = client.get_agents()
    wazuh_rules = client.get_rules()
    active_techniques = client.get_active_technique_ids()

    environment.last_sync_at = datetime.now(timezone.utc)

    platform = (
        db.query(DetectionPlatform)
        .filter(DetectionPlatform.environment_id == environment.id)
        .order_by(DetectionPlatform.created_at.desc())
        .first()
    )
    if platform is None:
        platform = DetectionPlatform(environment_id=environment.id, platform_type="wazuh", status="active")
        db.add(platform)
    platform.status = "connected"
    platform.version = None
    platform.manager_url = client.base_url
    platform.last_sync_at = datetime.now(timezone.utc)

    if isinstance(manager_info, dict):
        data = manager_info.get("data") if isinstance(manager_info.get("data"), dict) else manager_info
        if isinstance(data, dict):
            version_value = data.get("version") or data.get("manager_version") or data.get("data", {}).get("version")
            if version_value:
                platform.version = str(version_value)

    synced_agent_ids: set[str] = set()
    if isinstance(agents, list):
        existing_endpoints = {
            endpoint.agent_id: endpoint
            for endpoint in db.query(Endpoint)
            .filter(Endpoint.environment_id == environment.id)
            .filter(Endpoint.agent_id.isnot(None))
            .all()
            if endpoint.agent_id
        }
        for agent in agents:
            if not isinstance(agent, dict):
                continue
            agent_id = _extract_agent_id(agent)
            if not agent_id:
                continue
            hostname = _extract_agent_hostname(agent) or agent_id
            operating_system = _extract_agent_os(agent)
            agent_status = _compact_str(agent.get("status") or agent.get("state") or agent.get("connected"))
            agent_version = _extract_agent_version(agent)
            last_seen = _extract_agent_last_seen(agent)

            endpoint = existing_endpoints.get(agent_id)
            if endpoint is None:
                endpoint = Endpoint(
                    environment_id=environment.id,
                    hostname=hostname,
                    operating_system=operating_system,
                    agent_id=agent_id,
                    agent_status=agent_status,
                    agent_version=agent_version,
                    last_seen=last_seen,
                    metadata_json={"source": "sync", "wazuh_agent": True},
                )
                db.add(endpoint)
            else:
                endpoint.hostname = hostname
                endpoint.operating_system = operating_system or endpoint.operating_system
                endpoint.agent_status = agent_status or endpoint.agent_status
                endpoint.agent_version = agent_version or endpoint.agent_version
                endpoint.last_seen = last_seen or endpoint.last_seen
                endpoint.metadata_json = {**(endpoint.metadata_json or {}), "source": "sync", "wazuh_agent": True}
            synced_agent_ids.add(agent_id)

    synced_rules = 0
    if isinstance(wazuh_rules, list):
        existing_wazuh_rules = {
            rule.rule_id: rule
            for rule in db.query(WazuhRule)
            .filter(WazuhRule.environment_id == environment.id)
            .all()
        }
        for rule_data in wazuh_rules:
            if not isinstance(rule_data, dict):
                continue
            rule_id = _extract_rule_id(rule_data)
            if not rule_id:
                continue

            description = _compact_str(rule_data.get("description") or rule_data.get("title") or rule_data.get("rule_description"))
            level = _compact_str(rule_data.get("level") or rule_data.get("severity") or rule_data.get("priority"))
            status = _compact_str(rule_data.get("status") or rule_data.get("enabled") or rule_data.get("state"))
            if status is None and isinstance(rule_data.get("enabled"), bool):
                status = "enabled" if rule_data.get("enabled") else "disabled"
            groups = _extract_rule_groups(rule_data)
            decoder = _compact_str(rule_data.get("decoder") or rule_data.get("rule_decoder"))
            source = _compact_str(rule_data.get("source") or rule_data.get("source_name") or rule_data.get("origin"))
            techniques = [tid for tid in _extract_rule_techniques(rule_data) if re.fullmatch(r"T\d{4}(\.\d{3})?", tid)]

            wazuh_rule = existing_wazuh_rules.get(rule_id)
            if wazuh_rule is None:
                wazuh_rule = WazuhRule(
                    environment_id=environment.id,
                    rule_id=rule_id,
                    description=description,
                    level=level,
                    status=status,
                    groups=groups,
                    decoder=decoder,
                    source=source,
                    metadata_json={"source": "sync", "wazuh_rule": True},
                    last_synced_at=datetime.now(timezone.utc),
                )
                db.add(wazuh_rule)
                db.flush()
            else:
                wazuh_rule.description = description or wazuh_rule.description
                wazuh_rule.level = level or wazuh_rule.level
                wazuh_rule.status = status or wazuh_rule.status
                wazuh_rule.groups = groups or wazuh_rule.groups
                wazuh_rule.decoder = decoder or wazuh_rule.decoder
                wazuh_rule.source = source or wazuh_rule.source
                wazuh_rule.metadata_json = {**(wazuh_rule.metadata_json or {}), "source": "sync", "wazuh_rule": True}
                wazuh_rule.last_synced_at = datetime.now(timezone.utc)

            existing_technique_ids = {mapping.technique_id for mapping in wazuh_rule.technique_mappings}
            for technique_id in techniques:
                if technique_id not in existing_technique_ids:
                    db.add(WazuhRuleTechnique(wazuh_rule=wazuh_rule, technique_id=technique_id))
            for mapping in list(wazuh_rule.technique_mappings):
                if mapping.technique_id not in techniques:
                    db.delete(mapping)

            synced_rules += 1

    db.flush()

    synced_agent_count = len(synced_agent_ids)
    persisted_wazuh_rules = db.query(WazuhRule).filter(WazuhRule.environment_id == environment.id).all()
    rule_count = len(persisted_wazuh_rules)
    enabled_rule_count = sum(1 for rule in persisted_wazuh_rules if str(rule.status or "").lower() in {"enabled", "active"})
    disabled_rule_count = sum(1 for rule in persisted_wazuh_rules if str(rule.status or "").lower() in {"disabled", "inactive"})
    technique_ids = {mapping.technique_id for rule in persisted_wazuh_rules for mapping in rule.technique_mappings}
    technique_count = len(technique_ids)
    endpoints = [endpoint for endpoint in environment.endpoints if endpoint.metadata_json.get("wazuh_agent") is True]
    agent_count = len(endpoints)
    active_agent_count = sum(1 for endpoint in endpoints if str(endpoint.agent_status or "").lower() == "active")

    snapshot = EnvironmentSnapshot(environment_id=environment.id, metadata_json={
        "manager_reachable": True,
        "agent_count": agent_count,
        "active_agent_count": active_agent_count,
        "rule_count": rule_count,
        "enabled_rule_count": enabled_rule_count,
        "disabled_rule_count": disabled_rule_count,
        "technique_count": technique_count,
        "status": "ok",
    })
    db.add(snapshot)

    environment.last_sync_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "status": "ok",
        "environment": environment.name,
        "agents_synced": synced_agent_count,
        "rules_synced": synced_rules,
        "alerts_synced": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/environment/snapshots")
def list_environment_snapshots(db: Session = Depends(get_db)):
    snapshots = db.query(EnvironmentSnapshot).order_by(EnvironmentSnapshot.snapshot_timestamp.desc()).all()
    return [
        {
            "id": snapshot.id,
            "environment_name": snapshot.environment.name if snapshot.environment else None,
            "timestamp": snapshot.snapshot_timestamp.isoformat(),
            "metadata": snapshot.metadata_json,
        }
        for snapshot in snapshots
    ]


@app.post("/telemetry/ingest")
def ingest_telemetry(payload: TelemetryIngestRequest, db: Session = Depends(get_db)):
    """Persist bounded representative Sysmon/auditd telemetry for validation."""
    if len(payload.raw_telemetry.encode("utf-8")) > 200_000:
        raise HTTPException(status_code=422, detail="Telemetry exceeds 200000 byte limit")
    source_type = payload.source_type.strip().lower()
    if source_type == "sysmon":
        normalized_events = [parse_sysmon_text_block(payload.raw_telemetry)]
    elif source_type == "auditd":
        normalized_events = parse_auditd_batch(payload.raw_telemetry.splitlines())
    else:
        raise HTTPException(status_code=422, detail="source_type must be sysmon or auditd")
    if not normalized_events:
        raise HTTPException(status_code=422, detail="Telemetry could not be normalized")

    artifacts = []
    for event in normalized_events:
        normalized_event = event.to_dict()
        if payload.technique_id:
            normalized_event["technique_id"] = payload.technique_id
        artifact = TelemetryArtifact(
            source_type=source_type,
            schema_version=payload.schema_version or f"{source_type}/v1",
            raw_telemetry=payload.raw_telemetry,
            normalized_event=normalized_event,
            content_hash=_artifact_hash(payload.raw_telemetry, normalized_event),
        )
        db.add(artifact)
        db.flush()
        artifacts.append({"id": artifact.id, "content_hash": artifact.content_hash, "normalized_event": normalized_event})
    db.commit()
    return {"artifacts": artifacts}


@app.post("/validation-runs")
def create_validation_run(payload: ValidationRunCreateRequest, db: Session = Depends(get_db)):
    environment = db.get(Environment, payload.environment_id)
    if not environment:
        raise HTTPException(status_code=404, detail="Environment not found")

    endpoint = None
    if payload.endpoint_id:
        endpoint = db.get(Endpoint, payload.endpoint_id)
        if endpoint is None:
            raise HTTPException(status_code=404, detail="Endpoint not found")

    artifact = db.get(TelemetryArtifact, payload.telemetry_artifact_id) if payload.telemetry_artifact_id else None
    if payload.telemetry_artifact_id and artifact is None:
        raise HTTPException(status_code=404, detail="Telemetry artifact not found")
    rule_version = db.get(RuleVersion, payload.rule_version_id) if payload.rule_version_id else None
    if payload.rule_version_id and rule_version is None:
        raise HTTPException(status_code=404, detail="Rule version not found")

    manual_telemetry = payload.telemetry or ((payload.evidence or {}).get("telemetry") if payload.evidence else None) or ((payload.evidence or {}).get("log_input") if payload.evidence else None)
    if artifact is None:
        telemetry_input = manual_telemetry or ""
        normalized_event = {"raw_telemetry": telemetry_input}
        artifact = TelemetryArtifact(
            source_type="manual",
            schema_version="manual-logtext/v1",
            raw_telemetry=telemetry_input,
            normalized_event=normalized_event,
            content_hash=_artifact_hash(telemetry_input, normalized_event),
        )
        db.add(artifact)
        db.flush()
        wazuh_representation = "manual_log_text"
    else:
        # Wazuh receives the stored raw representation where available.  For
        # synthetic events this is normalized-event JSON, explicitly recorded
        # so the result is never presented as a native Wazuh event replay.
        telemetry_input = artifact.raw_telemetry or json.dumps(artifact.normalized_event, sort_keys=True)
        wazuh_representation = "artifact_raw_telemetry" if artifact.raw_telemetry else "normalized_event_json"
    expected_detection = _normalize_detection_value(payload.expected_detection)
    validation_source = "WAZUH_LOGTEST"

    twin_observed_detection = None
    twin_evidence: dict = {}
    twin_unavailable = False
    if rule_version is not None:
        twin_result = evaluate_rule_version_against_events(
            rule_version.id, rule_version.yaml_content, [artifact.normalized_event]
        )
        if twin_result["parse_error"]:
            twin_unavailable = True
            twin_evidence = {"parse_error": twin_result["parse_error"]}
        else:
            twin_observed_detection = "DETECT" if twin_result["matched"] else "NO_DETECT"
            twin_evidence = {
                "matched_event_index": twin_result["matched_event_index"],
                "failure_reasons": twin_result["failure_reasons"],
            }

    try:
        wazuh_client = WazuhClient()
        wazuh_result = wazuh_client.run_logtest(telemetry_input)
    except Exception as exc:  # pragma: no cover - exercised through mocked failures
        observed_detection = None
        status = "INCONCLUSIVE"
        matched_rule_id = None
        evaluation_evidence = {"reason": "wazuh_unavailable", "error": str(exc)}
    else:
        observed_detection, status, matched_rule_id, evaluation_evidence = _evaluate_validation_result(
            expected_detection,
            wazuh_result,
        )

    status = _classify_validation(expected_detection, twin_observed_detection, observed_detection, twin_unavailable or status in {"UNAVAILABLE", "ERROR", "INCONCLUSIVE"})
    evidence_payload = dict(payload.evidence or {})
    evidence_payload.update({
        "method": "wazuh_logtest",
        "validation_source": validation_source,
        "telemetry": telemetry_input,
        "telemetry_artifact_id": artifact.id,
        "telemetry_hash": artifact.content_hash,
        "wazuh_input_representation": wazuh_representation,
        "matched_rule_id": matched_rule_id,
        "wazuh_result": evaluation_evidence,
    })

    validation_run = ValidationRun(
        environment_id=environment.id,
        endpoint_id=endpoint.id if endpoint else None,
        telemetry_artifact_id=artifact.id,
        rule_version_id=rule_version.id if rule_version else None,
        technique_id=payload.technique_id,
        simulation_id=payload.simulation_id,
        expected_detection=expected_detection,
        observed_detection=observed_detection,
        twin_observed_detection=twin_observed_detection,
        twin_evidence_json=twin_evidence,
        status=status,
        evidence_json=evidence_payload,
    )
    db.add(validation_run)
    db.flush()

    if status in {"DETECTION_GAP", "FALSE_POSITIVE"}:
        gap = DetectionGap(
            environment_id=environment.id,
            technique_id=payload.technique_id,
            validation_run_id=validation_run.id,
            severity="medium",
            reason=(
                f"Expected {expected_detection or 'unknown'} but observed twin={twin_observed_detection or 'unavailable'}, wazuh={observed_detection or 'unavailable'}"
            ),
            recommendation="Review rule coverage and telemetry availability for the targeted technique.",
            status="open",
        )
        db.add(gap)

    db.commit()
    return {
        "id": validation_run.id,
        "environment_id": validation_run.environment_id,
        "endpoint_id": validation_run.endpoint_id,
        "telemetry_artifact_id": validation_run.telemetry_artifact_id,
        "telemetry_hash": artifact.content_hash,
        "rule_version_id": validation_run.rule_version_id,
        "technique_id": validation_run.technique_id,
        "simulation_id": validation_run.simulation_id,
        "expected_detection": validation_run.expected_detection,
        "observed_detection": validation_run.observed_detection,
        "twin_observed_detection": validation_run.twin_observed_detection,
        "twin_evidence": validation_run.twin_evidence_json,
        "status": validation_run.status,
        "validation_source": validation_source,
        "matched_rule_id": matched_rule_id,
        "evidence": validation_run.evidence_json,
        "started_at": validation_run.started_at.isoformat(),
    }


@app.get("/validation-runs")
def list_validation_runs(environment_id: str | None = None, db: Session = Depends(get_db)):
    query = db.query(ValidationRun)
    if environment_id:
        query = query.filter(ValidationRun.environment_id == environment_id)
    runs = query.order_by(ValidationRun.started_at.desc()).all()
    return [
        {
            "id": run.id,
            "environment_id": run.environment_id,
            "endpoint_id": run.endpoint_id,
            "telemetry_artifact_id": run.telemetry_artifact_id,
            "telemetry_hash": run.telemetry_artifact.content_hash if run.telemetry_artifact else None,
            "rule_version_id": run.rule_version_id,
            "technique_id": run.technique_id,
            "simulation_id": run.simulation_id,
            "expected_detection": run.expected_detection,
            "observed_detection": run.observed_detection,
            "twin_observed_detection": run.twin_observed_detection,
            "twin_evidence": run.twin_evidence_json,
            "status": run.status,
            "validation_source": run.evidence_json.get("validation_source") if isinstance(run.evidence_json, dict) else None,
            "matched_rule_id": run.evidence_json.get("matched_rule_id") if isinstance(run.evidence_json, dict) else None,
            "evidence": run.evidence_json,
            "started_at": run.started_at.isoformat(),
        }
        for run in runs
    ]


@app.get("/detection-gaps")
def list_detection_gaps(environment_id: str | None = None, db: Session = Depends(get_db)):
    query = db.query(DetectionGap)
    if environment_id:
        query = query.filter(DetectionGap.environment_id == environment_id)
    gaps = query.order_by(DetectionGap.created_at.desc()).all()
    return [
        {
            "id": gap.id,
            "environment_id": gap.environment_id,
            "technique_id": gap.technique_id,
            "validation_run_id": gap.validation_run_id,
            "severity": gap.severity,
            "reason": gap.reason,
            "recommendation": gap.recommendation,
            "status": gap.status,
            "created_at": gap.created_at.isoformat(),
        }
        for gap in gaps
    ]


# -------------------------------------------------------------- MITRE (FR-08)

@app.get("/mitre/techniques")
def list_techniques():
    return [{"technique_id": k, **v} for k, v in all_techniques().items()]


@app.get("/simulator/techniques")
def list_simulatable_techniques():
    return available_simulation_techniques()


@app.get("/simulator/coverage-gaps")
def list_simulation_coverage_gaps():
    return simulation_coverage_gaps()


# --------------------------------------------------------- Rules (FR-01..03)

@app.post("/rules/validate")
def validate_rule(payload: RuleUploadRequest):
    result = validate_rule_yaml(payload.yaml_content)
    return {
        "valid": result.valid,
        "errors": result.errors,
        "mitre_techniques": result.mitre_techniques or [],
        "title": getattr(result.rule, "title", None) if result.rule else None,
    }


@app.post("/rules")
def upload_rule(payload: RuleUploadRequest, db: Session = Depends(get_db)):
    result = validate_rule_yaml(payload.yaml_content)
    if not result.valid:
        raise HTTPException(status_code=422, detail={"errors": result.errors})

    rule = DetectionRule(title=result.rule.title, status="active")
    db.add(rule)
    db.flush()
    version = RuleVersion(
        rule_id=rule.id,
        version_number=1,
        yaml_content=payload.yaml_content,
        mitre_techniques=result.mitre_techniques or [],
        author=getattr(result.rule, "author", None),
        license=getattr(result.rule, "license", None),
        source="manual",
    )
    db.add(version)
    db.flush()
    for technique_id in dict.fromkeys(result.mitre_techniques or []):
        db.add(
            RuleTechniqueMap(
                rule_version_id=version.id,
                technique_id=technique_id,
                source="declared_tag",
                confirmed=True,
            )
        )
    db.commit()
    rebuild_rule_search_index(db)
    return {
        "rule_id": rule.id,
        "version_id": version.id,
        "title": rule.title,
        "mitre_techniques": result.mitre_techniques,
        "source": version.source,
    }


@app.put("/rules/{rule_id}")
def update_rule(rule_id: str, payload: RuleUploadRequest, db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    result = validate_rule_yaml(payload.yaml_content)
    if not result.valid:
        raise HTTPException(status_code=422, detail={"errors": result.errors})
    next_version_number = (rule.latest_version.version_number if rule.latest_version else 0) + 1
    version = RuleVersion(
        rule_id=rule.id,
        version_number=next_version_number,
        yaml_content=payload.yaml_content,
        mitre_techniques=result.mitre_techniques or [],
        author=getattr(result.rule, "author", None),
        license=getattr(result.rule, "license", None),
        source="manual",
    )
    db.add(version)
    db.flush()
    for technique_id in dict.fromkeys(result.mitre_techniques or []):
        db.add(
            RuleTechniqueMap(
                rule_version_id=version.id,
                technique_id=technique_id,
                source="declared_tag",
                confirmed=True,
            )
        )
    db.commit()
    rebuild_rule_search_index(db)
    return {
        "rule_id": rule.id,
        "version_id": version.id,
        "version_number": next_version_number,
        "source": version.source,
    }


@app.get("/rules")
def list_rules(db: Session = Depends(get_db), status: str | None = None):
    query = db.query(DetectionRule)
    if status is None:
        query = query.filter(DetectionRule.status != "archived")
    elif status.lower() == "archived":
        query = query.filter(DetectionRule.status == "archived")
    else:
        query = query.filter(DetectionRule.status == status)

    rules = query.all()
    out = []
    for r in rules:
        lv = r.latest_version
        title = r.title
        if lv and lv.yaml_content:
            title = _extract_yaml_scalar(lv.yaml_content, "title") or title
        out.append(
            {
                "rule_id": r.id,
                "title": title,
                "status": r.status,
                "version_number": lv.version_number if lv else None,
                "version_id": lv.id if lv else None,
                "author": lv.author if lv else None,
                "mitre_techniques": sorted({m.technique_id for m in lv.technique_mappings}) if lv else [],
                "source": lv.source if lv else None,
            }
        )
    return out


@app.get("/rules/search")
def search_rule_index(q: str = "", tactic: str | None = None, platform: str | None = None, status: str | None = None, db: Session = Depends(get_db)):
    return search_rules(db, q, tactic=tactic, platform=platform, status=status)


@app.get("/rules/{rule_id}")
def get_rule(rule_id: str, db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {
        "rule_id": rule.id,
        "title": rule.title,
        "status": rule.status,
        "versions": [
            {"version_id": v.id, "version_number": v.version_number, "yaml_content": v.yaml_content,
              "mitre_techniques": sorted({m.technique_id for m in v.technique_mappings}),
              "source": v.source,
              "author": v.author,
             "created_at": v.created_at.isoformat()}
            for v in sorted(rule.versions, key=lambda v: v.version_number)
        ],
    }


# Archive a rule (soft delete - preserves version history for drift reporting)
@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: str, db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.status = "archived"
    db.commit()
    rebuild_rule_search_index(db)
    return {"deleted": rule_id}


# ---------------------------------------------------------- Simulation (FR-05)

@app.post("/simulations")
def run_simulation_endpoint(payload: SimulateRequest, db: Session = Depends(get_db)):
    if payload.technique_id not in available_simulation_techniques():
        raise HTTPException(status_code=400, detail=f"No simulation for technique {payload.technique_id}")

    run = SimulationRun(technique_id=payload.technique_id, status="running")
    db.add(run)
    db.flush()

    events = run_simulation(payload.technique_id, run.id)
    for e in events:
        normalized_event = e.to_dict()
        raw_telemetry = json.dumps(normalized_event, sort_keys=True)
        artifact = TelemetryArtifact(
            source_type=e.source_type,
            schema_version="normalized-event/v1",
            raw_telemetry=raw_telemetry,
            normalized_event=normalized_event,
            content_hash=_artifact_hash(raw_telemetry, normalized_event),
            simulation_run_id=run.id,
        )
        db.add(artifact)
        db.flush()
        db.add(GeneratedLog(
            simulation_run_id=run.id,
            source_type=e.source_type,
            normalized_event=normalized_event,
            telemetry_artifact_id=artifact.id,
        ))

    run.status = "completed"
    run.finished_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "simulation_run_id": run.id,
        "technique_id": run.technique_id,
        "event_count": len(events),
        "events": [e.to_dict() for e in events],
    }


@app.get("/simulations")
def list_simulations(db: Session = Depends(get_db)):
    runs = db.query(SimulationRun).order_by(SimulationRun.started_at.desc()).all()
    return [
        {"simulation_run_id": r.id, "technique_id": r.technique_id, "status": r.status,
         "started_at": r.started_at.isoformat()}
        for r in runs
    ]


# ------------------------------------------------------- Evaluation (FR-06/07)

@app.post("/jobs/full-matrix-evaluation")
def create_full_matrix_job(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    job = Job(job_type="full_matrix_evaluation", status="queued", progress_current=0, progress_total=0)
    db.add(job)
    db.flush()
    background_tasks.add_task(_run_full_matrix_evaluation, job.id)
    db.commit()
    return {"job_id": job.id, "status": job.status, "progress_current": job.progress_current, "progress_total": job.progress_total}


@app.get("/jobs/{job_id}")
def get_job(job_id: str, db: Session = Depends(get_db)):
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "job_id": job.id,
        "job_type": job.job_type,
        "status": job.status,
        "progress_current": job.progress_current,
        "progress_total": job.progress_total,
        "result_summary": job.result_summary,
        "created_at": job.created_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }


@app.post("/rules/{rule_id}/suggest-techniques")
def suggest_rule_techniques_endpoint(rule_id: str, db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule_version = rule.latest_version
    if not rule_version:
        raise HTTPException(status_code=404, detail="Rule version not found")

    suggestions = suggest_rule_techniques(rule_version, db, rule_version.yaml_content)
    confirm_ai_suggestions(rule_version, db, suggestions)
    db.commit()
    return {
        "rule_version_id": rule_version.id,
        "suggestions": suggestions,
        "source": "ai_suggested",
    }


@app.post("/rules/{rule_id}/test")
def test_rule(rule_id: str, db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule_version = rule.latest_version
    if not rule_version:
        raise HTTPException(status_code=404, detail="Rule version not found")

    technique_meta = all_techniques()
    mapped_techniques = sorted(
        {
            mapping.technique_id
            for mapping in rule_version.technique_mappings
            if getattr(mapping, "source", "declared_tag") == "declared_tag"
        }
    )
    techniques_to_test = _candidate_techniques_for_rule_version(rule_version, technique_meta)

    results = []
    for technique_id in sorted(techniques_to_test):
        if technique_id not in available_simulation_techniques():
            continue
        events = run_simulation(technique_id, f"rule-test:{rule.id}:{technique_id}")
        result = evaluate_rule_version_against_events(rule_version.id, rule_version.yaml_content, events)
        results.append({"technique_id": technique_id, "matched": result["matched"]})

    unexpected_matches = [item["technique_id"] for item in results if item["matched"] and item["technique_id"] not in mapped_techniques]
    return {
        "rule_version_id": rule_version.id,
        "rule_title": rule.title,
        "mapped_techniques": mapped_techniques,
        "tested_techniques": [item["technique_id"] for item in results],
        "matched_techniques": [item["technique_id"] for item in results if item["matched"]],
        "unexpected_matches": unexpected_matches,
    }


@app.post("/evaluate")
def evaluate(payload: EvaluateRequest, db: Session = Depends(get_db)):
    run = db.get(SimulationRun, payload.simulation_run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")

    logs = db.query(GeneratedLog).filter(GeneratedLog.simulation_run_id == run.id).all()
    events = [log.normalized_event for log in logs]

    rules = db.query(DetectionRule).filter(DetectionRule.status == "active").all()
    rule_versions = []
    for r in rules:
        lv = r.latest_version
        if lv:
            rule_versions.append((lv.id, lv.yaml_content))

    eval_results = evaluate_rule_versions_against_events(rule_versions, events)

    alerts = []
    for res in eval_results:
        matched_event_id = None
        if res["matched"] and res["matched_event_index"] is not None:
            matched_event_id = logs[res["matched_event_index"]].id
        dr = DetectionResult(
            rule_version_id=res["rule_version_id"],
            simulation_run_id=run.id,
            matched=res["matched"],
            matched_event_id=matched_event_id,
        )
        db.add(dr)
        if res["matched"]:
            alerts.append(dr)
            rule_version = db.get(RuleVersion, res["rule_version_id"])
            if rule_version is not None:
                upsert_rule_technique_map(
                    db,
                    res["rule_version_id"],
                    run.technique_id,
                    "brute_force_confirmed",
                    confirmed=True,
                )
    db.commit()

    return {
        "simulation_run_id": run.id,
        "technique_id": run.technique_id,
        "rules_evaluated": len(rule_versions),
        "alerts_generated": len(alerts),
        "results": eval_results,
    }


@app.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    results = (
        db.query(DetectionResult)
        .filter(DetectionResult.matched == True)  # noqa: E712
        .order_by(DetectionResult.evaluated_at.desc())
        .all()
    )
    out = []
    for r in results:
        rv = db.get(RuleVersion, r.rule_version_id)
        run = db.get(SimulationRun, r.simulation_run_id)
        out.append(
            {
                "alert_id": r.id,
                "rule_title": rv.rule.title if rv else "(deleted rule)",
                "rule_author": rv.author if rv else None,
                "rule_version_id": r.rule_version_id,
                "technique_id": run.technique_id if run else None,
                "evaluated_at": r.evaluated_at.isoformat(),
            }
        )
    return out


@app.get("/alerts/{alert_id}/explain")
def explain_alert(alert_id: str, db: Session = Depends(get_db)):
    result = db.get(DetectionResult, alert_id)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    rule_version = db.get(RuleVersion, result.rule_version_id)
    if not rule_version:
        raise HTTPException(status_code=404, detail="Rule version not found")
    run = db.get(SimulationRun, result.simulation_run_id)
    event = None
    if run is not None:
        logs = db.query(GeneratedLog).filter(GeneratedLog.simulation_run_id == run.id).all()
        if logs:
            matched_log = next((log for log in logs if log.id == result.matched_event_id), None)
            event = matched_log.normalized_event if matched_log else logs[0].normalized_event
    explanation = explain_match(rule_version.yaml_content, event or {}, None)
    return {
        "alert_id": result.id,
        "rule_title": rule_version.rule.title if rule_version.rule else None,
        "rule_author": rule_version.author,
        "matched": result.matched,
        "explanation": explanation,
        "technique_id": run.technique_id if run else None,
    }


# ------------------------------------------------------- Coverage / Drift (FR-09/10)

@app.get("/coverage")
def coverage(db: Session = Depends(get_db)):
    """
    A rule only counts as covering a technique if it fired on an evaluation
    run of ITS OWN mapped technique's telemetry - not merely on whatever
    simulation happened to run most recently. Otherwise testing rule A
    against an unrelated technique's telemetry (a legitimate, expected
    thing to do) would make rule A look broken for coverage purposes even
    though it never got a fair shot at the technique it actually targets.
    """
    rule_techniques = {}
    verified_techniques_by_rule_version: dict[str, set[str]] = {}
    for lv in _active_rule_versions(db):
        mapping_rows = db.query(RuleTechniqueMap).filter(RuleTechniqueMap.rule_version_id == lv.id).all()
        preferred_rows = {}
        for row in mapping_rows:
            current = preferred_rows.get(row.technique_id)
            if current is None or _mapping_source_priority(row.source) > _mapping_source_priority(current.source):
                preferred_rows[row.technique_id] = row

        own_technique_ids = sorted(preferred_rows)
        rule_techniques[lv.id] = own_technique_ids
        verified_techniques_by_rule_version[lv.id] = _verified_techniques_for_rule_version(db, lv.id)

    return build_coverage_report(rule_techniques, verified_techniques_by_rule_version)


@app.get("/coverage/navigator-layer")
def coverage_navigator_layer(db: Session = Depends(get_db)):
    coverage_rows = coverage(db=db)
    techniques = []
    for row in coverage_rows:
        if not row["has_rule"]:
            continue
        techniques.append(
            {
                "techniqueID": row["technique_id"],
                "tactic": row["tactic"],
                "score": 100 if row["rule_passes"] else 0,
                "enabled": True,
                "color": "#35d488" if row["rule_passes"] else "#eab040",
                "comment": "verified" if row["rule_passes"] else "declared or pending verification",
            }
        )
    return {
        "version": "4.5",
        "name": "Detection Digital Twin coverage",
        "domain": "mitre-attack",
        "description": "Coverage view derived from verified brute-force matches.",
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "hideDisabled": False,
        "gradient": {"colors": ["#ffffff", "#35d488"], "minValue": 0, "maxValue": 100},
        "techniques": techniques,
    }


@app.get("/drift/production")
def production_drift(db: Session = Depends(get_db)):
    """
    Compares the digital twin's verified technique coverage against the real
    Wazuh production instance's actively enabled rules, to detect drift
    between what the twin has confirmed and what production currently covers.
    """
    twin_report = coverage(db)
    twin_verified = {row["technique_id"] for row in twin_report if row["rule_passes"]}

    client = WazuhClient()
    production_active = client.get_active_technique_ids()

    if production_active is None:
        snapshot = ProductionDriftSnapshot(
            wazuh_reachable=False,
            twin_verified_count=len(twin_verified),
            production_active_count=None,
            covered_both=[],
            twin_only=[],
            production_only=[],
        )
        db.add(snapshot)
        db.commit()
        return {
            "wazuh_reachable": False,
            "twin_verified_count": len(twin_verified),
            "production_active_count": None,
            "covered_both": [],
            "twin_only": [],
            "production_only": [],
        }

    covered_both = sorted(twin_verified & production_active)
    twin_only = sorted(twin_verified - production_active)
    production_only = sorted(production_active - twin_verified)

    snapshot = ProductionDriftSnapshot(
        wazuh_reachable=True,
        twin_verified_count=len(twin_verified),
        production_active_count=len(production_active),
        covered_both=covered_both,
        twin_only=twin_only,
        production_only=production_only,
    )
    db.add(snapshot)
    db.commit()

    return {
        "wazuh_reachable": True,
        "twin_verified_count": len(twin_verified),
        "production_active_count": len(production_active),
        "covered_both": covered_both,
        "twin_only": twin_only,
        "production_only": production_only,
    }


@app.get("/reports/summary")
def report_summary(db: Session = Depends(get_db)):
    """Generates a PDF summary of current coverage and production drift status."""
    coverage_data = coverage(db)
    drift_data = production_drift(db)

    technique_names = {row["technique_id"]: row["name"] for row in coverage_data}
    verified_count = sum(1 for row in coverage_data if row["rule_passes"])

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Detection Digital Twin — Coverage & Drift Summary", styles["Title"]))
    story.append(Paragraph(datetime.now(timezone.utc).strftime("Generated %Y-%m-%d %H:%M UTC"), styles["Normal"]))
    story.append(Spacer(1, 20))

    story.append(Paragraph("Summary", styles["Heading2"]))
    summary_table = Table([
        ["Total ATT&CK techniques", str(len(coverage_data))],
        ["Twin-verified techniques", str(verified_count)],
        ["Wazuh reachable", str(drift_data["wazuh_reachable"])],
        ["Wazuh active technique rules", str(drift_data.get("production_active_count", "N/A"))],
        ["Covered by both twin and production", str(len(drift_data.get("covered_both", [])))],
        ["Blind spots (twin verified, production has no rule)", str(len(drift_data.get("twin_only", [])))],
    ], colWidths=[300, 150])
    summary_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2740")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    if drift_data.get("twin_only"):
        story.append(Paragraph("Production Blind Spots", styles["Heading2"]))
        story.append(Paragraph(
            "The following techniques have been verified as detectable by the digital twin, "
            "but the real Wazuh production instance currently has no active rule for them:",
            styles["Normal"],
        ))
        rows = [["Technique ID", "Name"]] + [
            [tid, technique_names.get(tid, "Unknown")] for tid in drift_data["twin_only"]
        ]
        blind_spot_table = Table(rows, colWidths=[100, 350])
        blind_spot_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2740")),
        ]))
        story.append(blind_spot_table)
        story.append(Spacer(1, 20))

    story.append(Paragraph("Methodology", styles["Heading2"]))
    story.append(Paragraph(
        "Techniques are marked verified when a rule, evaluated by the twin's custom Sigma "
        "matcher against synthetic and Atomic Red Team-derived telemetry for that specific "
        "technique, produces a match. Production coverage is pulled live from the Wazuh "
        "manager REST API's enabled rule set and its declared MITRE ATT&CK mappings.",
        styles["Normal"],
    ))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Known Limitations", styles["Heading2"]))
    story.append(Paragraph(
        "Rules whose logsource category is network_connection may produce false-positive "
        "confirmations against Atomic-derived synthetic telemetry, since the current "
        "telemetry generator emits only process-creation fields (Image, CommandLine) and "
        "does not populate network fields such as DestinationIp. This is a disclosed, "
        "understood limitation, not a silent gap.",
        styles["Normal"],
    ))

    doc.build(story)
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=detection-digital-twin-report.pdf"},
    )


@app.get("/drift/production/history")
def production_drift_history(db: Session = Depends(get_db), limit: int = 30):
    rows = (
        db.query(ProductionDriftSnapshot)
        .order_by(ProductionDriftSnapshot.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "created_at": row.created_at.isoformat(),
            "wazuh_reachable": row.wazuh_reachable,
            "twin_verified_count": row.twin_verified_count,
            "production_active_count": row.production_active_count,
            "covered_both_count": len(row.covered_both or []),
            "twin_only_count": len(row.twin_only or []),
            "production_only_count": len(row.production_only or []),
        }
        for row in rows
    ]


@app.get("/drift")
def drift(db: Session = Depends(get_db)):
    results = db.query(DetectionResult).order_by(DetectionResult.evaluated_at.asc()).all()
    history = []
    for r in results:
        run = db.get(SimulationRun, r.simulation_run_id)
        history.append(
            {
                "rule_version_id": r.rule_version_id,
                "technique_id": run.technique_id if run else "unknown",
                "matched": r.matched,
                "evaluated_at": r.evaluated_at.isoformat(),
            }
        )
    drifted = build_drift_report(history)
    out = []
    for d in drifted:
        rv = db.get(RuleVersion, d["rule_version_id"])
        out.append({**d, "rule_title": rv.rule.title if rv else "(deleted rule)"})
    return out


@app.get("/health")
def health():
    return {"status": "ok"}
