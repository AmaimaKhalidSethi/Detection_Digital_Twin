from __future__ import annotations

from datetime import datetime, timezone

from fastapi import BackgroundTasks, FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models.db import (
    make_engine, make_session_factory, init_db,
    DetectionRule, RuleVersion, RuleTechniqueMap, SimulationRun, GeneratedLog,
    DetectionResult, DriftRecord, Job,
)
from app.detection_engine.rule_manager import validate_rule_yaml
from app.detection_engine.evaluator import (
    evaluate_rule_version_against_events,
    evaluate_rule_versions_against_events,
)
from app.detection_engine.analysis import build_coverage_report, build_drift_report
from app.ai.rule_search import search_rules, _extract_yaml_scalar
from app.ai.technique_suggester import confirm_ai_suggestions, suggest_rule_techniques
from app.ai.alert_explainer import explain_match
from app.technique_maps import upsert_rule_technique_map
from app.telemetry.generators.synthetic_log_generator import (
    available_simulation_techniques,
    run_simulation,
    simulation_coverage_gaps,
)
from app.mitre.data import all_techniques

engine = make_engine()
SessionLocal = make_session_factory(engine)
init_db(engine)

app = FastAPI(title="Detection Digital Twin API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------- schemas --

class RuleUploadRequest(BaseModel):
    yaml_content: str


class SimulateRequest(BaseModel):
    technique_id: str


class EvaluateRequest(BaseModel):
    simulation_run_id: str


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
            break
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
    return {
        "rule_id": rule.id,
        "version_id": version.id,
        "title": rule.title,
        "mitre_techniques": result.mitre_techniques,
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
    return {"rule_id": rule.id, "version_id": version.id, "version_number": next_version_number}


@app.get("/rules")
def list_rules(db: Session = Depends(get_db)):
    rules = db.query(DetectionRule).all()
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
             "author": v.author,
             "created_at": v.created_at.isoformat()}
            for v in sorted(rule.versions, key=lambda v: v.version_number)
        ],
    }


@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: str, db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
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
        db.add(GeneratedLog(simulation_run_id=run.id, source_type=e.source_type, normalized_event=e.to_dict()))

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
