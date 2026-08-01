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


def _upsert_rule_technique_map(
    db: Session,
    rule_version_id: str,
    technique_id: str,
    source: str,
    confirmed: bool = True,
    confidence: float | None = None,
) -> None:
    row = (
        db.query(RuleTechniqueMap)
        .filter_by(rule_version_id=rule_version_id, technique_id=technique_id, source=source)
        .one_or_none()
    )
    if row is None:
        row = RuleTechniqueMap(
            rule_version_id=rule_version_id,
            technique_id=technique_id,
            source=source,
            confirmed=confirmed,
            confidence=confidence,
        )
        db.add(row)
        return
    row.confirmed = confirmed
    row.confidence = confidence


def _run_full_matrix_evaluation(job_id: str) -> None:
    db = SessionLocal()
    try:
        job = db.get(Job, job_id)
        if not job:
            return

        job.status = "running"
        db.commit()

        active_versions = _active_rule_versions(db)
        techniques = sorted(set(available_simulation_techniques()))
        job.progress_total = len(active_versions) * len(techniques)
        db.commit()

        for technique_id in techniques:
            events = run_simulation(technique_id, f"{job_id}:{technique_id}")
            for rule_version in active_versions:
                result = evaluate_rule_version_against_events(rule_version.id, rule_version.yaml_content, events)
                if result["matched"]:
                    _upsert_rule_technique_map(
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
            "techniques_evaluated": len(techniques),
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
        out.append(
            {
                "rule_id": r.id,
                "title": r.title,
                "status": r.status,
                "version_number": lv.version_number if lv else None,
                "version_id": lv.id if lv else None,
                "mitre_techniques": sorted({m.technique_id for m in lv.technique_mappings}) if lv else [],
            }
        )
    return out


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


@app.post("/rules/{rule_id}/test")
def test_rule(rule_id: str, db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule_version = rule.latest_version
    if not rule_version:
        raise HTTPException(status_code=404, detail="Rule version not found")

    mapped_techniques = sorted({mapping.technique_id for mapping in rule_version.technique_mappings})
    techniques_to_test = set(mapped_techniques)
    technique_meta = all_techniques()
    tactic_names = {technique_meta[technique_id]["tactic"] for technique_id in mapped_techniques if technique_id in technique_meta}
    for tactic_name in tactic_names:
        for technique_id in sorted(technique_meta):
            if technique_id in mapped_techniques:
                continue
            if technique_meta[technique_id].get("tactic") != tactic_name:
                continue
            techniques_to_test.add(technique_id)
            if len(techniques_to_test) >= 8:
                break
        if len(techniques_to_test) >= 8:
            break

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
    latest_pass_by_rule_version = {}
    for lv in _active_rule_versions(db):
        own_technique_ids = sorted({mapping.technique_id for mapping in lv.technique_mappings})
        rule_techniques[lv.id] = own_technique_ids
        passed_on_own_technique = False
        if own_technique_ids:
            mapping_rows = (
                db.query(RuleTechniqueMap)
                .filter(RuleTechniqueMap.rule_version_id == lv.id)
                .filter(RuleTechniqueMap.technique_id.in_(own_technique_ids))
                .all()
            )
            if mapping_rows:
                preferred_rows = {}
                for row in mapping_rows:
                    current = preferred_rows.get(row.technique_id)
                    if current is None or _mapping_source_priority(row.source) > _mapping_source_priority(current.source):
                        preferred_rows[row.technique_id] = row
                passed_on_own_technique = any(row.confirmed for row in preferred_rows.values())
        latest_pass_by_rule_version[lv.id] = passed_on_own_technique

    return build_coverage_report(rule_techniques, latest_pass_by_rule_version)


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
