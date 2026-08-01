from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models.db import (
    make_engine, make_session_factory, init_db,
    DetectionRule, RuleVersion, SimulationRun, GeneratedLog, DetectionResult, DriftRecord,
)
from app.detection_engine.rule_manager import validate_rule_yaml
from app.detection_engine.evaluator import evaluate_rule_versions_against_events
from app.detection_engine.analysis import build_coverage_report, build_drift_report
from app.telemetry.generators.synthetic_log_generator import run_simulation, TECHNIQUE_SIMULATIONS
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


# -------------------------------------------------------------- MITRE (FR-08)

@app.get("/mitre/techniques")
def list_techniques():
    return [{"technique_id": k, **v} for k, v in all_techniques().items()]


@app.get("/simulator/techniques")
def list_simulatable_techniques():
    return sorted(TECHNIQUE_SIMULATIONS.keys())


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
    )
    db.add(version)
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
    )
    db.add(version)
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
                "mitre_techniques": lv.mitre_techniques if lv else [],
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
             "mitre_techniques": v.mitre_techniques, "created_at": v.created_at.isoformat()}
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
    if payload.technique_id not in TECHNIQUE_SIMULATIONS:
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
    rules = db.query(DetectionRule).filter(DetectionRule.status == "active").all()
    rule_techniques = {}
    latest_pass_by_rule_version = {}
    for r in rules:
        lv = r.latest_version
        if not lv:
            continue
        rule_techniques[lv.id] = lv.mitre_techniques or []

        own_technique_ids = lv.mitre_techniques or []
        passed_on_own_technique = False
        if own_technique_ids:
            results = (
                db.query(DetectionResult)
                .filter(DetectionResult.rule_version_id == lv.id)
                .order_by(DetectionResult.evaluated_at.desc())
                .all()
            )
            for res in results:
                run = db.get(SimulationRun, res.simulation_run_id)
                if run and run.technique_id in own_technique_ids:
                    passed_on_own_technique = res.matched
                    break  # most recent evaluation against its own technique
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
