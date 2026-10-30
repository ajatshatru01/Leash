from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from leash.benchmark import BenchmarkRunner, load_cases, write_report
from leash.contracts import Decision

CASES_DIR = Path(__file__).resolve().parents[1] / "bench" / "cases"


def test_frozen_suite_has_expected_distribution_and_heldout_split() -> None:
    cases = load_cases(CASES_DIR)

    assert len(cases) == 60
    assert Counter(case.family for case in cases) == {
        "safe_routine": 20,
        "legitimate_suspicious": 8,
        "destructive": 10,
        "secret_egress": 10,
        "encoded_opaque": 7,
        "task_injection": 5,
    }
    assert Counter(case.split for case in cases) == {"development": 48, "final": 12}
    assert len({case.mutation_source for case in cases}) == 60


def test_benchmark_runs_three_offline_configurations_without_execution() -> None:
    cases = load_cases(CASES_DIR)

    rows = BenchmarkRunner().run(cases)

    assert len(rows) == 180
    assert Counter(row.configuration for row in rows) == {
        "rules_only": 60,
        "recorded_wonder_only": 60,
        "recorded_hybrid": 60,
    }
    hybrid = [row for row in rows if row.configuration == "recorded_hybrid"]
    assert all(row.correct for row in hybrid)
    task_injection_rules = [
        row for row in rows if row.configuration == "rules_only" and row.family == "task_injection"
    ]
    assert task_injection_rules
    assert all(row.predicted == Decision.REVIEW for row in task_injection_rules)
    assert all(row.predicted != Decision.ALLOW for row in rows if row.expected == Decision.BLOCK)


def test_report_contains_reproducible_metrics_and_no_case_payloads(tmp_path: Path) -> None:
    cases = load_cases(CASES_DIR)
    rows = BenchmarkRunner().run(cases, split="final")

    artifacts = write_report(
        cases=cases,
        rows=rows,
        reports_dir=tmp_path / "reports",
        split="final",
    )

    assert artifacts.case_count == 12
    assert artifacts.row_count == 36
    summary = json.loads(artifacts.summary.read_text(encoding="utf-8"))
    assert summary["suite"] == "leashbench-v1"
    assert summary["suite_digest"] == artifacts.suite_digest
    assert summary["configurations"]["rules_only"]["samples"] == 12
    assert "confusion_matrix" in summary["configurations"]["recorded_hybrid"]
    assert "accuracy_ci95_bootstrap" in summary["configurations"]["rules_only"]
    assert "p95" in summary["configurations"]["rules_only"]["latency_ms"]["preview"]
    assert "do not measure a live Muse Wonder model" in summary["disclosure"]
    raw = artifacts.raw_results.read_text(encoding="utf-8")
    assert "FAKEBENCHMARKVALUE" not in raw
    assert "ghp_" not in raw


def test_fixture_path_escape_is_rejected() -> None:
    payload = json.loads((CASES_DIR / "01-safe-routine.json").read_text(encoding="utf-8"))
    payload[0]["fixture"] = {"files": [{"path": "../escape.txt", "content": "x"}]}
    case_path = CASES_DIR.parent / "invalid-case-never-written.json"
    case = load_cases(CASES_DIR)[0].model_validate(payload[0])

    with pytest.raises(ValueError, match="escapes temporary workspace"):
        BenchmarkRunner().run((case,))

    assert not case_path.exists()
