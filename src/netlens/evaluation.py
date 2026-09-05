import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from netlens.config import Settings
from netlens.detectors import analyze
from netlens.parsing import CaptureError, parse_capture
from netlens.providers.base import prepare_context
from netlens.providers.gateway import generate_report


def score(expected: list[dict], actual: list[dict]) -> dict:
    def keys(rows):
        return Counter((f["detector"], tuple(sorted(set(f["packet_refs"])))) for f in rows)

    gold, predicted = keys(expected), keys(actual)
    tp = sum((gold & predicted).values())
    fp, fn = sum(predicted.values()) - tp, sum(gold.values()) - tp
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
    }


def evaluate(root: Path, output: Path, settings: Settings, provider="mock") -> dict:
    manifest = json.loads((root / "evaluation/manifest.json").read_text())
    results, gold, actual = [], [], []
    for scenario in manifest["scenarios"]:
        row = {"scenario": scenario["id"]}
        try:
            stats, findings = analyze(
                parse_capture(root / scenario["path"], settings), settings.dns_slow_ms
            )
        except CaptureError as exc:
            row.update(rejected=True, error=exc.code, passed=bool(scenario.get("expected_error")))
            results.append(row)
            continue
        found = [f.model_dump(mode="json") for f in findings]
        expected = scenario.get("expected", [])
        metrics = score(expected, found)
        gold.extend({**f, "detector": scenario["id"] + ":" + f["detector"]} for f in expected)
        actual.extend({**f, "detector": scenario["id"] + ":" + f["detector"]} for f in found)
        row.update(
            detectors=metrics,
            passed=not scenario.get("expected_error")
            and metrics["false_positives"] == metrics["false_negatives"] == 0,
        )
        context, _ = prepare_context(stats.model_dump(), found)
        try:
            content, metadata = generate_report(provider, context, settings)
            observed = {
                identifier for issue in content.observed_issues for identifier in issue.finding_ids
            }
            known = {f.id for f in findings}
            row["ai"] = {
                "schema_valid": True,
                "evidence_valid": True,
                "expected_observation_coverage": len(observed & known) / len(known)
                if known
                else None,
                "provider_metadata": metadata.model_dump(),
                "content": content.model_dump(),
                "unsupported_claims_review": "human review required",
                "uncertainty_review": "human review required",
            }
        except Exception as exc:
            row["ai"] = {
                "schema_valid": False,
                "evidence_valid": False,
                "error": getattr(exc, "code", "evaluation_provider_failure"),
            }
            row["passed"] = False
        results.append(row)
    report = {
        "evaluation_version": 1,
        "manifest_version": manifest["version"],
        "evaluated_at": datetime.now(UTC).isoformat(),
        "run_type": "mock" if provider == "mock" else "live",
        "human_review_performed": False,
        "model_as_judge_used": False,
        "aggregate_detectors": score(gold, actual),
        "scenarios": results,
        "passed": all(row["passed"] for row in results),
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = [
        "# NetLens evaluation",
        "",
        f"Evaluated at: {report['evaluated_at']}",
        f"Run type: **{report['run_type']}**. Human review: **not performed**.",
        "",
        "Detector matching: exact detector and packet-reference set, "
        "one match per expected finding.",
        "Duplicate predictions count as false positives. Undefined precision/recall is null.",
        "",
        f"Aggregate: `{json.dumps(report['aggregate_detectors'])}`",
        "",
        "| Scenario | Passed | AI schema / evidence |",
        "|---|---|---|",
    ]
    for row in results:
        ai = row.get("ai")
        value = f"{ai['schema_valid']} / {ai['evidence_valid']}" if ai else "not applicable"
        lines.append(f"| {row['scenario']} | {row['passed']} | {value} |")
    lines.extend(
        [
            "",
            "Semantic unsupported-claim and uncertainty checks require "
            "the rubric in docs/testing.md.",
            "Mock coverage measures deterministic formatting, "
            "not model intelligence or real-world accuracy.",
        ]
    )
    (output / "report.md").write_text("\n".join(lines) + "\n")
    return report
