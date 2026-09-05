from pathlib import Path

from netlens.config import Settings
from netlens.evaluation import evaluate, score


def test_duplicate_predictions_are_false_positives():
    row = {"detector": "dns.nxdomain", "packet_refs": [1, 2]}
    assert score([row], [row, row])["precision"] == 0.5
    assert score([row], [])["false_negatives"] == 1
    assert score([], [])["precision"] is None


def test_actual_evaluation(tmp_path):
    report = evaluate(Path.cwd(), tmp_path, Settings())
    assert report["passed"]
    assert report["aggregate_detectors"]["true_positives"] == 6
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.md").exists()
