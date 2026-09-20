"""End-to-end：day-06 模擬資料經 CLI 產出 ranked_result.csv。"""

import csv
from pathlib import Path

from cve2action.cli import main
from cve2action.models import OUTPUT_COLUMNS

REPO_ROOT = Path(__file__).resolve().parents[1]


def run_rank(tmp_path: Path) -> list[dict]:
    out = tmp_path / "ranked_result.csv"
    exit_code = main(
        [
            "rank",
            "--scanner", str(REPO_ROOT / "data/synthetic/day-06-scanner.csv"),
            "--context", str(REPO_ROOT / "data/synthetic/day-06-asset-context.csv"),
            "--rules", str(REPO_ROOT / "config/risk_rules.yaml"),
            "--out", str(out),
        ]
    )
    assert exit_code == 0
    with out.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def test_end_to_end_ranking(tmp_path):
    rows = run_rank(tmp_path)
    assert rows and list(rows[0].keys()) == list(OUTPUT_COLUMNS)

    expected_order = [
        ("NS-MAIL-GW-02", "9.4", "Critical"),
        ("NS-APP-INTRANET-01", "8.25", "High"),
        ("NS-MAIL-GW-01", "7.9", "High"),
        ("NS-LAB-CONFLUENCE-01", "6.25", "Medium"),
        ("NS-FILE-SRV-01", "4.7", "Medium"),
    ]
    scored = rows[:-1]
    assert [(r["asset"], r["priority_score"], r["priority"]) for r in scored] == expected_order

    ghost = rows[-1]
    assert ghost["asset"] == "NS-IOT-CAM-77"
    assert ghost["decision"] == "NEEDS_CONTEXT"
    assert ghost["priority_score"] == ""
    assert "asset not found" in ghost["reason"]

    for row in scored:
        assert row["decision"] == "SCORED"
        assert row["reason"]


def test_broken_rules_exit_code(tmp_path):
    bad_rules = tmp_path / "bad.yaml"
    bad_rules.write_text("weights: {severity: 1.0}", encoding="utf-8")
    exit_code = main(
        [
            "rank",
            "--scanner", str(REPO_ROOT / "data/synthetic/day-06-scanner.csv"),
            "--context", str(REPO_ROOT / "data/synthetic/day-06-asset-context.csv"),
            "--rules", str(bad_rules),
            "--out", str(tmp_path / "out.csv"),
        ]
    )
    assert exit_code == 2
