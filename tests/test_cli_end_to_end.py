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


# --- Day 8：從 NVD 快照取 CVSS ---------------------------------------------

DAY08_ARGS = [
    "--scanner", str(REPO_ROOT / "data/synthetic/day-08-scanner.csv"),
    "--context", str(REPO_ROOT / "data/synthetic/day-08-asset-context.csv"),
    "--snapshots", str(REPO_ROOT / "data/snapshots/nvd"),
]


def run_day08(tmp_path: Path, rules: Path | None = None) -> list[dict]:
    out = tmp_path / "ranked.csv"
    rules = rules or REPO_ROOT / "config/risk_rules.yaml"
    assert main(["rank", *DAY08_ARGS, "--rules", str(rules), "--out", str(out)]) == 0
    with out.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def test_day08_snapshots_override_hand_filled_and_fill_blank(tmp_path):
    rows = run_day08(tmp_path)
    scored = [(r["asset"], r["cvss"], r["cvss_version"], r["priority_score"], r["priority"])
              for r in rows[:-1]]
    assert scored == [
        ("NS-MAIL-GW-02", "8.0", "3.1", "9.0", "Critical"),   # Day 6 手填 8.8 → 9.4
        ("NS-APP-INTRANET-01", "10.0", "3.1", "8.25", "High"),
        ("NS-MAIL-GW-01", "8.0", "3.1", "7.5", "High"),       # Day 6 手填 8.8 → 7.9
        ("NS-EDGE-RTR-01", "4.4", "3.1", "6.45", "Medium"),
        ("NS-PLC-LINE-A", "7.3", "4.0", "6.35", "Medium"),    # 掃描器空白，v4.0-only 補上
        ("NS-LAB-CONFLUENCE-01", "9.8", "3.1", "6.25", "Medium"),
        ("NS-FILE-SRV-01", "5.3", "3.1", "4.7", "Medium"),
    ]
    assert all(r["cvss_source"].startswith("nvd/") for r in rows[:-1])
    assert rows[-1]["asset"] == "NS-IOT-CAM-77" and rows[-1]["decision"] == "NEEDS_CONTEXT"
    mail = next(r for r in rows if r["asset"] == "NS-MAIL-GW-02")
    assert "scanner said 8.8" in mail["reason"]


def test_day08_preferring_v40_moves_router_into_high(tmp_path):
    rules = tmp_path / "rules40.yaml"
    text = (REPO_ROOT / "config/risk_rules.yaml").read_text(encoding="utf-8")
    assert '["3.1", "4.0"]' in text
    rules.write_text(text.replace('["3.1", "4.0"]', '["4.0", "3.1"]'), encoding="utf-8")

    rows = run_day08(tmp_path, rules)
    order = [r["asset"] for r in rows]
    router = next(r for r in rows if r["asset"] == "NS-EDGE-RTR-01")
    assert (router["cvss"], router["cvss_version"], router["priority_score"], router["priority"]) \
        == ("6.7", "4.0", "7.6", "High")
    assert order.index("NS-EDGE-RTR-01") < order.index("NS-MAIL-GW-01")
    # 其餘只有 v3.1 的列不受偏好順序影響
    assert next(r for r in rows if r["asset"] == "NS-MAIL-GW-02")["priority_score"] == "9.0"
