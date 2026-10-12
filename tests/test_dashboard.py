"""Day 28：儀表板。

兩件事要鎖住：

1. **儀表板上的數字等於命令列的數字。** `app/data.py` 跑的是 CLI 的同一條管線；
   這裡逐項對文章引用過的數字。
2. **畫得出來。** Streamlit 的 `AppTest` 在無頭模式把整個 app 跑一遍，任何例外都算失敗。
   沒裝 dashboard extra 的環境跳過這一條（CI 有裝）。
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import data  # noqa: E402


@pytest.fixture(scope="module")
def pipeline():
    return data.run()


def test_ranking_has_both_columns(pipeline):
    """成功標準 #5：CVSS 排名與本專案排名同一列。"""
    rows = data.ranking_rows(pipeline)
    assert len(rows) == 38
    assert {"rank", "cvss_rank", "move"} <= set(rows[0])


def test_cvss_ties_are_ties(pipeline):
    """六筆 10.0 在 CVSS 眼裡就是並列第一，不替它們編先後。"""
    head = data.headline(pipeline)
    assert head["cvss10"] == 6
    assert head["cvss10_span"] == (4, 32)
    assert head["top_cvss"]["cvss_rank"] == 1
    tens = [r for r in data.ranking_rows(pipeline) if r["cvss"] == 10.0]
    assert {r["cvss_rank"] for r in tens} == {1}


def test_headline_numbers(pipeline):
    head = data.headline(pipeline)
    assert (head["top_ours"]["asset"], head["top_ours"]["cvss_rank"]) == ("NS-VPN-GW-01", 7)
    assert (head["riser"]["asset"], head["riser"]["cve"]) == ("NS-WEB-PORTAL-02",
                                                              "CVE-2023-44487")
    assert head["riser"]["move"] == 20
    assert (head["faller"]["rank"], head["faller"]["cvss_rank"]) == (32, 1)


def test_top_two_are_shown_as_a_tie(pipeline):
    rows = data.ranking_rows(pipeline)
    assert rows[0]["score"] == rows[1]["score"] == 9.86
    assert rows[1]["tie_with_above"]


def test_cleared_finding_says_so(pipeline):
    jump = next(r for r in data.ranking_rows(pipeline) if r["asset"] == "NS-JUMP-01")
    assert jump["tier"] == "不必修"


def test_treatment_view_carries_the_day_26_correction(pipeline):
    view = data.view_treatment(pipeline)
    assert view["raised"] == 15
    assert view["tier_after"]["P0"] == 24


def test_simulation_matches_the_cli(pipeline):
    one = data.simulate(pipeline, ["REM-004"])
    assert (one["paths_after"], one["drop"], one["per_hour"]) == (28, 2.72, 1.36)
    two = data.simulate(pipeline, ["REM-004", "REM-010"])
    assert (two["paths_after"], two["drop"]) == (28, 11.09)


def test_pending_measures_are_flagged(pipeline):
    sim = data.simulate(pipeline, ["REM-006"])
    assert sim["pending"] == ["REM-006"]
    assert sim["drop"] == 0.0


def test_what_ifs_match_the_cli(pipeline):
    assert [w["資產"] for w in data.what_ifs(pipeline)] == [
        "NS-JUMP-01", "NS-APP-ORDER-01", "NS-VPN-GW-01"]


def test_jewel_graph_is_small_enough_to_read(pipeline):
    view = data.jewel_graph(pipeline)
    assert view["total_paths"] == 30
    assert len(view["nodes"]) == 13 and len(view["edges"]) == 18


def test_export_is_the_ranking(pipeline):
    lines = data.export_csv(pipeline).splitlines()
    assert lines[0].split(",") == data.EXPORT_FIELDS
    assert len(lines) == 1 + 38


def test_uploaded_scanner_keeps_unknown_assets_visible(tmp_path):
    """展示腳本第 1 步：換一份弱掃檔。清冊上沒有的資產不排名，但不能消失。"""
    path = tmp_path / "scan.csv"
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["asset", "cve", "cvss", "service"])
        writer.writerow(["NS-VPN-GW-01", "CVE-2024-21762", "9.8", "fortios-ssl-vpn"])
        writer.writerow(["NS-LAB-CONFLUENCE-01", "CVE-2022-26134", "9.8", "confluence"])
        writer.writerow(["NOT-IN-INVENTORY", "CVE-2021-44228", "10", "log4j2"])
    p = data.run(path)
    assert [r["asset"] for r in data.ranking_rows(p)] == ["NS-VPN-GW-01",
                                                          "NS-LAB-CONFLUENCE-01"]
    assert [r["asset"] for r in data.unscored_rows(p)] == ["NOT-IN-INVENTORY"]


def test_dashboard_renders_without_exceptions():
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(str(ROOT / "app" / "dashboard.py"), default_timeout=180).run()
    assert not app.exception, app.exception
    assert len(app.tabs) == 5
    assert any("CVE2Action" in t.value for t in app.title)
