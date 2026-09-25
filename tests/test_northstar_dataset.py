"""Northstar 模擬資料集：規模、完整性、無真實企業資訊，以及四個必測情境。"""

import csv
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from cve2action.collectors.nvd import load_snapshots
from cve2action.engine import rank
from cve2action.io import read_asset_context, read_scanner
from cve2action.models import DECISION_NEEDS_CONTEXT, DECISION_SCORED
from cve2action.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "synthetic" / "northstar"
RULES = load_rules(ROOT / "config" / "risk_rules.yaml")


def read(name: str) -> list[dict]:
    with (DATA / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


@pytest.fixture(scope="module")
def ranked() -> dict[tuple[str, str], dict]:
    rows = rank(read_scanner(DATA / "scanner.csv"),
                read_asset_context(DATA / "asset_context.csv"),
                RULES, load_snapshots(ROOT / "data" / "snapshots" / "nvd"))
    return {(r["asset"], r["cve"]): r for r in rows}


# --- 藍圖 §8.2 規模 -----------------------------------------------------------

def test_dataset_matches_blueprint_scale():
    assets, findings, controls = read("assets.csv"), read("scanner.csv"), read("controls.csv")
    assert len(assets) == 20
    assert len(findings) == 40
    assert len(controls) == 8
    assert sum(1 for a in assets if a["crown_jewel"] == "yes") == 4


def test_ids_are_unique_and_every_context_row_has_an_asset():
    assets = read("assets.csv")
    ids = [a["asset_id"] for a in assets]
    assert len(ids) == len(set(ids))
    assert {c["asset"] for c in read("asset_context.csv")} == set(ids)
    assert {c["asset_id"] for c in read("controls.csv")} <= set(ids)


def test_context_values_stay_inside_the_frozen_domains():
    for row in read("asset_context.csv"):
        assert row["environment"] in {"PROD", "NON_PROD"}
        assert row["reachability"] in RULES.reachability
        assert row["control_effectiveness"] in RULES.control_effectiveness
        assert row["business_criticality"] in RULES.business_criticality


def test_every_cve_is_backed_by_a_real_snapshot():
    """資產是虛構的，漏洞資料不是：每個 CVE 都必須有 NVD 快照。"""
    snapshots = load_snapshots(ROOT / "data" / "snapshots" / "nvd")
    missing = sorted({f["cve"] for f in read("scanner.csv")} - set(snapshots))
    assert not missing, f"no NVD snapshot for {missing}"


@pytest.mark.parametrize("name", ["assets.csv", "asset_context.csv", "scanner.csv", "controls.csv"])
def test_no_real_company_identifiers(name):
    """所有主機、團隊、網域都必須是虛構的 Northstar 命名。"""
    text = (DATA / name).read_text(encoding="utf-8").lower()
    for leaked in ("@gmail", "ithome", ".com.tw", "10.", "192.168.", "corp.local"):
        assert leaked not in text, f"{name} looks like it leaked {leaked!r}"


def test_control_effectiveness_is_derived_from_controls_file():
    """有控制措施的資產採其 effectiveness，其餘一律 NONE——不憑印象填。"""
    declared = {c["asset_id"]: c["effectiveness"] for c in read("controls.csv")}
    for row in read("asset_context.csv"):
        expected = declared.get(row["asset"], "NONE")
        assert row["control_effectiveness"] == expected, row["asset"]


# --- 引擎能吃、能排 -----------------------------------------------------------

def test_engine_scores_the_whole_dataset(ranked):
    scored = [r for r in ranked.values() if r["decision"] == DECISION_SCORED]
    assert len(scored) == 38
    assert all(r["cvss_source"].startswith("nvd/") for r in scored)


def test_band_distribution_is_the_one_the_article_quotes():
    """文章與配圖都引用這組數字；改動資料集就必須一起更新，不能悄悄漂移。"""
    rows = rank(read_scanner(DATA / "scanner.csv"),
                read_asset_context(DATA / "asset_context.csv"),
                RULES, load_snapshots(ROOT / "data" / "snapshots" / "nvd"))
    bands = Counter(r["priority"] for r in rows if r["decision"] == DECISION_SCORED)
    assert dict(bands) == {"Critical": 8, "High": 22, "Medium": 8}
    assert bands["Low"] == 0, "v0.1 公式在這家公司產不出 Low —— Day 18 校準的題目"
    assert sum(bands.values()) + 2 == len(rows) == 40


def test_the_two_gaps_are_needs_context_not_guesses(ranked):
    gaps = {k for k, r in ranked.items() if r["decision"] == DECISION_NEEDS_CONTEXT}
    assert gaps == {
        ("NS-SHADOW-NAS-02", "CVE-2017-0144"),   # 掃到清冊外的機器
        ("NS-MAIL-GW-01", "CVE-2011-3389"),      # NVD 沒有 v3.1，掃描器也沒給值
    }


def test_scanner_disagreement_is_recorded_not_overwritten(ranked):
    row = ranked[("NS-JUMP-01", "CVE-2019-0708")]
    assert row["cvss"] == 9.8 and "scanner said 9.9" in row["reason"]


# --- 藍圖 §8.4 必測情境 -------------------------------------------------------

def test_scenario_1_high_cvss_but_isolated_drops_out_of_the_top(ranked):
    row = ranked[("NS-LAB-CONFLUENCE-01", "CVE-2022-26134")]
    assert row["cvss"] == 9.8
    assert row["priority"] == "Medium", "隔離、無正式資料的 9.8 不該排在最前面"


def test_scenario_2_internet_reachable_critical_asset_tops_the_list(ranked):
    top = max((r for r in ranked.values() if r["decision"] == DECISION_SCORED),
              key=lambda r: r["priority_score"])
    assert top["priority"] == "Critical"
    assert top["environment"] == "PROD"


def test_scenario_3_the_same_cve_splits_on_control_evidence(ranked):
    """同一個漏洞、同樣對外、同樣關鍵業務，只差在 WAF 有沒有證據。"""
    with_waf = ranked[("NS-WEB-PORTAL-01", "CVE-2021-41773")]
    without = ranked[("NS-WEB-PORTAL-02", "CVE-2021-41773")]
    assert with_waf["cvss"] == without["cvss"] == 9.8
    assert (with_waf["priority_score"], with_waf["priority"]) == (8.4, "High")
    assert (without["priority_score"], without["priority"]) == (9.9, "Critical")


def test_unknown_control_does_not_earn_a_discount(ranked):
    """NS-APP-INTRANET-01 的 EDR 效果 UNKNOWN，曝險必須與完全沒有控制相同。"""
    unknown = ranked[("NS-APP-INTRANET-01", "CVE-2021-44228")]
    none = ranked[("NS-MON-01", "CVE-2021-44228")]
    assert unknown["effective_exposure"] == none["effective_exposure"] == 0.6


def test_context_is_derived_not_hand_written():
    """asset_context 的每一列都必須能從 assets + controls 推導出來，並帶著來源。"""
    from datetime import date

    from cve2action.normalization.exposure import derive_asset_context

    derived = derive_asset_context(read("assets.csv"), read("controls.csv"), RULES,
                                   date(2026, 9, 24))
    committed = read("asset_context.csv")
    assert derived == committed

    sources = {r["reachability_source"] for r in committed}
    assert sources == {"zone:DMZ", "zone:APP", "zone:DATA", "zone:CORP", "zone:MGMT",
                       "zone:OT", "zone:LAB"}, "每個值都要說得出是從哪個 Zone 推來的"
    expired = [r["asset"] for r in committed if "expired" in r["control_source"]]
    assert expired == ["NS-APP-INTRANET-01"], "90 天窗口下只有這台的控制證據過期"


# --- 可重現 -------------------------------------------------------------------

def test_rebuilding_from_snapshots_is_byte_identical():
    """資料集由快照重建；重跑不打網路，輸出必須完全一樣。"""
    before = {p.name: p.read_bytes() for p in sorted(DATA.glob("*.csv"))}
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_northstar.py")],
                   check=True, capture_output=True, cwd=ROOT)
    after = {p.name: p.read_bytes() for p in sorted(DATA.glob("*.csv"))}
    assert before == after
