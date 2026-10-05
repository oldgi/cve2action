"""Day 25：適用性閘門與 §9.6 規則覆寫。

兩個主張在這裡被鎖住：

1. **`NOT_APPLICABLE` 只能被證明出來，不能被推論出來。** 版本比對在真實資料上
   會以兩種方式騙人（編號體系對不上、空清單當成證據），兩種都有測試擋著。
   判錯成「要修」只是多花工，判錯成「不必修」是漏掉一台對外的機器。
2. **覆寫只升不降。** 降級是人的決定，走 `risk_acceptances.csv`，
   而且仍然要標記複核——§9.6 原文是「不得僅依數字自動降級」。
"""

from __future__ import annotations

import csv
from datetime import date
from pathlib import Path

import pytest

from cve2action.remediation import (
    APPLICABLE,
    KEV_REACHABLE_PATH,
    MISSING_CRITICAL_INPUT,
    NOT_APPLICABLE,
    TIER_ORDER,
    UNAUTHENTICATED_TO_CROWN_JEWEL,
    UNDECIDABLE,
    apply,
    decide,
    effective_acceptance,
    vulnerable_cpes,
)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "synthetic" / "northstar"
SNAPS = str(ROOT / "data" / "snapshots" / "nvd")
AS_OF = date(2026, 9, 24)


def read(name: str) -> list[dict]:
    with (DATA / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


@pytest.fixture(scope="module")
def evidence() -> dict[tuple[str, str], dict]:
    return {(r["asset_id"], r["cve"]): r for r in read("version_evidence.csv")}


def verdict_for(evidence, asset: str, cve: str):
    return decide(evidence.get((asset, cve)), vulnerable_cpes(cve, SNAPS), AS_OF)


# --- 閘門：唯一一種掙得 NOT_APPLICABLE 的方式 ---------------------------------

def test_product_absent_from_a_non_empty_list_earns_not_applicable(evidence):
    v = verdict_for(evidence, "NS-JUMP-01", "CVE-2019-0708")
    assert v.state == NOT_APPLICABLE
    assert v.leaves_queue
    assert "不在其中" in v.reason


def test_an_empty_cpe_list_is_not_evidence_of_anything(evidence):
    """CVE-2024-6242 的 configurations 整個是空的。

    「不在清單裡」在這裡只代表清單沒東西。把空集合讀成「不受影響」，
    是這個閘門最容易犯、也最貴的一種錯。
    """
    assert vulnerable_cpes("CVE-2024-6242", SNAPS) == []
    v = verdict_for(evidence, "NS-PLC-DC-ENV", "CVE-2024-6242")
    assert v.state == UNDECIDABLE
    assert "空清單不是證據" in v.reason


def test_a_version_scheme_mismatch_never_becomes_not_applicable(evidence):
    """Exchange 裝的是 15.2.792，CPE 用 2013／2016／2019。

    兩邊都是數字，比得出大小，而答案毫無意義：純數字比對會說「都沒命中」。
    如果「沒命中」可以推出「不受影響」，這台對外的 Exchange 就會從佇列裡消失。
    """
    v = verdict_for(evidence, "NS-MAIL-GW-01", "CVE-2021-26855")
    assert v.state == UNDECIDABLE
    assert "沒命中不等於不受影響" in v.reason


def test_a_banner_can_never_settle_anything(evidence):
    """openssh 7.4p1 落在 5.9–7.8 裡，但來源是 banner。

    發行版回溯修補之後，服務自報的版本不會變——看起來中招其實早就修了，
    反過來也一樣。
    """
    v = verdict_for(evidence, "NS-FILE-SRV-01", "CVE-2018-15919")
    assert v.state == UNDECIDABLE
    assert "banner" in v.reason


def test_a_non_numeric_bound_is_not_guessed(evidence):
    """ios_xe 的上界是 17.6.6a。`17.6.1 < 17.6.6a` 是直覺，不是規則。"""
    v = verdict_for(evidence, "NS-EDGE-RTR-01", "CVE-2023-20198")
    assert v.state == UNDECIDABLE
    assert "非數字邊界" in v.reason


def test_no_evidence_at_all_is_undecidable(evidence):
    v = verdict_for(evidence, "NS-DB-CUSTOMER-01", "CVE-2016-5195")
    assert v.state == UNDECIDABLE
    assert "沒有版本證據" in v.reason


def test_expired_evidence_cannot_clear_anything():
    stale = {"cpe_product": "windows_server_2019", "version": "2019",
             "source": "agent_inventory", "verified_at": "2025-01-01"}
    v = decide(stale, vulnerable_cpes("CVE-2019-0708", SNAPS), AS_OF)
    assert v.state == UNDECIDABLE
    assert "過期" in v.reason


def test_in_range_versions_are_applicable(evidence):
    for asset, cve in [("NS-WEB-PORTAL-01", "CVE-2021-41773"),
                       ("NS-VPN-GW-01", "CVE-2024-21762"),
                       ("NS-APP-INTRANET-01", "CVE-2023-22515"),
                       ("NS-APP-REPORT-01", "CVE-2020-1938")]:
        assert verdict_for(evidence, asset, cve).state == APPLICABLE, (asset, cve)


def test_the_moveit_row_is_applicable_for_the_wrong_reason(evidence):
    """誠實記一筆：這個結論是對的，但推理是錯的。

    MOVEit 裝的 `15.0.1` 是 moveit_cloud 的編號，而 CPE 的 moveit_transfer 用
    2021.x／2022.x。閘門把 15.0.1 跟一條沒有下界的 `< 2021.0.7` 比，比中了，
    於是判 APPLICABLE——**方向剛好安全，理由完全不成立**。

    這條測試把這個結果釘住：哪天有人「改進」版本比對、讓它翻成 NOT_APPLICABLE，
    這裡會紅。釘住一個靠運氣得到的答案，比假裝沒看到好。
    """
    v = verdict_for(evidence, "NS-APP-BILLING-01", "CVE-2023-34362")
    assert v.state == APPLICABLE
    bounds = {m.get("versionEndExcluding") for m in vulnerable_cpes("CVE-2023-34362", SNAPS)
              if ":moveit_transfer:" in m["criteria"]}
    assert bounds and all(str(b)[:4] in {"2021", "2022", "2023"} for b in bounds if b), (
        f"CPE 的上界應該全是年份編號，實際是 {bounds}"
    )


def test_the_whole_dataset_splits_one_nine_thirty(evidence):
    """文章引用的三個數字。"""
    states = [verdict_for(evidence, r["asset"], r["cve"]).state for r in read("scanner.csv")]
    assert states.count(NOT_APPLICABLE) == 1
    assert states.count(APPLICABLE) == 9
    assert states.count(UNDECIDABLE) == 30


# --- §9.6 覆寫 ---------------------------------------------------------------

def test_overrides_only_ever_raise():
    """窮舉四個起始層級 × 兩條升級規則，結果不得比原本輕。"""
    for tier in TIER_ORDER:
        for kev in (False, True):
            for jewel in (False, True):
                out = apply(tier, kev_listed=kev, reachable=kev, has_path=kev,
                            unauthenticated_jewel_path=jewel)
                assert TIER_ORDER.index(out.tier) <= TIER_ORDER.index(tier)


def test_kev_rule_needs_all_three_facts():
    for kwargs in ({"kev_listed": True}, {"reachable": True}, {"has_path": True},
                   {"kev_listed": True, "reachable": True}):
        assert apply("P2", **kwargs).tier == "P2"
    out = apply("P2", kev_listed=True, reachable=True, has_path=True)
    assert out.tier == "P0"
    assert out.rules == (KEV_REACHABLE_PATH,)


def test_the_jewel_rule_floors_at_p1_not_p0():
    out = apply("P2", unauthenticated_jewel_path=True)
    assert out.tier == "P1"
    assert out.rules == (UNAUTHENTICATED_TO_CROWN_JEWEL,)
    # 已經是 P0 就不該被往回拉
    assert apply("P0", unauthenticated_jewel_path=True).tier == "P0"


def test_a_rule_that_fires_without_raising_is_still_recorded():
    """規則成立但層級沒動，也要留紀錄——否則看不出它被考慮過。"""
    out = apply("P0", kev_listed=True, reachable=True, has_path=True)
    assert out.tier == "P0"
    assert out.rules == (KEV_REACHABLE_PATH,)
    assert not out.fired[0].raised


def test_missing_input_marks_review_without_touching_the_tier():
    out = apply("P2", undecidable_applicability=True)
    assert out.tier == "P2"
    assert out.review_required
    assert out.rules == (MISSING_CRITICAL_INPUT,)


# --- 風險接受 ----------------------------------------------------------------

def test_only_approved_and_unexpired_acceptances_count():
    rows = read("risk_acceptances.csv")
    assert effective_acceptance(rows, "NS-LAB-CONFLUENCE-01", "CVE-2022-26134",
                                AS_OF)["acceptance_id"] == "ACC-001"
    # 過期：狀態還掛 APPROVED，但日期已過
    assert effective_acceptance(rows, "NS-WEB-PORTAL-02", "CVE-2021-41773",
                                AS_OF) is None
    # 已撤銷
    assert effective_acceptance(rows, "NS-VPN-GW-01", "CVE-2018-13379",
                                AS_OF) is None


def test_an_acceptance_does_not_lower_the_tier_by_itself():
    """§9.6：「分數不取代人工決策。」反過來也成立——一份簽過的紙也不是
    數字可以自動執行的授權。接受被記下來、被標記複核，但層級不動。"""
    row = {"acceptance_id": "ACC-001", "approver": "林思妤（資安經理）",
           "valid_until": "2026-12-31", "ref": "RISK-2026-0418"}
    out = apply("P0", kev_listed=True, reachable=True, has_path=True, acceptance=row)
    assert out.tier == "P0"
    assert out.review_required
    assert out.accepted_by is row


# --- 端到端 ------------------------------------------------------------------

def test_cli_treat_reports_the_article_numbers(capsys):
    from cve2action.cli import main as cli_main

    code = cli_main([
        "treat",
        "--scanner", str(DATA / "scanner.csv"),
        "--context", str(DATA / "asset_context.csv"),
        "--rules", str(ROOT / "config/risk_rules.yaml"),
        "--snapshots", SNAPS,
        "--epss", str(ROOT / "data/snapshots/epss"),
        "--kev", str(ROOT / "data/snapshots/kev"),
        "--controls", str(DATA / "controls.csv"),
        "--evidence", str(DATA / "version_evidence.csv"),
        "--acceptances", str(DATA / "risk_acceptances.csv"),
        "--remediations", str(DATA / "remediations.csv"),
        "--assets", str(DATA / "assets.csv"),
        "--interfaces", str(DATA / "asset_interfaces.csv"),
        "--services", str(DATA / "services.csv"),
        "--network", str(DATA / "network_edges.csv"),
        "--identity", str(DATA / "identity_edges.csv"),
        "--policies", str(DATA / "network_policies.csv"),
        "--findings", str(DATA / "scanner.csv"),
        "--as-of", "2026-09-24",
    ])
    out = capsys.readouterr().out
    assert code == 0
    assert "證明不必修　  1 筆" in out
    assert "證不出來　　 30 筆" in out
    assert "26 筆　沒有版本證據" in out
    assert "清冊裡一個做法都沒有的：29 筆" in out


def test_a_cleared_finding_is_not_escalated(evidence):
    """被證明不必修的那一筆，不得再被 §9.6 推成 P0。

    跳板那筆同時滿足 KEV、可達、有路徑——如果閘門的結論沒有短路覆寫，
    它會被推到 P0，而那等於把剛剛證明出來的東西丟掉。
    """
    from cve2action.remediation.treatment import Facts, treat

    class Fake:
        asset, cve, tier = "NS-JUMP-01", "CVE-2019-0708", "P1"
        scored, degraded = True, False

    facts = Facts(kev=frozenset({"CVE-2019-0708"}),
                  reachable=frozenset({"NS-JUMP-01"}),
                  has_path=frozenset({"NS-JUMP-01"}),
                  unauthenticated_jewel=frozenset({"NS-JUMP-01"}),
                  evidence=dict(evidence))
    result = treat(Fake(), facts, SNAPS, AS_OF)
    assert result.applicability == NOT_APPLICABLE
    assert result.leaves_queue
    assert result.fired == ()
    assert not result.review_required
    assert "不進 §9.6 覆寫" in result.override_note
