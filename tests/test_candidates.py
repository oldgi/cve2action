"""Day 26：候選措施引擎。

三個主張在這裡被鎖住：

1. **先做與結案是兩個問題。** 緩解做完不等於修補完成（藍圖 §20.1）；
   只有 patch 算結案，config_change 要重掃才算，其餘漏洞都還在。
2. **成本不明不是零。** 不知道工時的措施排最後，不是最前；
   一個候選都沒有的 finding 不進任何成本比較。
3. **補償控制要先過番外篇二的閘。** 證據說攔不到就否決；
   沒資料就不否決，但也不優先選它。
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from cve2action.collectors.nvd import load_snapshots
from cve2action.normalization.control import APPLICABLE, NOT_APPLICABLE, UNDECIDABLE
from cve2action.remediation.candidates import (
    CLOSES,
    MOOT,
    NO_CANDIDATE,
    PLANNED,
    RESCAN_REQUIRED,
    STAYS_OPEN,
    CandidateError,
    Weakness,
    build_candidates,
    plan,
)
from cve2action.remediation.treatment import Treatment
from cve2action.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "synthetic" / "northstar"
SNAPS = str(ROOT / "data" / "snapshots" / "nvd")


def read(name: str) -> list[dict]:
    with (DATA / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


@pytest.fixture(scope="module")
def rules():
    return load_rules(ROOT / "config" / "risk_rules.yaml")


@pytest.fixture(scope="module")
def weaknesses(rules) -> dict[str, Weakness]:
    out = {}
    for cve, record in load_snapshots(SNAPS).items():
        chosen = record.cvss.preferred(rules.cvss_version_preference)
        out[cve.upper()] = Weakness(chosen.vector if chosen else None,
                                    tuple(record.weaknesses or ()))
    return out


@pytest.fixture(scope="module")
def candidates(rules, weaknesses):
    return build_candidates(read("remediations.csv"), weaknesses, read("controls.csv"),
                            rules.controls)


def treatment(asset: str, cve: str, tier: str = "P0",
              applicability: str = "APPLICABLE") -> Treatment:
    return Treatment(asset=asset, cve=cve, applicability=applicability,
                     applicability_reason="", tier=tier, tier_before=tier,
                     review_required=False)


def row(**overrides) -> dict:
    base = {"remediation_id": "REM-T", "asset": "NS-X", "cve": "CVE-2021-44228",
            "action": "patch", "effort_hours": "2", "downtime_minutes": "10",
            "compatibility": "none", "notes": ""}
    base.update(overrides)
    return base


# --- 先做與結案 --------------------------------------------------------------

def test_mitigation_goes_first_and_patch_closes(candidates):
    """路由器：關 WebUI 一小時零停機先做，patch 排窗口才算結案。"""
    result = plan(treatment("NS-EDGE-RTR-01", "CVE-2023-20198"), candidates)
    assert result.status == PLANNED
    assert result.first.action == "disable_service"
    assert result.close.action == "patch"
    assert result.first_is_not_close


def test_only_patch_closes_and_config_change_needs_a_rescan(candidates):
    by_action = {c.action: c.closure for c in candidates}
    assert by_action["patch"] == CLOSES
    assert by_action["config_change"] == RESCAN_REQUIRED
    for action in ("isolate", "disable_service", "compensating_control"):
        assert by_action[action] == STAYS_OPEN


def test_a_finding_with_only_mitigations_is_not_closable(candidates):
    """實驗室 Confluence 只有隔離一條路：做完了，finding 還開著。"""
    result = plan(treatment("NS-LAB-CONFLUENCE-01", "CVE-2022-26134", "P2"), candidates)
    assert result.first.action == "isolate"
    assert result.close is None
    assert result.closure == STAYS_OPEN
    assert not result.first_is_not_close


def test_rc4_is_closable_only_after_a_rescan(candidates):
    result = plan(treatment("NS-WEB-PORTAL-01", "CVE-2013-2566", "P1"), candidates)
    assert result.close is None
    assert result.closure == RESCAN_REQUIRED


# --- 成本與限制 --------------------------------------------------------------

def test_zero_downtime_is_not_zero_cost(candidates):
    """MOVEit 的隔離不停機、工時也比較少，但會斷掉合作夥伴上傳——要簽核。

    沒有限制的 patch 排在它前面。停機分鐘只是成本的一種。
    """
    result = plan(treatment("NS-APP-BILLING-01", "CVE-2023-34362"), candidates)
    isolate = next(c for c in result.candidates if c.action == "isolate")
    assert isolate.downtime_minutes == 0 and isolate.needs_signoff
    assert result.first.action == "patch"


def test_unknown_cost_is_none_not_zero(rules):
    [cand] = build_candidates([row(effort_hours="", downtime_minutes="")], {}, [],
                              rules.controls)
    assert cand.effort_hours is None and cand.downtime_minutes is None
    assert not cand.cost_known


def test_unknown_cost_sorts_last_not_first(rules):
    """把不知道當成零，它就會永遠第一個被選。"""
    cands = build_candidates([
        row(remediation_id="KNOWN", action="patch", effort_hours="8",
            downtime_minutes="120"),
        row(remediation_id="UNKNOWN", action="config_change", effort_hours="",
            downtime_minutes=""),
    ], {}, [], rules.controls)
    result = plan(treatment("NS-X", "CVE-2021-44228"), cands)
    assert result.first.remediation_id == "KNOWN"


def test_unknown_action_is_an_error_not_a_skip(rules):
    with pytest.raises(CandidateError):
        build_candidates([row(action="reboot_and_pray")], {}, [], rules.controls)


# --- 補償控制要過番外篇二的閘 ------------------------------------------------

def test_compensating_waf_for_log4shell_is_offered(candidates):
    result = plan(treatment("NS-API-GW-01", "CVE-2021-44228"), candidates)
    comp = next(c for c in result.candidates if c.action == "compensating_control")
    assert comp.effect == APPLICABLE
    assert result.first is comp
    assert result.close.action == "patch"


def test_compensating_control_without_a_registered_control_is_undecidable(candidates):
    """監控主機沒有登記任何控制：不知道補償的是哪一種，就不能說它攔得到。

    但也不否決——沉默不移動判定。它仍是唯一的選項，只是標記效果待證。
    """
    result = plan(treatment("NS-MON-01", "CVE-2021-44228", "P1"), candidates)
    [comp] = result.candidates
    assert comp.effect == UNDECIDABLE
    assert not comp.rejected
    assert result.first is comp


def test_a_control_blind_to_the_weakness_is_rejected(rules, weaknesses):
    """WAF 看不到 TLS 層：拿 WAF 當 RC4 的補償控制，憑證據否決。"""
    cands = build_candidates(
        [row(asset="NS-WEB-PORTAL-01", cve="CVE-2013-2566",
             action="compensating_control")],
        weaknesses, read("controls.csv"), rules.controls)
    [comp] = cands
    assert comp.effect == NOT_APPLICABLE and comp.rejected
    result = plan(treatment("NS-WEB-PORTAL-01", "CVE-2013-2566", "P1"), cands)
    assert result.status == NO_CANDIDATE
    assert result.first is None


# --- 沒有候選、不必修 --------------------------------------------------------

def test_no_candidate_is_not_invented(candidates):
    """清冊裡沒有的，引擎不替它編一個 patch——那等於假裝知道成本。"""
    result = plan(treatment("NS-VPN-GW-01", "CVE-2024-21762"), candidates)
    assert result.status == NO_CANDIDATE
    assert result.candidates == ()
    assert result.first is None and result.close is None


def test_a_cleared_finding_needs_no_plan(candidates):
    """跳板的 BlueKeep 已證明不必修；登記的 NLA 用不到。"""
    result = plan(treatment("NS-JUMP-01", "CVE-2019-0708", "",
                            applicability="NOT_APPLICABLE"), candidates)
    assert result.status == MOOT
    assert result.first is None
    assert [c.remediation_id for c in result.candidates] == ["REM-013"]


# --- 端到端 ------------------------------------------------------------------

def _cli_args(command: str) -> list[str]:
    return [
        command,
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
    ]


def test_cli_candidates_reports_the_article_numbers(capsys):
    from cve2action.cli import main as cli_main

    assert cli_main(_cli_args("candidates")) == 0
    out = capsys.readouterr().out
    assert "候選措施（15 項，對應 11 筆 finding；共 40 筆）" in out
    assert "先做與結案不是同一項　  3 筆" in out
    assert "先做的那一項要人簽核　  4 筆" in out
    assert "做完仍無法結案　　　　  2 筆　＋待重掃 1 筆" in out
    assert "補償控制　適用 1／否決 0／無從判斷 1" in out
    assert "工時 16 h，停機 150 分鐘" in out
    assert "REM-013" in out
    assert "一個候選都沒有的：29 筆" in out


def test_treat_counts_only_real_raises(capsys):
    """Day 25 更正：已證明不必修的那筆層級變成空白，那是離開佇列，不是升級。

    Day 25 把它算進「被推上去」，發表成 16 筆、P0 變 25；實際是 15 筆、P0 變 24。
    """
    from cve2action.cli import _treatments, build_parser

    treatments, code = _treatments(build_parser().parse_args(_cli_args("treat")))
    assert code == 0
    assert sum(1 for t in treatments if t.tier == "P0") == 24
    assert sum(1 for t in treatments if t.tier_before == "P0") == 9

    from cve2action.cli import main as cli_main
    capsys.readouterr()
    assert cli_main(_cli_args("treat")) == 0
    assert "§9.6 覆寫：15 筆層級被推上去" in capsys.readouterr().out

