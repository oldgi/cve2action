"""番外篇二：控制適用性的第二條軸線——這項控制懂不懂這一類弱點。

Day 15 問的是「攔截點在不在這條攻擊路徑上」，用 CVSS 的 AV 與 PR 回答。
那是一條軸線，而且它答不了另一個問題：WAF 檢查 HTTP，TLS 交握發生在它下面。

缺的那條軸線一直在資料裡——NVD 快照的 `raw.weaknesses` 從 Day 7 起就抓回來了，
`extracted` 投影從來沒把它取出來。

## 這個檔鎖住的主張

**沉默不移動判定。** 第二條軸線只能憑證據否決，不能憑沉默否決。
拿不到 CWE 時它什麼都不說，前一條軸線憑證據得到的結論原封不動。

這不是「UNKNOWN 不得降低風險」的例外：那條講的是缺資料不得換來比較**安全**的
結論，而沉默在這裡換到的是**不變**。它就是 Day 25「空清單不是證據」的同一條。

反過來說才是陷阱：如果每條新軸線都把「沒資料」讀成「不得折減」，那麼每加一條
軸線就剝掉一批折減，最後沒有任何補償控制拿得到分。**那不是保守，是棘輪。**
"""

from __future__ import annotations

import csv
import json
from datetime import date
from pathlib import Path

import pytest
import yaml

from cve2action.collectors.epss import load_snapshots as load_epss
from cve2action.collectors.kev import load_catalog
from cve2action.collectors.nvd import load_snapshots
from cve2action.io import read_asset_context, read_scanner
from cve2action.normalization.control import (
    APPLICABLE,
    NOT_APPLICABLE,
    ControlRulesError,
    applicability,
    parse_attack,
    parse_control_rules,
)
from cve2action.rules import load_rules
from cve2action.scoring import rank_explained

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "synthetic" / "northstar"
SNAPS = ROOT / "data" / "snapshots" / "nvd"
AS_OF = date(2026, 9, 24)
RC4 = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"


@pytest.fixture(scope="module")
def production():
    return load_rules(ROOT / "config/risk_rules.yaml")


@pytest.fixture(scope="module")
def frozen():
    return load_rules(ROOT / "config/risk_rules.v0.1.yaml")


def _controls() -> list[dict]:
    with (DATA / "controls.csv").open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def _rank(rules) -> dict[tuple[str, str], object]:
    return {(e.asset, e.cve): e for e in rank_explained(
        read_scanner(DATA / "scanner.csv"), read_asset_context(DATA / "asset_context.csv"),
        rules, load_snapshots(SNAPS), load_epss(ROOT / "data/snapshots/epss"),
        load_catalog(ROOT / "data/snapshots/kev"), _controls(), AS_OF)}


# --- ① CWE 進了投影，raw 不動 ------------------------------------------------

def test_cwe_is_projected_from_raw_not_invented():
    """`extracted` 是投影，`raw` 是唯一真相（Day 7）。"""
    document = json.loads((SNAPS / "CVE-2013-2566.json").read_text(encoding="utf-8"))
    assert document["extracted"]["weaknesses"] == ["CWE-326", "CWE-327"]
    record = document["raw"].get("vulnerabilities", [{}])[0].get(
        "cve", document["raw"].get("cve", document["raw"]))
    from_raw = {d["value"] for w in record["weaknesses"] for d in w["description"]
                if d["value"].startswith("CWE-")}
    assert from_raw == {"CWE-326", "CWE-327"}


def test_a_cve_with_no_cwe_projects_an_empty_list_not_a_missing_key():
    """空清單與欄位不存在是兩件事。空的代表 NVD 沒說，而那是要能讀出來的事實。"""
    document = json.loads((SNAPS / "CVE-2021-34527.json").read_text(encoding="utf-8"))
    assert "weaknesses" in document["extracted"]
    assert document["extracted"]["weaknesses"] == []


def test_four_of_the_dataset_cves_have_no_cwe_at_all():
    snapshots = load_snapshots(SNAPS)
    missing = sorted(c for c, r in snapshots.items() if not r.weaknesses)
    assert missing == ["CVE-2017-0144", "CVE-2020-1472", "CVE-2020-1938", "CVE-2021-34527"]


# --- ② 第二條軸線只否決，不批准 ----------------------------------------------

def test_the_second_axis_withdraws_a_control_that_is_blind_to_the_class(production):
    verdict, why = applicability("waf", parse_attack(RC4), production.controls,
                                 ("CWE-326", "CWE-327"))
    assert verdict == NOT_APPLICABLE
    assert "blind to CWE-326/CWE-327" == why


def test_silence_does_not_move_the_verdict(production):
    """同一筆攻擊，沒有 CWE 時結果必須與 Day 15 完全一樣。"""
    without = applicability("waf", parse_attack(RC4), production.controls, ())
    assert without == (APPLICABLE, "applies to AV:NETWORK")


def test_an_unlisted_cwe_does_not_grant_applicability(production):
    """沒列進 blind_to_weaknesses 不代表「看得到」，只代表沒有理由說它看不到。

    所以結果仍由第一條軸線決定——第二條軸線不會把 NOT_APPLICABLE 翻成 APPLICABLE。
    """
    local = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    verdict, why = applicability("waf", parse_attack(local), production.controls,
                                 ("CWE-22",))
    assert verdict == NOT_APPLICABLE
    assert "AV:LOCAL" in why


def test_the_first_axis_still_runs_when_the_second_says_nothing(production):
    zerologon = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    verdict, why = applicability("mfa_admin_tiering", parse_attack(zerologon),
                                 production.controls, ())
    assert verdict == NOT_APPLICABLE
    assert "PR:NONE" in why


# --- ③ 設定檔驗證 -------------------------------------------------------------

def test_malformed_cwe_entries_are_rejected():
    with pytest.raises(ControlRulesError, match="blind_to_weaknesses"):
        parse_control_rules({"applicability": {
            "waf": {"attack_vectors": ["NETWORK"], "blind_to_weaknesses": ["TLS-stuff"]}}})


def test_blind_to_weaknesses_must_be_a_list():
    with pytest.raises(ControlRulesError, match="blind_to_weaknesses"):
        parse_control_rules({"applicability": {
            "waf": {"attack_vectors": ["NETWORK"], "blind_to_weaknesses": "CWE-326"}}})


def test_the_axis_is_optional_so_older_configs_still_load(frozen):
    """`risk_rules.v0.1.yaml` 沒有宣告這一節，載入後等同於「這條軸線不存在」。"""
    for scope in frozen.controls.applicability.values():
        assert scope.blind_to_weaknesses == frozenset()


def test_only_production_declares_the_axis():
    """已發表數字靠凍結檔重現，所以那個檔不准宣告這一節。"""
    for name in ("risk_rules.v0.1.yaml", "risk_rules.geometric.yaml"):
        text = (ROOT / "config" / name).read_text(encoding="utf-8")
        assert "blind_to_weaknesses" not in text, f"{name} 不得宣告第二條軸線"
    current = yaml.safe_load((ROOT / "config/risk_rules.yaml").read_text(encoding="utf-8"))
    assert current["controls"]["applicability"]["waf"]["blind_to_weaknesses"] == [
        "CWE-326", "CWE-327", "CWE-310"]


# --- ④ 實測：撤回兩筆，其餘不動 -----------------------------------------------

def test_exactly_two_discounts_are_withdrawn(production):
    withdrawn = {k for k, e in _rank(production).items()
                 if e.factor("exposure") and "blind to" in (e.factor("exposure").source or "")}
    assert withdrawn == {("NS-WEB-PORTAL-01", "CVE-2013-2566"),
                         ("NS-API-GW-01", "CVE-2016-2107")}


def test_printnightmare_keeps_its_discount(production):
    """CVE-2021-34527 在 NVD 沒有 CWE。沉默不動，所以 MFA 的折減留著。

    這一筆是整個設計的試金石：如果「沒資料」會撤回折減，Day 15 已發表的
    那張對照表（Zerologon 撤銷 9.00 對 PrintNightmare 保留 7.68）就當場失效。
    """
    row = _rank(production)[("NS-AD-DC-01", "CVE-2021-34527")]
    source = row.factor("exposure").source
    assert "blind to" not in source
    assert "mfa_admin_tiering" in source
    assert row.factor("exposure").inputs["control"] == "STRONG"


# --- ⑤ 已發表數字原封不動 ------------------------------------------------------

def test_every_published_number_still_reproduces(frozen):
    """Day 15 與 Day 16 引用過的四個數字，用凍結檔必須一字不差。"""
    rows = _rank(frozen)
    assert rows[("NS-AD-DC-01", "CVE-2020-1472")].score == 9.0      # Day 15：Zerologon
    assert rows[("NS-AD-DC-01", "CVE-2021-34527")].score == 7.68    # Day 15：PrintNightmare
    assert rows[("NS-WEB-PORTAL-01", "CVE-2013-2566")].score == 7.01  # Day 16：RC4
    assert rows[("NS-APP-REPORT-01", "CVE-2020-1938")].score == 7.43  # Day 16：前一名


def test_the_published_band_distribution_is_untouched(frozen):
    from collections import Counter

    bands = Counter(e.band for e in _rank(frozen).values() if e.scored)
    assert dict(bands) == {"Critical": 9, "High": 24, "Medium": 5}
