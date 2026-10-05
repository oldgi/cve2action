"""Day 25 的兩份前置資料：版本證據與風險接受。

這個檔**不測適用性閘門**（那是 Day 25 的程式），只測兩件事：

1. **資料本身誠實。** 每一列宣稱的版本關係，都要對得上 `data/snapshots/nvd/` 裡
   真實的 CPE——否則 Day 25 的數字就是在虛構上再疊一層虛構。Northstar 的
   *資產* 是虛構的，*漏洞事實* 不是。
2. **三種判定都構造得出來。** 資料集裡要同時存在「版本在範圍內」「版本在範圍外」
   「判不了」的例子，否則閘門寫完也沒東西可驗——跟 Day 18 的 structural 探針
   同一個道理：沒有那個組合，不代表程式壞了，但也不代表程式對。
"""

from __future__ import annotations

import csv
import json
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "synthetic" / "northstar"
SNAPSHOTS = ROOT / "data" / "snapshots" / "nvd"
# Northstar 情境的基準日，與其他測試一致
AS_OF = date(2026, 9, 24)
# banner 自報的版本不能用來定案：發行版回溯修補後它不會變
UNSETTLEABLE_SOURCES = {"banner"}


def read(name: str) -> list[dict]:
    with (DATA / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def cpe_matches(cve: str) -> list[dict]:
    """快照裡所有標為 vulnerable 的 CPE 比對項。"""
    raw = json.loads((SNAPSHOTS / f"{cve}.json").read_text(encoding="utf-8"))["raw"]
    record = raw.get("vulnerabilities", [{}])[0].get("cve", raw.get("cve", raw))
    found = []
    for config in record.get("configurations") or []:
        for node in config.get("nodes", []):
            found.extend(m for m in node.get("cpeMatch", []) if m.get("vulnerable"))
    return found


def products(cve: str) -> set[str]:
    return {m["criteria"].split(":")[4] for m in cpe_matches(cve)}


@pytest.fixture(scope="module")
def evidence() -> list[dict]:
    return read("version_evidence.csv")


@pytest.fixture(scope="module")
def acceptances() -> list[dict]:
    return read("risk_acceptances.csv")


@pytest.fixture(scope="module")
def findings() -> set[tuple[str, str]]:
    return {(r["asset"], r["cve"]) for r in read("scanner.csv")}


# --- version_evidence.csv ----------------------------------------------------

def test_every_evidence_row_points_at_a_real_finding(evidence, findings):
    for row in evidence:
        assert (row["asset_id"], row["cve"]) in findings, row


def test_evidence_keys_are_unique(evidence):
    keys = [(r["asset_id"], r["cve"]) for r in evidence]
    assert len(keys) == len(set(keys)), "同一筆 finding 兩份版本證據會讓閘門沒有定論"


def test_dates_parse_and_are_not_in_the_future(evidence):
    for row in evidence:
        assert date.fromisoformat(row["verified_at"]) <= AS_OF, row


def test_coverage_is_deliberately_partial(evidence, findings):
    """**大部分 finding 根本沒有版本證據。**

    40 筆裡只有 14 筆查得到裝的是哪一版。這不是資料沒建完，是今天的題目：
    最便宜的處置是證明它不適用，而我們連「裝的是哪一版」都答不出來的時候，
    那條路是走不通的——而且不能因為走不通就當它不適用。
    """
    covered = {(r["asset_id"], r["cve"]) for r in evidence}
    assert len(covered) == 14
    assert len(findings) == 40
    assert len(findings - covered) == 26


# --- 對照真實 CPE ------------------------------------------------------------

def test_the_one_not_applicable_case_is_backed_by_the_snapshot(evidence):
    """CVE-2019-0708 的 CPE 只列 Windows 7／Server 2008／2008 R2。

    跳板裝的是 Server 2019，確實不在裡面——這是整份資料裡唯一一筆
    「版本證明它不適用」。它必須是真的，因為它是文章裡唯一能省下的工。
    """
    row = next(r for r in evidence if r["cve"] == "CVE-2019-0708")
    assert row["asset_id"] == "NS-JUMP-01"
    assert row["version"] == "2019"
    listed = products("CVE-2019-0708")
    # 這筆共列了 67 個產品——大多是內嵌 Windows 的廠商韌體。重點只有兩件事：
    # Microsoft 自家作業系統只到 2008，而 2019 一個都沒有。
    assert {p for p in listed if p.startswith("windows")} == {
        "windows_7", "windows_server_2008"}
    assert "windows_server_2019" not in listed


def test_the_not_applicable_case_does_not_rest_on_a_banner(evidence):
    """能讓 finding 離開佇列的那一筆，來源必須查得到安裝紀錄。"""
    row = next(r for r in evidence if r["cve"] == "CVE-2019-0708")
    assert row["source"] not in UNSETTLEABLE_SOURCES
    assert row["source"] == "agent_inventory"


def test_the_not_applicable_case_measures_the_os_not_the_protocol(evidence):
    """services.csv 記的是 `rdp 10.0`——協定版本答不了這個 CVE 的問題。

    所以證據量的是作業系統。這就是 `version_evidence.csv` 以 (asset, cve) 為鍵、
    而不是靠服務名 join 的理由：該看哪個產品，是判斷，不是字串比對。
    """
    row = next(r for r in evidence if r["cve"] == "CVE-2019-0708")
    assert row["product"] == "windows-server"
    service = next(s for s in read("services.csv")
                   if s["asset_id"] == "NS-JUMP-01" and s["service"] == "rdp")
    assert service["version"] == "10.0"
    assert row["version"] != service["version"]


def test_exact_version_cve_really_lists_exactly_one_version(evidence):
    """CVE-2021-41773 的 CPE 只有 apache http_server 2.4.49 一版，沒有範圍。"""
    matches = [m for m in cpe_matches("CVE-2021-41773")
               if "http_server" in m["criteria"]]
    assert len(matches) == 1
    assert matches[0]["criteria"].split(":")[5] == "2.4.49"
    assert not any(matches[0].get(k) for k in
                   ("versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding"))
    for row in (r for r in evidence if r["cve"] == "CVE-2021-41773"):
        assert row["version"] == "2.4.49"


def test_the_cve_with_no_cpe_at_all_is_in_the_dataset(evidence):
    """CVE-2024-6242 的 configurations 是空的——NVD 沒有給任何版本範圍。

    這不是我們編出來的缺口，是真實資料長這樣。沒有範圍就比不了，
    而比不了必須讀成「判不了」，不能讀成「不適用」。
    """
    assert cpe_matches("CVE-2024-6242") == []
    row = next(r for r in evidence if r["cve"] == "CVE-2024-6242")
    assert row["asset_id"] == "NS-PLC-DC-ENV"
    assert "configurations 是空的" in row["notes"]


def test_the_two_version_scheme_mismatches_are_real(evidence):
    """兩筆「編號體系對不上」不是藉口，CPE 真的是另一套編號。"""
    moveit = next(r for r in evidence if r["cve"] == "CVE-2023-34362")
    transfer = [m["criteria"] for m in cpe_matches("CVE-2023-34362")
                if ":moveit_transfer:" in m["criteria"]]
    assert transfer, "這個 CVE 要有 moveit_transfer 的 CPE，比較才成立"
    bounds = [m.get("versionEndIncluding") or "" for m in cpe_matches("CVE-2023-34362")
              if ":moveit_transfer:" in m["criteria"]]
    assert all(b.startswith(("2021", "2022")) for b in bounds if b)
    assert moveit["version"].startswith("15.0")  # 這是 moveit_cloud 的編號

    exchange = next(r for r in evidence if r["cve"] == "CVE-2021-26855")
    versions = {m["criteria"].split(":")[5] for m in cpe_matches("CVE-2021-26855")}
    assert versions <= {"2013", "2016", "2019"}, "CPE 用年份而非 15.2.x"
    assert exchange["version"].startswith("15.2.")


def test_the_backport_trap_is_a_banner(evidence):
    """openssh 7.4p1 看起來落在 5.9–7.8 裡，但來源是 banner。

    發行版回溯修補之後 banner 不會變，所以這一筆**判不了**，
    不能因為「數字在範圍內」就當它適用，也不能反過來。
    """
    row = next(r for r in evidence if r["cve"] == "CVE-2018-15919")
    assert row["source"] in UNSETTLEABLE_SOURCES
    assert "backport" in row["notes"] or "回溯修補" in row["notes"]


def test_the_stale_evidence_case_exists(evidence):
    """有一筆證據明顯過期——過期的證據不得用來判「不適用」。"""
    stale = [r for r in evidence
             if (AS_OF - date.fromisoformat(r["verified_at"])).days > 30]
    assert stale, "資料集要有過期證據的例子，否則過期這條規則沒東西可驗"
    assert {r["cve"] for r in stale} == {"CVE-2024-6242"}


def test_all_three_verdicts_are_constructible(evidence):
    """三種結局都要有例子：在範圍內、在範圍外、判不了。"""
    settleable = [r for r in evidence if r["source"] not in UNSETTLEABLE_SOURCES]
    assert any(r["cve"] == "CVE-2019-0708" for r in settleable)          # 範圍外
    assert any(r["cve"] == "CVE-2021-41773" for r in settleable)         # 範圍內
    assert any(r["source"] in UNSETTLEABLE_SOURCES for r in evidence)    # 判不了（來源弱）
    assert any(not cpe_matches(r["cve"]) for r in evidence)              # 判不了（沒範圍）


# --- risk_acceptances.csv ----------------------------------------------------

def test_every_acceptance_points_at_a_real_finding(acceptances, findings):
    for row in acceptances:
        assert (row["asset"], row["cve"]) in findings, row


def test_ids_are_unique(acceptances):
    ids = [r["acceptance_id"] for r in acceptances]
    assert len(ids) == len(set(ids))


def test_every_acceptance_carries_all_three_things_9_6_demands(acceptances):
    """藍圖 §9.6：原因、核准人、有效期限。缺一不可。"""
    for row in acceptances:
        assert row["reason"].strip(), row
        assert row["approver"].strip(), row
        assert row["ref"].strip(), row
        assert date.fromisoformat(row["valid_until"])


def test_the_approver_names_a_person(acceptances):
    """「資安部門」不是核准人。具名到人才追得回去。"""
    for row in acceptances:
        assert "（" in row["approver"] and "）" in row["approver"], (
            f"{row['acceptance_id']} 的核准人要寫成「姓名（職稱）」：{row['approver']}"
        )


def test_the_dataset_has_an_effective_an_expired_and_a_revoked_one(acceptances):
    """三種狀態都要有，否則 Day 25 的覆寫規則沒東西可驗。"""
    def effective(row):
        return (row["status"] == "APPROVED"
                and date.fromisoformat(row["valid_until"]) >= AS_OF)

    assert [r["acceptance_id"] for r in acceptances if effective(r)] == [
        "ACC-001", "ACC-002"]
    expired = [r for r in acceptances if r["status"] == "APPROVED"
               and date.fromisoformat(r["valid_until"]) < AS_OF]
    assert [r["acceptance_id"] for r in expired] == ["ACC-003"]
    assert [r["acceptance_id"] for r in acceptances if r["status"] == "REVOKED"] == [
        "ACC-004"]


def test_an_expired_acceptance_is_not_an_acceptance(acceptances):
    """ACC-003 還掛著 APPROVED，但日期已過。

    狀態欄寫 APPROVED 不等於現在有效——與 Day 23 的豁免到期是同一條紀律：
    寫了日期卻沒有人比對，等於永久赦免。
    """
    row = next(r for r in acceptances if r["acceptance_id"] == "ACC-003")
    assert row["status"] == "APPROVED"
    assert date.fromisoformat(row["valid_until"]) < AS_OF
