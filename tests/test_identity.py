"""Day 21：身分邊的前提條件（藍圖 §10「權限前置條件明確」）。

鎖住三件事：
1. 「打完拿到什麼權限」是**記錄**的，不是從 CVSS 推的。
2. 憑證不在機器上時，權限再高也拿不到。
3. `UNPROVEN` 不擋路——不能證明走不通，就得當它走得通。
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from cve2action.attack_graph import build_graph
from cve2action.attack_graph.identity import (
    BLOCKED,
    NO_EVIDENCE,
    SATISFIED,
    UNPROVEN,
    Obtainable,
    annotate,
    check,
    privilege_obtainable,
)
from cve2action.attack_graph.paths import find_paths
from cve2action.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "synthetic" / "northstar"


def read(name: str) -> list[dict]:
    with (DATA / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


@pytest.fixture(scope="module")
def vectors() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in sorted((ROOT / "data" / "snapshots" / "nvd").glob("CVE-*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        extracted = payload.get("extracted", payload)
        cve = (extracted.get("cve_id") or path.stem).upper()
        for score in extracted.get("scores", []):
            if score.get("version") == "3.1" and score.get("vector"):
                found[cve] = score["vector"]
                break
    return found


@pytest.fixture(scope="module")
def annotated(vectors):
    graph = build_graph(read("assets.csv"), read("asset_interfaces.csv"),
                        read("services.csv"), read("network_edges.csv"),
                        read("identity_edges.csv"))
    counts = annotate(graph, read("identity_edges.csv"), read("services.csv"),
                      read("scanner.csv"), vectors)
    return graph, counts


# --- 權限是記錄的，不是推的 -------------------------------------------------

def test_the_privilege_obtained_comes_from_the_service_record(vectors):
    """BlueKeep 打的是 RDP，而 RDP 的 runs_as 記錄為 local_admin。

    這條鏈不能從 CVSS 推出來：PR 說的是「需要什麼權限」，不是「拿到什麼權限」。
    """
    result = privilege_obtainable("NS-JUMP-01", read("services.csv"),
                                  read("scanner.csv"), vectors)
    assert result.level == "local_admin" and result.proven


def test_an_asset_with_no_matchable_finding_yields_no_evidence(vectors):
    """40 筆 finding 只有 15 筆對得上已登錄的服務。對不上就不猜。"""
    result = privilege_obtainable("NS-OPS-WS-07", read("services.csv"),
                                  read("scanner.csv"), vectors)
    assert result.basis == NO_EVIDENCE and not result.proven


def test_a_local_privilege_escalation_lifts_a_service_identity_to_admin(vectors):
    """AV:L 的提權漏洞讓服務身分升到 local_admin。"""
    result = privilege_obtainable("NS-APP-BILLING-01", read("services.csv"),
                                  read("scanner.csv"), vectors)
    assert result.level == "local_admin"
    assert "CVE-2021-3156" in result.detail


# --- 憑證不在機器上，權限再高也沒用 -----------------------------------------

def test_a_sealed_credential_is_blocked_at_any_privilege():
    edge = {"requires_privilege": "interactive_logon",
            "credential_source": "sealed_credential"}
    result = check(edge, Obtainable("domain_admin", "from_service"))
    assert result.status == BLOCKED
    assert "不在來源機器上" in result.reason


def test_insufficient_privilege_is_blocked_with_both_numbers():
    edge = {"requires_privilege": "local_admin", "credential_source": "memory"}
    result = check(edge, Obtainable("local_service", "from_service"))
    assert result.status == BLOCKED
    assert result.required == "local_admin" and result.obtained == "local_service"


def test_enough_privilege_satisfies():
    edge = {"requires_privilege": "local_service", "credential_source": "config_file"}
    assert check(edge, Obtainable("local_admin", "from_service")).status == SATISFIED


# --- 未知不擋路 -------------------------------------------------------------

def test_unproven_is_not_blocked():
    """不能證明走不通，就得當它走得通——Day 5 以來同一條規則。"""
    edge = {"requires_privilege": "local_admin", "credential_source": "memory"}
    result = check(edge, Obtainable("none", NO_EVIDENCE, "沒有證據"))
    assert result.status == UNPROVEN
    assert result.traversable


def test_an_edge_without_a_recorded_precondition_is_unproven():
    assert check({}, Obtainable("local_admin", "from_service")).status == UNPROVEN


# --- 套到 Northstar 上 ------------------------------------------------------

def test_the_numbers_the_article_quotes(annotated):
    _graph, counts = annotated
    assert counts == {SATISFIED: 5, UNPROVEN: 4, BLOCKED: 1}
    assert sum(counts.values()) == 10


def test_the_blocked_one_is_the_break_glass_credential(annotated):
    graph, _counts = annotated
    blocked = [e for e in graph.edges if e.attrs.get("precondition") == BLOCKED]
    assert len(blocked) == 1
    assert blocked[0].target == "NS-AD-DC-01"
    assert "sealed_credential" in blocked[0].attrs["precondition_reason"]


def test_sealing_one_credential_removes_only_one_path(annotated):
    """旁邊那條 adm_domain 的憑證就放在記憶體裡——把最嚴格的鎖好，
    不會讓隔壁那條變安全。"""
    graph, _counts = annotated
    jewels = sorted(n.id for n in graph.crown_jewels)
    ungated = sum(len(find_paths(graph, j, gated=False)) for j in jewels)
    gated = sum(len(find_paths(graph, j, gated=True)) for j in jewels)
    assert (ungated, gated) == (31, 30)
    assert len(find_paths(graph, "NS-AD-DC-01")) == 3


def test_the_domain_admin_chain_is_three_hops(annotated):
    """VPN → 跳板（BlueKeep 給 local_admin）→ 網域控制器。"""
    graph, _counts = annotated
    through_jump = [p for p in find_paths(graph, "NS-AD-DC-01")
                    if "NS-JUMP-01" in p.assets]
    assert through_jump
    shortest = min(through_jump, key=lambda p: p.length)
    assert shortest.assets == ("internet", "NS-VPN-GW-01", "NS-JUMP-01", "NS-AD-DC-01")


def test_blocked_edges_stay_in_the_graph(annotated):
    """邊留著：它記錄的是真實存在的權限關係，只是現在走不過去。
    拿掉它，之後這台多一個提權漏洞時就沒人想得起這條路。"""
    graph, _counts = annotated
    grants = [e for e in graph.edges if e.kind == "grants"]
    assert len(grants) == 10


# --- CLI --------------------------------------------------------------------

def test_cli_graph_reports_the_preconditions(capsys):
    code = cli_main([
        "graph",
        "--assets", str(DATA / "assets.csv"),
        "--interfaces", str(DATA / "asset_interfaces.csv"),
        "--services", str(DATA / "services.csv"),
        "--network", str(DATA / "network_edges.csv"),
        "--identity", str(DATA / "identity_edges.csv"),
        "--findings", str(DATA / "scanner.csv"),
        "--snapshots", str(ROOT / "data" / "snapshots" / "nvd"),
    ])
    out = capsys.readouterr().out
    assert code == 0
    assert "SATISFIED 5" in out and "UNPROVEN 4" in out and "BLOCKED 1" in out
    assert "sealed_credential" in out
