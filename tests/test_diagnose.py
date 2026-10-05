"""Day 22：找到路徑，以及查無路徑時說得出為什麼。

藍圖 §16 Day 24 門檻寫了「無法到達的資產不會被誤標為可達」。
反過來那半句沒寫但更容易出事：**可達的資產不應該被誤標為安全。**
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from cve2action.attack_graph import (
    ASSET,
    BLOCKED_BY_POLICY,
    EXCLUDED,
    NO_INBOUND,
    REACHABLE,
    SOURCE_UNREACHABLE,
    build_graph,
    coverage,
    diagnose,
    find_paths,
    render_coverage,
)
from cve2action.attack_graph.identity import annotate as identity_annotate
from cve2action.attack_graph.reachability import annotate as reach_annotate
from cve2action.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "synthetic" / "northstar"


def read(name: str) -> list[dict]:
    with (DATA / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


@pytest.fixture(scope="module")
def graph():
    vectors = {}
    for path in sorted((ROOT / "data" / "snapshots" / "nvd").glob("CVE-*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        extracted = payload.get("extracted", payload)
        cve = (extracted.get("cve_id") or path.stem).upper()
        for score in extracted.get("scores", []):
            if score.get("version") == "3.1" and score.get("vector"):
                vectors[cve] = score["vector"]
                break
    built = build_graph(read("assets.csv"), read("asset_interfaces.csv"),
                        read("services.csv"), read("network_edges.csv"),
                        read("identity_edges.csv"))
    reach_annotate(built, read("network_edges.csv"), read("network_policies.csv"),
                   {a["asset_id"]: a["zone"] for a in read("assets.csv")})
    identity_annotate(built, read("identity_edges.csv"), read("services.csv"),
                      read("scanner.csv"), vectors)
    return built


@pytest.fixture(scope="module")
def reachable(graph) -> set[str]:
    return {n.id for n in graph.of_kind(ASSET) if find_paths(graph, n.id)}


# --- 覆蓋狀況 ---------------------------------------------------------------

def test_the_numbers_the_article_quotes(graph, reachable):
    result = coverage(graph, reachable)
    assert len(result.reachable) == 14
    assert len(result.unreached) == 6
    assert result.counts[NO_INBOUND] == 6


def test_not_one_of_the_six_is_actually_blocked(graph, reachable):
    """六台「查無路徑」沒有一台是被擋住的——全部是清冊裡沒有指向它的連線。"""
    result = coverage(graph, reachable)
    assert result.genuinely_blocked == ()
    assert all(not item.means_safe for item in result.unreached)


def test_no_inbound_says_it_is_a_data_gap(graph, reachable):
    result = diagnose(graph, "NS-APP-INTRANET-01", reachable)
    assert result.status == NO_INBOUND
    assert any("資料缺口" in line for line in result.evidence)


def test_a_reachable_asset_reports_reachable(graph, reachable):
    assert diagnose(graph, "NS-DB-CUSTOMER-01", reachable).status == REACHABLE


def test_render_says_how_many_are_genuinely_blocked(graph, reachable):
    text = render_coverage(coverage(graph, reachable))
    assert "有路徑 14 台、查無路徑 6 台" in text
    assert "真的算「被擋住」的：0 台" in text


# --- 另外三種判定（資料集沒有，用合成輸入測） -------------------------------

def _tiny(network: list[dict], identity: list[dict] | None = None):
    assets = [{"asset_id": "A", "hostname": "a", "zone": "DMZ", "crown_jewel": "no"},
              {"asset_id": "B", "hostname": "b", "zone": "APP", "crown_jewel": "no"}]
    interfaces = [{"asset_id": a["asset_id"], "ip": f"10.0.0.{i}", "hostname": a["hostname"],
                   "mac": f"aa:{i}", "interface_type": "service"}
                  for i, a in enumerate(assets, start=1)]
    services = [{"asset_id": "B", "port": "80", "protocol": "tcp", "service": "http",
                 "version": "1", "state": "listening", "runs_as": "local_service"},
                {"asset_id": "A", "port": "443", "protocol": "tcp", "service": "https",
                 "version": "1", "state": "listening", "runs_as": "local_service"}]
    return build_graph(assets, interfaces, services, network, identity or [])


def test_an_edge_denied_by_policy_reads_as_blocked():
    graph = _tiny([{"source": "A", "target": "B", "port": "80", "protocol": "tcp",
                    "allowed": "no"}])
    result = diagnose(graph, "B", reachable=set())
    assert result.status == BLOCKED_BY_POLICY
    assert result.means_safe


def test_an_unreachable_source_is_not_the_same_as_blocked():
    """B 有入邊，但 A 自己到不了。這不是「被擋住」。"""
    graph = _tiny([{"source": "A", "target": "B", "port": "80", "protocol": "tcp",
                    "allowed": "yes"}])
    result = diagnose(graph, "B", reachable=set())
    assert result.status == SOURCE_UNREACHABLE
    assert not result.means_safe
    assert "A 自己也沒有路徑" in result.evidence[0]


def test_a_service_that_is_not_listening_shows_up_as_excluded():
    graph = _tiny([{"source": "INTERNET", "target": "B", "port": "8080",
                    "protocol": "tcp", "allowed": "yes"}])
    result = diagnose(graph, "B", reachable=set())
    assert result.status == EXCLUDED
    assert "沒有登錄任何服務" in result.evidence[0]


# --- CLI --------------------------------------------------------------------

def _argv(*extra: str) -> list[str]:
    return [
        "path",
        "--assets", str(DATA / "assets.csv"),
        "--interfaces", str(DATA / "asset_interfaces.csv"),
        "--services", str(DATA / "services.csv"),
        "--network", str(DATA / "network_edges.csv"),
        "--identity", str(DATA / "identity_edges.csv"),
        "--policies", str(DATA / "network_policies.csv"),
        "--findings", str(DATA / "scanner.csv"),
        "--snapshots", str(ROOT / "data" / "snapshots" / "nvd"), *extra,
    ]


def test_cli_path_shows_one_path_and_says_how_many_more(capsys):
    assert cli_main(_argv("--to", "NS-DB-CUSTOMER-01")) == 0
    out = capsys.readouterr().out
    assert "共 11 條路徑" in out
    assert "另有 10 條路徑共用其中的節點" in out
    assert out.count("INTERNET\n") == 1, "預設只展開一條"


def test_cli_path_all_expands_every_path(capsys):
    assert cli_main(_argv("--to", "NS-DB-CUSTOMER-01", "--all")) == 0
    assert capsys.readouterr().out.count("INTERNET\n") == 11


def test_cli_path_without_target_prints_coverage(capsys):
    assert cli_main(_argv()) == 0
    assert "查無路徑 6 台" in capsys.readouterr().out


def test_cli_path_explains_a_missing_path(capsys):
    assert cli_main(_argv("--to", "NS-PLC-DC-ENV")) == 0
    out = capsys.readouterr().out
    assert NO_INBOUND in out and "資料缺口" in out
