"""資料契約：committed 的 CSV 必須符合 data/schemas/ 宣告的內容。

包含反向測試——契約抓不到違規的話，它就只是一份會過期的文件。
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

from cve2action.cli import main as cli_main
from cve2action.models import OUTPUT_COLUMNS

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "data" / "schemas"
NORTHSTAR = ROOT / "data/synthetic/northstar"


def _load_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_schemas", ROOT / "scripts" / "validate_schemas.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["validate_schemas"] = module
    spec.loader.exec_module(module)
    return module


validator = _load_validator()


def schema(name: str) -> dict:
    return yaml.safe_load((SCHEMA_DIR / f"{name}.schema.yaml").read_text(encoding="utf-8"))


# --- 契約本身的形狀 ---------------------------------------------------------

@pytest.mark.parametrize("name", sorted(p.name.removesuffix(".schema.yaml")
                                        for p in SCHEMA_DIR.glob("*.schema.yaml")))
def test_every_schema_declares_the_keys_the_readme_promises(name):
    data = schema(name)
    assert {"file", "version", "columns"} <= set(data)
    assert data["columns"], "契約不能沒有欄位"
    for column in data["columns"]:
        assert {"name", "required", "blank_ok"} <= set(column), column
        if "domain" in column:
            assert isinstance(column["domain"], list) and column["domain"]


def test_committed_data_matches_its_contract():
    assert validator.validate() == []


# --- 反向測試：契約真的抓得到違規 -------------------------------------------

def _copy_with(tmp_path: Path, source: Path, transform) -> Path:
    lines = source.read_text(encoding="utf-8").splitlines()
    target = tmp_path / source.name
    target.write_text("\n".join(transform(lines)) + "\n", encoding="utf-8")
    return target


def test_out_of_domain_value_is_caught(tmp_path):
    broken = _copy_with(tmp_path, NORTHSTAR / "controls.csv",
                        lambda ls: [ls[0]] + [ls[1].replace(",STRONG,", ",VERY_STRONG,")] + ls[2:])
    problems = validator.check_file(schema("controls"), broken)
    assert any("VERY_STRONG" in p for p in problems), problems


def test_blank_in_a_must_not_be_blank_column_is_caught(tmp_path):
    header = (NORTHSTAR / "controls.csv").read_text(encoding="utf-8").splitlines()[0]
    broken = tmp_path / "controls.csv"
    broken.write_text(header + "\nNS-X-01,waf,STRONG,tested,\n", encoding="utf-8")
    problems = validator.check_file(schema("controls"), broken)
    assert any("verified_at" in p and "blank" in p for p in problems), problems


def test_undeclared_column_is_caught(tmp_path):
    broken = _copy_with(tmp_path, NORTHSTAR / "scanner.csv",
                        lambda ls: [ls[0] + ",surprise"] + [line + ",x" for line in ls[1:]])
    problems = validator.check_file(schema("scanner"), broken)
    assert any("surprise" in p for p in problems), problems


def test_missing_required_column_is_caught(tmp_path):
    broken = _copy_with(
        tmp_path, NORTHSTAR / "assets.csv",
        lambda ls: [line.rsplit(",", 1)[0] for line in ls])  # 砍掉 owner_team
    problems = validator.check_file(schema("assets"), broken)
    assert any("owner_team" in p for p in problems), problems


# --- 輸出契約 ---------------------------------------------------------------

def test_ranked_result_contract_matches_the_code_and_a_real_run(tmp_path):
    """契約的欄位順序必須與 OUTPUT_COLUMNS 相同，而且真的跑出來要過得了自己的契約。"""
    declared = [c["name"] for c in schema("ranked_result")["columns"]]
    assert declared == list(OUTPUT_COLUMNS)

    out = tmp_path / "ranked_result.csv"
    assert cli_main([
        "rank",
        "--scanner", str(NORTHSTAR / "scanner.csv"),
        "--context", str(NORTHSTAR / "asset_context.csv"),
        "--rules", str(ROOT / "config/risk_rules.v0.1.yaml"),
        "--snapshots", str(ROOT / "data/snapshots/nvd"),
        "--epss", str(ROOT / "data/snapshots/epss"),
        "--kev", str(ROOT / "data/snapshots/kev"),
        "--controls", str(NORTHSTAR / "controls.csv"),
        "--as-of", "2026-09-24",
        "--out", str(out),
    ]) == 0
    assert validator.check_file(schema("ranked_result"), out) == []
