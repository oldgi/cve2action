"""risk_rules.yaml 載入與驗證：規則檔壞掉必須拒載，不能默默用預設值。"""

from pathlib import Path

import pytest
import yaml

from cve2action.rules import RulesError, load_rules

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = REPO_ROOT / "config" / "risk_rules.yaml"


def load_raw() -> dict:
    return yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))


def dump(tmp_path: Path, raw: dict) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return path


def test_baseline_rules_load():
    rules = load_rules(RULES_PATH)
    assert rules.weights == {"severity": 0.50, "exposure": 0.25, "business": 0.25}
    assert rules.reachability["ISOLATED"] == 0.2
    assert rules.control_effectiveness["UNKNOWN"] == 1.0
    assert rules.band_for(9.40) == "Critical"
    assert rules.band_for(7.90) == "High"
    assert rules.band_for(6.25) == "Medium"
    assert rules.band_for(0.0) == "Low"


def test_weights_must_sum_to_one(tmp_path):
    raw = load_raw()
    raw["weights"]["severity"] = 0.6
    with pytest.raises(RulesError, match="sum to 1"):
        load_rules(dump(tmp_path, raw))


def test_missing_domain_key_rejected(tmp_path):
    raw = load_raw()
    del raw["reachability"]["ISOLATED"]
    with pytest.raises(RulesError, match="ISOLATED"):
        load_rules(dump(tmp_path, raw))


def test_unexpected_domain_key_rejected(tmp_path):
    raw = load_raw()
    raw["business_criticality"]["VIP"] = 1.0
    with pytest.raises(RulesError, match="VIP"):
        load_rules(dump(tmp_path, raw))


def test_unknown_control_may_not_lower_exposure(tmp_path):
    raw = load_raw()
    raw["control_effectiveness"]["UNKNOWN"] = 0.4
    with pytest.raises(RulesError, match="UNKNOWN"):
        load_rules(dump(tmp_path, raw))


def test_bands_must_cover_zero_to_ten(tmp_path):
    raw = load_raw()
    raw["priority_bands"] = [b for b in raw["priority_bands"] if b["label"] != "Low"]
    with pytest.raises(RulesError, match="cover 0"):
        load_rules(dump(tmp_path, raw))
