"""載入並驗證 risk_rules.yaml。

驗證失敗一律拒載（raise RulesError）：權重和必須為 1、
三組值域映射的鍵必須與 v0.1 規格完全一致、分級須連續涵蓋 0–10。
"""

from __future__ import annotations

import math
from pathlib import Path

import yaml

from .models import PriorityBand, RiskRules

# v0.1 凍結值域（ADR-day-05）；risk_rules.yaml 只提供數值映射，不得增刪鍵
REQUIRED_WEIGHT_KEYS = frozenset({"severity", "exposure", "business"})
REQUIRED_REACHABILITY_KEYS = frozenset({"INTERNET", "INTERNAL", "ISOLATED"})
REQUIRED_CONTROL_KEYS = frozenset({"NONE", "PARTIAL", "STRONG", "UNKNOWN"})
REQUIRED_BUSINESS_KEYS = frozenset({"CRITICAL", "IMPORTANT", "NORMAL"})


class RulesError(ValueError):
    """risk_rules.yaml 內容不符合 v0.1 規格。"""


def _require_mapping(raw: dict, key: str, required_keys: frozenset[str]) -> dict[str, float]:
    mapping = raw.get(key)
    if not isinstance(mapping, dict):
        raise RulesError(f"risk_rules.yaml: missing mapping section '{key}'")
    keys = set(mapping)
    if keys != required_keys:
        missing = sorted(required_keys - keys)
        extra = sorted(keys - required_keys)
        raise RulesError(
            f"risk_rules.yaml: '{key}' keys mismatch (missing={missing}, unexpected={extra})"
        )
    result: dict[str, float] = {}
    for name, value in mapping.items():
        number = float(value)
        if not 0.0 <= number <= 1.0:
            raise RulesError(f"risk_rules.yaml: '{key}.{name}' must be within 0–1, got {number}")
        result[name] = number
    return result


def _parse_bands(raw: dict) -> tuple[PriorityBand, ...]:
    entries = raw.get("priority_bands")
    if not isinstance(entries, list) or not entries:
        raise RulesError("risk_rules.yaml: missing 'priority_bands'")
    bands = tuple(
        PriorityBand(label=str(e["label"]), floor=float(e["floor"]), ceiling=float(e["ceiling"]))
        for e in entries
    )
    ordered = sorted(bands, key=lambda b: b.floor)
    if ordered[0].floor != 0.0 or ordered[-1].ceiling != 10.0:
        raise RulesError("risk_rules.yaml: priority_bands must cover 0–10")
    for lower, upper in zip(ordered, ordered[1:], strict=False):
        if upper.floor <= lower.ceiling:
            raise RulesError(
                f"risk_rules.yaml: overlapping bands '{lower.label}' and '{upper.label}'"
            )
    return bands


def load_rules(path: str | Path) -> RiskRules:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RulesError("risk_rules.yaml: top level must be a mapping")

    weights_raw = raw.get("weights")
    if not isinstance(weights_raw, dict) or set(weights_raw) != REQUIRED_WEIGHT_KEYS:
        raise RulesError(
            f"risk_rules.yaml: 'weights' must define exactly {sorted(REQUIRED_WEIGHT_KEYS)}"
        )
    weights = {name: float(value) for name, value in weights_raw.items()}
    if not math.isclose(sum(weights.values()), 1.0, abs_tol=1e-9):
        raise RulesError(f"risk_rules.yaml: weights must sum to 1, got {sum(weights.values())}")

    control = _require_mapping(raw, "control_effectiveness", REQUIRED_CONTROL_KEYS)
    # 不知道，就不能假裝已有防護：UNKNOWN 必須視同無有效控制
    if control["UNKNOWN"] < control["NONE"]:
        raise RulesError(
            "risk_rules.yaml: control_effectiveness.UNKNOWN must not lower exposure "
            f"(UNKNOWN={control['UNKNOWN']} < NONE={control['NONE']})"
        )

    return RiskRules(
        version=str(raw.get("version", "unversioned")),
        weights=weights,
        reachability=_require_mapping(raw, "reachability", REQUIRED_REACHABILITY_KEYS),
        control_effectiveness=control,
        business_criticality=_require_mapping(
            raw, "business_criticality", REQUIRED_BUSINESS_KEYS
        ),
        priority_bands=_parse_bands(raw),
    )
