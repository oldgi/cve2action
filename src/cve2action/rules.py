"""載入並驗證 risk_rules.yaml。

驗證失敗一律拒載（raise RulesError）：權重和必須為 1、
三組值域映射的鍵必須與 v0.1 規格完全一致、分級須連續涵蓋 0–10。
"""

from __future__ import annotations

import math
from pathlib import Path

import yaml

from .models import ADDITIVE, GEOMETRIC, PriorityBand, RiskRules
from .normalization.business import BusinessRules
from .normalization.control import ControlRules, ControlRulesError, parse_control_rules
from .normalization.cvss import SUPPORTED_VERSIONS
from .normalization.threat import ThreatRules

# v0.1 凍結值域（ADR-day-05）；risk_rules.yaml 只提供數值映射，不得增刪鍵
REQUIRED_WEIGHT_KEYS = frozenset({"severity", "threat", "exposure", "business"})
# 路徑項是 Day 23 才加的，v0.1 凍結版沒有它——所以它是選用的，不是必要的。
OPTIONAL_WEIGHT_KEYS = frozenset({"path"})
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
        PriorityBand(label=str(e["label"]), floor=float(e["floor"]), ceiling=float(e["ceiling"]),
                     tier=str(e.get("tier", "")), action=str(e.get("action", "")))
        for e in entries
    )
    tiers = [b.tier for b in bands]
    if not all(tiers) or len(set(tiers)) != len(tiers):
        raise RulesError(
            "risk_rules.yaml: 每個 priority_band 都要有唯一的 tier（對外的 P0–P3 層級）"
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


def _parse_cvss_preference(raw: dict) -> tuple[str, ...]:
    section = raw.get("cvss")
    if not isinstance(section, dict) or not isinstance(section.get("version_preference"), list):
        raise RulesError("risk_rules.yaml: missing 'cvss.version_preference' list")
    order = tuple(str(v) for v in section["version_preference"])
    if not order or len(set(order)) != len(order):
        raise RulesError(
            "risk_rules.yaml: cvss.version_preference must be non-empty, no duplicates"
        )
    unknown = [v for v in order if v not in SUPPORTED_VERSIONS]
    if unknown:
        raise RulesError(
            f"risk_rules.yaml: unsupported CVSS versions {unknown}; "
            f"allowed {list(SUPPORTED_VERSIONS)}"
        )
    return order


def _parse_exposure(raw: dict, reachability: dict[str, float]) -> tuple[dict[str, str], int]:
    section = raw.get("exposure")
    if not isinstance(section, dict):
        raise RulesError("risk_rules.yaml: missing 'exposure' section")

    mapping = section.get("zone_reachability")
    if not isinstance(mapping, dict) or not mapping:
        raise RulesError("risk_rules.yaml: missing 'exposure.zone_reachability'")
    zones = {str(z).upper(): str(v).upper() for z, v in mapping.items()}
    unknown = sorted({v for v in zones.values()} - set(reachability))
    if unknown:
        raise RulesError(
            f"risk_rules.yaml: zone_reachability maps to unknown values {unknown}; "
            f"allowed {sorted(reachability)}"
        )

    max_age = section.get("control_evidence_max_age_days")
    if not isinstance(max_age, int) or max_age <= 0:
        raise RulesError(
            "risk_rules.yaml: 'exposure.control_evidence_max_age_days' must be a positive integer"
        )
    return zones, max_age


def _parse_business_impact(raw: dict, criticality: dict[str, float]) -> BusinessRules:
    section = raw.get("business_impact")
    if not isinstance(section, dict):
        raise RulesError("risk_rules.yaml: missing 'business_impact' section")

    data_class = section.get("data_class")
    if not isinstance(data_class, dict) or not data_class:
        raise RulesError("risk_rules.yaml: missing 'business_impact.data_class'")
    mapped = {str(k).upper(): str(v).upper() for k, v in data_class.items()}

    bands_raw = section.get("rto_hours")
    if not isinstance(bands_raw, list) or not bands_raw:
        raise RulesError("risk_rules.yaml: missing 'business_impact.rto_hours'")
    bands = tuple(sorted(
        ((float(b["within"]), str(b["criticality"]).upper()) for b in bands_raw),
        key=lambda item: item[0],
    ))
    beyond = str(section.get("rto_beyond", "")).upper()
    floor = str(section.get("customer_facing_floor", "")).upper()

    declared = {v for _h, v in bands} | {beyond, floor} | set(mapped.values())
    unknown = sorted(declared - set(criticality))
    if unknown:
        raise RulesError(
            f"risk_rules.yaml: business_impact yields unknown criticality {unknown}; "
            f"allowed {sorted(criticality)}"
        )
    return BusinessRules(data_class=mapped, rto_bands=bands, rto_beyond=beyond,
                         customer_facing_floor=floor)


def _parse_threat(raw: dict) -> ThreatRules:
    section = raw.get("threat")
    if not isinstance(section, dict):
        raise RulesError("risk_rules.yaml: missing 'threat' section")
    base = section.get("epss_log_base")
    kev = section.get("kev_listed_value")
    if not isinstance(base, (int, float)) or base <= 0:
        raise RulesError("risk_rules.yaml: 'threat.epss_log_base' must be a positive number")
    if not isinstance(kev, (int, float)) or not 0.0 <= kev <= 1.0:
        raise RulesError("risk_rules.yaml: 'threat.kev_listed_value' must be within 0-1")
    return ThreatRules(epss_log_base=float(base), kev_listed_value=float(kev))


def _parse_controls(raw: dict) -> ControlRules:
    try:
        return parse_control_rules(raw.get("controls"))
    except ControlRulesError as error:
        raise RulesError(str(error)) from error


def _parse_form(raw: dict) -> str:
    form = str(raw.get("form", ADDITIVE))
    if form not in (ADDITIVE, GEOMETRIC):
        raise RulesError(
            f"risk_rules.yaml: 'form' 必須是 {ADDITIVE} 或 {GEOMETRIC}，得到 {form!r}")
    return form


def load_rules(path: str | Path) -> RiskRules:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RulesError("risk_rules.yaml: top level must be a mapping")

    weights_raw = raw.get("weights")
    keys = set(weights_raw) if isinstance(weights_raw, dict) else set()
    if not keys >= REQUIRED_WEIGHT_KEYS or not keys <= (REQUIRED_WEIGHT_KEYS
                                                        | OPTIONAL_WEIGHT_KEYS):
        raise RulesError(
            f"risk_rules.yaml: 'weights' 必須包含 {sorted(REQUIRED_WEIGHT_KEYS)}，"
            f"可選 {sorted(OPTIONAL_WEIGHT_KEYS)}；得到 {sorted(keys)}"
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

    reachability = _require_mapping(raw, "reachability", REQUIRED_REACHABILITY_KEYS)
    zones, max_age = _parse_exposure(raw, reachability)
    criticality = _require_mapping(raw, "business_criticality", REQUIRED_BUSINESS_KEYS)
    business = _parse_business_impact(raw, criticality)
    threat = _parse_threat(raw)

    return RiskRules(
        version=str(raw.get("version", "unversioned")),
        weights=weights,
        reachability=reachability,
        control_effectiveness=control,
        business_criticality=criticality,
        priority_bands=_parse_bands(raw),
        cvss_version_preference=_parse_cvss_preference(raw),
        zone_reachability=zones,
        control_evidence_max_age_days=max_age,
        business_impact=business,
        threat=threat,
        controls=_parse_controls(raw),
        form=_parse_form(raw),
    )
