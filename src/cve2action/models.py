"""Decision Engine v0.1 的資料模型。

值域與數值映射一律來自 risk_rules.yaml（外部化，不 hard-code）；
這裡只定義結構與欄位名稱。規格見 docs/architecture/decision-engine-v0.1-spec.md。
"""

from __future__ import annotations

from dataclasses import dataclass, field

# scanner.csv 必要欄位；service 為選填（僅用於定位與解釋，不進公式）
SCANNER_REQUIRED_COLUMNS = ("asset", "cve", "cvss")

# asset_context.csv 必要欄位；environment 僅用於定位與解釋，不進公式
CONTEXT_REQUIRED_COLUMNS = (
    "asset",
    "environment",
    "reachability",
    "control_effectiveness",
    "business_criticality",
)

# ranked_result.csv 輸出欄位（Day 5 規格的最小集合 + decision / environment）
OUTPUT_COLUMNS = (
    "asset",
    "cve",
    "cvss",
    "environment",
    "effective_exposure",
    "business_criticality",
    "priority_score",
    "priority",
    "decision",
    "reason",
)

DECISION_SCORED = "SCORED"
DECISION_NEEDS_CONTEXT = "NEEDS_CONTEXT"


@dataclass(frozen=True)
class PriorityBand:
    """單一優先分級：score 落在 [floor, ceiling] 之內（含端點）。"""

    label: str
    floor: float
    ceiling: float


@dataclass(frozen=True)
class RiskRules:
    """由 risk_rules.yaml 載入並驗證過的 Decision Rule。"""

    version: str
    weights: dict[str, float]  # keys: severity / exposure / business
    reachability: dict[str, float]
    control_effectiveness: dict[str, float]
    business_criticality: dict[str, float]
    priority_bands: tuple[PriorityBand, ...] = field(default_factory=tuple)

    def band_for(self, score: float) -> str:
        for band in self.priority_bands:
            if band.floor <= score <= band.ceiling:
                return band.label
        raise ValueError(f"priority score {score} falls outside all configured bands")
