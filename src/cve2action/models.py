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
    "cvss_version",
    "cvss_source",
    "threat",
    "threat_source",
    "environment",
    "control_effectiveness",
    "control_source",
    "effective_exposure",
    "business_criticality",
    "priority_score",
    "priority",
    "priority_tier",
    "decision",
    "reason",
)

# 合成分數的形式（Day 23，ADR-day-23）
ADDITIVE = "additive"
GEOMETRIC = "geometric"
# 幾何平均碰到 0 會整體歸零；下限與藍圖 §9.5 的 max(A, 0.05) 取同一個數
GEOMETRIC_FLOOR = 0.05

DECISION_SCORED = "SCORED"
DECISION_NEEDS_CONTEXT = "NEEDS_CONTEXT"


@dataclass(frozen=True)
class PriorityBand:
    """單一優先分級：score 落在 [floor, ceiling] 之內（含端點）。

    `label` 是 0–10 內部刻度的名稱（Day 5 以來的基準都用它）；
    `tier` 是對外呈現的處置層級 P0–P3，語彙與藍圖 §9.5 一致（Day 18）。
    """

    label: str
    floor: float
    ceiling: float
    tier: str = ""
    action: str = ""


@dataclass(frozen=True)
class RiskRules:
    """由 risk_rules.yaml 載入並驗證過的 Decision Rule。"""

    version: str
    weights: dict[str, float]  # keys: severity / exposure / business
    reachability: dict[str, float]
    control_effectiveness: dict[str, float]
    business_criticality: dict[str, float]
    priority_bands: tuple[PriorityBand, ...] = field(default_factory=tuple)
    # 從快照取 CVSS 時的版本偏好順序；同一列只會用一個版本，並在輸出標明
    cvss_version_preference: tuple[str, ...] = ("3.1", "4.0")
    # Zone → Reachability 的假設對應（Day 12）；有觀測值時以觀測為準
    zone_reachability: dict[str, str] = field(default_factory=dict)
    # 控制證據的有效天數；超過就不能再拿它打折
    control_evidence_max_age_days: int = 90
    # Business Criticality 的推導規則（Day 13）
    business_impact: object | None = None
    # EPSS/KEV 的正規化規則（Day 14）
    threat: object | None = None
    # 控制措施的適用範圍（Day 15）：攔截點不在攻擊路徑上的控制不得折減
    controls: object | None = None
    # 合成分數的形式：additive 或 geometric（Day 23）
    form: str = ADDITIVE

    def band_for(self, score: float) -> str:
        return self.band_object_for(score).label

    def tier_for(self, score: float) -> str:
        """對外的處置層級 P0–P3；內部計算一律用 label。"""
        return self.band_object_for(score).tier

    def band_object_for(self, score: float) -> PriorityBand:
        for band in self.priority_bands:
            if band.floor <= score <= band.ceiling:
                return band
        raise ValueError(f"priority score {score} falls outside all configured bands")
