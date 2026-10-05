"""處置模型（Day 25）：適用性閘門與 §9.6 規則覆寫。

「修漏洞不是唯一選項」在這裡有兩個具體意思：

1. **最便宜的處置是證明它不必修**——`applicability` 負責，但它更常回答「證不出來」。
2. **分數不是唯一的結論**——`overrides` 讓 §9.6 的規則把層級推上去，
   並且把「這筆要人看」標出來。兩者都只升不降。
"""

from .applicability import (
    APPLICABLE,
    DEFAULT_MAX_AGE_DAYS,
    NOT_APPLICABLE,
    SETTLEABLE_SOURCES,
    UNDECIDABLE,
    Verdict,
    decide,
    vulnerable_cpes,
)
from .overrides import (
    KEV_REACHABLE_PATH,
    MISSING_CRITICAL_INPUT,
    REVIEW_REQUIRED,
    TIER_ORDER,
    UNAUTHENTICATED_TO_CROWN_JEWEL,
    Fired,
    Outcome,
    apply,
    effective_acceptance,
    render,
)
from .treatment import Facts, Treatment, treat
from .treatment import report as treatment_report

__all__ = [
    "APPLICABLE", "NOT_APPLICABLE", "UNDECIDABLE", "Verdict", "decide",
    "vulnerable_cpes", "SETTLEABLE_SOURCES", "DEFAULT_MAX_AGE_DAYS",
    "apply", "effective_acceptance", "render", "Outcome", "Fired", "TIER_ORDER",
    "KEV_REACHABLE_PATH", "UNAUTHENTICATED_TO_CROWN_JEWEL",
    "MISSING_CRITICAL_INPUT", "REVIEW_REQUIRED",
    "treat", "treatment_report", "Treatment", "Facts",
]
