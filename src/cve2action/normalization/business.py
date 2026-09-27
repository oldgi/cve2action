"""從可查證的業務事實推導 Business Criticality。

`CRITICAL` / `IMPORTANT` / `NORMAL` 直接手標，等於把一個判斷寫死成資料。今天改成由三項
問得出答案的事實推導：

- **存什麼資料**（`data_class`）：受管制的資料外洩，衝擊與停機無關。
- **多久不能停**（`rto_hours`）：恢復時間目標是業務自己談出來的數字，不是資安猜的。
- **是否直接面對客戶**（`customer_facing`）：停機立刻被外部看見。

三個維度**取最嚴重的一個，不平均**。一台存放受管制資料、但停機容忍度很高的機器，
仍然是 CRITICAL——把它跟停機容忍度平均掉，等於用「可以慢慢修」沖淡「資料會外洩」。

推導結果一樣帶 `source`（`data:RESTRICTED` / `rto:2h` / `customer-facing`），
缺事實就是 `ExposureError`，不猜一個看起來合理的預設值。
"""

from __future__ import annotations

from dataclasses import dataclass

from .exposure import Derived, ExposureError

# 由輕到重；比較嚴重度時用索引
SEVERITY_ORDER = ("NORMAL", "IMPORTANT", "CRITICAL")


@dataclass(frozen=True)
class BusinessRules:
    """risk_rules.yaml 的 business_impact 區塊。"""

    data_class: dict[str, str]
    rto_bands: tuple[tuple[float, str], ...]  # (within_hours, criticality)，已依時數排序
    rto_beyond: str
    customer_facing_floor: str


def _rank(criticality: str) -> int:
    try:
        return SEVERITY_ORDER.index(criticality)
    except ValueError as error:
        raise ExposureError(f"unknown criticality {criticality!r}") from error


def _from_rto(hours: float, rules: BusinessRules) -> str:
    for within, criticality in rules.rto_bands:
        if hours <= within:
            return criticality
    return rules.rto_beyond


def derive_business_criticality(context: dict, rules: BusinessRules) -> Derived:
    """回傳最嚴重的那個維度，以及它是哪一個。"""
    asset_id = context.get("asset_id", "?")

    data_class = str(context.get("data_class", "")).strip().upper()
    if not data_class:
        raise ExposureError(f"{asset_id}: data_class is required to derive business impact")
    if data_class not in rules.data_class:
        raise ExposureError(f"{asset_id}: unknown data_class {data_class!r}")

    raw_rto = str(context.get("rto_hours", "")).strip()
    if not raw_rto:
        raise ExposureError(f"{asset_id}: rto_hours is required to derive business impact")
    try:
        rto = float(raw_rto)
    except ValueError as error:
        raise ExposureError(f"{asset_id}: rto_hours {raw_rto!r} is not a number") from error
    if rto <= 0:
        raise ExposureError(f"{asset_id}: rto_hours must be positive, got {rto}")

    candidates = [
        (rules.data_class[data_class], f"data:{data_class}"),
        (_from_rto(rto, rules), f"rto:{rto:g}h"),
    ]
    if str(context.get("customer_facing", "")).strip().lower() in {"yes", "true", "1"}:
        candidates.append((rules.customer_facing_floor, "customer-facing"))

    value, source = max(candidates, key=lambda item: _rank(item[0]))
    return Derived(value, source)


def derive_business_context(contexts: list[dict], rules: BusinessRules) -> dict[str, Derived]:
    """以 asset_id 為鍵推導整份業務衝擊。"""
    return {c["asset_id"]: derive_business_criticality(c, rules) for c in contexts}
