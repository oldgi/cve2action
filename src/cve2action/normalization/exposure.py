"""從資產與控制推導有效曝險的兩個輸入：Reachability 與 Control Effectiveness。

兩者都是**推導值，不是觀測值**，所以每個結果都帶一個 `source`，說明它從哪來：

- `zone:DMZ` —— 由 Zone 假設推導。Zone 是行政標籤，不等於防火牆實際允許什麼；
  一台在 DMZ 的機器可能只對合作夥伴開放，一台在 CORP 的機器可能因一條 NAT 規則而對外。
  這張對應表是可被推翻的假設，因此放在 risk_rules.yaml，並接受觀測值覆寫。
- `observed` —— 有實際觀測證據（Day 20 的 Reachability Engine 會從網路規則產生）。觀測優先於推導。
- `control:waf@2026-08-14` —— 由某項控制措施推導，附其證據日期。
- `control:waf@2026-05-30 (expired)` —— 證據過期。過期不代表控制失效，但不能再拿它打折，
  所以降為 UNKNOWN 而非 NONE：我們不知道它現在還有沒有效。
- `no-control` —— 這台資產沒有登錄任何控制措施。

多個控制不相乘：WAF 與 EDR 可能被同一個繞過手法同時穿過，把它們當獨立事件相乘
（0.4 × 0.4 = 0.16）是假精確。取證據最強的一個。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

CONTROL_UNKNOWN = "UNKNOWN"
CONTROL_NONE = "NONE"


class ExposureError(ValueError):
    """資產或控制資料不足以推導曝險。"""


@dataclass(frozen=True)
class Derived:
    """一個推導出來的值，以及它的來源。"""

    value: str
    source: str

    def __str__(self) -> str:
        return f"{self.value} ({self.source})"


def derive_reachability(asset: dict, rules, observed: str | None = None) -> Derived:
    """觀測值優先；沒有觀測時才用 Zone 假設推導。"""
    if observed:
        candidate = observed.strip().upper()
        if candidate not in rules.reachability:
            raise ExposureError(f"observed reachability {observed!r} is not a known value")
        return Derived(candidate, "observed")

    zone = str(asset.get("zone", "")).strip().upper()
    if not zone:
        raise ExposureError(f"{asset.get('asset_id')}: no zone and no observed reachability")
    mapped = rules.zone_reachability.get(zone)
    if mapped is None:
        raise ExposureError(f"{asset.get('asset_id')}: zone {zone!r} has no reachability mapping")
    return Derived(mapped, f"zone:{zone}")


def _evidence_age_days(verified_at: str, as_of: date) -> int | None:
    try:
        return (as_of - date.fromisoformat(verified_at.strip())).days
    except (ValueError, AttributeError):
        return None


def derive_control_effectiveness(asset_id: str, controls: list[dict], rules,
                                 as_of: date) -> Derived:
    """合併一台資產上的所有控制；沒有可用證據時回 NONE，證據過期回 UNKNOWN。

    只比較「有證據且未過期」的控制，取折減效果最強的那一個。UNKNOWN 的控制不參與比較，
    也不懲罰其他有證據的控制——不知道某項防護有沒有效，不代表別項的證據失效。
    """
    mine = [c for c in controls if c.get("asset_id") == asset_id]
    if not mine:
        return Derived(CONTROL_NONE, "no-control")

    usable: list[tuple[float, str, str]] = []  # (係數, 值, 來源)
    stale: list[str] = []
    for control in mine:
        effectiveness = str(control.get("effectiveness", "")).strip().upper()
        kind = control.get("control_type", "control")
        verified = str(control.get("verified_at", ""))
        age = _evidence_age_days(verified, as_of)
        if age is None:
            stale.append(f"control:{kind}@unknown-date")
            continue
        if age > rules.control_evidence_max_age_days:
            stale.append(f"control:{kind}@{verified} (expired {age}d)")
            continue
        factor = rules.control_effectiveness.get(effectiveness)
        if factor is None:
            raise ExposureError(f"{asset_id}: unknown control effectiveness {effectiveness!r}")
        if effectiveness == CONTROL_UNKNOWN:
            stale.append(f"control:{kind}@{verified} (unproven)")
            continue
        usable.append((factor, effectiveness, f"control:{kind}@{verified}"))

    if usable:
        # 係數愈小折減愈多；取最強的一個，不相乘
        factor, value, source = min(usable, key=lambda item: item[0])
        return Derived(value, source)
    # 有登錄控制但沒有一項拿得出有效證據：UNKNOWN，不是 NONE
    return Derived(CONTROL_UNKNOWN, "; ".join(stale) if stale else "no-usable-evidence")


def derive_asset_context(assets: list[dict], controls: list[dict], rules, as_of: date,
                         observed: dict[str, str] | None = None) -> list[dict]:
    """把 assets + controls 推導成引擎吃的 asset_context，並保留每個值的來源。"""
    observed = observed or {}
    rows = []
    for asset in assets:
        asset_id = asset["asset_id"]
        reach = derive_reachability(asset, rules, observed.get(asset_id))
        control = derive_control_effectiveness(asset_id, controls, rules, as_of)
        rows.append({
            "asset": asset_id,
            "environment": asset.get("environment", ""),
            "reachability": reach.value,
            "control_effectiveness": control.value,
            "business_criticality": asset.get("criticality", ""),
            "reachability_source": reach.source,
            "control_source": control.source,
        })
    return rows
