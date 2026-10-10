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

from .control import APPLICABLE, NOT_APPLICABLE, Attack
from .control import applicability as control_applicability

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


def derive_control_effectiveness(asset_id: str, controls: list[dict], rules, as_of: date,
                                 attack: Attack | None = None,
                                 check_applicability: bool = False,
                                 weaknesses: tuple[str, ...] = ()) -> Derived:
    """合併一台資產上的所有控制；沒有可用證據時回 NONE，證據過期回 UNKNOWN。

    只比較「有證據且未過期」的控制，取折減效果最強的那一個。UNKNOWN 的控制不參與比較，
    也不懲罰其他有證據的控制——不知道某項防護有沒有效，不代表別項的證據失效。

    `check_applicability`（Day 15）打開時先過一次適用性：攔截點不在這條攻擊路徑上的控制，
    不論證據多新、強度多高，都不參與折減；`attack` 讀不出來就是無法判斷，同樣不折減。

    `weaknesses`（番外篇二）是該 CVE 的 CWE 清單，供適用性的第二條軸線使用：
    **這項控制懂不懂這一類弱點。** 拿不到 CWE 時這條軸線沉默，不移動任何判定。
    """
    mine = [c for c in controls if c.get("asset_id") == asset_id]
    if not mine:
        return Derived(CONTROL_NONE, "no-control")

    usable: list[tuple[float, str, str]] = []  # (係數, 值, 來源)
    stale: list[str] = []
    inapplicable: list[str] = []
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
        verdict, why = _applicability(kind, attack, rules, check_applicability, weaknesses)
        if verdict != APPLICABLE:
            bucket = inapplicable if verdict == NOT_APPLICABLE else stale
            bucket.append(f"control:{kind}@{verified} ({why})")
            continue
        label = f"control:{kind}@{verified}"
        usable.append((factor, effectiveness, f"{label} ({why})" if why else label))

    if usable:
        # 係數愈小折減愈多；取最強的一個，不相乘
        factor, value, source = min(usable, key=lambda item: item[0])
        return Derived(value, source)
    if inapplicable and not stale:
        # 控制有效，只是攔不到這一類攻擊——這是事實，不是未知
        return Derived(CONTROL_NONE, "; ".join(inapplicable))
    # 有登錄控制但沒有一項拿得出有效證據：UNKNOWN，不是 NONE
    notes = stale + inapplicable
    return Derived(CONTROL_UNKNOWN, "; ".join(notes) if notes else "no-usable-evidence")


def _applicability(kind: str, attack: Attack | None, rules, evaluate: bool,
                   weaknesses: tuple[str, ...] = ()) -> tuple[str, str]:
    """資產層的推導（Day 12）不看適用性；逐筆評分（Day 15）才看。"""
    control_rules = getattr(rules, "controls", None)
    if not evaluate or control_rules is None:
        return APPLICABLE, ""
    return control_applicability(kind, attack, control_rules, weaknesses)


def derive_asset_context(assets: list[dict], controls: list[dict], rules, as_of: date,
                         observed: dict[str, str] | None = None,
                         business: dict[str, Derived] | None = None) -> list[dict]:
    """把 assets + controls 推導成引擎吃的 asset_context，並保留每個值的來源。

    `business` 是 Day 13 由 `business_context.csv` 推導出來的 criticality（附來源）。
    Day 13 之後 `assets.csv` 的欄位改名為 declared_criticality 且僅供對照，所以沒有給
    `business` 時這一欄只能留白——留白會讓該資產在評分時變成 NEEDS_CONTEXT，
    這是正確的失敗方式：缺業務事實就不評分，不拿宣告值頂替。
    """
    observed = observed or {}
    rows = []
    for asset in assets:
        asset_id = asset["asset_id"]
        reach = derive_reachability(asset, rules, observed.get(asset_id))
        control = derive_control_effectiveness(asset_id, controls, rules, as_of)
        row = {
            "asset": asset_id,
            "environment": asset.get("environment", ""),
            "reachability": reach.value,
            "control_effectiveness": control.value,
            "business_criticality": asset.get("criticality", ""),
            "reachability_source": reach.source,
            "control_source": control.source,
        }
        if business is not None:
            derived = business.get(asset_id)
            if derived is None:
                raise ExposureError(f"{asset_id}: no business context row to derive criticality")
            row["business_criticality"] = derived.value
            row["business_source"] = derived.source
        rows.append(row)
    return rows
