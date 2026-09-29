"""控制措施的適用性：這項防護到底攔不攔得到這個漏洞。

Day 12 讓控制的**強度**可推導（證據夠不夠新、多個控制取最強）。但強度再高，
前提是它的攔截點真的落在這條攻擊路徑上——一個調校過的 WAF 攔不到本機的
sudo 提權，一組管理員 MFA 攔不到不需要驗證的 Netlogon 繞過。Day 12 之前，
這些控制照樣把分數打了折。

判斷依據取 CVSS 向量裡兩個可查證的欄位，不另外發明欄位：

- **AV（Attack Vector）**——攻擊從哪裡來。網路型控制看不到 `AV:L` 的本機攻擊。
- **PR（Privileges Required）**——路徑上有沒有「驗證」這一關。`PR:N` 代表攻擊者
  不必先是誰就能打，驗證類控制（MFA）在這條路徑上沒有位置可以站。

三種結果，兩種都不折減但意義不同（沿用 Day 10 的三態紀律）：

- **適用**——套用該控制的強度係數。
- **不適用**——這是事實，不是未知：我們知道網段隔離攔不到本機提權。不折減。
- **無法判斷**——沒有向量可讀。不能證明攔得到，就不能拿它打折（Day 5 原則）。

網段隔離對 `AV:L` 不適用，常見的反駁是「隔離讓攻擊者根本上不了這台機器」。
那件事是真的，但它已經算在 **Reachability** 裡了——E = R × C 的 R 就是在回答
「誰到得了這台機器」。再從 C 扣一次，是把同一項控制在同一條公式裡算兩次。
C 要回答的是另一個問題：攻擊真的打進來時，這項控制攔不攔得住。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# CVSS v3.1 與 v4.0 共用的 AV 縮寫；v4.0 的 AV 值域與 v3.1 相同
ATTACK_VECTORS = {
    "N": "NETWORK",
    "A": "ADJACENT_NETWORK",
    "L": "LOCAL",
    "P": "PHYSICAL",
}
PRIVILEGES = {"N": "NONE", "L": "LOW", "H": "HIGH"}

APPLICABLE = "APPLICABLE"
NOT_APPLICABLE = "NOT_APPLICABLE"
UNDECIDABLE = "UNDECIDABLE"


class ControlRulesError(ValueError):
    """risk_rules.yaml 的 controls 區段不符合規格。"""


@dataclass(frozen=True)
class Attack:
    """一個漏洞的攻擊路徑特徵，全部讀自 CVSS 向量。"""

    attack_vector: str
    privileges_required: str

    @property
    def needs_authentication(self) -> bool:
        """攻擊者是否必須先通過驗證才走得到這一步。"""
        return self.privileges_required != "NONE"


@dataclass(frozen=True)
class ControlScope:
    """一種控制類型攔得到什麼。"""

    attack_vectors: frozenset[str]
    # True 代表這項控制靠「強化驗證」生效；攻擊不需要驗證時它就沒有位置可站
    requires_authentication: bool = False


@dataclass(frozen=True)
class ControlRules:
    applicability: dict[str, ControlScope] = field(default_factory=dict)

    def scope_for(self, control_type: str) -> ControlScope | None:
        return self.applicability.get(str(control_type).strip().lower())


def parse_attack(vector: str | None) -> Attack | None:
    """從 CVSS 向量讀出 AV 與 PR；讀不到就回 None（交由呼叫端當成無法判斷）。"""
    if not vector:
        return None
    av = re.search(r"/AV:([NALP])(?:/|$)", vector)
    pr = re.search(r"/PR:([NLH])(?:/|$)", vector)
    if av is None or pr is None:
        return None
    return Attack(ATTACK_VECTORS[av.group(1)], PRIVILEGES[pr.group(1)])


def applicability(control_type: str, attack: Attack | None,
                  rules: ControlRules) -> tuple[str, str]:
    """回傳 (結果, 一句話理由)。結果為三態之一。"""
    scope = rules.scope_for(control_type)
    if scope is None:
        # 沒有宣告適用範圍的控制類型：不假設它萬用，也不假設它無用
        return UNDECIDABLE, f"no applicability declared for {control_type}"
    if attack is None:
        return UNDECIDABLE, "no cvss vector to read AV/PR from"
    if attack.attack_vector not in scope.attack_vectors:
        return NOT_APPLICABLE, f"not applicable to AV:{attack.attack_vector}"
    if scope.requires_authentication and not attack.needs_authentication:
        return NOT_APPLICABLE, "attack needs no authentication (PR:NONE)"
    return APPLICABLE, f"applies to AV:{attack.attack_vector}"


def parse_control_rules(section: object) -> ControlRules:
    """解析 risk_rules.yaml 的 `controls.applicability`。"""
    if not isinstance(section, dict):
        raise ControlRulesError("risk_rules.yaml: missing 'controls' section")
    raw = section.get("applicability")
    if not isinstance(raw, dict) or not raw:
        raise ControlRulesError("risk_rules.yaml: missing 'controls.applicability'")

    scopes: dict[str, ControlScope] = {}
    allowed = set(ATTACK_VECTORS.values())
    for name, entry in raw.items():
        if not isinstance(entry, dict):
            raise ControlRulesError(f"risk_rules.yaml: controls.applicability.{name} must be a map")
        vectors = entry.get("attack_vectors")
        if not isinstance(vectors, list) or not vectors:
            raise ControlRulesError(
                f"risk_rules.yaml: controls.applicability.{name}.attack_vectors must be a list"
            )
        values = {str(v).strip().upper() for v in vectors}
        unknown = sorted(values - allowed)
        if unknown:
            raise ControlRulesError(
                f"risk_rules.yaml: controls.applicability.{name} has unknown attack vectors "
                f"{unknown}; allowed {sorted(allowed)}"
            )
        scopes[str(name).strip().lower()] = ControlScope(
            attack_vectors=frozenset(values),
            requires_authentication=bool(entry.get("requires_authentication", False)),
        )
    return ControlRules(applicability=scopes)
