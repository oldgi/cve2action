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
CWE_PATTERN = re.compile(r"CWE-\d+")

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
    """一種控制類型攔得到什麼。

    兩條**彼此獨立**的軸線：

    - `attack_vectors` / `requires_authentication`（Day 15）——
      **攔截點在不在這條攻擊路徑上？** 問 CVSS 的 AV 與 PR。
    - `blind_to_weaknesses`（番外篇二）——
      **這項控制懂不懂這一類弱點？** 問 NVD 的 CWE。

    第二條只會**否決**，不會批准：列在 `blind_to_weaknesses` 裡的 CWE 代表
    「這項控制看不到這一層」。沒列到的不代表看得到，只代表我們沒有理由說它看不到。
    """

    attack_vectors: frozenset[str]
    # True 代表這項控制靠「強化驗證」生效；攻擊不需要驗證時它就沒有位置可站
    requires_authentication: bool = False
    # 這項控制明確看不到的弱點類別（CWE）。空集合＝沒有宣告，不是「什麼都看得到」。
    blind_to_weaknesses: frozenset[str] = frozenset()


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


def applicability(control_type: str, attack: Attack | None, rules: ControlRules,
                  weaknesses: tuple[str, ...] = ()) -> tuple[str, str]:
    """回傳 (結果, 一句話理由)。結果為三態之一。

    `weaknesses` 是該 CVE 的 CWE 清單（番外篇二）。**沉默不移動判定**：
    拿不到 CWE 時這條軸線什麼都不說，前一條軸線憑證據得到的結論原封不動。

    這不是「UNKNOWN 不得降低風險」的例外。那條講的是缺資料不得換來比較**安全**
    的結論；而沉默在這裡換到的是**不變**。沒有資料的時候，兩個方向都不能動——
    與 Day 25「空清單不是證據」是同一條。
    """
    scope = rules.scope_for(control_type)
    if scope is None:
        # 沒有宣告適用範圍的控制類型：不假設它萬用，也不假設它無用
        return UNDECIDABLE, f"no applicability declared for {control_type}"
    if attack is None:
        return UNDECIDABLE, "no cvss vector to read AV/PR from"
    blind = sorted(scope.blind_to_weaknesses & set(weaknesses))
    if blind:
        return NOT_APPLICABLE, f"blind to {'/'.join(blind)}"
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
        blind = entry.get("blind_to_weaknesses") or []
        if not isinstance(blind, list):
            raise ControlRulesError(
                f"risk_rules.yaml: controls.applicability.{name}.blind_to_weaknesses "
                "must be a list"
            )
        cwes = {str(c).strip().upper() for c in blind}
        malformed = sorted(c for c in cwes if not CWE_PATTERN.fullmatch(c))
        if malformed:
            raise ControlRulesError(
                f"risk_rules.yaml: controls.applicability.{name}.blind_to_weaknesses "
                f"has malformed entries {malformed}; expected CWE-nnn"
            )
        scopes[str(name).strip().lower()] = ControlScope(
            attack_vectors=frozenset(values),
            requires_authentication=bool(entry.get("requires_authentication", False)),
            blind_to_weaknesses=frozenset(cwes),
        )
    return ControlRules(applicability=scopes)
