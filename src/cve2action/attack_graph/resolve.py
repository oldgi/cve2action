"""把一筆掃描觀測解析成一個資產（藍圖 §9.0 閘門 1）。

弱掃回報的是 IP 或 hostname，不是資產。一台有三個介面的機器會被回報三次，
同一個漏洞就產生三項修補工作——成功標準 #10 要求「重複觀測只形成一項」。

解析不能只靠一種識別子，資料本身就證明了這件事：

- **IP 不夠**：VIP `203.0.113.10` 被兩台入口網站同時宣稱。照 IP 併，兩台會變成一台。
- **hostname 不夠**：同一張網卡可以掛多個名字（`lab-wiki` 與 `wiki-old` 是同一台）。
  照 hostname 併，一台會被拆成好幾台。

所以回傳三態，與 Day 10 的 KEV、Day 15 的控制適用性同一條紀律：

- `RESOLVED`——恰好對到一台，這是事實。
- `AMBIGUOUS`——對到多台，這也是事實（例如打到 VIP）。**不是未知，是我們知道它分不開。**
- `UNKNOWN`——對不到任何一台。清冊沒有這台機器。

後兩者都不評分，但理由不同：AMBIGUOUS 要去查這個位址背後是誰，
UNKNOWN 要去查為什麼有一台機器不在清冊上。把兩者混成一句「找不到資產」，
就看不出該找誰。
"""

from __future__ import annotations

from dataclasses import dataclass, field

RESOLVED = "RESOLVED"
AMBIGUOUS = "AMBIGUOUS"
UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Resolution:
    """一筆觀測的解析結果。"""

    status: str
    asset: str | None = None
    candidates: tuple[str, ...] = ()
    matched_on: str = ""
    observation: str = ""

    @property
    def resolved(self) -> bool:
        return self.status == RESOLVED

    def __str__(self) -> str:
        if self.resolved:
            return f"{self.observation} -> {self.asset} ({self.matched_on})"
        if self.status == AMBIGUOUS:
            return f"{self.observation} -> AMBIGUOUS {list(self.candidates)} ({self.matched_on})"
        return f"{self.observation} -> UNKNOWN (不在清冊上)"


@dataclass(frozen=True)
class Inventory:
    """由 asset_interfaces.csv 建立的查找表。

    三張索引分開存，因為解析時要知道**是靠哪一種識別子對到的**——
    靠 MAC 對到和靠 IP 對到，可信程度不一樣。
    """

    by_mac: dict[str, set[str]] = field(default_factory=dict)
    by_hostname: dict[str, set[str]] = field(default_factory=dict)
    by_ip: dict[str, set[str]] = field(default_factory=dict)

    @property
    def assets(self) -> set[str]:
        return {a for owners in self.by_mac.values() for a in owners}

    def interfaces_of(self, asset: str) -> int:
        return sum(1 for index in (self.by_mac, self.by_hostname, self.by_ip)
                   for owners in index.values() if asset in owners)


def build_inventory(interfaces: list[dict]) -> Inventory:
    inventory = Inventory({}, {}, {})
    for row in interfaces:
        asset = str(row["asset_id"]).strip()
        for key, index in (("mac", inventory.by_mac),
                           ("hostname", inventory.by_hostname),
                           ("ip", inventory.by_ip)):
            value = str(row.get(key, "")).strip().lower()
            if value:
                index.setdefault(value, set()).add(asset)
    return inventory


# 解析順序：愈不容易共用的識別子愈優先。
# MAC 綁在網卡上；hostname 可以是別名但仍指向一台；IP 可以是 VIP，最容易共用。
PRECEDENCE = ("mac", "hostname", "ip")


def resolve(observation: str, inventory: Inventory) -> Resolution:
    """把一個 IP／hostname／MAC 解析成資產。

    依序試 MAC → hostname → IP。**第一個對到東西的識別子就決定答案**，
    即使它對到的是多台——換下一種識別子去「試到單一答案為止」是在湊答案，
    那會讓 VIP 悄悄被歸給其中一台。
    """
    needle = str(observation).strip().lower()
    if not needle:
        return Resolution(UNKNOWN, observation=observation)

    indexes = {"mac": inventory.by_mac, "hostname": inventory.by_hostname,
               "ip": inventory.by_ip}
    for kind in PRECEDENCE:
        owners = indexes[kind].get(needle)
        if not owners:
            continue
        if len(owners) == 1:
            return Resolution(RESOLVED, asset=next(iter(owners)), matched_on=kind,
                              observation=observation)
        return Resolution(AMBIGUOUS, candidates=tuple(sorted(owners)), matched_on=kind,
                          observation=observation)
    return Resolution(UNKNOWN, observation=observation)


def resolve_all(observations: list[str], inventory: Inventory) -> list[Resolution]:
    return [resolve(o, inventory) for o in observations]
