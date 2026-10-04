"""身分邊的前提條件（Day 21，藍圖 §10「權限前置條件明確」）。

Day 19 把帳號畫成節點，`asset --uses--> account --grants--> asset`。但那條邊當時是
**無條件可走的**，背後藏了三個沒講出來的假設：

1. 攻擊者拿得到這個帳號的憑證；
2. 他在來源端的權限足以拿到它；
3. 沒有控制擋住這次驗證。

今天把第一、二點變成**資料**，不是推論。

## 為什麼不能用推的

最想推導的那一項是「攻下這台之後拿到什麼權限」。CVSS 給不了：
**`PR` 說的是「需要什麼權限才能打」，不是「打完拿到什麼權限」。** 這兩件事方向相反。

所以權限要記在服務上（`services.runs_as`：攻下這個服務會取得什麼身分），
前提要記在身分邊上（`requires_privilege`：在來源端要有什麼權限才拿得到這組憑證）。
兩邊都是清冊查得到的事實，不是從分數猜出來的。

## 三態，而且未知不擋路

- `SATISFIED`——在來源端取得的權限足以拿到這組憑證。
- `BLOCKED`——拿不到。兩種情況：取得的權限不夠，或**憑證根本不在這台機器上**
  （封緘保管的 break-glass 憑證，本機管理員權限也打不開保險箱）。
- `UNPROVEN`——我們無法確定在來源端能拿到什麼權限（例如 finding 對不到任何已登錄的服務）。

**`UNPROVEN` 不會把邊從圖上拿掉。** 不能證明走不通，就得當它走得通——
這是 Day 5 以來同一條規則的第 N 次套用。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# 權限的高低。這是一條粗糙但可檢驗的序：能做的事愈多，排愈後面。
PRIVILEGE_RANK = {
    "none": 0,
    "db_read_only": 1,
    "db_read_write": 2,
    "local_service": 3,
    "interactive_logon": 4,
    "local_admin": 5,
    "domain_admin": 6,
}

SATISFIED = "SATISFIED"
BLOCKED = "BLOCKED"
UNPROVEN = "UNPROVEN"

FROM_SERVICE = "from_service"
FROM_LOCAL_PRIVESC = "from_local_privesc"
NO_EVIDENCE = "no_evidence"

LISTENING = "listening"

# 不存在於來源機器上的憑證。權限再高也拿不到——封緘憑證放在保險箱裡，
# 本機管理員權限不會讓保險箱打開。credential_source 這一欄存在的理由就是這個，
# 否則它只是裝飾。
OFFLINE_CREDENTIALS = frozenset({"sealed_credential"})


@dataclass(frozen=True)
class Obtainable:
    """在某台資產上能取得的最高權限，以及這個結論是怎麼來的。"""

    level: str
    basis: str
    detail: str = ""

    @property
    def rank(self) -> int:
        return PRIVILEGE_RANK.get(self.level, 0)

    @property
    def proven(self) -> bool:
        return self.basis != NO_EVIDENCE


@dataclass(frozen=True)
class Precondition:
    """一條身分邊的前提判定。"""

    status: str
    required: str = ""
    obtained: str = ""
    reason: str = ""

    @property
    def traversable(self) -> bool:
        """BLOCKED 以外都走得通——UNPROVEN 不擋路。"""
        return self.status != BLOCKED


def _local_privesc(asset: str, findings: list[dict], vectors: dict[str, str]) -> str | None:
    """這台有沒有可用的本機提權（AV:L）。有的話，服務身分可以升到 local_admin。"""
    for finding in findings:
        if finding.get("asset") != asset:
            continue
        vector = vectors.get(str(finding.get("cve", "")).upper(), "")
        if re.search(r"/AV:L(?:/|$)", vector):
            return str(finding["cve"])
    return None


def privilege_obtainable(asset: str, services: list[dict], findings: list[dict],
                         vectors: dict[str, str]) -> Obtainable:
    """攻擊者在這台資產上最高能取得什麼權限。

    只採計**有服務在聽、而且那個服務上有已知漏洞**的情況——服務名對不上登錄清單時
    不猜，回 `UNPROVEN`。資料裡 40 筆 finding 只有 15 筆對得上已登錄的服務，
    這個缺口是真的，不該用猜的補起來。
    """
    names = {(f.get("asset"), f.get("service")) for f in findings}
    best: tuple[int, str] | None = None
    for service in services:
        if service.get("asset_id") != asset or service.get("state") != LISTENING:
            continue
        if (asset, service.get("service")) not in names:
            continue
        level = str(service.get("runs_as", ""))
        rank = PRIVILEGE_RANK.get(level, 0)
        if best is None or rank > best[0]:
            best = (rank, level)

    escalation = _local_privesc(asset, findings, vectors)
    if escalation and (best is None or best[0] < PRIVILEGE_RANK["local_admin"]):
        return Obtainable("local_admin", FROM_LOCAL_PRIVESC,
                          f"{escalation} 為本機提權（AV:L）")
    if best is not None:
        return Obtainable(best[1], FROM_SERVICE, "由可利用的服務身分取得")
    return Obtainable("none", NO_EVIDENCE, "沒有對得上已登錄服務的漏洞，無法確定取得的權限")


def check(edge: dict, obtainable: Obtainable) -> Precondition:
    """這條身分邊的前提成不成立。"""
    stored = str(edge.get("credential_source", ""))
    if stored in OFFLINE_CREDENTIALS:
        return Precondition(
            BLOCKED, required=str(edge.get("requires_privilege", "")),
            obtained=obtainable.level,
            reason=f"憑證存放於 {stored}，不在來源機器上——權限再高也取不到")

    required = str(edge.get("requires_privilege", ""))
    if not required:
        return Precondition(UNPROVEN, obtained=obtainable.level,
                            reason="這條邊沒有記錄前提條件")
    if not obtainable.proven:
        return Precondition(UNPROVEN, required=required, obtained=obtainable.level,
                            reason=obtainable.detail)
    if obtainable.rank >= PRIVILEGE_RANK.get(required, 99):
        return Precondition(SATISFIED, required=required, obtained=obtainable.level,
                            reason=obtainable.detail)
    return Precondition(
        BLOCKED, required=required, obtained=obtainable.level,
        reason=f"需要 {required}，在來源端只能取得 {obtainable.level}"
               f"（憑證存放於 {edge.get('credential_source', '未記錄')}）")


def annotate(graph, identity_edges: list[dict], services: list[dict],
             findings: list[dict], vectors: dict[str, str]) -> dict[str, int]:
    """標記圖上每一條 `grants` 邊的前提，並回傳各狀態的筆數。

    `BLOCKED` 的邊標記為不可走，但**節點與邊都留著**——它記錄的是一個真實存在的
    權限關係，只是攻擊者目前走不過去。拿掉它，之後這台機器上多一個提權漏洞時，
    就沒有人會想起這條路曾經存在。
    """
    from .model import GRANTS, USES

    cache: dict[str, Obtainable] = {}
    counts: dict[str, int] = {}
    index = {(e["source"], e["account"], e["target"]): e for e in identity_edges}

    for edge in graph.edges:
        if edge.kind != GRANTS:
            continue
        account = graph.nodes[edge.source].label
        source = next((u.source for u in graph.edges
                       if u.kind == USES and u.target == edge.source), None)
        row = index.get((source, account, edge.target))
        if row is None:
            continue
        if source not in cache:
            cache[source] = privilege_obtainable(source, services, findings, vectors)
        result = check(row, cache[source])
        edge.attrs["precondition"] = result.status
        edge.attrs["requires"] = result.required
        edge.attrs["obtained"] = result.obtained
        if result.reason:
            edge.attrs["precondition_reason"] = result.reason
        counts[result.status] = counts.get(result.status, 0) + 1
    return counts
