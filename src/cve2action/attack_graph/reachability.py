"""可達性：一條連線憑什麼算數（Day 20，藍圖 §9.0 閘門 3）。

Day 19 的 `reaches` 只問了兩件事：政策有沒有允許、對面有沒有服務在聽。
那是「能不能送封包過去」。但可達性不是一個布林值，它是一串**有沒有依據**的判斷。

## 四種依據，不是通過與不通過

| 判定 | 意思 |
|---|---|
| `BY_POLICY` | 有一條 allow 政策涵蓋這個方向**與這個 port** |
| `INTRA_ZONE` | 同一個 zone 內，這組 zone 層政策管不到 |
| `DRIFT` | 政策明文拒絕，但實際連得通 |
| `UNGOVERNED` | 跨 zone，卻找不到任何談論這個方向與 port 的政策 |

**port 要逐一比對，不能只看 zone 對。** 一條「DMZ → MGMT 允許 3389」的政策
不授權 389——那是兩個不同的服務，差一個字元而已。

## 觀測贏過政策，但差異要講出來

`DRIFT` 的連線**不會從圖上移除**。政策寫錯不會讓封包不通；把觀測刪掉只是讓
報告變好看。它留在圖上，帶著「沒有依據」這個標記，讓 Day 23 的評分知道
這一跳的性質不同。

同理 `UNGOVERNED`：找不到政策不代表被擋住，只代表**沒有人寫下來這件事該不該發生**。

## 回程通道

有些利用需要受害端往外連（Log4Shell 的經典打法就是讓受害端去連攻擊者的 LDAP）。
擋不擋得住要看 egress 政策——**而沒有 egress 政策不等於 egress 被擋住**。
這是 Day 5 以來同一條規則：不知道，不能換來比較安全的結論。
"""

from __future__ import annotations

from dataclasses import dataclass

BY_POLICY = "BY_POLICY"
INTRA_ZONE = "INTRA_ZONE"
DRIFT = "DRIFT"
UNGOVERNED = "UNGOVERNED"

GOVERNED = "GOVERNED"
ALL_PORTS = 0
INTERNET_SCOPE = "INTERNET"


@dataclass(frozen=True)
class Basis:
    """一條連線的可達性依據。"""

    status: str
    policy: str = ""
    detail: str = ""

    @property
    def governed(self) -> bool:
        return self.status in (BY_POLICY, INTRA_ZONE)

    def __str__(self) -> str:
        suffix = f" [{self.policy}]" if self.policy else ""
        return f"{self.status}{suffix}{(' ' + self.detail) if self.detail else ''}"


def _matches(policy: dict, source: str, destination: str, port: int) -> bool:
    if policy["source_scope"] != source or policy["destination"] != destination:
        return False
    declared = int(policy["port"])
    return declared in (ALL_PORTS, port)


def classify(source_zone: str, destination_zone: str, port: int,
             policies: list[dict]) -> Basis:
    """一條跨 zone 連線的依據。同 zone 不由這組政策管轄。"""
    if source_zone == destination_zone:
        return Basis(INTRA_ZONE, detail="同一 zone，這組政策管不到")

    hits = [p for p in policies if _matches(p, source_zone, destination_zone, port)]
    allow = [p for p in hits if p["action"] == "allow"]
    deny = [p for p in hits if p["action"] == "deny"]

    if allow:
        return Basis(BY_POLICY, policy=allow[0]["policy_id"])
    if deny:
        # 政策說不行，實際卻連得通。觀測贏，但這是設定漂移，要指出來。
        return Basis(DRIFT, policy=deny[0]["policy_id"], detail="政策拒絕卻連得通")
    return Basis(UNGOVERNED, detail=f"{source_zone}→{destination_zone}:{port} 無任何政策")


def egress_governance(zone: str, policies: list[dict]) -> Basis:
    """這個 zone 往 Internet 的出向有沒有被政策談論過。

    回程通道（例如 Log4Shell 讓受害端往外連 LDAP）能不能成立就看這個。
    **沒有政策不等於被擋住**——回 `UNGOVERNED`，不回「已阻擋」。
    """
    hits = [p for p in policies
            if p["source_scope"] == zone and p["destination"] == INTERNET_SCOPE]
    if not hits:
        return Basis(UNGOVERNED, detail=f"{zone}→INTERNET 無任何政策，不得視為已阻擋")
    deny_all = [p for p in hits if p["action"] == "deny" and int(p["port"]) == ALL_PORTS]
    if deny_all:
        return Basis(BY_POLICY, policy=deny_all[0]["policy_id"], detail="出向全面阻擋")
    return Basis(BY_POLICY, policy=hits[0]["policy_id"])


def annotate(graph, network_edges: list[dict], policies: list[dict],
             zones: dict[str, str]) -> dict[str, int]:
    """逐條標記圖上 `reaches` 邊的依據，回傳各類判定的筆數。

    只標記、不刪除。刪掉沒有依據的連線，等於讓報告看起來比現實安全。
    """
    from .model import REACHES, service_id

    index = {}
    for row in network_edges:
        if row.get("allowed") != "yes":
            continue
        source = "internet" if row["source"].upper() == INTERNET_SCOPE else row["source"]
        index[(source, service_id(row["target"], row["port"]))] = row

    counts: dict[str, int] = {}
    for edge in graph.edges:
        if edge.kind != REACHES:
            continue
        row = index.get((edge.source, edge.target))
        if row is None:
            continue
        source_zone = (INTERNET_SCOPE if edge.source == "internet"
                       else zones.get(row["source"], ""))
        basis = classify(source_zone, zones.get(row["target"], ""), int(row["port"]),
                         policies)
        edge.attrs["basis"] = basis.status
        if basis.policy:
            edge.attrs["policy"] = basis.policy
        if basis.detail:
            edge.attrs["basis_detail"] = basis.detail
        counts[basis.status] = counts.get(basis.status, 0) + 1
    return counts
