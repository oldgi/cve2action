"""KEV Collector：取得 CISA Known Exploited Vulnerabilities 目錄。

跟 NVD / EPSS 最大的不同是**取數形狀**：KEV 是一份完整目錄（單一 JSON，約 1.7 MB、
一千多筆），一次抓整份、之後在本地查表，不是逐筆查詢。這帶來一個語意上的差別：

- NVD / EPSS 查不到 → 我們不知道（UNKNOWN）。
- KEV 目錄**已取得**、裡面沒有這個 CVE → 這是明確事實：CISA 目前沒有把它列入（NOT_LISTED）。
- 目錄**沒取得** → 才是 UNKNOWN。

所以 KEV 狀態是三態。`NOT_LISTED` 是關於目錄的事實，**不是「這個漏洞安全」**——
CISA 只收錄有可靠證據、已遭實際利用的漏洞，沒收錄只代表它不在那個門檻內。

`knownRansomwareCampaignUse` 同理：來源值是 "Known" / "Unknown"，後者映射為 None 而非 False。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_CACHE_DIR = Path("data/snapshots/kev")
CATALOG_FILENAME = "catalog.json"

KEV_LISTED = "LISTED"
KEV_NOT_LISTED = "NOT_LISTED"
KEV_UNKNOWN = "UNKNOWN"


class KevError(Exception):
    """KEV 取數或解析失敗的共同基底。"""


class KevUnavailable(KevError):
    """逾時或伺服器錯誤——可重試，且不得當成「目錄是空的」。"""


class KevCatalogError(KevError):
    """目錄內容不完整或自相矛盾，不可當成可信來源使用。"""


@dataclass(frozen=True)
class KevEntry:
    """KEV 目錄中的一筆；缺欄位保持 None，不猜測。"""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    due_date: str | None
    required_action: str
    known_ransomware: bool | None  # "Known" → True；"Unknown" → None（不是 False）


@dataclass(frozen=True)
class KevCatalog:
    """一次取得的完整 KEV 目錄快照。"""

    catalog_version: str
    date_released: str
    entries: dict[str, KevEntry]
    source_url: str
    retrieved_at: str

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, cve_id: str) -> KevEntry | None:
        return self.entries.get(cve_id.strip().upper())

    def status(self, cve_id: str) -> str:
        """LISTED 或 NOT_LISTED。目錄在手上，兩者都是事實；UNKNOWN 只在沒有目錄時出現。"""
        return KEV_LISTED if self.get(cve_id) is not None else KEV_NOT_LISTED


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ransomware(value: Any) -> bool | None:
    text = str(value or "").strip().lower()
    if text == "known":
        return True
    if text == "unknown":
        return None
    return None


def parse_catalog(payload: dict[str, Any], *, source_url: str, retrieved_at: str) -> KevCatalog:
    """解析目錄並檢查完整性；宣告筆數與實際筆數不符就拒收。"""
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise KevCatalogError("KEV catalog has no vulnerabilities array")

    declared = payload.get("count")
    if isinstance(declared, int) and declared != len(vulnerabilities):
        # 檔案被截斷或來源出錯時，寧可整批拒收，也不要拿殘缺目錄去判斷「不在清單裡」
        raise KevCatalogError(
            f"KEV catalog count mismatch: declared {declared}, got {len(vulnerabilities)}"
        )

    entries: dict[str, KevEntry] = {}
    for item in vulnerabilities:
        cve_id = str(item.get("cveID", "")).strip().upper()
        if not cve_id:
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            vendor_project=item.get("vendorProject", ""),
            product=item.get("product", ""),
            vulnerability_name=item.get("vulnerabilityName", ""),
            date_added=item.get("dateAdded", ""),
            due_date=item.get("dueDate") or None,
            required_action=item.get("requiredAction", ""),
            known_ransomware=_parse_ransomware(item.get("knownRansomwareCampaignUse")),
        )

    return KevCatalog(
        catalog_version=str(payload.get("catalogVersion", "")),
        date_released=str(payload.get("dateReleased", "")),
        entries=entries,
        source_url=source_url,
        retrieved_at=retrieved_at,
    )


class KevClient:
    """下載 CISA KEV 目錄。單一檔案，不需要限流。"""

    def __init__(self, *, timeout: float = 60.0) -> None:
        self.timeout = timeout

    def fetch(self) -> tuple[dict[str, Any], str]:
        request = urllib.request.Request(
            CATALOG_URL, headers={"User-Agent": "cve2action/0.2"}
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise KevUnavailable(f"KEV returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise KevUnavailable(f"KEV download failed ({error})") from error
        return payload, CATALOG_URL


def catalog_path(cache_dir: Path | str = DEFAULT_CACHE_DIR) -> Path:
    return Path(cache_dir) / CATALOG_FILENAME


def write_snapshot(path: Path, catalog: KevCatalog, payload: dict[str, Any]) -> None:
    """整份目錄存成一個檔；raw 是唯一真相，_meta 記錄目錄版本與取得時間。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "_meta": {
            "source_url": catalog.source_url,
            "retrieved_at": catalog.retrieved_at,
            "catalog_version": catalog.catalog_version,
            "date_released": catalog.date_released,
            "entry_count": len(catalog),
            "api": "CISA KEV catalog (JSON feed)",
            "extracted_by": "cve2action.collectors.kev",
        },
        "raw": payload,
    }
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")


def read_snapshot(path: Path) -> KevCatalog:
    document = json.loads(path.read_text(encoding="utf-8"))
    meta = document["_meta"]
    return parse_catalog(document["raw"], source_url=meta["source_url"],
                         retrieved_at=meta["retrieved_at"])


def get_catalog(*, cache_dir: Path | str = DEFAULT_CACHE_DIR, refresh: bool = False,
                client: KevClient | None = None) -> tuple[KevCatalog, bool]:
    """取得目錄，回傳 (catalog, from_cache)。預設讀快照，不打網路。"""
    path = catalog_path(cache_dir)
    if path.exists() and not refresh:
        return read_snapshot(path), True

    payload, url = (client or KevClient()).fetch()
    catalog = parse_catalog(payload, source_url=url, retrieved_at=_now_iso())
    write_snapshot(path, catalog, payload)
    return catalog, False


def load_catalog(cache_dir: Path | str = DEFAULT_CACHE_DIR) -> KevCatalog | None:
    """只讀既有快照，沒有就回 None——呼叫端據此標 UNKNOWN，而不是 NOT_LISTED。"""
    path = catalog_path(cache_dir)
    return read_snapshot(path) if path.exists() else None
