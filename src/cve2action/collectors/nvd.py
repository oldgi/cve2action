"""NVD Collector：取得 CVE 的 CVSS 資料，並以帶日期的快照保存。

三個不可妥協的性質（藍圖 §8.3、§15）：

1. **可快取**：抓過的 CVE 寫成 `data/snapshots/nvd/<CVE-ID>.json`，含來源網址與取得時間。
2. **可重跑**：預設讀快照，不打網路；`refresh=True` 才重新抓。文章與測試因此離線可重現。
3. **未知不得變成零**：NVD 沒有 v3.1 分數時回傳 None 並標 UNKNOWN，絕不填 0.0——
   缺資料若變成低分，整條優先序就被靜默污染了。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

API_ROOT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_DIR = Path("data/snapshots/nvd")
# 無 API key 時 NVD 限制 5 requests / 30 秒；留安全邊際
MIN_REQUEST_INTERVAL_SECONDS = 6.5
CVSS_UNKNOWN = "UNKNOWN"


class NvdError(Exception):
    """NVD 取數失敗的共同基底。"""


class NvdNotFound(NvdError):
    """NVD 沒有這個 CVE（明確的空結果，不是暫時性失敗）。"""


class NvdUnavailable(NvdError):
    """逾時、限流或伺服器錯誤——可重試，且不得當成『沒有漏洞』。"""


@dataclass(frozen=True)
class CveRecord:
    """從 NVD 原始回應抽出的欄位；分數缺漏時保持 None。"""

    cve_id: str
    cvss_version: str | None
    base_score: float | None
    vector: str | None
    severity: str
    published: str | None
    last_modified: str | None
    description: str
    source_url: str
    retrieved_at: str

    @property
    def has_score(self) -> bool:
        return self.base_score is not None


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pick_english_description(cve: dict[str, Any]) -> str:
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            return entry.get("value", "")
    return ""

def _pick_primary_metric(cve: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    """挑一組 CVSS 指標。

    v0.1 只認 v3.1，且優先採 NVD 自己的 Primary 評分；找不到就回 (None, None)，
    交由呼叫端標成 UNKNOWN。v4.0 與多來源評分如何共存是 Day 8 的題目，這裡不預先實作。
    """
    metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
    if not metrics:
        return None, None
    primary = next((m for m in metrics if m.get("type") == "Primary"), metrics[0])
    return "3.1", primary


def parse_cve(payload: dict[str, Any], *, cve_id: str, source_url: str,
              retrieved_at: str) -> CveRecord:
    """把 NVD 回應轉成 CveRecord；找不到該 CVE 時丟 NvdNotFound。"""
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        raise NvdNotFound(f"{cve_id}: NVD returned no vulnerability entry")

    cve = vulnerabilities[0].get("cve", {})
    version, metric = _pick_primary_metric(cve)
    data = (metric or {}).get("cvssData", {})
    score = data.get("baseScore")

    return CveRecord(
        cve_id=cve.get("id", cve_id),
        cvss_version=version,
        base_score=float(score) if score is not None else None,
        vector=data.get("vectorString"),
        severity=(data.get("baseSeverity") or CVSS_UNKNOWN).upper(),
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        description=_pick_english_description(cve),
        source_url=source_url,
        retrieved_at=retrieved_at,
    )


class NvdClient:
    """對 NVD API 2.0 發出請求，並自我限流。"""

    def __init__(self, *, api_key: str | None = None, timeout: float = 30.0,
                 min_interval: float = MIN_REQUEST_INTERVAL_SECONDS,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.min_interval = min_interval
        self._sleep = sleep
        self._last_request_at: float | None = None

    def _throttle(self) -> None:
        if self._last_request_at is None:
            return
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self.min_interval:
            self._sleep(self.min_interval - elapsed)

    def fetch(self, cve_id: str) -> tuple[dict[str, Any], str]:
        """回傳 (原始 JSON, 來源網址)。網路層問題一律轉成 NvdUnavailable。"""
        url = f"{API_ROOT}?cveId={cve_id}"
        request = urllib.request.Request(url, headers={"User-Agent": "cve2action/0.2"})
        if self.api_key:
            request.add_header("apiKey", self.api_key)

        self._throttle()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise NvdNotFound(f"{cve_id}: not found at NVD") from error
            raise NvdUnavailable(f"{cve_id}: NVD returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise NvdUnavailable(f"{cve_id}: NVD request failed ({error})") from error
        finally:
            self._last_request_at = time.monotonic()

        return payload, url


def snapshot_path(cve_id: str, cache_dir: Path | str = DEFAULT_CACHE_DIR) -> Path:
    return Path(cache_dir) / f"{cve_id.upper()}.json"


def write_snapshot(path: Path, record: CveRecord, payload: dict[str, Any]) -> None:
    """快照同時保存抽取結果與原始回應，讓後續施工日能重新解讀同一份資料。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "_meta": {
            "source_url": record.source_url,
            "retrieved_at": record.retrieved_at,
            "api": "NVD CVE API 2.0",
            "extracted_by": "cve2action.collectors.nvd",
        },
        "extracted": asdict(record),
        "raw": payload,
    }
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")


def read_snapshot(path: Path) -> CveRecord:
    document = json.loads(path.read_text(encoding="utf-8"))
    return CveRecord(**document["extracted"])


def get_cve(cve_id: str, *, cache_dir: Path | str = DEFAULT_CACHE_DIR,
            refresh: bool = False, client: NvdClient | None = None) -> tuple[CveRecord, bool]:
    """取得一筆 CVE，回傳 (record, from_cache)。

    預設走快照，因此重跑不需要網路、也不會因為 NVD 當掉就改變結果。
    """
    path = snapshot_path(cve_id, cache_dir)
    if path.exists() and not refresh:
        return read_snapshot(path), True

    payload, url = (client or NvdClient()).fetch(cve_id)
    record = parse_cve(payload, cve_id=cve_id.upper(), source_url=url, retrieved_at=_now_iso())
    write_snapshot(path, record, payload)
    return record, False
