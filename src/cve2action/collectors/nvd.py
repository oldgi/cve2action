"""NVD Collector：取得 CVE 的 CVSS 資料，並以帶日期的快照保存。

三個不可妥協的性質（藍圖 §8.3、§15）：

1. **可快取**：抓過的 CVE 寫成 `data/snapshots/nvd/<CVE-ID>.json`，含來源網址與取得時間。
2. **可重跑**：預設讀快照，不打網路；`refresh=True` 才重新抓。文章與測試因此離線可重現。
3. **未知不得變成零**：NVD 沒有任何 CVSS 分數時，`scores` 為空並標 UNKNOWN，絕不填 0.0——
   缺資料若變成低分，整條優先序就被靜默污染了。

快照裡的 `raw` 是唯一真相；`extracted` 只是方便閱讀的投影，讀取時一律從 `raw` 重新解析，
所以解析邏輯升級（例如 Day 8 加入 v4.0）不需要重新抓取任何資料。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..normalization.cvss import SEVERITY_UNKNOWN, CvssError, CvssSet, make_score

API_ROOT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_DIR = Path("data/snapshots/nvd")
# 無 API key 時 NVD 限制 5 requests / 30 秒；留安全邊際
MIN_REQUEST_INTERVAL_SECONDS = 6.5
CVSS_UNKNOWN = SEVERITY_UNKNOWN
# NVD 回應裡的指標區塊名稱與對應版本；v2 已淘汰，不納入
_METRIC_BLOCKS = (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"))


class NvdError(Exception):
    """NVD 取數失敗的共同基底。"""


class NvdNotFound(NvdError):
    """NVD 沒有這個 CVE（明確的空結果，不是暫時性失敗）。"""


class NvdUnavailable(NvdError):
    """逾時、限流或伺服器錯誤——可重試，且不得當成「沒有漏洞」。"""


@dataclass(frozen=True)
class CveRecord:
    """從 NVD 原始回應抽出的欄位；沒有分數時 `cvss.scores` 為空。"""

    cve_id: str
    cvss: CvssSet
    published: str | None
    last_modified: str | None
    description: str
    source_url: str
    retrieved_at: str

    @property
    def has_score(self) -> bool:
        return bool(self.cvss.scores)


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pick_english_description(cve: dict[str, Any]) -> str:
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            return entry.get("value", "")
    return ""


def _extract_scores(cve: dict[str, Any]) -> CvssSet:
    """把 v3.1 與 v4.0 的每一筆評分都保留下來，含評分者與 Primary/Secondary。"""
    metrics = cve.get("metrics", {})
    scores = []
    for block, version in _METRIC_BLOCKS:
        for entry in metrics.get(block, []):
            data = entry.get("cvssData", {})
            if data.get("baseScore") is None or not data.get("vectorString"):
                continue
            try:
                scores.append(make_score(
                    version=version,
                    base_score=data["baseScore"],
                    vector=data["vectorString"],
                    scorer=entry.get("source", ""),
                    scorer_type=entry.get("type", ""),
                ))
            except CvssError:
                # 來源資料自相矛盾（宣告版本與 vector 前綴不符）就略過該筆，不猜測
                continue
    return CvssSet(tuple(scores))


def parse_cve(payload: dict[str, Any], *, cve_id: str, source_url: str,
              retrieved_at: str) -> CveRecord:
    """把 NVD 回應轉成 CveRecord；找不到該 CVE 時丟 NvdNotFound。"""
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        raise NvdNotFound(f"{cve_id}: NVD returned no vulnerability entry")

    cve = vulnerabilities[0].get("cve", {})
    return CveRecord(
        cve_id=cve.get("id", cve_id),
        cvss=_extract_scores(cve),
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


def _extracted_view(record: CveRecord) -> dict[str, Any]:
    return {
        "cve_id": record.cve_id,
        "scores": record.cvss.to_dicts(),
        "published": record.published,
        "last_modified": record.last_modified,
        "description": record.description,
    }


def _write_document(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")


def write_snapshot(path: Path, record: CveRecord, payload: dict[str, Any]) -> None:
    """快照同時保存抽取結果與原始回應，讓後續施工日能重新解讀同一份資料。"""
    _write_document(path, {
        "_meta": {
            "source_url": record.source_url,
            "retrieved_at": record.retrieved_at,
            "api": "NVD CVE API 2.0",
            "extracted_by": "cve2action.collectors.nvd",
        },
        "extracted": _extracted_view(record),
        "raw": payload,
    })


def read_snapshot(path: Path) -> CveRecord:
    """從快照的 `raw` 重新解析；`extracted` 只是投影，不當作真相。"""
    document = json.loads(path.read_text(encoding="utf-8"))
    meta = document["_meta"]
    return parse_cve(
        document["raw"],
        cve_id=path.stem.upper(),
        source_url=meta["source_url"],
        retrieved_at=meta["retrieved_at"],
    )


def load_snapshots(cache_dir: Path | str = DEFAULT_CACHE_DIR) -> dict[str, CveRecord]:
    """讀入目錄下所有快照，以 CVE 編號（大寫）為鍵。"""
    directory = Path(cache_dir)
    if not directory.is_dir():
        return {}
    records = (read_snapshot(p) for p in sorted(directory.glob("CVE-*.json")))
    return {r.cve_id.upper(): r for r in records}


def reparse_snapshot(path: Path) -> CveRecord:
    """不打網路，用現行解析邏輯重寫 `extracted` 投影。"""
    document = json.loads(path.read_text(encoding="utf-8"))
    record = read_snapshot(path)
    document["extracted"] = _extracted_view(record)
    _write_document(path, document)
    return record


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
