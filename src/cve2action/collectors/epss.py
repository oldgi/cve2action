"""EPSS Collector：取得 FIRST EPSS 的遭利用機率，並以帶日期的快照保存。

與 NVD collector 相同的三個性質（可快取、可重跑、未知不得變成零），外加兩個 EPSS 特有的處理：

1. **查無資料是正常結果，不是錯誤。** EPSS 只涵蓋已發布且未被撤回的 CVE，新的、保留的、
   或 REJECTED 的 CVE 查不到。這種情況一樣寫快照（`epss: null`），重跑時不再打網路；
   引擎端視為 UNKNOWN，不得當成 0。
2. **分數每天重算。** `model_date` 是 EPSS 模型的日期，跟 `retrieved_at` 一樣重要——
   兩週前的 0.97 和今天的 0.97 不是同一個數字。

API 支援一次查多個 CVE，因此這裡以批次為單位取數，並在批次間留間隔。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

API_ROOT = "https://api.first.org/data/v1/epss"
DEFAULT_CACHE_DIR = Path("data/snapshots/epss")
BATCH_SIZE = 100  # FIRST 建議單次不超過 100 個 CVE
MIN_REQUEST_INTERVAL_SECONDS = 1.0


class EpssError(Exception):
    """EPSS 取數失敗的共同基底。"""


class EpssUnavailable(EpssError):
    """逾時、限流或伺服器錯誤——可重試，且不得當成「沒有威脅」。"""


@dataclass(frozen=True)
class EpssRecord:
    """單一 CVE 的 EPSS 快照；查無資料時 epss / percentile 為 None。"""

    cve_id: str
    epss: float | None  # 未來 30 天遭利用的機率，0–1
    percentile: float | None  # 在所有 CVE 中的相對位置，0–1
    model_date: str | None  # EPSS 模型日期（YYYY-MM-DD）
    source_url: str
    retrieved_at: str

    @property
    def has_score(self) -> bool:
        return self.epss is not None


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_entry(entry: dict[str, Any] | None, *, cve_id: str, source_url: str,
                retrieved_at: str) -> EpssRecord:
    """把 API 的單筆 data 轉成 EpssRecord；entry 為 None 代表查無資料。"""
    if entry is None:
        return EpssRecord(cve_id=cve_id.upper(), epss=None, percentile=None, model_date=None,
                          source_url=source_url, retrieved_at=retrieved_at)
    epss = float(entry["epss"])
    percentile = float(entry["percentile"])
    if not (0.0 <= epss <= 1.0 and 0.0 <= percentile <= 1.0):
        raise EpssError(f"{cve_id}: EPSS values out of range ({epss}, {percentile})")
    return EpssRecord(
        cve_id=str(entry.get("cve", cve_id)).upper(),
        epss=epss,
        percentile=percentile,
        model_date=entry.get("date"),
        source_url=source_url,
        retrieved_at=retrieved_at,
    )


class EpssClient:
    """對 FIRST EPSS API 發出批次請求，並在批次間留間隔。"""

    def __init__(self, *, timeout: float = 30.0, batch_size: int = BATCH_SIZE,
                 min_interval: float = MIN_REQUEST_INTERVAL_SECONDS,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.timeout = timeout
        self.batch_size = batch_size
        self.min_interval = min_interval
        self._sleep = sleep
        self._last_request_at: float | None = None

    def _throttle(self) -> None:
        if self._last_request_at is None:
            return
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self.min_interval:
            self._sleep(self.min_interval - elapsed)

    def _fetch_batch(self, cve_ids: list[str]) -> tuple[dict[str, dict[str, Any]], str]:
        url = f"{API_ROOT}?{urllib.parse.urlencode({'cve': ','.join(cve_ids)})}"
        request = urllib.request.Request(url, headers={"User-Agent": "cve2action/0.2"})
        self._throttle()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise EpssUnavailable(f"EPSS returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise EpssUnavailable(f"EPSS request failed ({error})") from error
        finally:
            self._last_request_at = time.monotonic()

        if payload.get("status") != "OK":
            raise EpssUnavailable(f"EPSS returned status {payload.get('status')!r}")
        found = {str(e["cve"]).upper(): e for e in payload.get("data", []) if "cve" in e}
        return found, url

    def fetch_many(self, cve_ids: Iterable[str]) -> dict[str, tuple[dict[str, Any] | None, str]]:
        """回傳 {CVE: (entry 或 None, 來源網址)}；查無資料的 CVE 也會出現在結果裡。"""
        ordered = list(dict.fromkeys(c.strip().upper() for c in cve_ids if c and c.strip()))
        results: dict[str, tuple[dict[str, Any] | None, str]] = {}
        for start in range(0, len(ordered), self.batch_size):
            batch = ordered[start:start + self.batch_size]
            found, url = self._fetch_batch(batch)
            for cve_id in batch:
                results[cve_id] = (found.get(cve_id), url)
        return results


def snapshot_path(cve_id: str, cache_dir: Path | str = DEFAULT_CACHE_DIR) -> Path:
    return Path(cache_dir) / f"{cve_id.upper()}.json"


def write_snapshot(path: Path, record: EpssRecord, entry: dict[str, Any] | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "_meta": {
            "source_url": record.source_url,
            "retrieved_at": record.retrieved_at,
            "api": "FIRST EPSS API v1",
            "extracted_by": "cve2action.collectors.epss",
        },
        "extracted": {
            "cve_id": record.cve_id,
            "epss": record.epss,
            "percentile": record.percentile,
            "model_date": record.model_date,
            "found": record.has_score,
        },
        "raw": entry,
    }
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")


def read_snapshot(path: Path) -> EpssRecord:
    """從快照的 `raw` 重新解析；`raw` 為 null 代表當時查無資料。"""
    document = json.loads(path.read_text(encoding="utf-8"))
    meta = document["_meta"]
    return parse_entry(document.get("raw"), cve_id=path.stem,
                       source_url=meta["source_url"], retrieved_at=meta["retrieved_at"])


def load_snapshots(cache_dir: Path | str = DEFAULT_CACHE_DIR) -> dict[str, EpssRecord]:
    directory = Path(cache_dir)
    if not directory.is_dir():
        return {}
    records = (read_snapshot(p) for p in sorted(directory.glob("CVE-*.json")))
    return {r.cve_id: r for r in records}


def get_epss_many(cve_ids: Iterable[str], *, cache_dir: Path | str = DEFAULT_CACHE_DIR,
                  refresh: bool = False, client: EpssClient | None = None,
                  ) -> dict[str, tuple[EpssRecord, bool]]:
    """取得多筆 EPSS，回傳 {CVE: (record, from_cache)}。

    有快照的直接讀，其餘合成一次批次請求；查無資料一樣寫快照，重跑不再打網路。
    """
    ordered = list(dict.fromkeys(c.strip().upper() for c in cve_ids if c and c.strip()))
    results: dict[str, tuple[EpssRecord, bool]] = {}
    pending: list[str] = []
    for cve_id in ordered:
        path = snapshot_path(cve_id, cache_dir)
        if path.exists() and not refresh:
            results[cve_id] = (read_snapshot(path), True)
        else:
            pending.append(cve_id)

    if pending:
        fetched = (client or EpssClient()).fetch_many(pending)
        retrieved_at = _now_iso()
        for cve_id in pending:
            entry, url = fetched[cve_id]
            record = parse_entry(entry, cve_id=cve_id, source_url=url, retrieved_at=retrieved_at)
            write_snapshot(snapshot_path(cve_id, cache_dir), record, entry)
            results[cve_id] = (record, False)

    return {cve_id: results[cve_id] for cve_id in ordered}
