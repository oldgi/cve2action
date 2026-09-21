"""EPSS Collector 測試：全部離線，驗證批次、快取、查無資料與逾時處理。"""

import json
import urllib.error

import pytest

from cve2action.collectors import epss


def entry(cve="CVE-2021-44228", score="0.9430", pct="0.9990", date="2026-09-21"):
    return {"cve": cve, "epss": score, "percentile": pct, "date": date}


class FakeClient:
    """回傳固定資料並記錄呼叫，用來證明快取與批次行為。"""

    def __init__(self, entries=None, error=None):
        self.entries = {e["cve"]: e for e in (entries or [])}
        self.error = error
        self.calls: list[list[str]] = []

    def fetch_many(self, cve_ids):
        ids = list(cve_ids)
        self.calls.append(ids)
        if self.error:
            raise self.error
        return {c: (self.entries.get(c), f"{epss.API_ROOT}?cve=...") for c in ids}


def test_parse_entry_reads_probability_percentile_and_model_date():
    record = epss.parse_entry(entry(), cve_id="CVE-2021-44228", source_url="u", retrieved_at="t")
    assert (record.epss, record.percentile, record.model_date) == (0.943, 0.999, "2026-09-21")
    assert record.has_score


def test_missing_entry_is_unknown_not_zero():
    record = epss.parse_entry(None, cve_id="cve-2099-1", source_url="u", retrieved_at="t")
    assert record.cve_id == "CVE-2099-1"
    assert record.epss is None and record.percentile is None
    assert not record.has_score


@pytest.mark.parametrize("bad", [entry(score="1.5"), entry(pct="-0.1")])
def test_out_of_range_values_rejected(bad):
    with pytest.raises(epss.EpssError):
        epss.parse_entry(bad, cve_id="CVE-2021-44228", source_url="u", retrieved_at="t")


def test_first_run_fetches_then_rerun_reads_cache(tmp_path):
    client = FakeClient([entry()])
    first = epss.get_epss_many(["CVE-2021-44228"], cache_dir=tmp_path, client=client)
    assert first["CVE-2021-44228"][1] is False and len(client.calls) == 1

    second = epss.get_epss_many(["CVE-2021-44228"], cache_dir=tmp_path, client=client)
    assert second["CVE-2021-44228"][1] is True and len(client.calls) == 1
    assert second["CVE-2021-44228"][0] == first["CVE-2021-44228"][0]


def test_not_found_is_cached_so_rerun_does_not_requery(tmp_path):
    client = FakeClient([])  # EPSS 查無此 CVE
    first = epss.get_epss_many(["CVE-2099-1"], cache_dir=tmp_path, client=client)
    assert not first["CVE-2099-1"][0].has_score
    document = json.loads((tmp_path / "CVE-2099-1.json").read_text(encoding="utf-8"))
    assert document["extracted"]["found"] is False and document["raw"] is None

    epss.get_epss_many(["CVE-2099-1"], cache_dir=tmp_path, client=client)
    assert len(client.calls) == 1, "查無資料也是答案，重跑不該再打網路"


def test_only_uncached_ids_go_to_network(tmp_path):
    client = FakeClient([entry(), entry(cve="CVE-2022-26134", score="0.97")])
    epss.get_epss_many(["CVE-2021-44228"], cache_dir=tmp_path, client=client)
    result = epss.get_epss_many(["CVE-2021-44228", "CVE-2022-26134"], cache_dir=tmp_path,
                                client=client)
    assert client.calls == [["CVE-2021-44228"], ["CVE-2022-26134"]]
    assert [r[1] for r in result.values()] == [True, False]


def test_refresh_refetches_even_when_cached(tmp_path):
    client = FakeClient([entry()])
    epss.get_epss_many(["CVE-2021-44228"], cache_dir=tmp_path, client=client)
    epss.get_epss_many(["CVE-2021-44228"], cache_dir=tmp_path, client=client, refresh=True)
    assert len(client.calls) == 2


def test_unavailable_writes_nothing(tmp_path):
    client = FakeClient(error=epss.EpssUnavailable("timeout"))
    with pytest.raises(epss.EpssUnavailable):
        epss.get_epss_many(["CVE-2021-44228"], cache_dir=tmp_path, client=client)
    assert not list(tmp_path.glob("*.json"))


def test_snapshot_keeps_source_and_raw(tmp_path):
    epss.get_epss_many(["CVE-2021-44228"], cache_dir=tmp_path, client=FakeClient([entry()]))
    document = json.loads((tmp_path / "CVE-2021-44228.json").read_text(encoding="utf-8"))
    assert document["_meta"]["api"] == "FIRST EPSS API v1"
    assert document["_meta"]["retrieved_at"].endswith("Z")
    assert document["raw"]["epss"] == "0.9430"
    assert document["extracted"]["model_date"] == "2026-09-21"


def test_load_snapshots_keys_by_cve_id(tmp_path):
    epss.get_epss_many(["cve-2021-44228"], cache_dir=tmp_path, client=FakeClient([entry()]))
    assert list(epss.load_snapshots(tmp_path)) == ["CVE-2021-44228"]
    assert epss.load_snapshots(tmp_path / "missing") == {}


# --- 真實 client 的網路層行為（以 monkeypatch 取代 urlopen） -------------------

class FakeResponse:
    def __init__(self, body: dict):
        self._body = json.dumps(body).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_client_batches_at_batch_size_and_throttles(monkeypatch):
    urls: list[str] = []
    slept: list[float] = []

    def fake_urlopen(request, timeout):
        urls.append(request.full_url)
        ids = urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)["cve"][0]
        data = [entry(cve=c) for c in ids.split(",")]
        return FakeResponse({"status": "OK", "data": data})

    monkeypatch.setattr(epss.urllib.request, "urlopen", fake_urlopen)
    client = epss.EpssClient(batch_size=2, min_interval=1.0, sleep=slept.append)
    result = client.fetch_many(["CVE-1", "CVE-2", "CVE-3"])
    assert len(urls) == 2, "3 個 CVE、批次大小 2 → 兩次請求"
    assert set(result) == {"CVE-1", "CVE-2", "CVE-3"}
    assert slept and 0 < slept[0] <= 1.0, "第二批前要等待"


def test_client_reports_missing_ids_as_none(monkeypatch):
    monkeypatch.setattr(
        epss.urllib.request, "urlopen",
        lambda *_a, **_k: FakeResponse({"status": "OK", "data": [entry(cve="CVE-1")]}),
    )
    result = epss.EpssClient(min_interval=0).fetch_many(["CVE-1", "CVE-2"])
    assert result["CVE-1"][0]["epss"] == "0.9430"
    assert result["CVE-2"][0] is None


@pytest.mark.parametrize("code", [429, 503])
def test_http_error_becomes_unavailable(monkeypatch, code):
    def boom(*_a, **_k):
        raise urllib.error.HTTPError("url", code, "err", {}, None)

    monkeypatch.setattr(epss.urllib.request, "urlopen", boom)
    with pytest.raises(epss.EpssUnavailable):
        epss.EpssClient(min_interval=0).fetch_many(["CVE-1"])


def test_timeout_becomes_unavailable(monkeypatch):
    def boom(*_a, **_k):
        raise TimeoutError("timed out")

    monkeypatch.setattr(epss.urllib.request, "urlopen", boom)
    with pytest.raises(epss.EpssUnavailable, match="timed out"):
        epss.EpssClient(min_interval=0).fetch_many(["CVE-1"])


def test_non_ok_status_becomes_unavailable(monkeypatch):
    monkeypatch.setattr(
        epss.urllib.request, "urlopen",
        lambda *_a, **_k: FakeResponse({"status": "ERROR", "data": []}),
    )
    with pytest.raises(epss.EpssUnavailable):
        epss.EpssClient(min_interval=0).fetch_many(["CVE-1"])
