"""NVD Collector 測試：全部離線，驗證快取、重跑與「未知不得變成零」。"""

import json
import urllib.error

import pytest

from cve2action.collectors import nvd


def payload(metrics: dict | None = None) -> dict:
    cve = {
        "id": "CVE-2022-26134",
        "published": "2022-06-03T15:15:08.070",
        "lastModified": "2023-11-07T03:44:32.323",
        "descriptions": [
            {"lang": "es", "value": "ignorado"},
            {"lang": "en", "value": "Atlassian Confluence OGNL injection."},
        ],
        "metrics": metrics if metrics is not None else {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }
            ]
        },
    }
    return {"vulnerabilities": [{"cve": cve}]}


class FakeClient:
    """記錄呼叫次數，讓測試能證明第二次讀的是快照而不是網路。"""

    def __init__(self, response=None, error=None):
        self.response = response if response is not None else payload()
        self.error = error
        self.calls = 0

    def fetch(self, cve_id):
        self.calls += 1
        if self.error:
            raise self.error
        return self.response, f"{nvd.API_ROOT}?cveId={cve_id}"


def test_parse_extracts_primary_v31_metric():
    record = nvd.parse_cve(payload(), cve_id="CVE-2022-26134", source_url="u", retrieved_at="t")
    assert (record.base_score, record.severity, record.cvss_version) == (9.8, "CRITICAL", "3.1")
    assert record.vector.startswith("CVSS:3.1/")
    assert record.description.startswith("Atlassian")
    assert record.has_score


def test_missing_score_stays_unknown_not_zero():
    record = nvd.parse_cve(payload(metrics={}), cve_id="CVE-0000-0000",
                           source_url="u", retrieved_at="t")
    assert record.base_score is None
    assert record.severity == nvd.CVSS_UNKNOWN
    assert not record.has_score


def test_empty_result_raises_not_found():
    with pytest.raises(nvd.NvdNotFound):
        nvd.parse_cve({"vulnerabilities": []}, cve_id="CVE-9999-1",
                      source_url="u", retrieved_at="t")


def test_primary_metric_preferred_over_secondary():
    metrics = {"cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}},
        {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}},
    ]}
    record = nvd.parse_cve(payload(metrics=metrics), cve_id="CVE-1",
                           source_url="u", retrieved_at="t")
    assert record.base_score == 9.8


def test_first_call_fetches_then_reruns_read_cache(tmp_path):
    client = FakeClient()
    record, from_cache = nvd.get_cve("CVE-2022-26134", cache_dir=tmp_path, client=client)
    assert (from_cache, client.calls) == (False, 1)

    again, from_cache = nvd.get_cve("CVE-2022-26134", cache_dir=tmp_path, client=client)
    assert (from_cache, client.calls) == (True, 1)  # 重跑不打網路
    assert again == record


def test_refresh_forces_new_fetch(tmp_path):
    client = FakeClient()
    nvd.get_cve("CVE-2022-26134", cache_dir=tmp_path, client=client)
    _, from_cache = nvd.get_cve("CVE-2022-26134", cache_dir=tmp_path, client=client, refresh=True)
    assert (from_cache, client.calls) == (False, 2)


def test_snapshot_records_source_and_keeps_raw(tmp_path):
    nvd.get_cve("CVE-2022-26134", cache_dir=tmp_path, client=FakeClient())
    document = json.loads((tmp_path / "CVE-2022-26134.json").read_text(encoding="utf-8"))
    assert document["_meta"]["source_url"].endswith("cveId=CVE-2022-26134")
    assert document["_meta"]["retrieved_at"].endswith("Z")
    assert document["raw"]["vulnerabilities"], "原始回應必須保留，供後續施工日重新解讀"
    assert document["extracted"]["base_score"] == 9.8


def test_unavailable_error_does_not_write_snapshot(tmp_path):
    client = FakeClient(error=nvd.NvdUnavailable("timeout"))
    with pytest.raises(nvd.NvdUnavailable):
        nvd.get_cve("CVE-2022-26134", cache_dir=tmp_path, client=client)
    assert not (tmp_path / "CVE-2022-26134.json").exists()


@pytest.mark.parametrize(
    "code, expected", [(404, nvd.NvdNotFound), (429, nvd.NvdUnavailable), (503, nvd.NvdUnavailable)]
)
def test_http_status_maps_to_typed_error(monkeypatch, code, expected):
    def boom(*_args, **_kwargs):
        raise urllib.error.HTTPError("url", code, "err", {}, None)

    monkeypatch.setattr(nvd.urllib.request, "urlopen", boom)
    with pytest.raises(expected):
        nvd.NvdClient(min_interval=0).fetch("CVE-2022-26134")


def test_client_throttles_between_requests(monkeypatch):
    slept = []
    monkeypatch.setattr(
        nvd.urllib.request, "urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(urllib.error.URLError("offline")),
    )
    client = nvd.NvdClient(min_interval=6.5, sleep=slept.append)
    for _ in range(2):
        with pytest.raises(nvd.NvdUnavailable):
            client.fetch("CVE-2022-26134")
    assert slept and 0 < slept[0] <= 6.5, "第二次請求前必須等待，避免觸發 NVD 限流"
