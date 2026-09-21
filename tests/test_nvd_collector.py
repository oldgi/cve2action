"""NVD Collector 測試：全部離線，驗證快取、重跑、多版本抽取與「未知不得變成零」。"""

import json
import urllib.error

import pytest

from cve2action.collectors import nvd

V31_PRIMARY = {
    "type": "Primary", "source": "nvd@nist.gov",
    "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                 "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
}
V31_SECONDARY = {
    "type": "Secondary", "source": "cna@example.org",
    "cvssData": {"version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH",
                 "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
}
V40_SECONDARY = {
    "type": "Secondary", "source": "sirt@juniper.net",
    "cvssData": {"version": "4.0", "baseScore": 6.7, "baseSeverity": "MEDIUM",
                 "vectorString": "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"},
}


def payload(metrics: dict | None = None) -> dict:
    cve = {
        "id": "CVE-2022-26134",
        "published": "2022-06-03T15:15:08.070",
        "lastModified": "2023-11-07T03:44:32.323",
        "descriptions": [
            {"lang": "es", "value": "ignorado"},
            {"lang": "en", "value": "Atlassian Confluence OGNL injection."},
        ],
        "metrics": metrics if metrics is not None else {"cvssMetricV31": [V31_PRIMARY]},
    }
    return {"vulnerabilities": [{"cve": cve}]}


def parse(metrics=None, cve_id="CVE-2022-26134"):
    return nvd.parse_cve(payload(metrics), cve_id=cve_id, source_url="u", retrieved_at="t")


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
    record = parse()
    score = record.cvss.for_version("3.1")
    assert (score.base_score, score.severity, score.scorer_type) == (9.8, "CRITICAL", "Primary")
    assert score.vector.startswith("CVSS:3.1/")
    assert record.description.startswith("Atlassian")
    assert record.has_score


def test_missing_score_stays_unknown_not_zero():
    record = parse(metrics={})
    assert not record.has_score
    assert record.cvss.preferred(("3.1", "4.0")) is None


def test_empty_result_raises_not_found():
    with pytest.raises(nvd.NvdNotFound):
        nvd.parse_cve({"vulnerabilities": []}, cve_id="CVE-9999-1",
                      source_url="u", retrieved_at="t")


def test_primary_preferred_over_secondary_within_same_version():
    record = parse(metrics={"cvssMetricV31": [V31_SECONDARY, V31_PRIMARY]})
    assert record.cvss.for_version("3.1").base_score == 9.8
    assert len(record.cvss.scores) == 2, "兩個評分者都要保留，只是選用時 Primary 優先"


def test_v31_and_v40_coexist_with_their_own_vectors():
    record = parse(metrics={"cvssMetricV31": [V31_PRIMARY], "cvssMetricV40": [V40_SECONDARY]})
    assert record.cvss.versions() == ("3.1", "4.0")
    assert record.cvss.for_version("4.0").base_score == 6.7
    assert record.cvss.for_version("4.0").vector.startswith("CVSS:4.0/")
    assert record.cvss.preferred(("3.1", "4.0")).base_score == 9.8
    assert record.cvss.preferred(("4.0", "3.1")).base_score == 6.7


def test_v40_only_cve_falls_back_when_v31_absent():
    record = parse(metrics={"cvssMetricV40": [V40_SECONDARY]})
    assert record.cvss.for_version("3.1") is None
    assert record.cvss.preferred(("3.1", "4.0")).version == "4.0"


def test_inconsistent_metric_is_skipped_not_guessed():
    v40_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
    bad = {"type": "Primary", "source": "x",
           "cvssData": {"baseScore": 5.0, "vectorString": v40_vector}}
    # 放在 v3.1 區塊裡卻帶 4.0 vector：資料自相矛盾，整筆略過
    record = parse(metrics={"cvssMetricV31": [bad]})
    assert not record.has_score


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
    assert document["extracted"]["scores"][0]["base_score"] == 9.8


def test_read_snapshot_reparses_raw_and_ignores_stale_extracted(tmp_path):
    """Day 7 的快照只抽了 v3.1；Day 8 的解析邏輯要能從同一份 raw 讀出 v4.0。"""
    path = tmp_path / "CVE-2022-26134.json"
    raw = payload(metrics={"cvssMetricV31": [V31_PRIMARY], "cvssMetricV40": [V40_SECONDARY]})
    path.write_text(json.dumps({
        "_meta": {"source_url": "u", "retrieved_at": "2026-09-20T00:00:00Z"},
        "extracted": {"cvss_version": "3.1", "base_score": 9.8},  # Day 7 的舊投影
        "raw": raw,
    }), encoding="utf-8")
    record = nvd.read_snapshot(path)
    assert record.cvss.versions() == ("3.1", "4.0")
    assert record.retrieved_at == "2026-09-20T00:00:00Z"

    nvd.reparse_snapshot(path)
    document = json.loads(path.read_text(encoding="utf-8"))
    assert [s["version"] for s in document["extracted"]["scores"]] == ["3.1", "4.0"]
    assert document["raw"] == raw, "reparse 不得改動原始回應"


def test_load_snapshots_keys_by_upper_cve_id(tmp_path):
    nvd.get_cve("cve-2022-26134", cache_dir=tmp_path, client=FakeClient())
    loaded = nvd.load_snapshots(tmp_path)
    assert list(loaded) == ["CVE-2022-26134"]
    assert nvd.load_snapshots(tmp_path / "missing") == {}


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
