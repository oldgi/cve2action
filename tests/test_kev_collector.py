"""KEV Collector 測試：全部離線，驗證三態語意、目錄完整性與快取。"""

import json
import urllib.error

import pytest

from cve2action.collectors import kev


def item(cve="CVE-2021-44228", added="2021-12-10", due="2021-12-24", ransomware="Known"):
    return {
        "cveID": cve,
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "dateAdded": added,
        "shortDescription": "…",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": due,
        "knownRansomwareCampaignUse": ransomware,
    }


def catalog_payload(items=None, *, version="2026.09.22", count=None):
    items = [item()] if items is None else items
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": version,
        "dateReleased": "2026-09-22T19:02:09.9788Z",
        "count": len(items) if count is None else count,
        "vulnerabilities": items,
    }


def parse(payload=None):
    return kev.parse_catalog(payload or catalog_payload(), source_url="u", retrieved_at="t")


class FakeClient:
    def __init__(self, payload=None, error=None):
        self.payload = payload if payload is not None else catalog_payload()
        self.error = error
        self.calls = 0

    def fetch(self):
        self.calls += 1
        if self.error:
            raise self.error
        return self.payload, kev.CATALOG_URL


# --- 三態語意（Day 10 的核心） ------------------------------------------------

def test_listed_cve_reports_listed_with_details():
    catalog = parse()
    assert catalog.status("CVE-2021-44228") == kev.KEV_LISTED
    entry = catalog.get("CVE-2021-44228")
    assert (entry.date_added, entry.due_date) == ("2021-12-10", "2021-12-24")
    assert entry.known_ransomware is True
    assert entry.vendor_project == "Apache"


def test_absent_cve_is_not_listed_because_the_catalog_is_complete():
    """目錄在手上，沒找到就是明確事實——NOT_LISTED，不是 UNKNOWN。"""
    assert parse().status("CVE-2018-15919") == kev.KEV_NOT_LISTED


def test_no_catalog_at_all_is_unknown(tmp_path):
    """沒有目錄時只能回 None，呼叫端據此標 UNKNOWN，不得當成 NOT_LISTED。"""
    assert kev.load_catalog(tmp_path) is None


def test_status_lookup_is_case_and_space_insensitive():
    catalog = parse()
    assert catalog.status("  cve-2021-44228 ") == kev.KEV_LISTED


def test_ransomware_unknown_maps_to_none_not_false():
    """「Unknown」是不知道，不是「沒有被勒索軟體用過」。"""
    catalog = parse(catalog_payload([item(ransomware="Unknown")]))
    assert catalog.get("CVE-2021-44228").known_ransomware is None


def test_missing_due_date_stays_none():
    catalog = parse(catalog_payload([item(due="")]))
    assert catalog.get("CVE-2021-44228").due_date is None


# --- 目錄完整性 ---------------------------------------------------------------

def test_count_mismatch_is_rejected():
    """宣告 500 筆卻只有 1 筆：檔案不完整，拒收而不是拿殘缺目錄判 NOT_LISTED。"""
    with pytest.raises(kev.KevCatalogError, match="count mismatch"):
        parse(catalog_payload(count=500))


@pytest.mark.parametrize("payload", [{}, {"vulnerabilities": []}, {"vulnerabilities": "nope"}])
def test_empty_or_malformed_catalog_rejected(payload):
    with pytest.raises(kev.KevCatalogError):
        kev.parse_catalog(payload, source_url="u", retrieved_at="t")


def test_entry_without_cve_id_is_skipped():
    catalog = parse(catalog_payload([item(), {"cveID": "", "dateAdded": "2020-01-01"}], count=2))
    assert len(catalog) == 1


def test_catalog_metadata_is_kept():
    catalog = parse()
    assert catalog.catalog_version == "2026.09.22"
    assert catalog.date_released.startswith("2026-09-22")


# --- 快取與重跑 ---------------------------------------------------------------

def test_first_call_downloads_then_rerun_reads_cache(tmp_path):
    client = FakeClient()
    catalog, from_cache = kev.get_catalog(cache_dir=tmp_path, client=client)
    assert (from_cache, client.calls) == (False, 1)

    again, from_cache = kev.get_catalog(cache_dir=tmp_path, client=client)
    assert (from_cache, client.calls) == (True, 1)
    assert again.catalog_version == catalog.catalog_version


def test_refresh_redownloads(tmp_path):
    client = FakeClient()
    kev.get_catalog(cache_dir=tmp_path, client=client)
    kev.get_catalog(cache_dir=tmp_path, client=client, refresh=True)
    assert client.calls == 2


def test_snapshot_is_one_file_with_version_and_raw(tmp_path):
    kev.get_catalog(cache_dir=tmp_path, client=FakeClient())
    files = list(tmp_path.iterdir())
    assert [f.name for f in files] == ["catalog.json"], "整份目錄存成單一檔，不拆成每個 CVE"
    document = json.loads(files[0].read_text(encoding="utf-8"))
    assert document["_meta"]["catalog_version"] == "2026.09.22"
    assert document["_meta"]["entry_count"] == 1
    assert document["_meta"]["retrieved_at"].endswith("Z")
    assert document["raw"]["vulnerabilities"][0]["cveID"] == "CVE-2021-44228"


def test_unavailable_writes_nothing(tmp_path):
    client = FakeClient(error=kev.KevUnavailable("timeout"))
    with pytest.raises(kev.KevUnavailable):
        kev.get_catalog(cache_dir=tmp_path, client=client)
    assert not list(tmp_path.glob("*.json"))


def test_incomplete_download_writes_nothing(tmp_path):
    client = FakeClient(payload=catalog_payload(count=999))
    with pytest.raises(kev.KevCatalogError):
        kev.get_catalog(cache_dir=tmp_path, client=client)
    assert not list(tmp_path.glob("*.json"))


def test_load_catalog_reads_existing_snapshot(tmp_path):
    kev.get_catalog(cache_dir=tmp_path, client=FakeClient())
    loaded = kev.load_catalog(tmp_path)
    assert loaded.status("CVE-2021-44228") == kev.KEV_LISTED


# --- 網路層 -------------------------------------------------------------------

class FakeResponse:
    def __init__(self, body):
        self._body = json.dumps(body).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_client_downloads_catalog(monkeypatch):
    monkeypatch.setattr(kev.urllib.request, "urlopen",
                        lambda *_a, **_k: FakeResponse(catalog_payload()))
    payload, url = kev.KevClient().fetch()
    assert payload["count"] == 1 and url == kev.CATALOG_URL


@pytest.mark.parametrize("code", [403, 503])
def test_http_error_becomes_unavailable(monkeypatch, code):
    def boom(*_a, **_k):
        raise urllib.error.HTTPError("url", code, "err", {}, None)

    monkeypatch.setattr(kev.urllib.request, "urlopen", boom)
    with pytest.raises(kev.KevUnavailable):
        kev.KevClient().fetch()


def test_timeout_becomes_unavailable(monkeypatch):
    def boom(*_a, **_k):
        raise TimeoutError("timed out")

    monkeypatch.setattr(kev.urllib.request, "urlopen", boom)
    with pytest.raises(kev.KevUnavailable, match="timed out"):
        kev.KevClient().fetch()
