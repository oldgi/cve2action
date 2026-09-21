"""統一 CVSS 模型：版本自洽、共用分級、偏好順序、不做跨版本換算。"""

import pytest

from cve2action.normalization import cvss

V31 = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N"
V40 = "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"


def test_version_is_read_from_vector_prefix():
    assert cvss.version_from_vector(V31) == "3.1"
    assert cvss.version_from_vector(V40) == "4.0"


@pytest.mark.parametrize("vector", ["", "AV:N/AC:L", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"])
def test_unsupported_or_malformed_vector_rejected(vector):
    with pytest.raises(cvss.CvssError):
        cvss.version_from_vector(vector)


def test_declared_version_must_match_vector():
    with pytest.raises(cvss.CvssError, match="does not match"):
        cvss.make_score(version="3.1", base_score=6.7, vector=V40)


@pytest.mark.parametrize("score, label", [
    (0.0, "NONE"), (0.1, "LOW"), (3.9, "LOW"), (4.0, "MEDIUM"), (6.9, "MEDIUM"),
    (7.0, "HIGH"), (8.9, "HIGH"), (9.0, "CRITICAL"), (10.0, "CRITICAL"),
])
def test_severity_bands_shared_by_both_versions(score, label):
    assert cvss.severity_for(score) == label


@pytest.mark.parametrize("score", [-0.1, 10.1])
def test_out_of_range_score_rejected(score):
    with pytest.raises(cvss.CvssError):
        cvss.severity_for(score)


def juniper_like() -> cvss.CvssSet:
    """真實案例 CVE-2025-21590 的形狀：同一 CNA 給 v3.1=4.4、v4.0=6.7。"""
    return cvss.CvssSet((
        cvss.make_score(version="3.1", base_score=4.4, vector=V31,
                        scorer="sirt@juniper.net", scorer_type="Secondary"),
        cvss.make_score(version="4.0", base_score=6.7, vector=V40,
                        scorer="sirt@juniper.net", scorer_type="Secondary"),
    ))


def test_preference_order_decides_which_version_is_used():
    scores = juniper_like()
    assert scores.preferred(("3.1", "4.0")).base_score == 4.4
    assert scores.preferred(("4.0", "3.1")).base_score == 6.7


def test_each_score_keeps_its_own_vector_and_version():
    for score in juniper_like().scores:
        assert score.vector.startswith(f"CVSS:{score.version}/")


def test_v40_only_set_falls_through_preference():
    only_v40 = cvss.CvssSet((cvss.make_score(version="4.0", base_score=7.3, vector=V40),))
    chosen = only_v40.preferred(("3.1", "4.0"))
    assert (chosen.version, chosen.base_score) == ("4.0", 7.3)


def test_primary_wins_within_a_version_regardless_of_order():
    secondary = cvss.make_score(version="3.1", base_score=10.0, vector=V31,
                                scorer="cisa-adp", scorer_type="Secondary")
    primary = cvss.make_score(version="3.1", base_score=9.8, vector=V31,
                              scorer="nvd@nist.gov", scorer_type="Primary")
    assert cvss.CvssSet((secondary, primary)).for_version("3.1").base_score == 9.8


def test_empty_set_means_unscored_not_zero():
    empty = cvss.CvssSet()
    assert empty.preferred(("3.1", "4.0")) is None
    assert empty.versions() == ()


def test_round_trips_through_dicts():
    scores = juniper_like()
    assert cvss.CvssSet.from_dicts(scores.to_dicts()) == scores
