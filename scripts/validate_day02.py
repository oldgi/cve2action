"""Validate Day 2 static fixtures; no external packages, network or writes."""
import csv
import json
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_csv(name):
    with (ROOT / 'data' / 'synthetic' / name).open(encoding='utf-8-sig', newline='') as stream:
        rows = list(csv.reader(stream))
    header = rows[0]
    assert len(header) == len(set(header)), f'{name}: duplicate headers'
    assert all(len(row) == len(header) for row in rows[1:]), f'{name}: ragged CSV'
    return header, [dict(zip(header, row)) for row in rows[1:]]


def validate(assets, findings, scenario):
    asset_ids = [a['asset_id'] for a in assets]
    assert len(asset_ids) == len(set(asset_ids)), 'duplicate asset IDs'
    assert len({f['finding_id'] for f in findings}) == len(findings), 'duplicate finding IDs'
    as_of = datetime.fromisoformat(scenario['scenario_as_of']).date()
    for asset in assets:
        assert asset['prod_reachability'] in {'true', 'false', 'conditional', 'unknown'}
        assert asset['owner_team'], 'owner missing'
    for finding in findings:
        assert finding['asset_id'] in asset_ids, 'orphan finding'
        assert 0 <= float(finding['cvss_base_score']) <= 10
        for field in ['control_verified_on', 'kev_date_added']:
            assert date.fromisoformat(finding[field]) <= as_of, f'future evidence: {field}'
        for field in ['sla_deadline', 'immediate_action_deadline', 'risk_acceptance_valid_until']:
            if finding[field]:
                date.fromisoformat(finding[field])
        if finding['risk_acceptance_status'] == 'APPROVED':
            assert finding['risk_acceptance_ref'], 'approval reference missing'
            assert finding['risk_acceptance_approver'], 'approver missing'
            assert finding['risk_acceptance_valid_until'], 'acceptance expiry missing'
            assert date.fromisoformat(finding['risk_acceptance_valid_until']) >= as_of, 'acceptance expired'
        if finding['decision_status'] == 'DEFER_APPROVED':
            assert finding['risk_acceptance_status'] == 'APPROVED', 'deferral not approved'
            age = (as_of - date.fromisoformat(finding['control_verified_on'])).days
            assert age <= scenario['control_evidence_max_age_calendar_days'], 'stale control evidence'


def main():
    ah, assets = read_csv('day-02-assets.csv')
    fh, findings = read_csv('day-02-findings.csv')
    scenario = json.loads((ROOT / 'data/synthetic/day-02-scenario.json').read_text(encoding='utf-8'))
    validate(assets, findings, scenario)
    assert (len(assets), len(ah), len(findings), len(fh)) == (5, 12, 2, 33)
    assert 'exploitation_scale' not in fh
    a, b = (next(f for f in findings if f['finding_id'] == fid) for fid in ['F-D02-A', 'F-D02-B'])
    assert a['decision_status'] == 'REVIEW_REQUIRED' and a['risk_acceptance_status'] == 'PENDING'
    assert not a['risk_acceptance_approver'] and not a['risk_acceptance_valid_until']
    assert a['path_status'] == 'NO_PATH_FOUND_IN_MODEL'
    assert b['decision_status'] == 'MITIGATE_NOW_PATCH_PENDING'
    assert b['compatibility_status'] == 'VALIDATION_PENDING'
    assert b['immediate_action_deadline'] == '2022-06-03' and not b['sla_deadline']
    assert all(f['scanning_activity'] == 'UNKNOWN' for f in findings)
    assert (date(2022, 6, 8) - date(2022, 6, 1)).days == 7
    assert (date(2022, 6, 9) - date(2022, 6, 1)).days == 8
    # Exercise calendar-age boundaries in a disposable fixture, not a real approval.
    approved = dict(a, risk_acceptance_status='APPROVED', risk_acceptance_approver='SYNTHETIC_TEST_ONLY',
                    risk_acceptance_valid_until='2022-06-16', decision_status='DEFER_APPROVED')
    validate(assets, [approved, dict(b)], dict(scenario, scenario_as_of='2022-06-08T23:00:00-07:00'))
    try:
        validate(assets, [approved, dict(b)], dict(scenario, scenario_as_of='2022-06-09T23:00:00-07:00'))
    except AssertionError as error:
        assert 'stale control evidence' in str(error)
    else:
        raise AssertionError('age 8 must be rejected')
    # Negative tests prove the checker rejects these invalid states.
    cases = [
        ({'asset_id': 'MISSING'}, 'orphan finding'),
        ({'risk_acceptance_status': 'APPROVED'}, 'approver missing'),
        ({'decision_status': 'DEFER_APPROVED'}, 'deferral not approved'),
        ({'control_verified_on': '2022-06-04'}, 'future evidence'),
    ]
    for changes, expected in cases:
        altered = [dict(a, **changes), dict(b)]
        try:
            validate(assets, altered, scenario)
        except AssertionError as error:
            assert expected in str(error), (expected, str(error))
        else:
            raise AssertionError(f'negative test was not rejected: {expected}')
    print('PASS: 5 assets / 2 findings; schema, keys, dates, decision fixtures, TTL boundary and 5 negative tests.')
    print('Scope: static data consistency only; no live controls or risk-engine validation.')


if __name__ == '__main__':
    main()
