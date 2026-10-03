"""CLI：cve2action rank --scanner ... --context ... --rules ... --out ranked_result.csv"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path

from . import __version__
from .collectors.epss import DEFAULT_CACHE_DIR as EPSS_CACHE_DIR
from .collectors.epss import EpssError, get_epss_many
from .collectors.epss import load_snapshots as load_epss_snapshots
from .collectors.kev import DEFAULT_CACHE_DIR as KEV_CACHE_DIR
from .collectors.kev import KEV_LISTED, KevError, get_catalog, load_catalog
from .collectors.nvd import (
    CVSS_UNKNOWN,
    DEFAULT_CACHE_DIR,
    NvdError,
    get_cve,
    load_snapshots,
    reparse_snapshot,
)
from .io import InputError, read_asset_context, read_scanner, write_ranked_result
from .models import DECISION_NEEDS_CONTEXT
from .normalization.business import derive_business_context
from .normalization.exposure import ExposureError, derive_asset_context
from .rules import RulesError, load_rules
from .scoring import explain_row, rank, rank_explained
from .scoring.calibration import CalibrationError, compare, load_baseline, report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cve2action",
        description="CVE2Action Decision Engine：計算可解釋的處置優先順序",
    )
    parser.add_argument("--version", action="version", version=f"cve2action {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    rank_parser = subparsers.add_parser(
        "rank", help="scanner.csv + asset_context.csv + risk_rules.yaml -> ranked_result.csv"
    )
    rank_parser.add_argument("--scanner", required=True, help="弱掃結果 CSV（asset,cve,cvss）")
    rank_parser.add_argument(
        "--context", required=True, help="資產情境 CSV（asset,environment,reachability,...）"
    )
    rank_parser.add_argument("--rules", required=True, help="Decision Rule 設定 YAML")
    rank_parser.add_argument("--out", required=True, help="輸出 ranked_result.csv 路徑")
    rank_parser.add_argument(
        "--snapshots", help="NVD 快照目錄；給了就用有來源的 CVSS 取代掃描器手填值"
    )
    rank_parser.add_argument("--epss", help="EPSS 快照目錄；給了才會有威脅項")
    rank_parser.add_argument("--kev", help="KEV 目錄快照所在目錄；給了才會有威脅項")
    rank_parser.add_argument(
        "--controls", help="控制措施 CSV；給了就逐筆檢查控制攔不攔得到該漏洞（Day 15）"
    )
    rank_parser.add_argument(
        "--as-of", default=str(date.today()), help="控制證據的評估基準日（YYYY-MM-DD）"
    )

    fetch_parser = subparsers.add_parser(
        "fetch-cve", help="從 NVD 取得 CVE/CVSS 並寫成帶日期的快照"
    )
    fetch_parser.add_argument("cve_ids", nargs="*", help="CVE 編號，可給多個")
    fetch_parser.add_argument("--from-scanner", help="改從 scanner.csv 讀取所有 CVE")
    fetch_parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR), help="快照目錄")
    fetch_parser.add_argument(
        "--refresh", action="store_true", help="忽略既有快照，重新向 NVD 取數"
    )
    fetch_parser.add_argument(
        "--reparse", action="store_true",
        help="不打網路，用現行解析邏輯重寫快照目錄裡所有檔案的 extracted 投影",
    )

    epss_parser = subparsers.add_parser(
        "fetch-epss", help="從 FIRST EPSS 取得遭利用機率並寫成帶日期的快照"
    )
    epss_parser.add_argument("cve_ids", nargs="*", help="CVE 編號，可給多個")
    epss_parser.add_argument("--from-scanner", help="改從 scanner.csv 讀取所有 CVE")
    epss_parser.add_argument("--cache-dir", default=str(EPSS_CACHE_DIR), help="快照目錄")
    epss_parser.add_argument(
        "--refresh", action="store_true", help="忽略既有快照，重新向 EPSS 取數"
    )

    kev_parser = subparsers.add_parser(
        "fetch-kev", help="下載 CISA KEV 完整目錄，並查詢指定 CVE 的列入狀態"
    )
    kev_parser.add_argument("cve_ids", nargs="*", help="要查狀態的 CVE 編號，可給多個")
    kev_parser.add_argument("--from-scanner", help="改從 scanner.csv 讀取所有 CVE")
    kev_parser.add_argument("--cache-dir", default=str(KEV_CACHE_DIR), help="快照目錄")
    kev_parser.add_argument(
        "--refresh", action="store_true", help="忽略既有快照，重新下載目錄"
    )

    explain_parser = subparsers.add_parser(
        "explain", help="說明某一筆（或整份）的分數怎麼來的，以及為什麼排在這裡"
    )
    for name, helptext in (
        ("--scanner", "弱掃結果 CSV"),
        ("--context", "資產企業脈絡 CSV"),
        ("--rules", "Decision Rule 設定 YAML"),
    ):
        explain_parser.add_argument(name, required=True, help=helptext)
    explain_parser.add_argument("--snapshots", help="NVD 快照目錄")
    explain_parser.add_argument("--epss", help="EPSS 快照目錄")
    explain_parser.add_argument("--kev", help="KEV 目錄快照所在目錄")
    explain_parser.add_argument("--controls", help="控制措施 CSV")
    explain_parser.add_argument("--as-of", default=str(date.today()), help="控制證據基準日")
    explain_parser.add_argument("--cve", help="只說明這個 CVE")
    explain_parser.add_argument("--asset", help="只說明這個資產")
    explain_parser.add_argument("--top", type=int, help="只說明前 N 名")
    explain_parser.add_argument("--json", action="store_true", help="輸出 JSON 而非文字")

    cal_parser = subparsers.add_parser(
        "calibrate", help="把人工排序基準與模型排序比對，列出每一處分歧"
    )
    for name, helptext in (
        ("--scanner", "弱掃結果 CSV"),
        ("--context", "資產企業脈絡 CSV"),
        ("--rules", "Decision Rule 設定 YAML"),
        ("--baseline", "人工排序基準 YAML"),
    ):
        cal_parser.add_argument(name, required=True, help=helptext)
    cal_parser.add_argument("--snapshots", help="NVD 快照目錄")
    cal_parser.add_argument("--epss", help="EPSS 快照目錄")
    cal_parser.add_argument("--kev", help="KEV 目錄快照所在目錄")
    cal_parser.add_argument("--controls", help="控制措施 CSV")
    cal_parser.add_argument("--as-of", default=str(date.today()), help="控制證據基準日")

    derive_parser = subparsers.add_parser(
        "derive-context", help="從 assets.csv + controls.csv 推導 asset_context.csv"
    )
    derive_parser.add_argument("--assets", required=True, help="資產清冊 CSV")
    derive_parser.add_argument("--controls", required=True, help="控制措施 CSV")
    derive_parser.add_argument(
        "--business", required=True,
        help="業務脈絡 CSV（data_class / rto_hours / customer_facing）；criticality 由此推導",
    )
    derive_parser.add_argument("--rules", required=True, help="Decision Rule 設定 YAML")
    derive_parser.add_argument("--out", required=True, help="輸出 asset_context.csv 路徑")
    derive_parser.add_argument(
        "--as-of", required=True,
        help="情境時點 YYYY-MM-DD；控制證據的年齡以此計算，固定值才能重現",
    )
    return parser


def _read_rows(path: str) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def _load_scoring_inputs(args):
    """explain 與 rank 共用的輸入載入；回傳 rank_explained 需要的全部參數。"""
    rules = load_rules(args.rules)
    return (
        read_scanner(args.scanner),
        read_asset_context(args.context),
        rules,
        load_snapshots(args.snapshots) if args.snapshots else {},
        load_epss_snapshots(args.epss) if args.epss else {},
        load_catalog(args.kev) if args.kev else None,
        _read_rows(args.controls) if args.controls else None,
        date.fromisoformat(args.as_of),
    )


def _run_explain(args) -> int:
    try:
        inputs = _load_scoring_inputs(args)
    except (RulesError, InputError, ValueError, FileNotFoundError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if args.kev and inputs[5] is None:
        print(f"error: no KEV catalog under {args.kev}", file=sys.stderr)
        return 2

    ordered = rank_explained(*inputs)
    # 先挑出要說明的，再把「它前面那一名」一起帶上——排序的理由只有在比較時才存在
    wanted = [
        (position, item) for position, item in enumerate(ordered)
        if (args.cve is None or item.cve.upper() == args.cve.upper())
        and (args.asset is None or item.asset.upper() == args.asset.upper())
    ]
    if args.top is not None:
        wanted = wanted[:args.top]
    if not wanted:
        print("error: nothing matched --cve/--asset", file=sys.stderr)
        return 2

    if args.json:
        payload = [dict(e.to_dict(), rank=p + 1) for p, e in wanted]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    for position, item in wanted:
        above = ordered[position - 1] if position > 0 else None
        print(f"#{position + 1} / {len(ordered)}")
        print(explain_row(item, above))
        print()
    return 0


def _run_calibrate(args) -> int:
    try:
        baseline = load_baseline(args.baseline)
        inputs = _load_scoring_inputs(args)
    except (RulesError, InputError, CalibrationError, ValueError, FileNotFoundError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    try:
        result = compare(baseline, rank(*inputs))
    except CalibrationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(report(result))
    if result.has_unexplained:
        print("", file=sys.stderr)
        print(f"FAIL: {len(result.unexplained)} 處分歧沒有書面解釋", file=sys.stderr)
        return 1
    return 0


def _run_derive_context(args) -> int:
    try:
        rules = load_rules(args.rules)
        as_of = date.fromisoformat(args.as_of)
        business = derive_business_context(_read_rows(args.business), rules.business_impact)
        rows = derive_asset_context(_read_rows(args.assets), _read_rows(args.controls),
                                    rules, as_of, business=business)
    except (RulesError, ExposureError, ValueError, KeyError, FileNotFoundError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    header = ["asset", "environment", "reachability", "control_effectiveness",
              "business_criticality", "reachability_source", "control_source",
              "business_source"]
    with open(args.out, "w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator='\n')
        writer.writerow(header)
        writer.writerows([row[column] for column in header] for row in rows)

    expired = sum(1 for r in rows if "expired" in r["control_source"])
    observed = sum(1 for r in rows if r["reachability_source"] == "observed")
    print(f"derived {len(rows)} asset(s) as of {as_of} -> {args.out}")
    print(f"reachability: {len(rows) - observed} from zone, {observed} observed; "
          f"control evidence expired on {expired} asset(s) "
          f"(max age {rules.control_evidence_max_age_days}d)")
    criticality = Counter(r["business_criticality"] for r in rows)
    print("business criticality: "
          + ", ".join(f"{v} {k}" for k, v in sorted(criticality.items())))
    return 0


def _run_fetch_kev(args) -> int:
    try:
        catalog, from_cache = get_catalog(cache_dir=args.cache_dir, refresh=args.refresh)
    except KevError as error:
        # 目錄拿不到或不完整時，不得把任何 CVE 判成「不在清單裡」
        print(f"error: {error}", file=sys.stderr)
        return 1

    origin = "cache" if from_cache else "cisa"
    print(f"catalog {catalog.catalog_version}: {len(catalog)} entries "
          f"(released {catalog.date_released[:10]}, {origin})")

    cve_ids = list(args.cve_ids)
    if args.from_scanner or cve_ids:
        cve_ids = _collect_cve_ids(args)
        if cve_ids is None:
            return 2
        listed = 0
        for cve_id in cve_ids:
            entry = catalog.get(cve_id)
            if entry is None:
                print(f"  {cve_id.upper():<18} {'NOT_LISTED':<12}")
                continue
            listed += 1
            ransomware = "ransomware" if entry.known_ransomware else "ransomware unknown"
            print(f"  {entry.cve_id:<18} {KEV_LISTED:<12} added={entry.date_added}"
                  f"  due={entry.due_date}  {ransomware}")
        print(f"{listed}/{len(cve_ids)} listed in KEV -> {args.cache_dir}")
    return 0


def _collect_cve_ids(args) -> list[str] | None:
    """合併命令列與 --from-scanner 的 CVE 清單；讀檔失敗回 None（已印出錯誤）。"""
    cve_ids = list(args.cve_ids)
    if args.from_scanner:
        try:
            findings = read_scanner(args.from_scanner)
        except (InputError, FileNotFoundError) as error:
            print(f"error: {error}", file=sys.stderr)
            return None
        seen = dict.fromkeys(f["cve"].strip() for f in findings if f.get("cve", "").strip())
        cve_ids.extend(cve for cve in seen if cve not in cve_ids)
    if not cve_ids:
        print("error: no CVE ids given (pass ids or --from-scanner)", file=sys.stderr)
        return None
    return cve_ids


def _run_fetch_epss(args) -> int:
    cve_ids = _collect_cve_ids(args)
    if cve_ids is None:
        return 2
    try:
        results = get_epss_many(cve_ids, cache_dir=args.cache_dir, refresh=args.refresh)
    except EpssError as error:
        # 整批失敗：不寫任何快照，也不得把這些 CVE 當成「沒有威脅」
        print(f"error: {error}", file=sys.stderr)
        return 1
    unknown = 0
    for record, from_cache in results.values():
        origin = "cache" if from_cache else "epss"
        if record.has_score:
            print(f"  {record.cve_id:<18} epss={record.epss:.4f}  pct={record.percentile:.4f}"
                  f"  model={record.model_date}  ({origin})")
        else:
            unknown += 1
            print(f"  {record.cve_id:<18} epss=   n/a  UNKNOWN (not in EPSS)  ({origin})")
    print(f"{len(results) - unknown}/{len(results)} scored, {unknown} unknown -> {args.cache_dir}")
    return 0


def _format_scores(record) -> str:
    if not record.has_score:
        return f" n/a  {CVSS_UNKNOWN}"
    parts = []
    for version in record.cvss.versions():
        score = record.cvss.for_version(version)
        parts.append(f"v{version}={score.base_score:g} {score.severity}")
    return "  ".join(parts)


def _run_fetch_cve(args) -> int:
    if args.reparse:
        paths = sorted(Path(args.cache_dir).glob("CVE-*.json"))
        for path in paths:
            record = reparse_snapshot(path)
            print(f"  {record.cve_id:<18} {_format_scores(record)}  (reparsed)")
        print(f"{len(paths)} snapshot(s) reparsed in {args.cache_dir}")
        return 0

    cve_ids = _collect_cve_ids(args)
    if cve_ids is None:
        return 2

    failures = 0
    for cve_id in cve_ids:
        try:
            record, from_cache = get_cve(cve_id, cache_dir=args.cache_dir, refresh=args.refresh)
        except NvdError as error:
            # 取數失敗不得靜默略過，也不得當成「這個 CVE 沒風險」
            print(f"  {cve_id:<18} FAILED   {error}", file=sys.stderr)
            failures += 1
            continue
        origin = "cache" if from_cache else "nvd"
        print(f"  {record.cve_id:<18} {_format_scores(record)}  ({origin})")

    print(f"{len(cve_ids) - failures}/{len(cve_ids)} resolved -> {args.cache_dir}")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "fetch-cve":
        return _run_fetch_cve(args)
    if args.command == "fetch-epss":
        return _run_fetch_epss(args)
    if args.command == "fetch-kev":
        return _run_fetch_kev(args)
    if args.command == "derive-context":
        return _run_derive_context(args)
    if args.command == "explain":
        return _run_explain(args)
    if args.command == "calibrate":
        return _run_calibrate(args)
    try:
        rules = load_rules(args.rules)
        findings = read_scanner(args.scanner)
        contexts = read_asset_context(args.context)
        controls = _read_rows(args.controls) if args.controls else None
        as_of = date.fromisoformat(args.as_of)
    except (RulesError, InputError, ValueError, FileNotFoundError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    snapshots = load_snapshots(args.snapshots) if args.snapshots else {}
    epss_records = load_epss_snapshots(args.epss) if args.epss else {}
    kev_catalog = load_catalog(args.kev) if args.kev else None
    if args.kev and kev_catalog is None:
        print(f"error: no KEV catalog under {args.kev}", file=sys.stderr)
        return 2
    rows = rank(findings, contexts, rules, snapshots, epss_records, kev_catalog,
                controls, as_of)
    write_ranked_result(rows, args.out)

    scored = sum(1 for r in rows if r["decision"] != DECISION_NEEDS_CONTEXT)
    pending = len(rows) - scored
    sourced = sum(1 for r in rows if str(r["cvss_source"]).startswith("nvd"))
    print(f"ranked {scored} finding(s), {pending} NEEDS_CONTEXT -> {args.out}")
    threatened = sum(1 for r in rows if r["threat"] != "")
    print(f"rules: {args.rules} (version {rules.version}); "
          f"cvss from nvd: {sourced}/{len(rows)}"
          + (f" (preference {list(rules.cvss_version_preference)})" if snapshots else ""))
    print(f"threat input on {threatened}/{len(rows)} row(s)"
          + ("" if threatened else "; threat weight redistributed to severity"))
    if controls is not None:
        revoked = sum(1 for r in rows if "not applicable" in str(r["control_source"])
                      or "no authentication" in str(r["control_source"]))
        discounted = sum(1 for r in rows
                         if str(r["control_effectiveness"]) in ("PARTIAL", "STRONG"))
        print(f"controls: {discounted} row(s) discounted, {revoked} revoked as inapplicable "
              f"(evidence as of {as_of})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
