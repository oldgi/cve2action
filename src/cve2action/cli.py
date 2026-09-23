"""CLI：cve2action rank --scanner ... --context ... --rules ... --out ranked_result.csv"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .collectors.epss import DEFAULT_CACHE_DIR as EPSS_CACHE_DIR
from .collectors.epss import EpssError, get_epss_many
from .collectors.kev import DEFAULT_CACHE_DIR as KEV_CACHE_DIR
from .collectors.kev import KEV_LISTED, KevError, get_catalog
from .collectors.nvd import (
    CVSS_UNKNOWN,
    DEFAULT_CACHE_DIR,
    NvdError,
    get_cve,
    load_snapshots,
    reparse_snapshot,
)
from .engine import rank
from .io import InputError, read_asset_context, read_scanner, write_ranked_result
from .models import DECISION_NEEDS_CONTEXT
from .rules import RulesError, load_rules


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
    return parser


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
    try:
        rules = load_rules(args.rules)
        findings = read_scanner(args.scanner)
        contexts = read_asset_context(args.context)
    except (RulesError, InputError, FileNotFoundError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    snapshots = load_snapshots(args.snapshots) if args.snapshots else {}
    rows = rank(findings, contexts, rules, snapshots)
    write_ranked_result(rows, args.out)

    scored = sum(1 for r in rows if r["decision"] != DECISION_NEEDS_CONTEXT)
    pending = len(rows) - scored
    sourced = sum(1 for r in rows if str(r["cvss_source"]).startswith("nvd"))
    print(f"ranked {scored} finding(s), {pending} NEEDS_CONTEXT -> {args.out}")
    print(f"rules: {args.rules} (version {rules.version}); "
          f"cvss from nvd: {sourced}/{len(rows)}"
          + (f" (preference {list(rules.cvss_version_preference)})" if snapshots else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
