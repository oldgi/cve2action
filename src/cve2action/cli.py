"""CLI：cve2action rank --scanner ... --context ... --rules ... --out ranked_result.csv"""

from __future__ import annotations

import argparse
import sys

from . import __version__
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rules = load_rules(args.rules)
        findings = read_scanner(args.scanner)
        contexts = read_asset_context(args.context)
    except (RulesError, InputError, FileNotFoundError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    rows = rank(findings, contexts, rules)
    write_ranked_result(rows, args.out)

    scored = sum(1 for r in rows if r["decision"] != DECISION_NEEDS_CONTEXT)
    pending = len(rows) - scored
    print(f"ranked {scored} finding(s), {pending} NEEDS_CONTEXT -> {args.out}")
    print(f"rules: {args.rules} (version {rules.version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
