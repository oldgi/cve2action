#!/usr/bin/env python
"""用 data/schemas/ 的契約檢查 repo 裡的 CSV。

檢查三件事，任何一件不符就以 exit 1 結束並列出每一處違規：

1. 表頭：required 欄位必須存在；不得出現契約沒有宣告的欄位。
2. 值域：宣告了 domain 的欄位，每一格都要落在裡面。
3. 缺值：blank_ok 為 false 的欄位不得空白——空白代表未知，不是零也不是 false。

這支腳本只看靜態資料是否符合自己宣告的契約，不執行評分，也不驗證數值是否合理。
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "data" / "schemas"

# 契約 → 套用到哪些實際檔案。一份契約可以管多個檔（例如 day-06 與 northstar 的 scanner）。
TARGETS: dict[str, tuple[str, ...]] = {
    "scanner": (
        "data/synthetic/northstar/scanner.csv",
        "data/synthetic/day-06-scanner.csv",
        "data/synthetic/day-08-scanner.csv",
    ),
    "assets": ("data/synthetic/northstar/assets.csv",),
    "controls": ("data/synthetic/northstar/controls.csv",),
    "business_context": ("data/synthetic/northstar/business_context.csv",),
    "asset_context": ("data/synthetic/northstar/asset_context.csv",),
    "network_edges": ("data/synthetic/northstar/network_edges.csv",),
    "identity_edges": ("data/synthetic/northstar/identity_edges.csv",),
    "remediations": ("data/synthetic/northstar/remediations.csv",),
    # day-06／day-08 的 asset_context 是 Day 12 之前手寫的，沒有 source 欄位：
    # 它們記錄的是當時的契約，刻意不回頭補欄位，所以不套用現行 asset_context 契約。
}


def load_schema(name: str) -> dict:
    return yaml.safe_load((SCHEMA_DIR / f"{name}.schema.yaml").read_text(encoding="utf-8"))


def check_file(schema: dict, path: Path) -> list[str]:
    problems: list[str] = []
    columns = {c["name"]: c for c in schema["columns"]}
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        header = reader.fieldnames or []
        rows = list(reader)

    for name, spec in columns.items():
        if spec.get("required") and name not in header:
            problems.append(f"{path}: missing required column '{name}'")
    for name in header:
        if name not in columns:
            problems.append(f"{path}: column '{name}' is not declared in {schema['file']} contract")

    for index, row in enumerate(rows, start=2):  # 2 = 表頭之後的第一列
        for name, spec in columns.items():
            if name not in header:
                continue
            value = (row.get(name) or "").strip()
            if not value:
                if not spec.get("blank_ok", False):
                    problems.append(f"{path}:{index}: '{name}' is blank but blank_ok is false")
                continue
            domain = spec.get("domain")
            if domain is not None and value not in [str(d) for d in domain]:
                problems.append(f"{path}:{index}: '{name}'='{value}' not in {domain}")
            bounds = spec.get("range")
            if bounds is not None:
                try:
                    number = float(value)
                except ValueError:
                    problems.append(f"{path}:{index}: '{name}'='{value}' is not a number")
                    continue
                low, high = float(bounds[0]), float(bounds[1])
                if not low <= number <= high:
                    problems.append(f"{path}:{index}: '{name}'={number} outside {bounds}")
    return problems


def validate() -> list[str]:
    problems: list[str] = []
    for name, targets in TARGETS.items():
        schema = load_schema(name)
        for target in targets:
            path = ROOT / target
            if not path.exists():
                problems.append(f"{target}: declared in TARGETS but missing on disk")
                continue
            problems.extend(check_file(schema, path))
    return problems


def main() -> int:
    problems = validate()
    if problems:
        print(f"FAIL: {len(problems)} schema violation(s)", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    checked = sum(len(t) for t in TARGETS.values())
    print(f"PASS: {checked} file(s) match their contract in data/schemas/.")
    print("Scope: header, declared domains and blank policy only; no scoring is executed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
