"""CSV 讀寫與欄位驗證（pandas 只出現在 I/O 邊界，engine 內部用純 dict）。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from .models import CONTEXT_REQUIRED_COLUMNS, OUTPUT_COLUMNS, SCANNER_REQUIRED_COLUMNS


class InputError(ValueError):
    """輸入檔缺少必要欄位或結構錯誤。"""


def _read_csv(path: str | Path, required: tuple[str, ...], label: str) -> pd.DataFrame:
    frame = pd.read_csv(path, dtype=str, encoding="utf-8-sig").fillna("")
    missing = [column for column in required if column not in frame.columns]
    if missing:
        raise InputError(f"{label} ({path}): missing required columns {missing}")
    return frame


def read_scanner(path: str | Path) -> list[dict[str, Any]]:
    frame = _read_csv(path, SCANNER_REQUIRED_COLUMNS, "scanner.csv")
    return frame.to_dict(orient="records")


def read_asset_context(path: str | Path) -> dict[str, dict[str, Any]]:
    frame = _read_csv(path, CONTEXT_REQUIRED_COLUMNS, "asset_context.csv")
    duplicated = frame.loc[frame["asset"].duplicated(), "asset"].tolist()
    if duplicated:
        raise InputError(
            f"asset_context.csv ({path}): duplicate asset ids {sorted(set(duplicated))}"
        )
    return {row["asset"]: row for row in frame.to_dict(orient="records")}


def write_ranked_result(rows: list[dict[str, Any]], path: str | Path) -> None:
    frame = pd.DataFrame(rows, columns=list(OUTPUT_COLUMNS))
    frame.to_csv(path, index=False, encoding="utf-8", lineterminator="\n")
