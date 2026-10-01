"""相容層：引擎自 Day 16 起住在 `cve2action.scoring.engine`。

既有的 `from cve2action.engine import rank` 仍可運作，新程式請改用
`from cve2action.scoring import rank`。
"""

from .scoring.engine import explain_finding, rank, rank_explained, row_from, score_finding

__all__ = ["rank", "rank_explained", "score_finding", "explain_finding", "row_from"]
