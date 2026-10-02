"""評分：把正規化後的因子算成 Priority Score，並解釋這個分數怎麼來的。

`engine` 負責算，`explain` 負責說。兩者共用同一組資料結構——輸出的 CSV 列與
人讀的理由都是同一份 Explanation 的投影，不是各自拼出來的（Day 16）。
"""

from .engine import explain_finding, rank, rank_explained, row_from, score_finding
from .explain import Explanation, Factor, explain_row

__all__ = ["rank", "rank_explained", "score_finding", "explain_finding", "row_from",
           "Explanation", "Factor", "explain_row"]
