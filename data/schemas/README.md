# 資料契約（schemas）

這裡定義 CVE2Action 讀寫的每一份 CSV 的欄位、值域與缺值語意。

**為什麼需要它**：到 Day 15 為止，欄位契約散在三個地方——`models.py` 的常數、`io.py` 的
必要欄位檢查、以及各篇文章的描述。Day 13 把 `assets.csv` 的 `criticality` 更名為
`declared_criticality` 時，`derive_asset_context` 沒跟著改，整整兩天沒人發現，
因為沒有任何一個地方同時記得「這個檔應該長什麼樣」和「誰在讀它」。

## 約定

每份 schema 是一個 YAML，欄位如下：

| 鍵 | 意義 |
|---|---|
| `file` | 這份契約描述哪個檔 |
| `version` | 契約版本；欄位增刪或值域變更就要進版，並在 CHANGELOG 留一行 |
| `produced_by` / `consumed_by` | 誰寫、誰讀——改欄位前先看這兩行 |
| `columns[].name` | 欄位名 |
| `columns[].required` | `true` 代表表頭必須有這一欄 |
| `columns[].blank_ok` | 這一欄允不允許空值 |
| `columns[].domain` | 列舉值域；未列則為自由文字或數值 |
| `columns[].range` | 數值上下界 |
| `columns[].note` | 這一欄為什麼存在，或它**不是**什麼 |

## 三條貫穿全系列的規則

1. **空白代表未知，永遠不代表零、false 或已核准。** 缺值的處理方式一律是移除該項或退回
   更保守的假設，不是補零（見開發規格 §3.2）。
2. **推導值必須帶來源。** 任何 `*_source` 欄位都是必填，值從哪裡來要說得出口。
3. **宣告值不進公式。** `declared_criticality` 這類人工標記只供對照；進公式的一律是推導值。

## 驗證

```bash
uv run python scripts/validate_schemas.py
```

CI 每次都會跑；`tests/test_schemas.py` 也會呼叫同一個驗證器，所以改壞欄位會在兩個地方同時紅。
Day 2 的靜態案例另有專屬檢查 `scripts/validate_day02.py`（契約版本 0.2.0，與這裡分開）。
