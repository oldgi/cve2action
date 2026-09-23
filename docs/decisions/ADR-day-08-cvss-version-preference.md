# ADR｜Day 8：CVSS v3.1 與 v4.0 並存，不換算、標版本、偏好順序外部化

- 日期：2026-09-21
- 狀態：Accepted for v0.1
- 影響範圍：`normalization/cvss.py`、`collectors/nvd.py`、`engine.py`、`risk_rules.yaml`

## 背景

Day 7 的 NVD 快照只讀 v3.1。實際資料顯示（`data/snapshots/nvd/`）：

- 同一個 CVE 可能同時有 v3.1 與 v4.0，且分數不同（CVE-2025-21590：4.4 vs 6.7）。
- 有些 CVE 只有 v4.0（CVE-2024-6242）。
- 同一版本可能有多個評分者：NVD 自己的 Primary，以及 CNA／CISA ADP 的 Secondary。7 個快照中 NVD 自評的只有 3 個。

Decision Engine v0.1 的 `S = CVSS / 10` 需要一個明確、可重現的規則決定用哪個數字。

## 決策

1. **每筆分數保留 version、base_score、vector、scorer、scorer_type，不做跨版本換算。** 兩版共用 0–10 與相同的定性分級，但公式不同，換算會製造假精確。
2. **選用順序外部化**於 `risk_rules.yaml` 的 `cvss.version_preference`，v0.1 為 `["3.1", "4.0"]`：先 3.1 是為了與 Day 5 建立的驗收基準可比；只有 4.0 的 CVE 才退用 4.0。
3. **同版本多評分者的取用順序：Primary → NVD 自評（`nvd@nist.gov`）→ 回應原始順序。**

   第二層於 Day 11 補上。NVD 偶爾把自己的評分標成 `Secondary`：CVE-2020-1472（Zerologon）
   的兩筆 v3.1 都是 Secondary，微軟 5.5 排在 NVD 自評 10.0 前面，只看 `type` 會讓 5.5 勝出
   （Medium 而非 Critical）。唯一的 `Primary` 是 CVSS v2，不在支援範圍。
4. **輸出每列標明 `cvss_version` 與 `cvss_source`**（`nvd/primary`、`nvd/secondary`、`scanner`），排序表裡不同版本的分數不得混在同一欄而不標示。
5. **有來源的快照分數優先於掃描器手填值**；不一致時在 `reason` 註明 `scanner said X`。快照存在但無任何分數時退回掃描器值並註明 `nvd unscored`；兩者皆無則 `NEEDS_CONTEXT`，不補零。
6. 快照的 `raw` 為唯一真相，`extracted` 只是投影；解析邏輯升級以 `fetch-cve --reparse` 重寫投影，不重新取數。

## 後果

- 改變 `version_preference` 會改變含 v4.0 CVE 的分級（實測 CVE-2025-21590 在 INTERNET×PARTIAL×CRITICAL 下：偏好 3.1 → 6.45 Medium；偏好 4.0 → 7.6 High），因此該設定視同權重，變更需更新本 ADR。
- Day 6 的 e2e 基準（不帶 `--snapshots`）維持不變；Day 8 另建帶快照的基準。
- v4.0 的 Threat／Environmental 指標與 CVSS v2 均不納入 v0.1。
