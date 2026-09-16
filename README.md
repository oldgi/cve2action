# CVE2Action

> 從 CVE 堆到修補優先序：教弱掃工具算出真實風險的 30 天

這個儲存庫保存 2026 iThome 鐵人賽系列的總體施工藍圖、重要設計決策與後續版本紀錄。

## 文件入口

- [30 天總體施工藍圖](docs/CVE2Action-30天總體施工藍圖.md)
- [架構決策 ADR-0001：專案定位](docs/decisions/ADR-0001-專案定位.md)
- [架構決策 ADR-0003：條件式行動決策](docs/decisions/ADR-0003-條件式行動決策.md)
- [Day 1：一份沒人看的弱掃報告](docs/articles/day-01.md)
- [Day 2：CVSS 9.8，真的就該第一個修嗎？](docs/articles/day-02.md)
- [Day 2 案例設計與查核備忘錄](docs/research/day-02-case-design.md)
- [Day 2 修訂包與手動更新說明](docs/releases/day-02-revision-MANIFEST.md)
- [版本紀錄](CHANGELOG.md)

## 目前版本

- 版本：`0.1.2`
- 狀態：Day 1 已發文；Day 2 修訂稿待審（Unreleased）
- 最近修訂：2026-09-16

Day 2 靜態資料契約版本為 `0.2.0`，與專案發行版本分開。可用 `python scripts/validate_day02.py` 檢查資料一致性；此檢查不代表已實作風險計算引擎。

## 專案定位

CVE2Action 不重新掃描主機，也不嘗試取代既有弱點掃描產品。它接收弱掃、資產、威脅情報、網路拓樸與控制措施資料，計算可解釋的修補優先分數、攻擊路徑與建議處置。

## 版本管理方式

- `main`：可回顧的穩定基線。
- `feature/day-NN-*`：每日文章或功能開發。
- Commit 採 Conventional Commits，例如 `feat(scoring): add EPSS signal`。
- 每一階段以 Git tag 留存，最終版本為 `v1.0.0`。
- 重要取捨以 ADR 記錄，不只記錄改了什麼，也保留當時為什麼這樣決定。

## 預定里程碑

| Tag | 內容 |
|---|---|
| `v0.1.0-blueprint` | 總體施工藍圖 |
| `v0.1.1-context-gates` | 資產歸併、適用性及可達性閘門 |
| `v0.1.2-day1-release` | Day 1 定稿與文章主視覺 |
| `v0.2.0-data` | 公開資料與模擬資料集 |
| `v0.3.0-scoring` | 可解釋風險評分 |
| `v0.4.0-attack-graph` | 攻擊路徑分析 |
| `v0.5.0-remediation` | 修補決策與 What-if |
| `v1.0.0-ironman` | 30 天文章與完整展示 |
