# Day 4｜審稿、發文與 Git 交付清單

日期：2026-09-18。版本：merged-1（Enterprise Context、MVP 雛形與三張配圖）。

本包以 `cve2action-day03-merged.zip` 為 baseline，只包含 Day 4 delta。ZIP 內路徑以儲存庫根目錄為起點，沒有外層資料夾，不含 `.git`。

## 檔案清單

| 路徑 | 用途 |
|---|---|
| `docs/articles/day-04.md` | Day 4 完整文章 |
| `docs/articles/day-04-visual-captions.md` | 配圖與閱讀節奏 |
| `docs/images/day-04-visible-vs-context.png` | 弱掃可見資訊與 Context 缺口 |
| `docs/images/day-04-context-rabbit-hole.png` | Context Scope 膨脹圖 |
| `docs/images/day-04-v01-portrait.png` | v0.1 輸入與 Decision 問號 |
| `docs/releases/day-04-publish-MANIFEST.md` | 本清單 |

## Git 匯入

在 repo root 解壓後：

```powershell
git status --short
git add -- docs/articles/day-04.md docs/articles/day-04-visual-captions.md docs/images/day-04-visible-vs-context.png docs/images/day-04-context-rabbit-hole.png docs/images/day-04-v01-portrait.png docs/releases/day-04-publish-MANIFEST.md
git diff --cached --check
git diff --cached --stat
git commit -m "docs(day-04): add enterprise context to decision engine"
git pull --rebase origin main
git push origin main
git status
```

若有既有未保存變更或 rebase 衝突，先停止處理，不 force push。

## Day 5 接點

Day 4 保留 `Severity + Threat + Context → ? → Priority / Action / Why`。Day 5 將 Freeze CVE2Action v0.1 的 Input / Process / Output / Out-of-Scope / Definition of Done，之後進入開發。
